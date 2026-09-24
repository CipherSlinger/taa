# tests/test_semgrep_runner.py
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
from models.audit.tools.semgrep_runner import SemgrepRunner, SemgrepScanResult

class TestSemgrepRunner(unittest.TestCase):
    """Unit tests for SemgrepRunner CLI integration and JSON parsing."""

    def setUp(self):
        self.runner = SemgrepRunner(executable="semgrep")

    def test_check_availability_fallback(self):
        runner = SemgrepRunner(executable="non_existent_semgrep_binary")
        with patch("shutil.which", return_value=None):
            self.assertFalse(runner.is_available())

    def test_parse_semgrep_json_output(self):
        mock_output = {
            "results": [
                {
                    "check_id": "taa-cmd-exec-python",
                    "path": "test_script.py",
                    "start": {"line": 15, "col": 5},
                    "end": {"line": 15, "col": 40},
                    "extra": {
                        "message": "Suspicious subprocess execution",
                        "severity": "ERROR",
                        "metadata": {"rule_family": "CMD_001", "category": "execution"},
                        "lines": "subprocess.run('rm -rf /', shell=True)"
                    }
                }
            ],
            "errors": []
        }
        res = self.runner.parse_output(mock_output, exit_code=0)
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f["rule_id"], "CMD_001")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["line"], 15)
        self.assertEqual(f["file"], "test_script.py")
        self.assertEqual(res.parser_errors, 0)
        self.assertTrue(res.scan_complete)

    def test_handle_timeout_fail_closed(self):
        with patch("subprocess.run") as mock_run:
            import subprocess
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=10)
            res = self.runner.scan_directory("/tmp/fake_dir", timeout=10)
            self.assertFalse(res.scan_complete)
            self.assertTrue(res.timed_out)
            self.assertFalse(res.passed)

    def test_the_scan_pins_its_worker_count(self):
        # The host has 16 cores and Semgrep's per-file cap does not bound how
        # many files are in flight, so an unpinned --jobs is the one knob with
        # no ceiling on it. The pin is what keeps a concurrent load test from
        # deciding the verdict through the 60 s LLM timeout, so dropping it
        # silently would be a silent change to how the criterion is measured.
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout='{"results": [], "errors": []}',
                                              returncode=0, stderr="")
            self.runner.scan_directory("/tmp/fake_dir")
            argv = mock_run.call_args[0][0]
            self.assertIn("--jobs", argv)
            self.assertEqual(argv[argv.index("--jobs") + 1], str(self.runner.jobs))

    def test_the_scan_does_not_pin_a_per_file_memory_cap(self):
        # --max-memory makes Semgrep skip a file that exceeds it, so pinning it
        # would be a change in semantics rather than in scheduling.
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout='{"results": [], "errors": []}',
                                              returncode=0, stderr="")
            self.runner.scan_directory("/tmp/fake_dir")
            self.assertNotIn("--max-memory", mock_run.call_args[0][0])

    def test_parse_taint_dataflow_trace(self):
        mock_output = {
            "results": [
                {
                    "check_id": "taa-secret-exfiltration-python",
                    "path": "train.py",
                    "start": {"line": 45, "col": 5},
                    "end": {"line": 45, "col": 50},
                    "extra": {
                        "message": "Sensitive credential flows to network",
                        "severity": "ERROR",
                        "metadata": {"rule_family": "EXF_001", "category": "credential"},
                        "lines": "requests.post(url, json=payload)",
                        "dataflow_trace": {
                            "taint_source": [
                                {
                                    "path": "train.py",
                                    "start": {"line": 12, "col": 5},
                                    "content": "key = os.environ['SECRET']"
                                }
                            ],
                            "intermediate_vars": [
                                {
                                    "path": "train.py",
                                    "start": {"line": 20, "col": 5},
                                    "content": "payload = {'key': key}"
                                }
                            ]
                        }
                    }
                }
            ],
            "errors": []
        }
        res = self.runner.parse_output(mock_output, exit_code=0)
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f["rule_id"], "EXF_001")
        self.assertGreater(len(f["taint_trace"]), 0)
        self.assertEqual(f["taint_trace"][0]["line"], 12)

    def test_parse_output_rejects_requires_login_placeholder(self):
        """Semgrep CE puts the literal string "requires login" in extra.lines.

        That field is mapped to code_snippet and fed to the LLM as "the code
        that triggered the rule", so the runner has to read the real line out of
        the file rather than forward the placeholder.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "sample.py"
            target.write_text("import os\nprint('hello')\nos.system('id')\n", encoding="utf-8")
            mock_output = {
                "results": [
                    {
                        "check_id": "taa-cmd-exec-python",
                        "path": str(target),
                        "start": {"line": 3, "col": 1},
                        "end": {"line": 3, "col": 15},
                        "extra": {
                            "lines": "requires login",
                            "message": "Command execution detected",
                            "severity": "ERROR",
                            "metadata": {"rule_family": "CMD_001", "category": "command"},
                        },
                    }
                ],
                "errors": [],
            }
            res = self.runner.parse_output(mock_output, exit_code=0)
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0]["code_snippet"], "os.system('id')")

    def test_parse_output_reports_slice_failure(self):
        """An unrecoverable snippet must be reported, not silently left empty.

        An empty code_snippet reads exactly like "the match had no code", so the
        reason has to survive to the caller (and, via the sample row, to the
        report) instead of being swallowed.
        """
        mock_output = {
            "results": [
                {
                    "check_id": "taa-cmd-exec-python",
                    "path": "/nonexistent/does-not-exist/sample.py",
                    "start": {"line": 3, "col": 1},
                    "end": {"line": 3, "col": 15},
                    "extra": {
                        "lines": "requires login",
                        "message": "Command execution detected",
                        "severity": "ERROR",
                        "metadata": {"rule_family": "CMD_001", "category": "command"},
                    },
                }
            ],
            "errors": [],
        }
        res = self.runner.parse_output(mock_output, exit_code=0)
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0]["code_snippet"], "")
        self.assertIn("cannot read", res.findings[0]["slice_error"])

    def test_real_semgrep_scan_directory(self):
        import tempfile
        if not self.runner.is_available():
            self.skipTest("Semgrep CLI not available")
        with tempfile.TemporaryDirectory() as td:
            sample_file = Path(td) / "sample.py"
            sample_file.write_text("import os\nprint('hello')\nos.system('id')\n", encoding="utf-8")
            res = self.runner.scan_directory(td)
            self.assertTrue(res.scan_complete)
            self.assertFalse(res.passed)
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0]["rule_id"], "CMD_001")
            # The snippet must be the real source line. Semgrep CE returns the
            # literal string "requires login" in extra.lines, and that string is
            # what the LLM was being asked to adjudicate, so the runner has to
            # slice the file by line number instead of trusting the field.
            self.assertEqual(res.findings[0]["code_snippet"], "os.system('id')")

if __name__ == "__main__":
    unittest.main()
