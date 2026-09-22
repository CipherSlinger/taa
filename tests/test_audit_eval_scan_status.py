# tests/test_audit_eval_scan_status.py
"""The evaluator must not confuse "the scan did not finish" with "the scan found nothing".

A dropped scan result and a clean scan both produce an empty finding list. Treating
them alike turns an infrastructure failure into a passing verdict, which is the
failure mode that would flatter whichever engine was more likely to fail.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from models.audit.tools import audit_benchmark_eval as ev


def make_sample(label: str = "benign") -> ev.SampleSpec:
    return ev.SampleSpec(
        sample_id="X-01",
        base_project="p1_xgboost_finance",
        family="B1",
        label=label,
        transformation="none",
        expected_rules=(),
        expected_severity="LOW",
        expected_final="BENIGN",
        trap_type="none",
        notes="",
        relative_path="p1_xgboost_finance/X-01",
    )


class StubScanner:
    """Stands in for an engine adapter, returning a fixed ScanOutcome."""

    def __init__(self, outcome):
        self.outcome = outcome

    def scan_directory(self, dirpath, extensions=(".py",)):
        return self.outcome


class TestScanStatusPropagation(unittest.TestCase):
    def _analyse(self, outcome, label: str = "benign") -> dict:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample_dir = root / "p1_xgboost_finance" / "X-01"
            sample_dir.mkdir(parents=True)
            (sample_dir / "train.py").write_text("print('hi')\n", encoding="utf-8")
            with patch.object(ev, "load_module_scanner", return_value=StubScanner(outcome)):
                return ev.analyse_sample(
                    sample=make_sample(label),
                    sample_dir=sample_dir,
                    results_dir=root / "results",
                    audit_mode="static-llm",
                    policy="gate",
                    llm_backend="none",
                    llm_model="qwen2.5-coder:3b",
                    extensions=(".py",),
                    max_findings=50,
                    engine="semgrep",
                )

    def test_incomplete_scan_is_not_a_bypass(self):
        row = self._analyse(ev.ScanOutcome(
            findings=[], scan_complete=False, timed_out=True,
            error_message="Semgrep scan timed out after 120 seconds",
        ))
        self.assertFalse(row["scan_complete"])
        self.assertTrue(row["scan_timed_out"])
        self.assertTrue(row["incomplete"])
        self.assertFalse(row["bypass"], "an unfinished scan must not count as 'nothing found'")

    def test_completed_empty_scan_is_a_bypass(self):
        row = self._analyse(ev.ScanOutcome(findings=[], scan_complete=True))
        self.assertTrue(row["scan_complete"])
        self.assertFalse(row["incomplete"])
        self.assertTrue(row["bypass"])

    def test_scan_error_is_recorded_on_the_row(self):
        row = self._analyse(ev.ScanOutcome(
            findings=[], scan_complete=False,
            error_message="Semgrep executable 'semgrep' not found in PATH",
        ))
        self.assertIn("not found", row["scan_error"])
        self.assertFalse(row["bypass"])

    def test_slice_errors_are_counted(self):
        finding = ev.Finding(
            file="train.py", line=3, rule_id="CMD_001", category="command",
            severity="HIGH", description="", code_snippet="", context_before="",
            context_after="", engine="semgrep",
        )
        row = self._analyse(ev.ScanOutcome(
            findings=[finding], scan_complete=True, slice_error_count=1,
        ))
        self.assertEqual(row["slice_error_count"], 1)

    def test_metrics_count_incomplete_and_error_rows(self):
        def row(**extra):
            base = {"label": "benign", "predicted_label": "benign", "blocked": False,
                    "scan_complete": True, "scan_error": None}
            base.update(extra)
            return base

        rows = [
            row(bypass=True),
            row(scan_complete=False, scan_error="timed out"),
            row(scan_complete=False),
        ]
        metrics = ev.metric_summary(rows)
        self.assertEqual(metrics["scan_incomplete_count"], 2)
        self.assertEqual(metrics["scan_error_count"], 1)


class TestScannerAdapterInterface(unittest.TestCase):
    def test_regex_adapter_reports_a_completed_scan(self):
        """The in-process regex pass has no partial state, so it is always complete."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "train.py").write_text("import os\nos.system('id')\n", encoding="utf-8")
            outcome = ev.RegexScannerAdapter().scan_directory(td, extensions=(".py",))
        self.assertIsInstance(outcome, ev.ScanOutcome)
        self.assertTrue(outcome.scan_complete)
        self.assertEqual([f.rule_id for f in outcome.findings], ["CMD_001"])

    def test_semgrep_adapter_surfaces_runner_status(self):
        """A failed runner scan must reach the caller as an incomplete outcome."""
        from models.audit.tools.semgrep_runner import SemgrepScanResult

        adapter = ev.SemgrepScannerAdapter()
        failed = SemgrepScanResult(
            scan_complete=False, passed=False, timed_out=True,
            error_message="Semgrep scan timed out after 120 seconds",
        )
        with patch.object(adapter.runner, "scan_directory", return_value=failed):
            outcome = adapter.scan_directory("/tmp/whatever", extensions=(".py",))
        self.assertIsInstance(outcome, ev.ScanOutcome)
        self.assertFalse(outcome.scan_complete)
        self.assertTrue(outcome.timed_out)
        self.assertIn("timed out", outcome.error_message)

    def test_semgrep_adapter_reports_missing_executable(self):
        from models.audit.tools.semgrep_runner import SemgrepScanResult

        adapter = ev.SemgrepScannerAdapter()
        missing = SemgrepScanResult(
            scan_complete=False, passed=False,
            error_message="Semgrep executable 'semgrep' not found in PATH",
        )
        with patch.object(adapter.runner, "scan_directory", return_value=missing):
            outcome = adapter.scan_directory("/tmp/whatever", extensions=(".py",))
        self.assertFalse(outcome.scan_complete)
        self.assertIn("not found", outcome.error_message)


if __name__ == "__main__":
    unittest.main()
