# tests/test_prompt_equivalence.py
"""Compare what the two engines ask the model, per sample.

Requirement 8 of the engine evidence spec: the arms must send equivalent prompts
per sample, or a difference in verdicts cannot be attributed to the engine. The
inequivalence is live today - the adapters fill different context fields for the
same hit, and the analyzer branches on exactly those fields - so the instrument
has to be able to say which value differed, not merely that the text did.

Two kinds of difference are not the same thing and must not be conflated:

* the arms report different hits. That IS the engine difference the comparison
  exists to measure, and it is recorded as such.
* the arms report the same hit and ask different questions about it. That is a
  confound, and under requirement 8 it is a violation.

Conflating them would either drown the comparison in noise or hide the confound.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from models.audit.tools import audit_benchmark_eval as ev
from models.audit.tools import prompt_equivalence as pe
from models.examples.code_security_analyzer import FileSummary


def finding_entry(file, rule_id, line, prompt, slots=None, level="finding"):
    return {
        "level": level, "file": file, "rule_id": rule_id, "line": line,
        "prompt": prompt, "prompt_sha256": pe.prompt_digest(prompt),
        "slots": slots if slots is not None else {},
    }


def file_entry(file, prompt, slots=None):
    entry = finding_entry(file, "", 0, prompt, slots, level="file")
    entry.pop("rule_id")
    entry.pop("line")
    return entry


def capture(engine, entries, sample_dir="/tmp/sample", **extra):
    payload = {
        "engine": engine,
        "sample_dir": sample_dir,
        "scan_complete": True,
        "findings": len(entries),
        "deduped": len(entries),
        "entries": entries,
    }
    payload.update(extra)
    return payload


class TestComparingCaptures(unittest.TestCase):
    def test_matching_prompts_for_the_same_hit_are_equivalent(self):
        regex = capture("regex", [finding_entry("train.py", "CMD_001", 3, "same text")])
        semgrep = capture("semgrep", [finding_entry("train.py", "CMD_001", 3, "same text")])

        result = pe.compare_captures(regex, semgrep)

        self.assertTrue(result["equivalent"])
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["compared_hits"], 1)
        self.assertEqual(result["arm_specific"], {"regex_only": [], "semgrep_only": []})

    def test_the_same_hit_with_different_text_is_a_violation_and_names_the_values(self):
        """Attribution is the point: 'they differ' is not actionable, the value is."""
        regex = capture("regex", [finding_entry(
            "train.py", "CMD_001", 3, "with trailing context",
            slots={"context_before": "before", "context_after": "after", "code_snippet": "x"},
        )])
        semgrep = capture("semgrep", [finding_entry(
            "train.py", "CMD_001", 3, "with enclosing scope",
            slots={"context_before": "", "context_after": "", "code_snippet": "x"},
        )])

        result = pe.compare_captures(regex, semgrep)

        self.assertFalse(result["equivalent"])
        self.assertEqual(len(result["violations"]), 1)
        violation = result["violations"][0]
        self.assertEqual((violation["file"], violation["rule_id"], violation["line"]),
                         ("train.py", "CMD_001", 3))
        self.assertEqual(violation["differing_slots"], ["context_after", "context_before"])

    def test_a_hit_only_one_arm_reports_is_not_a_violation(self):
        """That difference is the engine difference being measured, not a confound."""
        regex = capture("regex", [finding_entry("train.py", "CMD_001", 3, "a")])
        semgrep = capture("semgrep", [
            finding_entry("train.py", "CMD_001", 3, "a"),
            finding_entry("train.py", "NET_001", 9, "b"),
        ])

        result = pe.compare_captures(regex, semgrep)

        self.assertTrue(result["equivalent"])
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["arm_specific"]["semgrep_only"], ["train.py:NET_001:9"])
        self.assertEqual(result["arm_specific"]["regex_only"], [])

    def test_hits_in_different_files_are_not_compared(self):
        """The key includes the file, or two unrelated hits would be called a match."""
        regex = capture("regex", [finding_entry("train.py", "CMD_001", 3, "a")])
        semgrep = capture("semgrep", [finding_entry("model.py", "CMD_001", 3, "a")])

        result = pe.compare_captures(regex, semgrep)

        self.assertTrue(result["equivalent"])
        self.assertEqual(result["compared_hits"], 0)
        self.assertEqual(result["arm_specific"]["regex_only"], ["train.py:CMD_001:3"])

    def test_several_hits_in_one_file_are_compared_individually(self):
        regex = capture("regex", [
            finding_entry("train.py", "CMD_001", 3, "same"),
            finding_entry("train.py", "NET_001", 9, "same"),
        ])
        semgrep = capture("semgrep", [
            finding_entry("train.py", "CMD_001", 3, "same"),
            finding_entry("train.py", "NET_001", 9, "different"),
        ])

        result = pe.compare_captures(regex, semgrep)

        self.assertFalse(result["equivalent"])
        self.assertEqual(len(result["violations"]), 1)
        self.assertEqual(result["violations"][0]["rule_id"], "NET_001")


class TestComparingFileLevelPrompts(unittest.TestCase):
    def test_the_same_hits_with_the_same_prompt_are_equivalent(self):
        regex = capture("regex", [file_entry("train.py", "prompt", slots={"findings_count": 1})])
        semgrep = capture("semgrep", [file_entry("train.py", "prompt", slots={"findings_count": 1})])

        result = pe.compare_captures(regex, semgrep)

        self.assertTrue(result["equivalent"])
        self.assertEqual(result["files"][0]["same_hit_sets"], True)
        self.assertEqual(result["files"][0]["prompt_identical"], True)

    def test_a_file_prompt_that_differs_on_the_same_hits_is_a_violation(self):
        regex = capture("regex", [file_entry("train.py", "code without scope", slots={})])
        semgrep = capture("semgrep", [file_entry("train.py", "code with scope", slots={})])

        result = pe.compare_captures(regex, semgrep)

        self.assertFalse(result["equivalent"])
        self.assertEqual(len(result["violations"]), 1)
        self.assertEqual(result["violations"][0]["level"], "file")
        self.assertEqual(result["violations"][0]["file"], "train.py")

    def test_a_file_prompt_that_differs_because_the_hits_differ_is_recorded_not_flagged(self):
        """The file prompt states how many hits were found, so a hit difference reaches it.

        That is the engine difference showing through, not a confound: the note is
        what keeps it from being read as one.
        """
        regex = capture("regex", [
            finding_entry("train.py", "CMD_001", 3, "a"),
            file_entry("train.py", "one hit", slots={"findings_count": 1}),
        ])
        semgrep = capture("semgrep", [
            finding_entry("train.py", "CMD_001", 3, "a"),
            finding_entry("train.py", "NET_001", 9, "b"),
            file_entry("train.py", "two hits", slots={"findings_count": 2}),
        ])

        result = pe.compare_captures(regex, semgrep)

        self.assertTrue(result["equivalent"])
        self.assertEqual(result["violations"], [])
        row = result["files"][0]
        self.assertFalse(row["same_hit_sets"])
        self.assertFalse(row["prompt_identical"])
        self.assertEqual(row["differing_slots"], ["findings_count"])
        self.assertIn("hit", row["reason"])

    def test_the_same_hits_in_a_different_order_are_reported_with_that_reason(self):
        """Same content in a different order is still different text to the model.

        The two engines do not have to enumerate a file's hits in the same order,
        and the per-file prompt lists them in the order it was given.
        """
        regex = capture("regex", [
            finding_entry("train.py", "CMD_001", 3, "a"),
            finding_entry("train.py", "NET_001", 9, "b"),
            file_entry("train.py", "cmd then net", slots={"findings_summary": "CMD_001, NET_001"}),
        ])
        semgrep = capture("semgrep", [
            finding_entry("train.py", "NET_001", 9, "b"),
            finding_entry("train.py", "CMD_001", 3, "a"),
            file_entry("train.py", "net then cmd", slots={"findings_summary": "NET_001, CMD_001"}),
        ])

        result = pe.compare_captures(regex, semgrep)

        row = result["files"][0]
        self.assertTrue(row["same_hit_sets"])
        self.assertFalse(row["same_hit_order"])
        self.assertFalse(row["prompt_identical"])
        self.assertIn("order", row["reason"])


class StubScanner:
    def __init__(self, findings):
        self.findings = list(findings)

    def scan_directory(self, dirpath, extensions=(".py",)):
        return ev.ScanOutcome(findings=self.findings, scan_complete=True)


def finding(root, line, rule_id, **overrides):
    """A finding on the sample's real file, so the per-file prompt can be built."""
    base = dict(
        file=str(Path(root) / "train.py"), line=line, rule_id=rule_id, category="execution",
        severity="HIGH", description="d", code_snippet="os.system(cmd)",
        context_before="before\n", context_after="after\n", engine="regex",
    )
    base.update(overrides)
    return ev.Finding(**base)


class TestCapturingPrompts(unittest.TestCase):
    def _capture(self, factory, engine="regex", max_findings=50):
        """Runs a capture over a sample whose one file the factory's findings point at."""
        with tempfile.TemporaryDirectory() as td:
            sample_dir = Path(td)
            (sample_dir / "train.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
            with patch.object(pe.ev, "load_module_scanner",
                              return_value=StubScanner(factory(sample_dir))):
                result = pe.capture_prompts(str(sample_dir), engine=engine, max_findings=max_findings)
        return result, sample_dir

    def test_the_capture_sends_nothing_to_a_model(self):
        """Capture must be observation only: the analyzer it builds has no backend."""
        analyzer = pe.build_capture_analyzer()
        self.assertEqual(analyzer.backend, "none")

        with tempfile.TemporaryDirectory() as td:
            sample_dir = Path(td)
            (sample_dir / "train.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
            with patch.object(pe.ev, "load_module_scanner",
                              return_value=StubScanner([finding(sample_dir, 2, "CMD_001")])):
                pe.capture_prompts(str(sample_dir), engine="regex", analyzer=analyzer)
        self.assertEqual(analyzer.backend, "none")

    def test_the_capture_covers_exactly_the_hits_the_pipeline_would_arbitrate(self):
        """Reusing the pipeline's own selection is what makes the capture evidence."""
        result, _ = self._capture(lambda d: [
            finding(d, 2, "CMD_001"),
            finding(d, 2, "CMD_001"),
            finding(d, 9, "NET_001"),
        ], engine="semgrep")

        keys = [(e["file"], e["rule_id"], e["line"]) for e in result["entries"] if e["level"] == "finding"]
        self.assertEqual(keys, [("train.py", "CMD_001", 2), ("train.py", "NET_001", 9)])
        self.assertEqual(result["findings"], 3)
        self.assertEqual(result["deduped"], 2)

    def test_the_capture_respects_the_cap(self):
        result, _ = self._capture(lambda d: [finding(d, line, "CMD_001") for line in range(1, 8)],
                                  engine="semgrep", max_findings=3)
        keys = [e["line"] for e in result["entries"] if e["level"] == "finding"]
        self.assertEqual(keys, [1, 2, 3])
        self.assertEqual(result["deduped"], 7)

    def test_the_captured_prompt_is_the_one_the_analyzer_builds(self):
        result, sample_dir = self._capture(lambda d: [finding(d, 2, "CMD_001")])
        entry = next(e for e in result["entries"] if e["level"] == "finding")

        analyzer = pe.build_capture_analyzer()
        expected = analyzer.build_finding_prompt(finding(sample_dir, 2, "CMD_001"))
        self.assertEqual(entry["prompt"], expected)
        self.assertEqual(entry["prompt_sha256"], pe.prompt_digest(expected))

    def test_the_file_level_prompt_is_captured_too(self):
        result, _ = self._capture(lambda d: [finding(d, 2, "CMD_001")])
        levels = [e["level"] for e in result["entries"]]
        self.assertIn("file", levels)

    def test_an_incomplete_scan_is_reported_rather_than_captured_as_empty(self):
        class Broken:
            def scan_directory(self, dirpath, extensions=(".py",)):
                return ev.ScanOutcome(findings=[], scan_complete=False, timed_out=True)

        with tempfile.TemporaryDirectory() as td:
            with patch.object(pe.ev, "load_module_scanner", return_value=Broken()):
                result = pe.capture_prompts(td, engine="semgrep")
        self.assertFalse(result["scan_complete"])
        self.assertEqual(result["entries"], [])


class TestLiveInequivalence(unittest.TestCase):
    """The real engines, on a real file, produce different prompts for the same hit.

    This is the confound requirement 8 exists to catch. If this test ever starts
    failing, the inequivalence was fixed and the report should say so.
    """

    def test_the_regex_arm_and_the_semgrep_arm_ask_different_questions(self):
        with tempfile.TemporaryDirectory() as td:
            sample_dir = Path(td)
            (sample_dir / "run.py").write_text(
                "import os\n\ndef stage():\n    os.system('id')\n", encoding="utf-8"
            )
            try:
                regex = pe.capture_prompts(str(sample_dir), engine="regex")
                semgrep = pe.capture_prompts(str(sample_dir), engine="semgrep")
            except Exception as exc:  # pragma: no cover - environment without semgrep
                self.skipTest(f"semgrep unavailable: {exc}")

        if not regex["entries"] or not semgrep["entries"]:
            self.skipTest("no hits produced in this environment")

        result = pe.compare_captures(regex, semgrep)
        joined = result["compared_hits"]
        if joined == 0:
            self.skipTest("the two arms share no hit on this file")

        self.assertFalse(
            result["equivalent"],
            "the arms sent identical prompts; the confound may have been fixed",
        )
        self.assertTrue(result["violations"])


if __name__ == "__main__":
    unittest.main()
