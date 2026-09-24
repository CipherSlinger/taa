# tests/test_llm_timeout_counterfactual.py
"""The timeout counterfactual measures a bias, so its own accounting must not bias it.

The tool exists to size a defect that moves both columns of the comparison in
opposite directions: a failed call drops a true positive (lowering recall) and
also drops a would-be false positive (improving FPR). Four properties decide
whether its answer can be trusted, and each has a test here that fails if it
stops holding:

* both levels of failure are found. A file-level failure lives on the file summary
  and a finding-level failure on the finding, and the policy reads the file
  summary. Counting only findings undercounts the affected samples, which is the
  direction that flatters the result.
* the pre-registered rule is the one applied. Materiality is a changed
  `predicted_label` and nothing else, so a changed per-finding verdict or risk
  level must not be reported as material.
* direction is not summed away. A repaired false negative and a newly introduced
  false positive are different findings about the criterion and are classified
  separately.
* the replay refuses to run against a live matrix. Model calls issued inside the
  measurement window would perturb the run the replay is meant to explain, and
  the affected set would be a snapshot of a moving target.
"""
import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from models.audit.tools import llm_timeout_counterfactual as cf


def report_with(finding_reason=None, file_reason=None):
    finding = {"rule_id": "DYN_001", "line": 174}
    if finding_reason is not None:
        finding["llm_reason"] = finding_reason
    file_report = {"file": "sample.py", "reason": file_reason or "", "findings": [finding]}
    return {"file_reports": [file_report], "conclusion": {"passed": False}}


class FailureDiscoveryTest(unittest.TestCase):
    def test_timeout_is_classified_as_timeout(self):
        self.assertEqual(cf.failure_kind("ollama 调用失败: timed out"), "timeout")

    def test_other_call_failure_is_not_a_timeout(self):
        # Only a timeout can be repaired by the one parameter this tool changes,
        # so it must not be filed under the same name.
        self.assertEqual(cf.failure_kind("ollama 调用失败: connection refused"), "other")

    def test_success_is_not_a_failure(self):
        self.assertIsNone(cf.failure_kind(""))
        self.assertIsNone(cf.failure_kind("模型判定为恶意"))

    def test_finding_level_failure_is_found(self):
        failures = cf.find_failed_calls(report_with(finding_reason="ollama 调用失败: timed out"))
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["level"], "finding")
        self.assertEqual(failures[0]["rule_id"], "DYN_001")

    def test_file_level_failure_is_found_even_with_no_failing_finding(self):
        # The policy reads the file summary, so this sample is affected and would
        # be missed by a finding-only scan.
        failures = cf.find_failed_calls(report_with(file_reason="ollama 调用失败: timed out"))
        self.assertEqual([f["level"] for f in failures], ["file"])

    def test_both_levels_are_counted_separately(self):
        failures = cf.find_failed_calls(
            report_with(finding_reason="ollama 调用失败: timed out",
                        file_reason="ollama 调用失败: timed out")
        )
        self.assertEqual(sorted(f["level"] for f in failures), ["file", "finding"])


class TransitionTest(unittest.TestCase):
    def test_malicious_sample_scored_benign_becomes_malicious(self):
        self.assertEqual(
            cf.classify_transition("malicious", "benign", "malicious"),
            "false_negative_repaired",
        )

    def test_benign_sample_scored_malicious_becomes_benign(self):
        self.assertEqual(
            cf.classify_transition("benign", "malicious", "benign"),
            "false_positive_repaired",
        )

    def test_malicious_sample_losing_its_label_is_its_own_direction(self):
        self.assertEqual(
            cf.classify_transition("malicious", "malicious", "benign"),
            "false_negative_introduced",
        )

    def test_benign_sample_gaining_a_label_is_its_own_direction(self):
        self.assertEqual(
            cf.classify_transition("benign", "benign", "malicious"),
            "false_positive_introduced",
        )

    def test_the_two_directions_are_never_the_same_name(self):
        repaired = cf.classify_transition("malicious", "benign", "malicious")
        introduced = cf.classify_transition("benign", "benign", "malicious")
        self.assertNotEqual(repaired, introduced)


class GuardTest(unittest.TestCase):
    def test_running_matrix_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / ".running").write_text("12345", encoding="utf-8")
            with self.assertRaises(cf.CounterfactualError):
                cf.assert_matrix_not_running(base)

    def test_finished_matrix_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cf.assert_matrix_not_running(Path(tmp))

    def test_a_spent_output_dir_is_refused(self):
        # A second replay into the same dir would mix two counterfactuals into one
        # summary, which is the same failure the matrix driver refuses for runs.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "replay"
            out.mkdir()
            (out / "counterfactual-summary.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(cf.CounterfactualError):
                cf.assert_output_dir_free(out)

    def test_an_empty_output_dir_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cf.assert_output_dir_free(Path(tmp) / "replay")


class AffectedSampleTest(unittest.TestCase):
    def test_affected_samples_are_indexed_by_run_and_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for run in ("regex-run1", "semgrep-run1"):
                sample_dir = base / run / "pypi-0057"
                sample_dir.mkdir(parents=True)
                report = report_with(finding_reason="ollama 调用失败: timed out")
                (sample_dir / "audit_report.json").write_text(
                    json.dumps(report), encoding="utf-8"
                )
            clean = base / "regex-run1" / "pypi-0001"
            clean.mkdir()
            (clean / "audit_report.json").write_text(
                json.dumps(report_with()), encoding="utf-8"
            )
            affected = cf.affected_samples(base)
            self.assertEqual(sorted(affected), ["regex-run1/pypi-0057", "semgrep-run1/pypi-0057"])

    def test_an_unreadable_report_is_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            sample_dir = base / "regex-run1" / "broken"
            sample_dir.mkdir(parents=True)
            (sample_dir / "audit_report.json").write_text("{not json", encoding="utf-8")
            self.assertEqual(cf.affected_samples(base), {})


class TimeoutPatchTest(unittest.TestCase):
    def test_the_patch_forces_the_longer_timeout_and_is_restored(self):
        # The production call passes timeout=60 explicitly, so a wrapper that only
        # supplies a default would leave the cap in place and measure nothing.
        original = urllib.request.urlopen
        seen = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(req, *args, **kwargs):
            seen.update(kwargs)
            return FakeResponse()

        urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
        try:
            with cf.patched_llm_timeout(300):
                urllib.request.urlopen("http://x", timeout=60)
        finally:
            urllib.request.urlopen = original  # type: ignore[assignment]

        self.assertEqual(seen["timeout"], 300)
        self.assertIs(urllib.request.urlopen, original)

    def test_the_patch_is_restored_even_when_the_body_raises(self):
        original = urllib.request.urlopen
        with self.assertRaises(RuntimeError):
            with cf.patched_llm_timeout(300):
                raise RuntimeError("boom")
        self.assertIs(urllib.request.urlopen, original)


if __name__ == "__main__":
    unittest.main()
