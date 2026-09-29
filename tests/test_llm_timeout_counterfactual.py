# tests/test_llm_timeout_counterfactual.py
"""The timeout counterfactual measures a bias, so its own accounting must not bias it.

The tool exists to size a defect with a direction that had to be corrected once
already. A failed call is not silently benign: an UNCERTAIN verdict on a HIGH or
MEDIUM finding drives the risk level to HIGH, and under `assist` that blocks the
sample (`code_security_analyzer.py:855-875`). In this corpus -- which contains no
LOW-severity findings at all -- the defect therefore only inflates FPR and never
costs recall, and it is not symmetric between the arms.

Five properties decide whether the tool's answer can be trusted, and each has a
test here that fails if it stops holding:

* both ways a call can fail are found. A call can raise the 60 s timeout
  (`llm_unavailable`) or return a generation that `num_predict` cut off before the
  JSON closed (`parse_error`). Counting only the first undercounts the affected
  samples, and the replay has to repair both, because neither repair fixes the
  other's failure.
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

    def test_truncated_generation_is_classified_as_unparseable(self):
        # The production wording, verbatim from `_call_ollama`'s parse branch.
        self.assertEqual(
            cf.failure_kind("无法解析模型输出: {\"verdict\": \"MALICIO"),
            "unparseable",
        )

    def test_the_finding_level_parse_marker_is_recognised_too(self):
        # `classify_llm_state` accepts "decode response", which the sample-level
        # check does not. Missing it would drop a whole marker family.
        self.assertEqual(cf.failure_kind("decode response failed"), "unparseable")

    def test_unparseable_is_never_filed_as_a_timeout(self):
        # The two need opposite repairs, so conflating them would make the replay
        # claim to have tested a repair it did not apply.
        self.assertNotEqual(cf.failure_kind("无法解析: <html>"), "timeout")

    def test_other_call_failure_is_not_a_timeout(self):
        # Only time and tokens can repair the two known families, so a failure
        # that is neither must not be filed under the same name.
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

    def test_an_unparseable_generation_is_found_at_both_levels(self):
        failures = cf.find_failed_calls(
            report_with(finding_reason="无法解析模型输出: {",
                        file_reason="无法解析: {")
        )
        self.assertEqual(sorted(f["level"] for f in failures), ["file", "finding"])
        self.assertEqual({f["kind"] for f in failures}, {"unparseable"})

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


class StaticLlmGuardTest(unittest.TestCase):
    """The mode guard must read a field that separates the modes.

    It read `rules_count == 0`, on the belief that a `static-llm` run reports no
    rules. Measured on the 2026-09-28 matrix, both arms record 13 for every one
    of their 311 samples -- for the samples the model adjudicated and for the
    ones it never saw -- so the check separated nothing and refused every
    affected sample, which is every sample the replay exists to explain. The
    artifacts carry no `audit_mode` at all, which is why a proxy was used;
    `llm_enabled` is the property that is actually recorded per sample and does
    separate them (`regex-run1/cq-0001` False, `regex-run1/dd-0019` True, both
    with `rules_count` 13).
    """

    def test_a_run_where_the_model_was_used_is_allowed(self):
        cf.assert_static_llm_run("regex-run1/dd-0019",
                                 {"llm_enabled": True, "rules_count": 13})

    def test_a_run_where_the_model_was_disabled_is_refused(self):
        with self.assertRaises(cf.CounterfactualError):
            cf.assert_static_llm_run("regex-run1/cq-0001",
                                     {"llm_enabled": False, "rules_count": 13})

    def test_rules_count_does_not_decide_it(self):
        # The regression, in both directions, so the fix cannot be "accept 13".
        # Against the old guard the first assertion raises, because 13 != 0.
        cf.assert_static_llm_run("x/y", {"llm_enabled": True, "rules_count": 13})
        cf.assert_static_llm_run("x/y", {"llm_enabled": True, "rules_count": 0})
        with self.assertRaises(cf.CounterfactualError):
            cf.assert_static_llm_run("x/y", {"llm_enabled": False, "rules_count": 0})


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


class CallBudgetPatchTest(unittest.TestCase):
    def setUp(self):
        self.original_call = cf.LLMSecurityAnalyzer._call_ollama

    def tearDown(self):
        cf.LLMSecurityAnalyzer._call_ollama = self.original_call  # type: ignore[assignment]

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
            with cf.patched_call_budget(300, 800):
                urllib.request.urlopen("http://x", timeout=60)
        finally:
            urllib.request.urlopen = original  # type: ignore[assignment]

        self.assertEqual(seen["timeout"], 300)
        self.assertIs(urllib.request.urlopen, original)

    def test_the_patch_raises_a_truncating_cap(self):
        # 200 is the production finding cap and is what truncates the JSON. A
        # timeout-only replay would leave it in place and fail the same way.
        seen = {}

        def fake_call(self, prompt, num_predict=200):
            seen["num_predict"] = num_predict
            return {"verdict": "BENIGN"}

        cf.LLMSecurityAnalyzer._call_ollama = fake_call  # type: ignore[assignment]
        with cf.patched_call_budget(300, 800):
            cf.LLMSecurityAnalyzer()._call_ollama("prompt", 200)

        self.assertEqual(seen["num_predict"], 800)

    def test_the_patch_does_not_lower_an_already_larger_cap(self):
        # The file-level call already asks for 300, and a floor must be a floor:
        # lowering it would change the prompt's budget in the other direction.
        seen = {}

        def fake_call(self, prompt, num_predict=200):
            seen["num_predict"] = num_predict
            return {"verdict": "BENIGN"}

        cf.LLMSecurityAnalyzer._call_ollama = fake_call  # type: ignore[assignment]
        with cf.patched_call_budget(300, 800):
            cf.LLMSecurityAnalyzer()._call_ollama("prompt", 1200)

        self.assertEqual(seen["num_predict"], 1200)

    def test_the_cap_patch_is_restored_even_when_the_body_raises(self):
        with self.assertRaises(RuntimeError):
            with cf.patched_call_budget(300, 800):
                raise RuntimeError("boom")
        self.assertIs(cf.LLMSecurityAnalyzer._call_ollama, self.original_call)

    def test_the_timeout_patch_is_restored_even_when_the_body_raises(self):
        original = urllib.request.urlopen
        with self.assertRaises(RuntimeError):
            with cf.patched_call_budget(300, 800):
                raise RuntimeError("boom")
        self.assertIs(urllib.request.urlopen, original)


if __name__ == "__main__":
    unittest.main()
