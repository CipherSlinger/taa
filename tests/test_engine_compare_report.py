# tests/test_engine_compare_report.py
"""Paired non-inferiority analysis over the engine-compare runs.

The judgement in spec 5.3 is a per-pair, zero-tolerance one: for each of the
three pairs, dFPR must be <= 0 and drecall must be >= 0. That is not a summary
statistic, so it cannot be read off two independent confidence intervals - the
comparison has to be made sample by sample, within a pair, and a pair whose runs
are not both complete carries no verdict at all rather than a lenient one.

Expected values here are constructed from small labelled samples, not from the
runs: this file tests the arithmetic and the decision rule, and the corpus audit
tests the rules. Conflating the two is how a comparison ends up validating
itself.
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools import engine_compare_report as ec  # noqa: E402


def row(sample_id, label, predicted, family=None, scan_complete=True, rules=()):
    return {
        "sample_id": sample_id,
        "label": label,
        "predicted_label": predicted,
        "family": family or ("B1" if label == "benign" else "M1"),
        "scan_complete": scan_complete,
        "matched_rules": list(rules),
        "trap_type": "none",
    }


class TestPredictedMaliciousRule(unittest.TestCase):
    """One definition of "this arm flagged the sample", shared by both callers.

    The comparison and the confusion matrix have to agree on what counts as a
    detection. Two copies of that rule drifting apart would move the verdict
    without moving any test that reads only one of them.
    """

    def test_an_explicit_malicious_label_is_flagged(self):
        self.assertTrue(ec.predicted_malicious(row("S-01", "benign", "malicious")))

    def test_an_explicit_benign_label_is_not_flagged(self):
        self.assertFalse(ec.predicted_malicious(row("S-01", "malicious", "benign")))

    def test_a_missing_label_falls_back_to_the_block_flag(self):
        unflagged = row("S-01", "benign", None)
        unflagged["blocked"] = True
        self.assertTrue(ec.predicted_malicious(unflagged))

        flagged = row("S-02", "benign", None)
        flagged["blocked"] = False
        self.assertFalse(ec.predicted_malicious(flagged))


class TestPairing(unittest.TestCase):
    def test_identical_arms_produce_a_zero_delta(self):
        regex = [row("B1-01", "benign", "benign"), row("M1-01", "malicious", "malicious")]
        semgrep = [row("B1-01", "benign", "benign"), row("M1-01", "malicious", "malicious")]
        outcome = ec.pair_runs(1, regex, semgrep)
        self.assertEqual(outcome.n_paired, 2)
        self.assertEqual(outcome.delta_fpr, 0.0)
        self.assertEqual(outcome.delta_recall, 0.0)
        self.assertFalse(outcome.is_void)

    def test_the_delta_is_semgrep_minus_regex(self):
        # Benefit 1: regex flags a benign sample, semgrep does not.
        # Cost 1:    semgrep misses a malicious sample, regex catches it.
        regex = [
            row("B1-01", "benign", "malicious"),
            row("B1-02", "benign", "benign"),
            row("M1-01", "malicious", "malicious"),
            row("M1-02", "malicious", "malicious"),
        ]
        semgrep = [
            row("B1-01", "benign", "benign"),
            row("B1-02", "benign", "benign"),
            row("M1-01", "malicious", "malicious"),
            row("M1-02", "malicious", "benign"),
        ]
        outcome = ec.pair_runs(1, regex, semgrep)
        self.assertAlmostEqual(outcome.metrics_regex["fpr"], 0.5)
        self.assertAlmostEqual(outcome.metrics_semgrep["fpr"], 0.0)
        self.assertAlmostEqual(outcome.delta_fpr, -0.5)
        self.assertAlmostEqual(outcome.delta_recall, -0.5)

    def test_an_unscanned_sample_is_not_paired(self):
        """A sample one arm failed to scan has no verdict to compare."""
        regex = [row("B1-01", "benign", "benign"), row("M1-01", "malicious", "malicious")]
        semgrep = [
            row("B1-01", "benign", "benign"),
            row("M1-01", "malicious", "malicious", scan_complete=False),
        ]
        outcome = ec.pair_runs(1, regex, semgrep)
        self.assertEqual(outcome.n_paired, 1, "the unscanned sample must not be counted")
        self.assertTrue(outcome.is_void)
        self.assertIn("scan_complete", outcome.void_reason)

    def test_a_sample_missing_from_one_arm_voids_the_pair(self):
        """The corpus is fixed, so a missing sample means the run is not comparable."""
        regex = [row("B1-01", "benign", "benign"), row("M1-01", "malicious", "malicious")]
        semgrep = [row("B1-01", "benign", "benign")]
        outcome = ec.pair_runs(1, regex, semgrep)
        self.assertTrue(outcome.is_void)
        self.assertIn("M1-01", outcome.void_reason)

    def test_a_pair_over_no_samples_is_void_not_perfect(self):
        outcome = ec.pair_runs(1, [], [])
        self.assertTrue(outcome.is_void)
        self.assertEqual(outcome.n_paired, 0)


class TestMcNemar(unittest.TestCase):
    def test_the_fpr_test_counts_only_benign_samples(self):
        """A malicious sample cannot contribute to a false-positive comparison."""
        regex = [row("B1-01", "benign", "benign"), row("M1-01", "malicious", "benign")]
        semgrep = [row("B1-01", "benign", "malicious"), row("M1-01", "malicious", "malicious")]
        outcome = ec.pair_runs(1, regex, semgrep)
        # b = semgrep flagged / regex clean (1 benign sample); c = 0.
        self.assertEqual(outcome.mcnemar_fpr["b"], 1)
        self.assertEqual(outcome.mcnemar_fpr["c"], 0)
        # The malicious discordance belongs to the recall test, not this one.
        # b is "only semgrep got it wrong", so a miss by regex counts as c.
        self.assertEqual(outcome.mcnemar_recall["b"], 0)
        self.assertEqual(outcome.mcnemar_recall["c"], 1)

    def test_no_disagreement_gives_a_p_value_of_one(self):
        regex = [row("B1-01", "benign", "benign")]
        semgrep = [row("B1-01", "benign", "benign")]
        outcome = ec.pair_runs(1, regex, semgrep)
        self.assertEqual(outcome.mcnemar_fpr["p"], 1.0)
        self.assertEqual(outcome.mcnemar_recall["p"], 1.0)

    def test_the_exact_p_value_matches_the_binomial_for_five_discordant_pairs(self):
        # Five benign samples where only semgrep flags: b=5, c=0.
        # Two-sided exact McNemar: 2 * (1/2)^5 = 0.0625.
        regex = [row(f"B1-{i:02d}", "benign", "benign") for i in range(1, 6)]
        semgrep = [row(f"B1-{i:02d}", "benign", "malicious") for i in range(1, 6)]
        outcome = ec.pair_runs(1, regex, semgrep)
        self.assertAlmostEqual(outcome.mcnemar_fpr["p"], 0.0625)


class TestInconsistencyList(unittest.TestCase):
    def test_it_names_the_samples_the_arms_disagree_about(self):
        regex = [
            row("B2-01", "benign", "malicious", family="B2", rules=("EMB_002",)),
            row("M1-01", "malicious", "malicious", family="M1", rules=("CMD_001",)),
        ]
        semgrep = [
            row("B2-01", "benign", "benign", family="B2"),
            row("M1-01", "malicious", "benign", family="M1", rules=("CMD_001",)),
        ]
        listed = {entry["sample_id"]: entry for entry in ec.inconsistent_samples(regex, semgrep)}
        self.assertEqual(set(listed), {"B2-01", "M1-01"})
        self.assertEqual(listed["B2-01"]["direction"], "regex_flagged_only")
        self.assertEqual(listed["M1-01"]["direction"], "regex_flagged_only")
        # The rule sets are the only actionable lead for a rule-level root cause.
        self.assertEqual(listed["B2-01"]["regex_rules"], ["EMB_002"])
        self.assertEqual(listed["B2-01"]["semgrep_rules"], [])

    def test_agreement_produces_an_empty_list(self):
        rows = [row("B1-01", "benign", "benign")]
        self.assertEqual(ec.inconsistent_samples(rows, list(rows)), [])


class TestVerdict(unittest.TestCase):
    """Spec 5.3, zero tolerance: every pair must satisfy both conditions."""

    def _pair_outcome(self, index, delta_fpr, delta_recall, void_reason=None,
                      base_fpr=0.10, base_recall=0.90):
        """A pair whose rates differ from the regex arm's by the given deltas.

        The rates are supplied rather than derived so the failure reasons can be
        read as the report would print them; a stub with empty metrics would
        pass a decision rule that could never describe a real pair.
        """
        return ec.PairOutcome(
            index=index, n_paired=100,
            metrics_regex={"fpr": base_fpr, "recall": base_recall},
            metrics_semgrep={"fpr": base_fpr + delta_fpr, "recall": base_recall + delta_recall},
            delta_fpr=delta_fpr, delta_fpr_ci=(-0.01, 0.01),
            delta_recall=delta_recall, delta_recall_ci=(-0.01, 0.01),
            mcnemar_fpr={"b": 0, "c": 0, "p": 1.0},
            mcnemar_recall={"b": 0, "c": 0, "p": 1.0},
            void_reason=void_reason, expected_paired=100,
        )

    def test_three_noninferior_pairs_pass(self):
        outcomes = [self._pair_outcome(i, 0.0, 0.0) for i in (1, 2, 3)]
        verdict, reasons = ec.decide(outcomes)
        self.assertEqual(verdict, "通过")
        self.assertEqual(reasons, [])

    def test_one_pair_with_a_higher_fpr_fails(self):
        outcomes = [self._pair_outcome(1, 0.0, 0.0), self._pair_outcome(2, 0.01, 0.0), self._pair_outcome(3, 0.0, 0.0)]
        verdict, reasons = ec.decide(outcomes)
        self.assertEqual(verdict, "未通过")
        self.assertTrue(any("FPR" in r for r in reasons))

    def test_one_pair_with_a_lower_recall_fails(self):
        outcomes = [self._pair_outcome(1, 0.0, 0.0), self._pair_outcome(2, 0.0, -0.01), self._pair_outcome(3, 0.0, 0.0)]
        verdict, reasons = ec.decide(outcomes)
        self.assertEqual(verdict, "未通过")
        self.assertTrue(any("recall" in r for r in reasons))

    def test_a_void_pair_yields_insufficient_evidence_not_a_pass(self):
        outcomes = [
            self._pair_outcome(1, 0.0, 0.0),
            self._pair_outcome(2, 0.0, 0.0, void_reason="run 2 semgrep: scan_complete is False on 3 samples"),
            self._pair_outcome(3, 0.0, 0.0),
        ]
        verdict, reasons = ec.decide(outcomes)
        self.assertEqual(verdict, "证据不足")
        self.assertTrue(any("scan_complete" in r for r in reasons))

    def test_missing_pairs_are_insufficient_evidence(self):
        verdict, reasons = ec.decide([self._pair_outcome(1, 0.0, 0.0)])
        self.assertEqual(verdict, "证据不足")
        self.assertTrue(any("3" in r for r in reasons))

    def test_an_exact_tie_is_not_a_failure(self):
        """dFPR == 0 satisfies <= 0; a tie is non-inferior, not inconclusive."""
        outcomes = [self._pair_outcome(i, 0.0, 0.0) for i in (1, 2, 3)]
        self.assertEqual(ec.decide(outcomes)[0], "通过")


class TestAnalyseAllRuns(unittest.TestCase):
    """The six run directories in, one analysis out.

    The collection is the evidence, so a run that is missing or half-written has
    to reach the verdict as missing evidence. Crashing on it, or silently
    analysing five runs as if they were six, would both hide the gap at the
    moment it matters.
    """

    def _write_run(self, base, engine, index, rows, duration=10.0):
        run_dir = Path(base) / f"{engine}-run{index}"
        run_dir.mkdir(parents=True, exist_ok=True)
        with (run_dir / "sample-results.jsonl").open("w", encoding="utf-8") as handle:
            for entry in rows:
                handle.write(json.dumps(entry) + "\n")
        (run_dir / "summary.json").write_text(json.dumps({
            "engine": engine, "eval_duration_sec": duration,
            "metrics": {"fpr": 0.0, "recall": 1.0, "accuracy": 1.0, "precision": 1.0,
                        "f1": 1.0, "attribution_precision": 1.0, "bypass_rate": 0.22,
                        "fail_closed_count": 0, "scan_incomplete_count": 0},
        }), encoding="utf-8")
        return run_dir

    def _all_six(self, base, rows=None):
        rows = rows or [row("B1-01", "benign", "benign"), row("M1-01", "malicious", "malicious")]
        for engine in ("regex", "semgrep"):
            for index in (1, 2, 3):
                self._write_run(base, engine, index, rows)

    def test_identical_arms_across_six_runs_pass(self):
        with tempfile.TemporaryDirectory() as td:
            self._all_six(td)
            analysis = ec.analyse_all(td)
        self.assertEqual(analysis["verdict"], "通过")
        self.assertEqual(len(analysis["runs"]), 6)
        self.assertEqual(len(analysis["pairs"]), 3)

    def test_the_per_run_table_carries_the_summary_numbers(self):
        with tempfile.TemporaryDirectory() as td:
            self._all_six(td)
            analysis = ec.analyse_all(td)
        entry = analysis["runs"][0]
        self.assertEqual(entry["engine"], "regex")
        self.assertEqual(entry["run"], 1)
        self.assertEqual(entry["eval_duration_sec"], 10.0)
        self.assertEqual(entry["scan_incomplete_count"], 0)

    def test_a_missing_run_is_insufficient_evidence_not_a_crash(self):
        with tempfile.TemporaryDirectory() as td:
            self._all_six(td)
            shutil.rmtree(Path(td) / "semgrep-run3")
            analysis = ec.analyse_all(td)
        self.assertEqual(analysis["verdict"], "证据不足")
        self.assertTrue(any("pair 3" in reason for reason in analysis["reasons"]))

    def test_a_divergence_between_the_arms_is_reported_per_pair(self):
        with tempfile.TemporaryDirectory() as td:
            self._all_six(td)
            # Rewrite the semgrep runs so run 2 misses the malicious sample.
            for index in (2,):
                self._write_run(td, "semgrep", index, [
                    row("B1-01", "benign", "benign"), row("M1-01", "malicious", "benign"),
                ])
            analysis = ec.analyse_all(td)
        self.assertEqual(analysis["verdict"], "未通过")
        self.assertEqual([e["sample_id"] for e in analysis["inconsistencies"][1]], ["M1-01"])
        self.assertEqual(analysis["inconsistencies"][0], [])

    def test_it_writes_the_analysis_to_disk(self):
        """The numbers the report cites have to be re-derivable, not transcribed."""
        with tempfile.TemporaryDirectory() as td:
            self._all_six(td)
            out = Path(td) / "paired-analysis.json"
            ec.analyse_all(td, out_path=out)
            written = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(written["verdict"], "通过")
        self.assertIn("family_table", written)


if __name__ == "__main__":
    unittest.main()
