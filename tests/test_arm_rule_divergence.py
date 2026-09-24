# tests/test_arm_rule_divergence.py
"""Attribution of arm-to-arm rule differences on a holdout comparison.

The comparison decides whether one engine may replace another, so a difference
has to be explained before it is acted on. The distinction this module exists
for is between two causes that look identical in the verdict counts:

* the reference scanner keeps one finding per line while the Semgrep arm reports
  every matching rule, so a line both arms flag can differ in finding count with
  no rule differing ("shape"); and
* only one arm saw anything at that position, which is a difference in the rules
  or in the engine ("coverage").

The fixtures below are synthetic and minimal: the point is the attribution
arithmetic, not the corpus. Each test writes two results directories, because
reading the arms from real results files is the behaviour under test - the
per-line detail the attribution needs lives in the per-sample report, which the
summary row only points at.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools import arm_rule_divergence as ard  # noqa: E402


def write_arm(root: Path, samples: dict) -> Path:
    """Write one arm's results directory.

    `samples` maps sample_id to (label, blocked, findings), where findings is a
    list of (rule_id, file, line). The per-sample report is written the way the
    pipeline writes it, since that is where the attribution reads lines from.
    """
    root.mkdir(parents=True, exist_ok=True)
    rows = []
    for sample_id, (label, blocked, findings) in samples.items():
        sample_dir = root / sample_id
        sample_dir.mkdir(parents=True, exist_ok=True)
        by_file: dict = {}
        for rule_id, file, line in findings:
            by_file.setdefault(file, []).append({"rule_id": rule_id, "line": line})
        report = {
            "file_reports": [
                {"file": file, "findings": items} for file, items in by_file.items()
            ]
        }
        report_path = sample_dir / "audit_report.json"
        report_path.write_text(json.dumps(report))
        rows.append({
            "sample_id": sample_id,
            "label": label,
            "blocked": blocked,
            "report_path": str(report_path),
        })
    (root / ard.RESULTS_FILE).write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n"
    )
    return root


def total_findings(comparison, arm: str) -> int:
    """How many findings one arm recorded across every sample it scored."""
    findings = comparison.regex_findings if arm == "regex" else comparison.semgrep_findings
    return sum(len(items) for items in findings.values())


class ArmFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def compare(self, regex_samples, semgrep_samples):
        return ard.compare(
            write_arm(self.tmp / "regex", regex_samples),
            write_arm(self.tmp / "semgrep", semgrep_samples),
        )


class TestAttribution(ArmFixture):
    def test_a_finding_both_arms_share_is_not_a_divergence(self):
        shared = [("ENV_001", "sample.py", 5)]
        comparison = self.compare({"s1": ("malicious", True, shared)},
                                  {"s1": ("malicious", True, shared)})
        self.assertEqual(comparison.semgrep_only, [])
        self.assertEqual(comparison.regex_only, [])

    def test_a_position_only_one_arm_flags_is_coverage(self):
        comparison = self.compare(
            {"s1": ("benign", False, [])},
            {"s1": ("benign", True, [("ENV_001", "sample.py", 9)])},
        )
        self.assertEqual(len(comparison.semgrep_only), 1)
        self.assertEqual(comparison.semgrep_only[0].kind, ard.COVERAGE)
        self.assertEqual(comparison.semgrep_only[0].line, 9)

    def test_a_position_both_arms_flag_under_different_rules_is_shape(self):
        # The reference arm keeps the first match on the line; the Semgrep arm
        # reports the other rule too. Same position, so no rule coverage differs.
        comparison = self.compare(
            {"s1": ("benign", True, [("CMD_001", "sample.py", 12)])},
            {"s1": ("benign", True, [("CMD_001", "sample.py", 12),
                                     ("OBF_001", "sample.py", 12)])},
        )
        self.assertEqual(len(comparison.semgrep_only), 1)
        attribution = comparison.semgrep_only[0]
        self.assertEqual(attribution.kind, ard.SHAPE)
        self.assertEqual(attribution.other_rules, ("CMD_001",))

    def test_a_rule_the_reference_arm_never_fires_is_reported_as_inert(self):
        comparison = self.compare(
            {"s1": ("benign", False, []), "s2": ("malicious", True, [("CMD_001", "a.py", 1)])},
            {"s1": ("benign", True, [("ENV_001", "sample.py", 3)]),
             "s2": ("malicious", True, [("CMD_001", "a.py", 1),
                                        ("ENV_001", "a.py", 7)])},
        )
        rows = {row["rule_id"]: row for row in comparison.per_rule()}
        self.assertTrue(rows["ENV_001"]["inert_on_reference"])
        self.assertEqual(rows["ENV_001"]["regex"], 0)
        self.assertEqual(rows["ENV_001"]["semgrep"], 2)
        self.assertFalse(rows["CMD_001"]["inert_on_reference"])

    def test_the_two_causes_are_counted_separately_per_rule(self):
        comparison = self.compare(
            {"s1": ("benign", True, [("NET_001", "a.py", 4)])},
            {"s1": ("benign", True, [("NET_001", "a.py", 4),
                                     ("OBF_001", "a.py", 4),   # shape: same position
                                     ("ENV_001", "a.py", 30)])},  # coverage: new position
        )
        rows = {row["rule_id"]: row for row in comparison.per_rule()}
        self.assertEqual(rows["OBF_001"]["semgrep_shape"], 1)
        self.assertEqual(rows["OBF_001"]["semgrep_coverage"], 0)
        self.assertEqual(rows["ENV_001"]["semgrep_coverage"], 1)
        self.assertEqual(rows["ENV_001"]["semgrep_shape"], 0)

    def test_a_duplicated_finding_is_matched_once_and_the_rest_are_shape(self):
        # One arm can report the same rule at the same line twice. Matching by
        # set would absorb both copies against the other arm's single finding and
        # report no difference, while the per-rule totals show one.
        comparison = self.compare(
            {"s1": ("benign", True, [("ENV_001", "a.py", 7), ("ENV_001", "a.py", 7)])},
            {"s1": ("benign", True, [("ENV_001", "a.py", 7)])},
        )
        self.assertEqual(len(comparison.regex_only), 1)
        leftover = comparison.regex_only[0]
        # Both arms flagged that position, so this is a reporting-count
        # difference rather than one arm seeing something the other missed.
        self.assertEqual(leftover.kind, ard.SHAPE)
        self.assertEqual(leftover.other_rules, ("ENV_001",))
        self.assertEqual(len(comparison.semgrep_only), 0)

    def test_shape_names_the_rule_the_other_arm_used_at_that_position(self):
        # The harness keeps the first matching rule per line, so the arms can
        # flag the same line under different rules. `other_rules` is what makes
        # that distinguishable from a duplicate of the same rule.
        comparison = self.compare(
            {"s1": ("benign", True, [("CMD_001", "a.py", 3)])},
            {"s1": ("benign", True, [("CMD_001", "a.py", 3), ("OBF_001", "a.py", 3)])},
        )
        leftover = comparison.semgrep_only[0]
        self.assertEqual(leftover.kind, ard.SHAPE)
        self.assertNotIn("OBF_001", leftover.other_rules)
        self.assertEqual(leftover.other_rules, ("CMD_001",))

    def test_the_attribution_accounts_for_every_finding(self):
        # The two arms' totals and the attribution are computed separately, so
        # they can drift. This is the invariant that ties them together.
        cases = [
            ({"s1": ("malicious", True, [("CMD_001", "a.py", 1), ("CMD_001", "a.py", 1)])},
             {"s1": ("malicious", True, [("CMD_001", "a.py", 1), ("NET_001", "a.py", 9)])}),
            ({"s1": ("benign", True, [("OBF_001", "a.py", 2), ("OBF_001", "b.py", 2)]),
              "s2": ("benign", False, [])},
             {"s1": ("benign", True, []), "s2": ("benign", True, [("DYN_001", "a.py", 1)])}),
        ]
        for regex_samples, semgrep_samples in cases:
            comparison = self.compare(regex_samples, semgrep_samples)
            with self.subTest(regex=regex_samples, semgrep=semgrep_samples):
                self.assertEqual(
                    len(comparison.semgrep_only) - len(comparison.regex_only),
                    total_findings(comparison, "semgrep") - total_findings(comparison, "regex"),
                )


class TestCriterion(ArmFixture):
    def test_the_criterion_is_read_from_each_rows_own_verdict(self):
        # s2 carries no finding but is recorded blocked: the pipeline may block on
        # something a finding list does not show, so the row's verdict is what the
        # criterion uses and the findings must not override it.
        comparison = self.compare(
            {"s1": ("malicious", True, [("CMD_001", "a.py", 1)]),
             "s2": ("benign", False, [])},
            {"s1": ("malicious", False, []),
             "s2": ("benign", True, [])},
        )
        criterion = comparison.criterion()
        self.assertEqual(criterion["regex"]["tp"], 1)
        self.assertEqual(criterion["regex"]["tn"], 1)
        self.assertEqual(criterion["semgrep"]["fn"], 1)
        self.assertEqual(criterion["semgrep"]["fp"], 1)

    def test_a_fpr_increase_fails_and_an_equal_reading_passes(self):
        fails = self.compare(
            {"m1": ("malicious", True, []), "b1": ("benign", False, [])},
            {"m1": ("malicious", True, []), "b1": ("benign", True, [])},
        ).criterion()
        self.assertGreater(fails["delta_fpr"], 0)
        self.assertFalse(fails["passes"])

        passes = self.compare(
            {"m1": ("malicious", False, []), "b1": ("benign", False, [])},
            {"m1": ("malicious", True, []), "b1": ("benign", False, [])},
        ).criterion()
        self.assertLessEqual(passes["delta_fpr"], 0)
        self.assertGreaterEqual(passes["delta_recall"], 0)
        self.assertTrue(passes["passes"])

    def test_a_fpr_drop_with_a_recall_drop_still_fails(self):
        # Zero tolerance is conjunctive: the two conditions are not a trade.
        criterion = self.compare(
            {"m1": ("malicious", True, []), "b1": ("benign", True, [])},
            {"m1": ("malicious", False, []), "b1": ("benign", False, [])},
        ).criterion()
        self.assertLess(criterion["delta_fpr"], 0)
        self.assertLess(criterion["delta_recall"], 0)
        self.assertFalse(criterion["passes"])

    def test_flagged_flips_name_the_direction_of_the_change(self):
        comparison = self.compare(
            {"m1": ("malicious", True, [("CMD_001", "a.py", 1)]),
             "b1": ("benign", False, [])},
            {"m1": ("malicious", False, []),
             "b1": ("benign", True, [("ENV_001", "a.py", 2)])},
        )
        flips = {flip["sample_id"]: flip for flip in comparison.flips()}
        self.assertEqual(flips["m1"]["direction"], "regex-only")
        self.assertEqual(flips["b1"]["direction"], "semgrep-only")
        self.assertEqual(flips["b1"]["label"], "benign")


class TestReadingRefusesSilentMisreads(ArmFixture):
    def test_arms_that_scored_different_sample_sets_are_refused(self):
        # Pairing across an unfinished run scores an infrastructure failure as a
        # detection difference, so this must not quietly read the intersection.
        with self.assertRaises(ValueError) as caught:
            self.compare(
                {"s1": ("benign", False, []), "s2": ("benign", False, [])},
                {"s1": ("benign", False, [])},
            )
        self.assertIn("different sample sets", str(caught.exception))

    def test_a_duplicate_sample_id_is_refused(self):
        root = self.tmp / "dup"
        write_arm(root, {"s1": ("benign", False, [])})
        with (root / ard.RESULTS_FILE).open("a") as handle:
            handle.write(json.dumps({"sample_id": "s1", "label": "benign",
                                     "blocked": False, "report_path": "x"}) + "\n")
        with self.assertRaises(ValueError) as caught:
            ard.load_rows(root)
        self.assertIn("duplicate sample_id", str(caught.exception))

    def test_a_missing_report_is_refused_rather_than_read_as_clean(self):
        # An absent report and a clean scan both yield no findings; reading the
        # former as the latter would score a lost artifact as a detection.
        root = self.tmp / "gone"
        write_arm(root, {"s1": ("benign", False, [("CMD_001", "a.py", 1)])})
        (root / "s1" / "audit_report.json").unlink()
        with self.assertRaises(ValueError) as caught:
            ard.compare(root, root)
        self.assertIn("report missing", str(caught.exception))

    def test_a_finding_without_a_line_is_refused(self):
        # The attribution is keyed on position; a finding without one cannot be
        # placed, and defaulting it would silently mis-attribute the difference.
        root = self.tmp / "noline"
        root.mkdir(parents=True)
        (root / "s1").mkdir()
        (root / "s1" / "audit_report.json").write_text(json.dumps(
            {"file_reports": [{"file": "a.py", "findings": [{"rule_id": "CMD_001"}]}]}))
        (root / ard.RESULTS_FILE).write_text(json.dumps(
            {"sample_id": "s1", "label": "benign", "blocked": False,
             "report_path": str(root / "s1" / "audit_report.json")}) + "\n")
        with self.assertRaises(ValueError) as caught:
            ard.load_findings(ard.load_rows(root)["s1"])
        self.assertIn("without rule_id/line", str(caught.exception))


class TestReport(ArmFixture):
    def test_the_report_carries_the_criterion_and_the_per_rule_split(self):
        comparison = self.compare(
            {"m1": ("malicious", True, [("CMD_001", "a.py", 1)]),
             "b1": ("benign", False, [])},
            {"m1": ("malicious", True, [("CMD_001", "a.py", 1), ("NET_001", "a.py", 1)]),
             "b1": ("benign", True, [("ENV_001", "a.py", 40)])},
        )
        report = ard.build_report(comparison, self.tmp / "regex", self.tmp / "semgrep")
        self.assertEqual(report["samples"], 2)
        self.assertIn("criterion", report)
        self.assertIn("per_rule", report)
        rows = {row["rule_id"]: row for row in report["per_rule"]}
        self.assertEqual(rows["NET_001"]["semgrep_shape"], 1)
        self.assertEqual(rows["ENV_001"]["semgrep_coverage"], 1)
        self.assertEqual(len(report["flagged_flips"]), 1)

    def test_the_formatted_report_states_both_causes_and_the_verdict(self):
        comparison = self.compare(
            {"b1": ("benign", False, [])},
            {"b1": ("benign", True, [("ENV_001", "a.py", 40)])},
        )
        text = ard.format_report(
            ard.build_report(comparison, self.tmp / "regex", self.tmp / "semgrep"))
        self.assertIn("coverage", text)
        self.assertIn("shape", text)
        self.assertIn("FAIL", text)
        self.assertIn("reference arm never fires this rule", text)


if __name__ == "__main__":
    unittest.main()
