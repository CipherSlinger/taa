# tests/test_corpus_gate_semantics.py
"""Whether the corpus is judged the same way by the eval mirror and the gate.

Spec 9.8 registers a divergence the engine comparison cannot see past: the
production gate blocks only when a HIGH finding survives arbitration
(`report.Passed = highCount == 0`, `internal/codeaudit/verifier.go:160-178`),
whereas the Python evaluation mirror treats HIGH and MEDIUM alike - both arm a
suspicion when no verdict exonerates, and both can be exonerated by a BENIGN
verdict. Severity is therefore load-bearing in production and decorative in the
benchmark.

That asymmetry has a direction, and the direction is what makes it worth
measuring rather than footnoting. A malicious sample whose strongest finding is
MEDIUM is counted as a true positive by the mirror, while production would pass it
without the LLM even being consulted - so measured recall can exceed anything
production delivers. The benign direction is milder: a benign sample whose
strongest finding is MEDIUM is charged to the arm as a false positive production
would not have raised, so measured FPR is an upper bound on the production one.

Measured on this corpus, the malicious direction is not hypothetical. All ten M3
samples are caught only by MEDIUM rules, and deliberately so - the family is
declared `expected_severity="MEDIUM"` for secret theft through `FIL_001`/`ENV_001`.
That is 10 of the 50 malicious samples, so the absolute recall this round reports
is not a production-blocking recall. It does not touch the comparison itself: the
two arms share the rule set, so both carry the same inflation and the difference
between them is unaffected.

The corpus is scanned with the regex arm alone. Both arms report identical rule
sets on this corpus (asserted by `test_engine_rule_parity_corpus`), so severity
needs no second engine, and the regex arm is the one that can run beside the
resident Ollama model without risking the container.

This records existing behaviour rather than describing new behaviour. Correcting
the divergence means changing an evaluation asset, which would alter historical
comparability and has to be applied to both arms with a re-measurement (spec
12.4); it is not this round's work.
"""

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools.audit_benchmark_eval import RegexScannerAdapter  # noqa: E402
from models.examples.code_security_analyzer import SUSPICIOUS_PATTERNS  # noqa: E402

CORPUS_ROOT = REPO_ROOT / "models" / "audit" / "benchmarks" / "audit-100"
RECORD_PATH = (
    REPO_ROOT / "models" / "audit" / "audit-results" / "engine-compare" / "gate-semantics-audit.json"
)

SEVERITY_BY_RULE = {rule["id"]: rule["severity"] for rule in SUSPICIOUS_PATTERNS}

# The severities the production gate acts on. Named once so re-severitying a rule
# cannot quietly move this audit's conclusion along with it.
BLOCKING_SEVERITIES = frozenset({"HIGH", "CRITICAL"})


def classify(severities) -> str:
    """Bucket a sample by whether the production gate could act on its findings.

    `blocking` means at least one finding is a severity the gate blocks on, so the
    sample's fate is decided by the LLM verdict exactly as the mirror models it.
    `non_blocking` means every finding is below that bar: the mirror still counts
    the sample as detected, but production passes it with no LLM involvement, and
    the two disagree. `not_flagged` is a clean scan.
    """
    severities = set(severities)
    if not severities:
        return "not_flagged"
    if severities & BLOCKING_SEVERITIES:
        return "blocking"
    return "non_blocking"


def _sample_dirs():
    """The 100 sample directories, one level under each base project."""
    return sorted(
        sample_dir
        for base_project in CORPUS_ROOT.iterdir()
        if base_project.is_dir()
        for sample_dir in base_project.iterdir()
        if sample_dir.is_dir()
    )


class TestClassification(unittest.TestCase):
    """The bucketing rule, on inputs written out rather than scanned.

    The corpus scan below is a measurement; this is the logic the measurement is
    read through. Keeping them in separate classes is what stops a wrong bucket
    from being validated by the corpus agreeing with it.
    """

    def test_a_clean_scan_is_not_flagged(self):
        self.assertEqual(classify([]), "not_flagged")

    def test_a_high_finding_can_be_blocked(self):
        self.assertEqual(classify(["HIGH"]), "blocking")

    def test_a_medium_finding_alone_cannot_be_blocked(self):
        self.assertEqual(classify(["MEDIUM"]), "non_blocking")

    def test_one_high_among_mediums_still_makes_the_sample_blockable(self):
        """The bucket keys on the strongest finding, not on the first or the count."""
        self.assertEqual(classify(["HIGH", "MEDIUM", "MEDIUM"]), "blocking")
        self.assertEqual(classify(["MEDIUM", "HIGH"]), "blocking")

    def test_a_critical_finding_is_blocking(self):
        self.assertEqual(classify(["CRITICAL"]), "blocking")


class TestCorpusGateSemantics(unittest.TestCase):
    """One regex pass over the corpus, recorded for the report."""

    @classmethod
    def setUpClass(cls):
        if not CORPUS_ROOT.is_dir():
            raise unittest.SkipTest(f"corpus not present: {CORPUS_ROOT}")

        adapter = RegexScannerAdapter()
        cls.records = []
        for sample_dir in _sample_dirs():
            # `<family>-<nn>`: the directory name is all the corpus states about
            # the sample, and the expectation lives in the generator.
            family = sample_dir.name.split("-")[0]
            label = "benign" if family.startswith("B") else "malicious"
            outcome = adapter.scan_directory(str(sample_dir))
            severities = sorted(
                {SEVERITY_BY_RULE.get(finding.rule_id, "UNKNOWN") for finding in outcome.findings}
            )
            cls.records.append({
                "sample_id": sample_dir.name,
                "family": family,
                "label": label,
                "rules": sorted({finding.rule_id for finding in outcome.findings}),
                "severities": severities,
                "bucket": classify(severities),
            })
        cls._write_record()

    @classmethod
    def _write_record(cls):
        """The numbers the report cites have to be re-derivable, not transcribed."""
        def ids(label, bucket):
            return [r["sample_id"] for r in cls.records if r["label"] == label and r["bucket"] == bucket]

        cls.record = {
            "corpus_root": str(CORPUS_ROOT.relative_to(REPO_ROOT)),
            "blocking_severities": sorted(BLOCKING_SEVERITIES),
            "samples_scanned": len(cls.records),
            # The measurement the report must carry: detections the mirror counts
            # and a production gate would not act on.
            "malicious_non_blocking": ids("malicious", "non_blocking"),
            "benign_non_blocking": ids("benign", "non_blocking"),
            "malicious_not_flagged": ids("malicious", "not_flagged"),
            "benign_not_flagged": ids("benign", "not_flagged"),
            "buckets_by_family": {
                family: {
                    bucket: sum(
                        1 for r in cls.records if r["family"] == family and r["bucket"] == bucket
                    )
                    for bucket in ("blocking", "non_blocking", "not_flagged")
                }
                for family in sorted({r["family"] for r in cls.records})
            },
            "per_sample": cls.records,
        }
        RECORD_PATH.parent.mkdir(parents=True, exist_ok=True)
        RECORD_PATH.write_text(
            json.dumps(cls.record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    def test_the_audit_is_not_vacuous(self):
        """A bucket only means something if the arm flagged samples at all.

        An arm that found nothing would put every sample in `not_flagged` and the
        recorded buckets would describe nothing, which is the same empty-set pass
        the corpus parity audit guards against.
        """
        flagged = [r for r in self.records if r["bucket"] != "not_flagged"]
        self.assertGreater(len(flagged), 0, "the static arm flagged nothing across the corpus")
        self.assertGreater(
            len([r for r in flagged if r["label"] == "malicious"]), 0,
            "no malicious sample was flagged, so the malicious buckets are empty",
        )

    def test_every_sample_lands_in_exactly_one_bucket(self):
        self.assertEqual(len(self.records), 100)
        for record in self.records:
            self.assertIn(record["bucket"], {"blocking", "non_blocking", "not_flagged"})

    def test_the_non_blocking_malicious_samples_are_recorded_for_the_report(self):
        """The measured exposure, not an argument from the rule list.

        Spec 9.8.2 asserted the malicious families' primary rules were all HIGH and
        asked for the four MEDIUM rules to be checked one by one. Checked, the
        assertion does not hold: M3's attack reaches only MEDIUM. The count is
        recorded here so the report states it as a measurement.
        """
        self.assertIn("malicious_non_blocking", self.record)
        self.assertIn("M3-01", self.record["malicious_non_blocking"])

    def test_the_benign_direction_is_recorded_even_though_it_is_not_a_defect(self):
        self.assertIn("benign_non_blocking", self.record)


if __name__ == "__main__":
    unittest.main()
