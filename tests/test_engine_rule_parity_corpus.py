# tests/test_engine_rule_parity_corpus.py
"""Corpus-level parity audit over audit-100 - the acceptance gate for rule alignment.

`test_engine_rule_parity` compares the two rule sets over hand-written fixtures.
This compares them over the real corpus, and it is the check that caught the
EMB_001 over-reporting on train.py:99/105 that no fixture happened to cover.
Fixtures say what the rules should do on the constructs someone thought of; this
says what they do on the samples the benchmark actually scores.

Opt-in, because it runs a full Semgrep scan per sample (minutes, and it needs
Semgrep installed). Set TAA_CORPUS_PARITY=1 to run it:

    TAA_CORPUS_PARITY=1 python3 -m unittest tests.test_engine_rule_parity_corpus

The expectation is the regex arm, not a written-down list: StaticScanner is the
control the Semgrep arm is being compared against, so any construct only one arm
reports is a difference in the rules rather than in the engine. Semgrep reports
every matching rule while the baseline keeps one per line (it breaks on the first
match in SUSPICIOUS_PATTERNS order), so Semgrep's rows are collapsed to the same
first-match-wins shape first - that part is the scanner harness, not the rules.
"""

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools.audit_benchmark_eval import (  # noqa: E402
    RegexScannerAdapter,
    SemgrepScannerAdapter,
)
from models.examples.code_security_analyzer import SUSPICIOUS_PATTERNS  # noqa: E402

CORPUS_ROOT = REPO_ROOT / "models" / "audit" / "benchmarks" / "audit-100"

BASELINE_ORDER = {rule["id"]: i for i, rule in enumerate(SUSPICIOUS_PATTERNS)}


def _collapse_first_match(outcome):
    """Reduce findings to (file, line, rule) with the baseline's precedence."""
    per_site = {}
    for finding in outcome.findings:
        key = (finding.file, finding.line)
        rank = BASELINE_ORDER.get(finding.rule_id, len(BASELINE_ORDER))
        if key not in per_site or rank < per_site[key][0]:
            per_site[key] = (rank, finding.rule_id)
    return {(file_path, line, rule_id) for (file_path, line), (_, rule_id) in per_site.items()}


@unittest.skipUnless(
    os.environ.get("TAA_CORPUS_PARITY") == "1",
    "opt-in: set TAA_CORPUS_PARITY=1 (full Semgrep scan of audit-100, takes minutes)",
)
class TestCorpusRuleParity(unittest.TestCase):
    def test_every_audit_100_sample_agrees_between_the_arms(self):
        if not CORPUS_ROOT.is_dir():
            self.skipTest(f"corpus not present: {CORPUS_ROOT}")

        regex_adapter = RegexScannerAdapter()
        semgrep_adapter = SemgrepScannerAdapter()
        sample_dirs = sorted(p for p in CORPUS_ROOT.iterdir() if p.is_dir())

        divergences = []
        regex_total = 0
        semgrep_total = 0
        for sample_dir in sample_dirs:
            regex_rows = _collapse_first_match(regex_adapter.scan_directory(str(sample_dir)))
            semgrep_rows = _collapse_first_match(semgrep_adapter.scan_directory(str(sample_dir)))
            regex_total += len(regex_rows)
            semgrep_total += len(semgrep_rows)

            regex_only = sorted(regex_rows - semgrep_rows)
            semgrep_only = sorted(semgrep_rows - regex_rows)
            if regex_only or semgrep_only:
                divergences.append((sample_dir.name, regex_only, semgrep_only))

        # Two empty finding lists agree trivially, so a corpus where neither
        # scanner ran would pass the comparison below. The split is 50 benign and
        # 50 malicious samples and the static rules are meant to hit the
        # malicious half, so silence here means the scan did not happen.
        self.assertGreater(
            regex_total, 0, "the regex arm reported nothing across the whole corpus - comparison is vacuous"
        )
        self.assertGreater(
            semgrep_total, 0, "the semgrep arm reported nothing across the whole corpus - comparison is vacuous"
        )

        if divergences:
            report = []
            for name, regex_only, semgrep_only in divergences:
                report.append(
                    f"\n  {name}"
                    f"\n    regex only:   {[(line, rule) for _, line, rule in regex_only]}"
                    f"\n    semgrep only: {[(line, rule) for _, line, rule in semgrep_only]}"
                )
            self.fail(
                f"{len(divergences)}/{len(sample_dirs)} samples disagree between the two arms:"
                + "".join(report)
            )


if __name__ == "__main__":
    unittest.main()
