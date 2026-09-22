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

import json
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
RECORD_PATH = REPO_ROOT / "models" / "audit" / "audit-results" / "engine-compare" / "rule-parity-audit.json"

BASELINE_ORDER = {rule["id"]: i for i, rule in enumerate(SUSPICIOUS_PATTERNS)}


def _sample_dirs():
    """The 100 sample directories, which sit one level under a base project.

    Iterating CORPUS_ROOT alone would yield the four base projects and scan each
    as one unit: the same files, but divergences would be attributed to a project
    instead of to the sample that carries the scoring label.
    """
    return sorted(
        sample_dir
        for base_project in CORPUS_ROOT.iterdir()
        if base_project.is_dir()
        for sample_dir in base_project.iterdir()
        if sample_dir.is_dir()
    )


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
    """One Semgrep pass over the corpus, asserted from two angles.

    The scan is done once in setUpClass rather than per test: a second method
    that rescanned would double the memory the scan needs, and this is the one
    place in the suite where that matters - running it concurrently with the
    resident Ollama model is enough to get the container OOM-killed, which under
    the old fail-open behaviour would have looked like a clean corpus.
    """

    @classmethod
    def setUpClass(cls):
        if not CORPUS_ROOT.is_dir():
            raise unittest.SkipTest(f"corpus not present: {CORPUS_ROOT}")

        regex_adapter = RegexScannerAdapter()
        semgrep_adapter = SemgrepScannerAdapter()

        cls.sample_count = 0
        cls.regex_total = 0
        cls.semgrep_total = 0
        cls.divergences = []
        cls.snippet_mismatches = []
        cls.snippet_checked = 0

        for sample_dir in _sample_dirs():
            cls.sample_count += 1
            regex_outcome = regex_adapter.scan_directory(str(sample_dir))
            semgrep_outcome = semgrep_adapter.scan_directory(str(sample_dir))

            regex_rows = _collapse_first_match(regex_outcome)
            semgrep_rows = _collapse_first_match(semgrep_outcome)
            cls.regex_total += len(regex_rows)
            cls.semgrep_total += len(semgrep_rows)

            regex_only = sorted(regex_rows - semgrep_rows)
            semgrep_only = sorted(semgrep_rows - regex_rows)
            if regex_only or semgrep_only:
                cls.divergences.append((sample_dir.name, regex_only, semgrep_only))

            # The snippet is what the LLM is asked to adjudicate, so it has to be
            # the source line. Semgrep CE returns the literal "requires login" in
            # its own lines field, which is what used to be forwarded here.
            for finding in semgrep_outcome.findings:
                source = Path(finding.file)
                lines = source.read_text(encoding="utf-8", errors="ignore").splitlines()
                if not 0 < finding.line <= len(lines):
                    continue
                cls.snippet_checked += 1
                expected = lines[finding.line - 1].strip()
                if finding.code_snippet != expected:
                    cls.snippet_mismatches.append(
                        f"\n  {source.name}:{finding.line}"
                        f"\n    snippet:  {finding.code_snippet!r}"
                        f"\n    source:   {expected!r}"
                    )

    def test_the_comparison_is_not_vacuous(self):
        """Two empty finding lists agree trivially, so the arms must have fired."""
        self.assertGreater(
            self.regex_total, 0, "the regex arm reported nothing across the corpus - comparison is vacuous"
        )
        self.assertGreater(
            self.semgrep_total, 0, "the semgrep arm reported nothing across the corpus - comparison is vacuous"
        )

    def test_the_audit_leaves_a_machine_readable_record(self):
        """The report cites numbers, so the run has to produce them.

        This is an audit rather than a unit test: its output is evidence, and
        evidence that exists only as test stdout cannot be checked later. Written
        even when the run diverges, since a failing audit is the one whose numbers
        matter most.
        """
        summary = {
            "corpus_root": str(CORPUS_ROOT.relative_to(REPO_ROOT)),
            "samples_scanned": self.sample_count,
            "samples_with_a_divergence": len(self.divergences),
            "regex_findings": self.regex_total,
            "semgrep_findings": self.semgrep_total,
            "semgrep_snippets_verified": self.snippet_checked,
            "semgrep_snippet_mismatches": len(self.snippet_mismatches),
            "divergences": [
                {
                    "sample_id": name,
                    "regex_only": [[line, rule] for _, line, rule in regex_only],
                    "semgrep_only": [[line, rule] for _, line, rule in semgrep_only],
                }
                for name, regex_only, semgrep_only in self.divergences
            ],
        }
        RECORD_PATH.parent.mkdir(parents=True, exist_ok=True)
        RECORD_PATH.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def test_every_audit_100_sample_agrees_between_the_arms(self):
        if self.divergences:
            report = []
            for name, regex_only, semgrep_only in self.divergences:
                report.append(
                    f"\n  {name}"
                    f"\n    regex only:   {[(line, rule) for _, line, rule in regex_only]}"
                    f"\n    semgrep only: {[(line, rule) for _, line, rule in semgrep_only]}"
                )
            self.fail(
                f"{len(self.divergences)}/{self.sample_count} samples disagree between the two arms:"
                + "".join(report)
            )

    def test_semgrep_code_snippets_are_the_real_source_lines(self):
        self.assertGreater(
            self.snippet_checked, 0, "no semgrep finding was checked - the snippet assertion is vacuous"
        )
        self.assertEqual(
            self.snippet_mismatches,
            [],
            f"{len(self.snippet_mismatches)}/{self.snippet_checked} findings do not match the source:"
            + "".join(self.snippet_mismatches),
        )


if __name__ == "__main__":
    unittest.main()
