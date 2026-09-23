# tests/test_audit_eval_llm_dedup.py
"""Duplicate hits on one line must not buy extra LLM arbitrations.

Semgrep reports every match, while the regex baseline reports only the first
matching rule per line. The same construct therefore reaches the LLM once under
regex and several times under semgrep. Arbitrations per sample are capped, and
each one is an independent chance for a finding to come back suspicious or
malicious - which is what drives the block decision. Without deduplication the
cap converts a difference in reporting density into a difference in false
positive rate, and false positive rate is one of the two quantities the engine
comparison exists to measure.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from models.audit.tools import audit_benchmark_eval as ev
from models.examples.code_security_analyzer import FileSummary


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


def make_finding(file: str, line: int, rule_id: str, severity: str = "HIGH") -> ev.Finding:
    return ev.Finding(
        file=file, line=line, rule_id=rule_id, category="command",
        severity=severity, description="", code_snippet="os.system(x)",
        context_before="", context_after="", engine="semgrep",
    )


class StubScanner:
    """Stands in for an engine adapter, returning a fixed ScanOutcome."""

    def __init__(self, outcome):
        self.outcome = outcome

    def scan_directory(self, dirpath, extensions=(".py",)):
        return self.outcome


class RecordingAnalyzer:
    """Records what the pipeline asked the LLM to arbitrate."""

    def __init__(self):
        self.finding_calls = []
        self.file_calls = []

    def analyze_finding(self, finding):
        self.finding_calls.append((finding.file, finding.rule_id, finding.line))
        return finding

    def analyze_file(self, file_path, findings):
        self.file_calls.append(
            (file_path, sorted((f.rule_id, f.line) for f in findings))
        )
        return FileSummary(risk_level="BENIGN", summary="", chained=False, exfiltration=False)


class TestLLMArbitrationIsDeduplicated(unittest.TestCase):
    def _analyse(self, findings, max_findings: int = 50, label: str = "benign"):
        analyzer = RecordingAnalyzer()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample_dir = root / "p1_xgboost_finance" / "X-01"
            sample_dir.mkdir(parents=True)
            (sample_dir / "train.py").write_text("print('hi')\n", encoding="utf-8")
            with patch.object(ev, "load_module_scanner",
                              return_value=StubScanner(ev.ScanOutcome(findings=findings, scan_complete=True))), \
                 patch.object(ev, "build_analyzer", return_value=analyzer):
                row = ev.analyse_sample(
                    sample=make_sample(label),
                    sample_dir=sample_dir,
                    results_dir=root / "results",
                    audit_mode="static-llm",
                    policy="gate",
                    llm_backend="ollama",
                    llm_model="qwen2.5-coder:3b",
                    extensions=(".py",),
                    max_findings=max_findings,
                    engine="semgrep",
                )
        return row, analyzer

    def test_repeated_hits_on_one_line_are_arbitrated_once(self):
        """Three matches of the same rule on the same line are one question, not three."""
        findings = [
            make_finding("train.py", 3, "CMD_001"),
            make_finding("train.py", 3, "CMD_001"),
            make_finding("train.py", 3, "CMD_001"),
            make_finding("train.py", 9, "NET_001"),
        ]
        _, analyzer = self._analyse(findings, max_findings=2)

        self.assertEqual(
            sorted(set(analyzer.finding_calls)),
            [("train.py", "CMD_001", 3), ("train.py", "NET_001", 9)],
            "the cap must cover distinct (file, rule, line) hits, not duplicates",
        )
        self.assertEqual(len(analyzer.finding_calls), 2, "no duplicate arbitration")

    def test_duplicates_do_not_starve_later_distinct_hits(self):
        """A wall of duplicates must not use up the cap that other hits need.

        This is the asymmetric case: under the cap, duplicates push distinct
        hits out of the budget, and only the arm that reports duplicates loses
        the arbitration of the hits behind them.
        """
        findings = [make_finding("train.py", 3, "CMD_001") for _ in range(5)]
        findings.append(make_finding("train.py", 9, "NET_001"))
        _, analyzer = self._analyse(findings, max_findings=2)

        self.assertEqual(
            sorted(set(analyzer.finding_calls)),
            [("train.py", "CMD_001", 3), ("train.py", "NET_001", 9)],
        )

    def test_the_same_line_in_two_files_is_two_questions(self):
        """Deduplication keys on the file as well, or it would merge real hits."""
        findings = [
            make_finding("train.py", 3, "CMD_001"),
            make_finding("model.py", 3, "CMD_001"),
        ]
        _, analyzer = self._analyse(findings)

        self.assertEqual(
            sorted(set(analyzer.finding_calls)),
            [("model.py", "CMD_001", 3), ("train.py", "CMD_001", 3)],
        )

    def test_the_file_level_call_sees_the_same_deduplicated_view(self):
        """Both prompt levels must describe the same hits, or the arms differ again."""
        findings = [
            make_finding("train.py", 3, "CMD_001"),
            make_finding("train.py", 3, "CMD_001"),
            make_finding("train.py", 9, "NET_001"),
        ]
        _, analyzer = self._analyse(findings)

        self.assertEqual(
            analyzer.file_calls,
            [("train.py", [("CMD_001", 3), ("NET_001", 9)])],
        )

    def test_the_report_still_counts_every_finding(self):
        """Deduplication is an arbitration rule, not a licence to hide findings."""
        findings = [
            make_finding("train.py", 3, "CMD_001"),
            make_finding("train.py", 3, "CMD_001"),
            make_finding("train.py", 3, "CMD_001"),
            make_finding("train.py", 9, "NET_001"),
        ]
        row, _ = self._analyse(findings)

        stats = row["audit_report"]["statistics"]
        self.assertEqual(stats["total_findings"], 4)
        self.assertEqual(stats["high"], 4)


if __name__ == "__main__":
    unittest.main()
