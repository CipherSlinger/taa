# models/audit/tools/arm_rule_divergence.py
"""Attribute the difference between two engine arms to rules, shape, or coverage.

The holdout comparison decides whether the Semgrep arm may replace the regex
arm, and it does so on final verdicts. When the two arms disagree, the verdict
counts say *that* they disagree but not *why*, and the remedy differs by cause:

- A **shape** difference is the scanner harness. The regex arm keeps one finding
  per line (it breaks on the first match in SUSPICIOUS_PATTERNS order) while the
  Semgrep arm reports every matching rule, so a line that both arms flag can
  contribute a different number of findings without any rule differing at all
  (see tests/test_engine_rule_parity_corpus.py, which normalizes exactly this).
- A **coverage** difference is the rules or the engine: the other arm reported
  nothing on that line. Import-aware matching (`from urllib.request import
  urlopen`) and AST parsing are engine capabilities and are what the comparison
  exists to measure; a rule whose *pattern* was ported more loosely than the
  baseline is a porting defect, and the plan's rule-alignment loop (§9.4) is the
  place for it.

Telling those apart requires the line, which the summary rows do not carry, so
this reads each row's own `report_path`. Every number comes from artifacts the
evaluation pipeline wrote, not from a re-scan: a second scan would measure a
different run, and the reading would no longer describe the evidence the
criterion was computed from.

One signal is worth calling out because it is decisive when it appears: a rule
that fires on the reference arm **zero** times across the whole corpus while the
other arm fires it many times cannot be a difference in engine capability. The
reference arm had no opportunity to differ; the two rules are simply not the
same rule.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools.audit_benchmark_eval import confusion_counts  # noqa: E402

RESULTS_FILE = "sample-results.jsonl"

# How a finding present in one arm and absent from the other is explained.
COVERAGE = "coverage"
SHAPE = "shape"


@dataclass(frozen=True)
class Finding:
    """The identity a divergence is attributed at: which rule, where."""

    rule_id: str
    file: str
    line: int

    @property
    def location(self) -> Tuple[str, int]:
        return (self.file, self.line)


def load_rows(results_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Read a results directory's per-sample rows, keyed by sample id."""
    path = Path(results_dir) / RESULTS_FILE
    rows: Dict[str, Dict[str, Any]] = {}
    with path.open() as handle:
        for lineno, raw in enumerate(handle, 1):
            raw = raw.strip()
            if not raw:
                continue
            row = json.loads(raw)
            sample_id = row.get("sample_id")
            if not sample_id:
                raise ValueError(f"{path}:{lineno}: row carries no sample_id")
            if sample_id in rows:
                # The criterion is computed per sample, so a duplicate silently
                # double-counts one sample and drops another.
                raise ValueError(f"{path}:{lineno}: duplicate sample_id {sample_id!r}")
            rows[sample_id] = row
    if not rows:
        raise ValueError(f"{path}: no rows")
    return rows


def load_findings(row: Dict[str, Any]) -> List[Finding]:
    """Read the findings an arm recorded for one sample, from its own report.

    A row whose report is missing is an error rather than an empty arm: an
    absent report and a clean scan both yield no findings, and reading the
    former as the latter would score an infrastructure failure as a detection.
    """
    report_path = row.get("report_path")
    if not report_path:
        raise ValueError(f"{row.get('sample_id')!r}: row carries no report_path")
    path = Path(report_path)
    if not path.exists():
        raise ValueError(f"{row.get('sample_id')!r}: report missing at {path}")
    doc = json.loads(path.read_text())
    findings: List[Finding] = []
    for file_report in doc.get("file_reports", []):
        for finding in file_report.get("findings", []):
            rule_id = finding.get("rule_id")
            line = finding.get("line")
            if not rule_id or line is None:
                raise ValueError(
                    f"{row.get('sample_id')!r}: finding without rule_id/line in {path}"
                )
            findings.append(Finding(rule_id, file_report.get("file", ""), int(line)))
    return findings


def locations(findings: Iterable[Finding]) -> Dict[Tuple[str, int], set]:
    """Group findings by the source position they occupy."""
    grouped: Dict[Tuple[str, int], set] = {}
    for finding in findings:
        grouped.setdefault(finding.location, set()).add(finding.rule_id)
    return grouped


@dataclass(frozen=True)
class Attribution:
    """One arm's finding that the other arm does not have, and why."""

    sample_id: str
    label: str
    rule_id: str
    kind: str  # COVERAGE or SHAPE
    file: str
    line: int
    # For SHAPE, the rules the other arm used at the same position.
    other_rules: Tuple[str, ...] = ()


def attribute(
    sample_id: str,
    label: str,
    mine: Sequence[Finding],
    theirs: Sequence[Finding],
) -> List[Attribution]:
    """Explain the findings in `mine` that `theirs` does not account for.

    Findings are matched as a multiset on (rule, position), not as a set: one arm
    can report the same rule at the same line more than once, and matching by set
    would silently absorb a duplicate in one arm against a single finding in the
    other. The counts per rule are multisets for the same reason, so the two have
    to agree - `semgrep_only - regex_only` equals `semgrep - regex` in totals,
    which `test_the_attribution_accounts_for_every_finding` checks.

    A finding left over when the other arm has no findings at that position is a
    difference in the rules or in the engine. When the other arm does have
    findings there, the position was flagged by both arms and only the reporting
    differs, which is shape - either because the other arm used different rules
    (the harness keeps the first match on the line) or because it reported the
    same rule a different number of times (the harness reports every match).
    `other_rules` names what the other arm used there, so the two are told apart
    by whether the leftover's own rule appears in it.
    """
    their_counts = Counter((f.rule_id, f.file, f.line) for f in theirs)
    their_positions = locations(theirs)
    out: List[Attribution] = []
    for finding in mine:
        key = (finding.rule_id, finding.file, finding.line)
        if their_counts[key] > 0:
            their_counts[key] -= 1
            continue
        at_position = their_positions.get(finding.location)
        if at_position:
            out.append(Attribution(
                sample_id, label, finding.rule_id, SHAPE,
                finding.file, finding.line, tuple(sorted(at_position)),
            ))
        else:
            out.append(Attribution(
                sample_id, label, finding.rule_id, COVERAGE, finding.file, finding.line,
            ))
    return out


@dataclass
class ArmComparison:
    """Everything the comparison reports, computed once."""

    regex_rows: Dict[str, Dict[str, Any]]
    semgrep_rows: Dict[str, Dict[str, Any]]
    regex_findings: Dict[str, List[Finding]]
    semgrep_findings: Dict[str, List[Finding]]
    regex_only: List[Attribution]
    semgrep_only: List[Attribution]

    @property
    def sample_ids(self) -> List[str]:
        return sorted(self.regex_rows)

    def totals(self, arm: str) -> Counter:
        findings = self.regex_findings if arm == "regex" else self.semgrep_findings
        counter: Counter = Counter()
        for sample_findings in findings.values():
            for finding in sample_findings:
                counter[finding.rule_id] += 1
        return counter

    def per_rule(self) -> List[Dict[str, Any]]:
        """Per-rule totals with each arm's unmatched findings split by cause."""
        regex_totals, semgrep_totals = self.totals("regex"), self.totals("semgrep")
        rows = []
        for rule_id in sorted(set(regex_totals) | set(semgrep_totals)):
            gained = [a for a in self.semgrep_only if a.rule_id == rule_id]
            lost = [a for a in self.regex_only if a.rule_id == rule_id]
            rows.append({
                "rule_id": rule_id,
                "regex": regex_totals[rule_id],
                "semgrep": semgrep_totals[rule_id],
                "delta": semgrep_totals[rule_id] - regex_totals[rule_id],
                "semgrep_coverage": sum(1 for a in gained if a.kind == COVERAGE),
                "semgrep_shape": sum(1 for a in gained if a.kind == SHAPE),
                "regex_coverage": sum(1 for a in lost if a.kind == COVERAGE),
                "regex_shape": sum(1 for a in lost if a.kind == SHAPE),
                # A rule the reference arm never fires cannot be a capability
                # difference: the reference had no chance to disagree.
                "inert_on_reference": regex_totals[rule_id] == 0,
            })
        return rows

    def diverging_samples(self) -> List[Dict[str, Any]]:
        by_sample: Dict[str, Dict[str, Any]] = {}
        for attribution in self.semgrep_only + self.regex_only:
            entry = by_sample.setdefault(attribution.sample_id, {
                "sample_id": attribution.sample_id,
                "label": attribution.label,
                "semgrep_only": Counter(),
                "regex_only": Counter(),
            })
            target = "semgrep_only" if attribution in self.semgrep_only else "regex_only"
            entry[target][attribution.rule_id] += 1
        return [
            {
                "sample_id": entry["sample_id"],
                "label": entry["label"],
                "semgrep_only": dict(entry["semgrep_only"]),
                "regex_only": dict(entry["regex_only"]),
            }
            for entry in sorted(by_sample.values(), key=lambda e: e["sample_id"])
        ]

    def flagged(self, arm: str) -> Dict[str, bool]:
        """Per-sample flag state, taken from each row's own recorded verdict.

        The rows are used rather than the findings so that this reads the same
        predicate the criterion does, including any policy the pipeline applied.
        """
        rows = self.regex_rows if arm == "regex" else self.semgrep_rows
        return {sid: bool(row.get("blocked", False)) for sid, row in rows.items()}

    def flips(self) -> List[Dict[str, Any]]:
        """Samples whose flagged state differs between the arms."""
        left, right = self.flagged("regex"), self.flagged("semgrep")
        out = []
        for sample_id in self.sample_ids:
            if left[sample_id] != right[sample_id]:
                out.append({
                    "sample_id": sample_id,
                    "label": self.regex_rows[sample_id].get("label"),
                    "regex_flagged": left[sample_id],
                    "semgrep_flagged": right[sample_id],
                    "direction": "regex-only" if left[sample_id] else "semgrep-only",
                })
        return out

    def criterion(self) -> Dict[str, Any]:
        """The criterion's own numbers, computed by the pipeline's own counter."""
        regex_counts = confusion_counts(list(self.regex_rows.values()))
        semgrep_counts = confusion_counts(list(self.semgrep_rows.values()))

        def rate(counts: Dict[str, int]) -> Dict[str, float]:
            return {
                "recall": counts["tp"] / (counts["tp"] + counts["fn"])
                if counts["tp"] + counts["fn"] else 0.0,
                "fpr": counts["fp"] / (counts["fp"] + counts["tn"])
                if counts["fp"] + counts["tn"] else 0.0,
            }

        regex_rate, semgrep_rate = rate(regex_counts), rate(semgrep_counts)
        delta_fpr = semgrep_rate["fpr"] - regex_rate["fpr"]
        delta_recall = semgrep_rate["recall"] - regex_rate["recall"]
        return {
            "regex": {**regex_counts, **regex_rate},
            "semgrep": {**semgrep_counts, **semgrep_rate},
            "delta_fpr": delta_fpr,
            "delta_recall": delta_recall,
            "passes": delta_fpr <= 0 and delta_recall >= 0,
        }


def compare(regex_dir: Path, semgrep_dir: Path) -> ArmComparison:
    """Load both arms and attribute every finding one has and the other lacks."""
    regex_rows = load_rows(regex_dir)
    semgrep_rows = load_rows(semgrep_dir)
    missing = set(regex_rows) ^ set(semgrep_rows)
    if missing:
        # The comparison is paired. A sample only one arm scored is not a
        # detection difference, and pairing it would score an unfinished run as
        # one, so this refuses rather than reading the intersection.
        raise ValueError(
            f"arms scored different sample sets ({len(missing)} differ, "
            f"e.g. {sorted(missing)[:5]})"
        )

    regex_findings = {sid: load_findings(row) for sid, row in regex_rows.items()}
    semgrep_findings = {sid: load_findings(row) for sid, row in semgrep_rows.items()}

    regex_only: List[Attribution] = []
    semgrep_only: List[Attribution] = []
    for sample_id in sorted(regex_rows):
        label = regex_rows[sample_id].get("label", "unknown")
        regex_only.extend(attribute(
            sample_id, label, regex_findings[sample_id], semgrep_findings[sample_id]))
        semgrep_only.extend(attribute(
            sample_id, label, semgrep_findings[sample_id], regex_findings[sample_id]))

    return ArmComparison(
        regex_rows=regex_rows, semgrep_rows=semgrep_rows,
        regex_findings=regex_findings, semgrep_findings=semgrep_findings,
        regex_only=regex_only, semgrep_only=semgrep_only,
    )


def build_report(comparison: ArmComparison, regex_dir: Path, semgrep_dir: Path) -> Dict[str, Any]:
    criterion = comparison.criterion()
    return {
        "source": "models/audit/tools/arm_rule_divergence.py",
        "note": (
            "Attributes every finding one arm reports and the other does not to a "
            "cause: 'coverage' when the other arm reported nothing at that position, "
            "'shape' when it reported other rules there (the harness's one-per-line "
            "vs every-match reporting). Counts come from the arms' own pipeline "
            "artifacts, not from a re-scan."
        ),
        "regex_results": str(regex_dir),
        "semgrep_results": str(semgrep_dir),
        "samples": len(comparison.sample_ids),
        "criterion": criterion,
        "per_rule": comparison.per_rule(),
        "flagged_flips": comparison.flips(),
        "diverging_samples": comparison.diverging_samples(),
    }


def format_report(report: Dict[str, Any]) -> str:
    lines = []
    criterion = report["criterion"]
    lines.append(f"samples compared: {report['samples']}")
    lines.append("")
    lines.append("criterion (as the pipeline computes it, from each row's own verdict)")
    for arm in ("regex", "semgrep"):
        row = criterion[arm]
        lines.append(
            f"  {arm:<8} TP={row['tp']:<4} FP={row['fp']:<4} TN={row['tn']:<4} FN={row['fn']:<4}"
            f"  recall={row['recall']:.4f}  FPR={row['fpr']:.4f}")
    lines.append(f"  dFPR={criterion['delta_fpr']:+.4f}  drecall={criterion['delta_recall']:+.4f}"
                 f"  -> {'PASS' if criterion['passes'] else 'FAIL'}")
    lines.append("")
    lines.append("per rule (semgrep - regex), with each arm's unmatched findings split by cause")
    lines.append("  sg_cov/sg_shape: semgrep-only findings at a position the regex arm did not")
    lines.append("  flag at all (coverage) / flagged under other rules (shape); rx_cov/rx_shape")
    lines.append("  are the same two causes for findings only the regex arm has")
    lines.append(f"  {'rule':<10}{'regex':>6}{'semgrep':>8}{'delta':>7}"
                 f"{'sg_cov':>8}{'sg_shape':>9}{'rx_cov':>8}{'rx_shape':>9}   note")
    for row in report["per_rule"]:
        note = "reference arm never fires this rule" if row["inert_on_reference"] else ""
        lines.append(
            f"  {row['rule_id']:<10}{row['regex']:>6}{row['semgrep']:>8}{row['delta']:>+7}"
            f"{row['semgrep_coverage']:>8}{row['semgrep_shape']:>9}"
            f"{row['regex_coverage']:>8}{row['regex_shape']:>9}   {note}")
    lines.append("")
    lines.append(f"flagged-state flips: {len(report['flagged_flips'])}")
    for flip in report["flagged_flips"]:
        lines.append(f"  {flip['sample_id']:<10} {flip['label']:<9} {flip['direction']}")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--regex-results", required=True, type=Path)
    parser.add_argument("--semgrep-results", required=True, type=Path)
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    comparison = compare(args.regex_results, args.semgrep_results)
    report = build_report(comparison, args.regex_results, args.semgrep_results)
    if not args.quiet:
        print(format_report(report))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        if not args.quiet:
            print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
