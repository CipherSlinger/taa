# models/audit/tools/engine_compare_report.py
"""Paired non-inferiority analysis over the six engine-compare runs.

Spec 5.3 judges the Semgrep arm pair by pair, with zero tolerance: within each of
the three pairs, dFPR must be <= 0 and drecall must be >= 0. That is a statement
about every pair rather than about an average, so it cannot be read off two
independent confidence intervals, and it cannot be recovered from a summary: the
comparison is made sample by sample inside a pair, where the same sample is
measured under both arms and only the engine differs.

Two rules keep the arithmetic from flattering either arm:

- A sample is paired only when both arms actually scored it. An unfinished scan
  carries no verdict, and pairing it against the other arm's real verdict would
  score an infrastructure failure as a detection difference.
- A pair whose runs are not both complete is void, and a void pair yields
  "evidence insufficient" rather than a lenient reading. Spec 5.3 voids the round
  and requires a re-run; reporting a verdict from it would defeat that.

The point estimate and the interval are computed by resampling *pairs*, so the
two arms stay matched by construction. The interval therefore describes the
paired difference, not the difference of two independently estimated rates.
"""

from __future__ import annotations

import json
import math
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools.audit_benchmark_eval import (  # noqa: E402
    compute_bootstrap_ci,
    confusion_counts,
    safe_div,
)

BOOTSTRAP_N = 1000
BOOTSTRAP_SEED = 42
CONFIDENCE_LEVEL = 0.95
EXPECTED_PAIRS = 3

# The order the runs were collected in, which is also the order they are reported
# in: strictly alternating, one full round of the corpus per arm, so a drift in
# the machine over the session shows up as a difference between run indices
# rather than as a difference between engines.
RUN_ORDER: Tuple[Tuple[str, int], ...] = (
    ("regex", 1), ("semgrep", 1),
    ("regex", 2), ("semgrep", 2),
    ("regex", 3), ("semgrep", 3),
)

Row = Dict[str, Any]


def predicted_malicious(row: Row) -> bool:
    """Whether this arm flagged the sample, in one place for both callers.

    The comparison and the confusion matrix have to agree on what counts as a
    detection; two copies of this rule drifting apart would move the verdict
    without moving any test that reads only one of them.
    """
    predicted = row.get("predicted_label")
    if predicted is None:
        return bool(row.get("blocked", False))
    return predicted == "malicious"


def _scored(row: Row) -> bool:
    return bool(row.get("scan_complete", True))


def load_rows(results_dir: Path) -> Dict[str, Row]:
    """Sample rows from a run's sample-results.jsonl, keyed by sample id."""
    rows: Dict[str, Row] = {}
    path = Path(results_dir) / "sample-results.jsonl"
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            rows[row["sample_id"]] = row
    return rows


def fpr(rows: Sequence[Row]) -> float:
    """False-positive rate over the benign samples, via the shared counts."""
    counts = confusion_counts([r for r in rows if r.get("label") == "benign"])
    return safe_div(counts["fp"], counts["fp"] + counts["tn"])


def recall(rows: Sequence[Row]) -> float:
    """Recall over the malicious samples, via the shared counts."""
    counts = confusion_counts([r for r in rows if r.get("label") == "malicious"])
    return safe_div(counts["tp"], counts["tp"] + counts["fn"])


def exact_mcnemar(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value over the discordant pairs.

    Exact rather than chi-squared because the discordant count is small: the
    corpus is 100 samples and the discordances are the ones a rule change moved,
    which is a handful. The chi-squared approximation would need several times
    that to be trustworthy, and a p-value that is wrong in the permissive
    direction is the one error this comparison cannot afford.
    """
    discordant = b + c
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, i) for i in range(0, min(b, c) + 1))
    return min(1.0, 2.0 * tail / (2 ** discordant))


@dataclass
class PairOutcome:
    """One paired run: the same samples measured under both arms."""

    index: int
    n_paired: int
    metrics_regex: Dict[str, float]
    metrics_semgrep: Dict[str, float]
    delta_fpr: float
    delta_fpr_ci: Tuple[float, float]
    delta_recall: float
    delta_recall_ci: Tuple[float, float]
    mcnemar_fpr: Dict[str, Any]
    mcnemar_recall: Dict[str, Any]
    void_reason: Optional[str] = None
    expected_paired: int = 0
    duration_regex: float = 0.0
    duration_semgrep: float = 0.0

    @property
    def is_void(self) -> bool:
        return self.void_reason is not None

    @property
    def delta_duration(self) -> float:
        """Seconds the Semgrep arm cost over the regex arm, within this pair."""
        return self.duration_semgrep - self.duration_regex


def _pair_up(regex_rows: Dict[str, Row], semgrep_rows: Dict[str, Row]) -> Tuple[List[Tuple[Row, Row]], List[str]]:
    """The pairs that carry a verdict, plus the reasons the rest do not."""
    problems: List[str] = []

    regex_only = sorted(set(regex_rows) - set(semgrep_rows))
    semgrep_only = sorted(set(semgrep_rows) - set(regex_rows))
    if regex_only:
        problems.append(f"missing from the semgrep run: {', '.join(regex_only)}")
    if semgrep_only:
        problems.append(f"missing from the regex run: {', '.join(semgrep_only)}")

    pairs: List[Tuple[Row, Row]] = []
    unscored: List[str] = []
    for sample_id in sorted(set(regex_rows) & set(semgrep_rows)):
        regex_row, semgrep_row = regex_rows[sample_id], semgrep_rows[sample_id]
        if not (_scored(regex_row) and _scored(semgrep_row)):
            unscored.append(sample_id)
            continue
        pairs.append((regex_row, semgrep_row))

    if unscored:
        problems.append(
            f"scan_complete is False on {len(unscored)} sample(s): {', '.join(unscored[:5])}"
            + (" ..." if len(unscored) > 5 else "")
        )
    return pairs, problems


def _delta(pairs: Sequence[Tuple[Row, Row]]) -> Tuple[float, float]:
    regex_rows = [regex_row for regex_row, _ in pairs]
    semgrep_rows = [semgrep_row for _, semgrep_row in pairs]
    return fpr(semgrep_rows) - fpr(regex_rows), recall(semgrep_rows) - recall(regex_rows)


def _discordance(pairs: Sequence[Tuple[Row, Row]], label: str) -> Dict[str, Any]:
    """McNemar cells over the samples of one label.

    b counts the samples only the Semgrep arm got wrong, c the ones only regex
    got wrong. For benign samples "wrong" is a flag; for malicious samples it is
    a miss, which is why the two tests cannot share a cell count.
    """
    b = c = 0
    for regex_row, semgrep_row in pairs:
        if regex_row.get("label") != label:
            continue
        regex_flagged = predicted_malicious(regex_row)
        semgrep_flagged = predicted_malicious(semgrep_row)
        if label == "benign":
            regex_wrong, semgrep_wrong = regex_flagged, semgrep_flagged
        else:
            regex_wrong, semgrep_wrong = not regex_flagged, not semgrep_flagged
        if semgrep_wrong and not regex_wrong:
            b += 1
        elif regex_wrong and not semgrep_wrong:
            c += 1
    return {"b": b, "c": c, "p": exact_mcnemar(b, c)}


def pair_runs(
    index: int,
    regex_rows: Iterable[Row],
    semgrep_rows: Iterable[Row],
    duration_regex: float = 0.0,
    duration_semgrep: float = 0.0,
) -> PairOutcome:
    """Pair one regex run against one Semgrep run and judge the pair.

    The durations are passed in rather than read off the rows: they are whole-run
    facts from the summaries, and a pair's runtime difference is disclosed next to
    its verdict because non-inferior detection at several times the cost is a
    different decision from non-inferior at the same cost.
    """
    regex_by_id = {row["sample_id"]: row for row in regex_rows}
    semgrep_by_id = {row["sample_id"]: row for row in semgrep_rows}
    expected = max(len(regex_by_id), len(semgrep_by_id))

    pairs, problems = _pair_up(regex_by_id, semgrep_by_id)
    if not pairs:
        problems.append("no sample was scored by both arms")

    if problems:
        return PairOutcome(
            index=index, n_paired=len(pairs),
            metrics_regex={}, metrics_semgrep={},
            delta_fpr=0.0, delta_fpr_ci=(0.0, 0.0),
            delta_recall=0.0, delta_recall_ci=(0.0, 0.0),
            mcnemar_fpr={"b": 0, "c": 0, "p": 1.0},
            mcnemar_recall={"b": 0, "c": 0, "p": 1.0},
            void_reason="; ".join(problems), expected_paired=expected,
            duration_regex=duration_regex, duration_semgrep=duration_semgrep,
        )

    delta_fpr, delta_recall = _delta(pairs)
    fpr_ci = compute_bootstrap_ci(
        list(pairs), metric_fn=lambda batch: _delta(batch)[0],
        n_bootstraps=BOOTSTRAP_N, confidence_level=CONFIDENCE_LEVEL, seed=BOOTSTRAP_SEED,
    )
    recall_ci = compute_bootstrap_ci(
        list(pairs), metric_fn=lambda batch: _delta(batch)[1],
        n_bootstraps=BOOTSTRAP_N, confidence_level=CONFIDENCE_LEVEL, seed=BOOTSTRAP_SEED,
    )

    regex_only = [regex_row for regex_row, _ in pairs]
    semgrep_only = [semgrep_row for _, semgrep_row in pairs]
    return PairOutcome(
        index=index, n_paired=len(pairs),
        metrics_regex=_arm_metrics(regex_only),
        metrics_semgrep=_arm_metrics(semgrep_only),
        delta_fpr=delta_fpr, delta_fpr_ci=(fpr_ci["ci_lower"], fpr_ci["ci_upper"]),
        delta_recall=delta_recall, delta_recall_ci=(recall_ci["ci_lower"], recall_ci["ci_upper"]),
        mcnemar_fpr=_discordance(pairs, "benign"),
        mcnemar_recall=_discordance(pairs, "malicious"),
        expected_paired=expected,
        duration_regex=duration_regex, duration_semgrep=duration_semgrep,
    )


def _outcome_dict(outcome: PairOutcome) -> Dict[str, Any]:
    """One pair as JSON, carrying the runtime difference as well as the rates.

    `asdict` drops properties, and the difference is computed in one place on the
    dataclass rather than recomputed by every reader of the file - a reader that
    recomputed it could disagree with the report citing it.
    """
    return {**asdict(outcome), "delta_duration": outcome.delta_duration}


def _arm_metrics(rows: Sequence[Row]) -> Dict[str, float]:
    """The three headline rates for one arm, over the paired samples only."""
    counts = confusion_counts(rows)
    return {
        "fpr": safe_div(counts["fp"], counts["fp"] + counts["tn"]),
        "recall": safe_div(counts["tp"], counts["tp"] + counts["fn"]),
        "accuracy": safe_div(counts["tp"] + counts["tn"], len(rows)),
    }


def inconsistent_samples(regex_rows: Iterable[Row], semgrep_rows: Iterable[Row]) -> List[Dict[str, Any]]:
    """The samples the arms disagree about, with the rules each arm fired.

    The rule sets are the only actionable lead for a rule-level root cause: a
    difference in FPR says something moved, and only the rules say what.
    """
    regex_by_id = {row["sample_id"]: row for row in regex_rows}
    semgrep_by_id = {row["sample_id"]: row for row in semgrep_rows}
    entries: List[Dict[str, Any]] = []
    for sample_id in sorted(set(regex_by_id) & set(semgrep_by_id)):
        regex_row, semgrep_row = regex_by_id[sample_id], semgrep_by_id[sample_id]
        if not (_scored(regex_row) and _scored(semgrep_row)):
            continue
        regex_flagged = predicted_malicious(regex_row)
        semgrep_flagged = predicted_malicious(semgrep_row)
        if regex_flagged == semgrep_flagged:
            continue
        entries.append({
            "sample_id": sample_id,
            "family": regex_row.get("family"),
            "label": regex_row.get("label"),
            "trap_type": regex_row.get("trap_type"),
            "direction": "regex_flagged_only" if regex_flagged else "semgrep_passed_only",
            "regex_rules": sorted(regex_row.get("matched_rules") or []),
            "semgrep_rules": sorted(semgrep_row.get("matched_rules") or []),
        })
    return entries


def family_table(regex_rows: Iterable[Row], semgrep_rows: Iterable[Row]) -> List[Dict[str, Any]]:
    """Per-family FPR/recall for both arms.

    Read per family because a difference concentrated in one trap type is a rule
    problem, while one spread across all of them is a property of the engine -
    and that distinction decides whether the next round is a rule change or a
    different question.
    """
    regex_by_id = {row["sample_id"]: row for row in regex_rows}
    semgrep_by_id = {row["sample_id"]: row for row in semgrep_rows}
    table: List[Dict[str, Any]] = []
    families = sorted({row.get("family") for row in regex_by_id.values()} | {row.get("family") for row in semgrep_by_id.values()})
    for family in families:
        common = [
            sample_id for sample_id in sorted(set(regex_by_id) & set(semgrep_by_id))
            if regex_by_id[sample_id].get("family") == family
            and _scored(regex_by_id[sample_id]) and _scored(semgrep_by_id[sample_id])
        ]
        regex_only = [regex_by_id[s] for s in common]
        semgrep_only = [semgrep_by_id[s] for s in common]
        label = next((regex_by_id[s].get("label") for s in common), None)
        entry: Dict[str, Any] = {"family": family, "label": label, "n": len(common)}
        if label == "benign":
            entry["fpr_regex"] = fpr(regex_only)
            entry["fpr_semgrep"] = fpr(semgrep_only)
        else:
            entry["recall_regex"] = recall(regex_only)
            entry["recall_semgrep"] = recall(semgrep_only)
        table.append(entry)
    return table


def analyse_all(base_dir: Path, out_path: Optional[Path] = None) -> Dict[str, Any]:
    """The six run directories in, the whole stage-6 analysis out.

    A missing or half-written run reaches the verdict as missing evidence rather
    than as an exception or as a quietly smaller analysis: mid-collection is
    exactly when a gap is easiest to lose, and a five-run analysis that reports
    itself as complete is the failure this whole round is trying to avoid.
    """
    base = Path(base_dir)
    runs_meta: List[Dict[str, Any]] = []
    rows_by_engine: Dict[str, Dict[int, Dict[str, Row]]] = {"regex": {}, "semgrep": {}}

    for engine, index in RUN_ORDER:
        run_dir = base / f"{engine}-run{index}"
        rows = load_rows(run_dir) if (run_dir / "sample-results.jsonl").exists() else {}
        summary = {}
        if (run_dir / "summary.json").exists():
            summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
        rows_by_engine[engine][index] = rows

        metrics = summary.get("metrics") or {}
        runs_meta.append({
            "engine": engine,
            "run": index,
            "results_dir": str(run_dir),
            "present": bool(rows),
            "samples": len(rows),
            "eval_duration_sec": summary.get("eval_duration_sec", 0.0),
            "round_complete": summary.get("round_complete"),
            "scan_incomplete_count": metrics.get("scan_incomplete_count"),
            "scan_error_count": metrics.get("scan_error_count"),
            "scored_count": metrics.get("scored_count"),
            "bypass_count": metrics.get("bypass_count"),
            "fail_closed_count": metrics.get("fail_closed_count"),
            "llm_sample_count": metrics.get("llm_sample_count"),
            "per_sample_scan_sec": metrics.get("per_sample_scan_sec"),
            "per_sample_llm_sec": metrics.get("per_sample_llm_sec"),
            "fpr": metrics.get("fpr"),
            "recall": metrics.get("recall"),
            "accuracy": metrics.get("accuracy"),
            "precision": metrics.get("precision"),
            "f1": metrics.get("f1"),
            "attribution_precision": metrics.get("attribution_precision"),
        })

    pairs: List[PairOutcome] = []
    inconsistencies: List[List[Dict[str, Any]]] = []
    family_tables: List[List[Dict[str, Any]]] = []
    durations = {(entry["engine"], entry["run"]): entry["eval_duration_sec"] for entry in runs_meta}
    for index in (1, 2, 3):
        regex_rows = rows_by_engine["regex"].get(index, {})
        semgrep_rows = rows_by_engine["semgrep"].get(index, {})
        pairs.append(pair_runs(
            index, regex_rows.values(), semgrep_rows.values(),
            duration_regex=durations.get(("regex", index), 0.0),
            duration_semgrep=durations.get(("semgrep", index), 0.0),
        ))
        inconsistencies.append(inconsistent_samples(regex_rows.values(), semgrep_rows.values()))
        family_tables.append(family_table(regex_rows.values(), semgrep_rows.values()))

    verdict, reasons = decide(pairs)
    analysis: Dict[str, Any] = {
        "base_dir": str(base),
        "verdict": verdict,
        "reasons": reasons,
        "runs": runs_meta,
        "pairs": [_outcome_dict(outcome) for outcome in pairs],
        "inconsistencies": inconsistencies,
        "family_table": family_tables[0] if family_tables else [],
        "family_tables_by_pair": {str(i + 1): table for i, table in enumerate(family_tables)},
        "bootstrap_n": BOOTSTRAP_N,
        "bootstrap_seed": BOOTSTRAP_SEED,
        "confidence_level": CONFIDENCE_LEVEL,
    }
    if out_path is not None:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(analysis, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8"
        )
    return analysis


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-dir", default=str(REPO_ROOT / "models/audit/audit-results/engine-compare"),
                        help="directory holding regex-run1..3 and semgrep-run1..3")
    parser.add_argument("--out", default=None, help="where to write paired-analysis.json")
    args = parser.parse_args(argv)

    base = Path(args.base_dir)
    out = Path(args.out) if args.out else base / "paired-analysis.json"
    analysis = analyse_all(base, out_path=out)

    print(f"verdict: {analysis['verdict']}")
    for reason in analysis["reasons"]:
        print(f"  - {reason}")
    print(f"{'engine':>8} {'run':>3} {'n':>4} {'FPR':>7} {'recall':>7} {'scan s':>8} {'LLM s':>8} {'n_llm':>6} {'sec':>8}")
    for entry in analysis["runs"]:
        print(
            f"{entry['engine']:>8} {entry['run']:>3} {entry['samples']:>4} "
            f"{_fmt(entry['fpr']):>7} {_fmt(entry['recall']):>7} "
            f"{_fmt(entry['per_sample_scan_sec']):>8} {_fmt(entry['per_sample_llm_sec']):>8} "
            f"{str(entry['llm_sample_count']):>6} {entry['eval_duration_sec']:>8.1f}"
        )
    print(f"{'pair':>8} {'dFPR':>8} {'p(McNemar)':>11} {'drecall':>8} {'p(McNemar)':>11} {'n':>4} {'dsec':>8}")
    for pair in analysis["pairs"]:
        print(
            f"{pair['index']:>8} {pair['delta_fpr']:>+8.4f} {pair['mcnemar_fpr']['p']:>11.4f} "
            f"{pair['delta_recall']:>+8.4f} {pair['mcnemar_recall']['p']:>11.4f} "
            f"{pair['n_paired']:>4} {pair['delta_duration']:>+8.1f}"
        )
    print(f"analysis written to: {out}")
    return 0 if analysis["verdict"] == "通过" else 1


def _fmt(value: Optional[float]) -> str:
    return "-" if value is None else f"{value:.4f}"


def decide(outcomes: Sequence[PairOutcome]) -> Tuple[str, List[str]]:
    """The verdict, in the three wordings the spec allows.

    Order matters: a void pair is reported as insufficient evidence even if the
    pairs that did run look favourable, because the missing pair is exactly the
    evidence that could overturn them. And a failing pair is reported as a
    failure even if another pair is void, since a failure needs no completing.
    """
    failures: List[str] = []
    voids: List[str] = []

    for outcome in outcomes:
        if outcome.is_void:
            voids.append(f"pair {outcome.index}: {outcome.void_reason}")
            continue
        if outcome.delta_fpr > 0:
            failures.append(
                f"pair {outcome.index}: FPR rose by {outcome.delta_fpr:+.4f} "
                f"(regex {outcome.metrics_regex['fpr']:.4f} -> semgrep {outcome.metrics_semgrep['fpr']:.4f})"
            )
        if outcome.delta_recall < 0:
            failures.append(
                f"pair {outcome.index}: recall fell by {outcome.delta_recall:+.4f} "
                f"(regex {outcome.metrics_regex['recall']:.4f} -> semgrep {outcome.metrics_semgrep['recall']:.4f})"
            )

    if failures:
        return "未通过", failures + voids
    if voids:
        return "证据不足", voids
    if len(outcomes) < EXPECTED_PAIRS:
        return "证据不足", [f"only {len(outcomes)} of {EXPECTED_PAIRS} pairs were analysed"]
    return "通过", []


if __name__ == "__main__":
    raise SystemExit(main())
