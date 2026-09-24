# models/audit/tools/gate_rescore.py
"""Derive the gate policy's numbers from an assist run by re-scoring its artifacts.

Why this exists
---------------
The engine comparison is judged under two policies. Running `gate` as a second
matrix would double the LLM budget and, worse, would judge the two policies on
two different draws from the model: the gate numbers would then describe a
second run rather than the run the assist numbers came from. On the `static-llm`
path both policies are decided by one function,
``compute_conclusion(stats, file_summaries, policy)``, whose entire policy
dependence is a single string (`code_security_analyzer.py:898-899`, where assist
overrides ``passed`` with ``risk_level not in ("CRITICAL", "HIGH")``). Its inputs
are all persisted per sample, so the gate conclusion for a run can be recomputed
from that run's own artifacts with no model call and no scan.

Exactness rests on three conditions, and this module enforces all three.

1. It **calls** ``compute_conclusion`` instead of transcribing its branches. A
   transcribed formula would make "exact" a claim about the transcription rather
   than a fact about the production code, and a later edit to
   ``compute_conclusion`` would silently diverge from the derived numbers.
2. ``file_reports[].risk_level`` is read as a ``FileSummary`` risk level only when
   ``file_reports`` is non-empty *and* ``scan_metadata.llm_enabled`` is true. With
   the model disabled there are no ``FileSummary`` objects at all: the level comes
   from ``infer_risk_level()`` (`code_security_analyzer.py:971-974`, the
   "static scan only, no semantic analysis" placeholder) and describes a
   static-only finding. Feeding it into the chain check would report a static
   HIGH as a file-level attack chain and turn a MEDIUM-only sample into CRITICAL.
3. ``statistics`` must not carry ``scan_complete`` / ``parser_errors`` /
   ``timed_out``. ``compute_conclusion`` reads those three with ``.get(default)``
   (`code_security_analyzer.py:822-824`) and ``generate_audit_report`` never
   writes them into ``stats`` (`:948-956`), which is exactly why the
   fail-closed-on-incomplete-scan branch is unreachable on this path and the
   re-score is exact rather than approximate. If a future change threads scan
   state into ``stats``, the re-score becomes unsound, and the divergence trends
   toward **loosening** the gate: the defaults are ``True`` / ``0`` / ``False``,
   i.e. "scan completed, no parser errors, no timeout". So the invariant is
   asserted and the tool refuses to run rather than proceeding.

Two further facts the materialisation relies on, both asserted in code:

* ``gate`` is monotonically stricter than ``assist``. Every risk level that makes
  assist block (``CRITICAL``, ``HIGH``) also trips a gate branch, so
  ``blocked`` can only move ``False -> True``. A sample's attribution therefore
  only needs recomputing when the gate newly blocks it; otherwise the assist
  value is inherited, because ``check_sample_attribution`` reads only the label,
  ``blocked`` and the policy-independent ``file_reports``.
* ``conclusion.reason`` / ``conclusion.summary`` / ``conclusion.recommendation``
  do not depend on the policy (``code_security_analyzer.py:901-920`` for the
  first two, ``:997-1009`` for the recommendation, which reads only findings).
  They are asserted equal to what the run persisted, so a future edit that
  couples them to the policy fails loudly instead of producing a plausible
  artifact.

Nothing here writes to the source run. ``--validate`` only reads; the default
mode copies each run directory and rewrites the decision layer in the copy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools import audit_benchmark_eval as ev  # noqa: E402
from models.examples.code_security_analyzer import (  # noqa: E402
    FileSummary,
    compute_conclusion,
)

TOOL_PATH = Path(__file__).resolve()

DERIVED_POLICY = "gate"
SOURCE_POLICY = "assist"

# Keys whose presence in `statistics` would mean the fail-closed scan-state branch
# is reachable, which is the one case where re-scoring stops being exact.
FORBIDDEN_STATS_KEYS: Tuple[str, ...] = ("scan_complete", "parser_errors", "timed_out")

# The seven counters `generate_audit_report` builds and `compute_conclusion`
# consumes. A report missing any of them cannot be re-scored.
REQUIRED_STATS_KEYS: Tuple[str, ...] = (
    "total_findings", "high", "medium", "malicious", "suspicious", "benign", "uncertain",
)

# The conclusion fields the re-derivation compares against the persisted ones.
CONCLUSION_KEYS: Tuple[str, ...] = ("passed", "verdict", "reason", "risk_level", "summary")

# Row fields the decision layer owns. They are compared field by field against
# the source run wherever the two policies agree, and rewritten everywhere else.
DECISION_FIELDS: Tuple[str, ...] = (
    "predicted_label", "predicted_verdict", "predicted_risk",
    "blocked", "fail_closed", "error_type", "attributed", "reason",
)

FAIL_CLOSED_STATES = frozenset({"llm_unavailable", "parse_error"})

RUN_NAME_ENGINES = ("regex", "semgrep")
RUN_NAME_ROUNDS = (1, 2, 3)
# The layout engine_compare_report.py knows: anything else it reads past, so a run
# outside this set is refused rather than exported into a report that ignores it.
RUN_DIR_RE = re.compile(
    r"^(?:" + "|".join(RUN_NAME_ENGINES) + r")-run(?:"
    + "|".join(str(index) for index in RUN_NAME_ROUNDS) + r")$"
)


class RescoreError(RuntimeError):
    """The artifact cannot be re-scored or re-materialised as asked."""


class RescoreInvariantError(RescoreError):
    """The exactness invariant does not hold for this artifact.

    A kind of `RescoreError` so that a validation pass reports it per sample, but
    the message it carries is the one that must not be worked around.
    """


def tool_digest() -> str:
    """sha256 of this file, recorded so a derived artifact names its producer."""
    return hashlib.sha256(TOOL_PATH.read_bytes()).hexdigest()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RescoreError(f"missing artifact: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RescoreError(f"unreadable JSON: {path}: {exc}") from exc


def reconstruct(report_path: Path) -> Tuple[dict, Dict[str, FileSummary]]:
    """`(stats, file_summaries)` for `compute_conclusion`, from one audit_report.json.

    The returned pair is what the run's own decision used. `file_summaries` is
    empty wherever the model did not run, which is what keeps the chain check
    honest - see condition 2 in the module docstring.
    """
    return reconstruct_report(_load_json(report_path))


def reconstruct_report(report: dict) -> Tuple[dict, Dict[str, FileSummary]]:
    """`reconstruct` for an already-loaded report."""
    if not isinstance(report, dict):
        raise RescoreError("audit_report.json is not a JSON object")

    stats = report.get("statistics")
    if not isinstance(stats, dict):
        raise RescoreError("audit_report.json has no `statistics` object to re-score")

    forbidden = sorted(key for key in FORBIDDEN_STATS_KEYS if key in stats)
    if forbidden:
        raise RescoreInvariantError(
            "re-scoring this artifact would be unsound: `statistics` carries "
            f"{', '.join(forbidden)}. compute_conclusion reads those three with defaults "
            "(scan_complete=True, parser_errors=0, timed_out=False), so once they are "
            "present the fail-closed 'scan incomplete or defective' branch becomes "
            "reachable and re-scoring can no longer reproduce the run. The divergence "
            "trends toward LOOSENING the gate, never tightening it. Refusing to guess: "
            "re-derive the gate numbers by running the gate policy, or fix the artifact "
            "producer so the persisted `statistics` stays the seven counters it was."
        )

    missing = sorted(key for key in REQUIRED_STATS_KEYS if key not in stats)
    if missing:
        raise RescoreError(
            f"`statistics` is missing {', '.join(missing)}; the run predates the "
            "counters the decision consumes and cannot be re-scored"
        )

    scan_metadata = report.get("scan_metadata") or {}
    file_reports = report.get("file_reports") or []

    file_summaries: Dict[str, FileSummary] = {}
    # Only a run whose model ran has FileSummary objects behind these levels.
    # rebuild the FileSummary objects the decision layer consumed, not the levels the report
    # chose to print. Without the model the report's level is a static-scan
    # placeholder (`infer_risk_level`), and treating it as a file-level risk would
    # make a static-only HIGH look like a detected attack chain.
    if file_reports and scan_metadata.get("llm_enabled"):
        for file_report in file_reports:
            key = file_report.get("file_path") or file_report.get("file")
            if not key:
                raise RescoreError("a file_reports entry has neither `file_path` nor `file`")
            file_summaries[str(key)] = FileSummary(
                risk_level=str(file_report.get("risk_level", "UNCERTAIN")),
                summary=str(file_report.get("summary", "")),
                chained=bool(file_report.get("chained", False)),
                exfiltration=bool(file_report.get("has_exfiltration_pattern", False)),
            )

    return dict(stats), file_summaries


def rescore(report: dict, policy: str) -> dict:
    """The conclusion this report yields under `policy`, via the production function."""
    stats, file_summaries = reconstruct_report(report)
    return compute_conclusion(stats, file_summaries=file_summaries, policy=policy)


def rescore_path(report_path: Path, policy: str) -> dict:
    return rescore(_load_json(report_path), policy)


def _report_conclusion(report: dict) -> dict:
    conclusion = report.get("conclusion")
    if not isinstance(conclusion, dict):
        raise RescoreError("audit_report.json has no `conclusion` object to compare against")
    return conclusion


def _assert_policy_independent(report: dict, conclusion: dict) -> None:
    """`reason` / `summary` must match what the run persisted, under any policy.

    They are built from the counters and the file summaries only, so a difference
    here means the decision function gained a policy dependence this tool does not
    model - the derived artifact would then be plausible and wrong.
    """
    persisted = _report_conclusion(report)
    for key in ("reason", "summary"):
        if key in persisted and persisted[key] != conclusion.get(key):
            raise RescoreError(
                f"`conclusion.{key}` is no longer policy independent: the run persisted "
                f"{persisted[key]!r} and the re-score yields {conclusion.get(key)!r}. "
                "Stop and re-derive the gate numbers by running the gate policy."
            )


def derive_error_type(label: str, llm_state: str, predicted_label: str) -> str:
    """The row's `error_type`, mirroring the block in `analyse_sample`.

    Reproduced rather than imported because the eval computes it inline
    (`audit_benchmark_eval.py:1029-1042`) and exposes no helper. Every caller here
    asserts the reproduced value against the source row wherever the two policies
    agree, so a drift in that block fails the re-score instead of passing silently.
    """
    error_type = "ok"
    if llm_state == "static_only":
        error_type = "static_only"
    elif llm_state == "llm_unavailable":
        error_type = "llm_unavailable"
    elif llm_state == "parse_error":
        error_type = "parse_error"
    elif llm_state == "uncertain":
        error_type = "uncertain"

    if label == "benign" and predicted_label == "malicious":
        error_type = "false_positive"
    elif label == "malicious" and predicted_label == "benign":
        error_type = "false_negative"
    return error_type


def _resolve_sample_meta(row: dict, corpus_root: Optional[Path]) -> Optional[dict]:
    """The sample's `sample.json`, needed only to re-check attribution.

    Resolution order: the recorded `sample_path` as given, then the same path
    under `--corpus-root` (a run made inside the container records container
    paths, which do not resolve on the host).
    """
    sample_path = row.get("sample_path")
    if not sample_path:
        return None
    candidates = [Path(sample_path)]
    if corpus_root is not None:
        tail = Path(sample_path)
        candidates.append(Path(corpus_root) / tail.name)
        for parent in tail.parents:
            if parent.name and parent.parent.name:
                candidates.append(Path(corpus_root) / parent.parent.name / parent.name)
                break
    for candidate in candidates:
        meta_path = candidate / "sample.json"
        if meta_path.exists():
            try:
                return json.loads(meta_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return None
    return None


def derive_attributed(
    row: dict,
    report: dict,
    new_blocked: bool,
    corpus_root: Optional[Path],
    cache: Dict[str, Optional[dict]],
) -> bool:
    """The row's `attributed` under the new `blocked`.

    `check_sample_attribution` short-circuits on the label and on `blocked`, and
    otherwise reads only `file_reports` and the sample's declared primary attack
    finding - none of which the policy touches. So the assist value is inherited
    whenever the block decision is unchanged, and only a sample the gate newly
    blocks has to be re-checked.
    """
    if row.get("label") != "malicious" or not new_blocked:
        return False
    if row.get("blocked", False):
        return bool(row.get("attributed", False))

    sample_id = str(row.get("sample_id"))
    if sample_id not in cache:
        cache[sample_id] = _resolve_sample_meta(row, corpus_root)
    meta = cache[sample_id]
    if meta is None:
        raise RescoreError(
            f"sample {sample_id}: the gate newly blocks this sample, so `attributed` "
            "must be re-checked, but its sample.json could not be read. Pass "
            "`--corpus-root` pointing at the corpus so the sample metadata resolves; "
            "inheriting the assist value here would understate attribution_precision."
        )

    probe = dict(row)
    probe["blocked"] = True
    probe["audit_report"] = report
    probe["sample_meta"] = meta
    return bool(ev.check_sample_attribution(probe, meta))


def derive_row(
    row: dict,
    report: dict,
    policy: str,
    *,
    corpus_root: Optional[Path] = None,
    meta_cache: Optional[Dict[str, Optional[dict]]] = None,
) -> dict:
    """One sample-results row as the decision layer would have written it.

    The decision fields come from the real `compute_conclusion` and from the
    eval's own `infer_predicted_verdict`; only the two inline derivations
    (`predicted_label`/`blocked` and `error_type`) are reproduced, and both are
    checked against the source row whenever the policies agree.
    """
    cache = {} if meta_cache is None else meta_cache
    conclusion = rescore(report, policy)
    _assert_policy_independent(report, conclusion)

    llm_state = str(row.get("llm_state", ""))
    new_row = dict(row)
    new_blocked = not conclusion["passed"]
    predicted_label = "malicious" if new_blocked else "benign"

    new_row["predicted_label"] = predicted_label
    new_row["predicted_verdict"] = ev.infer_predicted_verdict(
        {**report, "conclusion": conclusion}, llm_state
    )
    new_row["predicted_risk"] = conclusion["risk_level"]
    new_row["blocked"] = new_blocked
    new_row["fail_closed"] = new_blocked and llm_state in FAIL_CLOSED_STATES
    new_row["error_type"] = derive_error_type(
        str(row.get("label", "")), llm_state, predicted_label
    )
    new_row["reason"] = conclusion["summary"]
    new_row["attributed"] = derive_attributed(row, report, new_blocked, corpus_root, cache)

    if new_blocked == bool(row.get("blocked", False)):
        # Same decision, so every derived field must equal what the run wrote.
        # This is the check that catches a reproduction drifting from the eval.
        for field in DECISION_FIELDS:
            if field in row and row[field] != new_row[field]:
                raise RescoreError(
                    f"sample {row.get('sample_id')}: `{field}` disagrees with the source "
                    f"run although both policies block the sample "
                    f"(source {row[field]!r}, re-derived {new_row[field]!r}). The "
                    "re-derivation no longer mirrors the decision layer."
                )
    return new_row


def derive_report(report: dict, policy: str) -> dict:
    """The per-sample report as the decision layer would have written it.

    Only the conclusion's decision fields and the recorded policy move. The
    recommendation is carried over verbatim because `generate_audit_report`
    builds it from findings alone (`code_security_analyzer.py:997-1009`), so it
    cannot differ between the two policies.
    """
    conclusion = rescore(report, policy)
    _assert_policy_independent(report, conclusion)

    new_report = dict(report)
    merged = dict(_report_conclusion(report))
    for key, value in conclusion.items():
        if key == "recommendation":
            continue
        merged[key] = value
    new_report["conclusion"] = merged

    scan_metadata = dict(new_report.get("scan_metadata") or {})
    if "policy" in scan_metadata:
        scan_metadata["policy"] = policy
    new_report["scan_metadata"] = scan_metadata
    return new_report


# ---------------------------------------------------------------------------
# Validation: re-derive each run under its own policy and compare.
# ---------------------------------------------------------------------------

def _run_dirs(base_dir: Path) -> List[Path]:
    """The base directory's run bundles, in the engine-compare layout.

    Only layout-named directories are runs. The matrix base directory also holds
    the press load's output (`press/`), which must not be read as a run and has no
    summary.json of its own, so name alone is what selects.

    A layout-named directory *without* a summary.json is an interrupted run rather
    than an absent one. Skipping it would be a fail-open: `--validate` would report
    a clean pass over zero samples and `--materialise` would write an empty gate
    bundle, both naming a run that never finished. Observed for real - the first
    holdout matrix died at sample 3 of `regex-run1` and left exactly that shape.
    """
    base = Path(base_dir)
    if not base.is_dir():
        raise RescoreError(f"base directory does not exist: {base}")
    runs: List[Path] = []
    for child in sorted(base.iterdir()):
        if not child.is_dir() or not RUN_DIR_RE.match(child.name):
            continue
        if not (child / "summary.json").exists():
            raise RescoreError(
                f"{child.name}: no summary.json, so this run has no conclusion to replay "
                "and no bundle to re-score. An interrupted matrix cannot be validated, and "
                "gate must not be derived from it."
            )
        runs.append(child)
    return runs


def _load_rows(run_dir: Path) -> List[dict]:
    jsonl = run_dir / "sample-results.jsonl"
    if not jsonl.exists():
        raise RescoreError(f"{run_dir}: no sample-results.jsonl")
    rows: List[dict] = []
    with jsonl.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _report_path(run_dir: Path, sample_id: str) -> Path:
    return run_dir / sample_id / "audit_report.json"


def validate_run(run_dir: Path, corpus_root: Optional[Path] = None) -> dict:
    """Re-derive one run with its own policy and count the exact matches."""
    run_dir = Path(run_dir)
    summary = _load_json(run_dir / "summary.json")
    policy = summary.get("policy")
    if not policy:
        raise RescoreError(f"{run_dir}: summary.json records no policy to validate against")
    _check_audit_mode(run_dir, summary)

    matches = 0
    mismatches: List[dict] = []
    meta_cache: Dict[str, Optional[dict]] = {}
    rows = _load_rows(run_dir)

    for row in rows:
        sample_id = str(row.get("sample_id"))
        report = _load_json(_report_path(run_dir, sample_id))
        persisted = _report_conclusion(report)
        try:
            derived_row = derive_row(
                row, report, policy, corpus_root=corpus_root, meta_cache=meta_cache
            )
            conclusion = rescore(report, policy)
        except RescoreError as exc:
            mismatches.append({"sample_id": sample_id, "detail": str(exc)})
            continue

        differences = {
            key: {"persisted": persisted.get(key), "rederived": conclusion.get(key)}
            for key in CONCLUSION_KEYS
            if key in persisted and persisted.get(key) != conclusion.get(key)
        }
        # `error_type` and `reason` are decision-layer outputs that the run wrote
        # into the row; comparing them here covers the fields the conclusion does
        # not carry.
        for field in ("error_type", "reason"):
            if field in row and row[field] != derived_row[field]:
                differences[field] = {"persisted": row[field], "rederived": derived_row[field]}

        if differences:
            mismatches.append({"sample_id": sample_id, "differences": differences})
        else:
            matches += 1

    return {
        "run": run_dir.name,
        "results_dir": str(run_dir),
        "policy": policy,
        "samples": len(rows),
        "matches": matches,
        "mismatches": len(mismatches),
        "mismatch_details": mismatches[:20],
    }


def validate_base_dir(base_dir: Path, corpus_root: Optional[Path] = None) -> dict:
    """Every run under `base_dir`, validated under its own policy."""
    runs = [validate_run(run_dir, corpus_root=corpus_root) for run_dir in _run_dirs(base_dir)]
    return {
        "base_dir": str(base_dir),
        "runs": runs,
        "samples": sum(run["samples"] for run in runs),
        "matches": sum(run["matches"] for run in runs),
        "mismatches": sum(run["mismatches"] for run in runs),
    }


def print_validation(validation: dict) -> None:
    for run in validation["runs"]:
        print(
            f"  {run['run']:<16} policy={run['policy']:<7} "
            f"matched {run['matches']}/{run['samples']}  mismatches={run['mismatches']}"
        )
        for detail in run["mismatch_details"]:
            print(f"      ! {detail}")
    print(
        f"  total: matched {validation['matches']}/{validation['samples']} "
        f"over {len(validation['runs'])} run(s), mismatches={validation['mismatches']}"
    )


# ---------------------------------------------------------------------------
# Materialisation: the gate bundle engine_compare_report.py can read unchanged.
# ---------------------------------------------------------------------------

def _check_audit_mode(run_dir: Path, summary: dict) -> None:
    """This tool models the `static-llm` decision only.

    The pure-llm tracks decide `passed` in the evaluator itself, not through
    `compute_conclusion` (`audit_benchmark_eval.py:840-878`), and their reports
    carry neither a `verdict` nor a `reason` in the conclusion. Re-scoring one of
    those here would compare the two different decision functions and call the
    difference a derivation, so it is refused by name.
    """
    audit_mode = summary.get("audit_mode")
    if audit_mode != "static-llm":
        raise RescoreError(
            f"{run_dir}: audit_mode is {audit_mode!r}, but gate re-scoring is only defined "
            "for the `static-llm` path, the one whose decision goes through "
            "compute_conclusion"
        )


def _gate_summary(source_summary: dict, results: List[dict], derived_note: str) -> dict:
    """The run's summary with the decision layer recomputed under `gate`.

    The key set is asserted identical to the source's, so the derived bundle is
    interchangeable with a run of the gate policy as far as a reader is
    concerned; the fact that it was derived is carried in `notes`.
    """
    summary = dict(source_summary)
    summary["policy"] = DERIVED_POLICY
    summary["counts"] = ev.confusion_counts(results)
    summary["metrics"] = ev.metric_summary(results)
    summary["confidence_intervals_95"] = ev.compute_all_bootstrap_ci(ev.scored_rows(results))
    summary["errors"] = ev.error_breakdown(results)

    source_notes = source_summary.get("notes") or ""
    summary["notes"] = f"{source_notes}; {derived_note}" if source_notes else derived_note

    added = sorted(set(summary) - set(source_summary))
    removed = sorted(set(source_summary) - set(summary))
    if added or removed:
        raise RescoreError(
            f"the derived summary's key set moved (added {added}, removed {removed}); "
            "engine_compare_report.py and the judge read this file by key"
        )
    return summary


def materialise(
    base_dir: Path,
    out_dir: Path,
    corpus_root: Optional[Path] = None,
) -> dict:
    """Copy the assist runs into `out_dir` and rewrite their decision layer as gate."""
    base = Path(base_dir)
    out = Path(out_dir)
    if out.resolve() == base.resolve():
        raise RescoreError("--out-dir must differ from --base-dir; the source run is read-only")

    run_dirs = _run_dirs(base)
    if not run_dirs:
        raise RescoreError(f"no run directories under {base}")
    for run_dir in run_dirs:
        # Checked before validation so the diagnosis is the specific one: a base
        # directory that is not an assist run is a different mistake from a run
        # whose artifacts fail to replay.
        source_summary = _load_json(run_dir / "summary.json")
        _check_audit_mode(run_dir, source_summary)
        if source_summary.get("policy") != SOURCE_POLICY:
            raise RescoreError(
                f"{run_dir.name}: source policy is {source_summary.get('policy')!r}, "
                f"expected {SOURCE_POLICY!r}; re-scoring is only defined assist -> gate"
            )

    # Gate may only be exported from artifacts whose assist conclusion this tool
    # actually reproduces. A partial or drifted run has to fail here rather than
    # produce gate numbers nobody can trace back.
    validation = validate_base_dir(base, corpus_root=corpus_root)
    if validation["mismatches"]:
        print_validation(validation)
        raise RescoreError(
            "refusing to derive gate: the assist conclusion was not reproduced for "
            f"{validation['mismatches']} of {validation['samples']} samples. Gate numbers "
            "may only be exported from artifacts whose own policy replays exactly."
        )

    derived_note = (
        "gate derived by re-scoring this run's persisted artifacts with "
        "models/audit/tools/gate_rescore.py; the gate policy was not run, so these "
        "numbers describe the same model draw as the assist run they came from"
    )

    runs: List[dict] = []
    for run_dir in run_dirs:
        source_summary = _load_json(run_dir / "summary.json")

        target = out / run_dir.name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(run_dir, target)

        results: List[dict] = []
        newly_blocked = 0
        meta_cache: Dict[str, Optional[dict]] = {}
        for row in _load_rows(target):
            sample_id = str(row.get("sample_id"))
            report_file = _report_path(target, sample_id)
            report = _load_json(report_file)
            new_report = derive_report(report, DERIVED_POLICY)
            ev.write_json(report_file, new_report)

            new_row = derive_row(
                row, report, DERIVED_POLICY, corpus_root=corpus_root, meta_cache=meta_cache
            )
            new_row["report_path"] = str(report_file)
            if new_row["blocked"] and not row.get("blocked", False):
                newly_blocked += 1
            results.append(new_row)

        # The eval's own bundle writer, so the copy is shaped exactly like a run.
        ev.write_results_bundle(target, results, _gate_summary(source_summary, results, derived_note))

        runs.append({
            "run": run_dir.name,
            "source_results_dir": str(run_dir),
            "results_dir": str(target),
            "samples": len(results),
            "policy": DERIVED_POLICY,
            "source_policy": source_summary.get("policy"),
            "newly_blocked": newly_blocked,
            "counts": ev.confusion_counts(results),
        })

    provenance = {
        "tool": str(TOOL_PATH.relative_to(REPO_ROOT)) if TOOL_PATH.is_relative_to(REPO_ROOT) else str(TOOL_PATH),
        "tool_sha256": tool_digest(),
        "source_base_dir": str(base),
        "out_dir": str(out),
        "derived_policy": DERIVED_POLICY,
        "source_policy": SOURCE_POLICY,
        "invariant": {
            "checked": list(FORBIDDEN_STATS_KEYS),
            "present": False,
            "result": "pass",
            "meaning": (
                "no sample's `statistics` carries scan_complete/parser_errors/timed_out, so "
                "compute_conclusion's fail-closed scan-state branch is unreachable and the "
                "re-score is exact rather than approximate"
            ),
        },
        "validation": {
            "runs": [
                {
                    "run": run["run"],
                    "policy": run["policy"],
                    "samples": run["samples"],
                    "matches": run["matches"],
                    "mismatches": run["mismatches"],
                }
                for run in validation["runs"]
            ],
            "samples": validation["samples"],
            "matches": validation["matches"],
            "mismatches": validation["mismatches"],
            "note": (
                "each run was re-derived under its own policy and compared field by field "
                "with the conclusion it persisted"
            ),
        },
        "derivation": (
            "the gate policy was NOT run. Every gate number in this bundle comes from calling "
            "the production compute_conclusion(stats, file_summaries, policy='gate') on the "
            "assist run's own persisted per-sample audit_report.json, via "
            "models/audit/tools/gate_rescore.py. The LLM was not invoked and no scan was run, "
            "so the two policies are compared on the same model draw."
        ),
        "runs": runs,
    }
    ev.write_json(out / "rescore-provenance.json", provenance)
    return provenance

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-dir", type=Path, required=True,
                        help="directory holding the assist runs, as (regex|semgrep)-run(1|2|3)")
    parser.add_argument("--out-dir", type=Path, default=None,
                        help="where to write the derived gate runs (required unless --validate)")
    parser.add_argument("--validate", action="store_true",
                        help="only re-derive each run under its own policy and compare; write nothing")
    parser.add_argument("--corpus-root", type=Path, default=None,
                        help="corpus root, so a sample's sample.json resolves when the run "
                             "recorded container paths")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    try:
        return _run(args)
    except RescoreError as exc:
        # A refusal is a result, not a crash: the caller needs the reason, and the
        # exit code needs to be distinguishable from a mismatch found by --validate.
        print(f"refusing: {exc}", file=sys.stderr)
        return 2


def _run(args: argparse.Namespace) -> int:
    if args.validate:
        print(f"validating {args.base_dir} (no writes)")
        validation = validate_base_dir(args.base_dir, corpus_root=args.corpus_root)
        print_validation(validation)
        if validation["mismatches"]:
            print("FAIL: the source runs do not replay; gate must not be derived from them")
            return 1
        print("OK: every sample replays under its own policy")
        return 0

    if args.out_dir is None:
        raise RescoreError("--out-dir is required unless --validate is given")

    provenance = materialise(args.base_dir, args.out_dir, corpus_root=args.corpus_root)
    for run in provenance["runs"]:
        counts = run["counts"]
        print(
            f"  {run['run']:<16} samples={run['samples']:<4} newly blocked by gate="
            f"{run['newly_blocked']:<4} tp={counts['tp']} fp={counts['fp']} "
            f"tn={counts['tn']} fn={counts['fn']}"
        )
    print(f"gate derived by re-scoring {provenance['source_base_dir']} -> {provenance['out_dir']}")
    print(f"provenance written to: {Path(provenance['out_dir']) / 'rescore-provenance.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
