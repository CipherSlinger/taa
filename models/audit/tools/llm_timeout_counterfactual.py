# models/audit/tools/llm_timeout_counterfactual.py
"""Bound the impact of a failed LLM call on the holdout judgement.

Why this exists
---------------
The holdout matrix reads its verdicts from model calls the evaluation caps at 60 s
(`code_security_analyzer.py:733`, ``urlopen(req, timeout=60)``) and at 200-300
generated tokens, and it never retries. A call can therefore fail in two ways,
and the evaluation files them under two different states
(`audit_benchmark_eval.py:820-823`):

* ``llm_unavailable`` -- the call raised, most often the 60 s timeout;
* ``parse_error`` -- the call returned, but the generation was cut off by
  ``num_predict`` before the JSON closed, so nothing could be parsed.

Either way the finding is recorded as ``UNCERTAIN``, and the sample-level
conclusion is then decided by ``compute_conclusion``
(`code_security_analyzer.py:855-875`):

    elif suspicious > 0 or (has_uncertain and has_high_or_medium):
        risk_level = "HIGH"
    ...
    elif has_uncertain and has_high_or_medium:
        passed = False
        reason = "Fail-Closed: LLM uncertain on high/medium finding"
    ...
    if policy_str == "assist":
        passed = risk_level not in ("CRITICAL", "HIGH")

So a failure is not silently benign. An ``UNCERTAIN`` verdict on a HIGH or MEDIUM
finding drives the risk level to HIGH, and under ``assist`` that blocks the
sample. The failure direction is therefore **toward malicious**:

* on a benign sample it fabricates a **false positive**, inflating FPR;
* on a malicious sample it changes nothing, since the sample was blocked anyway;
* only a failure on a LOW-severity finding could move a sample toward benign, and
  this corpus contains no LOW-severity findings at all (measured: 113 HIGH and 20
  MEDIUM across the first round's arbitrated findings, zero LOW).

The defect therefore **only inflates FPR, in this corpus, and never costs
recall**. It is not neutral for the comparison: the two arms decide different
numbers of findings, so they do not fail equally often, and the arm that fails
less often is measured with the cleaner FPR. The recorded comparison is
consequently lenient toward whichever arm fails less. A 0-tolerance criterion
cannot absorb that, so its size has to be measured rather than argued.

What this tool does
-------------------
It re-runs the affected samples through the **production** pipeline
(``audit_benchmark_eval.analyse_sample``) with the calls allowed to finish: a
longer HTTP timeout, and a floor under ``num_predict``. Everything else -- the
scan, the dedup and cap, the prompts, the arbitration, the policy, the conclusion
-- is the production code path, so the counterfactual label comes from the same
function that produced the recorded one instead of from a transcription of it.

Both knobs are inert unless a call was actually cut short: the timeout only
matters to a call that would have exceeded it, and a raised ``num_predict`` only
matters to a generation that had not yet stopped on its own. That is what makes
this a counterfactual about the failure rather than about the pipeline.

Pre-registered rule (fixed before any counterfactual is run)
------------------------------------------------------------
A failed call is **material** for a sample iff the counterfactual
``predicted_label`` differs from the recorded one. Nothing else counts: not a
changed verdict on an individual finding, not a changed risk level, not a
changed ``llm_state``. Material changes are reported split by direction
(see ``classify_transition``), because a repaired false positive and a newly
introduced false negative are different findings about the criterion and must not
be summed into one "changed" number.

The patch, stated plainly
-------------------------
The timeout is a literal inside ``_call_ollama`` and the generation cap is an
argument to it, so this tool replaces ``urllib.request.urlopen`` with a wrapper
that forces the longer timeout and replaces ``LLMSecurityAnalyzer._call_ollama``
with a wrapper that raises ``num_predict`` to the floor. Those wrappers are the
ONLY difference from the production path, they are announced on stdout, and their
values are recorded in the output. The replay writes to its own ``--out-dir``;
the source runs are opened read-only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools import audit_benchmark_eval as ev  # noqa: E402
from models.examples.code_security_analyzer import LLMSecurityAnalyzer  # noqa: E402

TOOL_PATH = Path(__file__).resolve()

# The markers the evaluation itself uses to recognise a failed call, in two
# families that need different repairs. The evaluation names them at two levels
# with slightly different spellings (`audit_benchmark_eval.py:820-822` for the
# static-llm sample state, `:1134-1136` for the finding-level state), so these are
# the unions. Keeping both in one place means a change on either side shows up here
# as a mismatch to reconcile, rather than as silently fewer affected samples.
CALL_FAILURE_MARKERS: Tuple[str, ...] = ("调用失败", "call failed", "未配置推理后端")
PARSE_FAILURE_MARKERS: Tuple[str, ...] = ("无法解析", "解析失败", "parse error", "decode response")
FAILURE_MARKERS: Tuple[str, ...] = CALL_FAILURE_MARKERS + PARSE_FAILURE_MARKERS

# The recorded run plans the source matrix uses, and the audit mode the holdout
# runs were taken under. A run whose metadata disagrees is refused: replaying it
# under a different mode would produce a counterfactual of the wrong pipeline.
DEFAULT_AUDIT_MODE = "static-llm"
DEFAULT_EXTENSIONS = ".py"
DEFAULT_MAX_FINDINGS = 50
# `pure-llm`/`pure-llm-checklist` populate `rules_count`; `static-llm` reports 0.
STATIC_LLM_RULES_COUNT = 0
# The production caps are 200 tokens for a finding and 300 for a file summary.
# 800 leaves room for a verdict object to close even when the model rambles first,
# and stays inside the replay's own timeout: at the measured 7.6-11.4 tok/s decode
# it is at most about 105 s against a 300 s cap.
DEFAULT_MIN_NUM_PREDICT = 800

MATERIAL_RULE = (
    "a failed call is material iff the counterfactual predicted_label differs "
    "from the recorded predicted_label"
)


class CounterfactualError(RuntimeError):
    """The counterfactual cannot be run as asked."""


def tool_digest() -> str:
    """sha256 of this file, recorded so the artifact names its producer."""
    return hashlib.sha256(TOOL_PATH.read_bytes()).hexdigest()


def failure_kind(reason: str) -> Optional[str]:
    """Classify one failure reason, or None when the call did not fail.

    Three kinds, because they need different repairs and only one of them is a
    timeout:

    * ``unparseable`` -- the call returned, but the generation was cut off by
      ``num_predict`` before the JSON closed, so ``extract_json_response`` had
      nothing to parse. More time cannot repair this; only more tokens can.
    * ``timeout`` -- the call raised the 60 s HTTP cap. More tokens cannot repair
      this; only more time can.
    * ``other`` -- a call failure that is neither. It will fail again in the
      replay, which is worth knowing on its own rather than averaging into either
      bucket.
    """
    text = reason or ""
    if not any(marker in text for marker in FAILURE_MARKERS):
        return None
    # Checked before the timeout wording, and the two are disjoint in practice: a
    # timed-out call raises before there is any text to parse, while a truncated
    # generation returns successfully. When both could match, the parse signature
    # is the more specific one.
    if any(marker in text for marker in PARSE_FAILURE_MARKERS):
        return "unparseable"
    if "timed out" in text.lower() or "timeout" in text.lower():
        return "timeout"
    return "other"


def find_failed_calls(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every failed model call recorded in one sample report.

    Both levels are collected. A finding-level failure is visible on the finding
    (``llm_reason``); a file-level failure is only visible on the file summary
    (``reason``), and the file summary is what the policy reads when it decides
    whether a file is ``UNCERTAIN``. Collecting only the finding level would
    undercount the affected samples, which is the direction that flatters the
    result.
    """
    failures: List[Dict[str, Any]] = []
    for file_report in report.get("file_reports") or []:
        level_kind = failure_kind(file_report.get("reason", ""))
        if level_kind is not None:
            failures.append({
                "level": "file",
                "file": file_report.get("file", ""),
                "kind": level_kind,
                "reason": file_report.get("reason", ""),
            })
        for finding in file_report.get("findings") or []:
            kind = failure_kind(finding.get("llm_reason", ""))
            if kind is not None:
                failures.append({
                    "level": "finding",
                    "file": file_report.get("file", ""),
                    "rule_id": finding.get("rule_id", ""),
                    "line": finding.get("line"),
                    "kind": kind,
                    "reason": finding.get("llm_reason", ""),
                })
    return failures


def classify_transition(label: str, recorded: str, counterfactual: str) -> str:
    """Name what a material change means for the criterion's two columns.

    Only called for material changes, so the two labels differ. The names are
    about the counterfactual being the more trustworthy reading: the recorded
    label is what the matrix scored, and a row that moves is a row the timeout
    had already decided.
    """
    if label == "malicious":
        if recorded == "benign" and counterfactual == "malicious":
            return "false_negative_repaired"
        if recorded == "malicious" and counterfactual == "benign":
            return "false_negative_introduced"
        return "malicious_other"
    if recorded == "malicious" and counterfactual == "benign":
        return "false_positive_repaired"
    if recorded == "benign" and counterfactual == "malicious":
        return "false_positive_introduced"
    return "benign_other"


def affected_samples(base_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Map ``<run dir>/<sample id>`` to the failed calls its report records."""
    found: Dict[str, List[Dict[str, Any]]] = {}
    for run_dir in sorted(p for p in base_dir.iterdir() if p.is_dir()):
        for report_path in sorted(run_dir.glob("*/audit_report.json")):
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            failures = find_failed_calls(report)
            if failures:
                found[f"{run_dir.name}/{report_path.parent.name}"] = failures
    return found


def assert_matrix_not_running(base_dir: Path) -> None:
    """Refuse while the source matrix is live.

    Two reasons, and the second is the one that matters. A replay spends model
    calls, and spending them inside the window the source matrix is measured in
    would perturb the very numbers being explained. And the matrix is still
    writing reports, so the affected set would be a snapshot of a moving target.
    """
    marker = base_dir / ".running"
    if marker.exists():
        raise CounterfactualError(
            f"{marker} exists: the source matrix is still running. The replay "
            "makes model calls and would perturb the run it is meant to explain."
        )


def assert_output_dir_free(out_dir: Path) -> None:
    """A replay must not be confused with an earlier one."""
    if out_dir.exists() and any(out_dir.iterdir()):
        raise CounterfactualError(
            f"{out_dir} exists and is not empty; move it aside or pass another --out-dir"
        )


@contextmanager
def patched_call_budget(seconds: int, min_num_predict: int) -> Iterator[None]:
    """Let a truncated or slow call finish: floor the token cap, raise the timeout.

    Two knobs because there are two ways a call is cut short and neither knob can
    repair the other's failure -- more time does not help a generation that had
    already stopped, and more tokens do not help a call that never returned.

    ``_call_ollama`` imports ``urllib.request`` inside its own body, so it resolves
    ``urlopen`` at call time through the module object and sees the patched
    attribute. It receives ``num_predict`` as an argument, so the cap is raised by
    wrapping the method; ``max`` rather than assignment so an already-larger budget
    is left alone.

    Both originals are restored on exit, including when the body raises.
    """
    original_urlopen = urllib.request.urlopen
    original_call = LLMSecurityAnalyzer._call_ollama

    def urlopen_wrapper(req: Any, *args: Any, **kwargs: Any) -> Any:
        kwargs["timeout"] = seconds
        return original_urlopen(req, *args, **kwargs)

    def call_wrapper(self: Any, prompt: str, num_predict: int = 200) -> Any:
        return original_call(self, prompt, max(num_predict, min_num_predict))

    urllib.request.urlopen = urlopen_wrapper  # type: ignore[assignment]
    LLMSecurityAnalyzer._call_ollama = call_wrapper  # type: ignore[assignment]
    try:
        yield
    finally:
        urllib.request.urlopen = original_urlopen  # type: ignore[assignment]
        LLMSecurityAnalyzer._call_ollama = original_call  # type: ignore[assignment]


def sample_specs(corpus_list: Path) -> Dict[str, ev.SampleSpec]:
    """The run plan, indexed the way the affected set is indexed."""
    return {spec.sample_id: spec for spec in ev.load_corpus_list(corpus_list)}


def replay_one(
    spec: ev.SampleSpec,
    benchmark_root: Path,
    out_dir: Path,
    engine: str,
    audit_mode: str,
    policy: str,
    llm_model: str,
    llm_seed: int,
    max_findings: int,
    extensions: Tuple[str, ...],
) -> Dict[str, Any]:
    """Re-run one sample through the production pipeline, returning its row."""
    return ev.analyse_sample(
        sample=spec,
        sample_dir=benchmark_root / spec.relative_path,
        results_dir=out_dir,
        audit_mode=audit_mode,
        policy=policy,
        llm_backend="ollama",
        llm_model=llm_model,
        extensions=extensions,
        max_findings=max_findings,
        engine=engine,
        llm_seed=llm_seed,
    )


def recorded_decision(run_dir: Path, sample_id: str) -> Dict[str, Any]:
    """The recorded label and the run settings the replay has to mirror.

    Read from the artifact rather than assumed, so a replay cannot silently
    describe a different policy or model than the run it is meant to explain.
    """
    report_path = run_dir / sample_id / "audit_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    meta = report.get("scan_metadata") or {}
    conclusion = report.get("conclusion") or {}
    passed = conclusion.get("passed")
    return {
        "predicted_label": "malicious" if passed is False else "benign",
        "policy": meta.get("policy"),
        "llm_model": meta.get("llm_model"),
        "llm_seed": meta.get("llm_seed"),
        "rules_count": meta.get("rules_count"),
        "llm_enabled": meta.get("llm_enabled"),
    }


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-dir", type=Path, required=True,
                        help="the source matrix base dir, read-only")
    parser.add_argument("--out-dir", type=Path, required=True,
                        help="where the replay writes; must not already hold a replay")
    parser.add_argument("--benchmark-root", type=Path,
                        default=REPO_ROOT / "models/audit/benchmarks/audit-holdout")
    parser.add_argument("--corpus-list", type=Path,
                        default=REPO_ROOT / "models/audit/benchmarks/audit-holdout/corpus-list.json")
    parser.add_argument("--timeout", type=int, default=300,
                        help="the HTTP timeout the replay uses instead of the production 60 s")
    parser.add_argument("--min-num-predict", type=int, default=DEFAULT_MIN_NUM_PREDICT,
                        help="floor under num_predict, so a generation truncated by the "
                             "production 200/300-token cap gets room to close its JSON")
    parser.add_argument("--max-findings", type=int, default=DEFAULT_MAX_FINDINGS)
    parser.add_argument("--runs", default=None,
                        help="comma-separated run dirs to cover; default is all of them")
    parser.add_argument("--dry-run", action="store_true",
                        help="list the affected samples and write nothing")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    affected = affected_samples(args.base_dir)
    if args.runs:
        wanted = {name.strip() for name in args.runs.split(",") if name.strip()}
        affected = {key: value for key, value in affected.items() if key.split("/")[0] in wanted}

    total_failures = sum(len(value) for value in affected.values())
    by_kind: Dict[str, int] = {}
    for failures in affected.values():
        for failure in failures:
            by_kind[failure["kind"]] = by_kind.get(failure["kind"], 0) + 1

    print(f"affected samples: {len(affected)}   failed calls: {total_failures}   by kind: {by_kind}")
    for key in sorted(affected):
        print(f"  {key}  {len(affected[key])} failed call(s)")

    if args.dry_run or not affected:
        # The running-matrix guard is checked here rather than at the top because
        # both of its reasons are about the replay: it spends model calls inside
        # the measurement window, and the affected set it works from would be a
        # snapshot of a moving target. A dry run does neither, so it may be used
        # against a live matrix -- but then its list is exactly that snapshot, and
        # saying so is the point of this warning.
        if (args.base_dir / ".running").exists():
            print("WARNING: the source matrix is still running; this list is a snapshot, "
                  "not the final affected set")
        return 0

    assert_matrix_not_running(args.base_dir)

    assert_output_dir_free(args.out_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    specs = sample_specs(args.corpus_list)

    print(f"replaying with HTTP timeout {args.timeout} s instead of the production 60 s")
    print(f"replaying with num_predict floored at {args.min_num_predict} "
          f"(production: 200 for a finding, 300 for a file summary)")
    print("these two wrappers are the ONLY difference from the production path")

    rows: List[Dict[str, Any]] = []
    with patched_call_budget(args.timeout, args.min_num_predict):
        for key in sorted(affected):
            run_name, sample_id = key.split("/", 1)
            spec = specs.get(sample_id)
            if spec is None:
                raise CounterfactualError(f"{sample_id} is not in {args.corpus_list}")
            engine = run_name.split("-")[0]
            recorded = recorded_decision(args.base_dir / run_name, sample_id)
            if recorded["rules_count"] != STATIC_LLM_RULES_COUNT:
                raise CounterfactualError(
                    f"{key}: rules_count={recorded['rules_count']} does not look like a "
                    f"{DEFAULT_AUDIT_MODE} run; replaying under another mode would "
                    "produce a counterfactual of a different pipeline"
                )
            row = replay_one(
                spec=spec,
                benchmark_root=args.benchmark_root,
                out_dir=args.out_dir / run_name,
                engine=engine,
                audit_mode=DEFAULT_AUDIT_MODE,
                policy=recorded["policy"],
                llm_model=recorded["llm_model"],
                llm_seed=recorded["llm_seed"],
                max_findings=args.max_findings,
                extensions=(DEFAULT_EXTENSIONS,),
            )
            counterfactual = row.get("predicted_label")
            material = counterfactual != recorded["predicted_label"]
            rows.append({
                "run": run_name,
                "sample_id": sample_id,
                "label": spec.label,
                "recorded": recorded["predicted_label"],
                "counterfactual": counterfactual,
                "material": material,
                "transition": (classify_transition(spec.label, recorded["predicted_label"], counterfactual)
                               if material else None),
                "failed_calls": affected[key],
            })
            flag = "MATERIAL" if material else "unchanged"
            print(f"  {key:<28} label={spec.label:<9} {recorded['predicted_label']:<9} -> "
                  f"{counterfactual:<9} {flag}")

    transitions: Dict[str, int] = {}
    for row in rows:
        if row["transition"]:
            transitions[row["transition"]] = transitions.get(row["transition"], 0) + 1

    summary = {
        "tool": TOOL_PATH.name,
        "tool_sha256": tool_digest(),
        "source_base_dir": str(args.base_dir),
        "patched_http_timeout_sec": args.timeout,
        "production_http_timeout_sec": 60,
        "patched_min_num_predict": args.min_num_predict,
        "production_num_predict": {"finding": 200, "file": 300},
        "material_rule": MATERIAL_RULE,
        "affected_samples": len(rows),
        "material_samples": sum(1 for row in rows if row["material"]),
        "transitions": transitions,
        "rows": rows,
    }
    (args.out_dir / "counterfactual-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"material: {summary['material_samples']}/{len(rows)} samples; transitions: {transitions or '{}'}")
    print(f"summary: {args.out_dir / 'counterfactual-summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
