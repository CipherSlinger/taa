# models/audit/tools/prompt_equivalence.py
"""Capture and compare the prompts the two Tier 1 engines send to the model.

Spec section 9.2 requirement 8: per-sample prompt equivalence between the arms.
Without it a difference in verdicts is not attributable to the engine, because
the model was asked a different question. The inequivalence is live: the regex
adapter fills context_before/context_after and the semgrep adapter fills
ast_enclosing_block, and the analyzer branches on exactly those fields.

This module records what each engine would send, and reports the two kinds of
difference separately:

* the arms report different hits. That is the engine difference the comparison
  exists to measure.
* the arms report the same hit and ask different questions about it. That is a
  confound, and it is reported as a violation with the values that differed
  named, so a reader can act on it.

Capture never contacts a model: the analyzer it builds has no backend, so a
capture run cannot send a prompt even if a caller changes the code to try.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools import audit_benchmark_eval as ev  # noqa: E402
from models.examples.code_security_analyzer import LLMSecurityAnalyzer  # noqa: E402

DEFAULT_ENGINES = ("regex", "semgrep")
DEFAULT_RESULTS_NAME = "prompt-equivalence.json"


def prompt_digest(prompt: str) -> str:
    """The digest the comparison keys on, so a report can be checked without the text."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def build_capture_analyzer(model_name: str = "prompt-capture") -> LLMSecurityAnalyzer:
    """An analyzer that can render a prompt but has nowhere to send it.

    Capture is observation only. The backend is "none" rather than a real one so
    that the tool cannot reach a model by construction, not by discipline.
    """
    return LLMSecurityAnalyzer(model_name=model_name, backend="none")


def file_key(file_path: str, sample_dir: str) -> str:
    """A file's identity within its sample, so two engines' paths can be compared.

    Both engines scan the same directory but each reports the path its own way -
    one from our walk of the directory, the other from the scanner's own output.
    Resolving both against the sample directory makes the key independent of how
    the sample was addressed. A path outside the sample is kept as reported
    rather than reduced to its basename, which would merge two same-named files
    in different directories into one key.
    """
    try:
        return str(Path(file_path).resolve().relative_to(Path(sample_dir).resolve()))
    except (ValueError, OSError):
        return str(file_path)


def _entry(level: str, prompt: str, slots: Dict[str, Any], **ids: Any) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"level": level}
    entry.update(ids)
    entry["prompt"] = prompt
    entry["prompt_sha256"] = prompt_digest(prompt)
    entry["slots"] = slots
    return entry


def capture_prompts(
    sample_dir: str,
    engine: str,
    max_findings: int = 50,
    extensions: Sequence[str] = (".py",),
    analyzer: Optional[LLMSecurityAnalyzer] = None,
) -> Dict[str, Any]:
    """Every prompt this engine would send for this sample.

    The hits are selected by the evaluator's own deduplication and cap and
    grouped by its own grouping, so the capture describes the arbitration that
    would actually happen rather than a reconstruction of it.

    An unfinished scan yields no prompts. The findings a partial scan produced
    are not a basis for comparing what the model would be asked, and a sample
    that cannot be scored must not contribute prompt evidence that looks clean.
    """
    analyzer = analyzer or build_capture_analyzer()
    scanner = ev.load_module_scanner(engine=engine)
    outcome = scanner.scan_directory(str(sample_dir), extensions=tuple(extensions))
    findings = list(outcome.findings)
    deduped = ev.dedupe_findings_for_llm(findings)

    entries: List[Dict[str, Any]] = []
    if outcome.scan_complete:
        for finding in deduped[:max_findings]:
            entries.append(_entry(
                "finding",
                analyzer.build_finding_prompt(finding),
                analyzer.finding_prompt_slots(finding),
                file=file_key(finding.file, sample_dir),
                rule_id=finding.rule_id,
                line=finding.line,
            ))
        # The per-file prompt is built from the grouped findings, exactly as the
        # pipeline builds it, so the grouping here is the pipeline's grouping.
        for file_path, file_findings in ev.group_findings_by_file(deduped).items():
            prompt = analyzer.build_file_prompt(file_path, file_findings)
            if prompt is None:
                continue
            entries.append(_entry(
                "file",
                prompt,
                analyzer.file_prompt_slots(file_path, file_findings),
                file=file_key(file_path, sample_dir),
            ))

    return {
        "engine": engine,
        "sample_dir": str(sample_dir),
        "scan_complete": outcome.scan_complete,
        "scan_error": outcome.error_message,
        "findings": len(findings),
        "deduped": len(deduped),
        "entries": entries,
    }


def _differing_slots(regex_slots: Dict[str, Any], semgrep_slots: Dict[str, Any]) -> List[str]:
    names = set(regex_slots or {}) | set(semgrep_slots or {})
    return sorted(name for name in names if (regex_slots or {}).get(name) != (semgrep_slots or {}).get(name))


def _hit_key(entry: Dict[str, Any]) -> Tuple[str, str, int]:
    return entry["file"], entry["rule_id"], entry["line"]


def _hit_label(key: Tuple[str, str, int]) -> str:
    return f"{key[0]}:{key[1]}:{key[2]}"


def compare_captures(regex_capture: Dict[str, Any], semgrep_capture: Dict[str, Any]) -> Dict[str, Any]:
    """Compare the two arms' prompts for one sample.

    `comparable` is False when either arm's scan did not finish, in which case
    there is nothing to compare and `equivalent` is False as well - a sample with
    no prompt evidence must not read as a sample with clean prompt evidence.
    """
    comparable = bool(regex_capture.get("scan_complete")) and bool(semgrep_capture.get("scan_complete"))

    regex_hits = {_hit_key(e): e for e in regex_capture.get("entries", []) if e["level"] == "finding"}
    semgrep_hits = {_hit_key(e): e for e in semgrep_capture.get("entries", []) if e["level"] == "finding"}

    violations: List[Dict[str, Any]] = []
    for key in sorted(set(regex_hits) & set(semgrep_hits)):
        regex_entry, semgrep_entry = regex_hits[key], semgrep_hits[key]
        if regex_entry["prompt_sha256"] == semgrep_entry["prompt_sha256"]:
            continue
        violations.append({
            "level": "finding",
            "file": key[0],
            "rule_id": key[1],
            "line": key[2],
            "reason": "the same hit with a different prompt",
            "differing_slots": _differing_slots(regex_entry["slots"], semgrep_entry["slots"]),
            "regex_prompt_sha256": regex_entry["prompt_sha256"],
            "semgrep_prompt_sha256": semgrep_entry["prompt_sha256"],
        })

    regex_files = {e["file"]: e for e in regex_capture.get("entries", []) if e["level"] == "file"}
    semgrep_files = {e["file"]: e for e in semgrep_capture.get("entries", []) if e["level"] == "file"}

    files: List[Dict[str, Any]] = []
    for file in sorted(set(regex_files) | set(semgrep_files)):
        regex_entry = regex_files.get(file)
        semgrep_entry = semgrep_files.get(file)
        if regex_entry is None or semgrep_entry is None:
            files.append({
                "file": file,
                "same_hit_sets": False,
                "same_hit_order": False,
                "prompt_identical": False,
                "differing_slots": [],
                "reason": "the per-file prompt exists in one arm only",
            })
            continue

        regex_order = [(_hit_key(e)[1], _hit_key(e)[2]) for e in regex_hits.values() if _hit_key(e)[0] == file]
        semgrep_order = [(_hit_key(e)[1], _hit_key(e)[2]) for e in semgrep_hits.values() if _hit_key(e)[0] == file]
        identical = regex_entry["prompt_sha256"] == semgrep_entry["prompt_sha256"]
        same_sets = sorted(regex_order) == sorted(semgrep_order)

        if identical:
            reason = "identical"
        elif not same_sets:
            # The per-file prompt states how many hits were found, so a difference
            # in the hit set reaches it. That is the engine difference showing
            # through, not a confound.
            reason = "the arms report different hits for this file"
        elif regex_order != semgrep_order:
            reason = "the same hits in a different order, which is different text to the model"
        else:
            reason = "the same hits with a different prompt"

        row = {
            "file": file,
            "same_hit_sets": same_sets,
            "same_hit_order": regex_order == semgrep_order,
            "prompt_identical": identical,
            "differing_slots": _differing_slots(regex_entry["slots"], semgrep_entry["slots"]),
            "reason": reason,
        }
        files.append(row)

        if not identical and same_sets:
            violations.append({
                "level": "file",
                "file": file,
                "reason": reason,
                "differing_slots": row["differing_slots"],
                "regex_prompt_sha256": regex_entry["prompt_sha256"],
                "semgrep_prompt_sha256": semgrep_entry["prompt_sha256"],
            })

    return {
        "sample_dir": regex_capture.get("sample_dir") or semgrep_capture.get("sample_dir"),
        "comparable": comparable,
        "equivalent": comparable and not violations,
        "compared_hits": len(set(regex_hits) & set(semgrep_hits)),
        "violations": violations,
        "arm_specific": {
            "regex_only": sorted(_hit_label(k) for k in set(regex_hits) - set(semgrep_hits)),
            "semgrep_only": sorted(_hit_label(k) for k in set(semgrep_hits) - set(regex_hits)),
        },
        "files": files,
    }


def run_comparison(
    samples: Sequence[Any],
    benchmark_root: Path,
    max_findings: int = 50,
    extensions: Sequence[str] = (".py",),
    engines: Sequence[str] = DEFAULT_ENGINES,
) -> Dict[str, Any]:
    """Capture and compare every sample, and total what was found."""
    left, right = engines[0], engines[1]
    analyzer = build_capture_analyzer()
    per_sample: List[Dict[str, Any]] = []
    not_comparable: List[Dict[str, str]] = []
    violation_count = 0
    arm_specific_count = 0
    equivalent_count = 0

    for sample in samples:
        sample_dir = benchmark_root / sample.relative_path
        captures = {
            engine: capture_prompts(str(sample_dir), engine=engine, max_findings=max_findings,
                                    extensions=extensions, analyzer=analyzer)
            for engine in (left, right)
        }
        comparison = compare_captures(captures[left], captures[right])
        row = {
            "sample_id": sample.sample_id,
            "family": sample.family,
            "label": sample.label,
            "relative_path": sample.relative_path,
            "scan_complete": {engine: captures[engine]["scan_complete"] for engine in (left, right)},
            "findings": {engine: captures[engine]["findings"] for engine in (left, right)},
            "compared_hits": comparison["compared_hits"],
            "equivalent": comparison["equivalent"],
            "violations": comparison["violations"],
            "arm_specific": comparison["arm_specific"],
            "files": comparison["files"],
        }
        per_sample.append(row)

        if not comparison["comparable"]:
            not_comparable.append({
                "sample_id": sample.sample_id,
                "reason": "; ".join(
                    f"{engine}: {captures[engine]['scan_error'] or 'scan did not complete'}"
                    for engine in (left, right) if not captures[engine]["scan_complete"]
                ),
            })
        if comparison["equivalent"]:
            equivalent_count += 1
        violation_count += len(comparison["violations"])
        arm_specific_count += len(comparison["arm_specific"]["regex_only"]) + len(comparison["arm_specific"]["semgrep_only"])

    return {
        "benchmark_root": str(benchmark_root),
        "max_findings": max_findings,
        "engines": [left, right],
        "totals": {
            "samples": len(per_sample),
            "comparable": len(per_sample) - len(not_comparable),
            "not_comparable": len(not_comparable),
            "equivalent": equivalent_count,
            "violations": violation_count,
            "arm_specific_hits": arm_specific_count,
        },
        "not_comparable": not_comparable,
        "samples": per_sample,
    }


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture and compare the prompts the two Tier 1 engines send to the model"
    )
    parser.add_argument("--benchmark-root", type=Path, default=ev.DEFAULT_BENCHMARK_ROOT,
                        help="root directory containing the sample folders")
    parser.add_argument("--corpus-list", type=Path, default=None,
                        help="JSON file declaring the samples to run; replaces the family-spec sample list")
    parser.add_argument("--results-dir", type=Path, default=None,
                        help=f"directory for the comparison artifact (default: alongside the benchmark root)")
    parser.add_argument("--max-findings", type=int, default=50, help="must match the run being explained")
    parser.add_argument("--extensions", default=".py", help="comma-separated list of source extensions to scan")
    parser.add_argument("--engines", default=",".join(DEFAULT_ENGINES), help="the arm pair, as engine,engine")
    parser.add_argument("--limit", type=int, default=0, help="limit the number of samples to compare")
    return parser.parse_args(args)


def main() -> int:
    args = parse_args()
    if args.corpus_list:
        samples = ev.load_corpus_list(args.corpus_list)
    else:
        samples = [ev.SampleSpec(**sample) for sample in ev.build_manifest(args.benchmark_root)["samples"]]
    if args.limit and args.limit > 0:
        samples = samples[: args.limit]

    engines = tuple(name.strip() for name in args.engines.split(",") if name.strip())
    if len(engines) != 2:
        raise SystemExit(f"--engines needs exactly two engines, got {len(engines)}")

    extensions = tuple(ext.strip() for ext in args.extensions.split(",") if ext.strip())
    report = run_comparison(
        samples=samples,
        benchmark_root=args.benchmark_root,
        max_findings=args.max_findings,
        extensions=extensions,
        engines=engines,
    )
    report["corpus_list"] = str(args.corpus_list) if args.corpus_list else None

    results_dir = args.results_dir or (args.benchmark_root / "prompt-equivalence")
    out_path = results_dir / DEFAULT_RESULTS_NAME
    ev.write_json(out_path, report)

    totals = report["totals"]
    print(f"samples compared     : {totals['comparable']} of {totals['samples']}")
    print(f"not comparable       : {totals['not_comparable']}")
    print(f"samples equivalent   : {totals['equivalent']}")
    print(f"prompt violations    : {totals['violations']}")
    print(f"arm-specific hits    : {totals['arm_specific_hits']}")
    print(f"written to           : {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
