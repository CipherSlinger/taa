#!/usr/bin/env python3
"""Run and export the 100-sample code-audit benchmark.

This script is the executable companion to:
- docs/audit/audit-benchmark-manifest.md
- docs/audit/audit-evaluation-design.md
- docs/audit/audit-evaluation-results-template.md

It serves two jobs:
1. expand the family-level benchmark spec into a machine-readable 100-sample manifest;
2. evaluate sample directories with the existing static scanner + LLM analyzer and
   write per-sample / aggregate results.

The script is intentionally self-contained so the benchmark can be exported,
reviewed, and re-run without duplicating the audit logic.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.examples.code_security_analyzer import (  # noqa: E402
    LLMSecurityAnalyzer,
    StaticScanner,
    generate_audit_report,
)

BENCHMARK_NAME = "audit-100"
BENCHMARK_VERSION = "2026-08-30"
DEFAULT_BENCHMARK_ROOT = REPO_ROOT / "benchmarks" / BENCHMARK_NAME
DEFAULT_MANIFEST_OUT = REPO_ROOT / "docs" / "audit" / "audit-benchmark-manifest.json"
DEFAULT_RESULTS_DIR = REPO_ROOT / "models" / "audit" / "audit-results" / BENCHMARK_NAME
DEFAULT_RULE_SET_VERSION = "default-rules-13"
DEFAULT_PROMPT_VERSION = "audit-prompt-v1"
BASE_PROJECTS = ("LogisticRegression", "TEE-test", "Retina-DKD")

# The family-to-project allocation is fixed so the overall distribution stays
# balanced: 17 / 17 / 16 per base project for benign and malicious halves.
PROJECT_ALLOCATION = {
    "B1": {"LogisticRegression": 5, "TEE-test": 5, "Retina-DKD": 0},
    "B2": {"LogisticRegression": 5, "TEE-test": 5, "Retina-DKD": 0},
    "B3": {"LogisticRegression": 5, "TEE-test": 5, "Retina-DKD": 0},
    "B4": {"LogisticRegression": 5, "TEE-test": 5, "Retina-DKD": 0},
    "B5": {"LogisticRegression": 5, "TEE-test": 5, "Retina-DKD": 0},
    "M1": {"LogisticRegression": 0, "TEE-test": 0, "Retina-DKD": 10},
    "M2": {"LogisticRegression": 0, "TEE-test": 0, "Retina-DKD": 10},
    "M3": {"LogisticRegression": 0, "TEE-test": 0, "Retina-DKD": 10},
    "M4": {"LogisticRegression": 0, "TEE-test": 0, "Retina-DKD": 10},
    "M5": {"LogisticRegression": 0, "TEE-test": 0, "Retina-DKD": 10},
}


@dataclass(frozen=True)
class FamilySpec:
    family: str
    label: str
    count: int
    transformation: str
    expected_rules: tuple[str, ...]
    expected_severity: str
    expected_final: str
    trap_type: str
    notes: str


FAMILY_SPECS: tuple[FamilySpec, ...] = (
    FamilySpec(
        family="B1",
        label="benign",
        count=10,
        transformation="pure_refactor_equivalent",
        expected_rules=(),
        expected_severity="LOW",
        expected_final="BENIGN",
        trap_type="refactor_fp",
        notes="函数拆分、重命名、import 调整、模块重组，但不引入恶意行为。",
    ),
    FamilySpec(
        family="B2",
        label="benign",
        count=10,
        transformation="safe_logging_and_debug",
        expected_rules=("EMB_003",),
        expected_severity="LOW",
        expected_final="BENIGN",
        trap_type="debug_logging_fp",
        notes="增加结构化日志、调试输出和状态统计，但不打印敏感数据。",
    ),
    FamilySpec(
        family="B3",
        label="benign",
        count=10,
        transformation="data_loading_and_config_wrapping",
        expected_rules=("FIL_001", "ENV_001"),
        expected_severity="LOW",
        expected_final="BENIGN",
        trap_type="config_read_fp",
        notes="封装数据读取、配置文件和 CLI 参数，避免把正常配置读取误判为窃密。",
    ),
    FamilySpec(
        family="B4",
        label="benign",
        count=10,
        transformation="report_generation_and_export",
        expected_rules=("EMB_001", "EMB_002", "EMB_003"),
        expected_severity="LOW",
        expected_final="BENIGN",
        trap_type="report_export_fp",
        notes="生成训练报告、写 JSON/YAML/CSV、导出结果摘要，但不泄露原始数据。",
    ),
    FamilySpec(
        family="B5",
        label="benign",
        count=10,
        transformation="wrapper_and_entrypoint_rewrite",
        expected_rules=(),
        expected_severity="LOW",
        expected_final="BENIGN",
        trap_type="wrapper_fp",
        notes="增加 phase wrapper、入口脚本和参数解析，但不执行系统命令。",
    ),
    FamilySpec(
        family="M1",
        label="malicious",
        count=10,
        transformation="command_execution",
        expected_rules=("CMD_001",),
        expected_severity="HIGH",
        expected_final="MALICIOUS",
        trap_type="cmd_exec",
        notes="通过 os.system / subprocess 等执行系统命令，模拟命令执行型攻击。",
    ),
    FamilySpec(
        family="M2",
        label="malicious",
        count=10,
        transformation="network_exfiltration",
        expected_rules=("NET_001", "NET_002", "EXF_001"),
        expected_severity="HIGH",
        expected_final="MALICIOUS",
        trap_type="network_exfil",
        notes="通过 requests / socket / httpx 把结果外传到外部地址。",
    ),
    FamilySpec(
        family="M3",
        label="malicious",
        count=10,
        transformation="sensitive_data_theft",
        expected_rules=("FIL_001", "ENV_001"),
        expected_severity="MEDIUM",
        expected_final="MALICIOUS",
        trap_type="secret_theft",
        notes="读取 .env、.ssh、.aws 或环境变量中的密钥 / token。",
    ),
    FamilySpec(
        family="M4",
        label="malicious",
        count=10,
        transformation="obfuscation_and_encoding",
        expected_rules=("OBF_001", "EXF_001"),
        expected_severity="HIGH",
        expected_final="MALICIOUS",
        trap_type="obfuscation",
        notes="使用 base64、pickle、marshal 或压缩把载荷隐藏后再外传。",
    ),
    FamilySpec(
        family="M5",
        label="malicious",
        count=10,
        transformation="attack_chain_and_persistence",
        expected_rules=("CMD_001", "PER_001", "EXF_001"),
        expected_severity="HIGH",
        expected_final="MALICIOUS",
        trap_type="attack_chain",
        notes="把读取、编码、外传和持久化串成攻击链，测试跨文件推理。",
    ),
)


@dataclass(frozen=True)
class SampleSpec:
    sample_id: str
    base_project: str
    family: str
    label: str
    transformation: str
    expected_rules: tuple[str, ...]
    expected_severity: str
    expected_final: str
    trap_type: str
    notes: str
    relative_path: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_sample_specs(benchmark_root: Path) -> list[SampleSpec]:
    samples: list[SampleSpec] = []
    for spec in FAMILY_SPECS:
        per_project = PROJECT_ALLOCATION[spec.family]
        index = 1
        for base_project in BASE_PROJECTS:
            quota = per_project[base_project]
            for _ in range(quota):
                sample_id = f"{spec.family}-{index:02d}"
                relative_path = f"{base_project}/{sample_id}"
                samples.append(
                    SampleSpec(
                        sample_id=sample_id,
                        base_project=base_project,
                        family=spec.family,
                        label=spec.label,
                        transformation=spec.transformation,
                        expected_rules=spec.expected_rules,
                        expected_severity=spec.expected_severity,
                        expected_final=spec.expected_final,
                        trap_type=spec.trap_type,
                        notes=spec.notes,
                        relative_path=relative_path,
                    )
                )
                index += 1
        if index != spec.count + 1:
            raise ValueError(f"{spec.family} expands to {index - 1} samples, expected {spec.count}")
    return samples


def build_manifest(benchmark_root: Path) -> dict[str, Any]:
    samples = make_sample_specs(benchmark_root)
    family_rows = []
    for spec in FAMILY_SPECS:
        family_rows.append(
            {
                "family": spec.family,
                "label": spec.label,
                "count": spec.count,
                "transformation": spec.transformation,
                "expected_rules": list(spec.expected_rules),
                "expected_severity": spec.expected_severity,
                "expected_final": spec.expected_final,
                "trap_type": spec.trap_type,
                "notes": spec.notes,
                "project_allocation": PROJECT_ALLOCATION[spec.family],
            }
        )

    return {
        "benchmark_name": BENCHMARK_NAME,
        "benchmark_version": BENCHMARK_VERSION,
        "benchmark_root": str(benchmark_root),
        "base_projects": list(BASE_PROJECTS),
        "rule_set_version": DEFAULT_RULE_SET_VERSION,
        "prompt_version": DEFAULT_PROMPT_VERSION,
        "totals": {
            "samples": len(samples),
            "benign": sum(1 for sample in samples if sample.label == "benign"),
            "malicious": sum(1 for sample in samples if sample.label == "malicious"),
        },
        "families": family_rows,
        "samples": [asdict(sample) for sample in samples],
    }


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: Any) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_module_scanner() -> StaticScanner:
    return StaticScanner()


def analyse_sample(
    sample: SampleSpec,
    sample_dir: Path,
    results_dir: Path,
    policy: str,
    llm_backend: str,
    llm_model: str,
    extensions: tuple[str, ...],
    max_findings: int,
) -> dict[str, Any]:
    sample_out_dir = results_dir / sample.sample_id
    sample_out_dir.mkdir(parents=True, exist_ok=True)
    report_path = sample_out_dir / "audit_report.json"

    if not sample_dir.exists():
        return {
            "sample_id": sample.sample_id,
            "base_project": sample.base_project,
            "family": sample.family,
            "label": sample.label,
            "predicted_label": "missing",
            "predicted_verdict": "UNCERTAIN",
            "predicted_risk": "UNKNOWN",
            "blocked": False,
            "matched_rules": [],
            "reason": f"missing sample directory: {sample_dir}",
            "error_type": "missing_sample",
            "llm_state": "missing_sample",
            "expected_rules": list(sample.expected_rules),
            "expected_severity": sample.expected_severity,
            "expected_final": sample.expected_final,
            "trap_type": sample.trap_type,
            "sample_path": str(sample_dir),
            "report_path": str(report_path),
            "files_scanned": 0,
            "total_findings": 0,
            "llm_available": False,
            "fail_closed": False,
            "audit_report": None,
        }

    scanner = load_module_scanner()
    findings = scanner.scan_directory(str(sample_dir), extensions=extensions)

    file_summaries: Dict[str, Any] = {}
    analyzer = None
    if llm_backend != "none" and findings:
        analyzer = LLMSecurityAnalyzer(model_name=llm_model, backend=llm_backend)
        for finding in findings[:max_findings]:
            analyzer.analyze_finding(finding)
        for file_path, file_findings in group_findings_by_file(findings).items():
            file_summaries[file_path] = analyzer.analyze_file(file_path, file_findings)

    started_at = utc_now_iso()
    finished_at = utc_now_iso()
    report = generate_audit_report(
        findings,
        str(sample_dir),
        file_summaries,
        str(report_path),
        policy=policy,
        llm_model=llm_model,
        llm_enabled=(llm_backend != "none"),
        scan_duration_ms=0,
    )

    matched_rules = sorted({finding.rule_id for finding in findings})
    llm_state = classify_llm_state(findings, llm_backend)
    predicted_verdict = infer_predicted_verdict(report, llm_state)
    predicted_label = "malicious" if not report["conclusion"]["passed"] else "benign"
    predicted_risk = report["conclusion"]["risk_level"]
    blocked = not report["conclusion"]["passed"]
    fail_closed = llm_state in {"llm_unavailable", "parse_error"} and blocked

    error_type = "ok"
    if llm_state == "static_only":
        error_type = "static_only"
    elif llm_state == "llm_unavailable":
        error_type = "llm_unavailable"
    elif llm_state == "parse_error":
        error_type = "parse_error"
    elif llm_state == "uncertain":
        error_type = "uncertain"

    if sample.label == "benign" and predicted_label == "malicious":
        error_type = "false_positive"
    elif sample.label == "malicious" and predicted_label == "benign":
        error_type = "false_negative"

    return {
        "sample_id": sample.sample_id,
        "base_project": sample.base_project,
        "family": sample.family,
        "label": sample.label,
        "predicted_label": predicted_label,
        "predicted_verdict": predicted_verdict,
        "predicted_risk": predicted_risk,
        "blocked": blocked,
        "matched_rules": matched_rules,
        "reason": report["conclusion"]["summary"],
        "error_type": error_type,
        "llm_state": llm_state,
        "expected_rules": list(sample.expected_rules),
        "expected_severity": sample.expected_severity,
        "expected_final": sample.expected_final,
        "trap_type": sample.trap_type,
        "sample_path": str(sample_dir),
        "report_path": str(report_path),
        "files_scanned": report["target"]["files_scanned"],
        "total_findings": report["statistics"]["total_findings"],
        "llm_available": llm_state == "ok",
        "fail_closed": fail_closed,
        "started_at": started_at,
        "finished_at": finished_at,
        "audit_report": report,
    }


def group_findings_by_file(findings: Iterable[Any]) -> dict[str, list[Any]]:
    groups: dict[str, list[Any]] = {}
    for finding in findings:
        groups.setdefault(finding.file, []).append(finding)
    return groups


def classify_llm_state(findings: Iterable[Any], llm_backend: str) -> str:
    if llm_backend == "none":
        return "static_only"

    findings = list(findings)
    if not findings:
        return "static_only"

    reasons = [getattr(finding, "llm_reason", "") or "" for finding in findings]
    verdicts = [getattr(finding, "llm_verdict", "") or "" for finding in findings]
    joined = "\n".join(reasons)

    if any("调用失败" in reason or "未配置推理后端" in reason for reason in reasons):
        return "llm_unavailable"
    if any("无法解析" in reason or "解析失败" in reason or "decode response" in reason for reason in reasons):
        return "parse_error"
    if any(verdict == "UNCERTAIN" for verdict in verdicts):
        return "uncertain"
    if joined:
        return "ok"
    return "llm_unavailable"


def infer_predicted_verdict(report: dict[str, Any], llm_state: str) -> str:
    if report["conclusion"]["passed"]:
        return "BENIGN"

    verdicts: list[str] = []
    for file_report in report.get("file_reports", []):
        for finding in file_report.get("findings", []):
            verdict = finding.get("llm_verdict", "")
            if verdict:
                verdicts.append(verdict)

    if "MALICIOUS" in verdicts:
        return "MALICIOUS"
    if "SUSPICIOUS" in verdicts:
        return "SUSPICIOUS"
    if llm_state in {"static_only", "llm_unavailable", "parse_error", "uncertain"}:
        return "UNCERTAIN"
    return "SUSPICIOUS"


def confusion_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for row in results:
        truth = row["label"] == "malicious"
        pred = row["predicted_label"] == "malicious"
        if truth and pred:
            tp += 1
        elif truth and not pred:
            fn += 1
        elif not truth and pred:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def metric_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = confusion_counts(results)
    tp = counts["tp"]
    fp = counts["fp"]
    tn = counts["tn"]
    fn = counts["fn"]
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    f05 = safe_div(1.25 * precision * recall, 0.25 * precision + recall)
    accuracy = safe_div(tp + tn, tp + tn + fp + fn)
    llm_available_rate = safe_div(sum(1 for row in results if row["llm_available"]), len(results))
    fail_closed_count = sum(1 for row in results if row["fail_closed"])

    return {
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
        "fnr": fnr,
        "f1": f1,
        "f0_5": f05,
        "accuracy": accuracy,
        "llm_available_rate": llm_available_rate,
        "fail_closed_count": fail_closed_count,
    }


def error_breakdown(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in results:
        key = row.get("error_type", "ok") or "ok"
        counts[key] = counts.get(key, 0) + 1
    return counts


def build_summary_report(
    results: list[dict[str, Any]],
    benchmark_root: Path,
    policy: str,
    llm_backend: str,
    llm_model: str,
    notes: str,
) -> dict[str, Any]:
    counts = confusion_counts(results)
    metrics = metric_summary(results)
    return {
        "run_id": f"{BENCHMARK_NAME}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        "run_time": utc_now_iso(),
        "benchmark_version": BENCHMARK_VERSION,
        "auditor_version": f"{llm_backend}:{llm_model}" if llm_backend != "none" else "static-only",
        "rule_set_version": DEFAULT_RULE_SET_VERSION,
        "prompt_version": DEFAULT_PROMPT_VERSION,
        "policy": policy,
        "notes": notes,
        "benchmark_root": str(benchmark_root),
        "counts": counts,
        "metrics": metrics,
        "errors": error_breakdown(results),
    }


def write_results_bundle(results_dir: Path, results: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    write_json(results_dir / "summary.json", summary)

    jsonl_path = results_dir / "sample-results.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in results:
            row = dict(row)
            row.pop("audit_report", None)
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    write_json(results_dir / "confusion-matrix.json", summary["counts"])
    write_csv(results_dir / "sample-results.csv", results)
    write_markdown(results_dir / "final-report.md", results, summary)


def write_csv(path: Path, results: list[dict[str, Any]]) -> None:
    ensure_parent(path)
    fieldnames = [
        "sample_id",
        "base_project",
        "family",
        "label",
        "predicted_label",
        "predicted_risk",
        "blocked",
        "llm_state",
        "error_type",
        "matched_rules",
        "sample_path",
        "report_path",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow({
                "sample_id": row["sample_id"],
                "base_project": row["base_project"],
                "family": row["family"],
                "label": row["label"],
                "predicted_label": row["predicted_label"],
                "predicted_risk": row["predicted_risk"],
                "blocked": row["blocked"],
                "llm_state": row["llm_state"],
                "error_type": row["error_type"],
                "matched_rules": ";".join(row.get("matched_rules", [])),
                "sample_path": row["sample_path"],
                "report_path": row["report_path"],
            })


def write_markdown(path: Path, results: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    metric = summary["metrics"]
    counts = summary["counts"]
    errors = summary["errors"]
    lines = [
        f"# {BENCHMARK_NAME} 评测结果",
        "",
        f"- 运行时间: {summary['run_time']}",
        f"- 基准版本: {summary['benchmark_version']}",
        f"- 审计器: {summary['auditor_version']}",
        f"- 策略: {summary['policy']}",
        f"- 备注: {summary['notes'] or '无'}",
        "",
        "## 指标",
        "",
        f"- precision: {metric['precision']:.4f}",
        f"- recall: {metric['recall']:.4f}",
        f"- fpr: {metric['fpr']:.4f}",
        f"- fnr: {metric['fnr']:.4f}",
        f"- f1: {metric['f1']:.4f}",
        f"- f0.5: {metric['f0_5']:.4f}",
        f"- accuracy: {metric['accuracy']:.4f}",
        f"- llm_available_rate: {metric['llm_available_rate']:.4f}",
        f"- fail_closed_count: {metric['fail_closed_count']}",
        "",
        "## 混淆矩阵",
        "",
        f"- tp: {counts['tp']}",
        f"- fp: {counts['fp']}",
        f"- tn: {counts['tn']}",
        f"- fn: {counts['fn']}",
        "",
        "## 错误分类",
        "",
    ]
    for key in sorted(errors):
        lines.append(f"- {key}: {errors[key]}")
    lines.extend([
        "",
        "## 样本概览",
        "",
        f"- 总样本数: {len(results)}",
        f"- 良性: {sum(1 for row in results if row['label'] == 'benign')}",
        f"- 恶意: {sum(1 for row in results if row['label'] == 'malicious')}",
    ])
    ensure_parent(path)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run and export the code-audit benchmark")
    parser.add_argument("--benchmark-root", type=Path, default=DEFAULT_BENCHMARK_ROOT, help="root directory containing benchmark sample folders")
    parser.add_argument("--manifest-out", type=Path, default=DEFAULT_MANIFEST_OUT, help="write the normalized benchmark manifest to this file")
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR, help="directory for benchmark output artifacts")
    parser.add_argument("--policy", choices=["assist", "gate"], default="gate", help="audit policy to use")
    parser.add_argument("--llm-backend", choices=["none", "ollama", "llamacpp"], default="none", help="LLM backend used for semantic verification")
    parser.add_argument("--llm-model", default="qwen2.5-coder:0.5b", help="LLM model name")
    parser.add_argument("--extensions", default=".py", help="comma-separated list of source extensions to scan")
    parser.add_argument("--max-findings", type=int, default=50, help="max findings to send to the LLM per sample")
    parser.add_argument("--limit", type=int, default=0, help="limit the number of samples to evaluate")
    parser.add_argument("--notes", default="", help="free-form notes recorded in the summary")
    parser.add_argument("--dump-manifest", action="store_true", help="write the normalized manifest and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = build_manifest(args.benchmark_root)
    write_json(args.manifest_out, manifest)

    if args.dump_manifest:
        print(f"manifest written to: {args.manifest_out}")
        return 0

    samples = [SampleSpec(**sample) for sample in manifest["samples"]]
    if args.limit and args.limit > 0:
        samples = samples[: args.limit]

    extensions = tuple(ext.strip() for ext in args.extensions.split(",") if ext.strip())
    results: list[dict[str, Any]] = []
    for sample in samples:
        sample_dir = args.benchmark_root / sample.relative_path
        results.append(
            analyse_sample(
                sample=sample,
                sample_dir=sample_dir,
                results_dir=args.results_dir,
                policy=args.policy,
                llm_backend=args.llm_backend,
                llm_model=args.llm_model,
                extensions=extensions,
                max_findings=args.max_findings,
            )
        )

    summary = build_summary_report(
        results=results,
        benchmark_root=args.benchmark_root,
        policy=args.policy,
        llm_backend=args.llm_backend,
        llm_model=args.llm_model,
        notes=args.notes,
    )
    write_results_bundle(args.results_dir, results, summary)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"results written to: {args.results_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
