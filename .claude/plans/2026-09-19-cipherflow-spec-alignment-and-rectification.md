# CipherFlow Spec Alignment and Rectification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align `models/spec` (CipherFlow Python SDK & Protobuf specifications) with TAA's latest three-tier output directory isolation (`/opt/taa/output/{result,log,progress}`), eradicate forbidden network calls (`urllib`), add model terminal log support, and sync `.proto` contracts across the repository.

**Architecture:** Update `OutputPathSpec` in `sandbox.py` to manage `result_dir`, `log_dir`, and `progress_dir` with fallbacks and environment variable priorities matching TAA runtime; modernize `ProgressReporter` to emit dual `percent`/`percentage` payloads directly into `/opt/taa/output/progress/progress.json` without `urllib.request`; add `ModelLogger` for TAA's `JSONLLogReader`; synchronize all Protobuf definitions and docstrings in both `models/spec/cipherflow/protos/` and `api/proto/cipherflow/v1/`.

**Tech Stack:** Python 3.10+ (dataclasses, typing, pathlib), Protocol Buffers v3, Go (TAA contract consumers).

---

### File Structure & Responsibility

- `models/spec/cipherflow/sandbox.py`: Path conventions, `OutputPathSpec`, `TeePathContract`, environment variable resolution.
- `models/spec/cipherflow/result.py`: `TrainingResult` serialization, saving standard result to `result_dir/training_result.json`.
- `models/spec/cipherflow/logger.py` *(new)*: `ModelLogger` for writing terminal logs to `/opt/taa/output/log/model.log`.
- `models/spec/cipherflow/progress.py`: `ProgressReporter`, file flush to `/opt/taa/output/progress/progress.json`, removal of `urllib`.
- `models/spec/cipherflow/__init__.py`: Package exports for `ModelLogger`, `get_log_dir`, `get_progress_dir`.
- `models/spec/cipherflow/protos/cipherflow/v1/`: Protobuf schemas for sandbox, progress, result, evaluation.
- `api/proto/cipherflow/v1/`: Synchronized mirror of the protobuf schemas in root repo.
- `models/spec/tests/test_cipherflow.py`: Comprehensive test suite verifying paths, output files, telemetry, and audit compliance.

---

### Task 1: Clean Up Legacy Empty Directories in `models/spec`

**Files:**
- Remove: `models/spec/models/`
- Remove: `models/spec/api/`

- [ ] **Step 1: Check and remove residual empty directories**

```bash
rm -rf models/spec/models models/spec/api
```

- [ ] **Step 2: Verify directories are removed**

```bash
ls -la models/spec/models models/spec/api 2>&1 || true
```
Expected: `No such file or directory` for both.

---

### Task 2: Refactor Sandbox Path Contracts (`models/spec/cipherflow/sandbox.py`)

**Files:**
- Modify: `models/spec/cipherflow/sandbox.py`

- [ ] **Step 1: Update sandbox directory constants and path getters**

Add `DEFAULT_RESULT_DIR`, `DEFAULT_LOG_DIR`, `DEFAULT_PROGRESS_DIR`. Update `get_output_dir()`, `get_log_dir()`, `get_progress_dir()`, and `OutputPathSpec`:

```python
DEFAULT_INPUT_DIR = "/opt/taa/input"
DEFAULT_OUTPUT_DIR = "/opt/taa/output"
DEFAULT_RESULT_DIR = "/opt/taa/output/result"
DEFAULT_LOG_DIR = "/opt/taa/output/log"
DEFAULT_PROGRESS_DIR = "/opt/taa/output/progress"
DEFAULT_CHECKPOINT_DIR = "/opt/taa/checkpoint"
DEFAULT_RESULT_FILE = "training_result.json"
DEFAULT_PROGRESS_FILE = "progress.json"


def get_input_dir(fallback_dir: str | Path | None = None) -> Path:
    """Get the standard fixed input directory."""
    for i, arg in enumerate(sys.argv[:-1]):
        if arg in ("--input", "--data-dir", "-i"):
            return Path(sys.argv[i + 1]).expanduser().resolve(strict=False)

    for env_key in ("CIPHERFLOW_INPUT_DIR", "TAA_INPUT_DIR", "TAA_DATA_DIR", "TAA_MODEL_INPUT_DIR"):
        val = os.getenv(env_key)
        if val and val.strip():
            return Path(val.strip()).expanduser().resolve(strict=False)

    if fallback_dir:
        return Path(fallback_dir).expanduser().resolve(strict=False)

    return Path(DEFAULT_INPUT_DIR)


def get_output_dir(fallback_dir: str | Path | None = None) -> Path:
    """Get the standard model primary result directory (defaults to /opt/taa/output/result)."""
    for i, arg in enumerate(sys.argv[:-1]):
        if arg in ("--output", "--output-dir", "-o"):
            return Path(sys.argv[i + 1]).expanduser().resolve(strict=False)

    for env_key in ("CIPHERFLOW_OUTPUT_DIR", "TAA_OUTPUT_DIR", "TAA_MODEL_OUTPUT_DIR"):
        val = os.getenv(env_key)
        if val and val.strip():
            return Path(val.strip()).expanduser().resolve(strict=False)

    if fallback_dir:
        return Path(fallback_dir).expanduser().resolve(strict=False)

    return Path(DEFAULT_RESULT_DIR)


def get_log_dir(fallback_dir: str | Path | None = None) -> Path:
    """Get the standard model log directory (/opt/taa/output/log)."""
    for env_key in ("CIPHERFLOW_LOG_DIR", "TAA_MODEL_LOG_DIR", "TAA_LOG_DIR"):
        val = os.getenv(env_key)
        if val and val.strip():
            return Path(val.strip()).expanduser().resolve(strict=False)

    if fallback_dir:
        return Path(fallback_dir).expanduser().resolve(strict=False)

    return Path(DEFAULT_LOG_DIR)


def get_progress_dir(fallback_dir: str | Path | None = None) -> Path:
    """Get the standard model progress snapshot directory (/opt/taa/output/progress)."""
    for env_key in ("CIPHERFLOW_PROGRESS_DIR", "TAA_MODEL_PROGRESS_DIR", "TAA_PROGRESS_DIR"):
        val = os.getenv(env_key)
        if val and val.strip():
            return Path(val.strip()).expanduser().resolve(strict=False)

    if fallback_dir:
        return Path(fallback_dir).expanduser().resolve(strict=False)

    return Path(DEFAULT_PROGRESS_DIR)
```

- [ ] **Step 2: Update `OutputPathSpec` to maintain the three-tier hierarchy**

In `OutputPathSpec`:
```python
@dataclass
class OutputPathSpec:
    """Output path specification with three-tier isolation contract."""
    root_dir: Path = field(default_factory=lambda: Path(DEFAULT_OUTPUT_DIR))
    result_dir: Path = field(default_factory=get_output_dir)
    weights_dir: Path = field(init=False)
    training_result_file: Path = field(init=False)
    evaluation_result_file: Path = field(init=False)
    log_dir: Path = field(default_factory=get_log_dir)
    progress_dir: Path = field(default_factory=get_progress_dir)
    progress_file: Path = field(init=False)
    custom_slots: dict[str, Path] = field(default_factory=dict)
    access_mode: PathAccessMode = PathAccessMode.READ_WRITE

    def __post_init__(self):
        self.root_dir = Path(self.root_dir)
        self.result_dir = Path(self.result_dir)
        self.weights_dir = self.result_dir / "weights"
        self.training_result_file = self.result_dir / DEFAULT_RESULT_FILE
        self.evaluation_result_file = self.result_dir / "test_result.xlsx"
        self.log_dir = Path(self.log_dir)
        self.progress_dir = Path(self.progress_dir)
        self.progress_file = self.progress_dir / DEFAULT_PROGRESS_FILE

    def ensure_directories(self) -> None:
        """Create output subdirectories if they do not exist."""
        try:
            self.root_dir.mkdir(parents=True, exist_ok=True)
            self.result_dir.mkdir(parents=True, exist_ok=True)
            self.weights_dir.mkdir(parents=True, exist_ok=True)
            self.log_dir.mkdir(parents=True, exist_ok=True)
            self.progress_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
```

- [ ] **Step 3: Verify import and basic syntax**

Run: `PYTHONPATH=models/spec python3 -c "from cipherflow.sandbox import OutputPathSpec; o = OutputPathSpec(); print(o.result_dir, o.log_dir, o.progress_dir)"`
Expected output: `/opt/taa/output/result /opt/taa/output/log /opt/taa/output/progress`

---

### Task 3: Update Standard Training Result Output (`models/spec/cipherflow/result.py`)

**Files:**
- Modify: `models/spec/cipherflow/result.py`

- [ ] **Step 1: Ensure `TrainingResult.save()` writes to `result_dir`**

Review and ensure `save` in `models/spec/cipherflow/result.py`:
```python
    def save(self, output_dir: str | Path | None = None, filename: str = DEFAULT_RESULT_FILE) -> Path:
        """Save to training_result.json in the standard result directory."""
        target_dir = Path(output_dir) if output_dir else get_output_dir()
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / filename

        tmp_path = file_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
            f.write("\n")
        tmp_path.replace(file_path)
        print(f"[CIPHERFLOW_RESULT] Standard training result saved to: {file_path}", flush=True)
        return file_path
```

- [ ] **Step 2: Verify `TrainingResult.save()` default path**

Run:
```bash
PYTHONPATH=models/spec python3 -c "
from cipherflow.result import TrainingResult, TrainingTaskSummary, MetricsSummary, DatasetSummary
r = TrainingResult(TrainingTaskSummary(task_id='t1'), MetricsSummary(), DatasetSummary())
import tempfile
from pathlib import Path
with tempfile.TemporaryDirectory() as d:
    p = r.save(output_dir=d)
    assert p == Path(d) / 'training_result.json'
    assert p.exists()
"
```
Expected: `[CIPHERFLOW_RESULT] Standard training result saved to: ...`

---

### Task 4: Implement Terminal Logger (`models/spec/cipherflow/logger.py`)

**Files:**
- Create: `models/spec/cipherflow/logger.py`
- Modify: `models/spec/cipherflow/__init__.py`

- [ ] **Step 1: Create `models/spec/cipherflow/logger.py`**

```python
"""
Standard Model Terminal Logger writing to /opt/taa/output/log for TAA Forwarding.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .sandbox import get_log_dir


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ModelLogger:
    """Thread-safe terminal and file logger for models running in TAA CSV TEE."""

    def __init__(
        self,
        log_dir: str | Path | None = None,
        filename: str = "model.log",
        also_stdout: bool = True,
    ):
        self.log_dir = Path(log_dir) if log_dir else get_log_dir()
        self.filename = filename
        self.also_stdout = also_stdout
        self.log_file = self.log_dir / self.filename

        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def log(self, message: str, level: str = "INFO", **kwargs: Any) -> None:
        """Write a formatted log message."""
        timestamp = _utc_now_iso()
        formatted_line = f"[{timestamp}] [{level.upper()}] {message}"
        if kwargs:
            formatted_line += f" | {json.dumps(kwargs, ensure_ascii=False)}"

        if self.also_stdout:
            print(formatted_line, flush=True)

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(formatted_line + "\n")
        except OSError:
            pass

    def info(self, message: str, **kwargs: Any) -> None:
        self.log(message, level="INFO", **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self.log(message, level="WARNING", **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self.log(message, level="ERROR", **kwargs)
```

- [ ] **Step 2: Export `ModelLogger`, `get_log_dir`, `get_progress_dir` in `models/spec/cipherflow/__init__.py`**

In `models/spec/cipherflow/__init__.py`, import and add `ModelLogger`, `get_log_dir`, `get_progress_dir` to `__all__`.

- [ ] **Step 3: Verify import and log write**

Run:
```bash
PYTHONPATH=models/spec python3 -c "
import tempfile
from pathlib import Path
from cipherflow import ModelLogger
with tempfile.TemporaryDirectory() as d:
    logger = ModelLogger(log_dir=d, filename='test.log', also_stdout=False)
    logger.info('test message', epoch=1)
    content = (Path(d) / 'test.log').read_text()
    assert 'test message' in content
    assert '[INFO]' in content
"
```
Expected: Exit code 0.

---

### Task 5: Modernize Progress Reporting and Remove Network Dependencies (`models/spec/cipherflow/progress.py`)

**Files:**
- Modify: `models/spec/cipherflow/progress.py`

- [ ] **Step 1: Update `TrainingProgress` and `ProgressReporter`**

1. In `TrainingProgress.to_dict()`:
   Ensure both `percent` and `percentage` keys are present:
   ```python
   def to_dict(self) -> dict[str, Any]:
       d = asdict(self)
       d["percent"] = self.percentage
       return d
   ```
2. In `ProgressReporter.__init__`:
   Default `output_dir`:
   ```python
   self.output_dir = Path(output_dir) if output_dir else get_progress_dir()
   self.progress_file = self.output_dir / "progress.json"
   ```
3. Remove `_post_http` completely.
4. Remove `import urllib.request` entirely.
5. In `_emit()`:
   Only keep Channel 1 (STDOUT) and Channel 2 (File Flush). If `HTTP_POST` mode is requested, log a warning to stderr that TAA uses file-based progress polling.

- [ ] **Step 2: Check for any occurrence of `urllib` in `progress.py`**

Run: `grep -rn "urllib" models/spec/cipherflow/progress.py || true`
Expected: Empty output.

- [ ] **Step 3: Test file flush generating valid progress snapshot**

Run:
```bash
PYTHONPATH=models/spec python3 -c "
import tempfile, json
from pathlib import Path
from cipherflow.progress import ProgressReporter, ProgressTransportMode
with tempfile.TemporaryDirectory() as d:
    reporter = ProgressReporter(task_id='test-task', total_epochs=5, output_dir=d, transport_mode=ProgressTransportMode.FILE_FLUSH)
    reporter.report(epoch=2, loss=0.5, accuracy=0.85)
    data = json.loads((Path(d) / 'progress.json').read_text())
    assert data['percent'] == 40.0
    assert data['percentage'] == 40.0
    assert data['current_metrics']['loss'] == 0.5
"
```
Expected: Exit code 0.

---

### Task 6: Synchronize Protobuf Definitions & Documentation

**Files:**
- Modify: `models/spec/cipherflow/protos/cipherflow/v1/sandbox.proto`
- Modify: `models/spec/cipherflow/protos/cipherflow/v1/progress.proto`
- Modify: `models/spec/cipherflow/protos/cipherflow/v1/result.proto`
- Modify: `models/spec/cipherflow/protos/cipherflow/v1/evaluation.proto`
- Modify: `api/proto/cipherflow/v1/sandbox.proto`
- Modify: `api/proto/cipherflow/v1/progress.proto`
- Modify: `api/proto/cipherflow/v1/result.proto`
- Modify: `api/proto/cipherflow/v1/evaluation.proto`

- [ ] **Step 1: Update comments and paths in `models/spec/cipherflow/protos/cipherflow/v1/`**
  - In `sandbox.proto`:
    - Add `result_dir` (slot 9) to `OutputPathSpec`:
      `string result_dir = 9; // 模型主结果产物目录，固定为 "/opt/taa/output/result"`
    - Update `weights_dir` comment: `如 "/opt/taa/output/result/weights"`
    - Update `training_result_file` comment: `必须为 "/opt/taa/output/result/training_result.json"`
    - Update `logs_dir` comment: `固定为 "/opt/taa/output/log"`
    - Update `progress_file` comment: `必须为 "/opt/taa/output/progress/progress.json"`
  - In `progress.proto`:
    - Update `FILE_FLUSH` comment: `写入 /opt/taa/output/progress/progress.json`
    - Update `HTTP_POST` comment: `[Deprecated in TAA] 本地 HTTP 请求`
  - In `result.proto` & `evaluation.proto`:
    - Update references from `/opt/taa/output/training_result.json` to `/opt/taa/output/result/training_result.json`.

- [ ] **Step 2: Copy modified `.proto` files to `api/proto/cipherflow/v1/`**

```bash
cp -r models/spec/cipherflow/protos/cipherflow/v1/*.proto api/proto/cipherflow/v1/
```

- [ ] **Step 3: Verify diff between the two proto directories**

```bash
diff -r models/spec/cipherflow/protos/cipherflow/v1/ api/proto/cipherflow/v1/
```
Expected: Empty output (byte-for-byte identical).

---

### Task 7: Update and Run Unit Tests (`models/spec/tests/test_cipherflow.py`)

**Files:**
- Modify: `models/spec/tests/test_cipherflow.py`

- [ ] **Step 1: Update unit tests in `models/spec/tests/test_cipherflow.py`**
  - Add test for `OutputPathSpec` default directories (`result_dir`, `log_dir`, `progress_dir`).
  - Add test for `ModelLogger` writing logs to `log_dir / "model.log"`.
  - Add test for `ProgressReporter` with `percent` / `percentage`.
  - Add test asserting no `urllib` in `progress.py`.
  - Support execution without `pytest` using standard `unittest` framework runner.

- [ ] **Step 2: Run test suite**

```bash
PYTHONPATH=models/spec python3 -m unittest models/spec/tests/test_cipherflow.py
```
Expected: All tests pass (`OK`).

---

### Task 8: Final Verification & Commit

- [ ] **Step 1: Run Go tests to ensure no regressions in TAA**

```bash
go test ./...
```
Expected: All packages pass.

- [ ] **Step 2: Check git status across both repos**

```bash
git -C models/spec status
git status
```

- [ ] **Step 3: Commit changes in `models/spec`**

```bash
git -C models/spec add cipherflow/ protos/ tests/
git -C models/spec commit -m "refactor(spec): align cipherflow contracts and sdk with taa output directory structure"
```

- [ ] **Step 4: Commit changes in root repo (`api/proto/`, `.claude/plans/`)**

```bash
git add api/proto/cipherflow/v1/ .claude/plans/
git commit -m "refactor(proto): sync cipherflow protobuf definitions with three-tier output layout"
```
Ensure no AI attribution signatures are included.
