# CipherFlow Spec Alignment and Rectification Design

- **Date**: 2026-09-19
- **Status**: Proposed / Approved by User
- **Target Modules**: `models/spec/cipherflow/`, `models/spec/cipherflow/protos/`, `api/proto/cipherflow/v1/`, `models/spec/tests/`

---

## 1. Background and Motivation

### 1.1 Context
In the TAA (Trusted Application Agent) architecture, machine learning models execute inside a hardware-isolated CSV (China Secure Virtualization) TEE container. On 2026-09-15 (Commit `42bb9b8`), the TAA platform upgraded its runtime output isolation architecture and real-time telemetry pipelines:
1. **Three-Tier Output Directory Isolation**: The previously flat `/opt/taa/output` sandbox was split into three specialized directories:
   - `/opt/taa/output/result`: Primary output artifacts (weights, `training_result.json`, `test_result.xlsx`).
   - `/opt/taa/output/log`: Model execution terminal logs polled by `JSONLLogReader` and reported to `/v1/taa/modelLog`.
   - `/opt/taa/output/progress`: Real-time training progress snapshots polled by `ReadLatestProgress` and reported to `/v1/taa/reportProgress`.
2. **Macro and Environment Alignment**: The `<output>` command-line macro and `TAA_OUTPUT_DIR` environment variable now resolve to `/opt/taa/output/result`.
3. **Telemetry Polling Model**: TAA operates purely on local filesystem polling (non-streaming `cmd.Wait()` on stdout/stderr, no `/internal/progress` HTTP endpoint, no gRPC server).

### 1.2 Problem Statement
The `models/spec` repository (CipherFlow specification and Python SDK) was authored on 2026-09-11 and remains on the outdated flat output structure:
- `DEFAULT_OUTPUT_DIR` defaults to `/opt/taa/output`, causing `TrainingResult.save()` to write to `/opt/taa/output/training_result.json`. When training finishes, TAA searches `/opt/taa/output/result/training_result.json` and fails because the file is missing.
- `ProgressReporter` flushes to `/opt/taa/output/progress.json`, whereas TAA polls `/opt/taa/output/progress/*.json`. Progress is never picked up.
- `ProgressReporter` retains an HTTP callback invoking `urllib.request.urlopen`, directly triggering TAA's `NET_001` (High) security audit rule and causing imported models to be rejected as `MALICIOUS`.
- `models/spec` lacks standard logger support for writing to `/opt/taa/output/log/`.
- `models/spec/cipherflow/protos/cipherflow/v1/` and `api/proto/cipherflow/v1/` proto docstrings and field specs reflect obsolete paths.
- Leftover empty directories exist under `models/spec/models/` and `models/spec/api/`.

---

## 2. Architecture & Data Flow

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            TAA CSV TEE Container                            │
│                                                                             │
│  [Input Sandbox]  /opt/taa/input (READ_ONLY)                                │
│   ├── train/, val/, test/, labels.csv, weights/                             │
│                                                                             │
│  [Output Sandbox] /opt/taa/output (READ_WRITE)                              │
│   ├── result/             <── TeePathContract.output.result_dir             │
│   │   ├── weights/        <── TeePathContract.output.weights_dir            │
│   │   ├── training_result.json <── TrainingResult.save()                    │
│   │   └── test_result.xlsx<── Evaluation outputs                            │
│   │                                                                         │
│   ├── log/                <── TeePathContract.output.log_dir                │
│   │   └── model.log / *.jsonl <── ModelLogger (polled by TAA JSONLLogReader)│
│   │                                                                         │
│   └── progress/           <── TeePathContract.output.progress_dir           │
│       └── progress.json   <── ProgressReporter (polled by TAA ProgressWatch)│
│                                                                             │
│  [Checkpoint]     /opt/taa/checkpoint (READ_WRITE)                          │
│   └── latest.pt, checkpoint_meta.json                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Component Specifications

### 3.1 Sandbox Path Contracts (`cipherflow/sandbox.py`)

#### Path Constants
```python
DEFAULT_INPUT_DIR = "/opt/taa/input"
DEFAULT_OUTPUT_DIR = "/opt/taa/output"
DEFAULT_RESULT_DIR = "/opt/taa/output/result"
DEFAULT_LOG_DIR = "/opt/taa/output/log"
DEFAULT_PROGRESS_DIR = "/opt/taa/output/progress"
DEFAULT_CHECKPOINT_DIR = "/opt/taa/checkpoint"
DEFAULT_RESULT_FILE = "training_result.json"
DEFAULT_PROGRESS_FILE = "progress.json"
```

#### OutputPathSpec
`OutputPathSpec` manages the three-tier hierarchy:
- `root_dir`: Base output root (`/opt/taa/output`).
- `result_dir`: Main artifact directory (`/opt/taa/output/result`). If `TAA_OUTPUT_DIR` or `CIPHERFLOW_OUTPUT_DIR` is set, `result_dir` adopts that value.
- `weights_dir`: Subdirectory under `result_dir / "weights"`.
- `training_result_file`: Standard path `result_dir / "training_result.json"`.
- `evaluation_result_file`: Standard path `result_dir / "test_result.xlsx"`.
- `log_dir`: Standard path `root_dir / "log"` (or via `TAA_MODEL_LOG_DIR` / `CIPHERFLOW_LOG_DIR`).
- `progress_dir`: Standard path `root_dir / "progress"` (or via `TAA_MODEL_PROGRESS_DIR` / `CIPHERFLOW_PROGRESS_DIR`).
- `progress_file`: Standard path `progress_dir / "progress.json"`.
- `ensure_directories()`: Automatically creates `result_dir`, `weights_dir`, `log_dir`, and `progress_dir`.

#### Environment Variable Resolution Priority
1. `get_output_dir()`:
   - CLI flags: `--output`, `--output-dir`, `-o`
   - Env vars: `TAA_OUTPUT_DIR`, `CIPHERFLOW_OUTPUT_DIR`, `TAA_MODEL_OUTPUT_DIR`
   - Fallback: `DEFAULT_RESULT_DIR` (`/opt/taa/output/result`)
2. `get_log_dir()`:
   - Env vars: `TAA_MODEL_LOG_DIR`, `CIPHERFLOW_LOG_DIR`
   - Fallback: `DEFAULT_LOG_DIR` (`/opt/taa/output/log`)
3. `get_progress_dir()`:
   - Env vars: `TAA_MODEL_PROGRESS_DIR`, `CIPHERFLOW_PROGRESS_DIR`
   - Fallback: `DEFAULT_PROGRESS_DIR` (`/opt/taa/output/progress`)

---

### 3.2 Result Generation (`cipherflow/result.py`)

- `TrainingResult.save(output_dir=None, filename="training_result.json")`:
  - If `output_dir` is omitted, defaults to `get_output_dir()` (which points to `/opt/taa/output/result`).
  - Writes atomically via `.tmp` swap.
  - Ensures the resulting file path is `<result_dir>/training_result.json`.

---

### 3.3 Progress Reporting & Telemetry (`cipherflow/progress.py`)

#### Removal of Network / HTTP Code
- Delete `_post_http` and all imports of `urllib.request`.
- Deprecate `ProgressTransportMode.HTTP_POST` (or make it a no-op with warning).
- Default transport remains `AUTO` (console tagging + file flush).

#### File Flush Target
- `ProgressReporter` writes to `progress_dir / "progress.json"` (defaulting to `/opt/taa/output/progress/progress.json`).
- Payload structure guaranteed to include:
  ```json
  {
    "task_id": "task-001",
    "percent": 50.0,
    "percentage": 50.0,
    "current_epoch": 5,
    "total_epochs": 10,
    "current_step": 500,
    "total_steps": 1000,
    "current_metrics": {"loss": 0.231, "accuracy": 0.92},
    "timestamp": "2026-09-19T01:30:00Z"
  }
  ```
- Both `percent` and `percentage` are emitted to guarantee compatibility with `runtime.ReadLatestProgress`.

---

### 3.4 Model Terminal Logger (`cipherflow/logger.py`)

Add a lightweight helper `ModelLogger` to allow model providers to stream standard logs directly into `/opt/taa/output/log/model.log` or `model.jsonl`:
```python
class ModelLogger:
    """Standardized logger writing to /opt/taa/output/log for TAA log forwarding."""
    def __init__(self, log_dir=None, filename="model.log"):
        ...
    def log(self, message: str, level: str = "INFO"):
        ...
```
Export `ModelLogger` from `cipherflow/__init__.py`.

---

### 3.5 Protobuf Protocol Alignment

Update `.proto` files in both `models/spec/cipherflow/protos/cipherflow/v1/` and `api/proto/cipherflow/v1/`:
1. `sandbox.proto`:
   - Clarify `weights_dir` comments to `/opt/taa/output/result/weights`.
   - Update `training_result_file` comments to `/opt/taa/output/result/training_result.json`.
   - Update `logs_dir` comments to `/opt/taa/output/log`.
   - Update `progress_file` comments to `/opt/taa/output/progress/progress.json`.
   - Add `result_dir` (slot 9) if desirable, or document that `weights_dir` and `training_result_file` reside in `result/`.
2. `progress.proto`:
   - Update `FILE_FLUSH` comments to reflect writing into `/opt/taa/output/progress/progress.json`.
   - Mark `HTTP_POST` as deprecated in comments.
3. `result.proto` & `evaluation.proto`:
   - Update documentation references from `/opt/taa/output/training_result.json` to `/opt/taa/output/result/training_result.json`.

---

### 3.6 Repository Cleanup

1. Remove empty legacy directories:
   - `models/spec/models/spec/taa_spec/protos/taa_spec/v1`
   - `models/spec/models/spec/taa_spec`
   - `models/spec/models/spec`
   - `models/spec/models`
   - `models/spec/api/proto/taa_spec/v1`
   - `models/spec/api/proto/taa_spec`
   - `models/spec/api/proto`
   - `models/spec/api`
2. Keep `models/spec/secretflow_spec/` untouched for upstream compatibility.

---

## 4. Verification & Testing Strategy

1. **Python Unit Tests**:
   - Run `models/spec/tests/test_cipherflow.py` via python test runner.
   - Test default path resolution: `result_dir == /opt/taa/output/result`, `log_dir == /opt/taa/output/log`, `progress_dir == /opt/taa/output/progress`.
   - Test `TrainingResult.save()` writing to `<result_dir>/training_result.json`.
   - Test `ProgressReporter` file flush creating `/opt/taa/output/progress/progress.json` with valid `percent` field.
   - Verify no imports of `urllib` in `progress.py` to ensure zero triggers against TAA code audit `NET_001`.
2. **Git & Commit Standards**:
   - Follow Conventional Commits: `refactor(spec): align cipherflow contracts and sdk with taa output directory structure`.
   - English commit messages only, strictly no AI attribution traces.
