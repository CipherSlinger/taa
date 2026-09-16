# Retina-DKD 训练终端日志与进度落盘适配实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 Retina-DKD 训练代码 `train_fusion.py` 增加标准化的任务终端日志（`train.log`）和任务进度（`progress.json`）落盘功能，严格适配 TAA 平台的读取上报机制。

**Architecture:** 在 `train_fusion.py` 中新增 `--log-dir` 和 `--progress-dir` 命令行参数解析并智能推导路径（完全不读取环境变量），引入轻量级 `ModelLogger`（JSONL 单行即时刷盘）和 `ProgressTracker`（原子替换写入 JSON），并在训练生命周期关键节点进行插桩。

**Tech Stack:** Python 3 (standard library: `argparse`, `pathlib`, `json`, `datetime`, `os`, `sys`), PyTorch, Go (集成测试与验证)

---

### File Structure

- 修改：`models/examples/Retina-DKD/Retina-DKD/train_fusion.py`
  - 职责：核心训练脚本，解析命令行、初始化网络、执行训练/验证循环、写入模型权重、日志及进度文件。
- 修改：`models/examples/Retina-DKD/Retina-DKD/TRAIN.md`
  - 职责：更新参数说明与日志/进度产物说明。
- 新增：`models/examples/Retina-DKD/Retina-DKD/test_reporting_helpers.py`
  - 职责：针对路径推导、日志 JSONL 格式解析及进度原子写入的独立自动化单元测试。
- 验证：`internal/controller/retina_runtime_test.go`
  - 职责：Go 语言控制器层对 Retina-DKD 运行能力的回归测试。

---

### Task 1: 编写路径推导、日志写入器与进度追踪器的单元测试

**Files:**
- Create: `models/examples/Retina-DKD/Retina-DKD/test_reporting_helpers.py`

- [ ] **Step 1: 编写测试用例**

```python
"""Unit tests for reporting helper classes and path resolution in Retina-DKD."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

# 从待实现的模块/函数中导入
from train_fusion import (
    ModelLogger,
    ProgressTracker,
    resolve_log_dir,
    resolve_progress_dir,
)


class TestReportingHelpers(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.output_dir = self.temp_dir / "output" / "result"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_resolve_log_dir_explicit(self):
        explicit = self.temp_dir / "custom_log"
        resolved = resolve_log_dir(str(explicit), str(self.output_dir))
        self.assertEqual(resolved, explicit.resolve())

    def test_resolve_log_dir_from_output_dir_result(self):
        # --output-dir 为 .../output/result 时推导同级 log 目录
        resolved = resolve_log_dir(None, str(self.output_dir))
        expected = (self.temp_dir / "output" / "log").resolve()
        self.assertEqual(resolved, expected)

    def test_resolve_log_dir_from_generic_output_dir(self):
        generic_output = self.temp_dir / "out"
        resolved = resolve_log_dir(None, str(generic_output))
        expected = (generic_output / "log").resolve()
        self.assertEqual(resolved, expected)

    def test_resolve_progress_dir_explicit(self):
        explicit = self.temp_dir / "custom_progress"
        resolved = resolve_progress_dir(str(explicit), str(self.output_dir))
        self.assertEqual(resolved, explicit.resolve())

    def test_resolve_progress_dir_from_output_dir_result(self):
        # --output-dir 为 .../output/result 时推导同级 progress 目录
        resolved = resolve_progress_dir(None, str(self.output_dir))
        expected = (self.temp_dir / "output" / "progress").resolve()
        self.assertEqual(resolved, expected)

    def test_model_logger_writes_jsonl(self):
        log_dir = self.temp_dir / "logs"
        logger = ModelLogger(log_dir)
        logger.log("[Init] Starting test")
        logger.log("[Train] Epoch 1 - loss: 0.1234")
        logger.close()

        log_file = log_dir / "train.log"
        self.assertTrue(log_file.exists())
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        self.assertEqual(len(lines), 2)

        data0 = json.loads(lines[0])
        self.assertEqual(data0["message"], "[Init] Starting test")
        self.assertIn("timestamp", data0)

        data1 = json.loads(lines[1])
        self.assertEqual(data1["message"], "[Train] Epoch 1 - loss: 0.1234")

    def test_progress_tracker_atomic_update(self):
        prog_dir = self.temp_dir / "prog"
        tracker = ProgressTracker(prog_dir)
        tracker.update(25.5)

        prog_file = prog_dir / "progress.json"
        self.assertTrue(prog_file.exists())
        data = json.loads(prog_file.read_text(encoding="utf-8"))
        self.assertEqual(data["percent"], 25.5)
        self.assertIn("timestamp", data)
        # 确保临时文件不存在
        self.assertFalse((prog_dir / "progress.json.tmp").exists())

        # 更新至 100%
        tracker.update(100.0)
        data2 = json.loads(prog_file.read_text(encoding="utf-8"))
        self.assertEqual(data2["percent"], 100.0)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试并验证失败（当前尚未在 train_fusion.py 中导出）**

Run: `python3 -m unittest models/examples/Retina-DKD/Retina-DKD/test_reporting_helpers.py`
Expected: FAIL with `ImportError: cannot import name 'ModelLogger' from 'train_fusion'`

---

### Task 2: 在 `train_fusion.py` 中实现路径解析与 `ModelLogger`、`ProgressTracker` 类

**Files:**
- Modify: `models/examples/Retina-DKD/Retina-DKD/train_fusion.py:20-120`

- [ ] **Step 1: 新增 CLI 参数与路径解析函数（不检测环境变量）**

在 `train_fusion.py` 的参数解析中增加：
```python
parser.add_argument('--log-dir', type=str, required=False, default=None, help='log directory for terminal execution logs (train.log)')
parser.add_argument('--progress-dir', type=str, required=False, default=None, help='progress directory for training percentage (progress.json)')
```

添加路径解析函数：
```python
def resolve_log_dir(log_dir_text: str | None, output_dir_text: str | None) -> Path:
    if log_dir_text:
        return Path(log_dir_text).expanduser().resolve(strict=False)
    if output_dir_text:
        out = Path(output_dir_text).expanduser().resolve(strict=False)
        if out.name == "result":
            return out.parent / "log"
        return out / "log"
    return Path("/opt/taa/output/log")


def resolve_progress_dir(progress_dir_text: str | None, output_dir_text: str | None) -> Path:
    if progress_dir_text:
        return Path(progress_dir_text).expanduser().resolve(strict=False)
    if output_dir_text:
        out = Path(output_dir_text).expanduser().resolve(strict=False)
        if out.name == "result":
            return out.parent / "progress"
        return out / "progress"
    return Path("/opt/taa/output/progress")
```

- [ ] **Step 2: 实现 `ModelLogger` 类与 `ProgressTracker` 类**

```python
class ModelLogger:
    """Writes JSONL formatted logs to train.log with immediate flush."""

    def __init__(self, log_dir: Path, filename: str = "train.log"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / filename
        self._file = open(self.log_path, "a", encoding="utf-8")

    def log(self, message: str) -> None:
        clean_msg = str(message).strip()
        if not clean_msg:
            return
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = {"timestamp": ts, "message": clean_msg}
        self._file.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._file.flush()
        print(clean_msg)

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.close()


class ProgressTracker:
    """Atomically writes percent and timestamp to progress.json."""

    def __init__(self, progress_dir: Path, filename: str = "progress.json"):
        self.progress_dir = Path(progress_dir)
        self.progress_dir.mkdir(parents=True, exist_ok=True)
        self.progress_path = self.progress_dir / filename
        self.tmp_path = self.progress_dir / f"{filename}.tmp"
        self._last_percent = -1.0

    def update(self, percent: float) -> None:
        clamped = max(0.0, min(100.0, round(float(percent), 2)))
        # 相同百分比跳过写入
        if abs(clamped - self._last_percent) < 1e-4 and clamped != 100.0:
            return
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        payload = {"percent": clamped, "timestamp": ts}
        temp_data = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        with open(self.tmp_path, "w", encoding="utf-8") as f:
            f.write(temp_data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(self.tmp_path, self.progress_path)
        self._last_percent = clamped
```

- [ ] **Step 3: 重新运行 Task 1 的单元测试验证通过**

Run: `python3 -m unittest models/examples/Retina-DKD/Retina-DKD/test_reporting_helpers.py`
Expected: PASS (Ran 6 tests, OK)

- [ ] **Step 4: 提交核心工具类修改**

```bash
git add models/examples/Retina-DKD/Retina-DKD/train_fusion.py models/examples/Retina-DKD/Retina-DKD/test_reporting_helpers.py
git commit -m "feat(retina-dkd): 实现终端日志 ModelLogger 与进度原子写入 ProgressTracker"
```

---

### Task 3: 在 `train_fusion.py` 训练流程中插桩日志与进度，并更新文档

**Files:**
- Modify: `models/examples/Retina-DKD/Retina-DKD/train_fusion.py:160-390`
- Modify: `models/examples/Retina-DKD/Retina-DKD/TRAIN.md`

- [ ] **Step 1: 在 `main()` 函数中初始化 logger 与 progress**

```python
    log_dir = resolve_log_dir(args.log_dir, args.output_dir)
    progress_dir = resolve_progress_dir(args.progress_dir, args.output_dir)
    logger = ModelLogger(log_dir)
    progress = ProgressTracker(progress_dir)

    progress.update(0.0)
    logger.log(f"[Init] Starting Retina-DKD training: basic_net={basic_model}, epochs={EPOCH}, batch_size={args.batch}, img_size={img_size}")
    logger.log(f"[Init] Directories: data_root={data_root}, output_root={output_root}, log_dir={log_dir}, progress_dir={progress_dir}")
```

- [ ] **Step 2: 模型构建完毕节点插桩**

```python
    progress.update(2.0)
    logger.log(f"[Init] KeNetMultFactorNew initialized successfully on device={device}. Dataset sizes: train={len(dr_dataset_train)}, test={len(dr_dataset_test)}")
```

- [ ] **Step 3: 在 Epoch 循环中插桩**

```python
    for epoch in range(epoc_begin, EPOCH):
        # 在 epoch 开始时更新进度
        current_percent = 2.0 + 93.0 * (epoch / max(EPOCH, 1))
        progress.update(current_percent)
        logger.log(f"[Train] Starting Epoch {epoch + 1}/{EPOCH} (lr={optimizer.param_groups[0]['lr']})")
        
        # ... 训练批次执行 ...
        
        epoch_loss = running_results['acc_loss'] / max(count, 1)
        epoch_acc = running_results['acc'] / max(count, 1)
        logger.log(f"[Train] Epoch {epoch + 1}/{EPOCH} finished - train_loss: {epoch_loss:.4f}, train_acc: {epoch_acc:.2f}%")

        if epoch % 4 == 0:
            # ... 验证执行 ...
            logger.log(f"[Eval] Epoch {epoch + 1}/{EPOCH} - Testset Acc: {Acc * 100:.1f}%, Sen: {Sen * 100:.1f}%, Spec: {Spec * 100:.1f}%")
```

- [ ] **Step 4: 在训练结束收尾处插桩**

```python
    progress.update(100.0)
    logger.log(f"[Done] Training finished successfully: duration={duration_seconds}s, final_acc={best_acc:.4f}, result saved to {result_path}")
    logger.close()
```

- [ ] **Step 5: 更新 `TRAIN.md` 文档**

在 `models/examples/Retina-DKD/Retina-DKD/TRAIN.md` 中添加 `--log-dir` 与 `--progress-dir` 参数说明，以及输出日志 `train.log` 和进度 `progress.json` 路径规范。

- [ ] **Step 6: 提交插桩与文档修改**

```bash
git add models/examples/Retina-DKD/Retina-DKD/train_fusion.py models/examples/Retina-DKD/Retina-DKD/TRAIN.md
git commit -m "feat(retina-dkd): 在训练主流程中插桩任务终端日志与进度更新"
```

---

### Task 4: 端到端功能运行验证与整体测试回归

**Files:**
- Test: `models/examples/Retina-DKD/Retina-DKD/test_reporting_helpers.py`
- Test: `internal/controller/retina_runtime_test.go`

- [ ] **Step 1: 运行 Python 辅助模块单元测试**

Run: `python3 -m unittest models/examples/Retina-DKD/Retina-DKD/test_reporting_helpers.py`
Expected: PASS

- [ ] **Step 2: 静态语法编译检查**

Run: `python3 -m py_compile models/examples/Retina-DKD/Retina-DKD/train_fusion.py`
Expected: 编译无错误（退出码 0）

- [ ] **Step 3: 运行 Go 控制器相关测试**

Run: `go test -v ./internal/controller -run "TestRetinaDKD"`
Expected: PASS

- [ ] **Step 4: 运行 Go 端到端日志与进度监听测试**

Run: `go test -v ./internal/controller -run "TestReportWatcherSendsLogAndProgress"`
Expected: PASS

- [ ] **Step 5: 最终确认工作区状态无未跟踪残留**

Run: `git status`
Expected: working tree clean
