"""Unit tests for reporting helper classes and path resolution in Retina-DKD."""

import argparse
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# 确保在未安装 PyTorch/CUDA 等重量级依赖的环境中也能独立执行 reporting helper 的单元测试
for _mod in [
    "torch", "torch.nn", "torch.optim", "torch.utils", "torch.utils.data",
    "torch.cuda", "numpy", "tensorboardX", "tqdm", "network",
    "data_pre_process", "data_pre_process.data_process",
    "config", "config.train_config",
]:
    if _mod not in sys.modules:
        try:
            __import__(_mod)
        except ImportError:
            sys.modules[_mod] = MagicMock()

# 兼容 train_fusion 模块顶层参数解析，避免执行 unittest 时因未传 -b 参数退出
_orig_parse_args = argparse.ArgumentParser.parse_args


def _safe_parse_args(self, *args, **kwargs):
    try:
        return _orig_parse_args(self, ["-b", "test_net"])
    except Exception:
        return MagicMock()


argparse.ArgumentParser.parse_args = _safe_parse_args

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

# 从待实现的模块/函数中导入
from train_fusion import (
    ModelLogger,
    ProgressTracker,
    resolve_log_dir,
    resolve_progress_dir,
)

# 恢复 parse_args
argparse.ArgumentParser.parse_args = _orig_parse_args


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
        # 当 output_dir 尾部为 result 时（如 <dir>/output/result），推导为同级 <dir>/output/log
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
        # 当 output_dir 尾部为 result 时推导为同级 <dir>/output/progress
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
        self.assertFalse((prog_dir / "progress.json.tmp").exists())

        # Update to 100.0 and verify
        tracker.update(100.0)
        data2 = json.loads(prog_file.read_text(encoding="utf-8"))
        self.assertEqual(data2["percent"], 100.0)
        self.assertIn("timestamp", data2)
        self.assertFalse((prog_dir / "progress.json.tmp").exists())

    def test_progress_tracker_rich_metadata_and_rfc3339nano_timestamp(self):
        prog_dir = self.temp_dir / "rich_prog"
        tracker = ProgressTracker(prog_dir)
        written = tracker.update(
            percent=12.345,
            stage="train",
            message="Epoch 1/10 [Batch 5/20] - loss: 0.4521, acc: 88.50%",
            epoch=1,
            total_epochs=10,
            batch=5,
            total_batches=20,
            loss=0.452123,
            acc=88.504,
            force=True,
        )
        self.assertTrue(written)

        prog_file = prog_dir / "progress.json"
        self.assertTrue(prog_file.exists())
        data = json.loads(prog_file.read_text(encoding="utf-8"))
        self.assertEqual(data["percent"], 12.35)
        self.assertEqual(data["stage"], "train")
        self.assertEqual(data["message"], "Epoch 1/10 [Batch 5/20] - loss: 0.4521, acc: 88.50%")
        self.assertEqual(data["epoch"], 1)
        self.assertEqual(data["total_epochs"], 10)
        self.assertEqual(data["batch"], 5)
        self.assertEqual(data["total_batches"], 20)
        self.assertEqual(data["loss"], 0.4521)
        self.assertEqual(data["acc"], 88.5)

        # Verify RFC3339Nano timestamp formatting
        ts = data["timestamp"]
        self.assertTrue(ts.endswith("Z"))
        self.assertIn(".", ts)

    def test_progress_tracker_monotonic_clamping(self):
        prog_dir = self.temp_dir / "monotonic_prog"
        tracker = ProgressTracker(prog_dir)

        # First update
        tracker.update(50.0, force=True)
        self.assertEqual(tracker.last_percent, 50.0)

        # Attempt to regress without force: should clamp to 50.0
        tracker.update(40.0, force=True)
        data = json.loads((prog_dir / "progress.json").read_text(encoding="utf-8"))
        self.assertEqual(data["percent"], 50.0)

        # Over-100% clamps to 100.0
        tracker.update(120.0, force=True)
        data2 = json.loads((prog_dir / "progress.json").read_text(encoding="utf-8"))
        self.assertEqual(data2["percent"], 100.0)

    def test_progress_tracker_throttling(self):
        prog_dir = self.temp_dir / "throttle_prog"
        tracker = ProgressTracker(prog_dir, min_interval_seconds=10.0, min_percent_delta=1.0)

        # First update always writes
        w1 = tracker.update(10.0)
        self.assertTrue(w1)

        # Insignificant delta (< 1.0) and time (< 10s) should be throttled
        w2 = tracker.update(10.2)
        self.assertFalse(w2)

        # Delta >= 1.0 should pass throttling
        w3 = tracker.update(11.5)
        self.assertTrue(w3)

        # Force override should bypass throttling
        w4 = tracker.update(11.6, force=True)
        self.assertTrue(w4)

    def test_progress_tracker_update_batch(self):
        prog_dir = self.temp_dir / "batch_prog"
        tracker = ProgressTracker(prog_dir)
        written = tracker.update_batch(
            epoch_idx=1,
            total_epochs=10,
            batch_idx=5,
            total_batches=10,
            epoch_base_pct=2.0,
            epoch_span_pct=10.0,
            train_ratio=0.8,
            loss=0.31416,
            acc=92.5,
            force=True,
        )
        self.assertTrue(written)

        data = json.loads((prog_dir / "progress.json").read_text(encoding="utf-8"))
        # 2.0 + 10.0 * 0.8 * (5 / 10) = 2.0 + 4.0 = 6.0%
        self.assertEqual(data["percent"], 6.0)
        self.assertEqual(data["stage"], "train")
        self.assertEqual(data["epoch"], 1)
        self.assertEqual(data["total_epochs"], 10)
        self.assertEqual(data["batch"], 5)
        self.assertEqual(data["total_batches"], 10)
        self.assertEqual(data["loss"], 0.3142)
        self.assertEqual(data["acc"], 92.5)
        self.assertIn("Epoch 1/10 [Batch 5/10]", data["message"])


if __name__ == "__main__":
    unittest.main()
