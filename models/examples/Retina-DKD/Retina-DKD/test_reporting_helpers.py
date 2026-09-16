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

        # 再次更新为 100.0 并验证
        tracker.update(100.0)
        data2 = json.loads(prog_file.read_text(encoding="utf-8"))
        self.assertEqual(data2["percent"], 100.0)
        self.assertIn("timestamp", data2)
        self.assertFalse((prog_dir / "progress.json.tmp").exists())


if __name__ == "__main__":
    unittest.main()
