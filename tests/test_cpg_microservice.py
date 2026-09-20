# tests/test_cpg_microservice.py
"""
Unit tests for the MicroserviceBoundaryBridge.
Tests client detection, route parsing, path normalization, and boundary edge synthesis.
"""

import tempfile
import unittest
from pathlib import Path

from models.audit.tools.cpg.builder import CPGBuilder
from models.audit.tools.cpg.microservice import MicroserviceBoundaryBridge
from models.audit.tools.cpg.models import EdgeType, NodeType


class TestCPGMicroserviceBridge(unittest.TestCase):
    """Test suite for cross-microservice client-to-route boundary bridging."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Service 1: Client / Worker
        client_dir = self.root / "worker"
        client_dir.mkdir()
        (client_dir / "worker.py").write_text(
            "import os, requests\n\n"
            "def send_telemetry():\n"
            "    token = os.environ.get('SECRET_TOKEN')\n"
            "    data = {'auth': token}\n"
            "    requests.post('http://sidecar:8080/v1/telemetry', json=data)\n",
            encoding="utf-8",
        )

        # Service 2: Server / Sidecar
        server_dir = self.root / "sidecar"
        server_dir.mkdir()
        (server_dir / "server.py").write_text(
            "import subprocess\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n\n"
            "@app.post('/v1/telemetry')\n"
            "def handle_telemetry():\n"
            "    payload = request.get_json()\n"
            "    tok = payload.get('auth')\n"
            "    subprocess.run('echo ' + tok, shell=True)\n"
            "    return {'status': 'ok'}\n",
            encoding="utf-8",
        )

        self.builder = CPGBuilder(workspace_roots=[str(self.root)])
        self.cpg = self.builder.build()
        self.bridge = MicroserviceBoundaryBridge()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_client_detection(self):
        clients = self.bridge.extract_client_calls(self.cpg)
        self.assertEqual(len(clients), 1)
        client = clients[0]
        self.assertEqual(client.http_method, "POST")
        self.assertEqual(client.normalized_endpoint, "/v1/telemetry")
        self.assertIn("sidecar:8080/v1/telemetry", client.raw_url)

    def test_server_route_detection(self):
        routes = self.bridge.extract_server_routes(self.cpg)
        self.assertEqual(len(routes), 1)
        route = routes[0]
        self.assertIn("POST", route.http_methods)
        self.assertEqual(route.normalized_endpoint, "/v1/telemetry")
        self.assertEqual(route.func_node.symbol_name, "handle_telemetry")

    def test_bridge_boundaries_and_edges(self):
        links_created = self.bridge.bridge_boundaries(self.cpg)
        self.assertEqual(links_created, 1)

        # Check MICROSERVICE_HTTP edge
        calls = self.cpg.find_nodes_by_type(NodeType.AST_CALL)
        post_calls = [c for c in calls if c.symbol_name and "post" in c.symbol_name]
        self.assertGreaterEqual(len(post_calls), 1)
        client_call = post_calls[0]

        http_succs = self.cpg.get_successors(client_call.node_id, {EdgeType.MICROSERVICE_HTTP})
        self.assertEqual(len(http_succs), 1)
        server_func, edge = http_succs[0]
        self.assertEqual(server_func.symbol_name, "handle_telemetry")
        self.assertEqual(edge.edge_type, EdgeType.MICROSERVICE_HTTP)
        self.assertEqual(edge.metadata.get("endpoint"), "/v1/telemetry")

        # Check MICROSERVICE_PAYLOAD edge
        payload_edges = [
            e for edges in self.cpg.adj_out.values() for e in edges if e.edge_type == EdgeType.MICROSERVICE_PAYLOAD
        ]
        self.assertGreaterEqual(len(payload_edges), 1)


if __name__ == "__main__":
    unittest.main()
