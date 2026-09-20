# tests/test_cpg_builder.py
"""
Unit tests for the inter-procedural CPGBuilder.
Tests intra-procedural CFG/DFG, cross-file call edges, caller argument to callee
parameter bindings, and callee return to caller bindings.
"""

import tempfile
import unittest
from pathlib import Path

from models.audit.tools.cpg.builder import CPGBuilder
from models.audit.tools.cpg.models import EdgeType, NodeType


class TestCPGBuilder(unittest.TestCase):
    """Test suite for CPG construction across single and multi-file projects."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # File A: util.py
        util_file = self.root / "util.py"
        util_file.write_text(
            "def sanitize(raw_token):\n"
            "    cleaned = raw_token.strip()\n"
            "    return cleaned\n",
            encoding="utf-8",
        )

        # File B: main.py
        main_file = self.root / "main.py"
        main_file.write_text(
            "import os\n"
            "from util import sanitize\n\n"
            "def process():\n"
            "    secret = os.environ.get('KEY')\n"
            "    final_tok = sanitize(secret)\n"
            "    print(final_tok)\n",
            encoding="utf-8",
        )

        self.builder = CPGBuilder(workspace_roots=[str(self.root)])
        self.cpg = self.builder.build()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_node_creation_and_counts(self):
        self.assertGreater(self.cpg.count_nodes(), 5)
        self.assertGreater(self.cpg.count_edges(), 5)

        # Function definition nodes
        func_nodes = self.cpg.find_nodes_by_type(NodeType.AST_FUNC_DEF)
        func_names = {n.symbol_name for n in func_nodes}
        self.assertIn("sanitize", func_names)
        self.assertIn("process", func_names)

    def test_cross_file_call_edge(self):
        # Find call to sanitize in main.py
        calls = self.cpg.find_nodes_by_type(NodeType.AST_CALL)
        sanitize_calls = [c for c in calls if c.symbol_name == "sanitize"]
        self.assertEqual(len(sanitize_calls), 1)
        sanitize_call = sanitize_calls[0]

        # Verify CALL edge exists from sanitize_call to sanitize FunctionDef
        call_successors = self.cpg.get_successors(sanitize_call.node_id, {EdgeType.CALL})
        self.assertEqual(len(call_successors), 1)
        target_func, edge = call_successors[0]
        self.assertEqual(target_func.symbol_name, "sanitize")
        self.assertEqual(edge.edge_type, EdgeType.CALL)

    def test_call_argument_binding(self):
        # Parameter binding: actual arg secret -> formal param raw_token
        params = self.cpg.find_nodes_by_type(NodeType.AST_PARAM)
        raw_token_params = [p for p in params if p.symbol_name == "raw_token"]
        self.assertEqual(len(raw_token_params), 1)
        raw_token_param = raw_token_params[0]

        param_preds = self.cpg.get_predecessors(raw_token_param.node_id, {EdgeType.CALL_ARG})
        self.assertGreaterEqual(len(param_preds), 1)
        self.assertEqual(param_preds[0][1].edge_type, EdgeType.CALL_ARG)

    def test_call_return_binding(self):
        # Return binding: return cleaned -> caller sanitize(...)
        calls = self.cpg.find_nodes_by_type(NodeType.AST_CALL)
        sanitize_call = [c for c in calls if c.symbol_name == "sanitize"][0]

        call_preds = self.cpg.get_predecessors(sanitize_call.node_id, {EdgeType.CALL_RET})
        self.assertEqual(len(call_preds), 1)
        ret_node, edge = call_preds[0]
        self.assertEqual(ret_node.node_type, NodeType.AST_RETURN)
        self.assertEqual(edge.edge_type, EdgeType.CALL_RET)


if __name__ == "__main__":
    unittest.main()
