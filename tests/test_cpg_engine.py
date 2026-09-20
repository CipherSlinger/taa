# tests/test_cpg_engine.py
"""
Unit tests for the Core Code Property Graph (CPG) data structures,
node/edge indexing, and bidirectional graph traversal.
"""

import unittest
from models.audit.tools.cpg.models import (
    NodeType,
    EdgeType,
    CPGNode,
    CPGEdge,
    CodePropertyGraph,
)


class TestCPGEngine(unittest.TestCase):
    """Test suite for CodePropertyGraph container and query methods."""

    def setUp(self):
        self.cpg = CodePropertyGraph()

    def test_add_nodes_and_indices(self):
        node1 = CPGNode(
            node_id="n1",
            file_path="services/worker.py",
            line=10,
            col=4,
            end_line=10,
            end_col=35,
            node_type=NodeType.AST_ASSIGN,
            code_str="token = os.environ['KEY']",
            symbol_name="token",
        )
        node2 = CPGNode(
            node_id="n2",
            file_path="services/worker.py",
            line=15,
            col=4,
            end_line=15,
            end_col=40,
            node_type=NodeType.AST_CALL,
            code_str="requests.post(url, json=token)",
            symbol_name="requests.post",
        )
        self.cpg.add_node(node1)
        self.cpg.add_node(node2)

        self.assertEqual(self.cpg.count_nodes(), 2)
        self.assertEqual(self.cpg.get_node("n1"), node1)
        self.assertEqual(self.cpg.get_node("n2"), node2)

        # File-line lookup
        line10_nodes = self.cpg.find_nodes_at_line("services/worker.py", 10)
        self.assertEqual(len(line10_nodes), 1)
        self.assertEqual(line10_nodes[0].node_id, "n1")

        # Symbol lookup
        sym_nodes = self.cpg.find_nodes_by_symbol("token")
        self.assertEqual(len(sym_nodes), 1)
        self.assertEqual(sym_nodes[0].node_id, "n1")

        # Type lookup
        call_nodes = self.cpg.find_nodes_by_type(NodeType.AST_CALL)
        self.assertEqual(len(call_nodes), 1)
        self.assertEqual(call_nodes[0].node_id, "n2")

    def test_add_edges_and_bidirectional_traversal(self):
        node1 = CPGNode(
            node_id="n1",
            file_path="a.py",
            line=1,
            col=0,
            end_line=1,
            end_col=10,
            node_type=NodeType.AST_ASSIGN,
            code_str="x = 1",
        )
        node2 = CPGNode(
            node_id="n2",
            file_path="a.py",
            line=2,
            col=0,
            end_line=2,
            end_col=10,
            node_type=NodeType.AST_ASSIGN,
            code_str="y = x + 1",
        )
        node3 = CPGNode(
            node_id="n3",
            file_path="a.py",
            line=3,
            col=0,
            end_line=3,
            end_col=10,
            node_type=NodeType.AST_CALL,
            code_str="print(y)",
        )
        self.cpg.add_node(node1)
        self.cpg.add_node(node2)
        self.cpg.add_node(node3)

        edge1 = CPGEdge(source_id="n1", target_id="n2", edge_type=EdgeType.DFG_DEF_USE)
        edge2 = CPGEdge(source_id="n2", target_id="n3", edge_type=EdgeType.DFG_DEF_USE)
        edge3 = CPGEdge(source_id="n1", target_id="n2", edge_type=EdgeType.CFG_NEXT)

        self.cpg.add_edge(edge1)
        self.cpg.add_edge(edge2)
        self.cpg.add_edge(edge3)

        self.assertEqual(self.cpg.count_edges(), 3)

        # Successors of n1
        succs_all = self.cpg.get_successors("n1")
        self.assertEqual(len(succs_all), 2)  # DFG_DEF_USE and CFG_NEXT to n2

        succs_dfg = self.cpg.get_successors("n1", {EdgeType.DFG_DEF_USE})
        self.assertEqual(len(succs_dfg), 1)
        self.assertEqual(succs_dfg[0][0].node_id, "n2")
        self.assertEqual(succs_dfg[0][1].edge_type, EdgeType.DFG_DEF_USE)

        # Predecessors of n3
        preds_n3 = self.cpg.get_predecessors("n3")
        self.assertEqual(len(preds_n3), 1)
        self.assertEqual(preds_n3[0][0].node_id, "n2")

    def test_ignore_edge_with_missing_node(self):
        node1 = CPGNode(
            node_id="n1",
            file_path="a.py",
            line=1,
            col=0,
            end_line=1,
            end_col=5,
            node_type=NodeType.AST_STMT,
            code_str="pass",
        )
        self.cpg.add_node(node1)
        invalid_edge = CPGEdge(source_id="n1", target_id="missing", edge_type=EdgeType.CFG_NEXT)
        self.cpg.add_edge(invalid_edge)
        self.assertEqual(self.cpg.count_edges(), 0)


if __name__ == "__main__":
    unittest.main()
