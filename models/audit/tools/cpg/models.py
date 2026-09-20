# models/audit/tools/cpg/models.py
"""
Data models and graph container for the Cross-Repository Code Property Graph (CPG).

Fuses Abstract Syntax Tree (AST), Control Flow Graph (CFG),
Data Flow Graph (DFG), inter-procedural Call Graph (CG), and
microservice boundary communication edges into a unified queryable graph.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class NodeType(str, Enum):
    """Classification of nodes within the Code Property Graph."""
    AST_STMT = "AST_STMT"
    AST_EXPR = "AST_EXPR"
    AST_CALL = "AST_CALL"
    AST_ASSIGN = "AST_ASSIGN"
    AST_FUNC_DEF = "AST_FUNC_DEF"
    AST_CLASS_DEF = "AST_CLASS_DEF"
    AST_RETURN = "AST_RETURN"
    AST_PARAM = "AST_PARAM"
    AST_IMPORT = "AST_IMPORT"
    MICROSERVICE_CLIENT = "MICROSERVICE_CLIENT"
    MICROSERVICE_ENDPOINT = "MICROSERVICE_ENDPOINT"


class EdgeType(str, Enum):
    """Classification of directed relationships between CPG nodes."""
    # Syntactic hierarchy (AST)
    AST_CHILD = "AST_CHILD"

    # Intra-procedural Control Flow (CFG)
    CFG_NEXT = "CFG_NEXT"
    CFG_BRANCH_TRUE = "CFG_BRANCH_TRUE"
    CFG_BRANCH_FALSE = "CFG_BRANCH_FALSE"
    CFG_LOOP_EXIT = "CFG_LOOP_EXIT"
    CFG_EXCEPT = "CFG_EXCEPT"

    # Intra-procedural Data Flow (DFG)
    DFG_DEF_USE = "DFG_DEF_USE"

    # Inter-procedural Call Graph & parameter bindings
    CALL = "CALL"
    CALL_ARG = "CALL_ARG"
    CALL_RET = "CALL_RET"

    # Cross-service microservice boundary edges
    MICROSERVICE_HTTP = "MICROSERVICE_HTTP"
    MICROSERVICE_PAYLOAD = "MICROSERVICE_PAYLOAD"
    MICROSERVICE_RESPONSE = "MICROSERVICE_RESPONSE"


@dataclass
class CPGNode:
    """A node in the Code Property Graph representing code elements or boundary abstractions."""
    node_id: str
    file_path: str
    line: int
    col: int
    end_line: int
    end_col: int
    node_type: NodeType
    code_str: str
    enclosing_scope: str = ""
    scope_id: str = ""
    symbol_name: Optional[str] = None
    ast_node: Optional[Any] = field(default=None, repr=False)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CPGEdge:
    """A directed edge in the Code Property Graph connecting two nodes."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    metadata: Dict[str, Any] = field(default_factory=dict)


class CodePropertyGraph:
    """
    In-memory multi-layered graph container with O(1) indices for fast
    inter-procedural dataflow queries and taint propagation.
    """

    def __init__(self):
        self.nodes: Dict[str, CPGNode] = {}
        self.adj_out: Dict[str, List[CPGEdge]] = {}
        self.adj_in: Dict[str, List[CPGEdge]] = {}
        self._file_line_index: Dict[Tuple[str, int], List[str]] = {}
        self._symbol_index: Dict[str, List[str]] = {}
        self._type_index: Dict[NodeType, List[str]] = {}

    def add_node(self, node: CPGNode) -> None:
        """Register a node in the graph and update lookup indices."""
        self.nodes[node.node_id] = node
        self.adj_out.setdefault(node.node_id, [])
        self.adj_in.setdefault(node.node_id, [])
        self._file_line_index.setdefault((node.file_path, node.line), []).append(node.node_id)
        if node.symbol_name:
            self._symbol_index.setdefault(node.symbol_name, []).append(node.node_id)
        self._type_index.setdefault(node.node_type, []).append(node.node_id)

    def add_edge(self, edge: CPGEdge) -> None:
        """Register a directed edge between two existing nodes."""
        if edge.source_id in self.nodes and edge.target_id in self.nodes:
            self.adj_out[edge.source_id].append(edge)
            self.adj_in[edge.target_id].append(edge)

    def get_node(self, node_id: str) -> Optional[CPGNode]:
        """Retrieve node by unique node ID."""
        return self.nodes.get(node_id)

    def get_successors(
        self, node_id: str, edge_types: Optional[Set[EdgeType]] = None
    ) -> List[Tuple[CPGNode, CPGEdge]]:
        """Retrieve target nodes and edges originating from the given node."""
        result: List[Tuple[CPGNode, CPGEdge]] = []
        for edge in self.adj_out.get(node_id, []):
            if edge_types is None or edge.edge_type in edge_types:
                target_node = self.nodes.get(edge.target_id)
                if target_node:
                    result.append((target_node, edge))
        return result

    def get_predecessors(
        self, node_id: str, edge_types: Optional[Set[EdgeType]] = None
    ) -> List[Tuple[CPGNode, CPGEdge]]:
        """Retrieve source nodes and edges leading into the given node."""
        result: List[Tuple[CPGNode, CPGEdge]] = []
        for edge in self.adj_in.get(node_id, []):
            if edge_types is None or edge.edge_type in edge_types:
                source_node = self.nodes.get(edge.source_id)
                if source_node:
                    result.append((source_node, edge))
        return result

    def find_nodes_at_line(self, file_path: str, line: int) -> List[CPGNode]:
        """Lookup nodes present at a specific file path and line number."""
        node_ids = self._file_line_index.get((file_path, line), [])
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]

    def find_nodes_by_symbol(self, symbol_name: str) -> List[CPGNode]:
        """Lookup nodes associated with a symbol name."""
        node_ids = self._symbol_index.get(symbol_name, [])
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]

    def find_nodes_by_type(self, node_type: NodeType) -> List[CPGNode]:
        """Lookup nodes of a specific NodeType."""
        node_ids = self._type_index.get(node_type, [])
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]

    def count_nodes(self) -> int:
        """Return total number of nodes in graph."""
        return len(self.nodes)

    def count_edges(self) -> int:
        """Return total number of edges in graph."""
        return sum(len(edges) for edges in self.adj_out.values())
