# models/audit/tools/cpg/__init__.py
"""
Cross-Repository Code Property Graph (CPG) and Inter-Procedural Analysis Engine.

Exports data models, symbol resolver, graph builder, microservice boundary
bridge, inter-procedural taint engine, and evidence slicer.
"""

from models.audit.tools.cpg.models import (
    NodeType,
    EdgeType,
    CPGNode,
    CPGEdge,
    CodePropertyGraph,
)
from models.audit.tools.cpg.resolver import SymbolResolver
from models.audit.tools.cpg.builder import CPGBuilder
from models.audit.tools.cpg.microservice import (
    HttpClientCall,
    HttpServerRoute,
    MicroserviceBoundaryBridge,
)
from models.audit.tools.cpg.taint_engine import (
    TaintViolation,
    InterProceduralTaintEngine,
)
from models.audit.tools.cpg.slicer import CPGEvidenceSlicer

__all__ = [
    "NodeType",
    "EdgeType",
    "CPGNode",
    "CPGEdge",
    "CodePropertyGraph",
    "SymbolResolver",
    "CPGBuilder",
    "HttpClientCall",
    "HttpServerRoute",
    "MicroserviceBoundaryBridge",
    "TaintViolation",
    "InterProceduralTaintEngine",
    "CPGEvidenceSlicer",
]
