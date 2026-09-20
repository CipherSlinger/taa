# models/audit/tools/cpg/taint_engine.py
"""
Inter-procedural taint propagation engine for the Code Property Graph (CPG).

Uses a fixed-point worklist algorithm to trace dataflow from canonical
security sources (environment variables, credential files, raw dataset access)
across module imports, function arguments, return values, and microservice
boundary HTTP hops to security sinks.
"""

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from models.audit.tools.cpg.models import (
    CodePropertyGraph,
    CPGEdge,
    CPGNode,
    EdgeType,
    NodeType,
)


@dataclass
class TaintViolation:
    """Represents a verified end-to-end taint propagation chain from source to sink."""
    violation_id: str
    rule_id: str
    severity: str
    source_node: CPGNode
    sink_node: CPGNode
    path: List[Tuple[CPGNode, Optional[EdgeType]]]
    is_cross_file: bool = False
    is_microservice: bool = False
    microservice_info: Optional[Dict[str, Any]] = None


@dataclass
class _TaintState:
    source_node: CPGNode
    source_rule: str
    current_node: CPGNode
    path: List[Tuple[CPGNode, Optional[EdgeType]]]
    is_cross_file: bool = False
    is_microservice: bool = False
    microservice_info: Optional[Dict[str, Any]] = None
    hops: int = 0


class InterProceduralTaintEngine:
    """
    Executes fixed-point inter-procedural taint propagation across
    files and microservice boundaries.
    """

    SOURCE_SIGNATURES = {
        "ENV_001": ["os.environ", "os.getenv", "environ.get"],
        "FIL_001": ["open(", "read_text", "read_bytes", "Path("],
        "RAW_DATA": ["load_creditcard_records", "raw_data", "load_data", "dataset", "train_data"],
        "SYS_IN": ["sys.argv", "sys.stdin"],
    }

    SINK_SIGNATURES = {
        "CMD_001": ["subprocess.", "os.system", "os.popen", "execv", "spawn"],
        "NET_001": ["requests.", "urllib.", "httpx.", "socket."],
        "DYN_001": ["eval(", "exec(", "__import__", "importlib.import_module"],
        "PER_001": [".bashrc", ".bash_profile", ".profile", "/etc/cron"],
        "EMB_001": ["torch.save", "np.save", "pickle.dump"],
    }

    def __init__(self, cpg: CodePropertyGraph, max_hops: int = 50):
        self.cpg = cpg
        self.max_hops = max_hops

    def analyze(self) -> List[TaintViolation]:
        """Perform inter-procedural taint propagation and return detected violations."""
        violations: List[TaintViolation] = []
        sources = self._identify_sources()
        worklist: deque[_TaintState] = deque()

        for src_node, rule_id in sources:
            worklist.append(
                _TaintState(
                    source_node=src_node,
                    source_rule=rule_id,
                    current_node=src_node,
                    path=[(src_node, None)],
                    hops=0,
                )
            )

        # visited set: (current_node_id, source_node_id)
        visited: Set[Tuple[str, str]] = set()

        while worklist:
            state = worklist.popleft()
            curr = state.current_node
            visit_key = (curr.node_id, state.source_node.node_id)

            if visit_key in visited or state.hops >= self.max_hops:
                continue
            visited.add(visit_key)

            # Check if current node is a Sink (and not the source itself)
            if curr.node_id != state.source_node.node_id:
                sink_rule = self._match_sink(curr)
                if sink_rule:
                    final_rule = self._resolve_violation_rule(state.source_rule, sink_rule)
                    severity = "CRITICAL" if (state.is_microservice or state.is_cross_file) else "HIGH"

                    violations.append(
                        TaintViolation(
                            violation_id=f"VIO-{len(violations) + 1}",
                            rule_id=final_rule,
                            severity=severity,
                            source_node=state.source_node,
                            sink_node=curr,
                            path=list(state.path),
                            is_cross_file=state.is_cross_file,
                            is_microservice=state.is_microservice,
                            microservice_info=state.microservice_info,
                        )
                    )

            # Propagate taint along outgoing dataflow and inter-procedural/microservice edges
            target_edges = {
                EdgeType.DFG_DEF_USE,
                EdgeType.CALL_ARG,
                EdgeType.CALL_RET,
                EdgeType.MICROSERVICE_PAYLOAD,
                EdgeType.MICROSERVICE_HTTP,
            }

            for next_node, edge in self.cpg.get_successors(curr.node_id, target_edges):
                if self._is_sanitizer(next_node):
                    continue

                new_cross_file = state.is_cross_file or (curr.file_path != next_node.file_path)
                new_microservice = state.is_microservice or (edge.edge_type in (
                    EdgeType.MICROSERVICE_PAYLOAD, EdgeType.MICROSERVICE_HTTP
                ))
                ms_info = state.microservice_info
                if edge.edge_type in (EdgeType.MICROSERVICE_PAYLOAD, EdgeType.MICROSERVICE_HTTP):
                    ms_info = edge.metadata

                worklist.append(
                    _TaintState(
                        source_node=state.source_node,
                        source_rule=state.source_rule,
                        current_node=next_node,
                        path=state.path + [(next_node, edge.edge_type)],
                        is_cross_file=new_cross_file,
                        is_microservice=new_microservice,
                        microservice_info=ms_info,
                        hops=state.hops + 1,
                    )
                )

        return violations

    def _matches_signature(self, sig: str, text: str) -> bool:
        """Check signature match while avoiding substring false positives (e.g. open in Popen)."""
        if sig == "open(":
            return bool(re.search(r"(?<![A-Za-z0-9_])open\s*\(", text))
        return sig in text

    def _identify_sources(self) -> List[Tuple[CPGNode, str]]:
        """Find candidate taint origin nodes in the CPG."""
        sources: List[Tuple[CPGNode, str]] = []
        for node in self.cpg.nodes.values():
            code = node.code_str or ""
            for rule_id, sigs in self.SOURCE_SIGNATURES.items():
                if any(self._matches_signature(sig, code) for sig in sigs):
                    sources.append((node, rule_id))
                    break
        return sources

    def _match_sink(self, node: CPGNode) -> Optional[str]:
        """Check if node matches known security sink signatures."""
        code = node.code_str or ""
        sym = node.symbol_name or ""

        for rule_id, sigs in self.SINK_SIGNATURES.items():
            if any(sig in code or sig in sym for sig in sigs):
                return rule_id
        return None

    def _resolve_violation_rule(self, source_rule: str, sink_rule: str) -> str:
        """Derive canonical TAA security rule ID from source and sink combination."""
        # If sensitive credential / env / file flows to network, it's EXF_001
        if sink_rule == "NET_001" and source_rule in ("ENV_001", "FIL_001", "RAW_DATA"):
            return "EXF_001"
        # If command execution sink reached, CMD_001
        if sink_rule == "CMD_001":
            return "CMD_001"
        # If dynamic eval/exec, DYN_001
        if sink_rule == "DYN_001":
            return "DYN_001"
        # If steganographic model save with raw data, EMB_001
        if sink_rule == "EMB_001" and source_rule == "RAW_DATA":
            return "EMB_001"
        return sink_rule

    def _is_sanitizer(self, node: CPGNode) -> bool:
        """Check if node is an irreversible sanitizer (e.g. SHA-256 without salt leak)."""
        code = node.code_str or ""
        # One-way cryptographic hash with no salt concatenation
        if "hashlib.sha256" in code and "salt" not in code:
            return True
        return False
