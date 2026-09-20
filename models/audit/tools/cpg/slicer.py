# models/audit/tools/cpg/slicer.py
"""
Deep Audit Evidence Slicer and Trajectory Compressor.

Performs Program Dependence Graph (PDG) slicing on inter-procedural taint
violations, eliminates redundant intermediate variable re-assignments, and
formats compressed multi-file trajectories and enclosing scopes for LLM prompts.
"""

from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from models.audit.tools.cpg.models import CPGNode, EdgeType
from models.audit.tools.cpg.taint_engine import TaintViolation


class CPGEvidenceSlicer:
    """
    Slices and compresses CPG taint propagation paths into minimal,
    high-signal audit evidence blocks for Semgrep findings and LLM prompts.
    """

    def __init__(self):
        pass

    def compress_trajectory(self, violation: TaintViolation) -> List[Dict[str, Any]]:
        """
        Compress a raw violation path into a deduplicated, human/LLM readable
        sequence of causality checkpoints.
        """
        raw_steps = violation.path
        if not raw_steps:
            return []

        compressed: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[str, int, str]] = set()

        total = len(raw_steps)
        for idx, (node, edge_type) in enumerate(raw_steps):
            is_first = idx == 0
            is_last = idx == total - 1

            step_type = "PROPAGATOR"
            if is_first:
                step_type = f"SOURCE ({violation.rule_id})"
            elif is_last:
                step_type = f"SINK ({violation.rule_id})"
            elif edge_type in (EdgeType.MICROSERVICE_PAYLOAD, EdgeType.MICROSERVICE_HTTP):
                step_type = "MICROSERVICE_EGRESS" if idx < total // 2 else "MICROSERVICE_INGRESS"
            elif edge_type == EdgeType.CALL_ARG:
                step_type = "INTER_PROC_CALL"
            elif edge_type == EdgeType.CALL_RET:
                step_type = "CALL_RETURN"
            elif edge_type == EdgeType.DFG_DEF_USE and idx > 0 and node.file_path != raw_steps[idx - 1][0].file_path:
                step_type = "CROSS_MODULE_HOP"

            # Clean path filename for concise display
            clean_file = Path(node.file_path).name if node.file_path else "unknown"
            code_line = (node.code_str or "").strip()
            if len(code_line) > 120:
                code_line = code_line[:117] + "..."

            dedup_key = (clean_file, node.line, code_line)
            if not is_first and not is_last and dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            compressed.append(
                {
                    "step": len(compressed) + 1,
                    "type": step_type,
                    "file": clean_file,
                    "full_path": node.file_path,
                    "line": node.line,
                    "code": code_line,
                    "enclosing_scope": node.enclosing_scope,
                    "edge_type": edge_type.value if edge_type else None,
                }
            )

        return compressed

    def format_trajectory_block(self, steps: List[Dict[str, Any]]) -> str:
        """
        Format compressed steps into the standard tree-structured
        [Deep Audit Inter-Procedural Taint Trajectory] block.
        """
        if not steps:
            return ""

        lines = ["[Deep Audit Inter-Procedural Taint Trajectory]"]
        total = len(steps)
        for i, step in enumerate(steps):
            is_last = i == total - 1
            branch = "└──" if is_last else "├──"
            file_name = step.get("file", "unknown")
            line_no = step.get("line", 0)
            step_type = step.get("type", "STEP")
            code = step.get("code", "")
            lines.append(f"  {branch} [Step {step['step']}: {step_type}] (File: {file_name}, Line {line_no}): {code}")

        return "\n".join(lines)

    def extract_multi_file_context(
        self, violation: TaintViolation, max_lines_per_file: int = 15
    ) -> str:
        """
        Extract code slices and enclosing scopes for each distinct file
        involved in the taint trajectory.
        """
        files_to_lines: Dict[str, Set[int]] = {}
        for node, _ in violation.path:
            if node.file_path:
                files_to_lines.setdefault(node.file_path, set()).add(node.line)

        sections = ["# [Cross-File & Microservice Sliced Context]"]
        for fpath, lines in files_to_lines.items():
            p = Path(fpath)
            fname = p.name
            if not p.is_file():
                continue

            try:
                src_lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue

            sections.append(f"# --- File: {fname} ---")

            # Determine line window around visited lines
            min_line = max(1, min(lines) - 2)
            max_line = min(len(src_lines), max(lines) + 2)

            # Cap window if too large
            if (max_line - min_line + 1) > max_lines_per_file:
                # Center around minimum line
                max_line = min(len(src_lines), min_line + max_lines_per_file)

            for lno in range(min_line, max_line + 1):
                marker = ">>>" if lno in lines else "   "
                text = src_lines[lno - 1] if 1 <= lno <= len(src_lines) else ""
                sections.append(f"{marker} {lno:4d} | {text}")

        return "\n".join(sections)
