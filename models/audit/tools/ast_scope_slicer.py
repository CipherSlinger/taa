# models/audit/tools/ast_scope_slicer.py
"""
Extracts function/class enclosing scope from AST and formats taint traces.
Provides integration with CPG multi-file and inter-procedural evidence slicing.
"""

import ast
from pathlib import Path
from typing import Any, Dict, List, Optional


class ASTScopeSlicer:
    """Extracts function/class enclosing scope from AST and formats taint traces."""

    def extract_enclosing_scope(self, source_code: str, target_line: int, language: str = "python") -> str:
        """Extracts the innermost function/class scope enclosing the target line."""
        if language.lower() == "python":
            return self._extract_python_scope(source_code, target_line)
        return self.extract_fallback_window(source_code, target_line)

    def _extract_python_scope(self, source_code: str, target_line: int) -> str:
        lines = source_code.splitlines()
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return self.extract_fallback_window(source_code, target_line)

        target_node = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                    if node.lineno <= target_line <= node.end_lineno:
                        # Pick the innermost matching node (smallest span)
                        if target_node is None or (node.end_lineno - node.lineno < target_node.end_lineno - target_node.lineno):
                            target_node = node

        if target_node and hasattr(target_node, "lineno") and hasattr(target_node, "end_lineno"):
            start = max(0, target_node.lineno - 1)
            end = min(len(lines), target_node.end_lineno)
            return "\n".join(lines[start:end])

        return self.extract_fallback_window(source_code, target_line)

    def extract_fallback_window(self, source_code: str, target_line: int, window: int = 7) -> str:
        """Fallback semantic window when AST is not parseable or node is outside a block."""
        lines = source_code.splitlines()
        start = max(0, target_line - window - 1)
        end = min(len(lines), target_line + window)
        return "\n".join(lines[start:end])

    def format_taint_trajectory(self, taint_nodes: List[Dict[str, Any]]) -> str:
        """Formats taint propagation nodes into a structured trajectory block."""
        if not taint_nodes:
            return "No cross-line taint trajectory available (direct AST node match)."

        trajectory_lines = ["[Taint Dataflow Trajectory]"]
        for idx, node in enumerate(taint_nodes):
            step = node.get("step", idx + 1)
            node_type = node.get("type", "NODE").upper()
            line = node.get("line", 0)
            code = node.get("code", "").strip()
            trajectory_lines.append(f"  └── [Step {step}: {node_type}] (Line {line}): {code}")

        return "\n".join(trajectory_lines)

    def format_inter_procedural_trajectory(self, taint_steps: List[Dict[str, Any]]) -> str:
        """
        Formats cross-file and microservice taint propagation steps into
        a tree-structured [Deep Audit Inter-Procedural Taint Trajectory] block.
        """
        if not taint_steps:
            return self.format_taint_trajectory([])

        lines = ["[Deep Audit Inter-Procedural Taint Trajectory]"]
        total = len(taint_steps)
        for i, step in enumerate(taint_steps):
            is_last = i == total - 1
            branch = "└──" if is_last else "├──"
            step_no = step.get("step", i + 1)
            step_type = step.get("type", "STEP")
            file_name = step.get("file", "unknown")
            line_no = step.get("line", 0)
            code = step.get("code", "").strip()
            lines.append(f"  {branch} [Step {step_no}: {step_type}] (File: {file_name}, Line {line_no}): {code}")

        return "\n".join(lines)

    def extract_cpg_sliced_scope(
        self, cpg: Any, finding_file: str, finding_line: int, max_lines: int = 25
    ) -> str:
        """
        Extracts multi-file sliced context from CPG for a finding, including
        cross-module caller or microservice ingress scopes.
        """
        nodes = cpg.find_nodes_at_line(finding_file, finding_line)
        if not nodes:
            # Fallback to file reading
            p = Path(finding_file)
            if p.is_file():
                return self.extract_enclosing_scope(p.read_text(encoding="utf-8", errors="replace"), finding_line)
            return ""

        target_node = nodes[0]
        # Gather predecessor and successor nodes within 2 hops
        related_nodes = [target_node]
        for pred, _ in cpg.get_predecessors(target_node.node_id):
            related_nodes.append(pred)
        for succ, _ in cpg.get_successors(target_node.node_id):
            related_nodes.append(succ)

        files_to_lines: Dict[str, List[int]] = {}
        for n in related_nodes:
            if n.file_path:
                files_to_lines.setdefault(n.file_path, []).append(n.line)

        sections = ["# [CPG Multi-File Sliced Scope]"]
        for fpath, lnums in files_to_lines.items():
            p = Path(fpath)
            if not p.is_file():
                continue
            fname = p.name
            src_lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            sections.append(f"# --- File: {fname} ---")
            min_l = max(1, min(lnums) - 2)
            max_l = min(len(src_lines), max(lnums) + 2)
            if (max_l - min_l + 1) > max_lines:
                max_l = min(len(src_lines), min_l + max_lines)
            for l in range(min_l, max_l + 1):
                marker = ">>>" if l in lnums else "   "
                txt = src_lines[l - 1] if 1 <= l <= len(src_lines) else ""
                sections.append(f"{marker} {l:4d} | {txt}")

        return "\n".join(sections)
