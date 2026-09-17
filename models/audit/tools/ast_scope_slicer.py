import ast
from typing import List, Dict, Any, Optional

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
