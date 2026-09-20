# models/audit/tools/cpg/resolver.py
"""
Multi-file and cross-repository symbol and import resolver.

Indexes functions, classes, methods, and variables across multiple files
and resolves absolute, relative, and aliased imports into canonical
Fully Qualified Names (FQNs).
"""

import ast
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


class SymbolResolver:
    """
    Scans project workspace roots and maintains an index of symbol definitions
    and import bindings to resolve cross-file function calls and references.
    """

    def __init__(self, workspace_roots: List[str]):
        self.workspace_roots: List[Path] = [Path(r).resolve() for r in workspace_roots]
        self.file_to_module: Dict[str, str] = {}
        self.module_to_file: Dict[str, str] = {}
        # FQN -> (file_path, ast_node)
        self.global_symbols: Dict[str, Tuple[str, ast.AST]] = {}
        # file_path -> {local_alias: target_FQN}
        self.file_imports: Dict[str, Dict[str, str]] = {}
        # class FQN -> list of base class names / FQNs
        self.class_hierarchy: Dict[str, List[str]] = {}
        # AST trees per file
        self.file_trees: Dict[str, ast.AST] = {}

    def index_workspace(self) -> None:
        """Discover and index all Python files across workspace roots."""
        py_files: List[Path] = []
        for root in self.workspace_roots:
            if root.is_file() and root.suffix == ".py":
                py_files.append(root)
            elif root.is_dir():
                for dirpath, _, filenames in os.walk(root):
                    for fname in filenames:
                        if fname.endswith(".py"):
                            py_files.append(Path(dirpath) / fname)

        # 1. Map file paths to canonical module names
        for fpath in py_files:
            abs_str = str(fpath.resolve())
            mod_name = self._compute_module_name(fpath)
            self.file_to_module[abs_str] = mod_name
            self.module_to_file[mod_name] = abs_str

        # 2. Parse AST for each file and record definitions and imports
        for fpath in py_files:
            abs_str = str(fpath.resolve())
            try:
                code = fpath.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(code, filename=abs_str)
                self.file_trees[abs_str] = tree
                self._index_file_ast(abs_str, tree)
            except Exception:
                continue

    def _compute_module_name(self, fpath: Path) -> str:
        """Compute dotted module name relative to the nearest workspace root."""
        for root in self.workspace_roots:
            try:
                rel = fpath.relative_to(root)
                parts = list(rel.parts)
                if parts[-1].endswith(".py"):
                    parts[-1] = parts[-1][:-3]
                if parts[-1] == "__init__":
                    parts = parts[:-1]
                if parts:
                    return ".".join(parts)
            except ValueError:
                continue
        # Fallback to stem
        return fpath.stem

    def _index_file_ast(self, file_path: str, tree: ast.AST) -> None:
        """Index top-level definitions and imports for a single parsed AST."""
        module_name = self.file_to_module.get(file_path, "")
        imports_map: Dict[str, str] = {}
        self.file_imports[file_path] = imports_map

        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fqn = f"{module_name}.{node.name}" if module_name else node.name
                self.global_symbols[fqn] = (file_path, node)

            elif isinstance(node, ast.ClassDef):
                class_fqn = f"{module_name}.{node.name}" if module_name else node.name
                self.global_symbols[class_fqn] = (file_path, node)
                bases = []
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        bases.append(base.id)
                    elif isinstance(base, ast.Attribute):
                        bases.append(self._attr_to_str(base))
                self.class_hierarchy[class_fqn] = bases

                # Index methods
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_fqn = f"{class_fqn}.{item.name}"
                        self.global_symbols[method_fqn] = (file_path, item)

            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_fqn = f"{module_name}.{target.id}" if module_name else target.id
                        self.global_symbols[var_fqn] = (file_path, node)

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    imports_map[local_name] = alias.name

            elif isinstance(node, ast.ImportFrom):
                target_mod = self._resolve_import_from_module(file_path, node.module or "", node.level)
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    if alias.name == "*":
                        # Wildcard import: link all symbols in target_mod
                        self._expand_wildcard_import(file_path, target_mod, imports_map)
                    else:
                        full_target = f"{target_mod}.{alias.name}" if target_mod else alias.name
                        imports_map[local_name] = full_target

    def _resolve_import_from_module(self, file_path: str, mod: str, level: int) -> str:
        """Resolve relative import level to absolute module path."""
        if level == 0:
            return mod

        current_module = self.file_to_module.get(file_path, "")
        parts = current_module.split(".") if current_module else []

        # level 1 is same directory, level 2 is parent directory, etc.
        slice_idx = max(0, len(parts) - level)
        base_parts = parts[:slice_idx]
        if mod:
            base_parts.append(mod)
        return ".".join(base_parts)

    def _expand_wildcard_import(self, file_path: str, target_mod: str, imports_map: Dict[str, str]) -> None:
        """Import all non-private symbols from target_mod into file imports map."""
        prefix = f"{target_mod}."
        for sym in self.global_symbols:
            if sym.startswith(prefix):
                sub = sym[len(prefix):]
                if "." not in sub and not sub.startswith("_"):
                    imports_map[sub] = sym

    def _attr_to_str(self, node: ast.Attribute) -> str:
        """Recursively format an ast.Attribute chain into a dotted string."""
        parts = []
        curr: Any = node
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        parts.reverse()
        return ".".join(parts)

    def resolve_symbol(
        self, current_file: str, symbol_expr: str, current_scope: str = ""
    ) -> Optional[str]:
        """
        Resolve a symbol name or call expression to its canonical FQN.
        Checks:
        1. Current enclosing scope / class
        2. Module imports table for current file
        3. Local definitions in the same module
        4. Global symbol table across workspace
        """
        current_file = str(Path(current_file).resolve())
        module_name = self.file_to_module.get(current_file, "")
        imports_map = self.file_imports.get(current_file, {})

        # Normalize symbol expression (e.g. self.method -> ClassName.method)
        if symbol_expr.startswith("self.") and current_scope:
            scope_parts = current_scope.split(".")
            class_name = scope_parts[0]
            member_name = symbol_expr[5:]
            candidate = f"{module_name}.{class_name}.{member_name}" if module_name else f"{class_name}.{member_name}"
            if candidate in self.global_symbols:
                return candidate

        # 1. Check local imports map
        first_part = symbol_expr.split(".")[0]
        remainder = symbol_expr.split(".")[1:]
        if first_part in imports_map:
            target_base = imports_map[first_part]
            if remainder:
                full_resolved = f"{target_base}.{'.'.join(remainder)}"
            else:
                full_resolved = target_base
            if full_resolved in self.global_symbols:
                return full_resolved
            # Even if target is not a directly parsed def (e.g. standard library), return target FQN
            return full_resolved

        # 2. Check local module definitions
        local_fqn = f"{module_name}.{symbol_expr}" if module_name else symbol_expr
        if local_fqn in self.global_symbols:
            return local_fqn

        # 3. Check direct match in global symbols
        if symbol_expr in self.global_symbols:
            return symbol_expr

        # 4. Check bare name uniqueness across workspace
        matching_fqns = [fqn for fqn in self.global_symbols if fqn.endswith(f".{symbol_expr}")]
        if len(matching_fqns) == 1:
            return matching_fqns[0]

        return None

    def get_symbol_definition(self, fqn: str) -> Optional[Tuple[str, ast.AST]]:
        """Retrieve the (file_path, ast_node) for a resolved symbol FQN."""
        return self.global_symbols.get(fqn)
