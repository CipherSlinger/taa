# models/audit/tools/cpg/builder.py
"""
Inter-procedural Code Property Graph (CPG) Builder.

Parses Abstract Syntax Trees (AST), constructs intra-procedural Control Flow
Graphs (CFG), computes intra-procedural Data Flow Graphs (DFG / reaching definitions),
and establishes inter-procedural Call Graph edges with caller argument to callee
parameter bindings and return value assignments.
"""

import ast
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from models.audit.tools.cpg.models import (
    CodePropertyGraph,
    CPGEdge,
    CPGNode,
    EdgeType,
    NodeType,
)
from models.audit.tools.cpg.resolver import SymbolResolver


class CPGBuilder:
    """
    Constructs an interconnected CodePropertyGraph across single or multiple
    repositories, linking callers and callees across file and module boundaries.
    """

    def __init__(self, workspace_roots: List[str]):
        self.workspace_roots = workspace_roots
        self.resolver = SymbolResolver(workspace_roots)
        self.cpg = CodePropertyGraph()
        self._node_counter = 0

        # Map ast.AST object id -> CPGNode
        self._ast_to_cpg: Dict[int, CPGNode] = {}
        # Map FQN -> CPGNode for function definitions
        self._func_fqn_to_node: Dict[str, CPGNode] = {}
        # List of call sites to resolve in inter-procedural pass
        self._call_sites: List[Tuple[CPGNode, ast.Call, str, str, Dict[str, CPGNode]]] = []

    def _next_id(self, prefix: str = "node") -> str:
        self._node_counter += 1
        return f"{prefix}_{self._node_counter}"

    def build(self) -> CodePropertyGraph:
        """Execute full CPG construction pipeline."""
        # 1. Index symbols across workspace
        self.resolver.index_workspace()

        # 2. Build intra-procedural AST, CFG, and DFG for each file
        for file_path, tree in self.resolver.file_trees.items():
            self._build_file_cpg(file_path, tree)

        # 3. Inter-procedural Call Graph & Parameter Binding pass
        self._build_inter_procedural_edges()

        return self.cpg

    def _get_code_segment(self, file_path: str, node: ast.AST) -> str:
        """Extract exact or approximate source line for an AST node."""
        try:
            tree = self.resolver.file_trees.get(file_path)
            lines = getattr(tree, "_source_lines", None)
            if lines is None and Path(file_path).is_file():
                lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
                if tree is not None:
                    tree._source_lines = lines  # type: ignore

            if lines and hasattr(node, "lineno") and 1 <= node.lineno <= len(lines):
                line_text = lines[node.lineno - 1]
                if hasattr(node, "end_lineno") and node.end_lineno == node.lineno:
                    col = getattr(node, "col_offset", 0)
                    end_col = getattr(node, "end_col_offset", len(line_text))
                    return line_text[col:end_col].strip()
                return line_text.strip()
        except Exception:
            pass
        return ast.dump(node)

    def _create_cpg_node(
        self,
        file_path: str,
        ast_node: ast.AST,
        node_type: NodeType,
        enclosing_scope: str = "",
        symbol_name: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> CPGNode:
        """Instantiate and register a CPGNode from an AST element."""
        line = getattr(ast_node, "lineno", 1)
        col = getattr(ast_node, "col_offset", 0)
        end_line = getattr(ast_node, "end_lineno", line)
        end_col = getattr(ast_node, "end_col_offset", col)
        code_str = self._get_code_segment(file_path, ast_node)

        cpg_node = CPGNode(
            node_id=self._next_id(node_type.value.lower()),
            file_path=file_path,
            line=line,
            col=col,
            end_line=end_line,
            end_col=end_col,
            node_type=node_type,
            code_str=code_str,
            enclosing_scope=enclosing_scope,
            symbol_name=symbol_name,
            ast_node=ast_node,
            attributes=attributes or {},
        )
        self.cpg.add_node(cpg_node)
        self._ast_to_cpg[id(ast_node)] = cpg_node
        return cpg_node

    def _build_file_cpg(self, file_path: str, tree: ast.AST) -> None:
        """Process file AST: instantiate nodes, CFG edges, and intra-procedural reaching defs."""
        module_name = self.resolver.file_to_module.get(file_path, "")

        # Top-level module body scope
        self._process_statement_block(
            file_path=file_path,
            statements=getattr(tree, "body", []),
            enclosing_scope=module_name,
            scope_type="module",
        )

    def _process_statement_block(
        self,
        file_path: str,
        statements: List[ast.stmt],
        enclosing_scope: str,
        scope_type: str = "func",
        initial_defs: Optional[Dict[str, CPGNode]] = None,
    ) -> Tuple[Optional[CPGNode], Optional[CPGNode]]:
        """
        Process a sequential block of statements.
        Builds CFG_NEXT edges and DFG_DEF_USE reaching definition chains.
        Returns (first_cfg_node, last_cfg_node).
        """
        first_node: Optional[CPGNode] = None
        prev_cfg_node: Optional[CPGNode] = None

        # Reaching definitions table for this scope: var_name -> CPGNode of definition
        reaching_defs: Dict[str, CPGNode] = dict(initial_defs or {})

        for stmt in statements:
            stmt_entry, stmt_exit = self._process_statement(
                file_path, stmt, enclosing_scope, reaching_defs
            )
            if not stmt_entry:
                continue

            if first_node is None:
                first_node = stmt_entry

            if prev_cfg_node is not None and stmt_entry is not None:
                self.cpg.add_edge(
                    CPGEdge(
                        source_id=prev_cfg_node.node_id,
                        target_id=stmt_entry.node_id,
                        edge_type=EdgeType.CFG_NEXT,
                    )
                )

            prev_cfg_node = stmt_exit

        return first_node, prev_cfg_node

    def _process_statement(
        self,
        file_path: str,
        stmt: ast.stmt,
        enclosing_scope: str,
        reaching_defs: Dict[str, CPGNode],
    ) -> Tuple[Optional[CPGNode], Optional[CPGNode]]:
        """Process an individual statement, generating CPG nodes and local data/control edges."""
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_node = self._create_cpg_node(
                file_path=file_path,
                ast_node=stmt,
                node_type=NodeType.AST_FUNC_DEF,
                enclosing_scope=enclosing_scope,
                symbol_name=stmt.name,
            )
            fqn = f"{enclosing_scope}.{stmt.name}" if enclosing_scope else stmt.name
            self._func_fqn_to_node[fqn] = func_node

            # Formal parameters
            func_defs = dict(reaching_defs)
            for param in stmt.args.args:
                param_node = self._create_cpg_node(
                    file_path=file_path,
                    ast_node=param,
                    node_type=NodeType.AST_PARAM,
                    enclosing_scope=fqn,
                    symbol_name=param.arg,
                )
                self.cpg.add_edge(
                    CPGEdge(
                        source_id=func_node.node_id,
                        target_id=param_node.node_id,
                        edge_type=EdgeType.AST_CHILD,
                    )
                )
                func_defs[param.arg] = param_node

            # Process function body
            self._process_statement_block(
                file_path=file_path,
                statements=stmt.body,
                enclosing_scope=fqn,
                scope_type="func",
                initial_defs=func_defs,
            )
            return func_node, func_node

        elif isinstance(stmt, ast.ClassDef):
            class_node = self._create_cpg_node(
                file_path=file_path,
                ast_node=stmt,
                node_type=NodeType.AST_CLASS_DEF,
                enclosing_scope=enclosing_scope,
                symbol_name=stmt.name,
            )
            class_fqn = f"{enclosing_scope}.{stmt.name}" if enclosing_scope else stmt.name
            self._process_statement_block(
                file_path=file_path,
                statements=stmt.body,
                enclosing_scope=class_fqn,
                scope_type="class",
            )
            return class_node, class_node

        elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            assign_node = self._create_cpg_node(
                file_path=file_path,
                ast_node=stmt,
                node_type=NodeType.AST_ASSIGN,
                enclosing_scope=enclosing_scope,
            )

            # Link variable usages on RHS to reaching definitions
            rhs_node = getattr(stmt, "value", None)
            if rhs_node is not None:
                self._link_expression_defs(file_path, rhs_node, assign_node, reaching_defs, enclosing_scope)

            # Update reaching definitions for target variables
            targets: List[ast.AST] = []
            if isinstance(stmt, ast.Assign):
                targets.extend(stmt.targets)
            elif isinstance(stmt, ast.AnnAssign):
                targets.append(stmt.target)
            elif isinstance(stmt, ast.AugAssign):
                targets.append(stmt.target)

            for target in targets:
                if isinstance(target, ast.Name):
                    reaching_defs[target.id] = assign_node
                    assign_node.symbol_name = target.id
                elif isinstance(target, ast.Attribute):
                    attr_str = self._expr_to_str(target)
                    reaching_defs[attr_str] = assign_node
                elif isinstance(target, ast.Subscript):
                    sub_str = self._expr_to_str(target.value)
                    reaching_defs[sub_str] = assign_node

            return assign_node, assign_node

        elif isinstance(stmt, ast.Return):
            ret_node = self._create_cpg_node(
                file_path=file_path,
                ast_node=stmt,
                node_type=NodeType.AST_RETURN,
                enclosing_scope=enclosing_scope,
            )
            if stmt.value is not None:
                self._link_expression_defs(file_path, stmt.value, ret_node, reaching_defs, enclosing_scope)
            return ret_node, ret_node

        elif isinstance(stmt, ast.Expr):
            expr_node = self._create_cpg_node(
                file_path=file_path,
                ast_node=stmt,
                node_type=NodeType.AST_STMT,
                enclosing_scope=enclosing_scope,
            )
            self._link_expression_defs(file_path, stmt.value, expr_node, reaching_defs, enclosing_scope)
            return expr_node, expr_node

        elif isinstance(stmt, ast.If):
            test_node = self._create_cpg_node(
                file_path=file_path,
                ast_node=stmt.test,
                node_type=NodeType.AST_EXPR,
                enclosing_scope=enclosing_scope,
            )
            self._link_expression_defs(file_path, stmt.test, test_node, reaching_defs, enclosing_scope)

            body_defs = dict(reaching_defs)
            body_first, body_last = self._process_statement_block(
                file_path, stmt.body, enclosing_scope, "func"
            )
            if body_first:
                self.cpg.add_edge(CPGEdge(source_id=test_node.node_id, target_id=body_first.node_id, edge_type=EdgeType.CFG_BRANCH_TRUE))

            orelse_defs = dict(reaching_defs)
            orelse_first, orelse_last = self._process_statement_block(
                file_path, stmt.orelse, enclosing_scope, "func"
            )
            if orelse_first:
                self.cpg.add_edge(CPGEdge(source_id=test_node.node_id, target_id=orelse_first.node_id, edge_type=EdgeType.CFG_BRANCH_FALSE))

            # Merge reaching definitions from both branches
            reaching_defs.update(body_defs)
            reaching_defs.update(orelse_defs)

            # Exit node joins both branches
            exit_node = self._create_cpg_node(
                file_path=file_path,
                ast_node=stmt,
                node_type=NodeType.AST_STMT,
                enclosing_scope=enclosing_scope,
            )
            if body_last:
                self.cpg.add_edge(CPGEdge(source_id=body_last.node_id, target_id=exit_node.node_id, edge_type=EdgeType.CFG_NEXT))
            if orelse_last:
                self.cpg.add_edge(CPGEdge(source_id=orelse_last.node_id, target_id=exit_node.node_id, edge_type=EdgeType.CFG_NEXT))
            if not orelse_first:
                self.cpg.add_edge(CPGEdge(source_id=test_node.node_id, target_id=exit_node.node_id, edge_type=EdgeType.CFG_BRANCH_FALSE))

            return test_node, exit_node

        elif isinstance(stmt, (ast.For, ast.While)):
            loop_head = getattr(stmt, "iter", getattr(stmt, "test", stmt))
            head_node = self._create_cpg_node(
                file_path=file_path,
                ast_node=loop_head,
                node_type=NodeType.AST_EXPR,
                enclosing_scope=enclosing_scope,
            )
            self._link_expression_defs(file_path, loop_head, head_node, reaching_defs, enclosing_scope)

            # In for loop, target variable is defined
            if isinstance(stmt, ast.For) and isinstance(stmt.target, ast.Name):
                reaching_defs[stmt.target.id] = head_node

            body_first, body_last = self._process_statement_block(
                file_path, stmt.body, enclosing_scope, "func"
            )
            if body_first:
                self.cpg.add_edge(CPGEdge(source_id=head_node.node_id, target_id=body_first.node_id, edge_type=EdgeType.CFG_BRANCH_TRUE))
            if body_last:
                self.cpg.add_edge(CPGEdge(source_id=body_last.node_id, target_id=head_node.node_id, edge_type=EdgeType.CFG_NEXT))

            exit_node = self._create_cpg_node(
                file_path=file_path,
                ast_node=stmt,
                node_type=NodeType.AST_STMT,
                enclosing_scope=enclosing_scope,
            )
            self.cpg.add_edge(CPGEdge(source_id=head_node.node_id, target_id=exit_node.node_id, edge_type=EdgeType.CFG_LOOP_EXIT))
            return head_node, exit_node

        else:
            generic_node = self._create_cpg_node(
                file_path=file_path,
                ast_node=stmt,
                node_type=NodeType.AST_STMT,
                enclosing_scope=enclosing_scope,
            )
            for child in ast.walk(stmt):
                if isinstance(child, ast.Call):
                    self._collect_call_site(file_path, child, generic_node, enclosing_scope, reaching_defs)
            return generic_node, generic_node

    def _link_expression_defs(
        self,
        file_path: str,
        expr_ast: ast.AST,
        target_cpg_node: CPGNode,
        reaching_defs: Dict[str, CPGNode],
        enclosing_scope: str,
    ) -> None:
        """Walk expression AST, find variable reads and function calls, and wire DFG_DEF_USE edges."""
        for child in ast.walk(expr_ast):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                var_name = child.id
                def_node = reaching_defs.get(var_name)
                if def_node and def_node.node_id != target_cpg_node.node_id:
                    self.cpg.add_edge(
                        CPGEdge(
                            source_id=def_node.node_id,
                            target_id=target_cpg_node.node_id,
                            edge_type=EdgeType.DFG_DEF_USE,
                            metadata={"variable": var_name},
                        )
                    )

            elif isinstance(child, ast.Call):
                self._collect_call_site(file_path, child, target_cpg_node, enclosing_scope, reaching_defs)

    def _collect_call_site(
        self,
        file_path: str,
        call_ast: ast.Call,
        enclosing_cpg_node: CPGNode,
        enclosing_scope: str,
        reaching_defs: Optional[Dict[str, CPGNode]] = None,
    ) -> None:
        """Record an ast.Call site for inter-procedural resolution."""
        call_expr = self._expr_to_str(call_ast.func)
        call_cpg_node = self._create_cpg_node(
            file_path=file_path,
            ast_node=call_ast,
            node_type=NodeType.AST_CALL,
            enclosing_scope=enclosing_scope,
            symbol_name=call_expr,
        )
        self.cpg.add_edge(
            CPGEdge(
                source_id=call_cpg_node.node_id,
                target_id=enclosing_cpg_node.node_id,
                edge_type=EdgeType.DFG_DEF_USE,
            )
        )
        defs_snapshot = dict(reaching_defs or {})
        for arg in list(call_ast.args) + [kw.value for kw in call_ast.keywords]:
            if isinstance(arg, ast.Name):
                def_node = defs_snapshot.get(arg.id)
                if def_node and def_node.node_id != call_cpg_node.node_id:
                    self.cpg.add_edge(
                        CPGEdge(
                            source_id=def_node.node_id,
                            target_id=call_cpg_node.node_id,
                            edge_type=EdgeType.DFG_DEF_USE,
                            metadata={"variable": arg.id},
                        )
                    )
        self._call_sites.append((call_cpg_node, call_ast, file_path, enclosing_scope, defs_snapshot))

    def _build_inter_procedural_edges(self) -> None:
        """Resolve call sites and establish cross-file CALL, CALL_ARG, and CALL_RET edges."""
        for call_node, call_ast, file_path, scope, call_defs in self._call_sites:
            call_expr = call_node.symbol_name or self._expr_to_str(call_ast.func)
            target_fqn = self.resolver.resolve_symbol(file_path, call_expr, current_scope=scope)

            if not target_fqn or target_fqn not in self._func_fqn_to_node:
                continue

            callee_func_node = self._func_fqn_to_node[target_fqn]
            callee_ast = callee_func_node.ast_node

            if not isinstance(callee_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # 1. Edge: Call site -> Callee Function Entry
            self.cpg.add_edge(
                CPGEdge(
                    source_id=call_node.node_id,
                    target_id=callee_func_node.node_id,
                    edge_type=EdgeType.CALL,
                    metadata={"target_fqn": target_fqn},
                )
            )

            # 2. Edge: Actual Arguments -> Formal Parameters (CALL_ARG)
            # Positional arguments
            for i, arg in enumerate(call_ast.args):
                if i < len(callee_ast.args.args):
                    formal_param = callee_ast.args.args[i]
                    param_cpg = self._ast_to_cpg.get(id(formal_param))
                    arg_cpg = None
                    if isinstance(arg, ast.Name):
                        arg_cpg = call_defs.get(arg.id)
                    if not arg_cpg:
                        arg_cpg = self._ast_to_cpg.get(id(arg)) or call_node
                    if param_cpg and arg_cpg:
                        self.cpg.add_edge(
                            CPGEdge(
                                source_id=arg_cpg.node_id,
                                target_id=param_cpg.node_id,
                                edge_type=EdgeType.CALL_ARG,
                                metadata={"param_name": formal_param.arg, "arg_index": i},
                            )
                        )

            # Keyword arguments
            param_map = {p.arg: p for p in callee_ast.args.args}
            for kw in call_ast.keywords:
                if kw.arg and kw.arg in param_map:
                    formal_param = param_map[kw.arg]
                    param_cpg = self._ast_to_cpg.get(id(formal_param))
                    kw_val_cpg = None
                    if isinstance(kw.value, ast.Name):
                        kw_val_cpg = call_defs.get(kw.value.id)
                    if not kw_val_cpg:
                        kw_val_cpg = self._ast_to_cpg.get(id(kw.value)) or call_node
                    if param_cpg and kw_val_cpg:
                        self.cpg.add_edge(
                            CPGEdge(
                                source_id=kw_val_cpg.node_id,
                                target_id=param_cpg.node_id,
                                edge_type=EdgeType.CALL_ARG,
                                metadata={"param_name": kw.arg},
                            )
                        )

            # 3. Edge: Callee Returns -> Caller Call Site (CALL_RET)
            for item in ast.walk(callee_ast):
                if isinstance(item, ast.Return):
                    ret_cpg = self._ast_to_cpg.get(id(item))
                    if ret_cpg:
                        self.cpg.add_edge(
                            CPGEdge(
                                source_id=ret_cpg.node_id,
                                target_id=call_node.node_id,
                                edge_type=EdgeType.CALL_RET,
                                metadata={"target_fqn": target_fqn},
                            )
                        )

    def _expr_to_str(self, node: ast.AST) -> str:
        """Convert AST expression (Name, Attribute, Call) into a string representation."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._expr_to_str(node.value)}.{node.attr}"
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return ""
