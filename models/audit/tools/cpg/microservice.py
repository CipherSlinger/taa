# models/audit/tools/cpg/microservice.py
"""
Microservice boundary penetration and communication graph analyzer.

Detects HTTP/RPC client calls (requests, httpx, urllib, aiohttp) and
web framework endpoints (Flask, FastAPI, Django), matches endpoints across
services, and synthesizes microservice boundary edges into the CPG to eliminate
cross-service audit blind spots.
"""

import ast
import re
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
class HttpClientCall:
    """Represents an egress HTTP/RPC client invocation in a microservice client."""
    cpg_node: CPGNode
    http_method: str
    raw_url: str
    normalized_endpoint: str
    payload_node: Optional[CPGNode] = None
    file_path: str = ""
    line: int = 0


@dataclass
class HttpServerRoute:
    """Represents an ingress HTTP/RPC route handler in a microservice server."""
    func_node: CPGNode
    framework: str
    http_methods: Set[str]
    route_pattern: str
    normalized_endpoint: str
    body_access_nodes: List[CPGNode] = field(default_factory=list)
    file_path: str = ""
    line: int = 0


class MicroserviceBoundaryBridge:
    """
    Scans the CPG for HTTP clients and servers, correlates routes across repositories,
    and synthesizes cross-service communication edges.
    """

    CLIENT_METHOD_MAP = {
        "requests.get": "GET",
        "requests.post": "POST",
        "requests.put": "PUT",
        "requests.delete": "DELETE",
        "requests.patch": "PATCH",
        "httpx.get": "GET",
        "httpx.post": "POST",
        "httpx.put": "PUT",
        "httpx.delete": "DELETE",
        "urllib.request.urlopen": "GET",
    }

    def __init__(self):
        pass

    def extract_client_calls(self, cpg: CodePropertyGraph) -> List[HttpClientCall]:
        """Discover all HTTP client invocations in the CPG."""
        client_calls: List[HttpClientCall] = []
        call_nodes = cpg.find_nodes_by_type(NodeType.AST_CALL)

        for cnode in call_nodes:
            ast_call = cnode.ast_node
            if not isinstance(ast_call, ast.Call):
                continue

            symbol = cnode.symbol_name or ""
            http_method: Optional[str] = None

            # Match library method
            for client_sym, method in self.CLIENT_METHOD_MAP.items():
                if symbol == client_sym or symbol.endswith(f".{client_sym.split('.')[-1]}"):
                    if "requests" in symbol or "httpx" in symbol:
                        http_method = method
                        break

            if not http_method:
                # Check generic requests.request(method, url)
                if symbol.endswith(".request") and ast_call.args:
                    first_arg = ast_call.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        http_method = first_arg.value.upper()

            if not http_method:
                continue

            # Extract URL expression
            url_ast = None
            if symbol.endswith(".request") and len(ast_call.args) >= 2:
                url_ast = ast_call.args[1]
            elif ast_call.args:
                url_ast = ast_call.args[0]
            elif ast_call.keywords:
                for kw in ast_call.keywords:
                    if kw.arg == "url":
                        url_ast = kw.value
                        break

            raw_url = self._extract_url_string(url_ast) if url_ast else ""
            normalized = self._normalize_endpoint(raw_url)

            # Extract payload argument (json=..., data=...)
            payload_ast = None
            for kw in ast_call.keywords:
                if kw.arg in ("json", "data", "params"):
                    payload_ast = kw.value
                    break

            payload_node = None
            if payload_ast is not None:
                # Find corresponding CPG node for the payload argument
                line = getattr(payload_ast, "lineno", cnode.line)
                nodes_at_line = cpg.find_nodes_at_line(cnode.file_path, line)
                for n in nodes_at_line:
                    if n.ast_node is payload_ast:
                        payload_node = n
                        break
                if not payload_node:
                    # Fallback to call node itself
                    payload_node = cnode

            client_calls.append(
                HttpClientCall(
                    cpg_node=cnode,
                    http_method=http_method,
                    raw_url=raw_url,
                    normalized_endpoint=normalized,
                    payload_node=payload_node,
                    file_path=cnode.file_path,
                    line=cnode.line,
                )
            )

        return client_calls

    def extract_server_routes(self, cpg: CodePropertyGraph) -> List[HttpServerRoute]:
        """Discover web server route handlers (Flask, FastAPI, Django) in the CPG."""
        routes: List[HttpServerRoute] = []
        func_nodes = cpg.find_nodes_by_type(NodeType.AST_FUNC_DEF)

        for fnode in func_nodes:
            ast_func = fnode.ast_node
            if not isinstance(ast_func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for decorator in ast_func.decorator_list:
                route_info = self._parse_route_decorator(decorator)
                if not route_info:
                    continue

                framework, methods, pattern = route_info
                normalized = self._normalize_endpoint(pattern)

                # Search body access nodes inside this function
                body_access_nodes = self._find_body_access_nodes(cpg, fnode, ast_func)

                routes.append(
                    HttpServerRoute(
                        func_node=fnode,
                        framework=framework,
                        http_methods=methods,
                        route_pattern=pattern,
                        normalized_endpoint=normalized,
                        body_access_nodes=body_access_nodes,
                        file_path=fnode.file_path,
                        line=fnode.line,
                    )
                )

        return routes

    def _parse_route_decorator(
        self, decorator: ast.AST
    ) -> Optional[Tuple[str, Set[str], str]]:
        """Parse decorator AST to extract (framework, http_methods, route_pattern)."""
        if not isinstance(decorator, ast.Call):
            return None

        dec_str = ""
        if isinstance(decorator.func, ast.Attribute):
            dec_str = f"{self._expr_to_str(decorator.func.value)}.{decorator.func.attr}"
        elif isinstance(decorator.func, ast.Name):
            dec_str = decorator.func.id

        # 1. Flask / Blueprint style: @app.route("/path", methods=["POST"])
        if ".route" in dec_str:
            pattern = ""
            if decorator.args:
                pattern = self._extract_url_string(decorator.args[0])
            methods: Set[str] = set()
            for kw in decorator.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            methods.add(elt.value.upper())
            if not methods:
                methods = {"GET", "POST"}  # Default permissive
            return "flask", methods, pattern

        # 2. Flask/FastAPI shorthand: @app.post("/path"), @app.get("/path")
        for method_name in ("get", "post", "put", "delete", "patch"):
            if dec_str.endswith(f".{method_name}"):
                pattern = ""
                if decorator.args:
                    pattern = self._extract_url_string(decorator.args[0])
                for kw in decorator.keywords:
                    if kw.arg in ("path", "rule"):
                        pattern = self._extract_url_string(kw.value)
                return "fastapi" if "router" in dec_str or "app" in dec_str else "generic", {method_name.upper()}, pattern

        return None

    def _find_body_access_nodes(
        self, cpg: CodePropertyGraph, func_node: CPGNode, ast_func: ast.AST
    ) -> List[CPGNode]:
        """Find nodes accessing incoming request payload (e.g. request.get_json(), request.data)."""
        access_nodes: List[CPGNode] = []
        for child in ast.walk(ast_func):
            # Check request.get_json(), request.json, request.data
            if isinstance(child, ast.Call):
                call_str = self._expr_to_str(child.func)
                if call_str in ("request.get_json", "req.get_json", "request.json", "request.data"):
                    nodes = cpg.find_nodes_at_line(func_node.file_path, getattr(child, "lineno", 0))
                    for n in nodes:
                        if n.ast_node is child:
                            access_nodes.append(n)
            elif isinstance(child, ast.Attribute):
                attr_str = self._expr_to_str(child)
                if attr_str in ("request.data", "request.json", "request.form", "req.body"):
                    nodes = cpg.find_nodes_at_line(func_node.file_path, getattr(child, "lineno", 0))
                    for n in nodes:
                        if n.ast_node is child:
                            access_nodes.append(n)

        # If no explicit request.* calls, fallback to formal parameters of the route handler
        if not access_nodes and isinstance(ast_func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for param in ast_func.args.args:
                if param.arg not in ("self", "cls"):
                    nodes = cpg.find_nodes_at_line(func_node.file_path, getattr(param, "lineno", func_node.line))
                    for n in nodes:
                        if n.symbol_name == param.arg:
                            access_nodes.append(n)

        if not access_nodes:
            access_nodes.append(func_node)

        return access_nodes

    def _extract_url_string(self, node: Optional[ast.AST]) -> str:
        """Extract literal URL or normalized template from AST."""
        if node is None:
            return ""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.JoinedStr):
            # Formatted f-string: e.g. f"http://{HOST}:{PORT}/api/v1/log"
            parts = []
            for val in node.values:
                if isinstance(val, ast.Constant):
                    parts.append(str(val.value))
                else:
                    parts.append("{var}")
            return "".join(parts)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # Concatenation: BASE_URL + "/api/v1/log"
            return self._extract_url_string(node.left) + self._extract_url_string(node.right)
        return ""

    def _normalize_endpoint(self, url: str) -> str:
        """Strip scheme, host, port, parameters, and variable delimiters to a normalized path."""
        if not url:
            return ""

        # Remove scheme
        url = re.sub(r"^https?://", "", url)
        # Remove host:port if present
        if "/" in url:
            url = "/" + url.split("/", 1)[1]
        elif not url.startswith("/"):
            url = "/" + url

        # Normalize path parameter variables: <int:id>, {user_id}, <id> -> :param
        url = re.sub(r"<[^>]+>", ":param", url)
        url = re.sub(r"\{[^}]+\}", ":param", url)

        # Strip query string
        url = url.split("?")[0]
        # Strip trailing slash
        if len(url) > 1 and url.endswith("/"):
            url = url[:-1]
        return url

    def bridge_boundaries(self, cpg: CodePropertyGraph) -> int:
        """
        Cross-reference HTTP client calls with server route handlers and
        synthesize cross-microservice CPG edges.
        Returns the number of synthesized boundary links.
        """
        clients = self.extract_client_calls(cpg)
        servers = self.extract_server_routes(cpg)
        bridge_count = 0

        for client in clients:
            for server in servers:
                # Check method compatibility
                if client.http_method not in server.http_methods:
                    continue

                # Check path match
                if not self._is_path_match(client.normalized_endpoint, server.normalized_endpoint):
                    continue

                # 1. Edge: Client Call Node -> Server Function Entry (MICROSERVICE_HTTP)
                cpg.add_edge(
                    CPGEdge(
                        source_id=client.cpg_node.node_id,
                        target_id=server.func_node.node_id,
                        edge_type=EdgeType.MICROSERVICE_HTTP,
                        metadata={
                            "client_file": client.file_path,
                            "server_file": server.file_path,
                            "endpoint": server.normalized_endpoint,
                            "method": client.http_method,
                        },
                    )
                )

                # 2. Edge: Client Payload -> Server Request Body Access (MICROSERVICE_PAYLOAD)
                payload_src = client.payload_node or client.cpg_node
                for body_target in server.body_access_nodes:
                    cpg.add_edge(
                        CPGEdge(
                            source_id=payload_src.node_id,
                            target_id=body_target.node_id,
                            edge_type=EdgeType.MICROSERVICE_PAYLOAD,
                            metadata={
                                "channel": "http_json",
                                "endpoint": server.normalized_endpoint,
                                "method": client.http_method,
                            },
                        )
                    )

                # 3. Edge: Server Returns -> Client Call Node (MICROSERVICE_RESPONSE)
                for item in ast.walk(server.func_node.ast_node):
                    if isinstance(item, ast.Return):
                        nodes = cpg.find_nodes_at_line(server.file_path, getattr(item, "lineno", 0))
                        for n in nodes:
                            if n.ast_node is item:
                                cpg.add_edge(
                                    CPGEdge(
                                        source_id=n.node_id,
                                        target_id=client.cpg_node.node_id,
                                        edge_type=EdgeType.MICROSERVICE_RESPONSE,
                                    )
                                )

                bridge_count += 1

        return bridge_count

    def _is_path_match(self, client_path: str, server_path: str) -> bool:
        """Compare client normalized path against server route pattern."""
        if not client_path or not server_path:
            return False

        if client_path == server_path:
            return True

        # Suffix matching: e.g. client called "/v1/telemetry", server defined "/telemetry"
        if client_path.endswith(server_path) or server_path.endswith(client_path):
            return True

        return False

    def _expr_to_str(self, node: ast.AST) -> str:
        """Format expression into string representation."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._expr_to_str(node.value)}.{node.attr}"
        return ""
