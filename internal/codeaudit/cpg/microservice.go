package cpg

import "strings"

// This file implements layer 4 of the Code Property Graph: microservice boundary
// penetration. It detects outbound HTTP client calls, inbound HTTP server routes,
// and cross references both sides so that a client call in one service is linked
// to the handler that serves it in another service.

// microserviceClientMethods maps a fully qualified HTTP client callee to the HTTP
// method it performs.
var microserviceClientMethods = map[string]string{
	"requests.get":           "GET",
	"requests.post":          "POST",
	"requests.put":           "PUT",
	"requests.delete":        "DELETE",
	"requests.patch":         "PATCH",
	"httpx.get":              "GET",
	"httpx.post":             "POST",
	"httpx.put":              "PUT",
	"httpx.delete":           "DELETE",
	"urllib.request.urlopen": "GET",
}

// microserviceGenericClientCalls lists the callees that carry the HTTP method as
// their first positional argument, e.g. requests.request("POST", url, json=body).
var microserviceGenericClientCalls = map[string]bool{
	"requests.request": true,
	"httpx.request":    true,
}

// microserviceSuffixMethods is an ordered list of the HTTP method names accepted
// by the alias tolerant callee resolution.
var microserviceSuffixMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

// microserviceAliasHints are dotted name fragments that identify a requests/httpx
// call even when the module was imported under an alias.
var microserviceAliasHints = []string{"requests", "httpx"}

// microserviceHTTPMethods is the set of HTTP methods that are recognized on both
// the client and the server side.
var microserviceHTTPMethods = map[string]bool{
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"PATCH":   true,
	"HEAD":    true,
	"OPTIONS": true,
}

// microserviceBodyAccessCalls are calls that read the inbound request payload.
var microserviceBodyAccessCalls = map[string]bool{
	"request.get_json": true,
	"req.get_json":     true,
	"request.json":     true,
	"request.data":     true,
}

// microserviceBodyAccessAttrs are attributes that read the inbound request payload.
var microserviceBodyAccessAttrs = map[string]bool{
	"request.data": true,
	"request.json": true,
	"request.form": true,
	"req.body":     true,
}

// HTTPClientCall describes an outbound HTTP request issued by a service.
type HTTPClientCall struct {
	Node               *CPGNode
	HTTPMethod         string
	RawURL             string
	NormalizedEndpoint string
	PayloadNode        *CPGNode
	FilePath           string
	Line               int
}

// HTTPServerRoute describes an inbound HTTP route exposed by a service.
type HTTPServerRoute struct {
	FuncNode           *CPGNode
	Framework          string
	HTTPMethods        map[string]bool
	RoutePattern       string
	NormalizedEndpoint string
	BodyAccessNodes    []*CPGNode
	FilePath           string
	Line               int
}

// MicroserviceBoundaryBridge correlates HTTP client calls with HTTP server routes
// across service boundaries.
type MicroserviceBoundaryBridge struct{}

// NewMicroserviceBoundaryBridge creates a MicroserviceBoundaryBridge instance.
func NewMicroserviceBoundaryBridge() *MicroserviceBoundaryBridge {
	return &MicroserviceBoundaryBridge{}
}

// ExtractClientCalls collects every outbound HTTP client call found in the graph.
func (b *MicroserviceBoundaryBridge) ExtractClientCalls(g *CodePropertyGraph) []*HTTPClientCall {
	if g == nil {
		return nil
	}

	var calls []*HTTPClientCall
	for _, node := range g.FindNodesByType(AST_CALL) {
		if node == nil || node.AST == nil {
			continue
		}

		method, generic := microserviceResolveClientMethod(node.AST)
		if method == "" {
			continue
		}

		rawURL := microserviceRenderString(microserviceClientURLNode(node.AST, generic))

		payload := (*CPGNode)(nil)
		if arg := microserviceKeywordArg(node.AST, "json", "data", "params"); arg != nil {
			payload = b.microserviceNodeAtLine(g, node.FilePath, arg.Lineno, arg)
		}
		if payload == nil {
			payload = node
		}

		calls = append(calls, &HTTPClientCall{
			Node:               node,
			HTTPMethod:         method,
			RawURL:             rawURL,
			NormalizedEndpoint: microserviceNormalizeEndpoint(rawURL),
			PayloadNode:        payload,
			FilePath:           node.FilePath,
			Line:               node.Line,
		})
	}
	return calls
}

// ExtractServerRoutes collects every HTTP route declared by the graph, together
// with the nodes that read the inbound request payload.
func (b *MicroserviceBoundaryBridge) ExtractServerRoutes(g *CodePropertyGraph) []*HTTPServerRoute {
	if g == nil {
		return nil
	}

	var routes []*HTTPServerRoute
	for _, node := range g.FindNodesByType(AST_FUNC_DEF) {
		if node == nil || node.AST == nil {
			continue
		}
		fn := node.AST
		if fn.Type != "FunctionDef" && fn.Type != "AsyncFunctionDef" {
			continue
		}
		for _, decorator := range fn.DecoratorList {
			if route := b.microserviceRouteFromDecorator(g, node, fn, decorator); route != nil {
				routes = append(routes, route)
			}
		}
	}
	return routes
}

// BridgeBoundaries cross references every client call with every server route and
// synthesizes the boundary edges. It returns the number of boundary links created.
func (b *MicroserviceBoundaryBridge) BridgeBoundaries(g *CodePropertyGraph) int {
	if g == nil {
		return 0
	}

	clients := b.ExtractClientCalls(g)
	routes := b.ExtractServerRoutes(g)

	links := 0
	for _, client := range clients {
		for _, route := range routes {
			if !route.HTTPMethods[client.HTTPMethod] {
				continue
			}
			if !microservicePathsMatch(client.NormalizedEndpoint, route.NormalizedEndpoint) {
				continue
			}

			// 1. The outbound call reaches the handler entry point.
			_ = g.AddEdge(&CPGEdge{
				SourceID: client.Node.NodeID,
				TargetID: route.FuncNode.NodeID,
				EdgeType: MICROSERVICE_HTTP,
				Metadata: map[string]interface{}{
					"client_file": client.FilePath,
					"server_file": route.FilePath,
					"endpoint":    route.NormalizedEndpoint,
					"method":      client.HTTPMethod,
				},
			})

			// 2. The request payload flows into every body access point.
			payload := client.PayloadNode
			if payload == nil {
				payload = client.Node
			}
			for _, body := range route.BodyAccessNodes {
				if body == nil {
					continue
				}
				_ = g.AddEdge(&CPGEdge{
					SourceID: payload.NodeID,
					TargetID: body.NodeID,
					EdgeType: MICROSERVICE_PAYLOAD,
					Metadata: map[string]interface{}{
						"channel":  "http_json",
						"endpoint": route.NormalizedEndpoint,
						"method":   client.HTTPMethod,
					},
				})
			}

			// 3. Every return statement of the handler flows back to the caller.
			for _, ret := range b.microserviceReturnNodes(g, route) {
				_ = g.AddEdge(&CPGEdge{
					SourceID: ret.NodeID,
					TargetID: client.Node.NodeID,
					EdgeType: MICROSERVICE_RESPONSE,
					Metadata: map[string]interface{}{
						"endpoint": route.NormalizedEndpoint,
						"method":   client.HTTPMethod,
					},
				})
			}

			links++
		}
	}
	return links
}

// ---------------------------------------------------------------------------
// Client side helpers
// ---------------------------------------------------------------------------

// microserviceResolveClientMethod resolves the HTTP method performed by a call. The
// second return value reports whether the call uses the generic request("METHOD",
// url) form, which shifts the URL argument to the second positional slot.
func microserviceResolveClientMethod(call *ASTNode) (string, bool) {
	if call == nil {
		return "", false
	}
	callee := strings.ToLower(strings.TrimSpace(call.GetCallFuncName()))
	if callee == "" {
		return "", false
	}

	if method, ok := microserviceClientMethods[callee]; ok {
		return method, false
	}

	if microserviceGenericClientCalls[callee] {
		if len(call.Args) > 0 {
			if value, ok := microserviceConstantString(call.Args[0]); ok {
				method := strings.ToUpper(strings.TrimSpace(value))
				if microserviceHTTPMethods[method] {
					return method, true
				}
			}
		}
		return "", true
	}

	// Alias tolerance: accept any callee that still mentions requests/httpx and
	// ends with a known method name, e.g. `my_requests.post`.
	for _, hint := range microserviceAliasHints {
		if !strings.Contains(callee, hint) {
			continue
		}
		for _, method := range microserviceSuffixMethods {
			if strings.HasSuffix(callee, "."+strings.ToLower(method)) {
				return method, false
			}
		}
	}
	return "", false
}

// microserviceClientURLNode returns the AST expression holding the request URL.
func microserviceClientURLNode(call *ASTNode, generic bool) *ASTNode {
	if call == nil {
		return nil
	}

	if generic {
		if len(call.Args) > 1 {
			return call.Args[1]
		}
	} else if len(call.Args) > 0 {
		return call.Args[0]
	}

	for _, kw := range call.Keywords {
		if kw != nil && kw.Arg == "url" {
			return kw.Value
		}
	}
	return nil
}

// microserviceKeywordArg returns the value of the first keyword argument matching
// one of the given names.
func microserviceKeywordArg(call *ASTNode, names ...string) *ASTNode {
	if call == nil {
		return nil
	}
	for _, kw := range call.Keywords {
		if kw == nil {
			continue
		}
		for _, name := range names {
			if kw.Arg == name {
				return kw.Value
			}
		}
	}
	return nil
}

// microserviceRenderString renders an AST string expression into its literal text.
// String constants are inlined, f-strings render each placeholder as {var} and
// additions of both are concatenated recursively.
func microserviceRenderString(n *ASTNode) string {
	if n == nil {
		return ""
	}

	switch n.Type {
	case "Constant":
		if n.ValueStr != "" {
			return n.ValueStr
		}
		if s, ok := n.Literal.(string); ok {
			return s
		}
		return ""
	case "JoinedStr":
		var b strings.Builder
		for _, part := range n.Values {
			if part == nil {
				continue
			}
			if part.Type == "FormattedValue" {
				b.WriteString("{" + microserviceVarName(part.Value) + "}")
				continue
			}
			b.WriteString(microserviceRenderString(part))
		}
		return b.String()
	case "BinOp":
		if n.Op == "Add" {
			return microserviceRenderString(n.Left) + microserviceRenderString(n.Right)
		}
		return ""
	default:
		return ""
	}
}

// microserviceVarName returns the textual name of an interpolated expression.
func microserviceVarName(n *ASTNode) string {
	if n == nil {
		return ""
	}
	if dotted := n.GetDottedName(); dotted != "" {
		return dotted
	}
	if n.ID != "" {
		return n.ID
	}
	return ""
}

// microserviceConstantString extracts a python string constant from an AST node.
func microserviceConstantString(n *ASTNode) (string, bool) {
	if n == nil || n.Type != "Constant" {
		return "", false
	}
	if s, ok := n.Literal.(string); ok {
		return s, true
	}
	if n.ValueStr != "" {
		return n.ValueStr, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Server side helpers
// ---------------------------------------------------------------------------

// microserviceRouteFromDecorator converts a single decorator into a route, or
// returns nil when the decorator does not declare an HTTP route.
func (b *MicroserviceBoundaryBridge) microserviceRouteFromDecorator(g *CodePropertyGraph, funcNode *CPGNode, fn *ASTNode, decorator *ASTNode) *HTTPServerRoute {
	if decorator == nil || decorator.Type != "Call" || decorator.Func == nil {
		return nil
	}

	dotted := decorator.Func.GetDottedName()
	if dotted == "" {
		return nil
	}
	lowered := strings.ToLower(dotted)
	segments := strings.Split(lowered, ".")
	last := segments[len(segments)-1]

	framework := ""
	pattern := ""
	methods := make(map[string]bool)

	switch {
	case last == "route":
		// Flask / Blueprint style: @app.route("/path", methods=["POST"]).
		framework = "flask"
		if len(decorator.Args) > 0 {
			pattern = microserviceRenderString(decorator.Args[0])
		}
		if methodsNode := microserviceKeywordArg(decorator, "methods"); methodsNode != nil {
			for _, elt := range methodsNode.Elts {
				value, ok := microserviceConstantString(elt)
				if !ok {
					continue
				}
				value = strings.ToUpper(strings.TrimSpace(value))
				if value != "" {
					methods[value] = true
				}
			}
		}
		if len(methods) == 0 {
			methods["GET"] = true
			methods["POST"] = true
		}

	case microserviceHTTPMethods[strings.ToUpper(last)]:
		// Shorthand style: @app.post("/path"), @router.get("/path").
		if strings.Contains(lowered, "router") || strings.Contains(lowered, "app") {
			framework = "fastapi"
		} else {
			framework = "generic"
		}
		methods[strings.ToUpper(last)] = true
		if len(decorator.Args) > 0 {
			pattern = microserviceRenderString(decorator.Args[0])
		}
		if pattern == "" {
			for _, name := range []string{"path", "rule"} {
				value := microserviceKeywordArg(decorator, name)
				if value == nil {
					continue
				}
				if pattern = microserviceRenderString(value); pattern != "" {
					break
				}
			}
		}

	default:
		return nil
	}

	return &HTTPServerRoute{
		FuncNode:           funcNode,
		Framework:          framework,
		HTTPMethods:        methods,
		RoutePattern:       pattern,
		NormalizedEndpoint: microserviceNormalizeEndpoint(pattern),
		BodyAccessNodes:    b.microserviceBodyAccessNodes(g, funcNode, fn),
		FilePath:           funcNode.FilePath,
		Line:               funcNode.Line,
	}
}

// microserviceBodyAccessNodes returns the nodes where the handler reads the inbound
// request payload. It falls back to the formal parameters and finally to the
// handler node itself so that the payload edge is never left dangling.
func (b *MicroserviceBoundaryBridge) microserviceBodyAccessNodes(g *CodePropertyGraph, funcNode *CPGNode, fn *ASTNode) []*CPGNode {
	var out []*CPGNode
	seen := make(map[string]bool)
	seenLines := make(map[int]bool)

	fn.Walk(func(n *ASTNode) bool {
		if n == nil {
			return false
		}

		switch n.Type {
		case "Call":
			if n.Func == nil || !microserviceBodyAccessCalls[n.Func.GetDottedName()] {
				return true
			}
		case "Attribute":
			if !microserviceBodyAccessAttrs[n.GetDottedName()] {
				return true
			}
		default:
			return true
		}

		if seenLines[n.Lineno] {
			return true
		}
		node := b.microserviceNodeAtLine(g, funcNode.FilePath, n.Lineno, n)
		if node == nil {
			return true
		}
		if !seen[node.NodeID] {
			seen[node.NodeID] = true
			seenLines[n.Lineno] = true
			out = append(out, node)
		}
		return true
	})

	if len(out) > 0 {
		return out
	}
	if params := b.microserviceParamNodes(g, funcNode, fn); len(params) > 0 {
		return params
	}
	return []*CPGNode{funcNode}
}

// microserviceParamNodes resolves the CPG nodes of the given function's formal
// parameters, excluding the implicit method receivers self and cls.
func (b *MicroserviceBoundaryBridge) microserviceParamNodes(g *CodePropertyGraph, funcNode *CPGNode, fn *ASTNode) []*CPGNode {
	names := fn.GetParamNames()
	if len(names) == 0 {
		return nil
	}

	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		if name == "" || name == "self" || name == "cls" {
			continue
		}
		wanted[name] = true
	}
	if len(wanted) == 0 {
		return nil
	}

	var out []*CPGNode
	seen := make(map[string]bool)
	for _, name := range names {
		if !wanted[name] {
			continue
		}
		for _, node := range g.FindNodesBySymbol(name) {
			if node == nil || seen[node.NodeID] || node.NodeType != AST_PARAM {
				continue
			}
			if funcNode.FilePath != "" && node.FilePath != funcNode.FilePath {
				continue
			}
			seen[node.NodeID] = true
			out = append(out, node)
		}
	}
	if len(out) > 0 {
		return out
	}

	// Fallback: parameter nodes declared on the function definition line.
	for _, node := range g.FindNodesAtLine(funcNode.FilePath, funcNode.Line) {
		if node == nil || seen[node.NodeID] || node.NodeType != AST_PARAM || !wanted[node.SymbolName] {
			continue
		}
		seen[node.NodeID] = true
		out = append(out, node)
	}
	return out
}

// microserviceReturnNodes locates the CPG nodes of every return statement inside
// the handler body.
func (b *MicroserviceBoundaryBridge) microserviceReturnNodes(g *CodePropertyGraph, route *HTTPServerRoute) []*CPGNode {
	if route == nil || route.FuncNode == nil || route.FuncNode.AST == nil {
		return nil
	}

	var out []*CPGNode
	seen := make(map[string]bool)
	route.FuncNode.AST.Walk(func(n *ASTNode) bool {
		if n == nil || n.Type != "Return" {
			return true
		}
		node := b.microserviceNodeAtLine(g, route.FilePath, n.Lineno, n)
		if node == nil {
			node = microserviceReturnNodeAt(g, route.FilePath, n.Lineno)
		}
		if node != nil && !seen[node.NodeID] {
			seen[node.NodeID] = true
			out = append(out, node)
		}
		return true
	})
	return out
}

// microserviceReturnNodeAt falls back to the first node at the given line that was
// itself derived from a return statement.
func microserviceReturnNodeAt(g *CodePropertyGraph, filePath string, line int) *CPGNode {
	nodes := g.FindNodesAtLine(filePath, line)
	for _, n := range nodes {
		if n != nil && n.AST != nil && n.AST.Type == "Return" {
			return n
		}
	}
	if len(nodes) > 0 {
		return nodes[0]
	}
	return nil
}

// microserviceNodeAtLine resolves the CPG node that represents the given AST node.
// The node carrying the same AST pointer is preferred, otherwise the first node
// registered on that line is used.
func (b *MicroserviceBoundaryBridge) microserviceNodeAtLine(g *CodePropertyGraph, filePath string, line int, want *ASTNode) *CPGNode {
	nodes := g.FindNodesAtLine(filePath, line)
	if len(nodes) == 0 {
		return nil
	}
	for _, n := range nodes {
		if n != nil && n.AST == want {
			return n
		}
	}
	return nodes[0]
}

// ---------------------------------------------------------------------------
// Endpoint normalization and matching
// ---------------------------------------------------------------------------

// microserviceNormalizeEndpoint reduces a raw URL or a route pattern to a
// comparable endpoint path.
func microserviceNormalizeEndpoint(raw string) string {
	path := strings.TrimSpace(raw)
	if path == "" {
		return ""
	}

	lowered := strings.ToLower(path)
	switch {
	case strings.HasPrefix(lowered, "http://"):
		path = path[len("http://"):]
	case strings.HasPrefix(lowered, "https://"):
		path = path[len("https://"):]
	}

	// Drop the host (and port) before the first path separator.
	if idx := strings.Index(path, "/"); idx >= 0 {
		path = path[idx:]
	} else {
		path = "/" + path
	}

	path = microserviceStripPathParams(path)

	// Drop the query string.
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}

	// Drop a trailing slash unless the path is the root itself.
	for len(path) > 1 && strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}
	return path
}

// microserviceStripPathParams replaces <converter:name> and {name} placeholders by
// the canonical :param marker.
func microserviceStripPathParams(path string) string {
	if !strings.ContainsAny(path, "<{") {
		return path
	}

	var b strings.Builder
	for i := 0; i < len(path); {
		switch path[i] {
		case '<':
			if end := strings.IndexByte(path[i:], '>'); end >= 0 {
				b.WriteString(":param")
				i += end + 1
				continue
			}
		case '{':
			if end := strings.IndexByte(path[i:], '}'); end >= 0 {
				b.WriteString(":param")
				i += end + 1
				continue
			}
		}
		b.WriteByte(path[i])
		i++
	}
	return b.String()
}

// microservicePathsMatch reports whether two normalized endpoints address the same
// resource. Segments are compared literally, or loosely when either side uses the
// :param placeholder.
func microservicePathsMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}

	left := strings.Split(a, "/")
	right := strings.Split(b, "/")
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] == right[i] || left[i] == ":param" || right[i] == ":param" {
			continue
		}
		return false
	}
	return true
}
