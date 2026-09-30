package cpg

import (
	"context"
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// Local CPG construction helpers.
//
// These tests build the Code Property Graph directly from parsed Python source
// so that they do not depend on the resolver/builder layers.
// ---------------------------------------------------------------------------

// microserviceSourcePair is an ordered (file path, python source) input for the
// local CPG builder used by these tests.
type microserviceSourcePair struct {
	FilePath string
	Source   string
}

// microserviceBuildGraph parses every python snippet with ExtractASTSource and
// materializes all AST nodes of all snippets as CPG nodes in one single graph,
// which mimics an inter-file (cross-service) analysis unit.
func microserviceBuildGraph(t *testing.T, pairs ...microserviceSourcePair) *CodePropertyGraph {
	t.Helper()

	g := NewCodePropertyGraph()
	for _, p := range pairs {
		microserviceAddSource(t, g, p.FilePath, p.Source)
	}
	return g
}

// microserviceAddSource converts one python source snippet into CPG nodes and
// appends them to g. Every AST node becomes exactly one CPG node carrying the
// original AST pointer, so the microservice layer can resolve arguments back to
// graph nodes through g.FindNodesAtLine.
func microserviceAddSource(t *testing.T, g *CodePropertyGraph, filePath, source string) {
	t.Helper()

	mod, err := ExtractASTSource(context.Background(), source)
	if err != nil {
		t.Fatalf("ExtractASTSource(%s) failed: %v", filePath, err)
	}

	counter := 0
	nextID := func() string {
		counter++
		return fmt.Sprintf("%s#%d", filePath, counter)
	}

	// Formal parameters are not reachable through ASTNode.GetChildren, therefore
	// they are materialized explicitly as AST_PARAM nodes.
	addParamNodes := func(fn *ASTNode) {
		if fn == nil || fn.Arguments == nil {
			return
		}
		for _, a := range fn.Arguments.Args {
			if a == nil {
				continue
			}
			name := a.Arg
			if name == "" {
				name = a.Name
			}
			if name == "" {
				continue
			}
			node := &CPGNode{
				NodeID:     nextID(),
				FilePath:   filePath,
				Line:       fn.Lineno,
				NodeType:   AST_PARAM,
				CodeStr:    name,
				SymbolName: name,
			}
			if err := g.AddNode(node); err != nil {
				t.Fatalf("AddNode(%s) failed: %v", node.NodeID, err)
			}
		}
	}

	var walk func(n *ASTNode)
	walk = func(n *ASTNode) {
		if n == nil {
			return
		}
		symbol := n.Name
		if symbol == "" {
			symbol = n.ID
		}
		node := &CPGNode{
			NodeID:     nextID(),
			FilePath:   filePath,
			Line:       n.Lineno,
			Col:        n.ColOffset,
			EndLine:    n.EndLineno,
			EndCol:     n.EndColOffset,
			NodeType:   microserviceTestNodeType(n),
			CodeStr:    microserviceTestCode(n),
			SymbolName: symbol,
			AST:        n,
		}
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%s) failed: %v", node.NodeID, err)
		}
		addParamNodes(n)
		for _, child := range n.GetChildren() {
			walk(child)
		}
	}

	for _, stmt := range mod.Body {
		walk(stmt)
	}
}

// microserviceTestNodeType maps a python AST node type onto the closest CPG node
// type. Only the categories that matter for the microservice layer are refined.
func microserviceTestNodeType(n *ASTNode) NodeType {
	switch n.Type {
	case "FunctionDef", "AsyncFunctionDef":
		return AST_FUNC_DEF
	case "ClassDef":
		return AST_CLASS_DEF
	case "Return":
		return AST_RETURN
	case "Call":
		return AST_CALL
	case "Assign", "AnnAssign", "AugAssign":
		return AST_ASSIGN
	case "If":
		return AST_IF
	case "For", "AsyncFor":
		return AST_FOR
	case "While":
		return AST_WHILE
	case "Try":
		return AST_TRY
	case "Import", "ImportFrom":
		return AST_IMPORT
	case "Module":
		return AST_MODULE
	case "Expr", "Constant", "Name", "Attribute", "BinOp", "JoinedStr",
		"FormattedValue", "List", "Tuple", "Dict", "Set", "Subscript",
		"Compare", "BoolOp", "UnaryOp", "Starred", "Lambda", "Await",
		"DictComp", "ListComp", "SetComp", "GeneratorExp":
		return AST_EXPR
	default:
		return AST_STMT
	}
}

// microserviceTestCode renders a short, human readable code string for a node.
func microserviceTestCode(n *ASTNode) string {
	if n == nil {
		return ""
	}
	switch {
	case n.ValueStr != "":
		return n.ValueStr
	case n.Name != "":
		return n.Name
	case n.ID != "":
		return n.ID
	case n.Attr != "":
		return n.Attr
	default:
		return n.Type
	}
}

// microserviceEdgesOfType returns all edges of the given type.
func microserviceEdgesOfType(g *CodePropertyGraph, edgeType EdgeType) []*CPGEdge {
	var out []*CPGEdge
	for _, e := range g.GetAllEdges() {
		if e.EdgeType == edgeType {
			out = append(out, e)
		}
	}
	return out
}

// microserviceMetadataString reads a string metadata value from an edge.
func microserviceMetadataString(e *CPGEdge, key string) string {
	if e == nil || e.Metadata == nil {
		return ""
	}
	s, _ := e.Metadata[key].(string)
	return s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestMicroserviceBridge covers the primary scenario of the specification: a
// FastAPI service reachable through requests.post with a json payload.
func TestMicroserviceBridge(t *testing.T) {
	clientSource := `import requests

def send_telemetry(payload):
    return requests.post("http://sidecar:8080/v1/telemetry", json=payload)
`
	serverSource := `from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/v1/telemetry")
async def ingest_telemetry(request: Request):
    data = request.get_json()
    return {"status": "ok"}
`

	g := microserviceBuildGraph(t,
		microserviceSourcePair{FilePath: "client.py", Source: clientSource},
		microserviceSourcePair{FilePath: "server.py", Source: serverSource},
	)

	bridge := NewMicroserviceBoundaryBridge()

	calls := bridge.ExtractClientCalls(g)
	if len(calls) != 1 {
		t.Fatalf("ExtractClientCalls() returned %d calls, want 1", len(calls))
	}
	if calls[0].FilePath != "client.py" {
		t.Errorf("client call file = %q, want %q", calls[0].FilePath, "client.py")
	}
	if calls[0].HTTPMethod != "POST" {
		t.Errorf("client HTTP method = %q, want POST", calls[0].HTTPMethod)
	}
	if calls[0].RawURL != "http://sidecar:8080/v1/telemetry" {
		t.Errorf("client raw URL = %q", calls[0].RawURL)
	}
	if calls[0].NormalizedEndpoint != "/v1/telemetry" {
		t.Errorf("client normalized endpoint = %q, want /v1/telemetry", calls[0].NormalizedEndpoint)
	}
	if calls[0].PayloadNode == nil {
		t.Fatalf("client call has no payload node")
	}

	routes := bridge.ExtractServerRoutes(g)
	if len(routes) != 1 {
		t.Fatalf("ExtractServerRoutes() returned %d routes, want 1", len(routes))
	}
	if routes[0].Framework != "fastapi" {
		t.Errorf("route framework = %q, want fastapi", routes[0].Framework)
	}
	if !routes[0].HTTPMethods["POST"] {
		t.Errorf("route methods = %v, want POST", routes[0].HTTPMethods)
	}
	if routes[0].NormalizedEndpoint != "/v1/telemetry" {
		t.Errorf("route normalized endpoint = %q, want /v1/telemetry", routes[0].NormalizedEndpoint)
	}
	if len(routes[0].BodyAccessNodes) == 0 {
		t.Fatalf("route has no body access nodes")
	}

	links := bridge.BridgeBoundaries(g)
	if links != 1 {
		t.Fatalf("BridgeBoundaries() = %d, want 1", links)
	}

	httpEdges := microserviceEdgesOfType(g, MICROSERVICE_HTTP)
	if len(httpEdges) != 1 {
		t.Fatalf("MICROSERVICE_HTTP edge count = %d, want 1", len(httpEdges))
	}
	if httpEdges[0].SourceID != calls[0].Node.NodeID {
		t.Errorf("MICROSERVICE_HTTP source = %q, want client call %q", httpEdges[0].SourceID, calls[0].Node.NodeID)
	}
	if httpEdges[0].TargetID != routes[0].FuncNode.NodeID {
		t.Errorf("MICROSERVICE_HTTP target = %q, want server func %q", httpEdges[0].TargetID, routes[0].FuncNode.NodeID)
	}
	if got := microserviceMetadataString(httpEdges[0], "endpoint"); got != "/v1/telemetry" {
		t.Errorf("MICROSERVICE_HTTP endpoint metadata = %q, want /v1/telemetry", got)
	}
	if got := microserviceMetadataString(httpEdges[0], "method"); got != "POST" {
		t.Errorf("MICROSERVICE_HTTP method metadata = %q, want POST", got)
	}
	if got := microserviceMetadataString(httpEdges[0], "client_file"); got != "client.py" {
		t.Errorf("MICROSERVICE_HTTP client_file metadata = %q, want client.py", got)
	}
	if got := microserviceMetadataString(httpEdges[0], "server_file"); got != "server.py" {
		t.Errorf("MICROSERVICE_HTTP server_file metadata = %q, want server.py", got)
	}

	payloadEdges := microserviceEdgesOfType(g, MICROSERVICE_PAYLOAD)
	if len(payloadEdges) != 1 {
		t.Fatalf("MICROSERVICE_PAYLOAD edge count = %d, want 1", len(payloadEdges))
	}
	if payloadEdges[0].TargetID != routes[0].BodyAccessNodes[0].NodeID {
		t.Errorf("MICROSERVICE_PAYLOAD target = %q, want body access node %q",
			payloadEdges[0].TargetID, routes[0].BodyAccessNodes[0].NodeID)
	}
	if payloadEdges[0].SourceID != calls[0].PayloadNode.NodeID {
		t.Errorf("MICROSERVICE_PAYLOAD source = %q, want payload node %q",
			payloadEdges[0].SourceID, calls[0].PayloadNode.NodeID)
	}
	if got := microserviceMetadataString(payloadEdges[0], "channel"); got != "http_json" {
		t.Errorf("MICROSERVICE_PAYLOAD channel metadata = %q, want http_json", got)
	}
	if got := microserviceMetadataString(payloadEdges[0], "endpoint"); got != "/v1/telemetry" {
		t.Errorf("MICROSERVICE_PAYLOAD endpoint metadata = %q, want /v1/telemetry", got)
	}

	responseEdges := microserviceEdgesOfType(g, MICROSERVICE_RESPONSE)
	if len(responseEdges) != 1 {
		t.Fatalf("MICROSERVICE_RESPONSE edge count = %d, want 1", len(responseEdges))
	}
	if responseEdges[0].TargetID != calls[0].Node.NodeID {
		t.Errorf("MICROSERVICE_RESPONSE target = %q, want client call %q",
			responseEdges[0].TargetID, calls[0].Node.NodeID)
	}
}

// TestMicroserviceBridgeFlaskRoute covers the Flask/Blueprint route style with an
// explicit methods list.
func TestMicroserviceBridgeFlaskRoute(t *testing.T) {
	clientSource := `import requests

def push_task(body):
    return requests.post("http://worker:9000/v1/task", json=body)
`
	serverSource := `from flask import Blueprint, request

bp = Blueprint("tasks", __name__)

@bp.route("/v1/task", methods=["post"])
def create_task():
    payload = request.get_json()
    return {"id": 1}
`

	g := microserviceBuildGraph(t,
		microserviceSourcePair{FilePath: "client.py", Source: clientSource},
		microserviceSourcePair{FilePath: "service.py", Source: serverSource},
	)

	bridge := NewMicroserviceBoundaryBridge()

	routes := bridge.ExtractServerRoutes(g)
	if len(routes) != 1 {
		t.Fatalf("ExtractServerRoutes() returned %d routes, want 1", len(routes))
	}
	if routes[0].Framework != "flask" {
		t.Errorf("route framework = %q, want flask", routes[0].Framework)
	}
	if !routes[0].HTTPMethods["POST"] {
		t.Errorf("route methods = %v, want POST", routes[0].HTTPMethods)
	}
	if len(routes[0].HTTPMethods) != 1 {
		t.Errorf("route methods = %v, want exactly one method", routes[0].HTTPMethods)
	}
	if routes[0].RoutePattern != "/v1/task" {
		t.Errorf("route pattern = %q, want /v1/task", routes[0].RoutePattern)
	}

	if links := bridge.BridgeBoundaries(g); links != 1 {
		t.Fatalf("BridgeBoundaries() = %d, want 1", links)
	}

	httpEdges := microserviceEdgesOfType(g, MICROSERVICE_HTTP)
	if len(httpEdges) != 1 {
		t.Fatalf("MICROSERVICE_HTTP edge count = %d, want 1", len(httpEdges))
	}
	if got := microserviceMetadataString(httpEdges[0], "endpoint"); got != "/v1/task" {
		t.Errorf("MICROSERVICE_HTTP endpoint metadata = %q, want /v1/task", got)
	}
	if got := microserviceMetadataString(httpEdges[0], "server_file"); got != "service.py" {
		t.Errorf("MICROSERVICE_HTTP server_file metadata = %q, want service.py", got)
	}
}

// TestMicroserviceBridgeMethodMismatch verifies that a route serving only GET is
// not bridged by a POST client call.
func TestMicroserviceBridgeMethodMismatch(t *testing.T) {
	clientSource := `import requests

def push_task(body):
    return requests.post("http://worker:9000/v1/task", json=body)
`
	serverSource := `from flask import Flask, request

app = Flask(__name__)

@app.route("/v1/task", methods=["GET"])
def list_tasks():
    return {"items": []}
`

	g := microserviceBuildGraph(t,
		microserviceSourcePair{FilePath: "client.py", Source: clientSource},
		microserviceSourcePair{FilePath: "service.py", Source: serverSource},
	)

	bridge := NewMicroserviceBoundaryBridge()
	if links := bridge.BridgeBoundaries(g); links != 0 {
		t.Fatalf("BridgeBoundaries() = %d, want 0 on method mismatch", links)
	}
	if edges := microserviceEdgesOfType(g, MICROSERVICE_HTTP); len(edges) != 0 {
		t.Fatalf("MICROSERVICE_HTTP edge count = %d, want 0", len(edges))
	}
}

// TestMicroserviceBridgePathMismatch verifies that identical HTTP methods with
// different paths are not bridged.
func TestMicroserviceBridgePathMismatch(t *testing.T) {
	clientSource := `import requests

def push_task(body):
    return requests.post("http://worker:9000/v1/task", json=body)
`
	serverSource := `from fastapi import FastAPI

app = FastAPI()

@app.post("/v1/other")
def other_endpoint():
    return {"status": "ok"}
`

	g := microserviceBuildGraph(t,
		microserviceSourcePair{FilePath: "client.py", Source: clientSource},
		microserviceSourcePair{FilePath: "service.py", Source: serverSource},
	)

	bridge := NewMicroserviceBoundaryBridge()
	if links := bridge.BridgeBoundaries(g); links != 0 {
		t.Fatalf("BridgeBoundaries() = %d, want 0 on path mismatch", links)
	}
}

// TestMicroserviceBridgePathParameterEquivalence verifies that path templates on
// both sides (angle brackets, braces, or a concrete value) normalize to the same
// endpoint and therefore bridge.
func TestMicroserviceBridgePathParameterEquivalence(t *testing.T) {
	cases := []struct {
		name         string
		clientURL    string
		serverRoute  string
		wantBridges  int
		wantEndpoint string
	}{
		{
			name:         "concrete value against angle bracket converter",
			clientURL:    "http://catalog:7000/v1/item/42",
			serverRoute:  "/v1/item/<int:item_id>",
			wantBridges:  1,
			wantEndpoint: "/v1/item/:param",
		},
		{
			name:         "concrete value against brace parameter",
			clientURL:    "http://catalog:7000/v1/item/42",
			serverRoute:  "/v1/item/{item_id}",
			wantBridges:  1,
			wantEndpoint: "/v1/item/:param",
		},
		{
			name:         "brace template against brace parameter",
			clientURL:    "http://catalog:7000/v1/item/{item_id}",
			serverRoute:  "/v1/item/{id}",
			wantBridges:  1,
			wantEndpoint: "/v1/item/:param",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			clientSource := fmt.Sprintf(`import requests

def fetch_item():
    return requests.get("%s")
`, tc.clientURL)
			serverSource := fmt.Sprintf(`from fastapi import FastAPI

app = FastAPI()

@app.get("%s")
def read_item(item_id: int):
    return {"id": item_id}
`, tc.serverRoute)

			g := microserviceBuildGraph(t,
				microserviceSourcePair{FilePath: "client.py", Source: clientSource},
				microserviceSourcePair{FilePath: "service.py", Source: serverSource},
			)

			bridge := NewMicroserviceBoundaryBridge()
			if links := bridge.BridgeBoundaries(g); links != tc.wantBridges {
				t.Fatalf("BridgeBoundaries() = %d, want %d", links, tc.wantBridges)
			}
			edges := microserviceEdgesOfType(g, MICROSERVICE_HTTP)
			if len(edges) != tc.wantBridges {
				t.Fatalf("MICROSERVICE_HTTP edge count = %d, want %d", len(edges), tc.wantBridges)
			}
			for _, e := range edges {
				if got := microserviceMetadataString(e, "endpoint"); got != tc.wantEndpoint {
					t.Errorf("endpoint metadata = %q, want %q", got, tc.wantEndpoint)
				}
			}
		})
	}
}

// TestMicroserviceExtractClientCallsURLForms verifies URL rendering (f-string and
// binary concatenation), query string stripping and the alternative calling forms.
func TestMicroserviceExtractClientCallsURLForms(t *testing.T) {
	source := `import requests

host = "sidecar:8080"

def notify(payload):
    requests.post(f"http://{host}/v1/telemetry", json=payload)
    requests.post("http://sidecar:8080" + "/v1/telemetry", json=payload)
    requests.post("http://sidecar:8080/v1/telemetry?trace=1&span=2", json=payload)
    requests.post(url="http://sidecar:8080/v1/telemetry", json=payload)
    requests.request("POST", "http://sidecar:8080/v1/telemetry", json=payload)
`

	g := microserviceBuildGraph(t, microserviceSourcePair{FilePath: "client.py", Source: source})

	bridge := NewMicroserviceBoundaryBridge()
	calls := bridge.ExtractClientCalls(g)
	if len(calls) != 5 {
		t.Fatalf("ExtractClientCalls() returned %d calls, want 5", len(calls))
	}

	wantRaw := []string{
		"http://{host}/v1/telemetry",
		"http://sidecar:8080/v1/telemetry",
		"http://sidecar:8080/v1/telemetry?trace=1&span=2",
		"http://sidecar:8080/v1/telemetry",
		"http://sidecar:8080/v1/telemetry",
	}
	for i, call := range calls {
		if call.HTTPMethod != "POST" {
			t.Errorf("call %d HTTP method = %q, want POST", i, call.HTTPMethod)
		}
		if call.RawURL != wantRaw[i] {
			t.Errorf("call %d raw URL = %q, want %q", i, call.RawURL, wantRaw[i])
		}
		if call.NormalizedEndpoint != "/v1/telemetry" {
			t.Errorf("call %d normalized endpoint = %q, want /v1/telemetry", i, call.NormalizedEndpoint)
		}
		if call.PayloadNode == nil {
			t.Errorf("call %d has no payload node", i)
		}
	}
}

// TestMicroserviceClientCalleeRecognition verifies the callee resolution rules:
// known dotted names, the generic request("METHOD", url) form and aliased imports.
func TestMicroserviceClientCalleeRecognition(t *testing.T) {
	source := `import requests
import requests as my_requests
import httpx

def call_all():
    requests.get("http://a:1/v1/x")
    requests.put("http://a:1/v1/x")
    requests.delete("http://a:1/v1/x")
    requests.patch("http://a:1/v1/x")
    httpx.post("http://a:1/v1/x")
    my_requests.post("http://a:1/v1/x")
    httpx.request("PUT", "http://a:1/v1/x")
`

	g := microserviceBuildGraph(t, microserviceSourcePair{FilePath: "client.py", Source: source})

	bridge := NewMicroserviceBoundaryBridge()
	calls := bridge.ExtractClientCalls(g)

	wantMethods := []string{"GET", "PUT", "DELETE", "PATCH", "POST", "POST", "PUT"}
	if len(calls) != len(wantMethods) {
		t.Fatalf("ExtractClientCalls() returned %d calls, want %d", len(calls), len(wantMethods))
	}
	for i, want := range wantMethods {
		if calls[i].HTTPMethod != want {
			t.Errorf("call %d HTTP method = %q, want %q", i, calls[i].HTTPMethod, want)
		}
		if calls[i].NormalizedEndpoint != "/v1/x" {
			t.Errorf("call %d normalized endpoint = %q, want /v1/x", i, calls[i].NormalizedEndpoint)
		}
	}
}

// TestMicroserviceServerRouteBodyAccessFallback verifies that a handler without any
// request body access falls back to its formal parameters.
func TestMicroserviceServerRouteBodyAccessFallback(t *testing.T) {
	source := `from fastapi import FastAPI

app = FastAPI()

@app.post("/v1/ping")
def ping(body_payload: dict):
    return {"pong": True}
`

	g := microserviceBuildGraph(t, microserviceSourcePair{FilePath: "service.py", Source: source})

	bridge := NewMicroserviceBoundaryBridge()
	routes := bridge.ExtractServerRoutes(g)
	if len(routes) != 1 {
		t.Fatalf("ExtractServerRoutes() returned %d routes, want 1", len(routes))
	}
	if len(routes[0].BodyAccessNodes) != 1 {
		t.Fatalf("body access node count = %d, want 1 (formal parameter fallback)",
			len(routes[0].BodyAccessNodes))
	}
	body := routes[0].BodyAccessNodes[0]
	if body.NodeType != AST_PARAM {
		t.Errorf("body access node type = %q, want %q", body.NodeType, AST_PARAM)
	}
	if body.SymbolName != "body_payload" {
		t.Errorf("body access symbol = %q, want body_payload", body.SymbolName)
	}
}

// TestMicroserviceServerRouteFrameworks verifies the framework classification and
// the default method set of Flask routes.
func TestMicroserviceServerRouteFrameworks(t *testing.T) {
	source := `from flask import Flask

app = Flask(__name__)

@app.route("/v1/defaults")
def defaults():
    return {}

@app.post(rule="/v1/rule")
def explicit_rule():
    return {}

@app.post("/v1/explicit")
def explicit():
    return {}

@app.get(path="/v1/keyword")
def keyword_path():
    return {}
`

	g := microserviceBuildGraph(t, microserviceSourcePair{FilePath: "service.py", Source: source})

	bridge := NewMicroserviceBoundaryBridge()
	routes := bridge.ExtractServerRoutes(g)
	if len(routes) != 4 {
		t.Fatalf("ExtractServerRoutes() returned %d routes, want 4", len(routes))
	}

	if routes[0].Framework != "flask" {
		t.Errorf("route 0 framework = %q, want flask", routes[0].Framework)
	}
	if !routes[0].HTTPMethods["GET"] || !routes[0].HTTPMethods["POST"] || len(routes[0].HTTPMethods) != 2 {
		t.Errorf("route 0 methods = %v, want {GET, POST} by default", routes[0].HTTPMethods)
	}

	if routes[1].Framework != "fastapi" || routes[1].NormalizedEndpoint != "/v1/rule" {
		t.Errorf("route 1 framework = %q pattern = %q, want fastapi and /v1/rule from the rule keyword",
			routes[1].Framework, routes[1].RoutePattern)
	}
	if routes[2].Framework != "fastapi" || !routes[2].HTTPMethods["POST"] {
		t.Errorf("route 2 framework = %q methods = %v, want fastapi/POST", routes[2].Framework, routes[2].HTTPMethods)
	}
	if routes[3].NormalizedEndpoint != "/v1/keyword" {
		t.Errorf("route 3 pattern = %q, want /v1/keyword from the path keyword", routes[3].RoutePattern)
	}
}

// TestMicroserviceNormalizeEndpoint unit tests the normalization pipeline and the
// path matching predicate on their boundary cases.
func TestMicroserviceNormalizeEndpoint(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"/", "/"},
		{"http://sidecar:8080/v1/telemetry", "/v1/telemetry"},
		{"https://sidecar:8443/v1/telemetry", "/v1/telemetry"},
		{"http://sidecar:8080/v1/task/", "/v1/task"},
		{"/v1/telemetry?trace=1", "/v1/telemetry"},
		// A URL without a leading slash has its first segment treated as the host.
		{"v1/telemetry", "/telemetry"},
		{"/v1/item/<int:item_id>", "/v1/item/:param"},
		{"/v1/item/{item_id}", "/v1/item/:param"},
		{"/{item_id}/detail/<int:page>", "/:param/detail/:param"},
	}

	for _, tc := range cases {
		if got := microserviceNormalizeEndpoint(tc.raw); got != tc.want {
			t.Errorf("microserviceNormalizeEndpoint(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	matchCases := []struct {
		a, b  string
		match bool
	}{
		{"/v1/telemetry", "/v1/telemetry", true},
		{"/v1/item/42", "/v1/item/:param", true},
		{"/v1/item/:param", "/v1/item/:param", true},
		{"/v1/item/42/detail", "/v1/item/:param", false},
		{"/v1/telemetry", "/v1/other", false},
		{"", "", false},
		{"", "/v1/telemetry", false},
		{"/v1/telemetry", "", false},
	}

	for _, tc := range matchCases {
		if got := microservicePathsMatch(tc.a, tc.b); got != tc.match {
			t.Errorf("microservicePathsMatch(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.match)
		}
	}
}
