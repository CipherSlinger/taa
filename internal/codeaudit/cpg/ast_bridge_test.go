package cpg

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCodePropertyGraph_CRUDAndIndices(t *testing.T) {
	graph := NewCodePropertyGraph()

	// 1. Add Nodes
	node1 := &CPGNode{
		NodeID:     "n1",
		FilePath:   "app/main.py",
		Line:       1,
		Col:        0,
		EndLine:    10,
		EndCol:     0,
		NodeType:   AST_FUNC_DEF,
		CodeStr:    "def handle_request(req):",
		SymbolName: "handle_request",
		Attributes: map[string]interface{}{"is_entry": true},
	}
	node2 := &CPGNode{
		NodeID:         "n2",
		FilePath:       "app/main.py",
		Line:           2,
		Col:            4,
		EndLine:        2,
		EndCol:         20,
		NodeType:       AST_ASSIGN,
		CodeStr:        "url = req.url",
		EnclosingScope: "handle_request",
		ScopeID:        "n1",
		SymbolName:     "url",
	}
	node3 := &CPGNode{
		NodeID:         "n3",
		FilePath:       "app/main.py",
		Line:           3,
		Col:            4,
		EndLine:        3,
		EndCol:         35,
		NodeType:       AST_CALL,
		CodeStr:        "res = requests.get(url)",
		EnclosingScope: "handle_request",
		ScopeID:        "n1",
		SymbolName:     "requests.get",
	}
	node4 := &CPGNode{
		NodeID:         "n4",
		FilePath:       "app/main.py",
		Line:           3,
		Col:            10,
		EndLine:        3,
		EndCol:         35,
		NodeType:       MICROSERVICE_CLIENT,
		CodeStr:        "requests.get(url)",
		EnclosingScope: "handle_request",
		ScopeID:        "n1",
		SymbolName:     "requests.get",
	}

	for _, n := range []*CPGNode{node1, node2, node3, node4} {
		if err := graph.AddNode(n); err != nil {
			t.Fatalf("failed to add node %s: %v", n.NodeID, err)
		}
	}

	// Verify node count
	if got := graph.CountNodes(); got != 4 {
		t.Fatalf("expected 4 nodes, got %d", got)
	}

	// 2. Add Edges
	edge1 := &CPGEdge{
		SourceID: "n1",
		TargetID: "n2",
		EdgeType: CFG_NEXT,
	}
	edge2 := &CPGEdge{
		SourceID: "n2",
		TargetID: "n3",
		EdgeType: DFG_DEF_USE,
		Metadata: map[string]interface{}{"var": "url"},
	}
	edge3 := &CPGEdge{
		SourceID: "n3",
		TargetID: "n4",
		EdgeType: CALL,
	}

	for _, e := range []*CPGEdge{edge1, edge2, edge3} {
		if err := graph.AddEdge(e); err != nil {
			t.Fatalf("failed to add edge %s -> %s: %v", e.SourceID, e.TargetID, err)
		}
	}

	// Verify edge count
	if got := graph.CountEdges(); got != 3 {
		t.Fatalf("expected 3 edges, got %d", got)
	}

	// 3. Query Node by ID
	n, found := graph.GetNode("n1")
	if !found || n == nil {
		t.Fatalf("node n1 not found")
	}
	if n.SymbolName != "handle_request" {
		t.Fatalf("expected handle_request, got %s", n.SymbolName)
	}

	// 4. Query Successors & Predecessors
	succs := graph.GetSuccessors("n2")
	if len(succs) != 1 || succs[0].TargetID != "n3" {
		t.Fatalf("expected successor n3 for n2, got %v", succs)
	}
	preds := graph.GetPredecessors("n3")
	if len(preds) != 1 || preds[0].SourceID != "n2" {
		t.Fatalf("expected predecessor n2 for n3, got %v", preds)
	}

	// 5. Query by Line
	lineNodes := graph.FindNodesAtLine("app/main.py", 2)
	if len(lineNodes) != 1 || lineNodes[0].NodeID != "n2" {
		t.Fatalf("expected [n2] at line 2, got %v", lineNodes)
	}

	line3Nodes := graph.FindNodesAtLine("app/main.py", 3)
	if len(line3Nodes) != 2 {
		t.Fatalf("expected 2 nodes at line 3, got %d", len(line3Nodes))
	}

	// 6. Query by Symbol
	symNodes := graph.FindNodesBySymbol("url")
	if len(symNodes) != 1 || symNodes[0].NodeID != "n2" {
		t.Fatalf("expected [n2] for symbol 'url', got %v", symNodes)
	}

	// 7. Query by Type
	callNodes := graph.FindNodesByType(AST_CALL)
	if len(callNodes) != 1 || callNodes[0].NodeID != "n3" {
		t.Fatalf("expected [n3] for type AST_CALL, got %v", callNodes)
	}
}

func TestExtractAST_ValidPythonFile(t *testing.T) {
	tmpDir := t.TempDir()
	pyFile := filepath.Join(tmpDir, "sample.py")
	pyCode := `import os
from sys import path as sys_path

def compute(val):
    base = os.getenv("BASE_VAL")
    res = val + base
    print(res)
    return res
`
	if err := os.WriteFile(pyFile, []byte(pyCode), 0644); err != nil {
		t.Fatalf("failed to write python test file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mod, err := ExtractAST(ctx, pyFile)
	if err != nil {
		t.Fatalf("ExtractAST failed: %v", err)
	}
	if mod == nil {
		t.Fatal("expected non-nil ASTModule")
	}

	if mod.Type != "Module" {
		t.Fatalf("expected root type Module, got %s", mod.Type)
	}

	// Check body items
	if len(mod.Body) < 3 {
		t.Fatalf("expected at least 3 statements in body, got %d", len(mod.Body))
	}

	// Statement 0: import os
	impStmt := mod.Body[0]
	if impStmt.Type != "Import" {
		t.Errorf("expected Body[0] to be Import, got %s", impStmt.Type)
	}
	impNames := impStmt.GetImportedNames()
	if len(impNames) != 1 || impNames[0] != "os" {
		t.Errorf("expected imported name 'os', got %v", impNames)
	}

	// Statement 1: from sys import path as sys_path
	fromStmt := mod.Body[1]
	if fromStmt.Type != "ImportFrom" {
		t.Errorf("expected Body[1] to be ImportFrom, got %s", fromStmt.Type)
	}
	fromNames := fromStmt.GetImportedNames()
	if len(fromNames) != 1 || fromNames[0] != "sys_path" {
		t.Errorf("expected imported alias 'sys_path', got %v", fromNames)
	}

	// Statement 2: def compute(val):
	fnDef := mod.Body[2]
	if fnDef.Type != "FunctionDef" {
		t.Fatalf("expected Body[2] to be FunctionDef, got %s", fnDef.Type)
	}
	if fnDef.Name != "compute" {
		t.Errorf("expected function name 'compute', got %s", fnDef.Name)
	}
	params := fnDef.GetParamNames()
	if len(params) != 1 || params[0] != "val" {
		t.Errorf("expected parameter 'val', got %v", params)
	}

	// Check function body statements: assign, assign, expr(call), return
	if len(fnDef.Body) < 4 {
		t.Fatalf("expected at least 4 stmts in compute function, got %d", len(fnDef.Body))
	}

	assign1 := fnDef.Body[0]
	if assign1.Type != "Assign" {
		t.Errorf("expected Assign stmt, got %s", assign1.Type)
	}
	if len(assign1.GetAssignTargetNames()) != 1 || assign1.GetAssignTargetNames()[0] != "base" {
		t.Errorf("expected assign target 'base', got %v", assign1.GetAssignTargetNames())
	}
	if assign1.Value == nil || assign1.Value.Type != "Call" {
		t.Fatalf("expected Call node as value of assign1, got %v", assign1.Value)
	}
	if callFunc := assign1.Value.GetCallFuncName(); callFunc != "os.getenv" {
		t.Errorf("expected call func 'os.getenv', got %s", callFunc)
	}

	retStmt := fnDef.Body[3]
	if retStmt.Type != "Return" {
		t.Errorf("expected Return stmt, got %s", retStmt.Type)
	}
}

func TestExtractAST_ErrorsAndTimeout(t *testing.T) {
	// 1. Non-existent file
	ctx := context.Background()
	_, err := ExtractAST(ctx, "/non/existent/path/never_existed.py")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}

	// 2. Syntax error in python file
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "syntax_err.py")
	if err := os.WriteFile(badFile, []byte("def broken(:\n  return"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = ExtractAST(ctx, badFile)
	if err == nil {
		t.Fatal("expected syntax error from python ast, got nil")
	}

	// 3. Context cancelled / timeout
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err = ExtractAST(cancelledCtx, badFile)
	if err == nil {
		t.Fatal("expected error with cancelled context, got nil")
	}
}

func TestExtractASTSource_Snippet(t *testing.T) {
	code := `
def ping():
    return "pong"
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mod, err := ExtractASTSource(ctx, code)
	if err != nil {
		t.Fatalf("ExtractASTSource failed: %v", err)
	}
	if mod == nil || len(mod.Body) == 0 {
		t.Fatalf("expected parsed module body, got %v", mod)
	}
	if mod.Body[0].Name != "ping" {
		t.Errorf("expected function ping, got %s", mod.Body[0].Name)
	}
}

func TestCodePropertyGraph_ValidationAndConcurrency(t *testing.T) {
	g := NewCodePropertyGraph()

	// Validation
	if err := g.AddNode(nil); err == nil {
		t.Error("expected error adding nil node")
	}
	if err := g.AddNode(&CPGNode{}); err == nil {
		t.Error("expected error adding node without NodeID")
	}
	if err := g.AddEdge(nil); err == nil {
		t.Error("expected error adding nil edge")
	}
	if err := g.AddEdge(&CPGEdge{SourceID: ""}); err == nil {
		t.Error("expected error adding edge without endpoints")
	}

	// Concurrent read/write stress
	done := make(chan bool)
	for i := 0; i < 5; i++ {
		go func(workerID int) {
			for j := 0; j < 50; j++ {
				nodeID := filepath.Join(string(rune('a'+workerID)), string(rune('0'+j)))
				_ = g.AddNode(&CPGNode{
					NodeID:     nodeID,
					FilePath:   "worker.py",
					Line:       j + 1,
					NodeType:   AST_STMT,
					SymbolName: "var",
				})
				_ = g.AddEdge(&CPGEdge{
					SourceID: nodeID,
					TargetID: "target",
					EdgeType: CFG_NEXT,
				})
				_ = g.FindNodesAtLine("worker.py", j+1)
				_ = g.FindNodesBySymbol("var")
				_ = g.FindNodesByType(AST_STMT)
				_ = g.CountNodes()
				_ = g.CountEdges()
			}
			done <- true
		}(i)
	}

	for i := 0; i < 5; i++ {
		<-done
	}

	if g.CountNodes() != 250 {
		t.Fatalf("expected 250 nodes after concurrent insertions, got %d", g.CountNodes())
	}
	if g.CountEdges() != 250 {
		t.Fatalf("expected 250 edges after concurrent insertions, got %d", g.CountEdges())
	}
	if len(g.GetAllNodes()) != 250 {
		t.Fatalf("expected 250 in GetAllNodes, got %d", len(g.GetAllNodes()))
	}
	if len(g.GetAllEdges()) != 250 {
		t.Fatalf("expected 250 in GetAllEdges, got %d", len(g.GetAllEdges()))
	}
}

func TestExtractAST_ComplexStructuresAndWalk(t *testing.T) {
	code := `
import os
from http import client as http_client

class BaseService:
    def __init__(self, host):
        self.host = host

    def send(self, data):
        try:
            if not self.host:
                raise ValueError("empty host")
            res = requests.post(self.host, json=data)
            return res.status_code
        except Exception as err:
            return -1
        finally:
            self.cleanup()
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mod, err := ExtractASTSource(ctx, code)
	if err != nil {
		t.Fatalf("ExtractASTSource failed: %v", err)
	}

	// Verify ClassDef
	if len(mod.Body) < 3 {
		t.Fatalf("expected 3 top-level items, got %d", len(mod.Body))
	}
	classDef := mod.Body[2]
	if classDef.Type != "ClassDef" || classDef.Name != "BaseService" {
		t.Fatalf("expected ClassDef BaseService, got %s / %s", classDef.Type, classDef.Name)
	}
	if len(classDef.Body) != 2 {
		t.Fatalf("expected 2 methods in class, got %d", len(classDef.Body))
	}

	sendMethod := classDef.Body[1]
	if sendMethod.Name != "send" {
		t.Fatalf("expected send method, got %s", sendMethod.Name)
	}

	// Test Walk: collect all node types
	typeCounts := make(map[string]int)
	for _, stmt := range mod.Body {
		stmt.Walk(func(n *ASTNode) bool {
			typeCounts[n.Type]++
			return true
		})
	}

	// Verify occurrences of key constructs
	if typeCounts["ClassDef"] != 1 {
		t.Errorf("expected 1 ClassDef, got %d", typeCounts["ClassDef"])
	}
	if typeCounts["FunctionDef"] != 2 {
		t.Errorf("expected 2 FunctionDef, got %d", typeCounts["FunctionDef"])
	}
	if typeCounts["Try"] != 1 {
		t.Errorf("expected 1 Try, got %d", typeCounts["Try"])
	}
	if typeCounts["Raise"] != 1 {
		t.Errorf("expected 1 Raise, got %d", typeCounts["Raise"])
	}
	if typeCounts["Call"] < 2 {
		t.Errorf("expected at least 2 Call nodes, got %d", typeCounts["Call"])
	}
}
