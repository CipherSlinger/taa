package cpg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers (all prefixed with "builder" to avoid collisions with sibling test
// files living in the same package).
// ---------------------------------------------------------------------------

func builderWriteFile(t *testing.T, root, rel, content string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create directory for %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	return path
}

func builderExtract(t *testing.T, code string) *ASTModule {
	t.Helper()
	mod, err := ExtractASTSource(context.Background(), code)
	if err != nil {
		t.Fatalf("ExtractASTSource failed: %v", err)
	}
	return mod
}

// builderNodeAt returns the single CPG node of the given type located at
// file:line, failing the test when there is none or more than one.
func builderNodeAt(t *testing.T, g *CodePropertyGraph, file string, line int, nt NodeType) *CPGNode {
	t.Helper()
	var found *CPGNode
	for _, n := range g.FindNodesAtLine(file, line) {
		if n.NodeType != nt {
			continue
		}
		if found != nil {
			t.Fatalf("ambiguous %s node at %s:%d", nt, file, line)
		}
		found = n
	}
	if found == nil {
		t.Fatalf("no %s node at %s:%d", nt, file, line)
	}
	return found
}

func builderHasEdge(g *CodePropertyGraph, srcID, dstID string, et EdgeType) bool {
	for _, e := range g.GetSuccessors(srcID) {
		if e.EdgeType == et && e.TargetID == dstID {
			return true
		}
	}
	return false
}

func builderEdgeTargets(g *CodePropertyGraph, srcID string, et EdgeType) []*CPGNode {
	var out []*CPGNode
	for _, e := range g.GetSuccessors(srcID) {
		if e.EdgeType != et {
			continue
		}
		if n, ok := g.GetNode(e.TargetID); ok {
			out = append(out, n)
		}
	}
	return out
}

func builderEdgeSources(g *CodePropertyGraph, dstID string, et EdgeType) []*CPGNode {
	var out []*CPGNode
	for _, e := range g.GetPredecessors(dstID) {
		if e.EdgeType != et {
			continue
		}
		if n, ok := g.GetNode(e.SourceID); ok {
			out = append(out, n)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Layer 2: SymbolResolver
// ---------------------------------------------------------------------------

func TestSymbolResolver_Imports(t *testing.T) {
	root := t.TempDir()

	builderWriteFile(t, root, "pkg/__init__.py", "")
	builderWriteFile(t, root, "pkg/util.py", "def helper(value):\n    return value\n")
	builderWriteFile(t, root, "pkg/sub/__init__.py", "")
	builderWriteFile(t, root, "pkg/sub/util.py", "def local(value):\n    return value\n")
	builderWriteFile(t, root, "pkg/sub/mod.py", "from . import util\n")
	builderWriteFile(t, root, "pkg/sub/deep/__init__.py", "")
	builderWriteFile(t, root, "pkg/sub/deep/mod.py", "from ...util import helper\n")
	// Directories that must never be indexed.
	builderWriteFile(t, root, "pkg/__pycache__/cached.py", "")
	builderWriteFile(t, root, ".git/hooks/legacy.py", "")
	builderWriteFile(t, root, "node_modules/vendor_lib.py", "")

	r := NewSymbolResolver(root)
	if err := r.Scan(); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	modPath := filepath.Join(root, "pkg", "sub", "mod.py")
	deepPath := filepath.Join(root, "pkg", "sub", "deep", "mod.py")

	// 1. Absolute import of a module registered inside the workspace.
	got, ok := r.ResolveImport(modPath, "pkg.util", 0)
	if !ok || got != "pkg.util" {
		t.Fatalf("absolute import: expected (pkg.util, true), got (%q, %v)", got, ok)
	}

	// 2. Absolute import of a module outside the workspace is not resolvable
	//    against the workspace index, but the module path is still reported.
	got, ok = r.ResolveImport(modPath, "os", 0)
	if ok || got != "os" {
		t.Fatalf("external import: expected (os, false), got (%q, %v)", got, ok)
	}

	// 3. level == 1 resolves to the current package ("from . import util").
	got, ok = r.ResolveImport(modPath, "", 1)
	if !ok || got != "pkg.sub" {
		t.Fatalf("level 1: expected (pkg.sub, true), got (%q, %v)", got, ok)
	}
	//    ... and the imported sub-module can be reached through FQN.
	if sub := r.FQN("pkg.sub", "util"); sub != "pkg.sub.util" {
		t.Fatalf("FQN: expected pkg.sub.util, got %q", sub)
	}
	if _, ok := r.LookupModule("pkg.sub.util"); !ok {
		t.Fatal("expected pkg.sub.util to be registered")
	}

	// 4. level == 2 resolves to the parent package ("from ..util import helper").
	got, ok = r.ResolveImport(modPath, "util", 2)
	if !ok || got != "pkg.util" {
		t.Fatalf("level 2: expected (pkg.util, true), got (%q, %v)", got, ok)
	}

	// 5. level == 3 from a deeper package ("from ...util import helper").
	got, ok = r.ResolveImport(deepPath, "util", 3)
	if !ok || got != "pkg.util" {
		t.Fatalf("level 3: expected (pkg.util, true), got (%q, %v)", got, ok)
	}

	// 6. A relative import escaping the workspace root is unresolvable.
	if got, ok = r.ResolveImport(modPath, "util", 5); ok {
		t.Fatalf("over-deep relative import: expected no resolution, got %q", got)
	}

	// 7. Package directories register the package itself through __init__.py.
	if _, ok := r.LookupModule("pkg"); !ok {
		t.Fatal("expected package pkg to be registered from pkg/__init__.py")
	}
	if _, ok := r.LookupModule("pkg.sub"); !ok {
		t.Fatal("expected package pkg.sub to be registered")
	}

	// 8. LookupModule returns the absolute path of the defining file.
	path, ok := r.LookupModule("pkg.util")
	if !ok || path != filepath.Join(root, "pkg", "util.py") {
		t.Fatalf("LookupModule(pkg.util) = (%q, %v), want %s", path, ok, filepath.Join(root, "pkg", "util.py"))
	}

	// 9. Skipped directories are not indexed.
	for _, skipped := range []string{
		"pkg.__pycache__.cached",
		".git.hooks.legacy",
		"node_modules.vendor_lib",
	} {
		if _, ok := r.LookupModule(skipped); ok {
			t.Fatalf("module %q must not be indexed", skipped)
		}
	}

	// 10. FQN composition.
	if fqn := r.FQN("pkg.util", "helper"); fqn != "pkg.util.helper" {
		t.Fatalf("FQN: expected pkg.util.helper, got %q", fqn)
	}
}

// ---------------------------------------------------------------------------
// Layer 1 + Layer 3: CPGBuilder
// ---------------------------------------------------------------------------

const builderCFGSnippet = `import os
import requests

def handle(url):
    x = os.environ["API_KEY"]
    if x:
        y = x.strip()
    else:
        y = "default"
    for i in range(3):
        sink(x)
    return y
`

func TestBuilder_CFG_DFG(t *testing.T) {
	const file = "<stdin>"
	g := NewCodePropertyGraph()
	b := NewCPGBuilder(NewSymbolResolver(""))
	if err := b.BuildFile(g, file, builderExtract(t, builderCFGSnippet)); err != nil {
		t.Fatalf("BuildFile failed: %v", err)
	}

	// --- Layer 1: node modelling -------------------------------------------
	modNode := builderNodeAt(t, g, file, 1, AST_MODULE)
	funcDef := builderNodeAt(t, g, file, 4, AST_FUNC_DEF)
	if funcDef.SymbolName != "handle" {
		t.Fatalf("expected function symbol handle, got %q", funcDef.SymbolName)
	}
	if funcDef.EnclosingScope != "" {
		t.Fatalf("top-level function must have no enclosing scope, got %q", funcDef.EnclosingScope)
	}

	param := builderNodeAt(t, g, file, 4, AST_PARAM)
	if param.SymbolName != "url" {
		t.Fatalf("expected parameter url, got %q", param.SymbolName)
	}
	if param.ScopeID != funcDef.NodeID {
		t.Fatalf("parameter must belong to the function scope %s, got %s", funcDef.NodeID, param.ScopeID)
	}
	if !builderHasEdge(g, funcDef.NodeID, param.NodeID, AST_CHILD) {
		t.Fatal("expected AST_CHILD edge from function definition to its parameter")
	}

	assign5 := builderNodeAt(t, g, file, 5, AST_ASSIGN)
	if assign5.SymbolName != "x" {
		t.Fatalf("expected assignment symbol x, got %q", assign5.SymbolName)
	}
	if assign5.EnclosingScope != "handle" {
		t.Fatalf("expected enclosing scope handle, got %q", assign5.EnclosingScope)
	}
	if assign5.ScopeID != funcDef.NodeID {
		t.Fatalf("expected scope id %s, got %s", funcDef.NodeID, assign5.ScopeID)
	}
	// The node ID convention is file:line:col:type.
	wantID := fmt.Sprintf("%s:%d:%d:%s", file, 5, 4, AST_ASSIGN)
	if assign5.NodeID != wantID {
		t.Fatalf("expected node id %q, got %q", wantID, assign5.NodeID)
	}
	if assign5.AST == nil || assign5.AST.Type != "Assign" {
		t.Fatalf("expected the raw AST node to be retained, got %+v", assign5.AST)
	}
	if assign5.CodeStr == "" {
		t.Fatal("expected a derived CodeStr for the assignment")
	}
	if !builderHasEdge(g, modNode.NodeID, funcDef.NodeID, AST_CHILD) {
		t.Fatal("expected AST_CHILD edge from module to the function definition")
	}
	if !builderHasEdge(g, funcDef.NodeID, assign5.NodeID, AST_CHILD) {
		t.Fatal("expected AST_CHILD edge from function definition to its body statement")
	}

	ifNode := builderNodeAt(t, g, file, 6, AST_IF)
	forNode := builderNodeAt(t, g, file, 10, AST_FOR)
	assign7 := builderNodeAt(t, g, file, 7, AST_ASSIGN)
	assign9 := builderNodeAt(t, g, file, 9, AST_ASSIGN)
	call11 := builderNodeAt(t, g, file, 11, AST_CALL)
	ret12 := builderNodeAt(t, g, file, 12, AST_RETURN)

	// --- Layer 3: CFG ------------------------------------------------------
	// Sequential statements.
	if !builderHasEdge(g, assign5.NodeID, ifNode.NodeID, CFG_NEXT) {
		t.Fatal("expected CFG_NEXT edge from the assignment to the following if statement")
	}
	// Branching.
	if !builderHasEdge(g, ifNode.NodeID, assign7.NodeID, CFG_BRANCH_TRUE) {
		t.Fatal("expected CFG_BRANCH_TRUE edge into the if body")
	}
	if !builderHasEdge(g, ifNode.NodeID, assign9.NodeID, CFG_BRANCH_FALSE) {
		t.Fatal("expected CFG_BRANCH_FALSE edge into the else body")
	}
	if builderHasEdge(g, ifNode.NodeID, forNode.NodeID, CFG_BRANCH_FALSE) {
		t.Fatal("CFG_BRANCH_FALSE must target the else body, not the statement after the if")
	}
	// Loop exit.
	if !builderHasEdge(g, forNode.NodeID, ret12.NodeID, CFG_LOOP_EXIT) {
		t.Fatal("expected CFG_LOOP_EXIT edge from the for loop to the statement after it")
	}

	// --- Layer 3: DFG ------------------------------------------------------
	// "x = ..." reaches the later load of "x" in "sink(x)".
	if !builderHasEdge(g, assign5.NodeID, call11.NodeID, DFG_DEF_USE) {
		t.Fatalf("expected DFG_DEF_USE edge from %s to %s", assign5.NodeID, call11.NodeID)
	}
	if !builderHasEdge(g, assign5.NodeID, ifNode.NodeID, DFG_DEF_USE) {
		t.Fatal("expected DFG_DEF_USE edge from the assignment into the if condition")
	}
	// The definition must not flow backwards to an earlier statement, and it
	// must not cross the function boundary.
	for _, e := range g.GetPredecessors(assign5.NodeID) {
		if e.EdgeType == DFG_DEF_USE {
			t.Fatalf("unexpected incoming DFG_DEF_USE edge on the assignment: %+v", e)
		}
	}
	for _, n := range builderEdgeTargets(g, assign5.NodeID, DFG_DEF_USE) {
		if n.ScopeID != funcDef.NodeID {
			t.Fatalf("DFG edge crossed a scope boundary into %s", n.NodeID)
		}
	}
}

func TestBuilder_CFG_IfWithoutElse(t *testing.T) {
	const file = "<stdin>"
	code := `def check(flag):
    if flag:
        sink()
    done()
`
	g := NewCodePropertyGraph()
	b := NewCPGBuilder(nil)
	if err := b.BuildFile(g, file, builderExtract(t, code)); err != nil {
		t.Fatalf("BuildFile failed: %v", err)
	}

	ifNode := builderNodeAt(t, g, file, 2, AST_IF)
	sinkStmt := builderNodeAt(t, g, file, 3, AST_EXPR)
	doneStmt := builderNodeAt(t, g, file, 4, AST_EXPR)

	if !builderHasEdge(g, ifNode.NodeID, sinkStmt.NodeID, CFG_BRANCH_TRUE) {
		t.Fatal("expected CFG_BRANCH_TRUE edge into the if body")
	}
	// With no else branch the false edge falls through to the next statement.
	if !builderHasEdge(g, ifNode.NodeID, doneStmt.NodeID, CFG_BRANCH_FALSE) {
		t.Fatal("expected CFG_BRANCH_FALSE fallthrough to the statement after the if")
	}
	if !builderHasEdge(g, ifNode.NodeID, doneStmt.NodeID, CFG_NEXT) {
		t.Fatal("expected CFG_NEXT edge to the statement after the if")
	}
}

func TestBuilder_CFG_TryExcept(t *testing.T) {
	const file = "<stdin>"
	code := `def risky(path):
    try:
        data = open(path).read()
    except OSError:
        data = ""
    return data
`
	g := NewCodePropertyGraph()
	b := NewCPGBuilder(nil)
	if err := b.BuildFile(g, file, builderExtract(t, code)); err != nil {
		t.Fatalf("BuildFile failed: %v", err)
	}

	tryNode := builderNodeAt(t, g, file, 2, AST_TRY)
	handlerStmt := builderNodeAt(t, g, file, 5, AST_ASSIGN)
	retStmt := builderNodeAt(t, g, file, 6, AST_RETURN)

	if !builderHasEdge(g, tryNode.NodeID, handlerStmt.NodeID, CFG_EXCEPT) {
		t.Fatal("expected CFG_EXCEPT edge into the exception handler body")
	}
	if !builderHasEdge(g, tryNode.NodeID, retStmt.NodeID, CFG_NEXT) {
		t.Fatal("expected CFG_NEXT edge from the try statement to the next statement")
	}
}

const builderCallSnippet = `def helper(value):
    return value

def run(data):
    result = helper(data)
    return result
`

func TestBuilder_CallArgRet_SameFile(t *testing.T) {
	const file = "<stdin>"
	g := NewCodePropertyGraph()
	b := NewCPGBuilder(nil)
	if err := b.BuildFile(g, file, builderExtract(t, builderCallSnippet)); err != nil {
		t.Fatalf("BuildFile failed: %v", err)
	}

	callee := builderNodeAt(t, g, file, 1, AST_FUNC_DEF)
	param := builderNodeAt(t, g, file, 1, AST_PARAM)
	calleeRet := builderNodeAt(t, g, file, 2, AST_RETURN)
	call := builderNodeAt(t, g, file, 5, AST_CALL)
	if call.SymbolName != "helper" {
		t.Fatalf("expected call symbol helper, got %q", call.SymbolName)
	}

	// Call graph edge.
	if !builderHasEdge(g, call.NodeID, callee.NodeID, CALL) {
		t.Fatal("expected CALL edge from the call site to the callee")
	}
	// CALL_ARG: the argument node flows into the formal parameter.
	argSources := builderEdgeSources(g, param.NodeID, CALL_ARG)
	if len(argSources) != 1 {
		t.Fatalf("expected exactly one CALL_ARG edge into the parameter, got %d", len(argSources))
	}
	if argSources[0].AST == nil || argSources[0].AST.ID != "data" {
		t.Fatalf("expected the argument node to be the Name 'data', got %+v", argSources[0].AST)
	}
	if argSources[0].Line != 5 {
		t.Fatalf("expected the argument at line 5, got %d", argSources[0].Line)
	}
	// CALL_RET: the return inside the callee flows back to the call site.
	if !builderHasEdge(g, calleeRet.NodeID, call.NodeID, CALL_RET) {
		t.Fatal("expected CALL_RET edge from the callee return to the call site")
	}
	// The return of the caller must not be attributed to the callee.
	callerRet := builderNodeAt(t, g, file, 6, AST_RETURN)
	if builderHasEdge(g, callerRet.NodeID, call.NodeID, CALL_RET) {
		t.Fatal("caller return must not produce a CALL_RET edge")
	}
}

func TestBuilder_CallResolution_CrossFile(t *testing.T) {
	root := t.TempDir()
	builderWriteFile(t, root, "pkg/__init__.py", "")
	utilPath := builderWriteFile(t, root, "pkg/util.py", `def helper(value):
    return value

def transform(payload):
    return payload
`)
	builderWriteFile(t, root, "app/__init__.py", "")
	mainPath := builderWriteFile(t, root, "app/main.py", `from pkg import util

def helper(value):
    return value

def run(data):
    a = helper(data)
    b = util.transform(data)
    return a
`)

	resolver := NewSymbolResolver(root)
	if err := resolver.Scan(); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if _, ok := resolver.LookupModule("pkg.util"); !ok {
		t.Fatal("expected pkg.util to be registered")
	}

	g := NewCodePropertyGraph()
	b := NewCPGBuilder(resolver)
	if err := b.Build(g, []string{mainPath, utilPath}); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Same-file preference: `helper` is defined in both files, the call in
	// app/main.py must bind to the local definition.
	callLocal := builderNodeAt(t, g, mainPath, 7, AST_CALL)
	localCallee := builderNodeAt(t, g, mainPath, 3, AST_FUNC_DEF)
	utilCallee := builderNodeAt(t, g, utilPath, 1, AST_FUNC_DEF)
	utilCalleeRet := builderNodeAt(t, g, utilPath, 2, AST_RETURN)
	if !builderHasEdge(g, callLocal.NodeID, localCallee.NodeID, CALL) {
		t.Fatal("expected the local helper to be preferred over the imported one")
	}
	if builderHasEdge(g, callLocal.NodeID, utilCallee.NodeID, CALL) {
		t.Fatal("the local call must not bind to the definition from another file")
	}
	if builderHasEdge(g, utilCalleeRet.NodeID, callLocal.NodeID, CALL_RET) {
		t.Fatal("the imported definition must not produce a CALL_RET edge for the local call")
	}

	// Cross-file resolution through the resolver: `util.transform(...)` binds
	// to the function defined in pkg/util.py.
	callRemote := builderNodeAt(t, g, mainPath, 8, AST_CALL)
	remoteCallee := builderNodeAt(t, g, utilPath, 4, AST_FUNC_DEF)
	remoteParam := builderNodeAt(t, g, utilPath, 4, AST_PARAM)
	if remoteParam.SymbolName != "payload" {
		t.Fatalf("expected parameter payload, got %q", remoteParam.SymbolName)
	}
	if !builderHasEdge(g, callRemote.NodeID, remoteCallee.NodeID, CALL) {
		t.Fatal("expected CALL edge to the function resolved through the import alias")
	}
	argSources := builderEdgeSources(g, remoteParam.NodeID, CALL_ARG)
	if len(argSources) != 1 {
		t.Fatalf("expected one cross-file CALL_ARG edge, got %d", len(argSources))
	}
	if argSources[0].Line != 8 || argSources[0].AST == nil || argSources[0].AST.ID != "data" {
		t.Fatalf("unexpected cross-file argument node: line %d ast %+v", argSources[0].Line, argSources[0].AST)
	}
	remoteRet := builderNodeAt(t, g, utilPath, 5, AST_RETURN)
	if !builderHasEdge(g, remoteRet.NodeID, callRemote.NodeID, CALL_RET) {
		t.Fatal("expected cross-file CALL_RET edge from the resolved callee")
	}
}

func TestBuilder_MultiTargetAssignment(t *testing.T) {
	const file = "<stdin>"
	code := `def pair(a):
    x = y = a
    return x + y
`
	g := NewCodePropertyGraph()
	b := NewCPGBuilder(nil)
	if err := b.BuildFile(g, file, builderExtract(t, code)); err != nil {
		t.Fatalf("BuildFile failed: %v", err)
	}

	assign := builderNodeAt(t, g, file, 2, AST_ASSIGN)
	retStmt := builderNodeAt(t, g, file, 3, AST_RETURN)
	// One statement yields one AST_ASSIGN node; the first simple target names it.
	if assign.SymbolName != "x" {
		t.Fatalf("expected assignment symbol x, got %q", assign.SymbolName)
	}
	// Every simple target name of the statement participates in the data flow.
	for _, name := range []string{"x", "y"} {
		found := false
		for _, e := range g.GetSuccessors(assign.NodeID) {
			if e.EdgeType != DFG_DEF_USE || e.TargetID != retStmt.NodeID {
				continue
			}
			if variable, _ := e.Metadata["var"].(string); variable == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a DFG_DEF_USE edge for %q from the assignment to the return", name)
		}
	}
}

func TestBuilder_NodeTypesAndImports(t *testing.T) {
	const file = "<stdin>"
	code := `import os
from http import client as http_client

class Service:
    def send(self, data):
        return data
`
	g := NewCodePropertyGraph()
	b := NewCPGBuilder(nil)
	if err := b.BuildFile(g, file, builderExtract(t, code)); err != nil {
		t.Fatalf("BuildFile failed: %v", err)
	}

	if nodes := g.FindNodesByType(AST_IMPORT); len(nodes) != 2 {
		t.Fatalf("expected 2 import nodes, got %d", len(nodes))
	}
	classNode := builderNodeAt(t, g, file, 4, AST_CLASS_DEF)
	if classNode.SymbolName != "Service" {
		t.Fatalf("expected class symbol Service, got %q", classNode.SymbolName)
	}
	method := builderNodeAt(t, g, file, 5, AST_FUNC_DEF)
	if method.EnclosingScope != "Service" {
		t.Fatalf("expected the method to be enclosed by the class, got %q", method.EnclosingScope)
	}
	if method.ScopeID != classNode.NodeID {
		t.Fatalf("expected the method to live in the class scope, got %q", method.ScopeID)
	}
	// The self parameter is materialised as an AST_PARAM node in the method scope.
	nodes := g.FindNodesAtLine(file, 5)
	var params []*CPGNode
	for _, n := range nodes {
		if n.NodeType == AST_PARAM {
			params = append(params, n)
		}
	}
	if len(params) != 2 {
		t.Fatalf("expected 2 parameter nodes, got %d", len(params))
	}
	if params[0].SymbolName != "self" || params[1].SymbolName != "data" {
		t.Fatalf("unexpected parameter names: %q, %q", params[0].SymbolName, params[1].SymbolName)
	}
	if params[0].NodeID == params[1].NodeID {
		t.Fatal("parameter nodes must have distinct ids")
	}
}
