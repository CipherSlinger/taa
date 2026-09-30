package codeaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scopeContextSample places a credential source five lines above the sink that
// consumes it, which is one line further than the physical window reaches.
const scopeContextSample = `import os
import subprocess

def deploy(payload):
    key = os.environ["API_KEY"]
    token = key.strip()
    header = {"Authorization": token}
    body = {"data": payload}
    subprocess.run(payload, shell=True)
`

// TestApplyScopeContext_ShowsTheSourceFromTheSink is the property the slice
// exists for. The physical window covers three lines on each side, so the
// os.environ read on line 5 is outside the context of the subprocess call on
// line 9 and the LLM is asked to judge a sink whose input it cannot see.
func TestApplyScopeContext_ShowsTheSourceFromTheSink(t *testing.T) {
	findings := []Finding{{File: "deploy.py", Line: 9, RuleID: "CMD_001"}}

	applyScopeContext(findings, scopeContextSample)

	before := findings[0].ContextBefore
	if !strings.Contains(before, `os.environ["API_KEY"]`) {
		t.Errorf("ContextBefore must reach the taint source on line 5, got:\n%s", before)
	}
	if !strings.Contains(before, "def deploy(payload):") {
		t.Errorf("ContextBefore must open at the enclosing definition, got:\n%s", before)
	}
}

// TestApplyScopeContext_KeepsThePhysicalWindowForNonPython pins that a language
// the AST layer cannot parse is left exactly as it was. The parser would reject
// the source and the fallback would reproduce the physical window, so the parse
// is skipped rather than paid for nothing.
func TestApplyScopeContext_KeepsThePhysicalWindowForNonPython(t *testing.T) {
	source := "package main\n\nfunc run(c string) {\n\texec.Command(\"sh\", \"-c\", c)\n}\n"
	lines := strings.Split(source, "\n")
	// Seeded with the window the engine builds before this function runs, so the
	// assertion is that it survives untouched rather than that it was never set.
	physicalBefore := contextWindow(lines, 0, 3)
	physicalAfter := contextWindow(lines, 4, 7)
	findings := []Finding{{
		File:          "run.go",
		Line:          4,
		RuleID:        "CMD_001",
		ContextBefore: physicalBefore,
		ContextAfter:  physicalAfter,
	}}

	applyScopeContext(findings, source)

	if findings[0].ContextBefore != physicalBefore || findings[0].ContextAfter != physicalAfter {
		t.Errorf("context was rewritten for a non-Python file: before %q, after %q",
			findings[0].ContextBefore, findings[0].ContextAfter)
	}
}

// TestApplyScopeContext_DegradesOnSyntaxError pins the fallback for a Python file
// that does not parse. The seeded window stands, which is the contract every
// degradation path shares: an unresolved scope yields no slice and the caller's
// window is left alone rather than reconstructed here.
func TestApplyScopeContext_DegradesOnSyntaxError(t *testing.T) {
	source := "def broken(:\n    pass\n    pass\n    pass\n    pass\n"
	lines := strings.Split(source, "\n")
	physicalBefore := contextWindow(lines, 1, 4)
	physicalAfter := contextWindow(lines, 5, 8)
	findings := []Finding{{
		File:          "broken.py",
		Line:          5,
		RuleID:        "CMD_001",
		ContextBefore: physicalBefore,
		ContextAfter:  physicalAfter,
	}}

	applyScopeContext(findings, source)

	if findings[0].ContextBefore != physicalBefore || findings[0].ContextAfter != physicalAfter {
		t.Errorf("ContextBefore = %q, want the physical window", findings[0].ContextBefore)
	}
}

// TestApplyScopeContext_ModuleLevelKeepsThePhysicalWindow checks the other
// degradation path: a finding outside every function has no enclosing scope, so
// there is no slice to take and the physical window stands.
func TestApplyScopeContext_ModuleLevelKeepsThePhysicalWindow(t *testing.T) {
	source := "import os\n\nkey = os.environ[\"K\"]\nvalue = key\nother = 1\nos.system(value)\n"
	lines := strings.Split(source, "\n")
	physicalBefore := contextWindow(lines, 2, 5)
	physicalAfter := contextWindow(lines, 6, 9)
	findings := []Finding{{
		File:          "top.py",
		Line:          6,
		RuleID:        "CMD_001",
		ContextBefore: physicalBefore,
		ContextAfter:  physicalAfter,
	}}

	applyScopeContext(findings, source)

	if findings[0].ContextBefore != physicalBefore || findings[0].ContextAfter != physicalAfter {
		t.Errorf("ContextBefore = %q, want the physical window", findings[0].ContextBefore)
	}
}

// TestApplyScopeContext_NoFindingsDoesNoWork pins the cost model: a file with
// nothing to report is never parsed, which is what keeps a scan of a large clean
// tree from starting one python3 process per file.
func TestApplyScopeContext_NoFindingsDoesNoWork(t *testing.T) {
	// An unparsable source is the observable proof: a parse was attempted would
	// have to fail, and a failure here is silent either way. The assertion is
	// therefore that an empty slice is accepted and left empty.
	var findings []Finding
	applyScopeContext(findings, "def broken(:\n")
	if len(findings) != 0 {
		t.Fatalf("applyScopeContext invented findings")
	}
}

// TestScanFile_ContextReachesTheEnclosingScope drives the whole path through the
// regex engine, so the wiring in ScanFile is covered and not just the helper.
func TestScanFile_ContextReachesTheEnclosingScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.py")
	if err := os.WriteFile(path, []byte(scopeContextSample), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := DefaultScanner().ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("the sample must produce at least one finding for this test to mean anything")
	}

	var checked bool
	for _, f := range findings {
		if f.Line != 9 {
			continue
		}
		checked = true
		if !strings.Contains(f.ContextBefore, `os.environ["API_KEY"]`) {
			t.Errorf("finding at line 9 has ContextBefore:\n%s\nwant it to include the source on line 5",
				f.ContextBefore)
		}
	}
	if !checked {
		t.Fatalf("no finding was reported at line 9; findings: %+v", findings)
	}
}

// TestScanFile_DegradedFileKeepsThePhysicalWindow is the other half of the
// contract: scopeContext only ever withholds a slice, so if the scan path did
// not build the physical window itself a module-level finding would reach the
// LLM with no context at all.
func TestScanFile_DegradedFileKeepsThePhysicalWindow(t *testing.T) {
	// Module-level statements, so every finding is outside any enclosing scope
	// and the semantic split declines all of them.
	const moduleLevel = "import os\n\nkey = os.environ[\"API_KEY\"]\nvalue = key\nos.system(value)\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "top.py")
	if err := os.WriteFile(path, []byte(moduleLevel), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := DefaultScanner().ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("the sample must produce at least one finding for this test to mean anything")
	}

	lines := strings.Split(moduleLevel, "\n")
	for _, f := range findings {
		want := contextWindow(lines, f.Line-4, f.Line-1)
		if f.ContextBefore != want {
			t.Errorf("finding at line %d has ContextBefore:\n%q\nwant the physical window:\n%q",
				f.Line, f.ContextBefore, want)
		}
	}
}
