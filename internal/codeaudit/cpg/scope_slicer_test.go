package cpg

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scopeSlicerRequirePython skips the calling test when python3 is unavailable,
// since the AST-backed slicing path shells out to the interpreter.
func scopeSlicerRequirePython(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available; skipping AST-dependent scope slicer test")
	}
}

// scopeSlicerSourceLines splits source the same way the slicer does, so tests can
// derive expected snippets by line index.
func scopeSlicerSourceLines(source string) []string {
	source = strings.TrimSuffix(source, "\n")
	return strings.Split(source, "\n")
}

const scopeSlicerNestedSource = `import os


def outer():
    x = 1

    def inner():
        y = 2
        return y

    return inner()
`

func TestScopeSlicer_ExtractsEnclosingFunction(t *testing.T) {
	scopeSlicerRequirePython(t)

	src := scopeSlicerNestedSource
	lines := scopeSlicerSourceLines(src)
	if len(lines) < 11 {
		t.Fatalf("fixture has %d lines, want at least 11", len(lines))
	}
	// inner() is declared on line 7 and ends on line 9.
	innerStart, innerEnd := 7, 9
	targetLine := innerStart + 1

	slicer := NewASTScopeSlicer()
	snippet, startLine, fallback := slicer.ExtractEnclosingScope(context.Background(), src, targetLine)

	if fallback {
		t.Fatalf("ExtractEnclosingScope reported fallback=true for a nested function target")
	}
	if startLine != innerStart {
		t.Errorf("startLine = %d, want %d", startLine, innerStart)
	}
	want := strings.Join(lines[innerStart-1:innerEnd], "\n")
	if snippet != want {
		t.Errorf("snippet mismatch\n got: %q\nwant: %q", snippet, want)
	}
	if strings.Contains(snippet, "def outer") {
		t.Errorf("snippet contains the outer function, want innermost closure only: %q", snippet)
	}
}

const scopeSlicerClassSource = `class Service:
    name = "svc"

    def handle(self):
        token = "abc"
        return token

    def other(self):
        return 1
`

func TestScopeSlicer_ExtractsClassScope(t *testing.T) {
	scopeSlicerRequirePython(t)

	src := scopeSlicerClassSource
	lines := scopeSlicerSourceLines(src)
	if len(lines) < 9 {
		t.Fatalf("fixture has %d lines, want at least 9", len(lines))
	}
	slicer := NewASTScopeSlicer()

	// A target inside the method body must resolve to the method, not the class.
	methodStart, methodEnd := 4, 6
	methodSnippet, methodStartLine, methodFallback := slicer.ExtractEnclosingScope(context.Background(), src, 5)
	if methodFallback {
		t.Fatalf("method target reported fallback=true")
	}
	if methodStartLine != methodStart {
		t.Errorf("method startLine = %d, want %d", methodStartLine, methodStart)
	}
	wantMethod := strings.Join(lines[methodStart-1:methodEnd], "\n")
	if methodSnippet != wantMethod {
		t.Errorf("method snippet mismatch\n got: %q\nwant: %q", methodSnippet, wantMethod)
	}

	// A target in the class body but outside any method must resolve to the class.
	classSnippet, classStartLine, classFallback := slicer.ExtractEnclosingScope(context.Background(), src, 2)
	if classFallback {
		t.Fatalf("class-body target reported fallback=true")
	}
	if classStartLine != 1 {
		t.Errorf("class startLine = %d, want 1", classStartLine)
	}
	wantClass := strings.Join(lines[0:9], "\n")
	if classSnippet != wantClass {
		t.Errorf("class snippet mismatch\n got: %q\nwant: %q", classSnippet, wantClass)
	}
	if !strings.Contains(classSnippet, "def other") {
		t.Errorf("class snippet should span the whole class body: %q", classSnippet)
	}
}

const scopeSlicerAsyncSource = `import asyncio


async def handler():
    data = await asyncio.sleep(0)
    return data
`

func TestScopeSlicer_AsyncFunction(t *testing.T) {
	scopeSlicerRequirePython(t)

	src := scopeSlicerAsyncSource
	lines := scopeSlicerSourceLines(src)
	if len(lines) < 6 {
		t.Fatalf("fixture has %d lines, want at least 6", len(lines))
	}

	slicer := NewASTScopeSlicer()
	snippet, startLine, fallback := slicer.ExtractEnclosingScope(context.Background(), src, 5)

	if fallback {
		t.Fatalf("ExtractEnclosingScope reported fallback=true for an async def target")
	}
	if startLine != 4 {
		t.Errorf("startLine = %d, want 4", startLine)
	}
	want := strings.Join(lines[3:6], "\n")
	if snippet != want {
		t.Errorf("snippet mismatch\n got: %q\nwant: %q", snippet, want)
	}
	if !strings.HasPrefix(snippet, "async def handler():") {
		t.Errorf("snippet should start at the async def line: %q", snippet)
	}
}

func TestScopeSlicer_FallsBackOnSyntaxError(t *testing.T) {
	scopeSlicerRequirePython(t)

	const src = "def broken(:\n  pass\n"

	slicer := NewASTScopeSlicer()
	snippet, startLine, fallback := slicer.ExtractEnclosingScope(context.Background(), src, 3)

	if !fallback {
		t.Fatalf("malformed source should take the fallback path")
	}
	if snippet == "" {
		t.Fatalf("fallback snippet must not be empty for non-empty source")
	}
	if startLine < 1 {
		t.Errorf("startLine = %d, want >= 1", startLine)
	}
	if !strings.Contains(snippet, "def broken(:") {
		t.Errorf("fallback window should cover the target region: %q", snippet)
	}
}

const scopeSlicerModuleLevelSource = `import os

CONFIG = {"a": 1}

def helper():
    return 1
`

func TestScopeSlicer_FallsBackAtModuleLevel(t *testing.T) {
	scopeSlicerRequirePython(t)

	src := scopeSlicerModuleLevelSource

	slicer := NewASTScopeSlicer()
	snippet, startLine, fallback := slicer.ExtractEnclosingScope(context.Background(), src, 3)

	if !fallback {
		t.Fatalf("module-level target should take the fallback path")
	}
	if snippet == "" {
		t.Fatalf("fallback snippet must not be empty for non-empty source")
	}
	if startLine < 1 {
		t.Errorf("startLine = %d, want >= 1", startLine)
	}
	if !strings.Contains(snippet, `CONFIG = {"a": 1}`) {
		t.Errorf("fallback window should include the target line: %q", snippet)
	}
}

func TestScopeSlicer_ClampsAtFileBoundaries(t *testing.T) {
	scopeSlicerRequirePython(t)

	const src = "import os\nimport sys\n\nVALUE = 1\n"
	lastLine := 4

	slicer := NewASTScopeSlicer()

	for _, targetLine := range []int{1, lastLine, 0, -5, 999} {
		snippet, startLine, fallback := slicer.ExtractEnclosingScope(context.Background(), src, targetLine)
		if snippet == "" {
			t.Errorf("targetLine %d: snippet is empty", targetLine)
		}
		if startLine < 1 {
			t.Errorf("targetLine %d: startLine = %d, want >= 1", targetLine, startLine)
		}
		if !fallback {
			t.Errorf("targetLine %d: expected fallback=true for a module-scope target", targetLine)
		}
	}
}

func TestScopeSlicer_ZeroFallbackWindowUsesDefault(t *testing.T) {
	scopeSlicerRequirePython(t)

	// A manually constructed slicer with a non-positive window must behave as
	// if DefaultScopeFallbackWindow had been configured.
	lines := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		lines = append(lines, "pass")
	}
	src := strings.Join(lines, "\n")

	slicer := &ASTScopeSlicer{}
	snippet, startLine, fallback := slicer.ExtractEnclosingScope(context.Background(), src, 10)
	if !fallback {
		t.Fatalf("expected fallback=true for a module-scope target")
	}
	wantStart := 10 - DefaultScopeFallbackWindow
	if startLine != wantStart {
		t.Errorf("startLine = %d, want %d (DefaultScopeFallbackWindow)", startLine, wantStart)
	}
	wantEnd := 10 + DefaultScopeFallbackWindow
	want := strings.Join(lines[wantStart-1:wantEnd], "\n")
	if snippet != want {
		t.Errorf("snippet = %q, want %q", snippet, want)
	}
}

func TestScopeSlicer_FromFile(t *testing.T) {
	scopeSlicerRequirePython(t)

	src := scopeSlicerNestedSource
	lines := scopeSlicerSourceLines(src)

	dir := t.TempDir()
	path := filepath.Join(dir, "sample.py")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	slicer := NewASTScopeSlicer()
	snippet, startLine, fallback := slicer.ExtractEnclosingScopeFromFile(context.Background(), path, 8)
	if fallback {
		t.Fatalf("ExtractEnclosingScopeFromFile reported fallback=true for a parsable file")
	}
	if startLine != 7 {
		t.Errorf("startLine = %d, want 7", startLine)
	}
	want := strings.Join(lines[6:9], "\n")
	if snippet != want {
		t.Errorf("snippet mismatch\n got: %q\nwant: %q", snippet, want)
	}

	// A missing file takes the fallback path without panicking.
	missing := filepath.Join(dir, "does-not-exist.py")
	_, missingStart, missingFallback := slicer.ExtractEnclosingScopeFromFile(context.Background(), missing, 8)
	if !missingFallback {
		t.Errorf("missing file should take the fallback path")
	}
	if missingStart < 1 {
		t.Errorf("missing file startLine = %d, want >= 1", missingStart)
	}
}
