package cpg

import (
	"context"
	"strings"
	"testing"
)

const scopeExtractorSample = `import os
import subprocess

API = "x"


def outer(payload):
    key = os.environ["API_KEY"]
    def inner():
        subprocess.run(payload, shell=True)
    return inner


class Service:
    def handle(self):
        return 1
`

// TestFileScopeExtractor_MatchesSlicer pins that the caching extractor answers
// exactly what the per-call slicer answers. The cache is an optimisation, and an
// optimisation that changes the answer is a defect.
func TestFileScopeExtractor_MatchesSlicer(t *testing.T) {
	slicer := NewASTScopeSlicer()
	extractor := NewFileScopeExtractor(context.Background(), scopeExtractorSample)

	lineCount := strings.Count(scopeExtractorSample, "\n")
	for line := 1; line <= lineCount; line++ {
		wantSnippet, wantStart, wantFallback := slicer.ExtractEnclosingScope(context.Background(), scopeExtractorSample, line)
		gotSnippet, gotStart, gotFallback := extractor.EnclosingScope(line)

		if gotSnippet != wantSnippet || gotStart != wantStart || gotFallback != wantFallback {
			t.Errorf("line %d: extractor = (%q, %d, %v), slicer = (%q, %d, %v)",
				line, gotSnippet, gotStart, gotFallback, wantSnippet, wantStart, wantFallback)
		}
	}
}

// TestFileScopeExtractor_InnermostScopeWins checks the semantic the cache must
// preserve: a line inside the nested function resolves to the nested function,
// not to the module-level one it is nested in.
func TestFileScopeExtractor_InnermostScopeWins(t *testing.T) {
	extractor := NewFileScopeExtractor(context.Background(), scopeExtractorSample)

	snippet, startLine, fallback := extractor.EnclosingScope(10)
	if fallback {
		t.Fatalf("line 10 sits inside inner(), so it must not fall back")
	}
	if startLine != 9 {
		t.Errorf("startLine = %d, want 9 (the def inner() line)", startLine)
	}
	if !strings.Contains(snippet, "def inner():") {
		t.Errorf("snippet should be inner()'s body, got %q", snippet)
	}
	if strings.Contains(snippet, "def outer(") {
		t.Errorf("snippet leaked the enclosing outer() definition: %q", snippet)
	}
}

// TestFileScopeExtractor_FallsBackOutsideAnyScope checks the degradation path:
// module-level code has no enclosing closure, so the physical window is used.
func TestFileScopeExtractor_FallsBackOutsideAnyScope(t *testing.T) {
	extractor := NewFileScopeExtractor(context.Background(), scopeExtractorSample)

	snippet, _, fallback := extractor.EnclosingScope(4)
	if !fallback {
		t.Fatalf("line 4 is module level, so it must fall back")
	}
	if snippet == "" {
		t.Fatalf("the fallback window must not be empty")
	}
}

// TestFileScopeExtractor_UnparsableSourceFallsBack checks that a syntax error
// degrades rather than failing the caller.
func TestFileScopeExtractor_UnparsableSourceFallsBack(t *testing.T) {
	extractor := NewFileScopeExtractor(context.Background(), "def broken(:\n    pass\n")

	if _, _, fallback := extractor.EnclosingScope(2); !fallback {
		t.Fatalf("unparsable source must take the fallback path")
	}
}

// TestFileScopeExtractor_LineAtBounds checks the accessor's range handling.
func TestFileScopeExtractor_LineAtBounds(t *testing.T) {
	extractor := NewFileScopeExtractor(context.Background(), "a\nb\nc\n")

	if got, ok := extractor.LineAt(2); !ok || got != "b" {
		t.Errorf("LineAt(2) = (%q, %v), want (\"b\", true)", got, ok)
	}
	if _, ok := extractor.LineAt(0); ok {
		t.Errorf("LineAt(0) must report ok=false")
	}
	if _, ok := extractor.LineAt(4); ok {
		t.Errorf("LineAt(4) is past the last line and must report ok=false")
	}
}
