package codeaudit

import (
	"context"
	"path/filepath"
	"strings"

	"taa/internal/codeaudit/cpg"
)

// semanticContextMaxSpan bounds how many lines of the enclosing scope are taken
// on each side of the flagged line.
//
// The scope slice is the whole function, and a function is not bounded by
// anything: an unbounded slice would put a several-hundred-line definition into
// the file-level prompt for every finding inside it. The cap is set well above
// the length of a typical Python function, so the source-to-sink distance that
// the physical window used to cut through is preserved while the prompt stays
// bounded. Measured on the audit corpus, fewer than one function in fifty
// exceeds it.
const semanticContextMaxSpan = 40

// applyScopeContext replaces the physical context window of every finding in one
// file with the semantically enclosing scope.
//
// The physical window is a fixed three lines on each side of the flagged line,
// which is what the context was before this function existed. It cuts a
// function in half: a taint source ten lines above a subprocess call is outside
// the window, so the LLM is asked to judge a sink whose input it cannot see. The
// AST slice instead hands over the enclosing definition, so the control flow and
// the closure the finding lives in are both present.
//
// Both engines call this, and they must: the non-inferiority measurement rests
// on the Tier 2 prompt being the same text whichever engine produced the
// finding (see TestSemgrepEngineContextsMatchTheRegexArm). A semantic context
// applied to one arm only would make the arms differ by something that is not
// the matcher, which is exactly the difference the measurement must be free of.
//
// The AST slice covers Python, which is the language the CPG layer parses. A
// file in any other language keeps the physical window: the parser would fail on
// it and the fallback would return the same lines, so the parse is skipped
// rather than paid for nothing. A finding whose scope resolution fails for any
// other reason - a syntax error, module-level code, an unusable region - also
// keeps the physical window.
func applyScopeContext(findings []Finding, source string) {
	if len(findings) == 0 || !isPythonSource(findings[0].File) {
		return
	}

	scope := cpg.NewFileScopeExtractor(context.Background(), source)

	for i := range findings {
		before, after := scopeContext(scope, findings[i].Line)
		if before == "" && after == "" {
			// A scope that yields nothing on either side - a one-line
			// definition, or a region the extractor could not resolve - leaves
			// the physical window in place. A finding with no context at all
			// would send the LLM a call it cannot evaluate.
			continue
		}
		findings[i].ContextBefore = before
		findings[i].ContextAfter = after
	}
}

// scopeContext returns the lines of the enclosing scope above and below
// targetLine, each side capped at semanticContextMaxSpan.
//
// The split is taken from the same scope resolution the CPG engine uses, so the
// text the LLM reads and the text the taint trajectory is built from describe
// the same region.
//
// Both sides are empty when the scope cannot be resolved. Empty means "no
// semantic slice", and the caller leaves the physical window it already built in
// place; this function deliberately does not reconstruct that window, so its
// geometry is defined once, where the window is built, and not again here.
func scopeContext(scope *cpg.FileScopeExtractor, targetLine int) (before, after string) {
	if scope == nil {
		return "", ""
	}

	snippet, startLine, fallback := scope.EnclosingScope(targetLine)
	if fallback || snippet == "" {
		return "", ""
	}

	scopeLines := strings.Split(snippet, "\n")
	offset := targetLine - startLine
	if offset < 0 || offset >= len(scopeLines) {
		// The resolved region does not contain the flagged line, which cannot
		// happen for a region derived from it. Treated as a failed resolution
		// rather than trusted, because indexing either side on it would panic.
		return "", ""
	}

	return semanticSide(scopeLines[:offset], true), semanticSide(scopeLines[offset+1:], false)
}

// semanticSide renders one side of a split scope, keeping the lines closest to
// the split when the side is longer than the cap.
func semanticSide(scopeLines []string, tail bool) string {
	if len(scopeLines) == 0 {
		return ""
	}
	if len(scopeLines) > semanticContextMaxSpan {
		if tail {
			scopeLines = scopeLines[len(scopeLines)-semanticContextMaxSpan:]
		} else {
			scopeLines = scopeLines[:semanticContextMaxSpan]
		}
	}
	return strings.TrimSpace(strings.Join(scopeLines, "\n"))
}

// isPythonSource reports whether path names a file the AST layer can parse.
func isPythonSource(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".py")
}
