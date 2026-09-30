package cpg

import (
	"context"
	"os"
	"strings"
)

// DefaultScopeFallbackWindow is the physical line radius used when AST parsing is unavailable.
const DefaultScopeFallbackWindow = 7

// ASTScopeSlicer extracts the innermost enclosing scope (function or class body)
// surrounding a target line, degrading to a physical line window when the source
// cannot be parsed.
type ASTScopeSlicer struct {
	FallbackWindow int
}

// NewASTScopeSlicer returns a slicer using DefaultScopeFallbackWindow.
func NewASTScopeSlicer() *ASTScopeSlicer {
	return &ASTScopeSlicer{FallbackWindow: DefaultScopeFallbackWindow}
}

// ExtractEnclosingScope parses sourceCode and returns the source text of the
// innermost FunctionDef / AsyncFunctionDef / ClassDef whose body contains
// targetLine (1-based). It never returns an error: on parse failure, a missing
// enclosing scope, or an out-of-range target line it falls back to the physical
// window and reports fallback=true.
func (s *ASTScopeSlicer) ExtractEnclosingScope(ctx context.Context, sourceCode string, targetLine int) (snippet string, startLine int, fallback bool) {
	window := s.scopeSlicerWindow()
	lines := scopeSlicerSplitLines(sourceCode)

	// Only a 1-based in-range target line can be resolved against the AST.
	if targetLine >= 1 {
		if module, err := ExtractASTSource(ctx, sourceCode); err == nil && module != nil {
			node := scopeSlicerFindInnermost(module, targetLine)
			if node != nil {
				if snippet, startLine, ok := scopeSlicerNodeRegion(lines, node); ok {
					return snippet, startLine, false
				}
			}
		}
	}

	return scopeSlicerFallbackWindow(lines, targetLine, window)
}

// ExtractEnclosingScopeFromFile reads filePath and applies ExtractEnclosingScope.
// A read error also takes the fallback path.
func (s *ASTScopeSlicer) ExtractEnclosingScopeFromFile(ctx context.Context, filePath string, targetLine int) (snippet string, startLine int, fallback bool) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		// The source is unreadable, so there is no region to report.
		return "", 1, true
	}
	return s.ExtractEnclosingScope(ctx, string(data), targetLine)
}

// scopeSlicerWindow resolves the effective physical window, treating a
// non-positive configured value (including a nil receiver) as the default.
func (s *ASTScopeSlicer) scopeSlicerWindow() int {
	if s == nil || s.FallbackWindow <= 0 {
		return DefaultScopeFallbackWindow
	}
	return s.FallbackWindow
}

// scopeSlicerSplitLines splits source into lines, dropping the single trailing
// empty element produced by a final newline so numbering matches editors.
func scopeSlicerSplitLines(source string) []string {
	lines := strings.Split(source, "\n")
	if len(lines) > 1 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// scopeSlicerFindInnermost returns the smallest enclosing scope node whose line
// range contains targetLine, preferring the more deeply nested node on a tie.
func scopeSlicerFindInnermost(module *ASTModule, targetLine int) *ASTNode {
	if module == nil {
		return nil
	}

	var best *ASTNode
	for _, root := range module.Body {
		root.Walk(func(node *ASTNode) bool {
			if !scopeSlicerIsScopeNode(node) {
				return true
			}
			// Nodes without end_lineno cannot be matched: a zero value is
			// missing information, not a zero-length range.
			if node.EndLineno <= 0 || node.Lineno < 1 {
				return true
			}
			if targetLine < node.Lineno || targetLine > node.EndLineno {
				return true
			}
			if best == nil || scopeSlicerIsMoreSpecific(node, best) {
				best = node
			}
			return true
		})
	}
	return best
}

// scopeSlicerIsScopeNode reports whether the node opens a closure scope.
func scopeSlicerIsScopeNode(node *ASTNode) bool {
	if node == nil {
		return false
	}
	switch node.Type {
	case "FunctionDef", "AsyncFunctionDef", "ClassDef":
		return true
	default:
		return false
	}
}

// scopeSlicerIsMoreSpecific reports whether candidate is a better enclosing scope
// than current: the narrower line span wins, and an equal span is broken in favor
// of the later declaration, which is the deeper node.
func scopeSlicerIsMoreSpecific(candidate, current *ASTNode) bool {
	candidateSpan := candidate.EndLineno - candidate.Lineno
	currentSpan := current.EndLineno - current.Lineno
	if candidateSpan != currentSpan {
		return candidateSpan < currentSpan
	}
	return candidate.Lineno > current.Lineno
}

// scopeSlicerNodeRegion renders the complete [Lineno, EndLineno] region of node
// verbatim, reporting ok=false when the range lies outside the source lines.
func scopeSlicerNodeRegion(lines []string, node *ASTNode) (snippet string, startLine int, ok bool) {
	if node == nil || node.Lineno < 1 || node.Lineno > len(lines) {
		return "", 0, false
	}
	start := node.Lineno
	end := node.EndLineno
	if end > len(lines) {
		end = len(lines)
	}
	if end < start {
		return "", 0, false
	}
	return strings.Join(lines[start-1:end], "\n"), start, true
}

// scopeSlicerFallbackWindow returns the clamped physical window around targetLine.
func scopeSlicerFallbackWindow(lines []string, targetLine, window int) (snippet string, startLine int, fallback bool) {
	if len(lines) == 0 {
		return "", 1, true
	}

	start := targetLine - window
	end := targetLine + window
	if start < 1 {
		start = 1
	}
	if start > len(lines) {
		start = len(lines)
	}
	if end < start {
		end = start
	}
	if end > len(lines) {
		end = len(lines)
	}

	return strings.Join(lines[start-1:end], "\n"), start, true
}
