package cpg

import (
	"context"
)

// FileScopeExtractor answers enclosing-scope queries for many lines of one file
// while parsing that file at most once.
//
// ASTScopeSlicer parses on every call, and parsing means starting a python3
// process. A scan routinely reports several findings in the same file - the
// reason a file-level context exists at all is that a taint source and its sink
// can sit in one module - so the per-call parse would be paid once per finding
// for identical input. This type pays it once: the line split and the parse are
// done in the constructor, and each query is an in-memory walk.
//
// The zero value is not usable; build one with NewFileScopeExtractor.
type FileScopeExtractor struct {
	fallbackWindow int
	lines          []string
	module         *ASTModule
}

// NewFileScopeExtractor splits and parses sourceCode once. A parse failure is
// not an error here: it is the condition that makes every query fall back to
// the physical window, which is the same degradation ASTScopeSlicer describes.
// The context bounds that single parse.
func NewFileScopeExtractor(ctx context.Context, sourceCode string) *FileScopeExtractor {
	e := &FileScopeExtractor{
		fallbackWindow: DefaultScopeFallbackWindow,
		lines:          scopeSlicerSplitLines(sourceCode),
	}
	if module, err := ExtractASTSource(ctx, sourceCode); err == nil {
		e.module = module
	}
	return e
}

// EnclosingScope returns the source text of the innermost
// FunctionDef / AsyncFunctionDef / ClassDef whose body contains targetLine
// (1-based), and the 1-based line number the snippet starts at. When the file
// could not be parsed, targetLine lies outside every scope, or the resolved
// region is unusable, it falls back to the physical window and reports
// fallback=true. It never returns an error.
func (e *FileScopeExtractor) EnclosingScope(targetLine int) (snippet string, startLine int, fallback bool) {
	if e == nil {
		return "", 1, true
	}

	if targetLine >= 1 && e.module != nil {
		if node := scopeSlicerFindInnermost(e.module, targetLine); node != nil {
			if snippet, startLine, ok := scopeSlicerNodeRegion(e.lines, node); ok {
				return snippet, startLine, false
			}
		}
	}

	return scopeSlicerFallbackWindow(e.lines, targetLine, e.fallbackWindow)
}
