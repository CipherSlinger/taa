package codeaudit

// Engine identity strings. They are written into Report.Engine and Name()
// returns them, so that a report can prove which engine produced it rather than
// leaving the reader to infer it from a mode name.
const (
	EngineNameRegex   = "regex"
	EngineNameSemgrep = "semgrep"
)

// StaticEngine is the Tier 1 static scanning boundary. It exists so that
// "which engine scans the code" is one decision in one place, and so that
// swapping the engine is a change to the implementation behind this interface
// rather than a change to its callers.
//
// Two implementations are expected: regexEngine, wrapping the existing Scanner,
// and a Semgrep CLI adapter. Callers must not depend on anything beyond these
// three methods — in particular, nothing may type-assert back to *Scanner, or
// the abstraction stops being a boundary.
type StaticEngine interface {
	// ScanDirectory walks dir and returns a report whose Passed field is keyed
	// on the static severities alone.
	ScanDirectory(dir string) (*Report, error)

	// ScanDirectoryWithLines is ScanDirectory plus a per-file line count, which
	// the file-level LLM prompt needs.
	ScanDirectoryWithLines(dir string) (*Report, map[string]int, error)

	// Name reports the engine identity, for Report.Engine.
	Name() string
}

// regexEngine adapts *Scanner to StaticEngine.
//
// It is a pass-through by design and holds no state of its own: every method
// delegates to the scanner and returns its result unmodified. The scan decision
// itself, including Report.Passed, stays where it already lives, in
// Scanner.buildReport.
type regexEngine struct {
	scanner *Scanner
}

// ScanDirectory delegates to the wrapped scanner.
func (e regexEngine) ScanDirectory(dir string) (*Report, error) {
	return e.scanner.ScanDirectory(dir)
}

// ScanDirectoryWithLines delegates to the wrapped scanner.
func (e regexEngine) ScanDirectoryWithLines(dir string) (*Report, map[string]int, error) {
	return e.scanner.ScanDirectoryWithLines(dir)
}

// Name reports the regex engine identity.
func (e regexEngine) Name() string { return EngineNameRegex }

// DefaultEngine returns the Tier 1 engine production uses.
//
// This is the single selection point for the engine. It currently returns the
// regex baseline unconditionally. When the Semgrep adapter lands it is chosen
// here, and this function is the only place that has to change — but the
// default stays regex until the holdout evidence passes, so this returning the
// regex engine is a decision, not a placeholder.
func DefaultEngine() StaticEngine {
	return regexEngine{scanner: DefaultScanner()}
}
