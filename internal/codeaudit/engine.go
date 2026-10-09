package codeaudit

import (
	"fmt"
	"os"
	"strings"
	"time"
)

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

// ScanDirectory delegates to the wrapped scanner and stamps the engine
// identity onto the result.
func (e regexEngine) ScanDirectory(dir string) (*Report, error) {
	report, err := e.scanner.ScanDirectory(dir)
	return e.stamp(report), err
}

// ScanDirectoryWithLines delegates to the wrapped scanner and stamps the engine
// identity onto the result.
func (e regexEngine) ScanDirectoryWithLines(dir string) (*Report, map[string]int, error) {
	report, lineCounts, err := e.scanner.ScanDirectoryWithLines(dir)
	return e.stamp(report), lineCounts, err
}

// stamp records what the regex engine knows about its own scan.
//
// ScanComplete is set explicitly rather than left to the zero value. The regex
// engine always completes: it is a synchronous in-memory match over lines it
// has already read, with no parser and no subprocess, so there is no partial
// state for it to be in. Leaving the field alone would report every regex scan
// as incomplete, and the fail-closed path keys on exactly this field.
//
// The remaining completeness fields stay at their zero values because they
// describe failure modes this engine does not have: it has no parser to fail,
// no subprocess to exit, and its extension filtering is configuration rather
// than a file it could not handle. Truncated is set by the scanner, which is
// the only code that knows whether the walk stopped at the finding cap.
func (e regexEngine) stamp(report *Report) *Report {
	if report == nil {
		return nil
	}
	report.Engine = EngineNameRegex
	report.ScanComplete = true
	return report
}

// Name reports the regex engine identity.
func (e regexEngine) Name() string { return EngineNameRegex }

// EngineConfig selects the Tier 1 engine and configures the engine selected.
type EngineConfig struct {
	// Name is one of the EngineName* constants.
	Name string
	// SemgrepRulesPath is the --config argument for the semgrep engine: a rules
	// file or a directory of them. Empty means DefaultSemgrepRulesPath. It is
	// ignored by the regex engine, which carries its rules in the binary.
	SemgrepRulesPath string
	// SemgrepTimeout bounds one semgrep scan. Zero means DefaultSemgrepTimeout.
	// Like the rules path it is a semgrep-only setting, and the regex engine
	// ignores it: a deadline for an in-memory match would suggest the baseline
	// arm is bounded by it too, which is a comparison the evidence does not make.
	SemgrepTimeout time.Duration
}

// engineNames lists the engines NewEngine accepts, for the rejection message.
var engineNames = []string{EngineNameRegex, EngineNameSemgrep}

// NewEngine resolves an engine selection into the engine itself.
//
// This is the only place a name becomes an engine. An unrecognized name is an
// error rather than a fallback to the regex baseline: a deployment that asked
// for an engine it did not get would otherwise scan with something other than
// what it configured, and the only trace would be a report field nobody reads.
//
// The rules path is checked here, where the deployment is configured, rather
// than left to the first scan. A missing rules file does not degrade the scan,
// it fails every import and has the model code deleted, which from the
// operator's side is indistinguishable from the scanner working and finding
// something. Failing at construction turns that into a startup error.
func NewEngine(cfg EngineConfig) (StaticEngine, error) {
	switch cfg.Name {
	case EngineNameRegex:
		return regexEngine{scanner: DefaultScanner()}, nil

	case EngineNameSemgrep:
		rulesPath := cfg.SemgrepRulesPath
		if rulesPath == "" {
			rulesPath = DefaultSemgrepRulesPath
		}
		// Stat rather than open: --config takes a file or a directory, and the
		// existence of the path is the whole question. Semgrep reports an
		// unreadable config the same way it reports a broken one, on stderr,
		// where the adapter turns it into a failed scan.
		if _, err := os.Stat(rulesPath); err != nil {
			return nil, fmt.Errorf("semgrep rules %s: %w", rulesPath, err)
		}
		return NewSemgrepEngine(DefaultScanner(), rulesPath, SemgrepLimits{Timeout: cfg.SemgrepTimeout}), nil

	default:
		return nil, fmt.Errorf("unsupported static engine %q: must be one of %s",
			cfg.Name, strings.Join(engineNames, ", "))
	}
}

// DefaultEngine returns the Tier 1 engine production uses.
//
// This is the single selection point for the engine, and it returns the regex
// baseline. That is a decision, not a placeholder: the Semgrep adapter is
// reachable through NewEngine and through the codeScanEngine configuration item,
// and the default moves only after the holdout evidence passes under the assist
// policy. It is written as the literal rather than as NewEngine(...) because the
// baseline engine's construction has no failure mode, and routing it through the
// error-returning selector would mean either an impossible error to discard or a
// panic on a path that cannot fail. A test pins that the two agree.
func DefaultEngine() StaticEngine {
	return regexEngine{scanner: DefaultScanner()}
}
