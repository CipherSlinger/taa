package codeaudit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── The selector ──────────────────────────────────────────

// TestNewEngineReturnsTheNamedEngine pins that a name maps to the engine that
// carries that name back on every surface a report is read from: Name() and the
// report's own Engine field. The two are separate writes, so a selector that
// returned one engine under another engine's name would look correct from the
// outside until someone compared a report to the configuration that produced it.
func TestNewEngineReturnsTheNamedEngine(t *testing.T) {
	semgrepCLI(t)

	cases := []struct {
		name     string
		cfg      EngineConfig
		wantName string
	}{
		{EngineNameRegex, EngineConfig{Name: EngineNameRegex}, EngineNameRegex},
		{EngineNameSemgrep, EngineConfig{
			Name:             EngineNameSemgrep,
			SemgrepRulesPath: repoSemgrepRules(t),
		}, EngineNameSemgrep},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := NewEngine(tc.cfg)
			if err != nil {
				t.Fatalf("NewEngine(%+v) error = %v", tc.cfg, err)
			}
			if got := engine.Name(); got != tc.wantName {
				t.Fatalf("Name() = %q, want %q", got, tc.wantName)
			}

			dir := t.TempDir()
			writeTestFile(t, dir, "train.py", "import os\nx = os.environ.get('api_key')\n")
			report, err := engine.ScanDirectory(dir)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if report.Engine != tc.wantName {
				t.Errorf("report.Engine = %q, want %q; the report does not say which engine scanned it",
					report.Engine, tc.wantName)
			}
			if len(report.Findings) == 0 {
				t.Fatal("the fixture produced no findings; the assertions above would be vacuous")
			}
		})
	}
}

// TestNewEngineRejectsUnknownEngineName is the last line of defence behind the
// config whitelist. The config layer rejects an unknown name too, but a caller
// that skips the config — the coordinator, a future entry point — must not get a
// silent regex scan back. Falling back here is the failure mode the whole
// selector exists to prevent: the scan runs, the report is honest, and nobody
// notices the configured engine was never used.
func TestNewEngineRejectsUnknownEngineName(t *testing.T) {
	for _, name := range []string{"", "nope", "Semgrep", "regexp", "regex, semgrep"} {
		t.Run("name="+name, func(t *testing.T) {
			engine, err := NewEngine(EngineConfig{Name: name})
			if err == nil {
				t.Fatalf("NewEngine(%q) returned %T with no error; want a rejection", name, engine)
			}
			if engine != nil {
				t.Errorf("NewEngine(%q) returned an engine alongside an error", name)
			}
			if name != "" && !strings.Contains(err.Error(), name) {
				t.Errorf("error %q should name the rejected value %q", err, name)
			}
			// The message has to say what is accepted, or the operator has to
			// read the source to fix the configuration.
			for _, want := range []string{EngineNameRegex, EngineNameSemgrep} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q should list the accepted engine %q", err, want)
				}
			}
		})
	}
}

// TestNewEngineValidatesTheSemgrepRulesAtConstruction pins that a Semgrep
// deployment fails where it is configured rather than where it is used.
//
// The rules path is the one thing Semgrep cannot run without, and its built-in
// default is relative to the repository root, so a container that does not set
// it is the expected mistake. Without this check that mistake surfaces as every
// model import being blocked and its code deleted — indistinguishable, from the
// operator's side, from the scanner working correctly and finding something.
func TestNewEngineValidatesTheSemgrepRulesAtConstruction(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "rules.yaml")
	if _, err := os.Stat(missing); err == nil {
		t.Fatalf("fixture %s exists; the check below would be vacuous", missing)
	}

	engine, err := NewEngine(EngineConfig{Name: EngineNameSemgrep, SemgrepRulesPath: missing})
	if err == nil {
		t.Fatalf("NewEngine accepted a missing rules path and returned %T", engine)
	}
	if engine != nil {
		t.Error("NewEngine returned an engine alongside an error")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q should name the path that was not found", err)
	}
}

// TestNewEngineTreatsAnEmptyRulesPathAsTheBuiltInDefault pins the one rules value
// that is not a path. Empty means "not configured" and has to resolve to the
// adapter's default; left as the empty string it would reach semgrep as a
// --config it cannot open, which is a scan failure per import.
//
// The built-in default is relative to the repository root, which is not this
// package's directory, so whether it resolves depends on where the test runs.
// Both branches below assert the same mapping, and neither is vacuous: an
// implementation that passed the empty string through would fail in both, once
// as an error naming "stat :" and once as a rulesPath of "".
func TestNewEngineTreatsAnEmptyRulesPathAsTheBuiltInDefault(t *testing.T) {
	semgrepCLI(t)

	_, statErr := os.Stat(DefaultSemgrepRulesPath)

	engine, err := NewEngine(EngineConfig{Name: EngineNameSemgrep})
	if statErr != nil {
		if err == nil {
			t.Fatalf("the built-in default does not exist relative to this directory "+
				"(%v), but NewEngine returned %T; the empty path is not being checked",
				statErr, engine)
		}
		if !strings.Contains(err.Error(), DefaultSemgrepRulesPath) {
			t.Fatalf("error %q should name the built-in default %q; an unset path has to map to "+
				"it rather than to the empty string", err, DefaultSemgrepRulesPath)
		}
		return
	}

	if err != nil {
		t.Fatalf("the built-in default exists relative to this directory, but NewEngine failed: %v", err)
	}
	concrete, ok := engine.(*semgrepEngine)
	if !ok {
		t.Fatalf("NewEngine(semgrep) returned %T, want *semgrepEngine", engine)
	}
	if concrete.rulesPath != DefaultSemgrepRulesPath {
		t.Errorf("rulesPath = %q, want the built-in default %q", concrete.rulesPath, DefaultSemgrepRulesPath)
	}
}

// TestDefaultEngineIsStillTheRegexBaseline pins the default, which is a decision
// rather than an implementation detail: the production engine stays regex until
// the holdout evidence passes under the assist policy (spec §6.5, §9.4). It also
// pins that the default and the selector agree, so the two ways of asking for
// the baseline engine cannot drift into different engines.
func TestDefaultEngineIsStillTheRegexBaseline(t *testing.T) {
	def := DefaultEngine()
	if def == nil {
		t.Fatal("DefaultEngine() = nil")
	}
	if got := def.Name(); got != EngineNameRegex {
		t.Errorf("DefaultEngine().Name() = %q, want %q; switching the default engine is a "+
			"separate decision that the holdout evidence gates", got, EngineNameRegex)
	}

	named, err := NewEngine(EngineConfig{Name: EngineNameRegex})
	if err != nil {
		t.Fatalf("NewEngine(regex) error = %v", err)
	}
	if named.Name() != def.Name() {
		t.Errorf("DefaultEngine() is %q but NewEngine(%q) is %q; the default has to be a name "+
			"the selector recognises", def.Name(), EngineNameRegex, named.Name())
	}
}

// ── The engine reaches the scan ───────────────────────────

// TestGenerateAuditReportUsesTheEngineItWasGiven is the assertion that makes the
// engine selection real rather than cosmetic. Everything else in this stage
// validates a name; this one checks that the name is the engine that scanned the
// code, by reading it back out of the report a consumer would read.
//
// A silent fallback to the regex engine would satisfy every other test here. It
// would not survive this one.
func TestGenerateAuditReportUsesTheEngineItWasGiven(t *testing.T) {
	semgrepCLI(t)

	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\nx = os.environ.get('api_key')\n")

	for _, tc := range []struct {
		name string
		cfg  EngineConfig
	}{
		{EngineNameRegex, EngineConfig{Name: EngineNameRegex}},
		{EngineNameSemgrep, EngineConfig{Name: EngineNameSemgrep, SemgrepRulesPath: repoSemgrepRules(t)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := NewEngine(tc.cfg)
			if err != nil {
				t.Fatalf("NewEngine(%+v): %v", tc.cfg, err)
			}
			audit, err := GenerateAuditReport(context.Background(), dir, engine, LLMConfig{Policy: "assist"}, nil)
			if err != nil {
				t.Fatalf("GenerateAuditReport: %v", err)
			}
			if audit.ScanMetadata.Engine != tc.name {
				t.Errorf("ScanMetadata.Engine = %q, want %q; the configured engine is not the one "+
					"that scanned the code", audit.ScanMetadata.Engine, tc.name)
			}
			// Non-vacuity: a report can only name its engine if a scan happened.
			if audit.Target.FilesScanned != 1 {
				t.Errorf("FilesScanned = %d, want 1; the engine did not scan the fixture",
					audit.Target.FilesScanned)
			}
		})
	}
}

// TestNewEngineCarriesTheConfiguredScanTimeout pins that the deadline a
// deployment configures is the deadline the engine enforces, and that an unset
// deadline resolves to the adapter's default rather than to no deadline.
//
// The two directions matter equally. A configuration that is silently ignored
// leaves a deployment believing it shortened a scan it did not, and a zero that
// reached the engine as "no deadline" would let one wedged CLI hang the import
// path indefinitely, which is the failure the deadline exists to bound.
func TestNewEngineCarriesTheConfiguredScanTimeout(t *testing.T) {
	semgrepCLI(t)

	for _, tc := range []struct {
		name  string
		given time.Duration
		want  time.Duration
	}{
		{"configured", 42 * time.Second, 42 * time.Second},
		{"unset falls back to the default", 0, DefaultSemgrepTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := NewEngine(EngineConfig{
				Name:             EngineNameSemgrep,
				SemgrepRulesPath: repoSemgrepRules(t),
				SemgrepTimeout:   tc.given,
			})
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			concrete, ok := engine.(*semgrepEngine)
			if !ok {
				t.Fatalf("NewEngine(semgrep) returned %T, want *semgrepEngine", engine)
			}
			if concrete.timeout != tc.want {
				t.Errorf("timeout = %v, want %v", concrete.timeout, tc.want)
			}
		})
	}
}

// TestNewEngineIgnoresAScanTimeoutForTheRegexEngine pins that the semgrep-only
// knobs do not leak into the baseline engine. The regex engine is an in-memory
// match with no subprocess, so a deadline is meaningless for it; accepting one
// silently would suggest the regex arm is bounded by it too, and the two arms
// would then be documented as comparable on a dimension where only one is.
func TestNewEngineIgnoresAScanTimeoutForTheRegexEngine(t *testing.T) {
	engine, err := NewEngine(EngineConfig{Name: EngineNameRegex, SemgrepTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewEngine(regex) with a scan timeout error = %v, want it ignored", err)
	}
	if engine.Name() != EngineNameRegex {
		t.Fatalf("Name() = %q, want %q", engine.Name(), EngineNameRegex)
	}
}

// TestGenerateAuditReportRejectsAMissingEngine pins that an unset engine is a
// configuration error rather than a scan with no engine, which in Go would be a
// nil interface and a panic somewhere below. A caller that never got a valid
// selection — the coordinator's SecurityConfig can be built without one — has to
// be told, and the import has to fail closed, which is what an error does here.
func TestGenerateAuditReportRejectsAMissingEngine(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\n")

	audit, err := GenerateAuditReport(context.Background(), dir, nil, LLMConfig{Policy: "assist"}, nil)
	if err == nil {
		t.Fatalf("GenerateAuditReport with a nil engine returned an audit: %+v", audit)
	}
	if audit != nil {
		t.Error("GenerateAuditReport returned an audit alongside an error")
	}
	if !strings.Contains(err.Error(), "engine") {
		t.Errorf("error %q should say the engine is the problem", err)
	}
}
