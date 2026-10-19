package codeaudit

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
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
// that builds an EngineConfig by hand and skips the whitelist must not get a
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

// TestNewEngineRejectsTheNonSelectableChannelNames pins that the two channel
// names are not themselves selectable engines. EngineNameCPG is the graph
// engine that runs after a Tier 1 engine, and EngineNameBinary is the binary
// scanner that runs in addition to one; a deployment configures a source
// engine, and naming a channel here asks for something NewEngine cannot run.
// The default arm has to reject it rather than hand back a regex scan.
func TestNewEngineRejectsTheNonSelectableChannelNames(t *testing.T) {
	for _, name := range []string{EngineNameBinary, EngineNameCPG} {
		t.Run("name="+name, func(t *testing.T) {
			engine, err := NewEngine(EngineConfig{Name: name})
			if err == nil {
				t.Fatalf("NewEngine(%q) returned %T with no error; want a rejection", name, engine)
			}
			if engine != nil {
				t.Errorf("NewEngine(%q) returned an engine alongside an error", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error %q should name the rejected value %q", err, name)
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
// model import being blocked — indistinguishable, from the
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
// the holdout evidence passes the audit gate (spec §6.5, §9.4). It also pins
// that the default and the selector agree, so the two ways of asking for the
// baseline engine cannot drift into different engines.
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
			audit, err := GenerateAuditReport(context.Background(), dir, engine, AuditConfig{LLM: LLMConfig{}}, nil)
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
// selection — an engine left unset in a hand-built config — has to be told, and
// the import has to fail closed, which is what an error does here.
func TestGenerateAuditReportRejectsAMissingEngine(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\n")

	audit, err := GenerateAuditReport(context.Background(), dir, nil, AuditConfig{LLM: LLMConfig{}}, nil)
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

// TestGenerateAuditReportRunsTheBinaryChannelForEveryEngine pins the property
// that made the binary channel a channel rather than a third engine: whichever
// source engine a deployment configured, the binary files in the package are
// audited. A deployment must not have to choose between source coverage and
// binary coverage.
func TestGenerateAuditReportRunsTheBinaryChannelForEveryEngine(t *testing.T) {
	engines := map[string]StaticEngine{}
	for _, name := range []string{EngineNameRegex, EngineNameSemgrep} {
		// repoSemgrepRules(t), not DefaultSemgrepRulesPath: the latter is a path
		// relative to the repository root, and NewEngine stats it with the
		// process's working directory, which under `go test` is this package's
		// directory - so the bare default resolves to
		// internal/codeaudit/models/audit/... and NewEngine fails before any
		// subtest starts, where a skip inside the subtest could not save it. The
		// helper makes it absolute; the per-engine skip below is still needed for
		// a host without the CLI. The regex arm ignores the field, so one value
		// serves both.
		engine, err := NewEngine(EngineConfig{Name: name, SemgrepRulesPath: repoSemgrepRules(t)})
		if err != nil {
			t.Fatalf("NewEngine(%s): %v", name, err)
		}
		engines[name] = engine
	}

	for name, engine := range engines {
		t.Run(name, func(t *testing.T) {
			if name == EngineNameSemgrep {
				if _, err := exec.LookPath("semgrep"); err != nil {
					t.Skip("semgrep not installed on this host")
				}
			}

			dir := t.TempDir()
			// The packed section is not decoration: the corroboration gate downgrades
			// a presence-only family (NET_002, from the socket/connect imports) to LOW
			// unless the same file carries independent corroboration, so a fixture that
			// imported socket without a near-random executable section would carry no
			// blocking finding and this assertion could not hold. The measured entropy
			// is what makes the package block on evidence rather than on a name.
			writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
				imports:  []string{"socket", "connect"},
				needed:   []string{"libcurl.so.4"},
				text:     uniformBytes(512),
				textExec: true,
			}))

			cfg := AuditConfig{
				LLM:    LLMConfig{Enabled: false},
				Binary: DefaultBinaryConfig(),
			}
			audit, err := GenerateAuditReport(context.Background(), dir, engine, cfg, nil)
			if err != nil {
				t.Fatalf("GenerateAuditReport: %v", err)
			}
			if audit.ScanMetadata.Binary == nil {
				t.Fatal("ScanMetadata.Binary is nil: the binary channel did not run")
			}
			if audit.ScanMetadata.Binary.FilesCount != 1 {
				t.Errorf("Binary.FilesCount = %d, want 1", audit.ScanMetadata.Binary.FilesCount)
			}
			if audit.Conclusion.Passed {
				t.Error("conclusion Passed = true for a package whose shared object imports socket and connect")
			}
			found := false
			for _, fr := range audit.FileReports {
				for _, f := range fr.Findings {
					if f.RuleID == "NET_002" && f.Engine == EngineNameBinary {
						found = true
					}
				}
			}
			if !found {
				t.Error("no binary NET_002 finding in the audit report")
			}
		})
	}
}

// TestGenerateAuditReportWithBinaryDisabledIsUnchanged pins the rollback: with
// the channel off, an audit of a package full of native code behaves exactly as
// it did before the channel existed, and says so by leaving the field nil.
func TestGenerateAuditReportWithBinaryDisabledIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"socket", "connect"}}))

	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: false},
		Binary: BinaryConfig{Enabled: false},
	}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if audit.ScanMetadata.Binary != nil {
		t.Errorf("ScanMetadata.Binary = %+v with the channel disabled", audit.ScanMetadata.Binary)
	}
	if !audit.Conclusion.Passed {
		t.Error("Passed = false with the channel disabled; the disabled path is not a rollback")
	}
}

// TestGenerateAuditReportMirrorsBinaryGapsIntoMetadata pins that the metadata
// mirror carries the gap fields and not just the counts. The scan summary is
// what makes a blocked import explainable to the in-process consumers of the
// audit and to the host-side log line, and a copy that kept only FilesCount
// would read as a channel that finished on a package whose native code it never
// examined. The fixture fails after classify - the header parses, the section
// header table runs off the end - so the gap is Incomplete rather than a skipped
// file, which is exactly the shape the host's truncated CUDA libraries have.
func TestGenerateAuditReportMirrorsBinaryGapsIntoMetadata(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: []byte("truncated")})
	// e_shoff past the end of the file (ELF64 header offset 0x28).
	binary.LittleEndian.PutUint64(raw[0x28:0x30], 1<<30)
	writeTestBytes(t, dir, "truncated.so", raw)

	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(),
		AuditConfig{LLM: LLMConfig{Enabled: false}, Binary: DefaultBinaryConfig()}, nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if audit.ScanMetadata.Binary == nil {
		t.Fatal("ScanMetadata.Binary is nil: the binary channel did not run")
	}
	if audit.ScanMetadata.Binary.Incomplete != 1 {
		t.Errorf("ScanMetadata.Binary.Incomplete = %d, want 1: the mirror must carry the gap, not only the counts",
			audit.ScanMetadata.Binary.Incomplete)
	}
	if !audit.Conclusion.Passed {
		t.Error("Passed = false for a package whose native code could not be examined; scan gaps are advisory and do not decide the verdict")
	}
	if !strings.Contains(audit.Conclusion.Recommendation, "二进制文件未完整扫描") {
		t.Errorf("recommendation does not report the incomplete binary scan: %s", audit.Conclusion.Recommendation)
	}
}

// TestRunBinaryChannelReportsAWholePassFailure pins the failure contract for a
// channel that is enabled but could not run at all. The distinction it protects
// is the one between a pass that ran and a pass that did not: without it an
// Errored channel and a disabled one are the same nil result, ProvesCleanScan
// returns true, and the report reads as a clean scan of a package whose native
// code was never examined.
func TestRunBinaryChannelReportsAWholePassFailure(t *testing.T) {
	// A path that is not a directory reaches the scan-failure branch, because
	// BinaryScanner.ScanDirectory stats the path and returns an error for
	// anything that is not a directory before it walks a single file. A regular
	// file therefore produces a scan error rather than an empty clean scan, which
	// is what makes this the input that exercises the branch.
	notADir := writeTestFile(t, t.TempDir(), "model.py", "import os\n")

	res := runBinaryChannel(notADir, BinaryConfig{Enabled: true})
	if res == nil {
		t.Fatal("runBinaryChannel returned nil for an enabled channel that could not scan: " +
			"an enabled failure is now indistinguishable from a disabled channel")
	}
	if !res.Summary.Errored {
		t.Error("Summary.Errored = false after a scan failure: the gap does not travel in the summary")
	}

	// The downstream chain the summary feeds: MergeBinaryFindings attaches it to
	// the scan report, and ProvesCleanScan then withholds the report-level pass
	// on Errored. The audit conclusion does not consume that flag; the gap
	// reaches the operator as an advisory note in the recommendation.
	report := &Report{ScanComplete: true}
	MergeBinaryFindings(report, res)
	if report.ProvesCleanScan() {
		t.Error("ProvesCleanScan() = true for a report whose binary channel could not run: " +
			"the package would read as a clean scan of native code that was never examined")
	}
}
