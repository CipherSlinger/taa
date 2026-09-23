package codeaudit

import (
	"testing"
	"time"

	"github.com/CipherSlinger/teellm"
)

// ── The predicate ─────────────────────────────────────────

// TestProvesCleanScanRequiresEveryCompletenessField pins the fields that have to
// hold before a report may be read as evidence of absence.
//
// The audit conclusion treats "no findings" as a pass, and that is only sound if
// the scan actually looked at everything and dropped nothing. Each field below
// is a different way for the scan to have not looked: it did not finish, it hit
// the finding cap and stopped walking, it could not parse a file, or the
// subprocess failed. Every one of them has to be able to withhold the pass on
// its own; a predicate that checked only some of them would let the others
// through silently.
func TestProvesCleanScanRequiresEveryCompletenessField(t *testing.T) {
	clean := func() *Report {
		return &Report{
			Engine:          EngineNameSemgrep,
			ScanComplete:    true,
			EngineVersion:   "1.177.0",
			ProcessExitCode: 0,
		}
	}

	if !clean().ProvesCleanScan() {
		t.Fatal("a completed scan with nothing skipped does not prove a clean scan; " +
			"the cases below would then pass for the wrong reason")
	}

	cases := []struct {
		name   string
		mu     func(*Report)
		reason string
	}{
		{"scan did not complete", func(r *Report) { r.ScanComplete = false },
			"an engine that did not finish cannot have established the absence of findings"},
		{"the finding cap was hit", func(r *Report) { r.Truncated = true },
			"findings were dropped, so the report does not contain what the scan found"},
		{"a file could not be parsed", func(r *Report) { r.ParserErrors = 1 },
			"a file the engine could not read is a file it did not scan"},
		{"files were skipped by extension", func(r *Report) { r.UnsupportedExts = 1 },
			"a skipped file is unexamined input"},
		{"the subprocess failed", func(r *Report) { r.ProcessExitCode = 2 },
			"a failed process's empty result set is not a result"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := clean()
			tc.mu(r)
			if r.ProvesCleanScan() {
				t.Errorf("ProvesCleanScan() = true although %s", tc.reason)
			}
		})
	}
}

// TestProvesCleanScanHandlesNil pins that a missing report is not a clean scan.
// AssembleAuditReport is called with a nil scan report on some paths, and the
// safe reading of "no report" is that nothing was proved.
func TestProvesCleanScanHandlesNil(t *testing.T) {
	var r *Report
	if r.ProvesCleanScan() {
		t.Error("a nil report proved a clean scan")
	}
}

// ── The decision sites ────────────────────────────────────

// TestTruncatedScanCannotPassTheAuditConclusion is the defect this stage exists
// for, at the level production reads.
//
// import_processing.go:645 acts on audit.Conclusion.Passed. A scan that hit the
// finding cap has dropped findings the engine did find, and Passed is computed
// from what remains — so a truncated scan of medium-only findings passed the
// assist policy while parts of the input had never been examined. The fixture is
// asserted to be truncated and to have passed on the strength of its findings
// alone, so the test cannot quietly become vacuous.
func TestTruncatedScanCannotPassTheAuditConclusion(t *testing.T) {
	dir := t.TempDir()
	// Five medium findings against a cap of two. No HIGH, so under assist the
	// finding-based decision alone is a pass.
	writeTestFile(t, dir, "train.py",
		"import os\n"+
			"a = os.environ.get('api_key')\n"+
			"b = os.environ.get('api_key')\n"+
			"c = os.environ.get('api_key')\n"+
			"d = os.environ.get('api_key')\n"+
			"e = os.environ.get('api_key')\n")

	scanReport, lineCounts, err := truncatingScanner(2).ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !scanReport.Truncated {
		t.Fatal("fixture did not truncate; the assertion below would be vacuous")
	}
	if !scanReport.Passed {
		t.Fatalf("fixture does not pass on its findings alone (Passed = false); "+
			"it would fail this test whether or not truncation is handled: %+v", scanReport)
	}

	audit := AssembleAuditReport(dir, scanReport,
		[]FileReport{BuildFileReport("train.py", scanReport.Findings)},
		lineCounts, LLMConfig{Policy: "assist"}, 10*time.Millisecond)

	if audit.Conclusion.Passed {
		t.Error("a scan that dropped findings at the cap passed the audit; " +
			"the part of the input that was never examined is invisible in the report")
	}
}

// TestIncompleteScanCannotPassTheAuditConclusion is the same requirement for an
// engine that reports incompleteness instead of failing the scan.
//
// The adapter returns an error rather than such a report, and the pipeline
// turns that error into a block, so this path is not reachable through the
// semgrep engine today. It is pinned anyway because the conclusion reads a
// report, and a report carrying ScanComplete = false must not pass on the
// strength of an empty finding list.
func TestIncompleteScanCannotPassTheAuditConclusion(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\n")

	scanReport, lineCounts, err := NewScanner(DefaultRules(), DefaultConfig()).ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(scanReport.Findings) != 0 {
		t.Fatalf("fixture produced %d findings; the empty-list path is what is under test", len(scanReport.Findings))
	}
	// What an engine reports when it could not read the input.
	scanReport.ScanComplete = false

	audit := AssembleAuditReport(dir, scanReport, nil, lineCounts, LLMConfig{Policy: "assist"}, 10*time.Millisecond)

	if audit.Conclusion.Passed {
		t.Error("a report whose scan did not complete passed the audit on an empty finding list")
	}
	if audit.ScanMetadata.ScanComplete {
		t.Error("ScanMetadata.ScanComplete = true for a report that did not complete")
	}
}

// TestScanMetadataCarriesIncompletenessToTheReportThatLeaves pins that the
// fields the conclusion is derived from are also visible to a reader of the
// audit report, so a blocked import can be explained.
func TestScanMetadataCarriesIncompletenessToTheReportThatLeaves(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\n")

	scanReport, lineCounts, err := NewScanner(DefaultRules(), DefaultConfig()).ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	scanReport.Truncated = true
	scanReport.ParserErrors = 3

	audit := AssembleAuditReport(dir, scanReport, nil, lineCounts, LLMConfig{Policy: "assist"}, 10*time.Millisecond)

	if !audit.ScanMetadata.Truncated {
		t.Error("ScanMetadata.Truncated = false although the scan dropped findings")
	}
	if audit.ScanMetadata.ParserErrors != 3 {
		t.Errorf("ScanMetadata.ParserErrors = %d, want 3", audit.ScanMetadata.ParserErrors)
	}
}

// TestEveryEngineProvesACleanScanForANormalScan is the guard on the trap the
// precondition would otherwise set.
//
// Withholding a pass from a report that cannot prove it looked is only safe if
// the engines actually can prove it. The completeness fields default to values
// that withhold the pass — ScanComplete is false by default and false means "did
// not complete" — so an engine that forgets to stamp them, or a new construction
// path that bypasses stamping, does not merely lose information: it blocks every
// import, and the report still reads as a scan that found nothing. That failure
// has been observed rather than imagined: the gate-semantics fixture built bare
// Report literals, and once the precondition landed its false positive rate went
// from 0.52 to 1.00. This test is what makes that show up as one failing
// assertion instead of a plausible-looking evidence artifact.
func TestEveryEngineProvesACleanScanForANormalScan(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\nx = os.environ.get('api_key')\n")

	t.Run("regex", func(t *testing.T) {
		report, err := DefaultEngine().ScanDirectory(dir)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !report.ProvesCleanScan() {
			t.Errorf("the regex engine's report for a normal scan cannot prove it looked: "+
				"ScanComplete=%v Truncated=%v ParserErrors=%d UnsupportedExts=%d ProcessExitCode=%d",
				report.ScanComplete, report.Truncated, report.ParserErrors,
				report.UnsupportedExts, report.ProcessExitCode)
		}
	})

	t.Run("semgrep", func(t *testing.T) {
		semgrepCLI(t)
		engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), repoSemgrepRules(t))
		report, err := engine.ScanDirectory(dir)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !report.ProvesCleanScan() {
			t.Errorf("the semgrep engine's report for a normal scan cannot prove it looked: "+
				"ScanComplete=%v Truncated=%v ParserErrors=%d UnsupportedExts=%d ProcessExitCode=%d",
				report.ScanComplete, report.Truncated, report.ParserErrors,
				report.UnsupportedExts, report.ProcessExitCode)
		}
	})
}

// TestRecomputeReportPassedWithholdsPassForAnIncompleteScan pins the other
// place the pass decision is made. CheckImportWithLLM returns Report.Passed on
// every path that does not go through the audit assembly, and this function is
// what recomputes it, so it has to carry the same precondition.
func TestRecomputeReportPassedWithholdsPassForAnIncompleteScan(t *testing.T) {
	medium := Finding{File: "train.py", Line: 2, RuleID: "ENV_001", Severity: SeverityMedium}

	cases := []struct {
		name      string
		mu        func(*Report)
		wantPass  bool
		whyString string
	}{
		{"clean and complete", func(r *Report) {}, true,
			"a complete scan with only medium findings passes the static decision"},
		{"truncated", func(r *Report) { r.Truncated = true }, false,
			"findings were dropped"},
		{"not complete", func(r *Report) { r.ScanComplete = false }, false,
			"the scan did not finish"},
		{"parser errors", func(r *Report) { r.ParserErrors = 1 }, false,
			"a file was not parsed"},
		{"subprocess failed", func(r *Report) { r.ProcessExitCode = 1 }, false,
			"the engine process failed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Report{
				ScanComplete:    true,
				Findings:        []Finding{medium},
				ProcessExitCode: 0,
			}
			tc.mu(r)
			recomputeReportPassed(r, false)
			if r.Passed != tc.wantPass {
				t.Errorf("Passed = %v, want %v (%s)", r.Passed, tc.wantPass, tc.whyString)
			}
		})
	}
}

// TestAHighFindingStillBlocksAnIncompleteScan pins that the two reasons to block
// compose rather than replace each other: the completeness precondition must not
// become a reason to ignore a finding.
func TestAHighFindingStillBlocksAnIncompleteScan(t *testing.T) {
	r := &Report{
		ScanComplete: true,
		Findings: []Finding{
			{File: "train.py", Line: 2, RuleID: "CMD_001", Severity: SeverityHigh},
		},
	}
	r.Truncated = true

	recomputeReportPassed(r, false)
	if r.Passed {
		t.Error("Passed = true for a report with a HIGH finding")
	}
	// And the exoneration path must not launder it either.
	r.Findings[0].LLMVerdict = teellm.VerdictBenign
	recomputeReportPassed(r, true)
	if r.Passed {
		t.Error("Passed = true for a truncated report whose HIGH finding the LLM exonerated; " +
			"an unexamined part of the input cannot be exonerated")
	}
}
