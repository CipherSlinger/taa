package codeaudit

import (
	"regexp"
	"strings"
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

// TestTruncatedScanPassesWithAScanGapNote pins the current contract: truncation
// is a follow-up item in the recommendation, not a refusal. The fixture still
// asserts that the scan really truncated, so the note cannot be vacuous.
func TestTruncatedScanPassesWithAScanGapNote(t *testing.T) {
	dir := t.TempDir()
	// Five LOW findings against a cap of two. The severity is load-bearing: the
	// gate blocks HIGH and MEDIUM, so a fixture built from either would fail on
	// its kept findings alone and stop isolating the truncation signal. A LOW
	// finding does not block, so the conclusion passes and only the advisory
	// note can reveal the truncation. The built-in rule set has no LOW rule,
	// hence the local one.
	writeTestFile(t, dir, "train.py",
		"low_fixture_line_1\n"+
			"low_fixture_line_2\n"+
			"low_fixture_line_3\n"+
			"low_fixture_line_4\n"+
			"low_fixture_line_5\n")

	lowRule := Rule{
		ID:          "TEST_LOW",
		Category:    "test",
		Severity:    SeverityLow,
		Description: "fixture rule",
		Patterns:    []*regexp.Regexp{regexp.MustCompile(`low_fixture_line`)},
	}
	scanReport, lineCounts, err := truncatingScannerWithRules([]Rule{lowRule}, 2).ScanDirectoryWithLines(dir)
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
		lineCounts, LLMConfig{}, 10*time.Millisecond)

	if !audit.Conclusion.Passed {
		t.Error("a truncated scan whose classified findings do not block was refused; " +
			"scan gaps are advisory follow-up items, not part of the verdict")
	}
	if !strings.Contains(audit.Conclusion.Recommendation, "扫描完整性提示") {
		t.Errorf("recommendation does not report the scan gap: %s", audit.Conclusion.Recommendation)
	}
	if !strings.Contains(audit.Conclusion.Recommendation, "结果被截断") {
		t.Errorf("recommendation does not name truncation: %s", audit.Conclusion.Recommendation)
	}
}

// TestIncompleteScanPassesWithAScanGapNote covers an engine that reports
// incompleteness instead of failing the scan: the gap is recorded and reported,
// but it does not withdraw the pass.
func TestIncompleteScanPassesWithAScanGapNote(t *testing.T) {
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

	audit := AssembleAuditReport(dir, scanReport, nil, lineCounts, LLMConfig{}, 10*time.Millisecond)

	if !audit.Conclusion.Passed {
		t.Error("a report whose scan did not complete was refused; scan gaps are advisory follow-up items")
	}
	if !strings.Contains(audit.Conclusion.Recommendation, "扫描未完成") {
		t.Errorf("recommendation does not report the incomplete scan: %s", audit.Conclusion.Recommendation)
	}
	if audit.ScanMetadata.ScanComplete {
		t.Error("ScanMetadata.ScanComplete = true for a report that did not complete")
	}
}

// TestScanMetadataCarriesIncompletenessToTheReportThatLeaves pins that the
// fields behind the advisory scan note are also visible to a reader of the
// audit report, so a follow-up item can be explained.
func TestScanMetadataCarriesIncompletenessToTheReportThatLeaves(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\n")

	scanReport, lineCounts, err := NewScanner(DefaultRules(), DefaultConfig()).ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	scanReport.Truncated = true
	scanReport.ParserErrors = 3

	audit := AssembleAuditReport(dir, scanReport, nil, lineCounts, LLMConfig{}, 10*time.Millisecond)

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
// path that bypasses stamping, does not merely lose information: every audit
// would carry a scan-gap note, and callers of CheckImportWithLLM would block
// every import. That failure has been observed rather than imagined: the
// gate-semantics fixture built bare Report literals, and once the precondition
// landed its false positive rate went from 0.52 to 1.00. This test is what makes
// that show up as one failing assertion instead of a plausible-looking evidence
// artifact.
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
		engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), repoSemgrepRules(t), SemgrepLimits{})
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

// ── The binary channel's gaps ─────────────────────────────

// TestProvesCleanScanWithholdsOnBinaryGaps pins the fold. A report whose binary
// channel did not look everywhere is not evidence of absence, and the two
// classes are treated differently on purpose: a bounded executable is a look
// that did not finish, a bounded data file is a look that finished on as much as
// there was reason to read.
//
// The finding cap is in the table as a case that does NOT withhold, because that
// is the property being pinned: reaching the cap means the channel found more
// than its listing budget, which is not the same fact as a look that did not
// happen, and treating it as one would refuse an import for having findings.
func TestProvesCleanScanWithholdsOnBinaryGaps(t *testing.T) {
	base := func(sum BinaryScanSummary) *Report {
		return &Report{
			ScanComplete:    true,
			ProcessExitCode: 0,
			Binary:          &sum,
		}
	}
	cases := []struct {
		name string
		sum  BinaryScanSummary
		want bool
	}{
		{"no binary files at all", BinaryScanSummary{}, true},
		{"files examined, nothing bounded", BinaryScanSummary{FilesCount: 3}, true},
		{"a bounded data file is visible but does not withhold", BinaryScanSummary{FilesCount: 3, BoundedData: 1}, true},
		{"a capped listing is a data bound", BinaryScanSummary{FilesCount: 3, BoundedData: 2}, true},
		{"the finding cap does not withhold", BinaryScanSummary{FilesCount: 3, FindingsCapped: true, FindingsDropped: 4}, true},
		{"a bounded executable withholds", BinaryScanSummary{FilesCount: 3, BoundedExecutable: 1}, false},
		{"an unexamined file withholds", BinaryScanSummary{FilesCount: 3, Incomplete: 1}, false},
		{"a pass that could not run withholds", BinaryScanSummary{Errored: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := base(tc.sum).ProvesCleanScan(); got != tc.want {
				t.Errorf("ProvesCleanScan() = %v, want %v for %+v", got, tc.want, tc.sum)
			}
		})
	}
}

// TestProvesCleanScanUnchangedWithoutABinaryChannel pins the rollback: a report
// that never ran the binary channel - every existing caller, and any deployment
// that turns it off - behaves exactly as it did before.
func TestProvesCleanScanUnchangedWithoutABinaryChannel(t *testing.T) {
	r := &Report{ScanComplete: true, ProcessExitCode: 0}
	if !r.ProvesCleanScan() {
		t.Error("a report with no binary channel must still prove a clean scan")
	}
}
