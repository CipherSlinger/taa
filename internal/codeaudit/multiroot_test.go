package codeaudit

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// highSource is one line that produces exactly one HIGH finding, so a fixture
// can be sized to the finding cap by counting lines.
const highSource = "subprocess.run(cmd, shell=True)\n"

// mergedEngineRoots builds two roots, each with one file that produces a HIGH
// finding, and returns them with the file paths.
func mergedEngineRoots(t *testing.T) (rootA, rootB, fileA, fileB string) {
	t.Helper()
	rootA = t.TempDir()
	fileA = writeTestFile(t, rootA, "train.py", highSource)
	rootB = t.TempDir()
	fileB = writeTestFile(t, rootB, "util.py", highSource)
	return rootA, rootB, fileA, fileB
}

// TestScanDirectoriesWithLinesMergesRoots pins the union: one call walks both
// roots and reports what both contain, with the first root as the primary.
func TestScanDirectoriesWithLinesMergesRoots(t *testing.T) {
	rootA, rootB, fileA, fileB := mergedEngineRoots(t)

	report, lineCounts, err := NewDefaultScanner().ScanDirectoriesWithLines([]string{rootA, rootB})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if report.FilesCount != 2 {
		t.Errorf("FilesCount = %d, want 2 (the union of both roots)", report.FilesCount)
	}
	if report.ScannedDir != rootA {
		t.Errorf("ScannedDir = %q, want the first root %q", report.ScannedDir, rootA)
	}
	if !reflect.DeepEqual(report.Directories, []string{rootA, rootB}) {
		t.Errorf("Directories = %v, want [%s %s]", report.Directories, rootA, rootB)
	}

	gotFiles := make(map[string]bool)
	for _, f := range report.Findings {
		gotFiles[f.File] = true
	}
	if !gotFiles[fileA] || !gotFiles[fileB] {
		t.Errorf("findings cover %v, want one file from each root (%s, %s)", gotFiles, fileA, fileB)
	}
	if len(report.Findings) != 2 {
		t.Errorf("len(Findings) = %d, want 2, one per root", len(report.Findings))
	}
	if len(lineCounts) != 2 {
		t.Errorf("len(lineCounts) = %d, want 2 (the union of both roots)", len(lineCounts))
	}
}

// TestSingleRootScanLeavesDirectoriesEmpty pins the byte-compatibility rule:
// Directories is filled only for a merged scan, so a single-root report is
// indistinguishable from one produced before multi-root existed. Every parity
// comparison in this package rests on that.
func TestSingleRootScanLeavesDirectoriesEmpty(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", highSource)

	scannerReport, _, err := NewDefaultScanner().ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatalf("scanner scan: %v", err)
	}
	if len(scannerReport.Directories) != 0 {
		t.Errorf("Scanner.ScanDirectoryWithLines set Directories = %v for one root", scannerReport.Directories)
	}

	engineReport, _, err := DefaultEngine().ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatalf("engine scan: %v", err)
	}
	if len(engineReport.Directories) != 0 {
		t.Errorf("Engine.ScanDirectoryWithLines set Directories = %v for one root", engineReport.Directories)
	}
}

// TestScanDirectoriesWithLinesRejectsMissingRoot pins that a root the scan
// cannot walk is an error, not a skipped root, and that no partial report is
// returned for it.
//
// A skipped root is the quiet failure this guards: the scan would report on the
// one root it did read, Passed would be computed from that alone, and nothing in
// the report would say an input was never examined.
func TestScanDirectoriesWithLinesRejectsMissingRoot(t *testing.T) {
	rootA := t.TempDir()
	writeTestFile(t, rootA, "train.py", highSource)
	missing := filepath.Join(rootA, "does-not-exist")

	report, _, err := NewDefaultScanner().ScanDirectoriesWithLines([]string{rootA, missing})
	if err == nil {
		t.Fatal("a scan with a missing root returned no error; the missing root was skipped")
	}
	if report != nil {
		t.Error("a scan with a missing root returned a report; a partial report reads as a decision")
	}
}

// TestScanDirectoriesWithLinesUsesOneBudgetAcrossRoots pins that the finding cap
// is global, not per root.
//
// The fixture is sized to discriminate: two findings per root against a cap of
// three. One budget stops at three and marks the scan truncated; a budget per
// root would keep all four and mark it complete. The second is the difference
// that matters, because Truncated is what withholds a pass from a scan that
// dropped findings.
func TestScanDirectoriesWithLinesUsesOneBudgetAcrossRoots(t *testing.T) {
	rootA := t.TempDir()
	writeTestFile(t, rootA, "a.py", manyHighFindings(2))
	rootB := t.TempDir()
	writeTestFile(t, rootB, "b.py", manyHighFindings(2))

	report, _, err := truncatingScanner(3).ScanDirectoriesWithLines([]string{rootA, rootB})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !report.Truncated {
		t.Error("Truncated = false although the roots together produced more findings than the cap")
	}
	if len(report.Findings) != 3 {
		t.Errorf("len(Findings) = %d, want exactly the cap (3); a per-root budget keeps 4",
			len(report.Findings))
	}
}

// TestScanDirectoriesWithLinesDoesNotDoubleCountNestedRoots pins that a root
// nested inside one already walked does not have its files counted twice. Both
// orders are covered, because the input is a caller's list and neither order is
// more correct than the other.
func TestScanDirectoriesWithLinesDoesNotDoubleCountNestedRoots(t *testing.T) {
	build := func(t *testing.T) (root, nested string) {
		t.Helper()
		root = t.TempDir()
		writeTestFile(t, root, "train.py", highSource)
		nested = filepath.Join(root, "pkg")
		writeTestFile(t, root, "pkg/util.py", highSource)
		return root, nested
	}

	t.Run("ancestor first", func(t *testing.T) {
		root, nested := build(t)
		report, lineCounts, err := NewDefaultScanner().ScanDirectoriesWithLines([]string{root, nested})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if report.FilesCount != 2 {
			t.Errorf("FilesCount = %d, want 2; the nested root's file was counted twice", report.FilesCount)
		}
		if len(report.Findings) != 2 {
			t.Errorf("len(Findings) = %d, want 2; the nested root's finding was counted twice", len(report.Findings))
		}
		if len(lineCounts) != 2 {
			t.Errorf("len(lineCounts) = %d, want 2; the nested root's file was counted twice", len(lineCounts))
		}
	})

	t.Run("descendant first", func(t *testing.T) {
		root, nested := build(t)
		report, lineCounts, err := NewDefaultScanner().ScanDirectoriesWithLines([]string{nested, root})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if report.FilesCount != 2 {
			t.Errorf("FilesCount = %d, want 2; the ancestor's walk re-counted the nested file", report.FilesCount)
		}
		if len(report.Findings) != 2 {
			t.Errorf("len(Findings) = %d, want 2; the ancestor's walk re-counted the nested finding", len(report.Findings))
		}
		if len(lineCounts) != 2 {
			t.Errorf("len(lineCounts) = %d, want 2; the ancestor's walk re-counted the nested file", len(lineCounts))
		}
	})
}

// TestRegexEngineScansDirectoriesWithLines pins the regex engine's multi-root
// path: it stamps its identity on the merged report, keeps the first root as the
// primary, and records the whole root list.
func TestRegexEngineScansDirectoriesWithLines(t *testing.T) {
	rootA, rootB, _, _ := mergedEngineRoots(t)

	report, _, err := DefaultEngine().ScanDirectoriesWithLines([]string{rootA, rootB})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if report.Engine != EngineNameRegex {
		t.Errorf("Engine = %q, want %q; the merged report cannot prove which engine produced it",
			report.Engine, EngineNameRegex)
	}
	if !report.ScanComplete {
		t.Error("ScanComplete = false; the regex engine always completes its scan")
	}
	if report.ScannedDir != rootA {
		t.Errorf("ScannedDir = %q, want %q", report.ScannedDir, rootA)
	}
	if !reflect.DeepEqual(report.Directories, []string{rootA, rootB}) {
		t.Errorf("Directories = %v, want [%s %s]", report.Directories, rootA, rootB)
	}
	if report.FilesCount != 2 {
		t.Errorf("FilesCount = %d, want 2", report.FilesCount)
	}
}

// TestSemgrepEngineScansBothRootsInOneInvocation pins that a merged scan is one
// semgrep run whose targets are the union of both roots' files.
//
// The completeness check compares the walked target list against the paths
// semgrep reports as scanned, so the target list is the thing that has to be the
// union: if only one root's files were passed, the other root's code would go
// unexamined while the report still read as a completed scan of "the audit".
func TestSemgrepEngineScansBothRootsInOneInvocation(t *testing.T) {
	stub := &stubSemgrep{}
	rootA, rootB, fileA, fileB := mergedEngineRoots(t)
	rulesDir := t.TempDir()
	rulesPath := writeTestFile(t, rulesDir, "rules.yaml", "rules: []\n")

	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), rulesPath, SemgrepLimits{})
	engine.execFn = stub.exec

	// The payload claims to have scanned both roots' files, which is what a
	// complete merged run looks like.
	stub.stdout = semgrepPayload([]string{fileA, fileB}, "", "")

	report, _, err := engine.ScanDirectoriesWithLines([]string{rootA, rootB})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(stub.calls) != 1 {
		t.Fatalf("semgrep was invoked %d times, want 1 for a merged scan", len(stub.calls))
	}
	targets := targetsOf(stub.calls[0].args)
	if !reflect.DeepEqual(targets, []string{fileA, fileB}) {
		t.Errorf("semgrep targets = %v, want the union of both roots' files [%s %s]",
			targets, fileA, fileB)
	}
	if report.FilesCount != 2 {
		t.Errorf("FilesCount = %d, want 2", report.FilesCount)
	}
	if report.ScannedDir != rootA {
		t.Errorf("ScannedDir = %q, want %q", report.ScannedDir, rootA)
	}
	if !reflect.DeepEqual(report.Directories, []string{rootA, rootB}) {
		t.Errorf("Directories = %v, want [%s %s]", report.Directories, rootA, rootB)
	}
}

// TestSemgrepEngineCompletenessCoversEveryRoot mirrors the single-root
// unscanned-target test for a merged scan: a file omitted from either root's
// share of the target list fails the scan. The two directions are separate
// cases because a check that only looked at the first root's targets would pass
// the second.
func TestSemgrepEngineCompletenessCoversEveryRoot(t *testing.T) {
	rootA, rootB, fileA, fileB := mergedEngineRoots(t)
	rulesDir := t.TempDir()
	rulesPath := writeTestFile(t, rulesDir, "rules.yaml", "rules: []\n")

	cases := []struct {
		name    string
		scanned []string
	}{
		{"the second root's file is missing", []string{fileA}},
		{"the first root's file is missing", []string{fileB}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubSemgrep{}
			engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), rulesPath, SemgrepLimits{})
			engine.execFn = stub.exec
			stub.stdout = semgrepPayload(tc.scanned, "", "")

			if _, _, err := engine.ScanDirectoriesWithLines([]string{rootA, rootB}); err == nil {
				t.Error("a merged scan that read one root's target but not the other's was accepted as complete")
			}
		})
	}
}

// TestGenerateAuditReportForDirsMergesRoots pins the entry point end to end: the
// primary root is the audit target, the per-root breakdown has one entry per
// root with the right counts, and the profile of the scan is carried out.
func TestGenerateAuditReportForDirsMergesRoots(t *testing.T) {
	rootA, rootB, _, _ := mergedEngineRoots(t)

	audit, err := GenerateAuditReportForDirs(context.Background(), []string{rootA, rootB},
		DefaultEngine(), LLMConfig{Policy: "assist"}, nil)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}

	if audit.Target.Directory != rootA {
		t.Errorf("Target.Directory = %q, want the primary root %q", audit.Target.Directory, rootA)
	}
	if len(audit.Roots) != 2 {
		t.Fatalf("len(Roots) = %d, want 2: %+v", len(audit.Roots), audit.Roots)
	}
	if audit.Roots[0].Directory != rootA || audit.Roots[1].Directory != rootB {
		t.Errorf("Roots directories = [%s %s], want [%s %s]",
			audit.Roots[0].Directory, audit.Roots[1].Directory, rootA, rootB)
	}
	for i, root := range audit.Roots {
		if root.FindingsCount != 1 {
			t.Errorf("Roots[%d] (%s) FindingsCount = %d, want 1", i, root.Directory, root.FindingsCount)
		}
		if root.FilesScanned != 1 {
			t.Errorf("Roots[%d] (%s) FilesScanned = %d, want 1", i, root.Directory, root.FilesScanned)
		}
		if root.Passed {
			t.Errorf("Roots[%d] (%s) Passed = true for a root carrying a HIGH finding", i, root.Directory)
		}
	}
	// A HIGH finding on each root fails the audit, but the scan itself finished
	// and dropped nothing: the completeness verdict is true while the policy
	// verdict is false, and the two are carried separately.
	if audit.Conclusion.Passed {
		t.Error("Conclusion.Passed = true for an audit with a HIGH finding on every root")
	}
	if !audit.ScanMetadata.ScanProvedClean {
		t.Error("ScanMetadata.ScanProvedClean = false for a scan that ran to completion and dropped nothing")
	}
}

// TestRootPassedFollowsPolicyNotFindingPresence pins the corrected per-root rule
// against the situations that separate the two candidate definitions.
//
// The first case is the one the rule exists for. A root carrying only a LOW
// finding does not fail the audit under the assist policy, so its per-root
// verdict has to say passed — otherwise a reader sees passed:false beside a
// passing code and cannot tell whether anything was wrong. The second case is
// the other direction: a scan that finished and found something only on one root
// clears the other, which is exactly what lets a reader of a failed merged audit
// see which root caused it.
func TestRootPassedFollowsPolicyNotFindingPresence(t *testing.T) {
	t.Run("a LOW finding does not fail its root when the audit passes", func(t *testing.T) {
		rootA := t.TempDir()
		// EMB_003 is classified LOW, so under assist the audit passes.
		writeTestFile(t, rootA, "log.py", "print(train_data)\n")
		rootB := t.TempDir()
		writeTestFile(t, rootB, "clean.py", "x = 1\n")

		audit, err := GenerateAuditReportForDirs(context.Background(), []string{rootA, rootB},
			DefaultEngine(), LLMConfig{Policy: "assist"}, nil)
		if err != nil {
			t.Fatalf("audit: %v", err)
		}
		if !audit.Conclusion.Passed {
			t.Fatalf("fixture does not pass the audit (statistics %+v); the case under test needs it to",
				audit.Statistics)
		}
		if audit.Roots[0].FindingsCount == 0 {
			t.Fatal("fixture produced no finding under the first root; the case under test would be vacuous")
		}
		for i, root := range audit.Roots {
			if !root.Passed {
				t.Errorf("Roots[%d] (%s) Passed = false although the audit passed and the scan completed",
					i, root.Directory)
			}
		}
	})

	t.Run("findings on one root clear the other", func(t *testing.T) {
		rootA, rootB, _, _ := mergedEngineRoots(t)

		audit, err := GenerateAuditReportForDirs(context.Background(), []string{rootA, rootB},
			DefaultEngine(), LLMConfig{Policy: "assist"}, nil)
		if err != nil {
			t.Fatalf("audit: %v", err)
		}
		if audit.Conclusion.Passed {
			t.Fatal("fixture should fail the audit; the case under test needs it to")
		}
		// Both roots carry a finding here, so both fail; the discriminating
		// case for the other direction is the one below.
		for i, root := range audit.Roots {
			if root.FindingsCount == 0 && !root.Passed {
				t.Errorf("Roots[%d] (%s) Passed = false with no finding under it and a complete scan",
					i, root.Directory)
			}
		}
	})

	t.Run("a HIGH finding on one root clears the other", func(t *testing.T) {
		rootA := t.TempDir()
		writeTestFile(t, rootA, "train.py", highSource)
		rootB := t.TempDir()
		writeTestFile(t, rootB, "clean.py", "x = 1\n")

		audit, err := GenerateAuditReportForDirs(context.Background(), []string{rootA, rootB},
			DefaultEngine(), LLMConfig{Policy: "assist"}, nil)
		if err != nil {
			t.Fatalf("audit: %v", err)
		}
		if audit.Conclusion.Passed {
			t.Fatal("fixture should fail the audit; the case under test needs it to")
		}
		if !audit.ScanMetadata.ScanProvedClean {
			t.Fatal("fixture scan should have completed; the case under test needs a complete scan")
		}
		if audit.Roots[0].Passed {
			t.Errorf("Roots[0] (%s) Passed = true with a HIGH finding under it", audit.Roots[0].Directory)
		}
		if !audit.Roots[1].Passed {
			t.Errorf("Roots[1] (%s) Passed = false with no finding under it and a complete scan; "+
				"a reader cannot see which root caused the failure", audit.Roots[1].Directory)
		}
	})
}

// TestGenerateAuditReportForDirsTruncation pins that a truncated merged scan
// withholds the pass from every root and carries the truncation out, even though
// the findings it kept sit under one root only.
//
// The fixture is shaped so the second root has no visible finding at all: the
// cap is reached inside the first root, so the walk never reaches the second.
// That is the exact fail-open the completeness verdict exists to close — a root
// whose visible findings are zero must not be reported as passed when the scan
// stopped early, because the finding that would have failed it may be the one
// that was dropped.
func TestGenerateAuditReportForDirsTruncation(t *testing.T) {
	rootA := t.TempDir()
	writeTestFile(t, rootA, "a.py", manyHighFindings(3))
	rootB := t.TempDir()
	writeTestFile(t, rootB, "b.py", manyHighFindings(2))

	engine := regexEngine{scanner: truncatingScanner(3)}
	audit, err := GenerateAuditReportForDirs(context.Background(), []string{rootA, rootB},
		engine, LLMConfig{Policy: "assist"}, nil)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}

	if !audit.ScanMetadata.Truncated {
		t.Fatal("ScanMetadata.Truncated = false although the scan hit the finding cap")
	}
	if audit.ScanMetadata.ScanProvedClean {
		t.Error("ScanMetadata.ScanProvedClean = true for a truncated scan; a scan that dropped findings proved nothing")
	}

	total := 0
	for i, root := range audit.Roots {
		total += root.FindingsCount
		if root.Passed {
			t.Errorf("Roots[%d] (%s) Passed = true although the scan was truncated", i, root.Directory)
		}
	}
	if total != 3 {
		t.Errorf("findings across roots = %d, want exactly the cap (3)", total)
	}
	// The root the walk never reached carries no finding and must still not be
	// cleared: this is the assertion the completeness term exists for.
	if audit.Roots[1].FindingsCount != 0 {
		t.Fatalf("Roots[1] has %d findings; the fixture no longer exercises a root the truncated scan never reached",
			audit.Roots[1].FindingsCount)
	}
}

// TestGenerateAuditReportForDirsEmptyInputs preserves the empty-directory guard
// for the new entry point: an empty list and an empty element in the list are
// both the caller error one empty directory has always been, and the message is
// the same one a test asserts on.
func TestGenerateAuditReportForDirsEmptyInputs(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name string
		dirs []string
	}{
		{"nil list", nil},
		{"empty list", []string{}},
		{"an empty element", []string{dir, ""}},
		{"an empty first element", []string{"", dir}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GenerateAuditReportForDirs(context.Background(), tc.dirs,
				DefaultEngine(), LLMConfig{}, nil)
			if err == nil {
				t.Fatal("expected an error for an empty audit root")
			}
			if !strings.Contains(err.Error(), "audit directory is empty") {
				t.Errorf("error = %q, want it to carry the empty-directory wording", err.Error())
			}
		})
	}
}
