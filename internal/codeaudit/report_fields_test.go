package codeaudit

import (
	"strings"
	"testing"
	"time"
)

// truncatingScanner builds a scanner with a small finding cap so that
// truncation can be reached with a two-line fixture.
func truncatingScanner(maxFindings int) *Scanner {
	cfg := DefaultConfig()
	cfg.MaxFindings = maxFindings
	return NewScanner(DefaultRules(), cfg)
}

// manyHighFindings returns Python source with n independent HIGH-finding lines.
// Shell execution is used because CMD_001 fires on each line separately.
func manyHighFindings(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("subprocess.run(cmd, shell=True)\n")
	}
	return b.String()
}

// TestScanDirectoryRecordsTruncation pins that hitting the finding cap is
// reported rather than silent.
//
// scanner.go truncates to Config.MaxFindings and stops walking with
// filepath.SkipAll. It used to record nothing at all, so the only way to tell a
// truncated scan from a complete one was to count findings and guess: a report
// whose findings stop exactly at the cap is indistinguishable from one that
// legitimately produced that many. The consequence is a silent allow, because
// every HIGH past the cap is dropped and Passed is computed from what remains.
func TestScanDirectoryRecordsTruncation(t *testing.T) {
	t.Run("at the cap", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, dir, "many.py", manyHighFindings(5))

		report, err := truncatingScanner(2).ScanDirectory(dir)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !report.Truncated {
			t.Error("Truncated = false after hitting the finding cap; the scan silently dropped findings")
		}
		if len(report.Findings) != 2 {
			t.Errorf("len(Findings) = %d, want 2 (the cap)", len(report.Findings))
		}
	})

	t.Run("below the cap", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, dir, "few.py", manyHighFindings(2))

		report, err := truncatingScanner(10).ScanDirectory(dir)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if report.Truncated {
			t.Error("Truncated = true on a scan that never reached the cap")
		}
		// The count equalling a different cap must not be what sets the flag.
		if len(report.Findings) != 2 {
			t.Errorf("len(Findings) = %d, want 2", len(report.Findings))
		}
	})

	t.Run("does not leak across scans on one scanner", func(t *testing.T) {
		// DefaultScanner is a process-wide singleton, so a truncation flag kept
		// on the Scanner rather than in the walk would survive into the next
		// call and mark a clean scan as truncated. The flag is a local, and
		// this pins that.
		scanner := truncatingScanner(2)
		bad := t.TempDir()
		writeTestFile(t, bad, "many.py", manyHighFindings(5))
		good := t.TempDir()
		writeTestFile(t, good, "few.py", manyHighFindings(1))

		first, err := scanner.ScanDirectory(bad)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !first.Truncated {
			t.Fatal("first scan should have truncated")
		}
		second, err := scanner.ScanDirectory(good)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if second.Truncated {
			t.Error("Truncated leaked from the previous scan into an untruncated one")
		}
	})
}

// TestScanDirectoryWithLinesRecordsTruncation is the same contract for the
// entry point GenerateAuditReport uses. Both call sites truncate, so both have
// to report it; a flag set on only one of them would be worse than none,
// because it would look trustworthy.
func TestScanDirectoryWithLinesRecordsTruncation(t *testing.T) {
	t.Run("at the cap", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, dir, "many.py", manyHighFindings(5))

		report, _, err := truncatingScanner(2).ScanDirectoryWithLines(dir)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !report.Truncated {
			t.Error("Truncated = false after hitting the finding cap")
		}
	})

	t.Run("below the cap", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, dir, "few.py", manyHighFindings(1))

		report, _, err := truncatingScanner(10).ScanDirectoryWithLines(dir)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if report.Truncated {
			t.Error("Truncated = true on a scan that never reached the cap")
		}
	})
}

// TestRegexEnginePopulatesEngineIdentity pins the fields the regex engine is
// responsible for filling in.
//
// ScanComplete is the dangerous one. Its zero value is false, which reads as
// "the scan did not complete", and the regex engine always completes: it is a
// synchronous in-memory match with no parser and no subprocess. Leaving the
// field unset would therefore report every regex scan as incomplete, so the
// engine sets it explicitly rather than relying on the zero value.
func TestRegexEnginePopulatesEngineIdentity(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "subprocess.run(cmd, shell=True)\n")

	t.Run("ScanDirectory", func(t *testing.T) {
		report, err := DefaultEngine().ScanDirectory(dir)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if report.Engine != EngineNameRegex {
			t.Errorf("Engine = %q, want %q", report.Engine, EngineNameRegex)
		}
		if !report.ScanComplete {
			t.Error("ScanComplete = false; the regex engine always completes its scan")
		}
		if report.Truncated {
			t.Error("Truncated = true on a two-line fixture")
		}
	})

	t.Run("ScanDirectoryWithLines", func(t *testing.T) {
		report, _, err := DefaultEngine().ScanDirectoryWithLines(dir)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if report.Engine != EngineNameRegex {
			t.Errorf("Engine = %q, want %q", report.Engine, EngineNameRegex)
		}
		if !report.ScanComplete {
			t.Error("ScanComplete = false; the regex engine always completes its scan")
		}
	})
}

// TestAuditMetadataCarriesEngineProvenance pins that the engine identity and the
// completeness fields reach the report production writes.
//
// These fields exist so a report can prove how it was produced. A field that is
// set on the scan report but never copied into the audit report is write-only,
// and the project has already been through that once: the benchmark matrix's
// engine field was inferred from a mode name and its only effect was to be
// quoted by later readers. The audit report is what leaves the process, so this
// is where the provenance has to land.
func TestAuditMetadataCarriesEngineProvenance(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "subprocess.run(cmd, shell=True)\n")

	scanReport, lineCounts, err := DefaultEngine().ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	audit := AssembleAuditReport(dir, scanReport,
		[]FileReport{BuildFileReport("train.py", scanReport.Findings)},
		lineCounts, LLMConfig{Policy: "assist"}, 10*time.Millisecond)

	if audit.ScanMetadata.Engine != EngineNameRegex {
		t.Errorf("ScanMetadata.Engine = %q, want %q; the report cannot prove which engine produced it",
			audit.ScanMetadata.Engine, EngineNameRegex)
	}
	if !audit.ScanMetadata.ScanComplete {
		t.Error("ScanMetadata.ScanComplete = false for a completed regex scan")
	}
	if audit.ScanMetadata.Truncated {
		t.Error("ScanMetadata.Truncated = true on a two-line fixture")
	}
}

// TestAuditMetadataCarriesTruncation is the other direction: a truncated scan
// must say so in the report that leaves the process, not only in the scan
// report that stays inside it.
func TestAuditMetadataCarriesTruncation(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "many.py", manyHighFindings(5))

	scanReport, lineCounts, err := truncatingScanner(2).ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !scanReport.Truncated {
		t.Fatal("fixture did not truncate; the assertion below would be vacuous")
	}

	audit := AssembleAuditReport(dir, scanReport, nil, lineCounts, LLMConfig{Policy: "assist"}, 10*time.Millisecond)

	if !audit.ScanMetadata.Truncated {
		t.Error("ScanMetadata.Truncated = false although the scan hit the finding cap; " +
			"findings were dropped and the report does not say so")
	}
}
