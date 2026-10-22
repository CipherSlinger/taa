package codeaudit

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// TestScannerCancelStopsWalk pins the entry check: a context cancelled before
// the call returns context.Canceled instead of scanning the directory.
func TestScannerCancelStopsWalk(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.py", "import os\nos.system('x')\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := NewScanner(DefaultRules(), DefaultConfig()).ScanDirectoryWithLinesContext(ctx, dir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// cancelAfterCallsContext returns nil from Err for its first `allowed` calls and
// context.Canceled afterwards. It lets a test cancel between the scanner's entry
// check and its first walk callback without racing a goroutine or sleeping.
type cancelAfterCallsContext struct {
	context.Context
	mu      sync.Mutex
	calls   int
	allowed int
}

func (c *cancelAfterCallsContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls > c.allowed {
		return context.Canceled
	}
	return nil
}

// TestScannerCancelStopsMidWalk pins that the walk itself observes cancellation,
// not just the entry check: with a single allowed Err() call the entry passes and
// the first walk callback is cancelled before any file is read.
func TestScannerCancelStopsMidWalk(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.py", "import os\nos.system('x')\n")

	ctx := &cancelAfterCallsContext{Context: context.Background(), allowed: 1}

	report, lineCounts, err := NewScanner(DefaultRules(), DefaultConfig()).ScanDirectoryWithLinesContext(ctx, dir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if report != nil {
		t.Fatalf("a cancelled scan returned a report: %+v", report)
	}
	if len(lineCounts) != 0 {
		t.Fatalf("a cancelled scan returned line counts: %+v", lineCounts)
	}
}

// TestScannerContextMatchesPlainScan is the regression side: a live context
// produces the same report and line counts as the context-free entry point.
func TestScannerContextMatchesPlainScan(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.py", "import os\nos.system('x')\n")

	plain, plainLines, err := NewScanner(DefaultRules(), DefaultConfig()).ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctxReport, ctxLines, err := NewScanner(DefaultRules(), DefaultConfig()).ScanDirectoryWithLinesContext(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if plain.Passed != ctxReport.Passed || len(plain.Findings) != len(ctxReport.Findings) {
		t.Fatalf("context scan diverged: plain=%+v ctx=%+v", plain, ctxReport)
	}
	if len(plainLines) != len(ctxLines) {
		t.Fatalf("line counts diverged: plain=%d ctx=%d", len(plainLines), len(ctxLines))
	}
}
