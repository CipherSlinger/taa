package codeaudit

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
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

// blockingSemgrep replaces the process boundary with one that blocks until the
// context is cancelled, so the test can prove the adapter passes cancellation
// through rather than waiting for the CLI to finish.
type blockingSemgrep struct {
	called chan struct{}
}

func (b *blockingSemgrep) exec(ctx context.Context, _ string, _ []string) ([]byte, int, error) {
	close(b.called)
	<-ctx.Done()
	return nil, -1, ctx.Err()
}

// semgrepScanResult carries every return value of the context entry point, so a
// cancellation can be checked for partial output as well as for its error.
type semgrepScanResult struct {
	report     *Report
	lineCounts map[string]int
	err        error
}

// TestSemgrepCancelStopsTheRun pins that cancelling the audit context reaches
// the process boundary and returns promptly.
func TestSemgrepCancelStopsTheRun(t *testing.T) {
	scanDir := t.TempDir()
	writeTestFile(t, scanDir, "train.py", semgrepFixtureSource())
	rulesDir := t.TempDir()
	rulesPath := writeTestFile(t, rulesDir, "rules.yaml", "rules: []\n")

	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), rulesPath, SemgrepLimits{})
	stub := &blockingSemgrep{called: make(chan struct{})}
	engine.execFn = stub.exec

	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan semgrepScanResult, 1)
	go func() {
		report, lineCounts, err := engine.ScanDirectoryWithLinesContext(ctx, scanDir)
		results <- semgrepScanResult{report: report, lineCounts: lineCounts, err: err}
	}()

	select {
	case <-stub.called:
	case <-time.After(5 * time.Second):
		t.Fatal("semgrep exec was never reached, so cancellation could not be observed")
	}
	cancel()

	select {
	case res := <-results:
		if !errors.Is(res.err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", res.err)
		}
		if res.report != nil {
			t.Fatalf("a cancelled scan returned a report: %+v", res.report)
		}
		if res.lineCounts != nil {
			t.Fatalf("a cancelled scan returned line counts: %+v", res.lineCounts)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("semgrep scan did not stop after cancellation")
	}
}

// TestBinaryScannerCancelStopsWalk pins that cancellation is observed inside the
// walk and not only at the entry: the entry check and the root-directory callback
// both pass, and the file's callback observes the cancellation before the file is
// read. With the callback check removed the walk runs to completion, the post-walk
// check is still passing the allowed calls, and the scan returns a full result
// with no error - so the assertions below discriminate the two paths.
func TestBinaryScannerCancelStopsWalk(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "blob.bin", "\x7fELF")

	ctx := &cancelAfterCallsContext{Context: context.Background(), allowed: 2}

	res, err := NewBinaryScanner(nil, BinaryConfig{}).ScanDirectoryContext(ctx, dir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res != nil {
		t.Fatalf("a cancelled scan returned a result: %+v", res)
	}
}

// cancelingEngine is a StaticEngine stub that cancels the audit's context during
// the source scan, so GenerateAuditReport's post-binary cancellation exit is what
// stops the audit before the LLM phases. The embedded interface supplies the rest
// of the contract without hand-written forwards.
type cancelingEngine struct {
	StaticEngine
	cancel func()
}

func (e *cancelingEngine) ScanDirectoryWithLinesContext(_ context.Context, dir string) (*Report, map[string]int, error) {
	e.cancel()
	file := filepath.Join(dir, "train.py")
	return &Report{
		ScanComplete: true,
		Findings: []Finding{{
			File:     file,
			Line:     1,
			RuleID:   "TEST_001",
			Severity: SeverityHigh,
		}},
	}, map[string]int{file: 1}, nil
}

// Name is overridden because the embedded interface is nil: a promoted method
// would dereference it.
func (e *cancelingEngine) Name() string { return "canceling" }

// TestGenerateAuditReportStopsOnScanCancellation pins the exit that follows the
// binary pass: when the source scan cancels the audit context, GenerateAuditReport
// returns the cancellation rather than a report, and the LLM phases never run.
// The scan reports one finding so that a run which did reach Phase 2 would have a
// finding to adjudicate, and the mock carries a decision so that adjudication
// would be counted rather than silently answered without a call.
func TestGenerateAuditReportStopsOnScanCancellation(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\nos.system('x')\n")

	ctx, cancel := context.WithCancel(context.Background())
	engine := &cancelingEngine{cancel: cancel}
	client := &mockLLMClient{decisions: []LLMDecision{{Verdict: "BENIGN", Reason: "test decision"}}}

	audit, err := GenerateAuditReport(ctx, dir, engine, AuditConfig{LLM: LLMConfig{Enabled: true}}, client)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if audit != nil {
		t.Fatalf("a cancelled audit returned a report: %+v", audit)
	}
	if client.callCount != 0 || client.fileCallCount != 0 {
		t.Fatalf("the LLM was called after cancellation: verify=%d file=%d",
			client.callCount, client.fileCallCount)
	}
}
