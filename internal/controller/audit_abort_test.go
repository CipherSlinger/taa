package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"taa/internal/codeaudit"
)

// blockingAuditEngine blocks the audit's static scan until the audit context is
// cancelled. Every call blocks, so a test that starts two audits releases the
// second one explicitly.
type blockingAuditEngine struct {
	startedOnce sync.Once
	stoppedOnce sync.Once
	started     chan struct{}
	stopped     chan struct{}
}

func newBlockingAuditEngine() *blockingAuditEngine {
	return &blockingAuditEngine{
		started: make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

func (e *blockingAuditEngine) ScanDirectory(dir string) (*codeaudit.Report, error) {
	report, _, err := e.ScanDirectoryWithLinesContext(context.Background(), dir)
	return report, err
}

func (e *blockingAuditEngine) ScanDirectoryWithLines(dir string) (*codeaudit.Report, map[string]int, error) {
	return e.ScanDirectoryWithLinesContext(context.Background(), dir)
}

func (e *blockingAuditEngine) ScanDirectoryWithLinesContext(ctx context.Context, dir string) (*codeaudit.Report, map[string]int, error) {
	e.startedOnce.Do(func() { close(e.started) })
	<-ctx.Done()
	e.stoppedOnce.Do(func() { close(e.stopped) })
	return nil, nil, ctx.Err()
}

func (e *blockingAuditEngine) Name() string { return "blocking" }

// TestAbortModelAuditStopsTheRunningAudit pins that an abort cancels the scan,
// clears the durable pending marker, and leaves the audit fields idle.
func TestAbortModelAuditStopsTheRunningAudit(t *testing.T) {
	state, _ := setupTestState(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)
	state.Security.ScanEnabled = true
	engine := newBlockingAuditEngine()
	state.Security.Engine = engine

	req := importRequest{RequestID: "req-old", TaskID: "task-old"}
	state.mu.Lock()
	state.markModelAuditPendingLocked(req, 1)
	state.saveModelSuccessLocked("https://example.test/old.tar.gz")
	state.mu.Unlock()
	state.launchModelAudit(req)

	select {
	case <-engine.started:
	case <-time.After(5 * time.Second):
		t.Fatal("audit did not start")
	}

	state.abortModelAudit()

	select {
	case <-engine.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("audit did not stop after abort")
	}
	state.waitAuditStopped()

	state.mu.RLock()
	running := state.AuditRunning
	op := state.CurrentAuditOp
	taskID := state.ActiveAuditTaskID
	pending := state.pendingAudit
	state.mu.RUnlock()

	if running || op != "idle" || taskID != "" {
		t.Fatalf("audit state not reset: running=%v op=%s task=%s", running, op, taskID)
	}
	if pending != nil {
		t.Fatalf("pending audit marker survived abort: %+v", pending)
	}

	sealed, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if sealed.AuditPending != nil {
		t.Fatalf("the abort left a durable pending marker: %+v", sealed.AuditPending)
	}
}

// TestFinishAuditStaleGenerationKeepsTheNewAudit pins that the goroutine of an
// aborted audit cannot clear the state or the marker of the audit that replaced
// it.
func TestFinishAuditStaleGenerationKeepsTheNewAudit(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true

	state.mu.Lock()
	state.auditGen++
	oldGen := state.auditGen
	oldDone := make(chan struct{})
	state.auditDone = oldDone
	state.mu.Unlock()

	state.mu.Lock()
	state.auditGen++
	state.auditDone = make(chan struct{})
	state.auditCancel = func() {}
	state.markModelAuditPendingLocked(importRequest{RequestID: "req-new", TaskID: "task-new"}, 1)
	newDone := state.auditDone
	state.mu.Unlock()

	state.finishAudit(oldGen, oldDone)

	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.ActiveAuditTaskID != "task-new" || !state.AuditRunning {
		t.Fatalf("stale finish cleared the new audit state: running=%v task=%s",
			state.AuditRunning, state.ActiveAuditTaskID)
	}
	if state.pendingAudit == nil || state.pendingAudit.TaskID != "task-new" {
		t.Fatalf("stale finish cleared the new pending marker: %+v", state.pendingAudit)
	}
	// The identity check must leave the replacement audit's registration alone:
	// its channel and cancel func are what waitAuditStopped and abortModelAudit
	// will use.
	if state.auditDone == nil || state.auditDone != newDone {
		t.Fatalf("stale finish replaced the new audit's done channel: got %p, want %p", state.auditDone, newDone)
	}
	if state.auditCancel == nil {
		t.Fatal("stale finish cleared the new audit's cancel func")
	}
}

// TestAbortedAuditDoesNotReport pins the silent-abort decision: the old audit
// must not reach the platform, even though it was interrupted rather than
// completed.
func TestAbortedAuditDoesNotReport(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	engine := newBlockingAuditEngine()
	state.Security.Engine = engine

	reports := make(chan reportRequest, 4)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == reportAuditEndpoint {
			var rr reportRequest
			_ = json.NewDecoder(r.Body).Decode(&rr)
			reports <- rr
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	req := importRequest{RequestID: "req-old", TaskID: "task-old"}
	state.launchModelAudit(req)
	select {
	case <-engine.started:
	case <-time.After(5 * time.Second):
		t.Fatal("audit did not start")
	}

	state.abortModelAudit()
	state.waitAuditStopped()

	select {
	case rr := <-reports:
		t.Fatalf("aborted audit reported to the platform: %+v", rr)
	case <-time.After(300 * time.Millisecond):
	}
}
