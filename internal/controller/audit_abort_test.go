package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// TestModelImportReplacesAuditingModelAndAuditsAgain is the whole contract:
// the old audit is cancelled, the archive replaces ModelDir, and a new audit is
// launched under the new request ids, while the platform receives nothing for
// the aborted audit.
func TestModelImportReplacesAuditingModelAndAuditsAgain(t *testing.T) {
	state, server := setupTestServer(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)
	engine := newBlockingAuditEngine()
	state.Security.Engine = engine
	state.Security.ScanEnabled = true

	var mu sync.Mutex
	var auditReports []reportRequest
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == reportAuditEndpoint {
			var rr reportRequest
			_ = json.NewDecoder(r.Body).Decode(&rr)
			mu.Lock()
			auditReports = append(auditReports, rr)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	oldReq := importRequest{RequestID: "req-old", TaskID: "task-old"}
	state.mu.Lock()
	state.markModelAuditPendingLocked(oldReq, 1)
	state.saveModelSuccessLocked("https://example.test/old.tar.gz")
	state.mu.Unlock()
	state.launchModelAudit(oldReq)
	select {
	case <-engine.started:
	case <-time.After(5 * time.Second):
		t.Fatal("old audit did not start")
	}
	state.mu.RLock()
	oldDone := state.auditDone
	state.mu.RUnlock()
	if oldDone == nil {
		t.Fatal("the old audit registered no done channel")
	}

	// A file left behind by the previous model: the replacement must delete the
	// old tree, not merge the new package into it.
	oldFilePath := filepath.Join(state.Security.ModelDir, "bundle", "old.txt")
	if err := os.MkdirAll(filepath.Dir(oldFilePath), 0o755); err != nil {
		t.Fatalf("create old model dir: %v", err)
	}
	if err := os.WriteFile(oldFilePath, []byte("old model\n"), 0o644); err != nil {
		t.Fatalf("write old model file: %v", err)
	}

	archive := buildTarGzArchive(t, map[string]archiveEntry{
		"bundle/train.py": {mode: 0o755, data: []byte("print('new model')\n")},
	})
	ciphertext, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, archive)
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ciphertext)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   fileServer.URL + "/model-package.tar.gz?dataKeyCipher=" + keyHex,
		"requestId":     "req-new",
		"taskId":        "task-new",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3", "train.py"}, nil),
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model import during audit returned %d, want 200: %s", resp.StatusCode, api.Msg)
	}

	select {
	case <-engine.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("old audit was not cancelled")
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		state.mu.RLock()
		pending := state.pendingAudit
		newAuditRegistered := state.auditDone != nil && state.auditDone != oldDone
		state.mu.RUnlock()
		if pending != nil && pending.TaskID == "task-new" && newAuditRegistered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the new audit was not launched for the new model")
		}
		time.Sleep(10 * time.Millisecond)
	}

	got, err := os.ReadFile(filepath.Join(state.Security.ModelDir, "bundle", "train.py"))
	if err != nil {
		t.Fatalf("read replaced model: %v", err)
	}
	if !strings.Contains(string(got), "new model") {
		t.Fatalf("model directory was not replaced: %q", got)
	}
	if _, err := os.Stat(oldFilePath); !os.IsNotExist(err) {
		t.Fatalf("old model file survived the import: %v", err)
	}

	// The old audit goroutine is fully unwound before this check:
	// processImportedResource calls waitAuditStopped before registering the new
	// pending marker, and the loop above waits for that registration. Nothing is
	// therefore still in flight that could report the aborted audit.
	mu.Lock()
	for _, rr := range auditReports {
		if rr.RequestID == "req-old" || rr.TaskID == "task-old" {
			mu.Unlock()
			t.Fatalf("aborted audit was reported to the platform: %+v", rr)
		}
	}
	mu.Unlock()

	// Release the second blocking audit and wait for it, so it cannot outlive
	// the test's TempDir cleanup.
	state.abortModelAudit()
	state.waitAuditStopped()
}

// TestModelImportDownloadFailureAfterAbortRollsBack pins the failure path: the
// old audit has already been aborted when the download fails, the imported flag
// is rolled back, and no audit verdict is sent for the old model.
func TestModelImportDownloadFailureAfterAbortRollsBack(t *testing.T) {
	state, server := setupTestServer(t)
	engine := newBlockingAuditEngine()
	state.Security.Engine = engine
	state.Security.ScanEnabled = true

	var mu sync.Mutex
	var auditReports []reportRequest
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == reportAuditEndpoint {
			var rr reportRequest
			_ = json.NewDecoder(r.Body).Decode(&rr)
			mu.Lock()
			auditReports = append(auditReports, rr)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()
	state.mu.Lock()
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"
	state.ModelImported = true
	state.mu.Unlock()

	oldReq := importRequest{RequestID: "req-old", TaskID: "task-old"}
	state.mu.Lock()
	state.markModelAuditPendingLocked(oldReq, 1)
	state.mu.Unlock()
	state.launchModelAudit(oldReq)
	select {
	case <-engine.started:
	case <-time.After(5 * time.Second):
		t.Fatal("old audit did not start")
	}

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   fileServer.URL + "/missing.tar.gz",
		"requestId":     "req-new",
		"taskId":        "task-new",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3", "train.py"}, nil),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("download failure status = %d, want 500", resp.StatusCode)
	}

	select {
	case <-engine.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("old audit was not cancelled before the failed download")
	}
	state.waitAuditStopped()

	state.mu.RLock()
	imported := state.ModelImported
	state.mu.RUnlock()
	if imported {
		t.Fatal("ModelImported stayed true after the download failed")
	}

	mu.Lock()
	for _, rr := range auditReports {
		if rr.RequestID == "req-old" || rr.TaskID == "task-old" {
			mu.Unlock()
			t.Fatalf("aborted audit was reported to the platform: %+v", rr)
		}
	}
	mu.Unlock()
}
