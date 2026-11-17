package controller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestStopTrainingDuringDownloadCancelsTheImport covers the window that had no
// stop at all: the task is acquired and the bytes are still arriving, so no
// model process exists yet.
//
// Before the stop handle was created at acquisition, this stop was answered
// "不存在训练任务" - truthfully, nothing was training - and the import ran on to
// training afterwards. The handle now exists for the whole task, so the stop
// reaches the download and the pipeline never starts the runs.
func TestStopTrainingDuringDownloadCancelsTheImport(t *testing.T) {
	state, server := setupTestServer(t)
	state.mu.Lock()
	state.CurrentPhase = 1
	state.mu.Unlock()

	downloadStarted := make(chan struct{})
	releaseDownload := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseDownload) }) }
	resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(downloadStarted)
		select {
		case <-releaseDownload:
		case <-r.Context().Done():
		}
	}))
	defer resourceServer.Close()
	// A parked handler holds the stub server's Close open; releasing it on every
	// exit path keeps a failing assertion from hanging the test.
	t.Cleanup(release)

	type result struct {
		statusCode int
		api        apiResponse
	}
	importResult := make(chan result, 1)
	go func() {
		resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": resourceServer.URL + "/data.tar.gz",
			"requestId":   "req-stop-download",
			"taskId":      "task-stop-download",
		})
		importResult <- result{statusCode: resp.StatusCode, api: decodeResponse(t, resp)}
	}()

	select {
	case <-downloadStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the import never reached its download")
	}

	resp := postEmptyJSON(t, server.URL+"/v1/taa/stopTraining")
	stopAPI := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || stopAPI.Error != 0 {
		t.Fatalf("stop: status=%d error=%d msg=%q", resp.StatusCode, stopAPI.Error, stopAPI.Msg)
	}
	if stopAPI.Msg != "任务已中止" {
		t.Fatalf("stop msg = %q, want '任务已中止': nothing was training yet, but the task was in flight", stopAPI.Msg)
	}

	// The download ends when the cancellation reaches it, not when the stub
	// releases it: releasing here only matters for the test's own cleanup.
	release()

	var importReply result
	select {
	case importReply = <-importResult:
	case <-time.After(5 * time.Second):
		t.Fatal("the import handler did not return after the stop cancelled its download")
	}
	if importReply.statusCode != http.StatusOK || importReply.api.Error != 0 {
		t.Fatalf("import reply after stop: status=%d error=%d msg=%q", importReply.statusCode, importReply.api.Error, importReply.api.Msg)
	}
	if importReply.api.Msg != "任务已中止" {
		t.Fatalf("import msg after stop = %q, want '任务已中止'", importReply.api.Msg)
	}

	// The task released its acquisition, and nothing was left sealed as imported.
	deadline := time.Now().Add(5 * time.Second)
	for {
		state.mu.RLock()
		idle := state.CurrentOp == "idle"
		settled := state.activeTask == nil
		control := state.trainingControl
		state.mu.RUnlock()
		if idle && settled && control == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the stopped task did not settle: op=%q activeTask=%v control=%v", state.CurrentOp, settled, control != nil)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Nothing may be reported to the platform for a task the platform stopped.
	// The test state points PlatformIP at an unreachable address, so a report
	// would only block; what is checked instead is that the import index holds no
	// committed record.
	store, err := state.importIndexStore()
	if err != nil {
		t.Fatalf("importIndexStore: %v", err)
	}
	if _, ok := store.LookupByTaskID("task-stop-download"); ok {
		t.Fatal("a stopped import left a committed record in the import index")
	}
}

// TestStopTrainingDuringStagingDoesNotStartTraining covers a stop that lands in
// the window between the download and the training gate: the import itself is
// clean, and the task is answered by the training gate refusing to promote it.
func TestStopTrainingDuringStagingDoesNotStartTraining(t *testing.T) {
	state, server := setupTestServer(t)
	state.mu.Lock()
	state.CurrentPhase = 1
	state.mu.Unlock()

	release, err := state.tryAcquireTask("task-stop-staging-import", "req-stop-staging-import", "downloading", false)
	if err != nil {
		t.Fatalf("tryAcquireTask: %v", err)
	}

	resp := postEmptyJSON(t, server.URL+"/v1/taa/stopTraining")
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 || api.Msg != "任务已中止" {
		t.Fatalf("stop: status=%d error=%d msg=%q, want 200/0/'任务已中止'", resp.StatusCode, api.Error, api.Msg)
	}

	// The pipeline's first action is the check this asserts on: a stopped import
	// unwinds without landing the data, committing an index record or training.
	state.mu.Lock()
	state.ModelImported = true
	state.mu.Unlock()
	plaintext := filepath.Join(t.TempDir(), "data.txt")
	if err := os.WriteFile(plaintext, []byte("data\n"), 0o644); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	state.processImportedResource(importRequest{
		TaskID:    "task-stop-staging-import",
		RequestID: "req-stop-staging-import",
	}, 1, false, plaintext, nil)
	release()

	store, err := state.importIndexStore()
	if err != nil {
		t.Fatalf("importIndexStore: %v", err)
	}
	if _, ok := store.LookupByTaskID("task-stop-staging-import"); ok {
		t.Fatal("a stopped import committed an index record")
	}
	state.mu.RLock()
	op := state.CurrentOp
	training := state.TrainingRunning
	state.mu.RUnlock()
	if op != "idle" {
		t.Fatalf("currentOp = %q, want 'idle'", op)
	}
	if training {
		t.Fatal("a stopped import must not enter training")
	}
}
