package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestImportDepsRejectsEmptyResourceURL(t *testing.T) {
	_, server := setupTestServer(t)

	resp := postJSON(t, server.URL+"/v1/taa/importDeps", map[string]any{
		"resourceUrl": "",
		"requestId":   "req-1",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestImportDepsRejectsMissingTaskAndRequestID(t *testing.T) {
	_, server := setupTestServer(t)

	resp := postJSON(t, server.URL+"/v1/taa/importDeps", map[string]any{
		"resourceUrl": "http://127.0.0.1:1/deps.tar.gz",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestImportDepsRejectsNonPost(t *testing.T) {
	_, server := setupTestServer(t)

	resp, err := http.Get(server.URL + "/v1/taa/importDeps")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

// waitForDepsSlotRelease polls until the task slot taken by importDeps is fully released.
// Both fields are checked because release() clears them together under a single lock hold; a
// leaked slot (a dropped release() call) leaves CurrentOp pinned at "deps_importing" and would
// otherwise turn every later import into a permanent 409 with no test noticing.
// It does not reuse waitForIdle, which only inspects CurrentOp.
func waitForDepsSlotRelease(t *testing.T, state *TAAState) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state.mu.RLock()
		released := state.CurrentOp == "idle" && state.ActiveTaskID == ""
		state.mu.RUnlock()
		if released {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the importDeps task slot to be released")
}

// TestImportDepsDownloadFailureReleasesTaskSlot covers the one synchronous path the other tests
// skip: the request passes parameter validation and acquires the task slot, then the download
// fails. The handler must answer 500 and still hand the slot back.
func TestImportDepsDownloadFailureReleasesTaskSlot(t *testing.T) {
	state, server := setupTestServer(t)

	// Loopback is exempt from ProxyFromEnvironment and port 1 refuses immediately, so the
	// download fails at once with an error carrying no pkgerrors code, giving the handler's
	// 500 branch.
	resp := postJSON(t, server.URL+"/v1/taa/importDeps", map[string]any{
		"resourceUrl": "http://127.0.0.1:1/deps.tar.gz",
		"requestId":   "req-download-failure",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (msg=%q)", resp.StatusCode, api.Msg)
	}

	waitForDepsSlotRelease(t, state)
}

// TestImportDepsSuccessReleasesTaskSlot covers the happy path end to end against a local file
// server: 200, the expected message, and the slot released afterwards.
func TestImportDepsSuccessReleasesTaskSlot(t *testing.T) {
	state, server := setupTestServer(t)

	archive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fake wheelhouse bytes"))
	}))
	t.Cleanup(archive.Close)

	resp := postJSON(t, server.URL+"/v1/taa/importDeps", map[string]any{
		"resourceUrl": archive.URL + "/deps.tar.gz",
		"requestId":   "req-success",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (msg=%q)", resp.StatusCode, api.Msg)
	}
	if api.Msg != "依赖包已接收，处理中" {
		t.Fatalf("msg = %q, want %q", api.Msg, "依赖包已接收，处理中")
	}

	// The envelope is written before runAsyncSafe launches the goroutine, so the slot may
	// still be held here; poll rather than assert immediately.
	waitForDepsSlotRelease(t, state)
}
