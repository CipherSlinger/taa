package mock

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newLLMHandlerRig(t *testing.T) (*fakeLLM, *llmStateStore, *taaLogStore, *llmPoller) {
	t.Helper()
	fake, poller, state, logs := newPollTestRig(t)
	return fake, state, logs, poller
}

func decodeLLMStatus(t *testing.T, rec *httptest.ResponseRecorder) (llmState, taaLogState) {
	t.Helper()
	var body struct {
		State llmState    `json:"state"`
		Logs  taaLogState `json:"logs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return body.State, body.Logs
}

func TestLLMStatusReportsPolledState(t *testing.T) {
	fake, state, logs, poller := newLLMHandlerRig(t)
	fake.setEntries([]llmLogPullEntry{{Seq: 1, Message: "hello"}})
	state.recordHeartbeat("m", 42, "teellm-3000000003")
	logs.addEntries("http://tt:6001", "run", "", []taaLogEntry{{Seq: 1, Message: "hello"}})

	rec := httptest.NewRecorder()
	llmStatusHandler(poller, state, logs)(rec, httptest.NewRequest(http.MethodGet, "/api/llm/status", nil))
	gotState, gotLogs := decodeLLMStatus(t, rec)

	if gotState.Model != "m" || gotState.Heartbeats != 1 {
		t.Errorf("state = %+v", gotState)
	}
	if len(gotLogs.Entries) != 1 {
		t.Errorf("logs = %+v", gotLogs)
	}
}

func TestLLMResetClearsStateAndLogs(t *testing.T) {
	fake, state, logs, poller := newLLMHandlerRig(t)
	fake.setEntries([]llmLogPullEntry{{Seq: 1, Message: "hello"}})
	poller.PollOnce(context.Background())

	rec := httptest.NewRecorder()
	llmResetHandler(state, logs)(rec, httptest.NewRequest(http.MethodPost, "/api/llm/reset", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := state.get(); got.Heartbeats != 0 || got.Reachable || got.LogCursor != 0 {
		t.Errorf("state after reset = %+v", got)
	}
	if entries := logs.get().Entries; len(entries) != 0 {
		t.Errorf("logs after reset = %+v", entries)
	}
}

// Clearing the log panel must not reset the read position: a cleared panel that
// immediately refills from the instance's buffer would look like the button did
// nothing.
func TestLLMLogsClearKeepsTheCursor(t *testing.T) {
	fake, state, logs, poller := newLLMHandlerRig(t)
	fake.setEntries([]llmLogPullEntry{{Seq: 1, Message: "hello"}, {Seq: 2, Message: "world"}})
	poller.PollOnce(context.Background())

	rec := httptest.NewRecorder()
	llmLogsClearHandler(state, logs)(rec, httptest.NewRequest(http.MethodPost, "/api/llm/logs/clear", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Result struct {
			Cleared int `json:"cleared"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Result.Cleared != 2 {
		t.Errorf("cleared = %d, want 2", body.Result.Cleared)
	}
	if entries := logs.get().Entries; len(entries) != 0 {
		t.Errorf("logs after clear = %+v", entries)
	}
	if got := state.get(); got.LogCursor != 2 || !got.Reachable {
		t.Errorf("state after clear = %+v, want the instance identity and cursor kept", got)
	}
}

func TestLLMPollHandlerRunsOnePoll(t *testing.T) {
	fake, state, _, poller := newLLMHandlerRig(t)
	fake.setEntries([]llmLogPullEntry{{Seq: 1, Message: "hello"}})

	rec := httptest.NewRecorder()
	llmPollNowHandler(poller)(rec, httptest.NewRequest(http.MethodPost, "/api/llm/poll", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := state.get(); got.Heartbeats != 1 || got.LogCursor != 1 {
		t.Errorf("state = %+v", got)
	}
}

func TestLLMAttestationHandlerStoresThePull(t *testing.T) {
	_, state, _, poller := newLLMHandlerRig(t)

	rec := httptest.NewRecorder()
	llmAttestationHandler(poller)(rec, httptest.NewRequest(http.MethodPost, "/api/llm/attestation", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := state.get().Attestation; got.RequestID != "req-1" || got.AttestationSize == 0 {
		t.Errorf("attestation = %+v", got)
	}
}

func TestLLMHandlersRejectTheWrongMethod(t *testing.T) {
	_, state, logs, poller := newLLMHandlerRig(t)
	cases := map[string]http.HandlerFunc{
		"/api/llm/reset":       llmResetHandler(state, logs),
		"/api/llm/logs/clear":  llmLogsClearHandler(state, logs),
		"/api/llm/poll":        llmPollNowHandler(poller),
		"/api/llm/attestation": llmAttestationHandler(poller),
	}
	for path, handler := range cases {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s GET status = %d, want 405", path, rec.Code)
		}
	}
}

func TestLLMLogStoreIsPerRun(t *testing.T) {
	logs := newTaaLogStoreAt(filepath.Join(t.TempDir(), "llm-log.json"), 10)
	// The same seq from a different run must not be mistaken for a duplicate:
	// that is how a restarted instance's first records survive the dedupe.
	if added := logs.addEntries("http://tt:6001", "run-1", "", []taaLogEntry{{Seq: 1, Message: "one"}}); added != 1 {
		t.Fatalf("first run added %d", added)
	}
	if added := logs.addEntries("http://tt:6001", "run-2", "", []taaLogEntry{{Seq: 1, Message: "one again"}}); added != 1 {
		t.Fatalf("second run added %d", added)
	}
	if added := logs.addEntries("http://tt:6001", "run-2", "", []taaLogEntry{{Seq: 1, Message: "one again"}}); added != 0 {
		t.Fatalf("replayed entry added %d, want 0", added)
	}
}
