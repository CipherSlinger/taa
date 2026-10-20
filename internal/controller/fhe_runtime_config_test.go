package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"taa/internal/fhe"
)

// newFHEHandlerTestState builds a TAAState whose fheEnabled is true, on top of
// the regular test state so that the log store and directories exist. Only the
// runner pointer decides the instance type - see fheEnabled.
func newFHEHandlerTestState(t *testing.T) *TAAState {
	t.Helper()
	state, _ := setupTestState(t)
	runner, err := fhe.New(fhe.Config{
		Endpoint:        "http://127.0.0.1:58996",
		DataDir:         t.TempDir(),
		KeyCacheDir:     t.TempDir(),
		CallbackBaseURL: "http://127.0.0.1:6001",
		MaxEvalKeyBytes: fhe.DefaultMaxEvalKeyBytes,
		PollInterval:    fhe.DefaultPollInterval,
		RequestTimeout:  fhe.DefaultRequestTimeout,
		TaskTimeout:     fhe.DefaultTaskTimeout,
	}, nil)
	if err != nil {
		t.Fatalf("fhe.New: %v", err)
	}
	state.SetFHERunner(runner)
	return state
}

// postModelImport calls the model endpoint directly, without the HTTP server:
// the runtimeConfig-only branch answers before any download, so no delivery
// machinery has to run for these cases.
func postModelImport(t *testing.T, state *TAAState, body map[string]any) (int, apiResponse) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/importModel", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	state.modelImportHandler(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	var api apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp.StatusCode, api
}

// An fhe instance serves the model through the fhe runner, so runtimeConfig is
// never read there. Accepting an empty one is the point: the platform may send
// the model dispatch without any command line at all, and the update of the
// imported flag must still land.
func TestFHEModelImportAcceptsEmptyRuntimeConfig(t *testing.T) {
	state := newFHEHandlerTestState(t)
	state.mu.Lock()
	state.SavedModelResourceURL = "http://platform.example/files/previous-model.tar.gz"
	state.mu.Unlock()

	for _, tc := range []struct {
		name          string
		runtimeConfig string
	}{
		{"absent", ""},
		{"invalid json", "{not json"},
		{"empty commands", `{"commands":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"requestId": "req-fhe-runtime-config",
				"taskId":    "task-fhe-runtime-config",
			}
			if tc.runtimeConfig != "" {
				body["runtimeConfig"] = tc.runtimeConfig
			}

			status, api := postModelImport(t, state, body)
			if status != http.StatusOK || api.Error != 0 {
				t.Fatalf("status=%d error=%d msg=%s, want 200: an fhe instance does not act on runtimeConfig",
					status, api.Error, api.Msg)
			}

			state.mu.RLock()
			imported := state.ModelImported
			state.mu.RUnlock()
			if !imported {
				t.Fatal("ModelImported = false after a runtimeConfig-only dispatch was accepted")
			}
		})
	}
}

// The tee instance still runs the training command, so the same request keeps
// its 400. This pins the instance-type split: a change that accepted the empty
// config everywhere would pass the fhe test above and break the tee contract.
func TestTEEModelImportStillRejectsEmptyRuntimeConfig(t *testing.T) {
	state, _ := setupTestState(t)
	state.mu.Lock()
	state.SavedModelResourceURL = "http://platform.example/files/previous-model.tar.gz"
	state.mu.Unlock()

	status, api := postModelImport(t, state, map[string]any{
		"requestId": "req-tee-runtime-config",
		"taskId":    "task-tee-runtime-config",
	})
	if status != http.StatusBadRequest || api.Error == 0 {
		t.Fatalf("status=%d error=%d msg=%s, want 400 for a tee instance with no runtimeConfig",
			status, api.Error, api.Msg)
	}
	if !strings.Contains(api.Msg, "runtimeConfig 不能为空") {
		t.Fatalf("msg = %q, want it to name the missing runtimeConfig", api.Msg)
	}

	state.mu.RLock()
	imported := state.ModelImported
	state.mu.RUnlock()
	if imported {
		t.Fatal("a rejected dispatch must not mark the model imported")
	}
}
