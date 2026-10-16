package fhe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, srv
}

func TestNewClientRejectsBadEndpoint(t *testing.T) {
	for _, bad := range []string{"", "   ", "127.0.0.1:58996", "ftp://host/api", "http://"} {
		if _, err := NewClient(bad, time.Second); err == nil {
			t.Errorf("NewClient(%q) = nil error, want error", bad)
		}
	}
}

func TestNewClientAcceptsEndpointWithOrWithoutPrefix(t *testing.T) {
	for _, raw := range []string{"http://h:1", "http://h:1/", "http://h:1/api/v1"} {
		c, err := NewClient(raw, time.Second)
		if err != nil {
			t.Fatalf("NewClient(%q): %v", raw, err)
		}
		if c.baseURL != "http://h:1/api/v1" {
			t.Errorf("NewClient(%q).baseURL = %q, want %q", raw, c.baseURL, "http://h:1/api/v1")
		}
	}
}

func TestCreateTaskSendsUserHeaderAndBody(t *testing.T) {
	var gotBody map[string]any
	var gotUser string

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tasks" {
			t.Errorf("path = %q, want /api/v1/tasks", r.URL.Path)
		}
		gotUser = r.Header.Get("X-User-Id")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"task_id":"task-1","status":"queued"}`))
	})

	req := CreateTaskRequest{
		UserID:             testHashA,
		ModelID:            testHashB,
		TaskID:             "task-1",
		CallbackURL:        "http://taa/v1/taa/fheCallback?token=x",
		CancelOnDisconnect: false,
	}
	if err := c.CreateTask(context.Background(), req); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if gotUser != testHashA {
		t.Errorf("X-User-Id = %q, want %q", gotUser, testHashA)
	}
	for k, want := range map[string]any{
		"user_id": testHashA, "model_id": testHashB, "task_id": "task-1",
		"callback_url": "http://taa/v1/taa/fheCallback?token=x", "cancel_on_disconnect": false,
	} {
		if got := gotBody[k]; got != want {
			t.Errorf("body[%q] = %v, want %v", k, got, want)
		}
	}
}

func TestCreateTaskSurfacesNon2xx(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	err := c.CreateTask(context.Background(), CreateTaskRequest{TaskID: "t", UserID: testHashA})
	if err == nil {
		t.Fatal("CreateTask = nil, want error")
	}
	var apiErr *APIError
	if !asAPIError(err, &apiErr) {
		t.Fatalf("error %v is not an *APIError", err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Error(), "boom") {
		t.Errorf("error %q does not carry the response body", apiErr.Error())
	}
}

func TestTaskParsesCasesAndProgress(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tasks/task-1" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"task_id":"task-1","status":"running","cases":[
			{"entry":"case-00.ct","result_id":"case-00.result.bin"},
			{"entry":"case-01.ct"},
			{"entry":"case-02.ct","error":"oops"}]}`))
	})
	st, err := c.Task(context.Background(), "task-1", testHashA)
	if err != nil {
		t.Fatalf("Task: %v", err)
	}
	if st.Status != "running" {
		t.Errorf("Status = %q, want running", st.Status)
	}
	done, total := st.Progress()
	if done != 2 || total != 3 {
		t.Errorf("Progress() = (%d, %d), want (2, 3)", done, total)
	}
	if failed := st.Failed(); failed != 1 {
		t.Errorf("Failed() = %d, want 1", failed)
	}
}

func TestTaskToleratesUnknownShape(t *testing.T) {
	// The per-case shape on GET /tasks/{id} is not documented. An unrecognised
	// body must still yield the status, and progress must degrade to (0, 0)
	// rather than fail the call.
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"task_id":"task-1","status":"completed","whatever":{"nested":true}}`))
	})
	st, err := c.Task(context.Background(), "task-1", testHashA)
	if err != nil {
		t.Fatalf("Task: %v", err)
	}
	if st.Status != "completed" {
		t.Errorf("Status = %q, want completed", st.Status)
	}
	if done, total := st.Progress(); done != 0 || total != 0 {
		t.Errorf("Progress() = (%d, %d), want (0, 0)", done, total)
	}
}

func TestTaskFallsBackToResultsKey(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"completed","results":[{"entry":"a","result_id":"a.bin"}]}`))
	})
	st, err := c.Task(context.Background(), "task-1", testHashA)
	if err != nil {
		t.Fatalf("Task: %v", err)
	}
	if done, total := st.Progress(); done != 1 || total != 1 {
		t.Errorf("Progress() = (%d, %d), want (1, 1)", done, total)
	}
}

func TestActivateModelAndHealth(t *testing.T) {
	var activateQuery string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/models/activate":
			activateQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})
	ctx := context.Background()
	if err := c.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if err := c.ActivateModel(ctx, testHashB); err != nil {
		t.Fatalf("ActivateModel: %v", err)
	}
	if activateQuery != "model_id="+testHashB {
		t.Errorf("activate query = %q, want %q", activateQuery, "model_id="+testHashB)
	}
}

func TestCancelAndContinue(t *testing.T) {
	var paths []string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		_, _ = w.Write([]byte(`{}`))
	})
	ctx := context.Background()
	if err := c.CancelTask(ctx, "task-1", testHashA); err != nil {
		t.Fatalf("CancelTask: %v", err)
	}
	if err := c.ContinueTask(ctx, "task-1", testHashA); err != nil {
		t.Fatalf("ContinueTask: %v", err)
	}
	want := []string{"POST /api/v1/tasks/task-1/cancel", "POST /api/v1/tasks/task-1/continue"}
	if len(paths) != 2 || paths[0] != want[0] || paths[1] != want[1] {
		t.Errorf("paths = %v, want %v", paths, want)
	}
}

func TestDownloadResultWritesFile(t *testing.T) {
	payload := []byte("zip-bytes")
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tasks/task-1/results/download" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write(payload)
	})
	dst := filepath.Join(t.TempDir(), "out", "output.zip")
	if err := c.DownloadResult(context.Background(), "task-1", testHashA, dst); err != nil {
		t.Fatalf("DownloadResult: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("result = %q, want %q", got, payload)
	}
}

func TestIsTerminalAndIsSuccess(t *testing.T) {
	terminal := []string{"completed", "succeeded", "failed", "error", "cancelled", "canceled", "timeout", "expired", " COMPLETED "}
	for _, s := range terminal {
		if !IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "queued", "running", "pending", "unknown"} {
		if IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = true, want false", s)
		}
	}
	for _, s := range []string{"completed", "succeeded", "SUCCESS"} {
		if !IsSuccess(s) {
			t.Errorf("IsSuccess(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"failed", "cancelled", ""} {
		if IsSuccess(s) {
			t.Errorf("IsSuccess(%q) = true, want false", s)
		}
	}
}
