package fhe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	return newTestClientWithTimeout(t, 5*time.Second, h)
}

func newTestClientWithTimeout(t *testing.T, timeout time.Duration, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, timeout)
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
	if !errors.As(err, &apiErr) {
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

// TestDownloadResultOutlivesTheRequestTimeout pins the one thing the download
// client must not inherit: the per-request timeout. http.Client.Timeout covers
// reading the body, so a client bounded by requestTimeout aborts a
// multi-gigabyte transfer mid-stream even though the caller's context still
// allows it - and this test uses 150 ms and a few hundred bytes to stand in for
// 30 s and 3 GiB. Verified by reverting the download client to the unary one:
// the error is "context deadline exceeded (Client.Timeout or context
// cancellation while reading body)".
func TestDownloadResultOutlivesTheRequestTimeout(t *testing.T) {
	payload := bytes.Repeat([]byte("chunk-"), 6)
	c, _ := newTestClientWithTimeout(t, 150*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flush(w)
		for i := 0; i < len(payload); i += 6 {
			time.Sleep(50 * time.Millisecond)
			if _, err := w.Write(payload[i : i+6]); err != nil {
				return
			}
			flush(w)
		}
	})

	dst := filepath.Join(t.TempDir(), "output.zip")
	// No deadline on the context: only the client's own timeout could stop this.
	if err := c.DownloadResult(context.Background(), "task-1", testHashA, dst); err != nil {
		t.Fatalf("DownloadResult: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("result is %d bytes, want the complete %d-byte payload", len(got), len(payload))
	}
}

// TestDownloadResultHonoursTheCallerContext proves the download is still bounded
// by something: removing the whole-request timeout must not remove every
// deadline, because the committed runner passes a context it bounds itself.
func TestDownloadResultHonoursTheCallerContext(t *testing.T) {
	c, _ := newTestClientWithTimeout(t, time.Minute, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flush(w)
		<-r.Context().Done() // the body never arrives
	})

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := c.DownloadResult(ctx, "task-1", testHashA, filepath.Join(dir, "output.zip"))
	if err == nil {
		t.Fatal("DownloadResult = nil, want the caller's deadline to abort it")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v does not wrap context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "task-1") {
		t.Errorf("error %q does not name the task", err)
	}
	if entries, readErr := os.ReadDir(dir); readErr == nil && len(entries) != 0 {
		t.Errorf("a failed download left %d files behind, want none", len(entries))
	}
}

// TestDownloadResultErrorNamesTaskDstAndBytes covers the diagnosability of a
// truncated transfer: "unexpected EOF" alone says nothing about which of a
// service's concurrent tasks produced it, where it was going, or how much
// arrived - and the byte count is the one number that tells a 3 GiB transfer
// truncated at the end from one that never started.
func TestDownloadResultErrorNamesTaskDstAndBytes(t *testing.T) {
	c, _ := newTestClientWithTimeout(t, time.Minute, func(w http.ResponseWriter, r *http.Request) {
		// Promise 100 bytes and deliver 10, so the client sees an unexpected EOF.
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0123456789"))
	})

	dst := filepath.Join(t.TempDir(), "out", "output.zip")
	err := c.DownloadResult(context.Background(), "task-1", testHashA, dst)
	if err == nil {
		t.Fatal("DownloadResult = nil, want an error for a truncated body")
	}
	for _, want := range []string{"task-1", dst, "10 bytes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not carry %q", err, want)
		}
	}
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Error("a truncated download must not leave dst behind: file exists means file complete")
	}
}

// TestConcurrentDownloadsDoNotShareATempFile runs two downloads of one task into
// one destination. The staging file is per-attempt, so neither can truncate the
// other's bytes; the served payloads differ, which is what a shared staging file
// would mix into a file that is neither one.
func TestConcurrentDownloadsDoNotShareATempFile(t *testing.T) {
	const half = 32 << 10
	var mu sync.Mutex
	arrived := 0
	var counter int32
	gate := make(chan struct{})
	c, _ := newTestClientWithTimeout(t, time.Minute, func(w http.ResponseWriter, r *http.Request) {
		fill := byte('a' + atomic.AddInt32(&counter, 1) - 1)
		block := bytes.Repeat([]byte{fill}, half)
		w.WriteHeader(http.StatusOK)
		flush(w)
		if _, err := w.Write(block); err != nil {
			return
		}
		flush(w)
		// Hold both requests here, so both staging files exist and are half
		// written before either finishes.
		mu.Lock()
		arrived++
		if arrived == 2 {
			close(gate)
		}
		mu.Unlock()
		<-gate
		if _, err := w.Write(block); err != nil {
			return
		}
		flush(w)
	})

	dir := t.TempDir()
	dst := filepath.Join(dir, "output.zip")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = c.DownloadResult(context.Background(), "task-1", testHashA, dst)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("download %d: %v", i, err)
		}
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(got) != 2*half {
		t.Fatalf("result is %d bytes, want a complete %d-byte payload", len(got), 2*half)
	}
	if !bytes.Equal(got, bytes.Repeat(got[:1], 2*half)) {
		t.Error("the result file mixes both payloads, so the two downloads shared a staging file")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "output.zip" {
		t.Errorf("dir holds %v, want only output.zip", entries)
	}
}

// TestUnaryCallsAndEmptyBodies covers both sides of the empty-body line: the
// calls whose response this package does not consume must treat 204 as success
// (the service is entitled to answer a cancel with nothing), while the calls
// whose body carries data must still fail, because a zero value there is a
// phantom success the runner would act on.
func TestUnaryCallsAndEmptyBodies(t *testing.T) {
	responses := []struct {
		name  string
		write func(http.ResponseWriter)
	}{
		{"204 No Content", func(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }},
		{"200 with a zero-length body", func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) }},
	}
	ctx := context.Background()
	calls := []struct {
		name    string
		emptyOK bool
		run     func(*Client) error
	}{
		{"Health", false, func(c *Client) error { return c.Health(ctx) }},
		{"CreateTask", false, func(c *Client) error {
			return c.CreateTask(ctx, CreateTaskRequest{TaskID: "task-1", UserID: testHashA})
		}},
		{"Task", false, func(c *Client) error { _, err := c.Task(ctx, "task-1", testHashA); return err }},
		{"ActivateModel", true, func(c *Client) error { return c.ActivateModel(ctx, testHashB) }},
		{"CancelTask", true, func(c *Client) error { return c.CancelTask(ctx, "task-1", testHashA) }},
		{"ContinueTask", true, func(c *Client) error { return c.ContinueTask(ctx, "task-1", testHashA) }},
	}
	for _, resp := range responses {
		c, _ := newTestClientWithTimeout(t, 5*time.Second, func(w http.ResponseWriter, r *http.Request) { resp.write(w) })
		for _, call := range calls {
			err := call.run(c)
			switch {
			case call.emptyOK && err != nil:
				t.Errorf("%s answered %s: err = %v, want nil - the body is not consumed", call.name, resp.name, err)
			case !call.emptyOK && err == nil:
				t.Errorf("%s answered %s: err = nil, want a decode error - the body carries data", call.name, resp.name)
			case !call.emptyOK && !errors.Is(err, io.EOF):
				t.Errorf("%s answered %s: err = %v, want an io.EOF decode failure", call.name, resp.name, err)
			}
		}
	}
}

// TestTaskScopedCallsRejectAnEmptyTenant covers the silently dropped header:
// with an empty user id the call used to succeed while carrying no X-User-Id at
// all, which the service reads as the tenant.
func TestTaskScopedCallsRejectAnEmptyTenant(t *testing.T) {
	var hits int32
	var seenUser atomic.Value
	c, _ := newTestClientWithTimeout(t, 5*time.Second, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		seenUser.Store(r.Header.Get("X-User-Id"))
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	ctx := context.Background()
	dir := t.TempDir()
	calls := []struct {
		name string
		run  func() error
	}{
		{"CreateTask", func() error {
			return c.CreateTask(ctx, CreateTaskRequest{TaskID: "task-1", UserID: ""})
		}},
		{"Task", func() error { _, err := c.Task(ctx, "task-1", ""); return err }},
		{"CancelTask", func() error { return c.CancelTask(ctx, "task-1", "") }},
		{"ContinueTask", func() error { return c.ContinueTask(ctx, "task-1", "") }},
		{"DownloadResult", func() error {
			return c.DownloadResult(ctx, "task-1", "", filepath.Join(dir, "output.zip"))
		}},
	}
	for _, call := range calls {
		if err := call.run(); err == nil {
			t.Errorf("%s with an empty tenant = nil, want an error", call.name)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("%d requests reached the service with no tenant, want 0", got)
	}

	// The premise: a non-empty tenant really is what puts the header on the wire.
	if err := c.CancelTask(ctx, "task-1", testHashA); err != nil {
		t.Fatalf("CancelTask: %v", err)
	}
	if got, _ := seenUser.Load().(string); got != testHashA {
		t.Errorf("X-User-Id = %q, want %q", got, testHashA)
	}
}

// TestTaskScopedCallsRejectAnUnsafeTaskID pins the second half of the same
// property. url.PathEscape is not a traversal defence: it escapes neither "." nor
// "/", so "../models/activate" survives escaping intact and the server decodes
// the path back to /api/v1/tasks/../models/activate.
func TestTaskScopedCallsRejectAnUnsafeTaskID(t *testing.T) {
	var hits int32
	c, _ := newTestClientWithTimeout(t, 5*time.Second, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	ctx := context.Background()
	for _, id := range []string{"../models/activate", "..", "", "task/../other", "task 1", "task-1/"} {
		dir := t.TempDir()
		if _, err := c.Task(ctx, id, testHashA); err == nil {
			t.Errorf("Task(%q) = nil, want an error", id)
		}
		if err := c.CancelTask(ctx, id, testHashA); err == nil {
			t.Errorf("CancelTask(%q) = nil, want an error", id)
		}
		if err := c.ContinueTask(ctx, id, testHashA); err == nil {
			t.Errorf("ContinueTask(%q) = nil, want an error", id)
		}
		if err := c.DownloadResult(ctx, id, testHashA, filepath.Join(dir, "output.zip")); err == nil {
			t.Errorf("DownloadResult(%q) = nil, want an error", id)
		}
		if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
			t.Errorf("task id %q created %d files, want none", id, len(entries))
		}
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("%d requests carried an unsafe task id, want 0", got)
	}
}

// TestClientDoesNotFollowRedirects is the regression for two proven failures: a
// 307 forwards X-User-Id to whatever host Location names, and a 303 turns a
// mutating POST into a GET that still answers 200 - a continue that silently did
// nothing while reporting success.
func TestClientDoesNotFollowRedirects(t *testing.T) {
	var secondHits int32
	var seenUser atomic.Value
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secondHits, 1)
		seenUser.Store(r.Header.Get("X-User-Id"))
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(second.Close)

	ctx := context.Background()
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusSeeOther} {
		target := second.URL + "/api/v1/tasks/task-1/continue"
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", target)
			w.WriteHeader(status)
		}))
		t.Cleanup(first.Close)
		c, err := NewClient(first.URL, 5*time.Second)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		err = c.ContinueTask(ctx, "task-1", testHashA)
		if err == nil {
			t.Errorf("HTTP %d: ContinueTask = nil, want the 3xx reported", status)
			continue
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Errorf("HTTP %d: error %v is not an *APIError", status, err)
			continue
		}
		if apiErr.StatusCode != status {
			t.Errorf("HTTP %d: StatusCode = %d, want %d", status, apiErr.StatusCode, status)
		}
	}
	if got := atomic.LoadInt32(&secondHits); got != 0 {
		t.Errorf("a redirect was followed to another host: %d requests arrived, X-User-Id %v",
			got, seenUser.Load())
	}
}

// TestDownloadRespectsRedirectsToo checks the download client got the same
// CheckRedirect: following a redirect there would send the tenant header to
// another host and write whatever that host answered into dst.
func TestDownloadRespectsRedirectsToo(t *testing.T) {
	var secondHits int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secondHits, 1)
		_, _ = w.Write([]byte("not-a-zip"))
	}))
	t.Cleanup(second.Close)

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", second.URL+"/elsewhere")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(first.Close)

	c, err := NewClient(first.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "output.zip")
	if err := c.DownloadResult(context.Background(), "task-1", testHashA, dst); err == nil {
		t.Error("DownloadResult = nil, want the 3xx reported")
	}
	if got := atomic.LoadInt32(&secondHits); got != 0 {
		t.Errorf("the download followed a redirect: %d requests arrived at the other host", got)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("a redirected download must not leave dst behind")
	}
}

// flush pushes a response out of the server's buffer, so a test can control when
// the client sees the headers and each body chunk rather than waiting for the
// handler to return.
func flush(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
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
