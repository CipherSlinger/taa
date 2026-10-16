package fhe

import (
	"context"
	"encoding/json"
	"fmt"
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

// fakeFHE is an in-process stand-in for the /api/v1 surface. It is what lets the
// whole contract be exercised on a machine with no GPU: the real service is
// CUDA-only (sm_89) and cannot run here.
type fakeFHE struct {
	mu           sync.Mutex
	tasks        map[string]string // task id -> status
	caseDone     map[string]int    // task id -> finished case count
	caseTotal    int
	activateHits int
	createHits   int
	continueHits int
	callbackURL  string
	// resultBytes is what /results/download serves.
	resultBytes []byte
	// resultOnDisk makes the task write results/<id>/output.zip, as the real
	// service does through the shared directory.
	resultOnDisk bool
	layout       Layout
}

func newFakeFHE(t *testing.T, layout Layout) (*fakeFHE, *httptest.Server) {
	t.Helper()
	f := &fakeFHE{
		tasks:        map[string]string{},
		caseDone:     map[string]int{},
		caseTotal:    3,
		resultBytes:  []byte("result-zip"),
		resultOnDisk: true,
		layout:       layout,
	}
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeFHE) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	switch {
	case path == "/api/v1/health":
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	case path == "/api/v1/models/activate":
		f.activateHits++
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	case path == "/api/v1/tasks" && r.Method == http.MethodPost:
		f.createHits++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		id, _ := body["task_id"].(string)
		f.callbackURL, _ = body["callback_url"].(string)
		if _, exists := f.tasks[id]; exists {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"task exists"}`))
			return
		}
		f.tasks[id] = "running"
		f.caseDone[id] = 0
		_, _ = w.Write([]byte(`{"task_id":"` + id + `","status":"running"}`))
	case strings.HasSuffix(path, "/continue") && r.Method == http.MethodPost:
		f.continueHits++
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/tasks/"), "/continue")
		f.tasks[id] = "running"
		_, _ = w.Write([]byte(`{"status":"running"}`))
	case strings.HasSuffix(path, "/cancel") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/tasks/"), "/cancel")
		f.tasks[id] = "cancelled"
		_, _ = w.Write([]byte(`{"status":"cancelled"}`))
	case strings.HasSuffix(path, "/results/download"):
		_, _ = w.Write(f.resultBytes)
	case strings.HasPrefix(path, "/api/v1/tasks/"):
		id := strings.TrimPrefix(path, "/api/v1/tasks/")
		status, ok := f.tasks[id]
		if !ok {
			http.Error(w, "no such task", http.StatusNotFound)
			return
		}
		if status == "completed" && f.resultOnDisk {
			if p, err := f.layout.ResultPath(id); err == nil {
				_ = os.MkdirAll(filepath.Dir(p), 0o755)
				if _, err := os.Stat(p); err != nil {
					_ = os.WriteFile(p, f.resultBytes, 0o644)
				}
			}
		}
		done := f.caseDone[id]
		if !IsTerminal(status) {
			done = f.caseTotal - 1
		}
		cases := ""
		for i := 0; i < f.caseTotal; i++ {
			if i > 0 {
				cases += ","
			}
			if i < done {
				cases += fmt.Sprintf(`{"entry":"case-%02d.ct","result_id":"case-%02d.result.bin"}`, i, i)
			} else {
				cases += fmt.Sprintf(`{"entry":"case-%02d.ct"}`, i)
			}
		}
		_, _ = fmt.Fprintf(w, `{"task_id":%q,"status":%q,"cases":[%s]}`, id, status, cases)
	default:
		http.Error(w, "unexpected path "+path, http.StatusNotFound)
	}
}

// completeTask moves a task to its terminal state, as the worker eventually does.
func (f *fakeFHE) completeTask(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tasks[id] = "completed"
	f.caseDone[id] = f.caseTotal
}

func (f *fakeFHE) status(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tasks[id]
}

func (f *fakeFHE) callback() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callbackURL
}

// newTestRunner wires a Runner against a fake service and a temp shared dir.
func newTestRunner(t *testing.T, srvURL string, layout Layout) *Runner {
	t.Helper()
	cfg := Config{
		Endpoint:        srvURL,
		DataDir:         layout.DataDir(),
		KeyCacheDir:     t.TempDir(),
		CallbackBaseURL: "http://taa.test:6001",
		CallbackToken:   "tok",
		MaxEvalKeyBytes: DefaultMaxEvalKeyBytes,
		PollInterval:    20 * time.Millisecond,
		RequestTimeout:  5 * time.Second,
		TaskTimeout:     5 * time.Second,
	}
	r, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// specFor stages an eval key and an input archive and returns a matching spec.
func specFor(t *testing.T, r *Runner, keySrvURL string, keyBytes, inputBytes []byte) TaskSpec {
	t.Helper()
	keyHash := sm3HexOf(t, keyBytes)
	in := filepath.Join(t.TempDir(), "input.zip")
	if err := os.WriteFile(in, inputBytes, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	return TaskSpec{
		TaskID:       "task-1",
		RequestID:    "req-1",
		UserID:       keyHash,
		ModelID:      testHashB,
		EvalKeyHash:  keyHash,
		EvalKeyURL:   keySrvURL + "/eval_context.bin",
		InputZipPath: in,
	}
}

func TestRunnerExecuteStagesSharedDirectoryAndCompletes(t *testing.T) {
	layout := NewLayout(t.TempDir())
	keyBytes := []byte("eval-key-bytes")
	inputBytes := []byte("input-zip-bytes")

	keySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyBytes)
	}))
	defer keySrv.Close()

	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	spec := specFor(t, r, keySrv.URL, keyBytes, inputBytes)

	// Complete the task as soon as it is created, so the first poll after the
	// create call already sees a terminal state.
	go func() {
		for i := 0; i < 200; i++ {
			if fake.status("task-1") != "" {
				fake.completeTask("task-1")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	out, err := r.Execute(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Status != StatusCompleted {
		t.Errorf("Status = %q, want %q", out.Status, StatusCompleted)
	}
	if out.ResultZip == "" {
		t.Fatal("ResultZip is empty, want the shared-directory output.zip")
	}
	if b, err := os.ReadFile(out.ResultZip); err != nil || string(b) != string(fake.resultBytes) {
		t.Errorf("result bytes = %q, err = %v", b, err)
	}
	if out.Total != 3 || out.Failed != 0 {
		t.Errorf("Total/Failed = %d/%d, want 3/0", out.Total, out.Failed)
	}

	// The key and the input package must be published where the service reads them.
	keyDst, _ := layout.KeyPath(spec.EvalKeyHash)
	if b, err := os.ReadFile(keyDst); err != nil || string(b) != string(keyBytes) {
		t.Errorf("published key = %q, err = %v", b, err)
	}
	inDst, _ := layout.TaskInputPath("task-1")
	if b, err := os.ReadFile(inDst); err != nil || string(b) != string(inputBytes) {
		t.Errorf("published input = %q, err = %v", b, err)
	}

	// The callback URL must carry the token, and must be pointed at our endpoint.
	cb := fake.callback()
	if !strings.Contains(cb, "/v1/taa/fheCallback") || !strings.Contains(cb, "token=tok") {
		t.Errorf("callback url = %q", cb)
	}
	if fake.activateHits != 0 {
		t.Errorf("activateHits = %d, want 0 (model activation belongs to importModel)", fake.activateHits)
	}
}

func TestRunnerExecuteRejectsInvalidIdentifiers(t *testing.T) {
	layout := NewLayout(t.TempDir())
	_, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)

	base := TaskSpec{
		TaskID: "task-1", UserID: testHashA, ModelID: testHashB,
		EvalKeyHash: testHashA, EvalKeyURL: "http://x/y", InputZipPath: "/nonexistent",
	}
	cases := map[string]func(*TaskSpec){
		"eval key hash": func(s *TaskSpec) { s.EvalKeyHash = "../../etc"; s.UserID = "../../etc" },
		"model hash":    func(s *TaskSpec) { s.ModelID = "../x" },
		"task id":       func(s *TaskSpec) { s.TaskID = "../x" },
	}
	for name, mutate := range cases {
		s := base
		mutate(&s)
		if _, err := r.Execute(context.Background(), s, nil); err == nil {
			t.Errorf("%s: Execute = nil, want error", name)
		}
	}
}

func TestRunnerDeliverIsIdempotent(t *testing.T) {
	layout := NewLayout(t.TempDir())
	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	r.registerTestRun("task-1", TaskSpec{TaskID: "task-1", UserID: testHashA, ModelID: testHashB})

	payload := CallbackPayload{TaskID: "task-1", Status: "completed", ResultZip: "results/task-1/output.zip"}
	if !r.Deliver(payload) {
		t.Fatal("first Deliver = false, want true")
	}
	for i := 0; i < 3; i++ {
		if r.Deliver(payload) {
			t.Fatalf("Deliver #%d = true, want false (the service retries at 0/1/4/16s)", i+2)
		}
	}
	_ = fake
}

func TestRunnerDeliverUnknownTaskIsIgnored(t *testing.T) {
	layout := NewLayout(t.TempDir())
	_, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	if r.Deliver(CallbackPayload{TaskID: "nope", Status: "completed"}) {
		t.Error("Deliver for an unknown task = true, want false")
	}
}

func TestRunnerCallbackWinsOverPollingExactlyOnce(t *testing.T) {
	layout := NewLayout(t.TempDir())
	_, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	// The service never reports a terminal state here: only the callback can end
	// the task, which is what makes the race observable.
	r.registerTestRun("task-1", TaskSpec{TaskID: "task-1", UserID: testHashA, ModelID: testHashB})

	var wg sync.WaitGroup
	var delivered int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.Deliver(CallbackPayload{TaskID: "task-1", Status: "completed"}) {
				atomic.AddInt64(&delivered, 1)
			}
		}()
	}
	run := r.lookupForTest("task-1")
	wg.Wait()
	<-run.done

	if got := atomic.LoadInt64(&delivered); got != 1 {
		t.Errorf("deliveries that advanced the task = %d, want exactly 1", got)
	}
}

func TestRunnerExecuteTimesOut(t *testing.T) {
	layout := NewLayout(t.TempDir())
	keyBytes := []byte("k")
	keySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyBytes)
	}))
	defer keySrv.Close()
	_, srv := newFakeFHE(t, layout)

	cfg := Config{
		Endpoint: srv.URL, DataDir: layout.DataDir(), KeyCacheDir: t.TempDir(),
		CallbackBaseURL: "http://taa.test:6001", CallbackToken: "tok",
		MaxEvalKeyBytes: DefaultMaxEvalKeyBytes,
		PollInterval:    10 * time.Millisecond,
		RequestTimeout:  5 * time.Second,
		TaskTimeout:     150 * time.Millisecond,
	}
	r, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := r.Execute(context.Background(), specFor(t, r, keySrv.URL, keyBytes, []byte("i")), nil)
	if err == nil {
		t.Fatal("Execute on a task that never terminates = nil, want error")
	}
	if out.Status != StatusFailed {
		t.Errorf("Status = %q, want %q", out.Status, StatusFailed)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error %q does not mention the timeout", err)
	}
}

func TestRunnerExecuteRetriesAnExistingTask(t *testing.T) {
	layout := NewLayout(t.TempDir())
	keyBytes := []byte("k")
	keySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyBytes)
	}))
	defer keySrv.Close()
	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	spec := specFor(t, r, keySrv.URL, keyBytes, []byte("i"))

	// Simulate a replayed import: the task already exists on the service. The
	// runner must resume it with /continue instead of creating a second task.
	fake.mu.Lock()
	fake.tasks["task-1"] = "failed"
	fake.caseDone["task-1"] = 1
	fake.mu.Unlock()

	go func() {
		for i := 0; i < 200; i++ {
			fake.mu.Lock()
			status := fake.tasks["task-1"]
			fake.mu.Unlock()
			if status == "running" {
				fake.completeTask("task-1")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	out, err := r.Execute(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Status != StatusCompleted {
		t.Errorf("Status = %q, want completed", out.Status)
	}
	if fake.continueHits != 1 {
		t.Errorf("continueHits = %d, want 1", fake.continueHits)
	}
}

func TestRunnerCancelMapsToTheCancelEndpoint(t *testing.T) {
	layout := NewLayout(t.TempDir())
	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	r.registerTestRun("task-1", TaskSpec{TaskID: "task-1", UserID: testHashA, ModelID: testHashB})
	fake.mu.Lock()
	fake.tasks["task-1"] = "running"
	fake.mu.Unlock()

	if err := r.Cancel(context.Background(), "task-1"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if got := fake.status("task-1"); got != "cancelled" {
		t.Errorf("service status = %q, want cancelled", got)
	}
	run := r.lookupForTest("task-1")
	select {
	case <-run.done:
	default:
		t.Fatal("Cancel did not finish the local run")
	}
	if run.outcome.Status != StatusCancelled {
		t.Errorf("local status = %q, want %q", run.outcome.Status, StatusCancelled)
	}
}

// TestRunnerCancelUnknownTaskIsRefused pins what Cancel does for a task this
// instance does not track - the state a restart leaves behind, because the
// in-flight table is in memory only. It must both refuse and stay off the wire:
// a cancel sent without the tenant is not a cancel, and a 2xx for it would be
// reported to the platform as a successful stop.
func TestRunnerCancelUnknownTaskIsRefused(t *testing.T) {
	layout := NewLayout(t.TempDir())
	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	// The service knows a task under this id; this TAA instance does not. If a
	// cancel request were sent, the fake would flip this to "cancelled".
	fake.mu.Lock()
	fake.tasks["task-1"] = "running"
	fake.mu.Unlock()

	err := r.Cancel(context.Background(), "task-1")
	if err == nil {
		t.Fatal("Cancel of an untracked task = nil, want an error: a cancel that matched nothing must not be reported as a success")
	}
	if got := fake.status("task-1"); got != "running" {
		t.Errorf("service status = %q, want running: no cancel request may be sent without a tenant", got)
	}
	for _, want := range []string{"task-1", "not in flight", "restart", "no cancel request was sent"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not tell the operator %q", err, want)
		}
	}
}

// TestRunnerCancelTrackedTaskStillWorks guards the refusal above from swallowing
// the normal path: a task created through Execute is cancelled as before.
func TestRunnerCancelTrackedTaskStillWorks(t *testing.T) {
	layout := NewLayout(t.TempDir())
	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	r.registerTestRun("task-1", TaskSpec{TaskID: "task-1", UserID: testHashA, ModelID: testHashB})
	fake.mu.Lock()
	fake.tasks["task-1"] = "running"
	fake.mu.Unlock()

	if err := r.Cancel(context.Background(), "task-1"); err != nil {
		t.Fatalf("Cancel of a tracked task: %v", err)
	}
	if got := fake.status("task-1"); got != "cancelled" {
		t.Errorf("service status = %q, want cancelled", got)
	}
}

// TestRunnerCopyResultDownloadIsNotBoundedByRequestTimeout is the regression
// test for a bulk transfer bounded by a per-call budget: the download fallback
// handed DownloadResult a RequestTimeout-sized context, so an archive that
// needed longer than 30s was aborted mid-body in production while a suite using
// ten-byte payloads passed. The body here takes longer than RequestTimeout and
// is still far inside TaskTimeout.
func TestRunnerCopyResultDownloadIsNotBoundedByRequestTimeout(t *testing.T) {
	layout := NewLayout(t.TempDir())
	head, tail := []byte("result-head"), []byte("result-tail")

	// The flush before the sleep is what makes this the documented failure: the
	// response headers are already in the client's hands, so only the body's
	// duration decides the outcome.
	const bodyDelay = 400 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/results/download") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(head)
		w.(http.Flusher).Flush()
		time.Sleep(bodyDelay)
		_, _ = w.Write(tail)
	}))
	defer srv.Close()

	cfg := Config{
		Endpoint: srv.URL, DataDir: layout.DataDir(), KeyCacheDir: t.TempDir(),
		CallbackBaseURL: "http://taa.test:6001", CallbackToken: "tok",
		MaxEvalKeyBytes: DefaultMaxEvalKeyBytes,
		PollInterval:    20 * time.Millisecond,
		RequestTimeout:  150 * time.Millisecond,
		TaskTimeout:     30 * time.Second,
	}
	r, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "out", "output.zip")
	// An outcome with no ResultZip is what selects the download fallback.
	got, err := r.CopyResult(context.Background(),
		TaskSpec{TaskID: "task-1", UserID: testHashA},
		TaskOutcome{Status: StatusCompleted}, dst)
	if err != nil {
		t.Fatalf("CopyResult via download = %v, want success: RequestTimeout must not bound a bulk transfer", err)
	}
	if got != "" {
		t.Errorf("returned path = %q, want \"\": only dst is guaranteed to hold the result", got)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read the downloaded result: %v", err)
	}
	if string(b) != string(head)+string(tail) {
		t.Errorf("downloaded %q, want %q", b, string(head)+string(tail))
	}
}

// TestRunnerCopyResultSharedDirectoryHit pins the other half of the return
// contract: the shared-directory hit returns the source path, not dst.
func TestRunnerCopyResultSharedDirectoryHit(t *testing.T) {
	layout := NewLayout(t.TempDir())
	r := newTestRunner(t, "http://127.0.0.1:1", layout)
	src := filepath.Join(t.TempDir(), "output.zip")
	if err := os.WriteFile(src, []byte("shared-result"), 0o600); err != nil {
		t.Fatalf("write the shared result: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "published", "output.zip")

	got, err := r.CopyResult(context.Background(),
		TaskSpec{TaskID: "task-1", UserID: testHashA},
		TaskOutcome{Status: StatusCompleted, ResultZip: src}, dst)
	if err != nil {
		t.Fatalf("CopyResult from the shared directory: %v", err)
	}
	if got != src {
		t.Errorf("returned path = %q, want the source %q", got, src)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "shared-result" {
		t.Errorf("dst = %q, err = %v", b, err)
	}
}

func TestParseCallback(t *testing.T) {
	p, err := ParseCallback([]byte(`{"task_id":"t1","status":"completed","result_zip":"results/t1/output.zip","cases":[{"entry":"a","result_id":"a.bin"}]}`))
	if err != nil {
		t.Fatalf("ParseCallback: %v", err)
	}
	if p.TaskID != "t1" || p.Status != "completed" || len(p.Cases) != 1 {
		t.Errorf("parsed = %+v", p)
	}

	// camelCase is accepted too: the exact casing of the callback is the
	// service's to choose, and guessing wrong must not drop a terminal state.
	p, err = ParseCallback([]byte(`{"taskId":"t2","status":"failed","resultZip":"x"}`))
	if err != nil {
		t.Fatalf("ParseCallback camelCase: %v", err)
	}
	if p.TaskID != "t2" || p.ResultZip != "x" {
		t.Errorf("parsed = %+v", p)
	}

	for _, bad := range []string{`{}`, `{"status":"completed"}`, `{`, `{"task_id":"t"}`, ``} {
		if _, err := ParseCallback([]byte(bad)); err == nil {
			t.Errorf("ParseCallback(%q) = nil, want error", bad)
		}
	}
}

func TestNewValidatesConfigAndCreatesDirs(t *testing.T) {
	layout := NewLayout(t.TempDir())
	cfg := Config{
		Endpoint: "http://127.0.0.1:1", DataDir: layout.DataDir(), KeyCacheDir: t.TempDir(),
		CallbackBaseURL: "http://taa:6001", CallbackToken: "t",
		MaxEvalKeyBytes: DefaultMaxEvalKeyBytes, PollInterval: time.Second,
		RequestTimeout: time.Second, TaskTimeout: time.Minute,
	}
	if _, err := New(cfg, nil); err != nil {
		t.Fatalf("New: %v", err)
	}
	bad := cfg
	bad.CallbackToken = ""
	if _, err := New(bad, nil); err == nil {
		t.Error("New with an empty callback token = nil, want error")
	}
}
