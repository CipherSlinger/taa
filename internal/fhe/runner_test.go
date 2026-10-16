package fhe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

// newRunnerWithTimeout wires a Runner against a fake service with the given task
// budget, for the tests whose subject is a deadline or a cancellation.
func newRunnerWithTimeout(t *testing.T, srvURL string, layout Layout, taskTimeout time.Duration) *Runner {
	t.Helper()
	cfg := Config{
		Endpoint:        srvURL,
		DataDir:         layout.DataDir(),
		KeyCacheDir:     t.TempDir(),
		CallbackBaseURL: "http://taa.test:6001",
		CallbackToken:   "tok",
		MaxEvalKeyBytes: DefaultMaxEvalKeyBytes,
		PollInterval:    10 * time.Millisecond,
		RequestTimeout:  5 * time.Second,
		TaskTimeout:     taskTimeout,
	}
	r, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// keyServer serves payload as the eval key, the way the deployment's key server
// does.
func keyServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// waitForRun waits until the in-flight table holds a run for taskID and returns
// it, so a test can act once a task is genuinely in flight.
func waitForRun(t *testing.T, r *Runner, taskID string) *taskRun {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if run := r.lookupForTest(taskID); run != nil {
			return run
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no run for %s appeared in the in-flight table", taskID)
	return nil
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

// TestRunnerExecuteRejectsInvalidIdentifiers pins prepare's validation, one
// error message at a time.
//
// Asserting only "an error came back" left all three checks untested: every one
// of these specs is also rejected downstream - by the layout's path builders or
// by the client's guard - so deleting the checks kept the test green. ModelID is
// the reason that mattered: nothing downstream validates it at all, and an
// invalid one reached the create request body unexamined. The identifiers become
// directory names, so this is the project's path-traversal boundary.
func TestRunnerExecuteRejectsInvalidIdentifiers(t *testing.T) {
	layout := NewLayout(t.TempDir())
	_, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)

	base := TaskSpec{
		TaskID: "task-1", UserID: testHashA, ModelID: testHashB,
		EvalKeyHash: testHashA, EvalKeyURL: "http://x/y", InputZipPath: "/nonexistent",
	}
	cases := map[string]struct {
		mutate func(*TaskSpec)
		want   string
	}{
		"eval key hash": {func(s *TaskSpec) { s.EvalKeyHash = "../../etc"; s.UserID = "../../etc" }, "invalid eval key hash"},
		"model hash":    {func(s *TaskSpec) { s.ModelID = "../x" }, "invalid model hash"},
		"task id":       {func(s *TaskSpec) { s.TaskID = "../x" }, "invalid task id"},
	}
	for name, tc := range cases {
		s := base
		tc.mutate(&s)
		_, err := r.Execute(context.Background(), s, nil)
		if err == nil {
			t.Errorf("%s: Execute = nil, want error", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not come from the %q check", name, err, tc.want)
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
	// An untracked task is not the same answer as one that already finished: the
	// first is a stop that cannot be performed, the second a stop that does not
	// have to be.
	if errors.Is(err, ErrTaskAlreadyFinished) {
		t.Error("an untracked task was reported as an already-finished one, which would turn a stop TAA never made into a no-op success")
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

// TestNewValidatesConfigAndCreatesDirs covers the startup gate.
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

// TestRunnerConcurrentRunsForOneTaskIDDoNotForgetEachOther is the regression
// test for forget deleting by task id alone.
//
// Two Executes for one task id - a replayed import, or a platform retry while
// the first is still in flight - both register under that id, and the second
// prepare replaces the first's entry in the table. Whichever run returns first
// then used to delete the other's entry, after which that run's terminal
// callback was dropped as "unknown task" and Execute sat there until its own
// timeout - which is why the second run here must still be resolved by its
// callback.
func TestRunnerConcurrentRunsForOneTaskIDDoNotForgetEachOther(t *testing.T) {
	layout := NewLayout(t.TempDir())
	keyBytes := []byte("k")
	keySrv := keyServer(t, keyBytes)
	_, srv := newFakeFHE(t, layout)
	r := newRunnerWithTimeout(t, srv.URL, layout, 5*time.Second)
	spec := specFor(t, r, keySrv.URL, keyBytes, []byte("i"))

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	firstDone := make(chan TaskOutcome, 1)
	go func() {
		out, _ := r.Execute(ctx1, spec, nil)
		firstDone <- out
	}()
	run1 := waitForRun(t, r, "task-1")

	secondDone := make(chan TaskOutcome, 1)
	secondErr := make(chan error, 1)
	go func() {
		out, err := r.Execute(context.Background(), spec, nil)
		secondDone <- out
		secondErr <- err
	}()
	// Wait until the second run has replaced the first in the table.
	deadline := time.Now().Add(5 * time.Second)
	var run2 *taskRun
	for time.Now().Before(deadline) {
		if got := r.lookupForTest("task-1"); got != nil && got != run1 {
			run2 = got
			break
		}
		time.Sleep(time.Millisecond)
	}
	if run2 == nil {
		t.Fatal("the second run never registered")
	}

	// Ending the first run is what triggers its cleanup.
	cancel1()
	<-firstDone

	if r.lookupForTest("task-1") != run2 {
		t.Fatal("run 2 was forgotten by run 1's cleanup while run 2 is still in flight")
	}
	start := time.Now()
	if !r.Deliver(CallbackPayload{TaskID: "task-1", Status: "completed"}) {
		t.Fatal("a callback for the still-in-flight run 2 was dropped")
	}
	err := <-secondErr
	out := <-secondDone
	if err != nil {
		t.Fatalf("the second Execute: %v", err)
	}
	if out.Status != StatusCompleted {
		t.Errorf("the second Execute returned %q, want %q", out.Status, StatusCompleted)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the second Execute took %v after its callback", elapsed)
	}
}

// TestRunnerExecuteAdoptsAnAlreadyCompletedTask is the regression test for the
// probe whose status was thrown away.
//
// A replayed import whose task has already completed failed to create - the task
// exists - and was then handed a /continue that reset it to running and dropped
// the result already sitting in the shared directory, so the import ended as a
// timeout failure for a task that had succeeded.
func TestRunnerExecuteAdoptsAnAlreadyCompletedTask(t *testing.T) {
	layout := NewLayout(t.TempDir())
	keyBytes := []byte("k")
	keySrv := keyServer(t, keyBytes)
	fake, srv := newFakeFHE(t, layout)
	r := newRunnerWithTimeout(t, srv.URL, layout, 500*time.Millisecond)
	spec := specFor(t, r, keySrv.URL, keyBytes, []byte("i"))

	// The task already ran to a successful end, and its result is on disk.
	fake.completeTask("task-1")
	stored, err := layout.ResultPath("task-1")
	if err != nil {
		t.Fatalf("ResultPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(stored), 0o755); err != nil {
		t.Fatalf("create the result dir: %v", err)
	}
	if err := os.WriteFile(stored, fake.resultBytes, 0o644); err != nil {
		t.Fatalf("write the stored result: %v", err)
	}

	out, err := r.Execute(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("Execute of an already completed task = %v, want the completed outcome", err)
	}
	if out.Status != StatusCompleted {
		t.Errorf("Status = %q, want %q", out.Status, StatusCompleted)
	}
	if out.ResultZip != stored {
		t.Errorf("ResultZip = %q, want the stored result %q", out.ResultZip, stored)
	}
	if fake.continueHits != 0 {
		t.Errorf("continueHits = %d, want 0: a completed task must not be restarted", fake.continueHits)
	}
}

// TestRunnerDeliverIgnoresNonTerminalCallbacks pins the two channels agreeing on
// what ends a task. Deliver used to resolve a run whatever status it was handed,
// so an out-of-contract status:"running" callback ended a live task as failed
// while the service was still working on it, and the once-only transition then
// shut the poller out.
func TestRunnerDeliverIgnoresNonTerminalCallbacks(t *testing.T) {
	layout := NewLayout(t.TempDir())
	_, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	run := r.registerTestRun("task-1", TaskSpec{TaskID: "task-1", UserID: testHashA, ModelID: testHashB})

	for _, status := range []string{"running", "queued", "pending", ""} {
		if r.Deliver(CallbackPayload{TaskID: "task-1", Status: status}) {
			t.Errorf("Deliver(status=%q) = true, want false: it is not a terminal state", status)
		}
		select {
		case <-run.done:
			t.Fatalf("Deliver(status=%q) resolved the run", status)
		default:
		}
	}

	// The predicate must not simply ignore everything: a terminal status still
	// advances the run.
	if !r.Deliver(CallbackPayload{TaskID: "task-1", Status: "failed"}) {
		t.Fatal("Deliver(status=failed) = false, want true")
	}
	<-run.done
	if run.outcome.Status != StatusFailed {
		t.Errorf("resolved status = %q, want %q", run.outcome.Status, StatusFailed)
	}
}

// TestRunnerExecuteIsResolvedByACallbackWhileItWaits covers the branch of wait
// that a callback takes - no test used to execute it (its coverage count was 0).
// The fake service never reports a terminal state here, so the callback is the
// only way this Execute can end, and it must end promptly and with the
// callback's outcome rather than with a stale one.
func TestRunnerExecuteIsResolvedByACallbackWhileItWaits(t *testing.T) {
	layout := NewLayout(t.TempDir())
	keyBytes := []byte("k")
	keySrv := keyServer(t, keyBytes)
	_, srv := newFakeFHE(t, layout)
	r := newRunnerWithTimeout(t, srv.URL, layout, 10*time.Second)
	spec := specFor(t, r, keySrv.URL, keyBytes, []byte("i"))

	done := make(chan TaskOutcome, 1)
	failed := make(chan error, 1)
	go func() {
		out, err := r.Execute(context.Background(), spec, nil)
		done <- out
		failed <- err
	}()
	waitForRun(t, r, "task-1")

	// An out-of-contract non-terminal callback must not resolve the run, which is
	// what Execute would then have reported as the task's status.
	if r.Deliver(CallbackPayload{TaskID: "task-1", Status: "running"}) {
		t.Error("a non-terminal callback advanced the run")
	}

	start := time.Now()
	if !r.Deliver(CallbackPayload{TaskID: "task-1", Status: "completed"}) {
		t.Fatal("the terminal callback did not advance the run")
	}
	out := <-done
	err := <-failed
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Execute returned %v after the callback: a delivered callback must resolve it promptly", elapsed)
	}
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Status != StatusCompleted {
		t.Errorf("Execute returned %q, want %q", out.Status, StatusCompleted)
	}
}

// TestRunnerExecuteAbortsStagingWhenTheCallerGivesUp is the regression test for
// staging that ignored the caller's context.
//
// The key download ran on http.Get with no context, so cancelling the caller
// left Execute publishing a multi-gigabyte key: it returned 1.5s after a
// cancellation at 100ms against a 3s download, and a key server that never
// answered would have held the import goroutine forever. Staging now runs on the
// task's context, so the cancellation stops it where it stands.
func TestRunnerExecuteAbortsStagingWhenTheCallerGivesUp(t *testing.T) {
	layout := NewLayout(t.TempDir())
	payload := []byte("eval-key-bytes")
	head, tail := payload[:4], payload[4:]

	started := make(chan struct{})
	var once sync.Once
	keySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(head)
		flush(w)
		once.Do(func() { close(started) })
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
		_, _ = w.Write(tail)
	}))
	defer keySrv.Close()

	fake, srv := newFakeFHE(t, layout)
	r := newRunnerWithTimeout(t, srv.URL, layout, time.Minute)
	spec := specFor(t, r, keySrv.URL, payload, []byte("i"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-started
		cancel()
	}()

	start := time.Now()
	out, err := r.Execute(ctx, spec, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Execute with a cancelled caller = nil, want error")
	}
	if out.Status != StatusFailed {
		t.Errorf("Status = %q, want %q", out.Status, StatusFailed)
	}
	if elapsed > time.Second {
		t.Errorf("Execute returned after %v, want it to stop when its caller cancelled at the start of a 3s download", elapsed)
	}
	if fake.createHits != 0 {
		t.Errorf("createHits = %d, want 0: staging failed, so no task may be created", fake.createHits)
	}
}

// TestRunnerPublishedFilesAreReadableDespiteTheUmask is the regression test for
// the modes of the files published into the shared directory.
//
// The FHE service reads them from a container running as another user, which is
// why linkOrCopy chmods the key; the input archive published by prepare got
// nothing, so under a restrictive umask it landed 0600 and the service could not
// read it at all.
func TestRunnerPublishedFilesAreReadableDespiteTheUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	layout := NewLayout(t.TempDir())
	keyBytes := []byte("eval-key-bytes")
	keySrv := keyServer(t, keyBytes)
	fake, srv := newFakeFHE(t, layout)
	r := newRunnerWithTimeout(t, srv.URL, layout, 2*time.Second)
	spec := specFor(t, r, keySrv.URL, keyBytes, []byte("i"))

	go func() {
		for i := 0; i < 400; i++ {
			if fake.status("task-1") != "" {
				fake.completeTask("task-1")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	if _, err := r.Execute(context.Background(), spec, nil); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	keyDst, err := layout.KeyPath(spec.EvalKeyHash)
	if err != nil {
		t.Fatalf("KeyPath: %v", err)
	}
	inDst, err := layout.TaskInputPath("task-1")
	if err != nil {
		t.Fatalf("TaskInputPath: %v", err)
	}
	for _, p := range []string{keyDst, inDst} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if got := st.Mode().Perm(); got != 0o644 {
			t.Errorf("%s is %v under umask 077, want 0644: the service reads it as another user", p, got)
		}
	}
}

// TestRunnerPublishedDirectoriesAreTraversableDespiteTheUmask is the regression
// test for the modes of the directories TAA publishes into the shared
// directory.
//
// A readable file inside an unenterable directory is still unreadable: the
// service reaches <data>/keys/<userID>/eval_context.bin and
// <data>/tasks/<taskID>/input.zip as another user, and traversal is checked
// against the mode of every directory on the way. os.MkdirAll applies the
// umask, so under umask 077 those directories were 0700 and the service could
// not enter them at all - the same failure the 0644 file fix removed, one path
// component further out.
func TestRunnerPublishedDirectoriesAreTraversableDespiteTheUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	layout := NewLayout(t.TempDir())
	keyBytes := []byte("eval-key-bytes")
	keySrv := keyServer(t, keyBytes)
	fake, srv := newFakeFHE(t, layout)
	r := newRunnerWithTimeout(t, srv.URL, layout, 2*time.Second)
	spec := specFor(t, r, keySrv.URL, keyBytes, []byte("i"))

	go func() {
		for i := 0; i < 400; i++ {
			if fake.status("task-1") != "" {
				fake.completeTask("task-1")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	if _, err := r.Execute(context.Background(), spec, nil); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	keyDst, err := layout.KeyPath(spec.EvalKeyHash)
	if err != nil {
		t.Fatalf("KeyPath: %v", err)
	}
	inDst, err := layout.TaskInputPath("task-1")
	if err != nil {
		t.Fatalf("TaskInputPath: %v", err)
	}
	for _, p := range []string{keyDst, inDst} {
		assertTraversableFromTheSharedRoot(t, layout.DataDir(), p)
	}
}

// assertTraversableFromTheSharedRoot fails when any directory between the shared
// root and p - both exclusive of the root, whose mode belongs to the bind mount
// and to deploy-fhe.sh - is not traversable by another user.
func assertTraversableFromTheSharedRoot(t *testing.T, root, p string) {
	t.Helper()
	for dir := filepath.Dir(p); dir != root; dir = filepath.Dir(dir) {
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if got := st.Mode().Perm(); got != sharedDirMode {
			t.Errorf("%s is %v under umask 077, want %v: the service traverses into it as another user, and a directory it cannot enter hides the readable file inside", dir, got, sharedDirMode)
		}
		if parent := filepath.Dir(dir); parent == dir {
			t.Fatalf("%s is not inside the shared root %s", p, root)
		}
	}
}

// TestLinkOrCopyKeepsThePublishedKeyWhenItFails is the regression test for the
// remove-then-link order: a publish that failed after removing dst left no key
// at all where a good one was, and in between the two calls a reader saw no key.
func TestLinkOrCopyKeepsThePublishedKeyWhenItFails(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "eval_context.bin")
	if err := os.WriteFile(dst, []byte("the-published-key"), 0o644); err != nil {
		t.Fatalf("write the published key: %v", err)
	}

	// A source that has vanished makes both os.Link and the copy fallback fail.
	if err := linkOrCopy(filepath.Join(t.TempDir(), "vanished"), dst); err == nil {
		t.Fatal("linkOrCopy of a missing source = nil, want error")
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("the published key is gone after a failed publish: %v", err)
	}
	if string(b) != "the-published-key" {
		t.Errorf("the published key is now %q, want the previous one", b)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the key dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "eval_context.bin" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("key dir holds %v after a failed publish, want only the published key", names)
	}
}

// TestCopyFileAtomicDoesNotWriteThroughAFixedStagingName pins the staging name.
//
// copyFileAtomic stages next to the destination, so a name derived from the
// destination alone is shared by every publisher of that destination - and this
// runs with no lock at all on the shared data directory, so two publishers
// truncate each other's bytes. One publisher's staging file standing in for the
// other is what that looks like from a single process.
func TestCopyFileAtomicDoesNotWriteThroughAFixedStagingName(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "input.zip")
	const foreign = "another-publisher-staging-bytes"
	fixed := dst + ".partial"
	if err := os.WriteFile(fixed, []byte(foreign), 0o644); err != nil {
		t.Fatalf("write the other publisher's staging file: %v", err)
	}

	src := filepath.Join(t.TempDir(), "input-src.zip")
	payload := []byte("the-input-archive")
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatalf("write the source archive: %v", err)
	}
	if err := copyFileAtomic(src, dst); err != nil {
		t.Fatalf("copyFileAtomic: %v", err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != string(payload) {
		t.Errorf("published archive = %q, err = %v", b, err)
	}
	if b, err := os.ReadFile(fixed); err != nil || string(b) != foreign {
		t.Errorf("the staging file at %s = %q, err = %v: copyFileAtomic wrote through a name derived from the destination", fixed, b, err)
	}
}

// TestRunnerCancelLosesTheRaceToThePollerAndSaysSo is the regression test for
// the cancel result that was thrown away.
//
// Cancel checked run.done once, then spent an HTTP round trip on the service's
// cancel endpoint, then resolved the run and discarded whether that resolution
// was the one that counted. When the poller - or a callback - won the terminal
// transition during that round trip, Cancel's own finish lost the once-only race
// and Cancel still returned nil, so the platform was told "FHE 任务已取消" for a
// task whose recorded outcome was completed. A false report is the worst failure
// class this path has, and ErrTaskAlreadyFinished is what exists to prevent it.
func TestRunnerCancelLosesTheRaceToThePollerAndSaysSo(t *testing.T) {
	layout := NewLayout(t.TempDir())
	cancelArrived := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/cancel") {
			http.NotFound(w, r)
			return
		}
		close(cancelArrived)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestRunner(t, srv.URL, layout)
	run := r.registerTestRun("task-1", TaskSpec{TaskID: "task-1", UserID: testHashA, ModelID: testHashB})

	errCh := make(chan error, 1)
	go func() { errCh <- r.Cancel(context.Background(), "task-1") }()
	<-cancelArrived

	// The poller sees the task finish while the cancel request is on the wire: the
	// run completed a moment before the stop arrived.
	if _, won := r.finish(run, TaskOutcome{Status: StatusCompleted}); !won {
		t.Fatal("the poller's terminal transition lost; the fixture no longer drives the race")
	}
	close(release)

	err := <-errCh
	if err == nil {
		t.Fatalf("Cancel = nil for a run whose recorded outcome is %q: the platform would be told the task was cancelled", run.outcome.Status)
	}
	if !errors.Is(err, ErrTaskAlreadyFinished) {
		t.Errorf("Cancel = %v, want ErrTaskAlreadyFinished: the run had already reached %q when the cancel round trip finished", err, run.outcome.Status)
	}
	if run.outcome.Status != StatusCompleted {
		t.Errorf("the recorded outcome is now %q, want %q left alone", run.outcome.Status, StatusCompleted)
	}
}

// TestRunnerCancelAfterTheTaskFinishedIsNotAFailedStop pins the third answer
// Cancel can give. A task that finished a moment before the platform's
// stopTraining arrived is a race, and reporting it as a failed stop would be
// wrong; it is reported through ErrTaskAlreadyFinished instead, and nothing is
// sent to the service.
func TestRunnerCancelAfterTheTaskFinishedIsNotAFailedStop(t *testing.T) {
	layout := NewLayout(t.TempDir())
	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	fake.mu.Lock()
	fake.tasks["task-1"] = "running"
	fake.mu.Unlock()

	run := r.registerTestRun("task-1", TaskSpec{TaskID: "task-1", UserID: testHashA, ModelID: testHashB})
	r.finish(run, TaskOutcome{Status: StatusCompleted})

	err := r.Cancel(context.Background(), "task-1")
	if !errors.Is(err, ErrTaskAlreadyFinished) {
		t.Fatalf("Cancel of a finished task = %v, want ErrTaskAlreadyFinished", err)
	}
	if got := fake.status("task-1"); got != "running" {
		t.Errorf("service status = %q, want running: a finished task must not be cancelled", got)
	}
	if run.outcome.Status != StatusCompleted {
		t.Errorf("the finished run's outcome is now %q, want it left alone", run.outcome.Status)
	}
}
