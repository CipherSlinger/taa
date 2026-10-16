package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"taa/internal/fhe"
)

// The identifiers a task needs. Both are well-formed digests, so a test that
// wants a shape rejection has to ask for one explicitly.
const (
	testUserID  = "1111111111111111111111111111111111111111111111111111111111111111"
	testModelID = "2222222222222222222222222222222222222222222222222222222222222222"
)

// ── Harness ──────────────────────────────────────────────

// newTestServer builds a server over a fresh data directory, publishing the eval
// context and the model directory so a task that names testUserID/testModelID
// gets past checkInputs.
func newTestServer(t *testing.T, delay time.Duration) (*server, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := newServer(dir, delay)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	writeFile(t, s.keyPath(testUserID), []byte("eval-context"))
	writeModelDir(t, s, testModelID)
	return s, s.dataDir
}

func writeModelDir(t *testing.T, s *server, modelID string) {
	t.Helper()
	if err := os.MkdirAll(s.modelServerDir(modelID), 0o755); err != nil {
		t.Fatalf("create the model server dir: %v", err)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeInputZip publishes a task's input archive with one entry per name, so a
// test can decide which entry names the case list holds.
func writeInputZip(t *testing.T, s *server, taskID string, entries ...string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", name, err)
		}
		if _, err := w.Write([]byte("ciphertext-" + name)); err != nil {
			t.Fatalf("write zip entry %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close the input zip: %v", err)
	}
	writeFile(t, s.taskInputPath(taskID), buf.Bytes())
}

func serve(t *testing.T, s *server) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(s.mux())
	t.Cleanup(srv.Close)
	return srv
}

func postJSON(t *testing.T, url string, body map[string]any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal the body: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func post(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func getTask(t *testing.T, base, taskID string) map[string]any {
	t.Helper()
	resp, err := http.Get(base + "/api/v1/tasks/" + taskID)
	if err != nil {
		t.Fatalf("GET the task: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode the task: %v", err)
	}
	return body
}

func createTask(t *testing.T, base, taskID, callbackURL string) *http.Response {
	t.Helper()
	return postJSON(t, base+"/api/v1/tasks", map[string]any{
		"user_id":      testUserID,
		"model_id":     testModelID,
		"task_id":      taskID,
		"callback_url": callbackURL,
	})
}

// callbackRecorder stands in for TAA's callback endpoint: it accepts everything
// and records the terminal states the double delivers.
type callbackRecorder struct {
	*httptest.Server

	mu     sync.Mutex
	bodies []map[string]any
}

func newCallbackRecorder(t *testing.T) *callbackRecorder {
	t.Helper()
	rec := &callbackRecorder{}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Errorf("undecodable callback body %q: %v", body, err)
		}
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, decoded)
		rec.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(rec.Close)
	return rec
}

// statuses returns the status of every callback received so far, in order.
func (r *callbackRecorder) statuses() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.bodies))
	for _, b := range r.bodies {
		status, _ := b["status"].(string)
		out = append(out, status)
	}
	return out
}

func (r *callbackRecorder) waitFor(t *testing.T, status string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, got := range r.statuses() {
			if got == status {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %q callback within 10s; got %v", status, r.statuses())
}

func waitForProgress(t *testing.T, base, taskID string, minDone int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		body := getTask(t, base, taskID)
		cases, _ := body["cases"].([]any)
		done := 0
		for _, raw := range cases {
			c, _ := raw.(map[string]any)
			if c["result_id"] != nil && c["result_id"] != "" {
				done++
			}
		}
		if done >= minDone {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %s never reached %d finished cases", taskID, minDone)
}

func waitForStatus(t *testing.T, base, taskID, status string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if got, _ := getTask(t, base, taskID)["status"].(string); got == status {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %s never reached status %q", taskID, status)
}

func zipEntryNames(t *testing.T, path string) []string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer zr.Close()
	names := make([]string, 0, len(zr.File))
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	return names
}

// ── Terminal-callback cardinality ────────────────────────

// One task can deliver more than one terminal callback: the guarantee is per work
// attempt, not per task, because work resets the task's notified flag so a
// resumed attempt can report its own end. The exact shape is what this pins - a
// cancel mid-run delivers "cancelled", the /continue that follows delivers
// "completed", and nothing else arrives, so the consumer that latches the first
// one (TAA's finish is a sync.Once) is exercised on both sides of the asymmetry.
//
// It fails if the reset is removed: the resumed attempt would find notified set
// and report nothing, leaving one callback instead of two.
func TestCancelThenContinueDeliversOneTerminalCallbackPerAttempt(t *testing.T) {
	s, _ := newTestServer(t, 25*time.Millisecond)
	const taskID = "cancel-resume-task"
	entries := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		entries = append(entries, fmt.Sprintf("case-%02d.ct", i))
	}
	writeInputZip(t, s, taskID, entries...)

	rec := newCallbackRecorder(t)
	srv := serve(t, s)

	if resp := createTask(t, srv.URL, taskID, rec.URL); resp.StatusCode != http.StatusOK {
		t.Fatalf("create = %d, want 200", resp.StatusCode)
	}
	waitForProgress(t, srv.URL, taskID, 1)

	if resp := post(t, srv.URL+"/api/v1/tasks/"+taskID+"/cancel"); resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel = %d, want 200", resp.StatusCode)
	}
	rec.waitFor(t, statusCancelled)
	waitForStatus(t, srv.URL, taskID, statusCancelled)
	// The cancelled worker's inflight flag is cleared a moment after its status
	// flips, and /continue is a no-op while it is set. Give it that moment.
	time.Sleep(100 * time.Millisecond)

	if resp := post(t, srv.URL+"/api/v1/tasks/"+taskID+"/continue"); resp.StatusCode != http.StatusOK {
		t.Fatalf("continue = %d, want 200", resp.StatusCode)
	}
	rec.waitFor(t, statusCompleted)
	// A retry or a duplicate terminal state would land here.
	time.Sleep(200 * time.Millisecond)

	got := rec.statuses()
	want := []string{statusCancelled, statusCompleted}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("terminal callbacks = %v, want exactly %v (one per attempt)", got, want)
	}

	// The resumed attempt finishes the task the cancelled one left behind.
	body := getTask(t, srv.URL, taskID)
	finished := 0
	for _, raw := range body["cases"].([]any) {
		if c, _ := raw.(map[string]any); c["result_id"] != nil && c["result_id"] != "" {
			finished++
		}
	}
	if finished != len(entries) {
		t.Errorf("finished cases after the resume = %d, want %d", finished, len(entries))
	}
}

// ── Restart fidelity ─────────────────────────────────────

// The double keeps its task table in memory only, so a restart over the same data
// directory forgets a running task: the task 404s, and a replayed import creates
// it fresh with a 200 instead of resuming it with a 409. That is the fidelity gap
// the taskContinue comment documents, and it is asserted here so that the comment
// cannot silently become untrue - either by implementing persistence or by
// claiming it.
func TestRestartForgetsTheTaskInsteadOfResuming(t *testing.T) {
	dir := t.TempDir()
	first, err := newServer(dir, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	writeFile(t, first.keyPath(testUserID), []byte("eval-context"))
	writeModelDir(t, first, testModelID)
	const taskID = "restart-task"
	writeInputZip(t, first, taskID, "case-00.ct", "case-01.ct")

	rec := newCallbackRecorder(t)
	srv1 := serve(t, first)
	if resp := createTask(t, srv1.URL, taskID, rec.URL); resp.StatusCode != http.StatusOK {
		t.Fatalf("create = %d, want 200", resp.StatusCode)
	}
	rec.waitFor(t, statusCompleted)

	// The restart: a new process over the same shared directory. The old one is
	// gone, so nothing it held in memory is reachable any more.
	second, err := newServer(dir, 0)
	if err != nil {
		t.Fatalf("restart newServer: %v", err)
	}
	srv2 := serve(t, second)

	resp, err := http.Get(srv2.URL + "/api/v1/tasks/" + taskID)
	if err != nil {
		t.Fatalf("GET after restart: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET after a restart = %d, want 404: the restarted double does not remember the task", resp.StatusCode)
	}

	resp2 := post(t, srv2.URL+"/api/v1/tasks/"+taskID+"/continue")
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("continue after a restart = %d, want 404", resp2.StatusCode)
	}

	// The input archive is on disk, so the replayed create succeeds - and it is a
	// fresh task, not the resumed one the real, Redis-backed service might keep.
	resp3 := createTask(t, srv2.URL, taskID, rec.URL)
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("create after a restart = %d, want 200 (a fresh task), not %d", resp3.StatusCode, http.StatusConflict)
	}
	// Let the fresh attempt finish: the result archive is written by the worker,
	// and the temporary directory must not be torn down underneath it.
	waitForStatus(t, srv2.URL, taskID, statusCompleted)
	body := getTask(t, srv2.URL, taskID)
	cases, _ := body["cases"].([]any)
	if len(cases) != 2 {
		t.Errorf("cases on the restarted task = %d, want the whole archive re-evaluated", len(cases))
	}
}

// ── Identifier validation ────────────────────────────────

// The identifiers the double accepts must be the ones TAA accepts: it validates
// them with internal/fhe's exported patterns rather than a copy, so a tightening
// on the TAA side reaches the double. This reads the acceptance through
// checkInputs: a shape rejection is recognisable because it is the only error that
// names the field that failed the shape check.
func TestIdentifierValidationMatchesTheProductionPackage(t *testing.T) {
	s, _ := newTestServer(t, 0)

	hashLike := []string{
		testUserID,
		strings.Repeat("a", 64),
		strings.Repeat("A", 64),
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("a", 63) + "g",
		"../" + strings.Repeat("a", 61),
		"",
	}
	for _, id := range hashLike {
		assertShapeAcceptance(t, "invalid user_id", fhe.ValidHash(id), s.checkInputs(id, testModelID, "task-1"))
		assertShapeAcceptance(t, "invalid model_id", fhe.ValidHash(id), s.checkInputs(testUserID, id, "task-1"))
	}

	taskLike := []string{
		"task-1",
		"a",
		strings.Repeat("a", 128),
		strings.Repeat("a", 129),
		"..",
		"a/../b",
		"-leading-dash",
		"",
	}
	for _, id := range taskLike {
		assertShapeAcceptance(t, "invalid task id", fhe.ValidTaskID(id) == nil, s.checkInputs(testUserID, testModelID, id))
	}
}

// assertShapeAcceptance checks that checkInputs' answer is governed by the
// production validator: shapeNeedle is the phrase the double's own shape check
// emits, so seeing it means the id was refused for its shape rather than for a
// missing file.
func assertShapeAcceptance(t *testing.T, shapeNeedle string, productionAccepts bool, err error) {
	t.Helper()
	rejected := err != nil && strings.Contains(err.Error(), shapeNeedle)
	if productionAccepts && rejected {
		t.Errorf("the double rejected an id that internal/fhe accepts: %v", err)
	}
	if !productionAccepts && !rejected {
		t.Errorf("an id internal/fhe rejects got err = %v, want an %q error", err, shapeNeedle)
	}
}

// ── Result-archive entry names ───────────────────────────

// Input-archive entry names are attacker-controlled and are copied into the
// archive TAA downloads, so a name that walks out of the archive must not survive
// the copy. It fails if resultName stops sanitising: "../evil.ct" would appear as
// "../evil.result.bin" in output.zip.
func TestResultArchiveEntryNamesStayInsideTheArchive(t *testing.T) {
	s, dir := newTestServer(t, 0)
	const taskID = "entry-name-task"
	writeInputZip(t, s, taskID, "case-00.ct", "../evil.ct", "sub/dir/case-01.ct", `..\win.ct`)

	rec := newCallbackRecorder(t)
	srv := serve(t, s)
	if resp := createTask(t, srv.URL, taskID, rec.URL); resp.StatusCode != http.StatusOK {
		t.Fatalf("create = %d, want 200", resp.StatusCode)
	}
	rec.waitFor(t, statusCompleted)
	waitForStatus(t, srv.URL, taskID, statusCompleted)

	names := zipEntryNames(t, filepath.Join(dir, "results", taskID, resultZipName))
	want := map[string]bool{
		"case-00.result.bin": true,
		"evil.result.bin":    true,
		"case-01.result.bin": true,
		"win.result.bin":     true,
	}
	if len(names) != len(want) {
		t.Fatalf("result entries = %v, want %d entries: %v", names, len(want), want)
	}
	for _, name := range names {
		if !want[name] {
			t.Errorf("unexpected result entry %q", name)
		}
		if strings.ContainsAny(name, `/\`) || name == ".." || name == "." || strings.HasPrefix(name, "..") {
			t.Errorf("result entry %q can leave the archive it is written into", name)
		}
	}
}

// ── Shared-directory paths ───────────────────────────────

// The result_zip the double reports is relative to the data directory. It is
// informational - TAA locates the archive through its own layout - but it is
// client-visible, so an absolute host path must not appear in it.
func TestReportedResultZipIsRelativeToTheDataDir(t *testing.T) {
	s, _ := newTestServer(t, 0)
	const taskID = "result-zip-task"
	writeInputZip(t, s, taskID, "case-00.ct")

	rec := newCallbackRecorder(t)
	srv := serve(t, s)
	if resp := createTask(t, srv.URL, taskID, rec.URL); resp.StatusCode != http.StatusOK {
		t.Fatalf("create = %d, want 200", resp.StatusCode)
	}
	rec.waitFor(t, statusCompleted)

	got, _ := getTask(t, srv.URL, taskID)["result_zip"].(string)
	if want := "results/" + taskID + "/" + resultZipName; got != want {
		t.Errorf("result_zip = %q, want %q", got, want)
	}
	if filepath.IsAbs(got) || strings.Contains(got, s.dataDir) {
		t.Errorf("result_zip %q leaks the data directory %s", got, s.dataDir)
	}
}
