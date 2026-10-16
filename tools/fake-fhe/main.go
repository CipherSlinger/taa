// Command fake-fhe stands in for the Latti FHE service so the whole TAA
// integration can be exercised on a machine with no GPU.
//
// The real service is CUDA-only (build-info/manifest.json pins
// cuda_architecture 89, Ada) and cannot run here. This one implements the same
// /api/v1 surface and the same shared-directory contract, substituting a trivial
// transform for the homomorphic evaluation: it writes one placeholder
// <case_id>.result.bin per ciphertext entry of the task's input archive into
// results/<task_id>/output.zip. It is a contract test double, not a
// cryptographic implementation, and must never be deployed as one.
//
// Like the real service it reads its inputs from the shared directory only - it
// has no upload endpoint - and it refuses a task whose eval context, model, or
// input archive is not already on disk. That refusal is the point: the fake must
// not go green on a premise the real service would reject.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Names inside the shared directory, fixed by the service contract.
const (
	evalKeyFileName = "eval_context.bin"
	taskInputName   = "input.zip"
	resultZipName   = "output.zip"
)

// Task statuses. The terminal ones end the worker and trigger the callback.
const (
	statusQueued    = "queued"
	statusRunning   = "running"
	statusCompleted = "completed"
	statusFailed    = "failed"
	statusCancelled = "cancelled"
)

// placeholderResultBytes is the size of one faked case result. A real result is
// a ciphertext of the same order, so the archive TAA downloads, unpacks, and
// reports on has a realistic shape without a multi-gigabyte footprint.
const placeholderResultBytes = 128 << 10

// callbackBackoff is the retry schedule for the terminal-state notification:
// four attempts, waiting 0/1/4/16 s before each one. A callback that never
// arrives must not wedge the caller, so the last attempt gives up and only logs.
var callbackBackoff = []time.Duration{0, time.Second, 4 * time.Second, 16 * time.Second}

var (
	hashPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type task struct {
	ID        string
	UserID    string
	ModelID   string
	Status    string
	Callback  string
	ResultZip string
	Cases     []caseResult

	// notified records that the terminal-state callback has been claimed, so a
	// cancel racing the worker cannot post the same terminal state twice.
	notified bool
}

type caseResult struct {
	Entry    string `json:"entry"`
	ResultID string `json:"result_id,omitempty"`
	Error    string `json:"error,omitempty"`

	// data is the placeholder result written into output.zip. It is never part
	// of a JSON body, so it carries no tag.
	data []byte
}

type server struct {
	dataDir string
	delay   time.Duration
	client  *http.Client

	mu        sync.Mutex
	tasks     map[string]*task
	inflight  map[string]bool
	activated map[string]bool
}

func main() {
	dataDir := flag.String("data-dir", "", "shared data directory (required)")
	addr := flag.String("addr", "127.0.0.1:58996", "listen address")
	delay := flag.Duration("delay", 200*time.Millisecond, "simulated per-case work")
	flag.Parse()
	if *dataDir == "" {
		log.Fatal("fake-fhe: -data-dir is required")
	}
	abs, err := filepath.Abs(*dataDir)
	if err != nil {
		log.Fatalf("fake-fhe: resolve data dir: %v", err)
	}
	// The four subdirectories are the contract TAA publishes into; create them so
	// a missing-dir error can only ever mean a missing input, not a missing root.
	for _, sub := range []string{"models", "keys", "tasks", "results"} {
		if err := os.MkdirAll(filepath.Join(abs, sub), 0o755); err != nil {
			log.Fatalf("fake-fhe: %v", err)
		}
	}

	s := &server{
		dataDir:   abs,
		delay:     *delay,
		client:    &http.Client{Timeout: 10 * time.Second},
		tasks:     map[string]*task{},
		inflight:  map[string]bool{},
		activated: map[string]bool{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.health)
	mux.HandleFunc("/api/v1/models", s.models)
	mux.HandleFunc("/api/v1/models/activate", s.activate)
	mux.HandleFunc("/api/v1/tasks", s.createTask)
	mux.HandleFunc("/api/v1/tasks/", s.taskRoutes)

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("fake-fhe listening on %s, data dir %s", *addr, abs)
	log.Fatal(httpServer.ListenAndServe())
}

// ── Shared-directory paths ───────────────────────────────

// The identifiers below arrive in HTTP bodies and headers and are used verbatim
// as path segments, so every one of them is validated first. This mirrors the
// layout the TAA side builds: <data>/models/<model>/server, <data>/keys/<user>/
// eval_context.bin, <data>/tasks/<id>/input.zip, <data>/results/<id>/output.zip.

func (s *server) keyPath(userID string) string {
	return filepath.Join(s.dataDir, "keys", userID, evalKeyFileName)
}

func (s *server) modelServerDir(modelID string) string {
	return filepath.Join(s.dataDir, "models", modelID, "server")
}

func (s *server) taskInputPath(taskID string) string {
	return filepath.Join(s.dataDir, "tasks", taskID, taskInputName)
}

func (s *server) resultPath(taskID string) string {
	return filepath.Join(s.dataDir, "results", taskID, resultZipName)
}

// ── Endpoints ────────────────────────────────────────────

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	// Readiness here means the shared directory is usable, which is the only
	// thing the fake can fail on that the real service also fails on.
	if st, err := os.Stat(s.dataDir); err != nil || !st.IsDir() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "error",
			"error":  "data directory " + s.dataDir + " is not readable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *server) models(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	entries, err := os.ReadDir(filepath.Join(s.dataDir, "models"))
	if err != nil && !os.IsNotExist(err) {
		writeError(w, http.StatusInternalServerError, "read the models directory: "+err.Error())
		return
	}

	s.mu.Lock()
	activated := make(map[string]bool, len(s.activated))
	for id, ok := range s.activated {
		activated[id] = ok
	}
	s.mu.Unlock()

	models := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		st, statErr := os.Stat(filepath.Join(s.dataDir, "models", entry.Name(), "server"))
		models = append(models, map[string]any{
			"model_id":   entry.Name(),
			"server_dir": statErr == nil && st.IsDir(),
			"activated":  activated[entry.Name()],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models})
}

// activate hot-loads a model. Activation is idempotent, and it is not a
// precondition of creating a task: a task needs the model on disk, which is what
// the create-time check enforces.
func (s *server) activate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	modelID := strings.TrimSpace(r.URL.Query().Get("model_id"))
	if modelID == "" {
		modelID = strings.TrimSpace(r.FormValue("model_id"))
	}
	if !hashPattern.MatchString(modelID) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid model_id %q: want 64 lowercase hex characters", modelID))
		return
	}
	serverDir := s.modelServerDir(modelID)
	if st, err := os.Stat(serverDir); err != nil || !st.IsDir() {
		writeError(w, http.StatusNotFound, fmt.Sprintf("model %s has no server directory at %s", modelID, serverDir))
		return
	}

	s.mu.Lock()
	s.activated[modelID] = true
	s.mu.Unlock()

	log.Printf("fake-fhe: model %s activated", modelID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "model_id": modelID})
}

func (s *server) createTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var req struct {
		UserID             string `json:"user_id"`
		ModelID            string `json:"model_id"`
		TaskID             string `json:"task_id"`
		CallbackURL        string `json:"callback_url"`
		CancelOnDisconnect bool   `json:"cancel_on_disconnect"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read the request body: "+err.Error())
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "decode the request body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.UserID) == "" {
		req.UserID = strings.TrimSpace(r.Header.Get("X-User-Id"))
	}
	if err := s.checkInputs(req.UserID, req.ModelID, req.TaskID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	t := &task{
		ID:       req.TaskID,
		UserID:   req.UserID,
		ModelID:  req.ModelID,
		Status:   statusQueued,
		Callback: strings.TrimSpace(req.CallbackURL),
	}
	s.mu.Lock()
	if _, exists := s.tasks[t.ID]; exists {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "task "+t.ID+" already exists; POST /continue to resume it")
		return
	}
	s.tasks[t.ID] = t
	s.mu.Unlock()

	log.Printf("fake-fhe: task %s queued (user=%s model=%s)", t.ID, t.UserID, t.ModelID)
	go s.work(t)
	writeJSON(w, http.StatusOK, map[string]any{"task_id": t.ID, "status": statusQueued})
}

// checkInputs enforces what the real service requires before it accepts a task:
// the eval context, the model, and the input archive must all already be in the
// shared directory. Nothing is uploaded over HTTP.
func (s *server) checkInputs(userID, modelID, taskID string) error {
	if !hashPattern.MatchString(userID) {
		return fmt.Errorf("invalid user_id %q: want 64 lowercase hex characters", userID)
	}
	if !hashPattern.MatchString(modelID) {
		return fmt.Errorf("invalid model_id %q: want 64 lowercase hex characters", modelID)
	}
	if !taskIDPattern.MatchString(taskID) {
		return fmt.Errorf("invalid task_id %q: want 1-128 characters of [A-Za-z0-9._-] starting with an alphanumeric", taskID)
	}
	if st, err := os.Stat(s.keyPath(userID)); err != nil || st.IsDir() {
		return fmt.Errorf("no eval context at keys/%s/%s", userID, evalKeyFileName)
	}
	if st, err := os.Stat(s.modelServerDir(modelID)); err != nil || !st.IsDir() {
		return fmt.Errorf("no model at models/%s/server", modelID)
	}
	if st, err := os.Stat(s.taskInputPath(taskID)); err != nil || st.IsDir() {
		return fmt.Errorf("no input archive at tasks/%s/%s", taskID, taskInputName)
	}
	return nil
}

func (s *server) taskRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/tasks/")
	if rest == r.URL.Path || rest == "" {
		writeError(w, http.StatusNotFound, "unknown task endpoint "+r.URL.Path)
		return
	}
	id, action, _ := strings.Cut(rest, "/")
	switch action {
	case "":
		s.taskStatus(w, r, id)
	case "cancel":
		s.taskCancel(w, r, id)
	case "continue":
		s.taskContinue(w, r, id)
	case "results/download":
		s.taskDownload(w, r, id)
	default:
		writeError(w, http.StatusNotFound, "unknown task endpoint "+r.URL.Path)
	}
}

func (s *server) taskStatus(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	snap, ok := s.snapshot(id, requestUserID(r))
	if !ok {
		writeError(w, http.StatusNotFound, "no such task "+id)
		return
	}
	writeJSON(w, http.StatusOK, snap.body())
}

func (s *server) taskCancel(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	s.mu.Lock()
	t, ok := s.lookupLocked(id, requestUserID(r))
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "no such task "+id)
		return
	}

	// Cancelling a finished task is a no-op, not an error: the caller may race
	// the terminal state.
	s.complete(t, statusCancelled, nil)
	snap, _ := s.snapshot(id, requestUserID(r))
	writeJSON(w, http.StatusOK, snap.body())
}

// taskContinue reruns whatever the task has not finished. The input archive and
// the per-case results survive a restart, so a replayed import resumes instead
// of starting over.
func (s *server) taskContinue(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	s.mu.Lock()
	t, ok := s.lookupLocked(id, requestUserID(r))
	if ok && (s.inflight[id] || t.Status == statusCompleted) {
		s.mu.Unlock()
		snap, _ := s.snapshot(id, requestUserID(r))
		writeJSON(w, http.StatusOK, snap.body())
		return
	}
	prevStatus := ""
	if ok {
		prevStatus = t.Status
	}
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "no such task "+id)
		return
	}

	// Resume is the point of this endpoint: a task that stopped in a
	// non-completed terminal state (cancelled, failed) picks up its unfinished
	// cases, and one that never started runs from the beginning.
	log.Printf("fake-fhe: task %s continued from %s", id, prevStatus)
	go s.work(t)
	writeJSON(w, http.StatusOK, map[string]any{"task_id": id, "status": statusRunning})
}

func (s *server) taskDownload(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	if _, ok := s.snapshot(id, requestUserID(r)); !ok {
		writeError(w, http.StatusNotFound, "no such task "+id)
		return
	}
	f, err := os.Open(s.resultPath(id))
	if err != nil {
		writeError(w, http.StatusNotFound, "no result archive for task "+id)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stat the result archive: "+err.Error())
		return
	}
	http.ServeContent(w, r, resultZipName, st.ModTime(), f)
}

// ── Worker ───────────────────────────────────────────────

// work drives one task to a terminal state the way the service's worker does:
// read the input archive, produce one result per case, write the result archive
// back into the shared directory, then notify the callback URL.
//
// It never runs twice for the same task: the inflight map makes /continue and a
// late /create idempotent under concurrency.
func (s *server) work(t *task) {
	s.mu.Lock()
	if s.inflight[t.ID] {
		s.mu.Unlock()
		return
	}
	s.inflight[t.ID] = true
	t.Status = statusRunning
	// A resumed task is a new attempt, so it claims the callback again: the
	// terminal state of the attempt that stopped was already reported, and this
	// one would otherwise never be.
	t.notified = false
	known := len(t.Cases)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.inflight, t.ID)
		s.mu.Unlock()
	}()

	if known == 0 {
		cases, err := readCases(s.taskInputPath(t.ID))
		if err != nil {
			s.complete(t, statusFailed, fmt.Errorf("read %s: %w", taskInputName, err))
			return
		}
		if len(cases) == 0 {
			s.complete(t, statusFailed, errors.New("the input archive holds no cases"))
			return
		}
		s.mu.Lock()
		t.Cases = cases
		s.mu.Unlock()
	}

	for _, entry := range s.pendingEntries(t.ID) {
		if s.isCancelled(t.ID) {
			s.complete(t, statusCancelled, nil)
			return
		}
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		if s.isCancelled(t.ID) {
			s.complete(t, statusCancelled, nil)
			return
		}

		s.storeCaseResult(t.ID, entry, resultName(entry), placeholderResult(entry))
		if err := s.writeResultZip(t.ID); err != nil {
			s.markCaseError(t.ID, entry, err.Error())
		}
	}

	done, errored, pending := s.caseCounts(t.ID)
	if errored > 0 {
		s.complete(t, statusFailed, fmt.Errorf("%d of %d cases failed", errored, done+errored+pending))
		return
	}
	if pending > 0 {
		s.complete(t, statusFailed, fmt.Errorf("%d of %d cases did not complete", pending, done+pending))
		return
	}
	s.complete(t, statusCompleted, nil)
}

// readCases lists the cases of an input archive: every non-directory entry is
// one ciphertext to evaluate, and its name decides the result name.
func readCases(inputPath string) ([]caseResult, error) {
	zr, err := zip.OpenReader(inputPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	cases := make([]caseResult, 0, len(zr.File))
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || strings.HasSuffix(f.Name, "/") {
			continue
		}
		cases = append(cases, caseResult{Entry: f.Name})
	}
	return cases, nil
}

// resultName maps a case's ciphertext entry to its result entry.
func resultName(entry string) string {
	return strings.TrimSuffix(entry, filepath.Ext(entry)) + ".result.bin"
}

// placeholderResult returns deterministic bytes standing in for an evaluated
// ciphertext. Determinism keeps a resumed task's archive reproducible; the size
// is what makes the archive realistic to unpack and report on.
func placeholderResult(entry string) []byte {
	state := uint64(0x9e3779b97f4a7c15)
	for _, b := range []byte(entry) {
		state = state*1099511628211 ^ uint64(b)
	}
	buf := make([]byte, placeholderResultBytes)
	for i := range buf {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		buf[i] = byte(state)
	}
	return buf
}

// writeResultZip rewrites results/<id>/output.zip from the results produced so
// far. The rename at the end keeps a reader from ever seeing a partial archive.
func (s *server) writeResultZip(taskID string) error {
	cases := s.caseSnapshot(taskID)
	dir := filepath.Join(s.dataDir, "results", taskID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, resultZipName+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()

	zw := zip.NewWriter(tmp)
	for _, c := range cases {
		if c.ResultID == "" {
			continue
		}
		// Ciphertext does not compress; store it instead of paying deflate.
		hdr := &zip.FileHeader{Name: c.ResultID, Method: zip.Store, Modified: time.Now()}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if _, err := w.Write(c.data); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	// CreateTemp is 0600; the shared directory is read by the TAA side, so the
	// archive lands with the same mode the rest of the layout uses.
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.resultPath(taskID)); err != nil {
		return err
	}
	ok = true
	return nil
}

// complete moves the task to a terminal state and posts its callback exactly
// once, whichever of the worker or a cancel gets there first.
func (s *server) complete(t *task, status string, cause error) {
	s.mu.Lock()
	if t.notified {
		s.mu.Unlock()
		return
	}
	t.notified = true
	t.Status = status
	if status == statusCompleted {
		t.ResultZip = pathInData(filepath.Join("results", t.ID, resultZipName))
	}
	snap := t.snapshot()
	s.mu.Unlock()

	if cause != nil {
		log.Printf("fake-fhe: task %s ended as %s: %v", t.ID, status, cause)
	} else {
		log.Printf("fake-fhe: task %s ended as %s", t.ID, status)
	}
	go s.notify(snap)
}

// notify posts the terminal state to the callback URL, retrying on the service's
// 0/1/4/16 s schedule. The callback is best effort: TAA polls as a fallback, so
// giving up only delays the outcome.
func (s *server) notify(snap taskSnapshot) {
	if snap.Callback == "" {
		log.Printf("fake-fhe: task %s has no callback URL", snap.ID)
		return
	}
	body, err := json.Marshal(snap.body())
	if err != nil {
		log.Printf("fake-fhe: encode the callback for task %s: %v", snap.ID, err)
		return
	}

	for attempt, wait := range callbackBackoff {
		if wait > 0 {
			time.Sleep(wait)
		}
		req, err := http.NewRequest(http.MethodPost, snap.Callback, bytes.NewReader(body))
		if err != nil {
			log.Printf("fake-fhe: build the callback for task %s: %v", snap.ID, err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(req)
		if err != nil {
			log.Printf("fake-fhe: callback for task %s, attempt %d: %v", snap.ID, attempt+1, err)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("fake-fhe: callback for task %s delivered (%s)", snap.ID, snap.Status)
			return
		}
		log.Printf("fake-fhe: callback for task %s, attempt %d: HTTP %d", snap.ID, attempt+1, resp.StatusCode)
	}
	log.Printf("fake-fhe: gave up on the callback for task %s after %d attempts", snap.ID, len(callbackBackoff))
}

// ── Task state ───────────────────────────────────────────

// taskSnapshot is a task's state read under the lock. Everything a handler or a
// callback is built from goes through one, so no goroutine reads a task while
// the worker is writing it.
type taskSnapshot struct {
	ID        string
	Status    string
	ResultZip string
	Callback  string
	Cases     []caseResult
}

// body is the JSON a task reports: the shape both GET /tasks/{id} and the
// callback carry, as the client documents it (status, result_zip, cases[].entry,
// cases[].result_id, cases[].error).
func (t taskSnapshot) body() map[string]any {
	out := map[string]any{
		"task_id": t.ID,
		"status":  t.Status,
		"cases":   t.Cases,
	}
	if t.ResultZip != "" {
		out["result_zip"] = t.ResultZip
	}
	return out
}

func (t *task) snapshot() taskSnapshot {
	return taskSnapshot{
		ID:        t.ID,
		Status:    t.Status,
		ResultZip: t.ResultZip,
		Callback:  t.Callback,
		Cases:     append([]caseResult(nil), t.Cases...),
	}
}

// lookupLocked finds a task by id. A request that names a user may only see its
// own tasks, which is the scoping the real service applies.
func (s *server) lookupLocked(id, userID string) (*task, bool) {
	t, ok := s.tasks[id]
	if !ok {
		return nil, false
	}
	if userID != "" && t.UserID != userID {
		return nil, false
	}
	return t, true
}

func (s *server) snapshot(id, userID string) (taskSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.lookupLocked(id, userID)
	if !ok {
		return taskSnapshot{}, false
	}
	return t.snapshot(), true
}

func (s *server) isCancelled(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	return ok && t.Status == statusCancelled
}

// pendingEntries lists the cases that still need work, in archive order.
func (s *server) pendingEntries(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return nil
	}
	pending := make([]string, 0, len(t.Cases))
	for _, c := range t.Cases {
		if c.ResultID == "" && c.Error == "" {
			pending = append(pending, c.Entry)
		}
	}
	return pending
}

func (s *server) caseCounts(id string) (done, errored, pending int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return 0, 0, 0
	}
	for _, c := range t.Cases {
		switch {
		case c.Error != "":
			errored++
		case c.ResultID != "":
			done++
		default:
			pending++
		}
	}
	return done, errored, pending
}

func (s *server) caseSnapshot(id string) []caseResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return nil
	}
	return append([]caseResult(nil), t.Cases...)
}

func (s *server) storeCaseResult(id, entry, resultID string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return
	}
	for i := range t.Cases {
		if t.Cases[i].Entry == entry {
			t.Cases[i].ResultID = resultID
			t.Cases[i].data = data
			return
		}
	}
}

func (s *server) markCaseError(id, entry, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return
	}
	for i := range t.Cases {
		if t.Cases[i].Entry == entry {
			t.Cases[i].Error = msg
			t.Cases[i].ResultID = ""
			return
		}
	}
}

// ── Small helpers ────────────────────────────────────────

func requestUserID(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-User-Id"))
}

// pathInData renders a shared-directory path the way the service reports it:
// relative to the data directory, with forward slashes.
func pathInData(p string) string {
	return filepath.ToSlash(p)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed; want "+allow)
}
