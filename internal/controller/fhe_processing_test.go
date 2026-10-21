package controller

import (
	"archive/zip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"taa/internal/fhe"
)

// newFHETestState builds the state of a server.type=fhe instance: a TAAState with
// a runner installed, which is the single switch fheEnabled keys on.
//
// The runner is a real one built with fhe.New against a temporary data dir. The
// tests here never call the FHE service, so no endpoint has to answer; the point
// is only that the pointer is non-nil.
func newFHETestState(t *testing.T) *TAAState {
	t.Helper()
	runner, err := fhe.New(fhe.Config{
		Endpoint:        "http://127.0.0.1:58996",
		DataDir:         t.TempDir(),
		KeyCacheDir:     t.TempDir(),
		CallbackBaseURL: "http://127.0.0.1:6001",
		MaxEvalKeyBytes: fhe.DefaultMaxEvalKeyBytes,
		PollInterval:    fhe.DefaultPollInterval,
		RequestTimeout:  fhe.DefaultRequestTimeout,
	}, nil)
	if err != nil {
		t.Fatalf("fhe.New: %v", err)
	}
	state := &TAAState{}
	state.SetFHERunner(runner)
	return state
}

// newTEETestState builds the state of a server.type=tee instance: no runner, so
// fheEnabled is false. That is exactly how app.buildFHERunner leaves a tee boot.
func newTEETestState() *TAAState {
	return &TAAState{}
}

const validEvalKeyHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestValidateFHEFields covers every branch of the field/instance-type matrix.
//
// Each rejection asserts on the message as well as on the fact of an error: the
// three messages mean three different operator mistakes, and a test that only
// checked for "some error" would pass even if the wrong branch fired.
func TestValidateFHEFields(t *testing.T) {
	const (
		msgTee  = "本实例类型为 tee，不接受 evalKeyUrl / evalKeyFileHash 字段"
		msgFHE  = "本实例类型为 fhe，evalKeyUrl 与 evalKeyFileHash 必须同时提供"
		msgHash = "evalKeyFileHash 必须是 64 位小写十六进制 SM3 摘要"
		msgTask = "本实例类型为 fhe，taskId 不能为空"
	)

	tests := []struct {
		name    string
		fhe     bool
		taskID  string
		url     string
		hash    string
		wantErr string // "" means the request must be accepted
	}{
		{"tee with neither field is accepted", false, "", "", "", ""},
		{"tee with evalKeyUrl only is rejected", false, "", "http://keys/1.bin", "", msgTee},
		{"tee with evalKeyFileHash only is rejected", false, "", "", validEvalKeyHash, msgTee},
		{"tee with both fields is rejected", false, "", "http://keys/1.bin", validEvalKeyHash, msgTee},

		// Whitespace-only input must count as absent, which is what makes the
		// "only one provided" case below a real rejection rather than a blank
		// string that happened to be non-empty.
		{"tee with whitespace-only fields is accepted", false, "", "   ", "\t\n", ""},

		{"fhe with neither field is rejected", true, "task-1", "", "", msgFHE},
		{"fhe with evalKeyUrl only is rejected", true, "task-1", "http://keys/1.bin", "", msgFHE},
		{"fhe with evalKeyFileHash only is rejected", true, "task-1", "", validEvalKeyHash, msgFHE},
		{"fhe with a whitespace-only url is rejected", true, "task-1", "   ", validEvalKeyHash, msgFHE},
		{"fhe with a whitespace-only hash is rejected", true, "task-1", "http://keys/1.bin", "  ", msgFHE},

		{"fhe with an uppercase hash is rejected", true, "task-1", "http://keys/1.bin", strings.ToUpper(validEvalKeyHash), msgHash},
		{"fhe with a short hash is rejected", true, "task-1", "http://keys/1.bin", validEvalKeyHash[:63], msgHash},
		{"fhe with a non-hex hash is rejected", true, "task-1", "http://keys/1.bin", strings.Repeat("z", 64), msgHash},
		{"fhe with a path-traversal hash is rejected", true, "task-1", "http://keys/1.bin", "../../etc/passwd", msgHash},

		// The FHE service keys the run, its input directory and its results by taskId,
		// so an import carrying only a requestId has nothing to submit under.
		{"fhe without a taskId is rejected", true, "", "http://keys/1.bin", validEvalKeyHash, msgTask},
		{"fhe with a whitespace-only taskId is rejected", true, "   ", "http://keys/1.bin", validEvalKeyHash, msgTask},

		{"fhe with both fields, a valid hash and a taskId is accepted", true, "task-1", "http://keys/1.bin", validEvalKeyHash, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := newTEETestState()
			if tc.fhe {
				state = newFHETestState(t)
			}

			err := state.validateFHEFields(importRequest{
				TaskID:          tc.taskID,
				EvalKeyURL:      tc.url,
				EvalKeyFileHash: tc.hash,
			})

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateFHEFields() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateFHEFields() = nil, want error %q", tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("validateFHEFields() = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// ── FHE task execution and result landing ────────────────────────────────

// newStubRunner builds a runner with no live service behind it.
//
// Its endpoint is a closed port, so it is only useful to tests that read the
// runner's presence (the instance-type switch) or that deliberately drive the
// failure branch of Execute. The callback and export test files share it and
// must not redefine it.
func newStubRunner(t *testing.T) *fhe.Runner {
	t.Helper()
	r, err := fhe.New(fhe.Config{
		Endpoint: "http://127.0.0.1:1", DataDir: t.TempDir(), KeyCacheDir: t.TempDir(),
		CallbackBaseURL: "http://taa:6001",
		MaxEvalKeyBytes: fhe.DefaultMaxEvalKeyBytes,
		PollInterval:    time.Second, RequestTimeout: time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("fhe.New: %v", err)
	}
	return r
}

// decodeImportRequest decodes a request body the way the import endpoints do.
func decodeImportRequest(body string, req *importRequest) error {
	return json.Unmarshal([]byte(body), req)
}

// postImport drives the real handler, so the FHE field validation is exercised
// through the HTTP surface the platform actually uses.
func postImport(t *testing.T, s *TAAState, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/import", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.importHandler(rec, req)
	return rec
}

func TestFHEImportRequestFieldsDecode(t *testing.T) {
	body := `{"resourceUrl":"http://x/in.zip","requestId":"r","taskId":"t",
	          "evalKeyUrl":"http://x/eval_context.bin","evalKeyFileHash":"` + strings.Repeat("a", 64) + `"}`
	var req importRequest
	if err := decodeImportRequest(body, &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.EvalKeyURL != "http://x/eval_context.bin" {
		t.Errorf("EvalKeyURL = %q", req.EvalKeyURL)
	}
	if req.EvalKeyFileHash != strings.Repeat("a", 64) {
		t.Errorf("EvalKeyFileHash = %q", req.EvalKeyFileHash)
	}
}

func TestImportRejectsFHEFieldsOnTEEInstance(t *testing.T) {
	s, _ := setupTestState(t)
	rec := postImport(t, s, `{"resourceUrl":"http://x/in.zip","requestId":"r","taskId":"t",
	  "evalKeyUrl":"http://x/k","evalKeyFileHash":"`+strings.Repeat("a", 64)+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "tee") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

// TestImportLogsEvalKeyFields covers the operator-facing record of which eval key
// a task is attributed to. The download target is a closed port: the handler logs
// the fields before it starts downloading, so the failed request still carries
// the line.
func TestImportLogsEvalKeyFields(t *testing.T) {
	env := newFHETestEnv(t)
	keyURL := env.stub.URL + "/eval_context.bin"
	rec := postImport(t, env.state, `{"resourceUrl":"http://127.0.0.1:1/in.zip",
	  "requestId":"req-log","taskId":"task-log",
	  "evalKeyUrl":"`+keyURL+`","evalKeyFileHash":"`+env.keyHash+`"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a failed download: %s", rec.Code, rec.Body.String())
	}
	requireLog(t, env.state, "evalKeyUrl="+keyURL)
	requireLog(t, env.state, "evalKeyFileHash="+env.keyHash)
}

// TestImportLogsRejectedEvalKeyRequest covers the request an operator actually
// has to diagnose: one the handler refuses for missing eval key fields. The
// record has to be written before the check, and it has to name the fields the
// request carried, so a field sent under a name TAA does not know is visible as
// such instead of looking like a field that was never sent.
func TestImportLogsRejectedEvalKeyRequest(t *testing.T) {
	env := newFHETestEnv(t)
	rec := postImport(t, env.state, `{"resourceUrl":"http://127.0.0.1:1/in.zip",
	  "requestId":"req-log-reject","taskId":"task-log-reject",
	  "evalKeyUrl":"http://keys/1.bin"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing evalKeyFileHash: %s", rec.Code, rec.Body.String())
	}
	requireLog(t, env.state, "evalKeyUrl=http://keys/1.bin")
	requireLog(t, env.state, "evalKeyFileHash=,")
	requireLog(t, env.state, "请求字段=evalKeyUrl,requestId,resourceUrl,taskId")
	requireLog(t, env.state, "拒绝数据 import 请求")
}

// fheServiceStub answers the calls the runner makes, so a controller-level test
// can drive a whole FHE task without the real service.
type fheServiceStub struct {
	*httptest.Server

	evalKey []byte

	mu             sync.Mutex
	created        []fhe.CreateTaskRequest
	activations    []string
	cancels        []string
	polls          int
	taskStatus     string
	caseEntries    int
	downloadStatus int
	downloadBody   string
	logBody        string

	// pollGate, when non-nil, holds a poll response until it is closed. A test
	// uses it to park a run inside its poll loop: that is the one moment a run can
	// be resolved by a callback and still be in the runner's in-flight table,
	// because Execute drops it there when it returns.
	pollGate chan struct{}

	// downloadGate, when non-nil, holds a result download until it is closed. It
	// parks a run that has already finished - Execute has returned and dropped the
	// task from the runner's table - inside CopyResult, which is where a stop used
	// to find a task marked active that no longer existed.
	downloadGate chan struct{}
	downloads    int

	// onCreate runs inside the service call that creates a task, which is the only
	// moment a run's own state can be sampled without racing it.
	onCreate           func()
	opDuringCreate     string
	activeDuringCreate string
	busyDuringCreate   bool
}

func newFHEServiceStub(t *testing.T) *fheServiceStub {
	t.Helper()
	s := &fheServiceStub{
		evalKey:      []byte("eval-context-bytes"),
		taskStatus:   "completed",
		caseEntries:  1,
		downloadBody: "DOWNLOADED-RESULT",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/eval_context.bin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(s.evalKey)
	})
	mux.HandleFunc("/api/v1/models/activate", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.activations = append(s.activations, r.URL.Query().Get("model_id"))
		s.mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/api/v1/tasks", func(w http.ResponseWriter, r *http.Request) {
		var req fhe.CreateTaskRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.created = append(s.created, req)
		cb := s.onCreate
		s.mu.Unlock()
		if cb != nil {
			cb()
		}
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/api/v1/tasks/", s.serveTask)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *fheServiceStub) serveTask(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/tasks/")
	switch {
	case strings.HasSuffix(path, "/results/download"):
		s.mu.Lock()
		status, body := s.downloadStatus, s.downloadBody
		gate := s.downloadGate
		s.downloads++
		s.mu.Unlock()
		if gate != nil {
			<-gate
		}
		if status != 0 {
			http.Error(w, "download refused", status)
			return
		}
		_, _ = w.Write([]byte(body))
	case strings.HasSuffix(path, "/logs"):
		s.mu.Lock()
		body := s.logBody
		s.mu.Unlock()
		_, _ = w.Write([]byte(body))
	case strings.HasSuffix(path, "/cancel"):
		s.mu.Lock()
		s.cancels = append(s.cancels, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	case strings.HasSuffix(path, "/continue"):
		_, _ = w.Write([]byte(`{}`))
	default:
		s.mu.Lock()
		s.polls++
		gate := s.pollGate
		status, entries := s.taskStatus, s.caseEntries
		s.mu.Unlock()
		if gate != nil {
			<-gate
		}
		cases := make([]fhe.CaseStatus, 0, entries)
		for i := 0; i < entries; i++ {
			cases = append(cases, fhe.CaseStatus{Entry: "case", ResultID: "r"})
		}
		_ = json.NewEncoder(w).Encode(fhe.TaskStatus{TaskID: path, Status: status, Cases: cases})
	}
}

func (s *fheServiceStub) createdTasks() []fhe.CreateTaskRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]fhe.CreateTaskRequest(nil), s.created...)
}

func (s *fheServiceStub) activateCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.activations...)
}

func (s *fheServiceStub) setTaskStatus(status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.taskStatus = status
}

// cancelCalls is every cancel request the service received, as "METHOD path".
func (s *fheServiceStub) cancelCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cancels...)
}

// holdPolls makes every poll block until releasePolls is called.
func (s *fheServiceStub) holdPolls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pollGate = make(chan struct{})
}

// releasePolls lets a poll held by holdPolls answer, and later polls run free.
func (s *fheServiceStub) releasePolls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pollGate != nil {
		close(s.pollGate)
		s.pollGate = nil
	}
}

func (s *fheServiceStub) pollCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.polls
}

func (s *fheServiceStub) failDownload(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downloadStatus = status
}

// holdDownloads makes the next result download block until releaseDownloads is
// called.
func (s *fheServiceStub) holdDownloads() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downloadGate = make(chan struct{})
}

// releaseDownloads lets a held download answer, and later ones run free.
func (s *fheServiceStub) releaseDownloads() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.downloadGate != nil {
		close(s.downloadGate)
		s.downloadGate = nil
	}
}

func (s *fheServiceStub) downloadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.downloads
}

func (s *fheServiceStub) sampleOnCreate() (op, active string, busy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opDuringCreate, s.activeDuringCreate, s.busyDuringCreate
}

// evalKeyHash is the digest the platform declares for the stub's eval key. The
// runner verifies the downloaded key against it, so the two must agree.
func (s *fheServiceStub) evalKeyHash(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eval_context.bin")
	if err := os.WriteFile(path, s.evalKey, 0o600); err != nil {
		t.Fatalf("write eval key: %v", err)
	}
	hash, err := sm3HexOfFile(path)
	if err != nil {
		t.Fatalf("hash eval key: %v", err)
	}
	return hash
}

// fheTestEnv is one FHE instance worth of fixture: the controller state, the stub
// service answering it, and the runner whose shared directory the two share.
type fheTestEnv struct {
	t         *testing.T
	state     *TAAState
	stub      *fheServiceStub
	runner    *fhe.Runner
	sharedDir string
	keyHash   string
	modelHash string
}

func newFHETestEnv(t *testing.T) *fheTestEnv {
	t.Helper()
	stub := newFHEServiceStub(t)
	sharedDir := t.TempDir()
	runner, err := fhe.New(fhe.Config{
		Endpoint:        stub.URL,
		DataDir:         sharedDir,
		KeyCacheDir:     t.TempDir(),
		CallbackBaseURL: "http://127.0.0.1:6001",
		MaxEvalKeyBytes: fhe.DefaultMaxEvalKeyBytes,
		PollInterval:    5 * time.Millisecond,
		RequestTimeout:  2 * time.Second,
		// Set explicitly, because this field's zero value is a working-but-wrong
		// configuration: a Config built without it stages models and never
		// hot-loads them (see fhe.Config.ActivateModelOnImport).
		ActivateModelOnImport: true,
	}, nil)
	if err != nil {
		t.Fatalf("fhe.New: %v", err)
	}
	state, _ := setupTestState(t)
	state.SetFHERunner(runner)
	return &fheTestEnv{
		t: t, state: state, stub: stub, runner: runner,
		sharedDir: sharedDir, keyHash: stub.evalKeyHash(t),
	}
}

// importModel drives the model half of the flow and returns the digest the
// platform names the model by.
//
// It goes through processImportedResource rather than calling the FHE branch
// directly, because the branch's position is part of what is being tested: a
// handler that selected it too late would still run the FHE import and then fall
// through into the training one, and only the entry point shows that.
func (e *fheTestEnv) importModel() string {
	e.t.Helper()
	zipPath, _ := writeTestZip(e.t, e.t.TempDir(), map[string]string{"server/model.bin": "fhe-model"})
	e.state.processImportedResource(importRequest{RequestID: "req-model", TaskID: "task-model"}, 1, true, zipPath, nil)
	hash, _ := e.state.getModelChecksum()["value"].(string)
	if !fhe.ValidHash(hash) {
		e.t.Fatalf("model checksum = %v, want an SM3 digest after a model import", e.state.getModelChecksum())
	}
	e.modelHash = hash
	return hash
}

// dataRequest is the import request the platform sends to run a task.
func (e *fheTestEnv) dataRequest() importRequest {
	return importRequest{
		ResourceURL:     "http://127.0.0.1:1/in.zip",
		RequestID:       "req-data",
		TaskID:          "task-data",
		EvalKeyURL:      e.stub.URL + "/eval_context.bin",
		EvalKeyFileHash: e.keyHash,
	}
}

// resultDir is where the platform expects the task's artifacts: the same layout
// the import index records for a training run.
func (e *fheTestEnv) resultDir() string {
	return resultDirForRequestTask(e.state.Security.ResultDir, "req-data", "task-data")
}

// reserveRecord takes the import index reservation for the task, which is what
// the import handler does before it hands the request to the asynchronous import.
//
// It deliberately does NOT commit a record. The record is the import path's own
// output and export resolves ResultDir and the leakage verdict through it, so a
// fixture that commits one itself would test export against state production
// never builds - which is how the import path's missing commit stayed invisible.
func (e *fheTestEnv) reserveRecord() {
	e.t.Helper()
	store, err := e.state.importIndexStore()
	if err != nil {
		e.t.Fatalf("importIndexStore: %v", err)
	}
	if err := store.Reserve("req-data", "task-data"); err != nil {
		e.t.Fatalf("Reserve: %v", err)
	}
}

// runData drives the data half through processImportedResource, which is the
// entry point the import handler calls: the FHE branch sits inside it.
//
// The reservation is taken first because the handler takes it before calling in:
// committing the record is the import path's own job.
func (e *fheTestEnv) runData(zipPath string) {
	e.t.Helper()
	e.reserveRecord()
	e.state.processImportedResource(e.dataRequest(), 2, false, zipPath, nil)
}

// writeTestZip writes a real archive and returns its path and bytes.
func writeTestZip(t *testing.T, dir string, entries map[string]string) (string, []byte) {
	t.Helper()
	path := filepath.Join(dir, "input.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create test zip: %v", err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close test zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close test zip file: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read test zip: %v", err)
	}
	return path, data
}

func readFileOrFail(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// logContains reports whether any log line carries substr.
func logContains(s *TAAState, substr string) bool {
	for _, entry := range s.Logs.All() {
		if strings.Contains(entry.Message, substr) {
			return true
		}
	}
	return false
}

// countLogs counts the log lines carrying substr. It is the assertion form for
// "logged exactly once": a duplicate line means two sites made the same decision.
func countLogs(s *TAAState, substr string) int {
	n := 0
	for _, entry := range s.Logs.All() {
		if strings.Contains(entry.Message, substr) {
			n++
		}
	}
	return n
}

// requireLog fails the test when no log line carries substr.
func requireLog(t *testing.T, s *TAAState, substr string) {
	t.Helper()
	if !logContains(s, substr) {
		t.Errorf("no log line contains %q; logs: %v", substr, logLines(s))
	}
}

func logLines(s *TAAState) []string {
	var out []string
	for _, entry := range s.Logs.All() {
		out = append(out, entry.Message)
	}
	return out
}

// trainingReportStatus reads the status the platform will see out of the report
// written into resultDir.
func trainingReportStatus(t *testing.T, resultDir string) (string, string) {
	t.Helper()
	raw := readFileOrFail(t, filepath.Join(resultDir, trainingReportFileName))
	var report struct {
		TrainingTask struct {
			Status        string `json:"status"`
			FailureReason string `json:"failure_reason"`
		} `json:"training_task"`
	}
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatalf("decode %s: %v", trainingReportFileName, err)
	}
	return report.TrainingTask.Status, report.TrainingTask.FailureReason
}

// TestFHEImportDispatchesTaskAndLandsResult walks the whole flow through
// processImportedResource for both halves: the model import stages the package
// into the shared directory, and the data import dispatches a task whose result
// is copied out of that directory into the task's result directory.
//
// It pins the published paths, not just the fact that something ran: output.zip
// and training_report.json have to be where the platform and the export handler
// look for them, and the leakage verdict has to be recorded, because export reads
// it under fail-closed.
func TestFHEImportDispatchesTaskAndLandsResult(t *testing.T) {
	env := newFHETestEnv(t)
	env.importModel()

	// The FHE service writes the result into the shared directory; the controller
	// has to copy it out of there rather than re-download it.
	sharedResult, err := env.runner.Layout().ResultPath("task-data")
	if err != nil {
		t.Fatalf("ResultPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(sharedResult), 0o755); err != nil {
		t.Fatalf("create shared result dir: %v", err)
	}
	if err := os.WriteFile(sharedResult, []byte("SHARED-RESULT"), 0o644); err != nil {
		t.Fatalf("write shared result: %v", err)
	}

	env.stub.onCreate = func() {
		// Sample the instance state at the one moment the run is definitely in
		// flight. The state lock is released between the two reads and busy is
		// computed under the lock alone: isTrainingBusyLocked and fheActiveTask
		// each take the lock themselves, and a nested RLock would deadlock as soon
		// as a writer queued up behind it.
		env.state.mu.RLock()
		op := env.state.CurrentOp
		busy := env.state.isTrainingBusyLocked()
		env.state.mu.RUnlock()
		active := env.state.fheActiveTask()

		env.stub.mu.Lock()
		defer env.stub.mu.Unlock()
		env.stub.opDuringCreate = op
		env.stub.busyDuringCreate = busy
		env.stub.activeDuringCreate = active
	}

	zipPath, zipData := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	env.runData(zipPath)

	created := env.stub.createdTasks()
	if len(created) != 1 {
		t.Fatalf("dispatched %d tasks, want 1", len(created))
	}
	if created[0].UserID != env.keyHash {
		t.Errorf("task user_id = %q, want the eval key digest %q", created[0].UserID, env.keyHash)
	}
	if created[0].ModelID != env.modelHash {
		t.Errorf("task model_id = %q, want the imported model digest %q", created[0].ModelID, env.modelHash)
	}
	if created[0].TaskID != "task-data" {
		t.Errorf("task id = %q, want task-data", created[0].TaskID)
	}
	if got, want := created[0].CallbackURL, "http://127.0.0.1:6001/v1/taa/fheCallback"; got != want {
		t.Errorf("callback url = %q, want %q", got, want)
	}

	// The plaintext zip arrived without an .enc suffix, so it must have been taken
	// as-is rather than decrypted.
	requireLog(t, env.state, "跳过解密")

	// The two inputs the service reads out of the shared directory.
	layout := env.runner.Layout()
	keyPath, err := layout.KeyPath(env.keyHash)
	if err != nil {
		t.Fatalf("KeyPath: %v", err)
	}
	if got := readFileOrFail(t, keyPath); got != string(env.stub.evalKey) {
		t.Errorf("published eval key = %q, want %q", got, env.stub.evalKey)
	}
	inputPath, err := layout.TaskInputPath("task-data")
	if err != nil {
		t.Fatalf("TaskInputPath: %v", err)
	}
	if got := readFileOrFail(t, inputPath); got != string(zipData) {
		t.Errorf("published input archive differs from the imported package (%d vs %d bytes)", len(got), len(zipData))
	}

	// The result the platform reads.
	resultDir := env.resultDir()
	if got := readFileOrFail(t, filepath.Join(resultDir, "output.zip")); got != "SHARED-RESULT" {
		t.Errorf("result archive = %q, want the service's bytes", got)
	}
	status, reason := trainingReportStatus(t, resultDir)
	if status != "succeeded" {
		t.Errorf("report status = %q (failure_reason %q), want succeeded", status, reason)
	}

	// The record the import committed on its own, and the verdict export reads
	// under fail-closed. Nothing seeded this: the lookup below fails unless the
	// data import committed both.
	store, err := env.state.importIndexStore()
	if err != nil {
		t.Fatalf("importIndexStore: %v", err)
	}
	record, err := store.Lookup("req-data", "task-data")
	if err != nil {
		t.Fatalf("the data import committed no index record: %v", err)
	}
	if record.ResultCheck == nil || !record.ResultCheck.Passed {
		t.Fatalf("recorded verdict = %+v, want a passing one", record.ResultCheck)
	}
	if len(record.ResultCheck.Details) == 0 || record.ResultCheck.Details[0] != "skipped: FHE ciphertext result" {
		t.Errorf("verdict details = %v, want the skip reason", record.ResultCheck.Details)
	}

	// While the run was in flight the instance had to look busy, and stopTraining
	// had to be able to find the task.
	op, active, busy := env.stub.sampleOnCreate()
	if op != "training" {
		t.Errorf("CurrentOp during the run = %q, want training (a status query would otherwise report the instance as free)", op)
	}
	if !busy {
		t.Error("isTrainingBusyLocked() = false during the run; a concurrent import would be admitted")
	}
	if active != "task-data" {
		t.Errorf("fheActiveTask() during the run = %q, want task-data", active)
	}

	// And afterwards nothing may be left marked in flight.
	if got := env.state.fheActiveTask(); got != "" {
		t.Errorf("fheActiveTask() after the run = %q, want empty", got)
	}
	if got := env.state.CurrentOp; got != "idle" {
		t.Errorf("CurrentOp after the run = %q, want idle", got)
	}
}

// TestExecuteFHETaskDownloadsResultWhenTheSharedDirMisses covers the fallback:
// the service did not write into the shared directory, so the result has to be
// fetched over the API instead.
func TestExecuteFHETaskDownloadsResultWhenTheSharedDirMisses(t *testing.T) {
	env := newFHETestEnv(t)
	env.importModel()
	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	env.runData(zipPath)

	if got := readFileOrFail(t, filepath.Join(env.resultDir(), "output.zip")); got != "DOWNLOADED-RESULT" {
		t.Errorf("result archive = %q, want the downloaded bytes", got)
	}
	status, reason := trainingReportStatus(t, env.resultDir())
	if status != "succeeded" {
		t.Errorf("report status = %q (failure_reason %q), want succeeded", status, reason)
	}
}

// TestExecuteFHETaskReportsAFailedTask pins the failure branch: a task the
// service reports as failed must produce a failed report and no result archive.
func TestExecuteFHETaskReportsAFailedTask(t *testing.T) {
	env := newFHETestEnv(t)
	env.importModel()
	env.stub.setTaskStatus("failed")
	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	env.runData(zipPath)

	if len(env.stub.createdTasks()) != 1 {
		t.Fatalf("the task was not dispatched: %+v", env.stub.createdTasks())
	}
	requireLog(t, env.state, "FHE 任务失败")
	status, reason := trainingReportStatus(t, env.resultDir())
	if status != "failed" {
		t.Errorf("report status = %q, want failed", status)
	}
	if reason == "" {
		t.Error("failure_reason is empty; the platform cannot tell why the task failed")
	}
	if _, err := os.Stat(filepath.Join(env.resultDir(), "output.zip")); err == nil {
		t.Error("output.zip exists for a failed task")
	}
	// A failed run has nothing to export, so it must leave no index record - and
	// must not keep the handler's reservation either. A held reservation is not
	// inert: it refuses every later submission of the same requestId/taskId, for
	// the life of the process.
	store, err := env.state.importIndexStore()
	if err != nil {
		t.Fatalf("importIndexStore: %v", err)
	}
	if record, err := store.Lookup("req-data", "task-data"); err == nil {
		t.Errorf("a failed task committed an index record (%+v); export would serve an empty result dir", record)
	}
	if err := store.Reserve("req-data", "task-data"); err != nil {
		t.Errorf("the reservation is still held after a failed run: %v", err)
	}
	// A failed run must release the task id it registered, on this exit path too.
	// A left-behind id is not inert: stopTraining consults it first, and the runner
	// refuses to cancel a task it does not track, so a stale id turns a later stop
	// into an error about a task that already ended.
	if got := env.state.fheActiveTask(); got != "" {
		t.Errorf("fheActiveTask() after a failed run = %q, want empty", got)
	}
	if got := env.state.CurrentOp; got != "idle" {
		t.Errorf("CurrentOp after a failed run = %q, want idle", got)
	}
}

// TestExecuteFHETaskReportsWhenTheResultCannotBeFetched is the other failure
// branch the plan names: the task succeeded but its archive could not be
// retrieved, which must also be reported as a failure rather than as a success
// with a missing result.
func TestExecuteFHETaskReportsWhenTheResultCannotBeFetched(t *testing.T) {
	env := newFHETestEnv(t)
	env.importModel()
	env.stub.failDownload(http.StatusInternalServerError)
	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	env.runData(zipPath)

	requireLog(t, env.state, "取回 FHE 结果失败")
	status, reason := trainingReportStatus(t, env.resultDir())
	if status != "failed" {
		t.Errorf("report status = %q, want failed", status)
	}
	if !strings.Contains(reason, "取回 FHE 结果失败") {
		t.Errorf("failure_reason = %q, want the fetch failure", reason)
	}
	if got := env.state.fheActiveTask(); got != "" {
		t.Errorf("fheActiveTask() after a result-fetch failure = %q, want empty", got)
	}
}

// TestExecuteFHETaskRejectsANonArchiveInput drives executeFHETask directly: a
// decrypted payload that is not an archive reaches it through
// resolvePlaintextResource (a resource with no .enc suffix whose bytes are not a
// known archive is decrypted, and what comes out need not be one).
func TestExecuteFHETaskRejectsANonArchiveInput(t *testing.T) {
	env := newFHETestEnv(t)
	env.importModel()
	plain := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(plain, []byte("not an archive"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	env.state.executeFHETask(env.dataRequest(), 2, plain, time.Now().UTC(), env.runner)

	requireLog(t, env.state, "输入包不是压缩包")
	if got := env.stub.createdTasks(); len(got) != 0 {
		t.Errorf("a non-archive input was dispatched as a task: %+v", got)
	}
	status, _ := trainingReportStatus(t, filepath.Join(env.state.Security.ResultDir, "train"))
	if status != "failed" {
		t.Errorf("report status = %q, want failed", status)
	}
}

// TestExecuteFHETaskRequiresAModelImport pins the ordering contract: a task
// submitted before any model was imported has no model to run against, and must
// be refused instead of being sent with an empty model id.
func TestExecuteFHETaskRequiresAModelImport(t *testing.T) {
	env := newFHETestEnv(t)
	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	env.state.executeFHETask(env.dataRequest(), 2, zipPath, time.Now().UTC(), env.runner)

	requireLog(t, env.state, "尚未导入模型")
	if got := env.stub.createdTasks(); len(got) != 0 {
		t.Errorf("a task ran without a model import: %+v", got)
	}
}

// TestExecuteFHETaskCommitsNothingWhenTheReportCannotBeWritten pins the single
// commit: export resolves the result directory, the report and the leakage verdict
// through one index record, so that record must not exist until all three do.
//
// The record used to be committed first and the verdict attached to it in a second
// call, with the report written after both. A failure in either of the later steps
// left the record committed - and the requestId/taskId spent for the life of the
// process - with nothing exportable behind it: no verdict is a permanent 500 under
// fail-closed, no report is a 404 at export's os.Stat, and the ids cannot be
// resubmitted to try again.
func TestExecuteFHETaskCommitsNothingWhenTheReportCannotBeWritten(t *testing.T) {
	env := newFHETestEnv(t)
	env.state.Security.ResultCheck = true
	env.state.Security.LLM.FailClosed = true
	env.importModel()

	// The seam is the report's own input: a directory where training_result.json
	// belongs makes buildAndSaveTrainingReport fail at its first read, before it
	// writes training_report.json, and it is the only failure available after the
	// result archive has landed.
	resultDir := env.resultDir()
	if err := os.MkdirAll(filepath.Join(resultDir, "training_result.json"), 0o755); err != nil {
		t.Fatalf("occupy the training_result.json path: %v", err)
	}

	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	env.runData(zipPath)

	requireLog(t, env.state, "生成结果报告失败")

	// The run itself succeeded and its archive is on disk: what failed is the
	// report, which is part of what the record promises.
	if _, err := os.Stat(filepath.Join(resultDir, "output.zip")); err != nil {
		t.Errorf("the result archive is missing (%v); the seam was supposed to leave the run successful", err)
	}
	if _, err := os.Stat(filepath.Join(resultDir, trainingReportFileName)); err == nil {
		t.Error("training_report.json exists; the report write was supposed to fail")
	}

	store, err := env.state.importIndexStore()
	if err != nil {
		t.Fatalf("importIndexStore: %v", err)
	}
	if record, err := store.Lookup("req-data", "task-data"); err == nil {
		t.Errorf("a run whose report was never written left a committed record (%+v); export would 404 on it and the ids are spent", record)
	}
	// And the ids have to be usable again: the reservation is what refuses every
	// later submission of the same requestId/taskId.
	if err := store.Reserve("req-data", "task-data"); err != nil {
		t.Errorf("the reservation is still held after the report failure: %v", err)
	}
}

// TestExecuteFHETaskCommitsTheVerdictWithTheRecord pins the other half of the
// single commit: the verdict export reads under fail-closed is part of the record
// from the start, so there is no state in which a committed record has no verdict.
func TestExecuteFHETaskCommitsTheVerdictWithTheRecord(t *testing.T) {
	env := newFHETestEnv(t)
	env.state.Security.ResultCheck = true
	env.state.Security.LLM.FailClosed = true
	env.importModel()

	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	env.runData(zipPath)

	store, err := env.state.importIndexStore()
	if err != nil {
		t.Fatalf("importIndexStore: %v", err)
	}
	record, err := store.Lookup("req-data", "task-data")
	if err != nil {
		t.Fatalf("the successful run left no record: %v", err)
	}
	if record.ResultCheck == nil || !record.ResultCheck.Passed {
		t.Fatalf("record verdict = %+v, want a passing one", record.ResultCheck)
	}
	// The same verdict has to be what a reload sees: it is one durable write now,
	// and a verdict that only ever lived in memory would fail closed after a restart.
	reloaded, err := LoadImportIndexStore(filepath.Join(env.state.Security.ResultDir, "import-index.json"))
	if err != nil {
		t.Fatalf("reload the import index: %v", err)
	}
	reloadedRecord, err := reloaded.Lookup("req-data", "task-data")
	if err != nil {
		t.Fatalf("the committed record does not survive a reload: %v", err)
	}
	if reloadedRecord.ResultCheck == nil || !reloadedRecord.ResultCheck.Passed {
		t.Errorf("reloaded verdict = %+v, want the persisted passing verdict", reloadedRecord.ResultCheck)
	}
}

// TestExecuteFHETaskReportsAnUnreachableService covers the last error path the
// plan names: Execute itself failing, here because the eval key cannot be
// fetched from a dead endpoint.
func TestExecuteFHETaskReportsAnUnreachableService(t *testing.T) {
	s, _ := setupTestState(t)
	s.SetFHERunner(newStubRunner(t))
	s.setModelChecksum(map[string]any{"size": int64(0), "algorithm": "sm3", "value": strings.Repeat("b", 64)})

	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	s.executeFHETask(importRequest{
		ResourceURL: "http://127.0.0.1:1/in.zip", RequestID: "req-data", TaskID: "task-data",
		EvalKeyURL: "http://127.0.0.1:1/eval_context.bin", EvalKeyFileHash: strings.Repeat("a", 64),
	}, 2, zipPath, time.Now().UTC(), s.fheRunner())

	requireLog(t, s, "FHE 任务失败")
	resultDir := resultDirForRequestTask(s.Security.ResultDir, "req-data", "task-data")
	status, reason := trainingReportStatus(t, resultDir)
	if status != "failed" || reason == "" {
		t.Errorf("report = (%q, %q), want a failed status with a reason", status, reason)
	}
	// This is the earliest failure Execute can produce - it never reaches the
	// service - so it is the one that would most easily skip a cleanup written at
	// the end of the happy path.
	if got := s.fheActiveTask(); got != "" {
		t.Errorf("fheActiveTask() after an unreachable service = %q, want empty", got)
	}
}

// TestProcessImportedResourceFHEWithoutRunnerFails covers the defensive guard:
// the branch is only reachable on an fhe instance, but a runner that went away
// must fail the import rather than silently drop it.
func TestProcessImportedResourceFHEWithoutRunnerFails(t *testing.T) {
	s, _ := setupTestState(t)
	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	s.processImportedResourceFHE(importRequest{RequestID: "req-data", TaskID: "task-data"}, 2, false, zipPath, time.Now().UTC())

	requireLog(t, s, "FHE 运行器未初始化")
	status, _ := trainingReportStatus(t, filepath.Join(s.Security.ResultDir, "train"))
	if status != "failed" {
		t.Errorf("report status = %q, want failed", status)
	}
}

// TestImportFHEModelStagesIntoSharedDirAndSkipsTheAudit covers the model half.
//
// The audit bypass is asserted structurally rather than through a log line: the
// training path extracts the package into s.Security.ModelDir and owes an audit
// for it (beginModelImportAndAudit sets AuditRunning), while the FHE path puts it
// in the shared directory and owes neither.
func TestImportFHEModelStagesIntoSharedDirAndSkipsTheAudit(t *testing.T) {
	env := newFHETestEnv(t)
	hash := env.importModel()

	modelDir, err := env.runner.Layout().ModelDir(hash)
	if err != nil {
		t.Fatalf("ModelDir: %v", err)
	}
	if got := readFileOrFail(t, filepath.Join(modelDir, "server", "model.bin")); got != "fhe-model" {
		t.Errorf("staged model = %q, want the package bytes", got)
	}

	if got := env.stub.activateCalls(); len(got) != 1 || got[0] != hash {
		t.Errorf("activate calls = %v, want exactly [%s] (ActivateModelOnImport must be read, not assumed)", got, hash)
	}

	// The training path's model directory must be untouched: it is what the audit
	// reads and what a TEE model import extracts into.
	if entries, err := os.ReadDir(env.state.Security.ModelDir); err == nil && len(entries) > 0 {
		t.Errorf("the package also landed in the training model dir (%v); the FHE import took the training path", entries)
	}
	env.state.mu.RLock()
	auditing := env.state.AuditRunning
	env.state.mu.RUnlock()
	if auditing {
		t.Error("AuditRunning is set; an FHE model import must not owe a code audit")
	}
	requireLog(t, env.state, "免代码审计")

	// And importModel is what names the model the task will run against.
	if got, _ := env.state.getModelChecksum()["value"].(string); got != hash {
		t.Errorf("recorded model checksum = %q, want %q", got, hash)
	}
}

// TestFHEModelImportIsReadableDespiteTheUmask is the regression test for the
// modes of the staged model package.
//
// The FHE service reads <data>/models/<hash>/server from a container running as
// another user, so every directory down to it has to be enterable and every file
// in it readable. The import created the model directory with os.MkdirAll, which
// applies the umask, and extraction then replaced that directory outright with
// one os.MkdirTemp had made - os.MkdirTemp is 0700 whatever the umask is - so
// under umask 077 the package the service had just been told to activate was
// unreachable. Nothing failed at import time: the failure surfaced at the first
// task, as an activation error against a model that had staged correctly.
func TestFHEModelImportIsReadableDespiteTheUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	env := newFHETestEnv(t)
	hash := env.importModel()

	modelDir, err := env.runner.Layout().ModelDir(hash)
	if err != nil {
		t.Fatalf("ModelDir: %v", err)
	}

	// <data>/models comes first because traversal is checked one component at a
	// time: a directory the service cannot enter hides everything below it, however
	// open the rest is.
	for _, dir := range []string{
		filepath.Join(env.sharedDir, "models"),
		modelDir,
		filepath.Join(modelDir, "server"),
	} {
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if got := st.Mode().Perm(); got != 0o755 {
			t.Errorf("%s is %v under umask 077, want 0755: the service traverses into it as another user", dir, got)
		}
	}

	modelFile := filepath.Join(modelDir, "server", "model.bin")
	st, err := os.Stat(modelFile)
	if err != nil {
		t.Fatalf("stat %s: %v", modelFile, err)
	}
	if got := st.Mode().Perm(); got != 0o644 {
		t.Errorf("%s is %v under umask 077, want 0644: the service reads it as another user", modelFile, got)
	}
}

// TestFHEImportResultIsExportable runs the deliverable through the HTTP surface:
// a data import arrives at /v1/taa/import on an fhe instance, the task runs against
// the FHE stub, and the result is then retrieved through /v1/taa/export, which is
// the only retrieval path the contract offers.
//
// Nothing about the store is seeded by hand. Export resolves ResultDir and the
// leakage verdict through the record the import itself commits, so a fixture that
// commits one would exercise export while leaving the path that has to produce the
// record unexercised - which is exactly how the missing commit stayed invisible.
//
// The port's phase is left at the fixture's default (1) and the leakage check is
// switched on with fail-closed, because that turns both halves of the record that
// export reads into hard requirements: no record is a 400, and a record without a
// verdict is a 500.
func TestFHEImportResultIsExportable(t *testing.T) {
	env := newFHETestEnv(t)

	env.state.Security.ResultCheck = true
	env.state.Security.LLM.FailClosed = true

	// The model first: a task without one is refused before it is dispatched.
	env.importModel()

	// The platform's reportRes endpoint. The import is asynchronous, and receiving
	// this report is what says the whole chain - task, result, verdict, report -
	// has run, without polling the filesystem for a file that may appear mid-write.
	type reportPayload struct {
		Code int     `json:"code"`
		Msg  *string `json:"msg"`
	}
	reported := make(chan reportPayload, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/taa/reportRes" {
			var payload reportPayload
			_ = json.NewDecoder(r.Body).Decode(&payload)
			reported <- payload
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()
	env.state.mu.Lock()
	env.state.PlatformIP = platform.URL
	env.state.mu.Unlock()

	// The package the platform delivers for this task.
	_, pkg := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	pkgServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pkg)
	}))
	defer pkgServer.Close()

	mux := http.NewServeMux()
	RegisterRoutes(mux, env.state)
	server := httptest.NewServer(mux)
	defer server.Close()

	importResp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl":     pkgServer.URL + "/in.zip",
		"requestId":       "req-data",
		"taskId":          "task-data",
		"evalKeyUrl":      env.stub.URL + "/eval_context.bin",
		"evalKeyFileHash": env.keyHash,
	})
	importBody, _ := io.ReadAll(importResp.Body)
	importResp.Body.Close()
	if importResp.StatusCode != http.StatusOK {
		t.Fatalf("import: status = %d, body = %s", importResp.StatusCode, importBody)
	}

	select {
	case payload := <-reported:
		if payload.Code != 0 {
			msg := ""
			if payload.Msg != nil {
				msg = *payload.Msg
			}
			t.Fatalf("reportRes code = %d (msg %q), want a successful FHE run", payload.Code, msg)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the FHE import to report its result")
	}

	// The retrieval the contract promises. It runs before the record assertions
	// below so that a missing record is reported as the failure the platform would
	// actually see - a refused export - with the lookup failure attached.
	exportResp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
		"requestId": "req-data",
		"taskId":    "task-data",
	})
	exportBody, err := io.ReadAll(exportResp.Body)
	exportResp.Body.Close()
	if err != nil {
		t.Fatalf("read export body: %v", err)
	}
	if exportResp.StatusCode != http.StatusOK {
		store, storeErr := env.state.importIndexStore()
		_, lookupErr := store.Lookup("req-data", "task-data")
		t.Fatalf("export of a finished FHE task: status = %d, body = %s (index store %v, lookup %v)",
			exportResp.StatusCode, exportBody, storeErr, lookupErr)
	}

	// The record the import had to leave behind, with the fields export reads.
	store, err := env.state.importIndexStore()
	if err != nil {
		t.Fatalf("importIndexStore: %v", err)
	}
	record, err := store.Lookup("req-data", "task-data")
	if err != nil {
		t.Fatalf("the FHE import left no usable index record: %v", err)
	}
	if record.Hash != env.modelHash {
		t.Errorf("record hash = %q, want the FHE model digest %q", record.Hash, env.modelHash)
	}
	if record.ResultDir != env.resultDir() {
		t.Errorf("record result dir = %q, want %q", record.ResultDir, env.resultDir())
	}
	// Non-zero on purpose: export reads phase 0 as "unknown, use the current one",
	// which would let a later phase change pick a different export key.
	if record.Phase == 0 {
		t.Error("record phase = 0; export would fall back to whatever phase the instance is in")
	}
	if record.ResultCheck == nil || !record.ResultCheck.Passed || record.ResultCheck.Error != "" {
		t.Fatalf("record verdict = %+v, want a passing, error-free one", record.ResultCheck)
	}

	// The export is the stored archive itself, not a directory re-zipped around it.
	if string(exportBody) != "DOWNLOADED-RESULT" {
		t.Errorf("exported body = %q, want the service's result archive bytes", exportBody)
	}

	// The record has to survive a restart as committed. LoadImportIndexStore fails
	// the whole index - not just the record - on a malformed one, and the fields it
	// checks are requestId/taskId/hash: the FHE record is the first committed with an
	// empty DataDir, so this is what proves that shape is loadable rather than a 500
	// on every export after a restart.
	reloaded, err := LoadImportIndexStore(filepath.Join(env.state.Security.ResultDir, "import-index.json"))
	if err != nil {
		t.Fatalf("reload the import index: %v", err)
	}
	reloadedRecord, err := reloaded.Lookup("req-data", "task-data")
	if err != nil {
		t.Fatalf("the committed record does not survive a reload: %v", err)
	}
	if reloadedRecord.Hash != env.modelHash || reloadedRecord.ResultDir != env.resultDir() {
		t.Errorf("reloaded record = %+v, want hash %q and result dir %q", reloadedRecord, env.modelHash, env.resultDir())
	}
	if reloadedRecord.ResultCheck == nil || !reloadedRecord.ResultCheck.Passed {
		t.Errorf("reloaded verdict = %+v, want the persisted passing verdict", reloadedRecord.ResultCheck)
	}
}

// TestImportModelWarnsOnEvalKeyFields pins both halves of the model endpoint's
// contract on an fhe instance: the eval key fields are inapplicable there - the
// eval key travels with the data package on /v1/taa/import - so they are ignored
// and warned about, but not refused. A refusal would close the only endpoint that
// stages a model package, which is exactly what this endpoint has to keep doing.
func TestImportModelWarnsOnEvalKeyFields(t *testing.T) {
	env := newFHETestEnv(t)

	zipPath, modelZip := writeTestZip(t, t.TempDir(), map[string]string{"server/model.bin": "fhe-model"})
	hash, err := sm3HexOfFile(zipPath)
	if err != nil {
		t.Fatalf("hash model package: %v", err)
	}
	pkgServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(modelZip)
	}))
	defer pkgServer.Close()

	mux := http.NewServeMux()
	RegisterRoutes(mux, env.state)
	server := httptest.NewServer(mux)
	defer server.Close()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":     pkgServer.URL + "/model.zip",
		"requestId":       "req-model",
		"taskId":          "task-model",
		"evalKeyUrl":      env.stub.URL + "/eval_context.bin",
		"evalKeyFileHash": env.keyHash,
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("importModel with inapplicable eval key fields: status = %d, body = %s (the fields must be ignored, not refused)", resp.StatusCode, body)
	}
	requireLog(t, env.state, "本接口不读取这两个字段")

	// Wait out the staging the handler starts asynchronously, so this test does not
	// leave it running into the fixture's temp-dir cleanup.
	modelDir, err := env.runner.Layout().ModelDir(hash)
	if err != nil {
		t.Fatalf("ModelDir: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(modelDir, "server")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the model package to be staged into %s", modelDir)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestFHESuccessReportsFullProgress pins the explicit final progress report.
//
// The poll that observes the terminal state reports 100% on its own, but the
// service's callback can resolve the run first and no further poll happens. The
// stub here holds its polls and answers a running task with no cases, so the
// callback is the only thing that can end the run - and 100% can only arrive if
// executeFHETask sends it once the run has succeeded.
func TestFHESuccessReportsFullProgress(t *testing.T) {
	env := newFHETestEnv(t)
	env.importModel()

	progress := make(chan float64, 4)
	reported := make(chan struct{}, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/taa/reportProgress":
			var payload struct {
				Percent float64 `json:"percent"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
				progress <- payload.Percent
			}
		case "/v1/taa/reportRes":
			reported <- struct{}{}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	env.state.mu.Lock()
	env.state.PlatformIP = platform.URL
	env.state.mu.Unlock()

	// Hold the first poll and make every poll answer "running" with no cases, so
	// the poll path cannot report progress; only the callback ends the run.
	env.stub.holdPolls()
	defer env.stub.releasePolls()
	env.stub.mu.Lock()
	env.stub.taskStatus = "running"
	env.stub.caseEntries = 0
	env.stub.mu.Unlock()

	pkgPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"case-00.ct": "ciphertext"})
	done := make(chan struct{})
	go func() {
		env.state.processImportedResource(importRequest{
			RequestID:       "req-data",
			TaskID:          "task-data",
			EvalKeyURL:      env.stub.URL + "/eval_context.bin",
			EvalKeyFileHash: env.keyHash,
		}, 3, false, pkgPath, nil)
		close(done)
	}()

	// The run is registered before the service is asked to create it, so a
	// created task means a callback will find it.
	deadline := time.Now().Add(10 * time.Second)
	for len(env.stub.createdTasks()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the FHE task to be created")
		}
		time.Sleep(5 * time.Millisecond)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, env.state)
	callback := httptest.NewServer(mux)
	defer callback.Close()

	resp := postJSON(t, callback.URL+"/v1/taa/fheCallback?token=test-token", map[string]any{
		"task_id": "task-data",
		"status":  "completed",
		"cases":   []map[string]any{{"entry": "case-00", "result_id": "r"}},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback: status = %d, want 200", resp.StatusCode)
	}

	env.stub.releasePolls()
	<-done

	select {
	case percent := <-progress:
		if percent != 100 {
			t.Errorf("progress report = %v, want 100 after a successful run", percent)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no progress report reached the platform; a callback-resolved run leaves the bar short")
	}

	// Let the asynchronous result report finish before the fixture's server goes
	// away, so the test does not end with a reset connection log line.
	select {
	case <-reported:
	case <-time.After(10 * time.Second):
		t.Fatal("the FHE run never reported its result")
	}
}
