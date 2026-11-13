package mock

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

// ── start / abandon / record ────────────────────────────────────────────────

func TestAuditJobBeginIsIdempotent(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()

	store.begin("d1", "req1", "task1")
	store.begin("d1", "req1", "task1")

	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1 after a repeated begin", len(jobs))
	}
	if jobs[0].Status != auditJobStatusPending {
		t.Fatalf("status = %q, want pending", jobs[0].Status)
	}
	if jobs[0].ID != "req1" || jobs[0].Code != 0 || jobs[0].Passed {
		t.Fatalf("pending row = %+v", jobs[0])
	}
	if jobs[0].High != 0 || jobs[0].Medium != 0 || jobs[0].Low != 0 {
		t.Fatalf("pending row carries severity counts: %+v", jobs[0])
	}
}

func TestAuditJobBeginDoesNotOverwriteDone(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	store.record("d1", "req1", "task1", 0, buildAuditTestReport(t, true, "HIGH", auditTestStats(1, 0, 0), 10, []int{1}))

	store.begin("d1", "req1", "task1")

	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(jobs))
	}
	if jobs[0].Status != auditJobStatusDone {
		t.Fatalf("status = %q, want done: a real verdict outranks a pending mark", jobs[0].Status)
	}
}

func TestAuditJobBeginIDRules(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	store.record("d1", "", "task1", 0, `{}`)
	store.begin("d1", "task1", "task2")

	ids := map[string]bool{}
	for _, job := range store.list("d1") {
		ids[job.ID] = true
	}
	if !ids["task1"] || !ids["task1-2"] {
		t.Fatalf("ids = %v, want task1 and task1-2", ids)
	}

	// No requestId and no taskId falls back to the clock-based name.
	store.begin("d1", "", "")
	jobs := store.list("d1")
	if !strings.HasPrefix(jobs[0].ID, "job-") {
		t.Fatalf("fallback id = %q, want a job-<nano> name", jobs[0].ID)
	}
}

func TestAuditJobRecordPromotesPendingInPlace(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()

	store.begin("d1", "req1", "task1")
	store.record("d1", "req1", "task1", 0,
		buildAuditTestReport(t, true, "MEDIUM", auditTestStats(0, 2, 0), 55, []int{2}))

	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1: the verdict must replace the pending row", len(jobs))
	}
	job := jobs[0]
	if job.ID != "req1" || job.Status != auditJobStatusDone {
		t.Fatalf("row = %+v, want id req1 and status done", job)
	}
	if job.Error != "" {
		t.Fatalf("a done row carries an error: %q", job.Error)
	}
	if !job.Passed || job.Medium != 2 || job.DurationMS != 55 {
		t.Fatalf("verdict was not applied: %+v", job)
	}
}

func TestAuditJobAbandon(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	store.begin("d1", "req1", "task1")

	if !store.abandon("d1", "req1", "下发失败: 连接被拒绝") {
		t.Fatal("abandon(pending row) = false, want true")
	}
	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want the abandoned row kept", len(jobs))
	}
	if jobs[0].Status != auditJobStatusFailed || jobs[0].Error != "下发失败: 连接被拒绝" {
		t.Fatalf("abandoned row = %+v", jobs[0])
	}

	if store.abandon("d1", "req1", "again") {
		t.Fatal("abandon on an already abandoned row must not match")
	}
	if store.abandon("d1", "missing", "x") {
		t.Fatal("abandon on an unknown requestId must not match")
	}

	// A completed verdict is never rewritten by a late failure.
	store.record("d1", "req2", "task2", 0, `{}`)
	if store.abandon("d1", "req2", "late") {
		t.Fatal("abandon must not rewrite a done row")
	}
}

func TestAuditOverviewCountsOnlyDoneJobs(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	store.record("d1", "req-a", "", 0, buildAuditTestReport(t, true, "HIGH", auditTestStats(1, 0, 0), 100, []int{1}))
	store.record("d1", "req-b", "", 1, buildAuditTestReport(t, false, "MEDIUM", auditTestStats(0, 1, 0), 200, []int{1}))
	store.begin("d1", "req-pending", "task-3")
	store.begin("d1", "req-abandoned", "task-4")
	store.abandon("d1", "req-abandoned", "下发失败")

	summary := store.overview("d1")
	if summary.Jobs != 2 {
		t.Fatalf("jobs = %d, want 2 done jobs", summary.Jobs)
	}
	if summary.Pending != 1 {
		t.Fatalf("pending = %d, want 1", summary.Pending)
	}
	if summary.Passed != 1 || summary.Failed != 1 || summary.LLMUnavailable != 0 {
		t.Fatalf("buckets = %+v", summary)
	}
	if summary.PassRate != 0.5 {
		t.Fatalf("passRate = %v, want 0.5 (done jobs only)", summary.PassRate)
	}
	if summary.AvgDurationMs != 150 {
		t.Fatalf("avgDurationMs = %d, want 150", summary.AvgDurationMs)
	}
	if summary.LastAt != "2026-11-13T09:01:00Z" {
		t.Fatalf("lastAt = %q, want the newest done row", summary.LastAt)
	}

	// The list still shows every row, pending and abandoned included.
	if jobs := store.list("d1"); len(jobs) != 4 {
		t.Fatalf("list = %d rows, want all 4", len(jobs))
	}
}

// ── archive sniffing ────────────────────────────────────────────────────────

func TestAuditPayloadIsArchive(t *testing.T) {
	zipBytes := func() []byte {
		var buf bytes.Buffer
		writer := zip.NewWriter(&buf)
		f, err := writer.Create("a.py")
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := f.Write([]byte("print(1)\n")); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close zip: %v", err)
		}
		return buf.Bytes()
	}

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"zip", zipBytes(), true},
		{"gzip", []byte{0x1F, 0x8B, 0x08, 0x00}, true},
		{"plain text", []byte("print('hello')\n"), false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newBytesMultipartFile(tc.data)
			got, err := auditPayloadIsArchive(f)
			if err != nil {
				t.Fatalf("sniff: %v", err)
			}
			if got != tc.want {
				t.Fatalf("isArchive = %v, want %v", got, tc.want)
			}
			// The sniff must not consume the payload: the handler rewinds and
			// stores it afterwards.
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.Fatalf("rewind: %v", err)
			}
			rest, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("read remaining: %v", err)
			}
			if !bytes.Equal(rest, tc.data) {
				t.Fatalf("file position after the sniff = %d bytes, want the payload intact", len(rest))
			}
		})
	}
}

// bytesMultipartFile is the smallest multipart.File over a byte slice.
type bytesMultipartFile struct {
	*bytes.Reader
}

func newBytesMultipartFile(data []byte) *bytesMultipartFile {
	return &bytesMultipartFile{Reader: bytes.NewReader(data)}
}

func (f *bytesMultipartFile) Close() error { return nil }

// ── handler ─────────────────────────────────────────────────────────────────

// auditSubmitRig builds a manager with a registered instance, a private job
// store and a temp upload directory, all wired the way server.go wires them.
func auditSubmitRig(t *testing.T, registerKey bool) (*instanceManager, *auditJobStore, string, string) {
	t.Helper()
	taaKey := testTAAKey(t)
	// The envelope direction needs the key in the keystore, not only in the
	// register state: sealing for an instance reads the keystore.
	registerTestTAAKey(t)
	mgr := testManagerWith(t, "d1", func(b *instanceStores) {
		state := registerState{Received: true, Accepted: true, ReceivedAt: "2026-11-13T09:00:00Z", VerifiedPass: true}
		if registerKey {
			pem, err := crypto.MarshalSM2PublicKeyPEM(&taaKey.PublicKey)
			if err != nil {
				t.Fatalf("marshal the TAA public key: %v", err)
			}
			state.TaaPublicKey = string(pem)
		}
		b.register.set(state)
	})
	// A placeholder target keeps address resolution from rejecting a
	// submission before the assertions that do not care where it goes. Port 1
	// is closed, so a test that actually dispatches fails there.
	mgr.staticTarget = "http://127.0.0.1:1"
	uploadDir := t.TempDir()
	return mgr, newAuditJobStore(), uploadDir, "127.0.0.1:6001"
}

// submitMultipart posts one submission to the handler.
func submitMultipart(t *testing.T, handler http.HandlerFunc, filename string, content []byte, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatalf("write field %s: %v", k, err)
		}
	}
	if filename != "" {
		part, err := writer.CreateFormFile("file", filename)
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := part.Write(content); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/audit/console/submit?dockerId=d1", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decodeSubmitResponse(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return body
}

func TestAuditSubmitMissingFile(t *testing.T) {
	mgr, jobs, uploadDir, addr := auditSubmitRig(t, true)
	rec := submitMultipart(t, auditSubmitHandler(mgr, jobs, uploadDir, addr), "", nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if body := decodeSubmitResponse(t, rec); body["ok"] != false {
		t.Fatalf("body = %v, want ok=false", body)
	}
}

func TestAuditSubmitRejectsUnknownEncryptMode(t *testing.T) {
	mgr, jobs, uploadDir, addr := auditSubmitRig(t, true)
	rec := submitMultipart(t, auditSubmitHandler(mgr, jobs, uploadDir, addr), "pkg.zip", []byte("PK\x03\x04"), map[string]string{"encryptMode": "rot13"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if len(jobs.list("d1")) != 0 {
		t.Fatal("a rejected submission registered a job")
	}
}

func TestAuditSubmitPlaintextRequiresArchive(t *testing.T) {
	mgr, jobs, uploadDir, addr := auditSubmitRig(t, true)
	rec := submitMultipart(t, auditSubmitHandler(mgr, jobs, uploadDir, addr), "notes.txt", []byte("print('hi')\n"), map[string]string{"encryptMode": "none"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if len(jobs.list("d1")) != 0 {
		t.Fatal("a rejected submission registered a job")
	}
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatalf("read upload dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("upload dir = %d entries, want none", len(entries))
	}
}

func TestAuditSubmitRequiresRegisteredKey(t *testing.T) {
	mgr, jobs, uploadDir, addr := auditSubmitRig(t, false)
	rec := submitMultipart(t, auditSubmitHandler(mgr, jobs, uploadDir, addr), "pkg.zip", []byte("PK\x03\x04junk"), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	body := decodeSubmitResponse(t, rec)
	if body["ok"] != false || !strings.Contains(fmt.Sprint(body["error"]), "公钥") {
		t.Fatalf("body = %v, want a missing-key message", body)
	}
	if len(jobs.list("d1")) != 0 {
		t.Fatal("an instance without a key registered a pending job")
	}
}

func TestAuditSubmitDispatchFailureAbandonsAndCleansUp(t *testing.T) {
	mgr, jobs, uploadDir, addr := auditSubmitRig(t, true)
	// The rig's placeholder target is closed, so the dispatch is refused.
	handler := auditSubmitHandler(mgr, jobs, uploadDir, addr)
	rec := submitMultipart(t, handler, "pkg.zip", auditTestZip(t), map[string]string{
		"encryptMode": "none",
		"requestId":   "req-doomed",
		"taskId":      "task-doomed",
	})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	body := decodeSubmitResponse(t, rec)
	if body["ok"] != false || !strings.Contains(fmt.Sprint(body["error"]), "下发失败") {
		t.Fatalf("body = %v, want a dispatch failure", body)
	}

	jobsList := jobs.list("d1")
	if len(jobsList) != 1 {
		t.Fatalf("jobs = %d, want the abandoned row", len(jobsList))
	}
	if jobsList[0].Status != auditJobStatusFailed || jobsList[0].Error == "" {
		t.Fatalf("row = %+v, want failed with a reason", jobsList[0])
	}

	// The upload and its sidecar must not survive a rejected submission.
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatalf("read upload dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("upload dir = %d entries, want none", len(entries))
	}
}

func TestAuditSubmitSuccessRegistersPendingJob(t *testing.T) {
	mgr, jobs, uploadDir, addr := auditSubmitRig(t, true)
	target := newAuditImportModelStub(t, "d1")
	defer target.Close()

	handler := auditSubmitHandler(mgr, jobs, uploadDir, addr)
	rec := submitMultipartTo(t, handler, mgr, "pkg.zip", auditTestZip(t), map[string]string{
		"encryptMode": "urlkey",
		"requestId":   "req-ok",
		"taskId":      "task-ok",
	}, target.URL)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	body := decodeSubmitResponse(t, rec)
	if body["ok"] != true || body["requestId"] != "req-ok" || body["taskId"] != "task-ok" {
		t.Fatalf("body = %v", body)
	}
	if body["jobId"] != "req-ok" {
		t.Fatalf("jobId = %v, want the pending row's id", body["jobId"])
	}
	if body["encrypted"] != true {
		t.Fatalf("encrypted = %v, want true for urlkey", body["encrypted"])
	}
	if s, _ := body["url"].(string); !strings.Contains(s, dataKeyCipherQueryParam+"=") {
		t.Fatalf("url = %q, want a dataKeyCipher envelope", s)
	}

	jobsList := jobs.list("d1")
	if len(jobsList) != 1 || jobsList[0].Status != auditJobStatusPending {
		t.Fatalf("jobs = %+v, want one pending row", jobsList)
	}

	// The body TAA received is the one this endpoint promised to build.
	if target.request == nil {
		t.Fatal("the stub TAA received no request")
	}
	if target.request.RequestID != "req-ok" || target.request.TaskID != "task-ok" {
		t.Fatalf("importModel ids = %+v", target.request)
	}
	if target.request.RuntimeConfig != auditSubmitDefaultRuntimeConfig {
		t.Fatalf("runtimeConfig = %q, want %q", target.request.RuntimeConfig, auditSubmitDefaultRuntimeConfig)
	}
	if !strings.HasPrefix(target.request.ResourceURL, "http://") || !strings.Contains(target.request.ResourceURL, "/files/") {
		t.Fatalf("resourceUrl = %q, want the platform's /files URL", target.request.ResourceURL)
	}
	if target.request.PublicKey == "" {
		t.Fatal("publicKey is empty: TAA would be told nothing about the key")
	}
}

// TestAuditSubmitHonoursRuntimeConfigOverride pins the field the console's own
// form is allowed to set.
func TestAuditSubmitHonoursRuntimeConfigOverride(t *testing.T) {
	body, err := buildAuditImportBody("http://h/files/a.sm4?dataKeyCipher=ab", "r", "t", "pub", `{"commands":["echo hi"],"env":""}`)
	if err != nil {
		t.Fatalf("build body: %v", err)
	}
	var decoded auditImportModelRequest
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if decoded.ResourceURL == "" || decoded.RequestID != "r" || decoded.TaskID != "t" ||
		decoded.PublicKey != "pub" || decoded.RuntimeConfig != `{"commands":["echo hi"],"env":""}` {
		t.Fatalf("body = %+v", decoded)
	}
}

// submitMultipartTo posts to a handler whose manager targets a stub.
func submitMultipartTo(t *testing.T, handler http.HandlerFunc, mgr *instanceManager, filename string, content []byte, fields map[string]string, targets ...string) *httptest.ResponseRecorder {
	t.Helper()
	if len(targets) > 0 {
		mgr.staticTarget = targets[0]
	}
	return submitMultipart(t, handler, filename, content, fields)
}

// auditImportModelStub is a fake TAA that speaks the envelope: it opens the
// sealed importModel body and answers in the mock's success shape.
type auditImportModelStub struct {
	*httptest.Server
	t       *testing.T
	request *auditImportModelRequest
}

func newAuditImportModelStub(t *testing.T, dockerID string) *auditImportModelStub {
	t.Helper()
	ks := currentPlatformKeys()
	if ks == nil {
		t.Fatal("no platform keystore is installed")
	}
	keys, err := envelope.NewKeys(&ks.platformPrivate().PublicKey, testTAAKey(t), ks.userIDBytes())
	if err != nil {
		t.Fatalf("build the stub's envelope keys: %v", err)
	}

	stub := &auditImportModelStub{t: t}
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("stub could not read the request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		env, err := envelope.Parse(raw)
		if err != nil {
			t.Errorf("stub received an unparseable envelope: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		plaintext, err := keys.Open(env)
		if err != nil {
			t.Errorf("stub could not open the request: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req auditImportModelRequest
		if err := json.Unmarshal(plaintext, &req); err != nil {
			t.Errorf("stub could not decode the body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stub.request = &req

		sealed, err := keys.Seal([]byte(`{"msg":"success","result":{"received":true},"error":0}`), dockerID)
		if err != nil {
			t.Errorf("stub could not seal the reply: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(sealed)
	}))
	return stub
}

// auditTestZip builds a minimal valid ZIP the plaintext path accepts.
func auditTestZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	f, err := writer.Create("main.py")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := f.Write([]byte("print('audit me')\n")); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}
