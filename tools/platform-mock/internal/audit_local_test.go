package mock

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CipherSlinger/teeaudit/codeaudit"
)

// localAuditRig builds a runner over a private store and a temp upload
// directory, with no console: the AI step is therefore skipped, which is the
// state a deployment without TEE-LLM is in.
func localAuditRig(t *testing.T) (*localAuditRunner, *auditJobStore, string, http.HandlerFunc) {
	t.Helper()
	jobs := newAuditJobStore()
	jobs.now = auditTestClock()
	uploadDir := t.TempDir()
	runner := newLocalAuditRunner(jobs, Config{UploadDir: uploadDir}, nil)
	return runner, jobs, uploadDir, auditSubmitHandler(runner, uploadDir)
}

func submitLocalMultipart(t *testing.T, handler http.HandlerFunc, filename string, content []byte, fields map[string]string) *httptest.ResponseRecorder {
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

	req := httptest.NewRequest(http.MethodPost, "/api/audit/console/submit", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decodeLocalSubmit(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return body
}

// waitLocalAudit polls until the row for requestID reaches status.
func waitLocalAudit(t *testing.T, jobs *auditJobStore, requestID, status string) auditJobSummary {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if row, ok := jobs.summaryForRequest(localAuditInstanceKey, requestID); ok && row.Status == status {
			return row
		}
		time.Sleep(5 * time.Millisecond)
	}
	row, _ := jobs.summaryForRequest(localAuditInstanceKey, requestID)
	t.Fatalf("audit %s did not reach %q: %+v", requestID, status, row)
	return auditJobSummary{}
}

func TestLocalAuditSubmitRunsThePipeline(t *testing.T) {
	_, jobs, uploadDir, handler := localAuditRig(t)

	rec := submitLocalMultipart(t, handler, "pkg.zip", localAuditZip(t), map[string]string{
		"requestId": "req-local",
		"taskId":    "task-local",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := decodeLocalSubmit(t, rec)
	if body["ok"] != true || body["jobId"] != "req-local" || body["stage"] != "receive" {
		t.Fatalf("body = %v", body)
	}
	if _, ok := body["stages"]; !ok {
		t.Fatalf("body has no stages block: %v", body)
	}
	for _, forbidden := range []string{"url", "encrypted", "dataKeyCipher"} {
		if _, ok := body[forbidden]; ok {
			t.Fatalf("local submission still returns %q: %v", forbidden, body)
		}
	}

	row := waitLocalAudit(t, jobs, "req-local", auditJobStatusDone)
	if row.Code != 0 && row.Code != 1 {
		t.Fatalf("code = %d, want 0 or 1", row.Code)
	}
	if row.ID != "req-local" || row.TaskID != "task-local" || row.Stage != "done" {
		t.Fatalf("row = %+v", row)
	}
	for _, step := range []string{"receive", "extract", "static", "binary", "conclude"} {
		if row.Stages[step] != auditStepDone {
			t.Fatalf("step %s = %q, want done (%v)", step, row.Stages[step], row.Stages)
		}
	}
	if row.Stages["ai"] != auditStepSkipped {
		t.Fatalf("ai = %q, want skipped with no gateway", row.Stages["ai"])
	}

	stored, ok := jobs.get(localAuditInstanceKey, "req-local")
	if !ok {
		t.Fatal("stored job missing")
	}
	var projection map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stored.Raw), &projection); err != nil {
		t.Fatalf("stored raw is not JSON: %v", err)
	}
	if len(projection) != 3 {
		t.Fatalf("projection keys = %v, want conclusion/file_reports/duration_ms", projection)
	}
	for _, key := range []string{"conclusion", "file_reports", "duration_ms"} {
		if _, ok := projection[key]; !ok {
			t.Fatalf("projection is missing %q: %s", key, stored.Raw)
		}
	}

	// The working directory is removed once the audit settles; the file area
	// that keeps the accepted archive is expected to stay.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if auditTempDirs(t, uploadDir) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("upload dir still has %d audit temp dirs after the audit", auditTempDirs(t, uploadDir))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLocalAuditBusyReturnsConflict(t *testing.T) {
	runner, jobs, uploadDir, handler := localAuditRig(t)

	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	runner.auditFn = func(ctx context.Context, dir string, engine codeaudit.StaticEngine, cfg codeaudit.AuditConfig, client codeaudit.LLMClient) (*codeaudit.AuditReport, error) {
		entered <- struct{}{}
		<-block
		return &codeaudit.AuditReport{Conclusion: codeaudit.AuditConclusion{Passed: true}}, nil
	}

	first := submitLocalMultipart(t, handler, "pkg.zip", localAuditZip(t), map[string]string{"requestId": "req-one"})
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d: %s", first.Code, first.Body.String())
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first audit never started")
	}

	second := submitLocalMultipart(t, handler, "pkg.zip", localAuditZip(t), map[string]string{"requestId": "req-two"})
	if second.Code != http.StatusConflict {
		t.Fatalf("second status = %d, want 409: %s", second.Code, second.Body.String())
	}
	if body := decodeLocalSubmit(t, second); !strings.Contains(toString(body["error"]), "已有审计任务正在执行") {
		t.Fatalf("second body = %v", body)
	}
	if len(jobs.list(localAuditInstanceKey)) != 1 {
		t.Fatalf("jobs = %d, want the refused submission to add none", len(jobs.list(localAuditInstanceKey)))
	}

	close(block)
	waitLocalAudit(t, jobs, "req-one", auditJobStatusDone)

	// The verdict is recorded just before the goroutine releases the slot, so
	// wait for the release rather than assuming the two happen together.
	waitRunnerIdle(t, runner)

	// The slot is free again after the audit settles.
	third := submitLocalMultipart(t, handler, "pkg.zip", localAuditZip(t), map[string]string{"requestId": "req-three"})
	if third.Code != http.StatusOK {
		t.Fatalf("third status = %d, want 200: %s", third.Code, third.Body.String())
	}
	waitLocalAudit(t, jobs, "req-three", auditJobStatusDone)
	// The temp directory is removed in the same deferred block that releases the
	// slot, so "done" alone does not yet mean the cleanup has run.
	waitRunnerIdle(t, runner)

	if dirs := auditTempDirs(t, uploadDir); dirs != 0 {
		t.Fatalf("upload dir = %d audit temp dirs, want none", dirs)
	}
}

func TestLocalAuditRejectsNonArchive(t *testing.T) {
	_, jobs, uploadDir, handler := localAuditRig(t)

	rec := submitLocalMultipart(t, handler, "notes.txt", []byte("print('hello')\n"), map[string]string{"requestId": "req-txt"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if body := decodeLocalSubmit(t, rec); !strings.Contains(toString(body["error"]), "必须是 zip、gzip 或 tar 归档") {
		t.Fatalf("body = %v", body)
	}
	if len(jobs.list(localAuditInstanceKey)) != 0 {
		t.Fatal("a rejected submission registered a job")
	}
	if dirs := auditTempDirs(t, uploadDir); dirs != 0 {
		t.Fatalf("upload dir = %d audit temp dirs, want none", dirs)
	}
}

func TestLocalAuditExtractFailureMarksTheStep(t *testing.T) {
	_, jobs, _, handler := localAuditRig(t)

	// A valid ZIP signature over a truncated body: archive sniffing accepts it,
	// extraction cannot.
	rec := submitLocalMultipart(t, handler, "broken.zip", []byte("PK\x03\x04"), map[string]string{"requestId": "req-broken"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	row := waitLocalAudit(t, jobs, "req-broken", auditJobStatusFailed)
	if row.Stage != "extract" || row.Stages["extract"] != auditStepError {
		t.Fatalf("failing step = %q / %v, want extract/error", row.Stage, row.Stages)
	}
	if row.Stages["receive"] != auditStepDone {
		t.Fatalf("receive = %q, want done", row.Stages["receive"])
	}
	if !strings.Contains(row.Error, "解压归档失败") {
		t.Fatalf("error = %q", row.Error)
	}
}

func TestLocalAuditErrorMarksTheRunningStep(t *testing.T) {
	runner, jobs, _, handler := localAuditRig(t)
	runner.auditFn = func(ctx context.Context, dir string, engine codeaudit.StaticEngine, cfg codeaudit.AuditConfig, client codeaudit.LLMClient) (*codeaudit.AuditReport, error) {
		cfg.OnStage(codeaudit.StageStatic)
		return nil, context.DeadlineExceeded
	}

	rec := submitLocalMultipart(t, handler, "pkg.zip", localAuditZip(t), map[string]string{"requestId": "req-error"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	row := waitLocalAudit(t, jobs, "req-error", auditJobStatusFailed)
	if row.Stage != "static" || row.Stages["static"] != auditStepError {
		t.Fatalf("failing step = %q / %v, want static/error", row.Stage, row.Stages)
	}
	if row.Stages["extract"] != auditStepDone {
		t.Fatalf("extract = %q, want done", row.Stages["extract"])
	}
	if !strings.Contains(row.Error, "审计失败") {
		t.Fatalf("error = %q", row.Error)
	}
}

func TestLocalAuditUsesTheConfiguredPrompt(t *testing.T) {
	runner, jobs, _, handler := localAuditRig(t)
	runner.setPrompt("只看外发行为")
	if got := runner.promptText(); got != "只看外发行为" {
		t.Fatalf("promptText = %q", got)
	}

	gotPrompt := make(chan string, 1)
	runner.auditFn = func(ctx context.Context, dir string, engine codeaudit.StaticEngine, cfg codeaudit.AuditConfig, client codeaudit.LLMClient) (*codeaudit.AuditReport, error) {
		gotPrompt <- cfg.LLM.PromptOverride
		return &codeaudit.AuditReport{Conclusion: codeaudit.AuditConclusion{Passed: true}}, nil
	}

	rec := submitLocalMultipart(t, handler, "pkg.zip", localAuditZip(t), map[string]string{"requestId": "req-prompt"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	select {
	case prompt := <-gotPrompt:
		if prompt != "只看外发行为" {
			t.Fatalf("audit saw prompt %q", prompt)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the audit never ran")
	}
	waitLocalAudit(t, jobs, "req-prompt", auditJobStatusDone)
}

func waitRunnerIdle(t *testing.T, runner *localAuditRunner) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runner.mu.Lock()
		busy := runner.busy
		runner.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the audit runner never released its slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func localAuditZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	f, err := writer.Create("main.py")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := f.Write([]byte("import os\n\ndef run():\n    os.system('rm -rf /')\n")); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

// TestLocalAuditFilesSaveAndReuse covers the file area's contract: an accepted
// upload is kept, and a later submission can name it by id instead of sending
// the bytes again.
func TestLocalAuditFilesSaveAndReuse(t *testing.T) {
	runner, jobs, _, handler := localAuditRig(t)

	rec := submitLocalMultipart(t, handler, "pkg.zip", localAuditZip(t), map[string]string{
		"requestId": "req-first",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("first status = %d: %s", rec.Code, rec.Body.String())
	}
	fileID := toString(decodeLocalSubmit(t, rec)["fileId"])
	if fileID == "" {
		t.Fatalf("first response has no fileId: %s", rec.Body.String())
	}
	waitLocalAudit(t, jobs, "req-first", auditJobStatusDone)
	// The verdict is recorded just before the goroutine releases its slot, so
	// waiting for "done" alone would race the reuse submission against a runner
	// that still reports busy.
	waitRunnerIdle(t, runner)

	files := runner.files.list()
	if len(files) != 1 || files[0].ID != fileID || files[0].Name != "pkg.zip" || files[0].Size <= 0 {
		t.Fatalf("file area = %+v", files)
	}

	rec = submitLocalMultipart(t, handler, "", nil, map[string]string{
		"requestId": "req-second",
		"fileId":    fileID,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("reuse status = %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeLocalSubmit(t, rec)
	if body["fileId"] != fileID || body["originalName"] != "pkg.zip" {
		t.Fatalf("reuse body = %v", body)
	}
	waitLocalAudit(t, jobs, "req-second", auditJobStatusDone)
}

func TestLocalAuditRejectsUnknownFileID(t *testing.T) {
	_, _, _, handler := localAuditRig(t)
	rec := submitLocalMultipart(t, handler, "", nil, map[string]string{"fileId": "0123456789abcdef"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := toString(decodeLocalSubmit(t, rec)["error"]); got != errAuditFileNotFound.Error() {
		t.Fatalf("error = %q", got)
	}
}

func TestAuditFileStorePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(t.TempDir(), "sample.zip")
	if err := os.WriteFile(src, []byte("not a real archive"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	store := newAuditFileStore(dir)
	entry, err := store.saveFromFile(src, "sample.zip", nil)
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	reloaded := newAuditFileStore(dir)
	files := reloaded.list()
	if len(files) != 1 || files[0].ID != entry.ID || files[0].Name != "sample.zip" {
		t.Fatalf("reloaded file area = %+v", files)
	}
	if _, path, ok := reloaded.path(entry.ID); !ok || path != filepath.Join(dir, entry.ID+".bin") {
		t.Fatalf("path = %q ok=%v", path, ok)
	}

	if !reloaded.delete(entry.ID) {
		t.Fatal("delete returned false")
	}
	if len(newAuditFileStore(dir).list()) != 0 {
		t.Fatal("deleted entry survived a reload")
	}
}

// auditTempDirs counts the per-submission work directories. The file area
// directory shares the upload root and is expected to persist, so the tests
// that used to assert an empty root count this way instead.
func auditTempDirs(t *testing.T, uploadDir string) int {
	t.Helper()
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatalf("read upload dir: %v", err)
	}
	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "local-audit-") {
			count++
		}
	}
	return count
}

// TestAuditPromptEndpointShowsTheEffectivePrompt pins what the settings editor
// displays: the effective prompt (built-in default or override), plus whether
// it is an override. Saving the default text back clears the override.
func TestAuditPromptEndpointShowsTheEffectivePrompt(t *testing.T) {
	runner, _, _, _ := localAuditRig(t)
	handler := auditPromptHandler(runner)

	decode := func(rec *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
		return body
	}

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/api/audit/console/prompt", nil))
	body := decode(rec)
	if got := toString(body["prompt"]); got != codeaudit.DefaultFindingPrompt() {
		t.Fatalf("default prompt mismatch:\n%s", got)
	}
	if body["custom"] != false {
		t.Fatalf("custom = %v, want false", body["custom"])
	}
	suffix := toString(body["suffix"])
	if suffix != codeaudit.FindingPromptEvidenceTemplate() {
		t.Fatalf("suffix is not the evidence template:\n%s", suffix)
	}
	if !strings.HasPrefix(suffix, codeaudit.FindingPromptEvidenceMarker) {
		t.Fatalf("suffix does not start at the evidence marker:\n%s", suffix)
	}

	// The editor shows the complete prompt, so a save can arrive with the
	// generated half still attached. Only the instruction half may be stored,
	// or the next audit would append the evidence template twice.
	fullPrompt := "只看外发行为\n\n" + suffix
	fullJSON, _ := json.Marshal(map[string]string{"prompt": fullPrompt})
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/audit/console/prompt", strings.NewReader(string(fullJSON)))
	handler(rec, req)
	body = decode(rec)
	if body["custom"] != true || toString(body["prompt"]) != "只看外发行为" {
		t.Fatalf("saving a complete prompt kept the generated half: %v", body)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/api/audit/console/prompt", strings.NewReader(`{"prompt":"只看外发行为"}`))
	handler(rec, req)
	body = decode(rec)
	if body["custom"] != true || body["prompt"] != "只看外发行为" {
		t.Fatalf("custom save = %v", body)
	}

	defaultJSON, _ := json.Marshal(map[string]string{"prompt": codeaudit.DefaultFindingPrompt()})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/api/audit/console/prompt", strings.NewReader(string(defaultJSON)))
	handler(rec, req)
	body = decode(rec)
	if body["custom"] != false || toString(body["prompt"]) != codeaudit.DefaultFindingPrompt() {
		t.Fatalf("saving the default did not clear the override: %v", body)
	}
}

func TestGatewayReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if !gatewayReachable(addr, time.Second) {
		t.Fatal("a listening gateway was reported unreachable")
	}
	ln.Close()
	if gatewayReachable(addr, 200*time.Millisecond) {
		t.Fatal("a closed port was reported reachable")
	}
}
