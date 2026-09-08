package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestIndexShowsTrainingReportAndResourceInfoModules(t *testing.T) {
	if strings.Contains(indexHTML, "③ 资源下载结果上报") {
		t.Fatal("index should not show the resource download result report card")
	}
	for _, want := range []string{"③ 训练结果上报", "registerBodyBtn", "card-attestation", "attestRequestId", "attestationResult", "saveReportBtn", "reportResBodyBtn", "reportResReportBtn", "openReportResReportModal", "查看报告", "reportModelImportBodyBtn", "bodyModal", "importModelPublicKey", "importModelCommands", "importModelEnv", "resourceInfoResult", "testGetResourceInfo", "/v1/taa/getResourceInfo", "/v1/taa/reportModelImport", "uploadedUrlInput", "uploadedFilesCount", "uploadedFilesList", "清空所有上传文件", "平台发往 TAA 的请求体记录", "requestLogStatusDot", "requestLogOutput", "requestLogEndpointFilter"} {
		if !strings.Contains(indexHTML, want) {
			t.Fatalf("index missing %q", want)
		}
	}
}

func TestRequestLogsHandlersExposeAndResetCapturedTraffic(t *testing.T) {
	requestLogs.reset()
	requestLogs.add(requestLogEntry{Timestamp: "2026-09-08T12:00:00Z", Direction: "in", Level: "info", Component: "register", Method: http.MethodPost, Path: "/v1/taa/register", Status: http.StatusOK, Message: "HTTP 200 POST (2ms)", Body: `{"dockerId":"docker-1"}`})

	req := httptest.NewRequest(http.MethodPost, "/api/request-logs/status", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	requestLogsStatusHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var api struct {
		Result struct {
			Logs  []requestLogEntry `json:"logs"`
			Total int               `json:"total"`
		} `json:"result"`
	}
	if err := json.NewDecoder(w.Body).Decode(&api); err != nil {
		t.Fatalf("decode request logs response: %v", err)
	}
	if got := len(api.Result.Logs); got != 1 || api.Result.Total != 1 {
		t.Fatalf("logs = %+v, want 1 entry", api.Result)
	}
	if api.Result.Logs[0].Component != "register" || api.Result.Logs[0].Direction != "in" {
		t.Fatalf("unexpected log entry: %+v", api.Result.Logs[0])
	}

	resetReq := httptest.NewRequest(http.MethodPost, "/api/request-logs/reset", nil)
	resetW := httptest.NewRecorder()
	requestLogsResetHandler(resetW, resetReq)
	if resetW.Code != http.StatusOK {
		t.Fatalf("reset status = %d, want 200; body=%s", resetW.Code, resetW.Body.String())
	}

	w = httptest.NewRecorder()
	requestLogsStatusHandler(w, httptest.NewRequest(http.MethodPost, "/api/request-logs/status", strings.NewReader(`{}`)))
	if err := json.NewDecoder(w.Body).Decode(&api); err != nil {
		t.Fatalf("decode reset request logs response: %v", err)
	}
	if api.Result.Total != 0 || len(api.Result.Logs) != 0 {
		t.Fatalf("logs after reset = %+v, want empty", api.Result)
	}
}

func TestReportResStatusIncludesTaskIDReportAndRawBody(t *testing.T) {
	store := &reportStateStore{path: filepath.Join(t.TempDir(), "reportRes-state.json")}
	handler := reportResHandler(store)

	body := strings.NewReader(`{"dockerId":"docker-1","requestId":"req-1","taskId":"task-1","code":0,"msg":null,"report":"{\"schema_version\":\"1.0\"}"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportRes", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	state := store.get()
	if state.DockerID != "docker-1" || state.RequestID != "req-1" || state.TaskID != "task-1" || state.Code != 0 {
		t.Fatalf("state = %+v", state)
	}
	if state.Report != `{"schema_version":"1.0"}` {
		t.Fatalf("report = %q", state.Report)
	}
	if !json.Valid([]byte(state.RawBody)) {
		t.Fatalf("raw body is not JSON: %q", state.RawBody)
	}
}

func TestReportModelImportStatusIncludesRequestID(t *testing.T) {
	store := &reportStateStore{path: filepath.Join(t.TempDir(), "reportModelImport-state.json")}
	handler := reportModelImportHandler(store)

	body := strings.NewReader(`{"dockerId":"docker-1","requestId":"req-1","taskId":"task-1","code":0,"msg":null,"report":"{\"conclusion\":{\"passed\":true}}"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportModelImport", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	state := store.get()
	if state.DockerID != "docker-1" || state.RequestID != "req-1" || state.TaskID != "task-1" || state.Code != 0 {
		t.Fatalf("state = %+v", state)
	}
	if state.Report != `{"conclusion":{"passed":true}}` {
		t.Fatalf("report = %q", state.Report)
	}
	if !json.Valid([]byte(state.RawBody)) {
		t.Fatalf("raw body is not JSON: %q", state.RawBody)
	}
}

func TestReportModelImportRequiresDockerID(t *testing.T) {
	store := &reportStateStore{path: filepath.Join(t.TempDir(), "reportModelImport-state.json")}
	handler := reportModelImportHandler(store)

	body := strings.NewReader(`{"taskId":"task-1","code":0}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportModelImport", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestTAAGetResourceInfoProxy(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network listeners unavailable: %v", err)
	}
	taa := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/taa/getResourceInfo" {
			t.Fatalf("path = %s, want /v1/taa/getResourceInfo", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "sample.tar.gz") {
			t.Fatalf("body = %s, want to contain resourceUrl", body)
		}
		writeEnvelope(w, http.StatusOK, "success", map[string]any{"total_samples": 2000}, 0)
	}))
	taa.Listener = ln
	taa.Start()
	defer taa.Close()

	handler := taaGetResourceInfoHandler(taa.URL)
	req := httptest.NewRequest(http.MethodPost, "/api/taa/getResourceInfo", strings.NewReader(`{"resourceUrl":"http://example.com/sample.tar.gz"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "total_samples") {
		t.Fatalf("response body = %s, want to contain total_samples", w.Body.String())
	}
}

func TestRegisterHandlerAcceptsJSONPayload(t *testing.T) {
	store := &registerStateStore{path: filepath.Join(t.TempDir(), "register-state.json")}
	handler := registerHandler(store, false)
	attestation := base64.StdEncoding.EncodeToString([]byte("attestation-body"))
	body := strings.NewReader(`{"dockerId":"docker-1","authInfo":null,"taaPublicKey":"-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----","attestationValues":"{\"userdata\":\"abcd\",\"mnonce\":\"ef01\",\"digest\":\"2345\",\"chipId\":\"6789\"}","timestamp":"1234567890","verifiedPass":true,"attestation":"` + attestation + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/register", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	state := store.get()
	if !state.Accepted || state.DockerID != "docker-1" || state.AuthInfo != "null" || state.Timestamp != "1234567890" || !state.VerifiedPass {
		t.Fatalf("state = %+v", state)
	}
	if state.ContentType != "application/json" {
		t.Fatalf("contentType = %q, want application/json", state.ContentType)
	}
	if state.TaaPublicKey != "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----" {
		t.Fatalf("taaPublicKey = %q", state.TaaPublicKey)
	}
	if state.AttestationValues != `{"userdata":"abcd","mnonce":"ef01","digest":"2345","chipId":"6789"}` {
		t.Fatalf("attestationValues = %q", state.AttestationValues)
	}
	if state.AttestationBase64 != attestation || state.AttestationSize != int64(len("attestation-body")) {
		t.Fatalf("attestation state = base64:%q size:%d", state.AttestationBase64, state.AttestationSize)
	}
}

func TestDiscoverTAAAddrUsesConfiguredPort(t *testing.T) {
	tmpDir := t.TempDir()
	kubectlPath := filepath.Join(tmpDir, "kubectl")
	if runtime.GOOS == "windows" {
		kubectlPath += ".bat"
	}

	script := "#!/bin/sh\nprintf '10.244.0.49'\n"
	if runtime.GOOS == "windows" {
		script = "@echo off\r\necho|set /p=10.244.0.49\r\n"
	}
	if err := os.WriteFile(kubectlPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", tmpDir+string(os.PathListSeparator)+oldPath)

	got := discoverTAAAddr("simple-busybox", "", "9001")
	want := "http://10.244.0.49:9001"
	if got != want {
		t.Fatalf("discoverTAAAddr() = %q, want %q", got, want)
	}
}

func newUploadTestServer(t *testing.T, uploadDir string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/upload", uploadHandler("127.0.0.1:6001", uploadDir))
	mux.HandleFunc("/api/uploads", uploadListHandler("127.0.0.1:6001", uploadDir))
	mux.HandleFunc("/api/uploads/reset", uploadResetHandler(uploadDir))
	mux.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(uploadDir))))
	return httptest.NewServer(mux)
}

func postMultipartUpload(t *testing.T, url, filename string, content []byte) apiResponse {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer resp.Body.Close()

	var api apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("upload response = %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}
	return api
}

func readUploadList(t *testing.T, resp *http.Response) []uploadedFileRecord {
	t.Helper()
	defer resp.Body.Close()
	var api struct {
		Msg    string `json:"msg"`
		Error  int    `json:"error"`
		Result struct {
			Files []uploadedFileRecord `json:"files"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		t.Fatalf("decode upload list: %v", err)
	}
	if api.Error != 0 {
		t.Fatalf("upload list response error = %d msg=%s", api.Error, api.Msg)
	}
	return api.Result.Files
}

func TestUploadListHandlerReturnsNewestFirst(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newUploadTestServer(t, uploadDir)
	defer server.Close()

	postMultipartUpload(t, server.URL+"/api/upload", "alpha.txt", []byte("alpha"))
	time.Sleep(2 * time.Millisecond)
	postMultipartUpload(t, server.URL+"/api/upload", "beta.txt", []byte("beta-data"))

	resp, err := http.Get(server.URL + "/api/uploads")
	if err != nil {
		t.Fatalf("list uploads: %v", err)
	}
	files := readUploadList(t, resp)
	if len(files) != 2 {
		t.Fatalf("files length = %d, want 2", len(files))
	}
	if files[0].OriginalName != "beta.txt" || files[1].OriginalName != "alpha.txt" {
		t.Fatalf("files order = %+v", files)
	}
	if files[0].Size != int64(len("beta-data")) || files[1].Size != int64(len("alpha")) {
		t.Fatalf("file sizes = %+v", files)
	}
	if files[0].UploadedAt.IsZero() || files[1].UploadedAt.IsZero() {
		t.Fatalf("uploadedAt not set: %+v", files)
	}
	if !strings.HasSuffix(files[0].URL, "/files/"+files[0].Filename) || !strings.HasSuffix(files[1].URL, "/files/"+files[1].Filename) {
		t.Fatalf("unexpected urls: %+v", files)
	}
}

func TestUploadResetHandlerClearsFiles(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newUploadTestServer(t, uploadDir)
	defer server.Close()

	postMultipartUpload(t, server.URL+"/api/upload", "reset-a.txt", []byte("a"))
	time.Sleep(2 * time.Millisecond)
	postMultipartUpload(t, server.URL+"/api/upload", "reset-b.txt", []byte("bb"))

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/uploads/reset", nil)
	if err != nil {
		t.Fatalf("create reset request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send reset request: %v", err)
	}
	var api apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		t.Fatalf("decode reset response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("reset response = %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatalf("read upload dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("upload dir not empty after reset: %d entries", len(entries))
	}

	resp, err = http.Get(server.URL + "/api/uploads")
	if err != nil {
		t.Fatalf("list uploads after reset: %v", err)
	}
	files := readUploadList(t, resp)
	if len(files) != 0 {
		t.Fatalf("files after reset = %+v, want empty", files)
	}
}

func TestUploadHandlerSanitizesFilename(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newUploadTestServer(t, uploadDir)
	defer server.Close()

	postMultipartUpload(t, server.URL+"/api/upload", `..\\nested/escape.txt`, []byte("safe"))

	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatalf("read upload dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("upload dir entries = %d, want 1", len(entries))
	}
	name := entries[0].Name()
	if strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		t.Fatalf("stored filename = %q, want sanitized basename", name)
	}

	resp, err := http.Get(server.URL + "/api/uploads")
	if err != nil {
		t.Fatalf("list uploads: %v", err)
	}
	files := readUploadList(t, resp)
	if len(files) != 1 {
		t.Fatalf("files length = %d, want 1", len(files))
	}
	if files[0].OriginalName != "escape.txt" {
		t.Fatalf("originalName = %q, want escape.txt", files[0].OriginalName)
	}
}
