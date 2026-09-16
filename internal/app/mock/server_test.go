package mock

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

	"taa/pkg/crypto"
)

func TestIndexShowsTrainingReportAndResourceInfoModules(t *testing.T) {
	if strings.Contains(indexHTML, "③ 资源下载结果上报") {
		t.Fatal("index should not show the resource download result report card")
	}
	for _, want := range []string{"③ 训练结果上报", "registerBodyBtn", "card-attestation", "attestRequestId", "attestationResult", "saveReportBtn", "reportResBodyBtn", "reportResReportBtn", "openReportResReportModal", "查看报告", "reportModelImportBodyBtn", "bodyModal", "importModelPublicKey", "importModelCommands", "importModelEnv", "resourceInfoResult", "testGetResourceInfo", "/v1/taa/getResourceInfo", "/v1/taa/reportModelImport", "setupResourceUrlDropZones", "uploadedFilesCount", "uploadedFilesList", "清空所有上传文件", "平台发往 TAA 的请求体记录", "requestLogStatusDot", "requestLogOutput", "requestLogEndpointFilter", "uploadEncryptSwitch", "启用加密", "deleteUploadedFile", "创建公钥", "generateImportModelPublicKey", "exportDecryptSwitch", "是否解密", "exportPrivateKey", "exportRequestId", "resourceInfoTreeContainer", "resourceInfoModalBtn", "resourceInfoModal", "loadSampleResourceTree", "renderResourceInfoTreeShell", "randomizeField", "randomizeImportModelIds", "randomizeImportIds"} {
		if !strings.Contains(indexHTML, want) {
			t.Fatalf("index missing %q", want)
		}
	}
}

func TestRequestIdAndTaskIdRandomizeButtons(t *testing.T) {
	requiredTriggers := []string{
		`randomizeField('importModelRequestId'`,
		`randomizeField('importModelTaskId'`,
		`randomizeField('importRequestId'`,
		`randomizeField('importTaskId'`,
		`randomizeImportModelIds()`,
		`randomizeImportIds()`,
	}
	for _, trigger := range requiredTriggers {
		if !strings.Contains(indexHTML, trigger) {
			t.Fatalf("index.html missing expected random generator trigger: %q", trigger)
		}
	}

	forbiddenTriggers := []string{
		`randomizeField('exportRequestId'`,
		`randomizeField('exportTaskId'`,
		`randomizeExportIds`,
	}
	for _, forbidden := range forbiddenTriggers {
		if strings.Contains(indexHTML, forbidden) {
			t.Fatalf("export interface must not have random generation buttons, found: %q", forbidden)
		}
	}
}

func TestGenerateKeyDoesNotAutoFillExportPublicKey(t *testing.T) {
	// 验证私钥仍然会同步到导出结果的解密私钥输入框
	if !strings.Contains(indexHTML, "exportPrivKey.value = privKey") {
		t.Fatal("generateImportModelPublicKey should keep syncing privateKey to exportPrivateKey")
	}

	// 验证不再自动将公钥赋值给 exportPublicKey
	forbiddenSnippets := []string{
		"exportPubKey.value = pubKey",
		"exportPubKey.value =",
		"document.getElementById('exportPublicKey').value = pubKey",
	}
	for _, snippet := range forbiddenSnippets {
		if strings.Contains(indexHTML, snippet) {
			t.Fatalf("exportPublicKey must not be auto-filled, found forbidden snippet: %q", snippet)
		}
	}

	// 验证 exportPublicKey 明确标注为选填/仅功能验证使用
	if !strings.Contains(indexHTML, `id="exportPublicKey" value="" placeholder="选填，留空=不传，需要验证时手动输入"`) {
		t.Fatal("exportPublicKey placeholder should indicate optional manual input")
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

	body := strings.NewReader(`{"dockerId":"docker-1","requestId":"req-1","taskId":"task-1","code":0,"msg":null,"report":"{\"conclusion\":{\"passed\":true}}","checksum":{"size":581632,"algorithm":"sm3","value":"a1b2c3d4"}}`)
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
	if state.Checksum == nil || state.Checksum["algorithm"] != "sm3" || state.Checksum["value"] != "a1b2c3d4" {
		t.Fatalf("checksum = %+v", state.Checksum)
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

func TestReportAuditStatusIncludesRequestID(t *testing.T) {
	store := &reportStateStore{path: filepath.Join(t.TempDir(), "reportAudit-state.json")}
	handler := reportAuditHandler(store)

	body := strings.NewReader(`{"dockerId":"docker-1","requestId":"req-1","taskId":"task-1","code":0,"msg":null,"report":"{\"conclusion\":{\"passed\":true}}"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportAudit", body)
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

func newUploadTestServer(t *testing.T, uploadDir string, registerStores ...*registerStateStore) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/upload", uploadHandler("127.0.0.1:6001", uploadDir, registerStores...))
	registerUploadDeleteRoutes(mux, uploadDir)
	mux.HandleFunc("/api/uploads", uploadListHandler("127.0.0.1:6001", uploadDir))
	mux.HandleFunc("/api/uploads/reset", uploadResetHandler(uploadDir))
	mux.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(uploadDir))))
	return httptest.NewServer(mux)
}

func postMultipartUploadWithFields(t *testing.T, url, filename string, content []byte, fields map[string]string) (int, apiResponse) {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for k, v := range fields {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatalf("write field %s: %v", k, err)
		}
	}
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
	return resp.StatusCode, api
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

func TestUploadDeleteHandler(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newUploadTestServer(t, uploadDir)
	defer server.Close()

	respA := postMultipartUpload(t, server.URL+"/api/upload", "del-a.txt", []byte("a"))
	time.Sleep(2 * time.Millisecond)
	respB := postMultipartUpload(t, server.URL+"/api/upload", "del-b.txt", []byte("b"))

	fileA := respA.Result.(map[string]any)["filename"].(string)
	fileB := respB.Result.(map[string]any)["filename"].(string)

	// 1. 通过 POST /api/upload/delete 删除文件 A
	delBody, _ := json.Marshal(map[string]string{"filename": fileA})
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/upload/delete", bytes.NewReader(delBody))
	if err != nil {
		t.Fatalf("create delete req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send delete req: %v", err)
	}
	var api apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		t.Fatalf("decode delete resp: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("delete status = %d, err = %d, msg = %s", resp.StatusCode, api.Error, api.Msg)
	}

	// 验证磁盘和列表仅剩文件 B
	listResp, err := http.Get(server.URL + "/api/uploads")
	if err != nil {
		t.Fatalf("get uploads list: %v", err)
	}
	files := readUploadList(t, listResp)
	if len(files) != 1 || files[0].Filename != fileB {
		t.Fatalf("files after delete = %+v, want only fileB (%s)", files, fileB)
	}

	// 2. 再次删除已不存在的文件 A，返回 404
	req404, _ := http.NewRequest(http.MethodPost, server.URL+"/api/upload/delete", bytes.NewReader(delBody))
	req404.Header.Set("Content-Type", "application/json")
	resp404, err := http.DefaultClient.Do(req404)
	if err != nil {
		t.Fatalf("send delete 404 req: %v", err)
	}
	resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp404.StatusCode)
	}

	// 3. 通过 DELETE 方法与 URL 参数删除文件 B
	reqDel, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/uploads/delete?filename="+fileB, nil)
	respDel, err := http.DefaultClient.Do(reqDel)
	if err != nil {
		t.Fatalf("send delete method req: %v", err)
	}
	respDel.Body.Close()
	if respDel.StatusCode != http.StatusOK {
		t.Fatalf("delete via query param status = %d, want 200", respDel.StatusCode)
	}

	// 列表变为空
	listResp2, err := http.Get(server.URL + "/api/uploads")
	if err != nil {
		t.Fatalf("get uploads list 2: %v", err)
	}
	files2 := readUploadList(t, listResp2)
	if len(files2) != 0 {
		t.Fatalf("files after all deletes = %+v, want empty", files2)
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

func TestUploadHandlerEncryption(t *testing.T) {
	privKey, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key pair: %v", err)
	}
	pubPEM, err := crypto.MarshalSM2PublicKeyPEM(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal SM2 public key PEM: %v", err)
	}

	regStore := &registerStateStore{path: filepath.Join(t.TempDir(), "register.json")}
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newUploadTestServer(t, uploadDir, regStore)
	defer server.Close()

	rawContent := []byte("hello sm2 sm4 gcm envelope encryption")

	// 1. 开启加密开关，传入公钥，文件名自动补齐 .enc
	status, api := postMultipartUploadWithFields(t, server.URL+"/api/upload", "model.tar.gz", rawContent, map[string]string{
		"encrypt":   "true",
		"publicKey": string(pubPEM),
	})
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("encrypted upload failed: status=%d, api=%+v", status, api)
	}
	resMap, ok := api.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not map: %+v", api.Result)
	}
	if orig, ok := resMap["originalName"].(string); !ok || orig != "model.tar.gz.enc" {
		t.Fatalf("originalName = %v, want model.tar.gz.enc", resMap["originalName"])
	}
	if enc, ok := resMap["encrypted"].(bool); !ok || !enc {
		t.Fatalf("encrypted flag = %v, want true", resMap["encrypted"])
	}

	storedName, ok := resMap["filename"].(string)
	if !ok || !strings.HasSuffix(storedName, ".enc") {
		t.Fatalf("stored filename = %v, want suffix .enc", resMap["filename"])
	}

	cipherBytes, err := os.ReadFile(filepath.Join(uploadDir, storedName))
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	decrypted, err := crypto.OpenSM2SM4GCM(privKey, cipherBytes)
	if err != nil {
		t.Fatalf("OpenSM2SM4GCM decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, rawContent) {
		t.Fatalf("decrypted = %q, want %q", string(decrypted), string(rawContent))
	}

	// 2. 文件名本身已带 .enc 后缀时，不重复添加
	status, api = postMultipartUploadWithFields(t, server.URL+"/api/upload", "already.tar.gz.enc", rawContent, map[string]string{
		"encrypt":   "true",
		"publicKey": string(pubPEM),
	})
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("upload already.enc failed: status=%d, api=%+v", status, api)
	}
	resMap = api.Result.(map[string]any)
	if orig := resMap["originalName"].(string); orig != "already.tar.gz.enc" {
		t.Fatalf("originalName = %q, want already.tar.gz.enc", orig)
	}

	// 3. 未传 publicKey 时，从 registerStore 回退获取公钥
	regStore.set(registerState{TaaPublicKey: string(pubPEM)})
	status, api = postMultipartUploadWithFields(t, server.URL+"/api/upload", "data.tar.gz", rawContent, map[string]string{
		"encrypt": "true",
	})
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("upload with fallback key failed: status=%d, api=%+v", status, api)
	}
	resMap = api.Result.(map[string]any)
	if orig := resMap["originalName"].(string); orig != "data.tar.gz.enc" {
		t.Fatalf("originalName with fallback = %q, want data.tar.gz.enc", orig)
	}
	fallbackCipher, err := os.ReadFile(filepath.Join(uploadDir, resMap["filename"].(string)))
	if err != nil {
		t.Fatalf("read fallback cipher: %v", err)
	}
	decryptedFallback, err := crypto.OpenSM2SM4GCM(privKey, fallbackCipher)
	if err != nil {
		t.Fatalf("decrypt fallback cipher failed: %v", err)
	}
	if !bytes.Equal(decryptedFallback, rawContent) {
		t.Fatalf("decrypted fallback = %q, want %q", string(decryptedFallback), string(rawContent))
	}

	// 4. 开启加密但既无 publicKey 也无注册公钥时，返回 400 错误
	regStore.set(registerState{})
	status, api = postMultipartUploadWithFields(t, server.URL+"/api/upload", "err.txt", rawContent, map[string]string{
		"encrypt": "true",
	})
	if status != http.StatusBadRequest || api.Error != http.StatusBadRequest {
		t.Fatalf("status = %d, error = %d, want 400", status, api.Error)
	}

	// 5. 传入非法公钥时，返回 400 错误
	status, api = postMultipartUploadWithFields(t, server.URL+"/api/upload", "err.txt", rawContent, map[string]string{
		"encrypt":   "true",
		"publicKey": "invalid-pem-key",
	})
	if status != http.StatusBadRequest || api.Error != http.StatusBadRequest {
		t.Fatalf("status = %d, error = %d, want 400", status, api.Error)
	}
}

func TestCryptoGenerateKeyHandler(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/crypto/generate-key", cryptoGenerateKeyHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	// 1. POST 请求生成 SM2 密钥对
	resp, err := http.Post(server.URL+"/api/crypto/generate-key", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/crypto/generate-key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var api struct {
		Msg    string `json:"msg"`
		Error  int    `json:"error"`
		Result struct {
			PublicKey  string `json:"publicKey"`
			PrivateKey string `json:"privateKey"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		t.Fatalf("decode generate-key response: %v", err)
	}
	if api.Error != 0 {
		t.Fatalf("api error = %d, msg = %s", api.Error, api.Msg)
	}
	if !strings.Contains(api.Result.PublicKey, "BEGIN PUBLIC KEY") {
		t.Fatalf("invalid publicKey PEM: %s", api.Result.PublicKey)
	}
	if !strings.Contains(api.Result.PrivateKey, "BEGIN PRIVATE KEY") {
		t.Fatalf("invalid privateKey PEM: %s", api.Result.PrivateKey)
	}

	// 验证公私钥可被成功解析并完成加解密往返
	pubKey, err := crypto.ParseSM2PublicKeyPEM([]byte(api.Result.PublicKey))
	if err != nil {
		t.Fatalf("parse generated public key: %v", err)
	}
	privKey, err := crypto.ParseSM2PrivateKeyPEM([]byte(api.Result.PrivateKey))
	if err != nil {
		t.Fatalf("parse generated private key: %v", err)
	}

	testData := []byte("platform-mock key generation test")
	sealed, err := crypto.SealSM2SM4GCM(pubKey, testData)
	if err != nil {
		t.Fatalf("seal test data: %v", err)
	}
	opened, err := crypto.OpenSM2SM4GCM(privKey, sealed)
	if err != nil {
		t.Fatalf("open sealed data: %v", err)
	}
	if !bytes.Equal(opened, testData) {
		t.Fatalf("opened = %q, want %q", opened, testData)
	}

	// 2. GET 请求同样支持
	getResp, err := http.Get(server.URL + "/api/crypto/generate-key")
	if err != nil {
		t.Fatalf("GET /api/crypto/generate-key: %v", err)
	}
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", getResp.StatusCode)
	}
}

func TestCryptoDecryptHandler(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/crypto/decrypt", cryptoDecryptHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	privKey, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privPEM, err := crypto.MarshalSM2PrivateKeyPEM(privKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	rawPlaintext := []byte("trained model export archive data contents")
	sealed, err := crypto.SealSM2SM4GCM(&privKey.PublicKey, rawPlaintext)
	if err != nil {
		t.Fatalf("seal test data: %v", err)
	}

	// 1. Multipart Form 上传解密
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("privateKey", string(privPEM)); err != nil {
		t.Fatalf("write privateKey field: %v", err)
	}
	part, err := writer.CreateFormFile("file", "export.tar.gz.enc")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := io.Copy(part, bytes.NewReader(sealed)); err != nil {
		t.Fatalf("copy sealed file: %v", err)
	}
	writer.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/crypto/decrypt", &body)
	if err != nil {
		t.Fatalf("create decrypt req: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do decrypt req: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("decrypt multipart status = %d, body = %s", resp.StatusCode, errBody)
	}
	decryptedBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read decrypted body: %v", err)
	}
	if !bytes.Equal(decryptedBytes, rawPlaintext) {
		t.Fatalf("decrypted = %q, want %q", decryptedBytes, rawPlaintext)
	}

	// 2. JSON 格式解密
	jsonPayload, _ := json.Marshal(map[string]string{
		"privateKey": string(privPEM),
		"ciphertext": base64.StdEncoding.EncodeToString(sealed),
	})
	jsonResp, err := http.Post(server.URL+"/api/crypto/decrypt", "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		t.Fatalf("do decrypt json req: %v", err)
	}
	defer jsonResp.Body.Close()

	if jsonResp.StatusCode != http.StatusOK {
		t.Fatalf("decrypt json status = %d", jsonResp.StatusCode)
	}
	var jsonResult struct {
		Msg    string `json:"msg"`
		Error  int    `json:"error"`
		Result struct {
			Plaintext string `json:"plaintext"`
			Size      int    `json:"size"`
		} `json:"result"`
	}
	if err := json.NewDecoder(jsonResp.Body).Decode(&jsonResult); err != nil {
		t.Fatalf("decode decrypt json result: %v", err)
	}
	decodedPlaintext, err := base64.StdEncoding.DecodeString(jsonResult.Result.Plaintext)
	if err != nil {
		t.Fatalf("decode base64 plaintext: %v", err)
	}
	if !bytes.Equal(decodedPlaintext, rawPlaintext) {
		t.Fatalf("json decrypted = %q, want %q", decodedPlaintext, rawPlaintext)
	}

	// 3. 错误密钥解密失败
	otherKey, _ := crypto.GenerateSM2KeyPair()
	otherPEM, _ := crypto.MarshalSM2PrivateKeyPEM(otherKey)
	failPayload, _ := json.Marshal(map[string]string{
		"privateKey": string(otherPEM),
		"ciphertext": base64.StdEncoding.EncodeToString(sealed),
	})
	failResp, err := http.Post(server.URL+"/api/crypto/decrypt", "application/json", bytes.NewReader(failPayload))
	if err != nil {
		t.Fatalf("fail decrypt req: %v", err)
	}
	failResp.Body.Close()
	if failResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("fail status = %d, want 400", failResp.StatusCode)
	}

	// 4. 缺少 privateKey 返回 400
	missingKeyPayload, _ := json.Marshal(map[string]string{
		"ciphertext": base64.StdEncoding.EncodeToString(sealed),
	})
	missingResp, err := http.Post(server.URL+"/api/crypto/decrypt", "application/json", bytes.NewReader(missingKeyPayload))
	if err != nil {
		t.Fatalf("missing key req: %v", err)
	}
	missingResp.Body.Close()
	if missingResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing key status = %d, want 400", missingResp.StatusCode)
	}
}

func TestUploadFilesStaticServing(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "custom-uploads")
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		t.Fatalf("mkdir uploadDir: %v", err)
	}
	testFile := "test-model.zip.enc"
	testContent := []byte("dummy encrypted model data")
	if err := os.WriteFile(filepath.Join(uploadDir, testFile), testContent, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(uploadDir))))
	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/files/" + testFile)
	if err != nil {
		t.Fatalf("get file: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, testContent) {
		t.Fatalf("content = %q, want %q", string(body), string(testContent))
	}
}

func TestIndexHandlerServesRootAndIndexHTML(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/index.html", indexHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	for _, path := range []string{"/", "/index.html"} {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status for %s = %d, want 200", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Errorf("content-type for %s = %q, want text/html", path, ct)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != indexHTML {
			t.Errorf("body mismatch for %s", path)
		}
	}

	// Non-matching path returns 404
	resp, err := http.Get(server.URL + "/nonexistent")
	if err != nil {
		t.Fatalf("get /nonexistent: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status for /nonexistent = %d, want 404", resp.StatusCode)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.UploadDir != ".local/upload" {
		t.Errorf("DefaultConfig().UploadDir = %q, want %q", cfg.UploadDir, ".local/upload")
	}

	emptyCfg := Config{}
	resolved := emptyCfg.withDefaults()
	if resolved.UploadDir != ".local/upload" {
		t.Errorf("Config{}.withDefaults().UploadDir = %q, want %q", resolved.UploadDir, ".local/upload")
	}
}

func TestReportModelImportStrictValidationAndChecksum(t *testing.T) {
	store := &reportStateStore{path: filepath.Join(t.TempDir(), "reportModelImport-state.json")}
	handler := reportModelImportHandler(store)

	// 1. 缺少 requestId 时返回 400
	reqNoReqID := httptest.NewRequest(http.MethodPost, "/v1/taa/reportModelImport", strings.NewReader(`{
		"dockerId": "docker-1",
		"code": 0,
		"checksum": {"size": 581632, "algorithm": "sm3", "value": "a1b2c3d4"}
	}`))
	reqNoReqID.Header.Set("Content-Type", "application/json")
	wNoReqID := httptest.NewRecorder()
	handler(wNoReqID, reqNoReqID)
	if wNoReqID.Code != http.StatusBadRequest {
		t.Fatalf("missing requestId status = %d, want 400; body=%s", wNoReqID.Code, wNoReqID.Body.String())
	}
	if !strings.Contains(wNoReqID.Body.String(), "缺少 requestId") {
		t.Fatalf("body = %s, want to contain '缺少 requestId'", wNoReqID.Body.String())
	}

	// 2. code=0 时缺少 checksum 返回 400
	reqNoChecksum := httptest.NewRequest(http.MethodPost, "/v1/taa/reportModelImport", strings.NewReader(`{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"code": 0
	}`))
	reqNoChecksum.Header.Set("Content-Type", "application/json")
	wNoChecksum := httptest.NewRecorder()
	handler(wNoChecksum, reqNoChecksum)
	if wNoChecksum.Code != http.StatusBadRequest {
		t.Fatalf("missing checksum status = %d, want 400; body=%s", wNoChecksum.Code, wNoChecksum.Body.String())
	}
	if !strings.Contains(wNoChecksum.Body.String(), "导入成功时 checksum 不能为空且必须包含 size、algorithm 与 value") {
		t.Fatalf("body = %s, want to contain checksum error message", wNoChecksum.Body.String())
	}

	// 3. 合法上报时返回 200，且通过 reportStateResult 能正确获取到 checksum 字段内容
	validBody := `{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"taskId": "task-1",
		"code": 0,
		"checksum": {"size": 581632, "algorithm": "sm3", "value": "a1b2c3d4"}
	}`
	reqValid := httptest.NewRequest(http.MethodPost, "/v1/taa/reportModelImport", strings.NewReader(validBody))
	reqValid.Header.Set("Content-Type", "application/json")
	wValid := httptest.NewRecorder()
	handler(wValid, reqValid)
	if wValid.Code != http.StatusOK {
		t.Fatalf("valid request status = %d, want 200; body=%s", wValid.Code, wValid.Body.String())
	}

	result := reportStateResult(store.get())
	if result["code"] != 0 {
		t.Fatalf("result code = %v, want 0", result["code"])
	}
	checksumMap, ok := result["checksum"].(map[string]any)
	if !ok || checksumMap == nil {
		t.Fatalf("result checksum is not a valid map: %+v", result["checksum"])
	}
	if checksumMap["algorithm"] != "sm3" || checksumMap["value"] != "a1b2c3d4" {
		t.Fatalf("checksum mismatch: %+v", checksumMap)
	}
	switch s := checksumMap["size"].(type) {
	case float64:
		if int64(s) != 581632 {
			t.Fatalf("checksum size = %v, want 581632", s)
		}
	case int:
		if s != 581632 {
			t.Fatalf("checksum size = %v, want 581632", s)
		}
	case int64:
		if s != 581632 {
			t.Fatalf("checksum size = %v, want 581632", s)
		}
	default:
		t.Fatalf("unexpected type for size: %T (%v)", checksumMap["size"], checksumMap["size"])
	}
}

func TestReportAuditStatisticsParsing(t *testing.T) {
	store := &reportStateStore{path: filepath.Join(t.TempDir(), "reportAudit-state.json")}
	handler := reportAuditHandler(store)

	// 1. 测试缺少 dockerId
	reqNoDockerID := httptest.NewRequest(http.MethodPost, "/v1/taa/reportAudit", strings.NewReader(`{
		"requestId": "req-1",
		"code": 0
	}`))
	reqNoDockerID.Header.Set("Content-Type", "application/json")
	wNoDockerID := httptest.NewRecorder()
	handler(wNoDockerID, reqNoDockerID)
	if wNoDockerID.Code != http.StatusBadRequest {
		t.Fatalf("missing dockerId status = %d, want 400", wNoDockerID.Code)
	}

	// 2. 测试缺少 requestId
	reqNoReqID := httptest.NewRequest(http.MethodPost, "/v1/taa/reportAudit", strings.NewReader(`{
		"dockerId": "docker-1",
		"code": 0
	}`))
	reqNoReqID.Header.Set("Content-Type", "application/json")
	wNoReqID := httptest.NewRecorder()
	handler(wNoReqID, reqNoReqID)
	if wNoReqID.Code != http.StatusBadRequest {
		t.Fatalf("missing requestId status = %d, want 400", wNoReqID.Code)
	}

	// 3. 测试 code 校验 (必须为 0, 1, 2)
	reqBadCode := httptest.NewRequest(http.MethodPost, "/v1/taa/reportAudit", strings.NewReader(`{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"code": 3
	}`))
	reqBadCode.Header.Set("Content-Type", "application/json")
	wBadCode := httptest.NewRecorder()
	handler(wBadCode, reqBadCode)
	if wBadCode.Code != http.StatusBadRequest {
		t.Fatalf("bad code status = %d, want 400", wBadCode.Code)
	}

	// 4. 测试上报带有 report 并解析 risk_level 和 statistics
	reportContent := `{"conclusion":{"risk_level":"LOW","statistics":{"high":0,"medium":1,"low":2}}}`
	bodyBytes, _ := json.Marshal(map[string]any{
		"dockerId":  "docker-1",
		"requestId": "req-1",
		"taskId":    "task-1",
		"code":      0,
		"report":    reportContent,
	})
	reqValid := httptest.NewRequest(http.MethodPost, "/v1/taa/reportAudit", bytes.NewReader(bodyBytes))
	reqValid.Header.Set("Content-Type", "application/json")
	wValid := httptest.NewRecorder()
	handler(wValid, reqValid)
	if wValid.Code != http.StatusOK {
		t.Fatalf("valid reportAudit status = %d, want 200; body=%s", wValid.Code, wValid.Body.String())
	}

	result := reportStateResult(store.get())
	if result["riskLevel"] != "LOW" {
		t.Fatalf("result riskLevel = %v, want LOW", result["riskLevel"])
	}
	statsMap, ok := result["statistics"].(map[string]any)
	if !ok || statsMap == nil {
		t.Fatalf("result statistics is not map: %+v", result["statistics"])
	}
	checkCount := func(key string, want int) {
		val, exists := statsMap[key]
		if !exists {
			t.Fatalf("statistics missing key %q", key)
		}
		switch v := val.(type) {
		case float64:
			if int(v) != want {
				t.Fatalf("statistics[%q] = %v, want %d", key, v, want)
			}
		case int:
			if v != want {
				t.Fatalf("statistics[%q] = %v, want %d", key, v, want)
			}
		default:
			t.Fatalf("unexpected type for statistics[%q]: %T (%v)", key, val, val)
		}
	}
	checkCount("high", 0)
	checkCount("medium", 1)
	checkCount("low", 2)
}

func TestReportProgressHandlingAndTimestampOrdering(t *testing.T) {
	store := newProgressStateStore(t.TempDir())
	handler := reportProgressHandler(store)

	sendProgress := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportProgress", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	// 1. 正常上报 35.5% 进度
	w1 := sendProgress(`{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"taskId": "task-1",
		"percent": 35.5,
		"timestamp": "2026-09-15T09:30:00Z"
	}`)
	if w1.Code != http.StatusOK {
		t.Fatalf("normal progress status = %d, want 200; body=%s", w1.Code, w1.Body.String())
	}
	state1 := store.get()
	if !state1.Accepted || state1.Percent != 35.5 {
		t.Fatalf("state after 35.5%% = %+v, want percent 35.5 and accepted true", state1)
	}
	if state1.DockerID != "docker-1" || state1.RequestID != "req-1" || state1.TaskID != "task-1" {
		t.Fatalf("state IDs mismatch: %+v", state1)
	}

	// 2. 较早时间戳到达（如 09:20:00Z < 09:30:00Z），验证返回 HTTP 200，但 store 中 Percent 保持 35.5
	w2 := sendProgress(`{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"taskId": "task-1",
		"percent": 20.0,
		"timestamp": "2026-09-15T09:20:00Z"
	}`)
	if w2.Code != http.StatusOK {
		t.Fatalf("earlier timestamp status = %d, want 200; body=%s", w2.Code, w2.Body.String())
	}
	state2 := store.get()
	if state2.Percent != 35.5 {
		t.Fatalf("state after out-of-order earlier timestamp = %+v, want percent to remain 35.5", state2)
	}

	// 3. 更新时间戳到达（如 09:40:00Z > 09:30:00Z），验证更新后 store.get().Percent == 80.0
	w3 := sendProgress(`{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"taskId": "task-1",
		"percent": 80.0,
		"timestamp": "2026-09-15T09:40:00Z"
	}`)
	if w3.Code != http.StatusOK {
		t.Fatalf("newer timestamp status = %d, want 200; body=%s", w3.Code, w3.Body.String())
	}
	state3 := store.get()
	if state3.Percent != 80.0 {
		t.Fatalf("state after newer timestamp = %+v, want percent 80.0", state3)
	}

	// 4. 必填参数校验返回 HTTP 400
	invalidCases := []struct {
		name string
		body string
	}{
		{
			name: "missing dockerId",
			body: `{"requestId":"req-1","taskId":"task-1","percent":50.0,"timestamp":"2026-09-15T09:50:00Z"}`,
		},
		{
			name: "missing requestId",
			body: `{"dockerId":"docker-1","taskId":"task-1","percent":50.0,"timestamp":"2026-09-15T09:50:00Z"}`,
		},
		{
			name: "percent < 0",
			body: `{"dockerId":"docker-1","requestId":"req-1","taskId":"task-1","percent":-1.0,"timestamp":"2026-09-15T09:50:00Z"}`,
		},
		{
			name: "percent > 100",
			body: `{"dockerId":"docker-1","requestId":"req-1","taskId":"task-1","percent":100.5,"timestamp":"2026-09-15T09:50:00Z"}`,
		},
		{
			name: "invalid timestamp",
			body: `{"dockerId":"docker-1","requestId":"req-1","taskId":"task-1","percent":50.0,"timestamp":"not-a-timestamp"}`,
		},
	}

	for _, tc := range invalidCases {
		w := sendProgress(tc.body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("case %s status = %d, want 400; body=%s", tc.name, w.Code, w.Body.String())
		}
	}
}

func TestReportProgressStatusAndReset(t *testing.T) {
	store := newProgressStateStore(t.TempDir())
	reportHandler := reportProgressHandler(store)
	statusHandler := progressStatusHandler(store)
	resetHandler := progressResetHandler(store)

	// 上报一次进度
	reqReport := httptest.NewRequest(http.MethodPost, "/v1/taa/reportProgress", strings.NewReader(`{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"taskId": "task-1",
		"percent": 60.0,
		"timestamp": "2026-09-15T10:00:00Z"
	}`))
	reqReport.Header.Set("Content-Type", "application/json")
	wReport := httptest.NewRecorder()
	reportHandler(wReport, reqReport)
	if wReport.Code != http.StatusOK {
		t.Fatalf("report status = %d, want 200", wReport.Code)
	}

	// 检查 status handler
	wStatus := httptest.NewRecorder()
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/reportProgress/status", nil)
	statusHandler(wStatus, reqStatus)
	if wStatus.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", wStatus.Code)
	}
	var resp struct {
		Msg    string        `json:"msg"`
		Result progressState `json:"result"`
	}
	if err := json.NewDecoder(wStatus.Body).Decode(&resp); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if resp.Result.Percent != 60.0 || resp.Result.DockerID != "docker-1" {
		t.Fatalf("status result = %+v, want percent 60.0", resp.Result)
	}

	// 重置
	wReset := httptest.NewRecorder()
	reqReset := httptest.NewRequest(http.MethodPost, "/api/reportProgress/reset", nil)
	resetHandler(wReset, reqReset)
	if wReset.Code != http.StatusOK {
		t.Fatalf("reset code = %d, want 200", wReset.Code)
	}
	if store.get().Percent != 0 || store.get().Received {
		t.Fatalf("store after reset = %+v, want empty", store.get())
	}
}

func TestModelLogDeduplicationAndRingBuffer(t *testing.T) {
	// 容量设为 5
	store := newModelLogStore(t.TempDir(), 5)
	handler := modelLogHandler(store)

	sendLogs := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/taa/modelLog", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	// 1. 发送一批日志（seq 1..2），验证接收后状态中包含 2 条日志，且顺序为 seq 1, 2
	w1 := sendLogs(`{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"taskId": "task-1",
		"seqStart": 1,
		"entries": [
			{"seq": 1, "message": "log 1", "timestamp": "2026-09-16T10:00:00Z"},
			{"seq": 2, "message": "log 2", "timestamp": "2026-09-16T10:00:01Z"}
		]
	}`)
	if w1.Code != http.StatusOK {
		t.Fatalf("batch 1 status = %d, want 200; body=%s", w1.Code, w1.Body.String())
	}
	st1 := store.get()
	if st1.TotalCount != 2 || len(st1.Entries) != 2 {
		t.Fatalf("state 1 count mismatch: total=%d entries=%d, want 2", st1.TotalCount, len(st1.Entries))
	}
	if st1.Entries[0].Seq != 1 || st1.Entries[1].Seq != 2 {
		t.Fatalf("state 1 entries order mismatch: %+v", st1.Entries)
	}
	if st1.LastSeq != 2 {
		t.Fatalf("state 1 lastSeq = %d, want 2", st1.LastSeq)
	}

	// 2. 发送带有重复日志（seq 2）以及新日志（seq 3）的批次，验证去重生效，总条数为 3，且没有重复项，按 seq 排序
	w2 := sendLogs(`{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"taskId": "task-1",
		"seqStart": 2,
		"entries": [
			{"seq": 2, "message": "log 2 duplicate", "timestamp": "2026-09-16T10:00:01Z"},
			{"seq": 3, "message": "log 3", "timestamp": "2026-09-16T10:00:02Z"}
		]
	}`)
	if w2.Code != http.StatusOK {
		t.Fatalf("batch 2 status = %d, want 200; body=%s", w2.Code, w2.Body.String())
	}
	st2 := store.get()
	if st2.TotalCount != 3 || len(st2.Entries) != 3 {
		t.Fatalf("state 2 count mismatch: total=%d entries=%d, want 3", st2.TotalCount, len(st2.Entries))
	}
	if st2.Entries[0].Seq != 1 || st2.Entries[1].Seq != 2 || st2.Entries[2].Seq != 3 {
		t.Fatalf("state 2 entries order/dedup mismatch: %+v", st2.Entries)
	}
	if st2.Entries[1].Message != "log 2" {
		t.Fatalf("state 2 seq 2 message should not be overwritten by duplicate: %q", st2.Entries[1].Message)
	}
	if st2.LastSeq != 3 {
		t.Fatalf("state 2 lastSeq = %d, want 3", st2.LastSeq)
	}

	// 3. 验证环形缓冲容量限制（例如容量设为 5，写入 8 条日志，最终仅保留最新的 5 条）
	w3 := sendLogs(`{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"taskId": "task-1",
		"seqStart": 4,
		"entries": [
			{"seq": 4, "message": "log 4"},
			{"seq": 5, "message": "log 5"},
			{"seq": 6, "message": "log 6"},
			{"seq": 7, "message": "log 7"},
			{"seq": 8, "message": "log 8"}
		]
	}`)
	if w3.Code != http.StatusOK {
		t.Fatalf("batch 3 status = %d, want 200; body=%s", w3.Code, w3.Body.String())
	}
	st3 := store.get()
	if st3.TotalCount != 8 {
		t.Fatalf("state 3 totalCount = %d, want 8", st3.TotalCount)
	}
	if len(st3.Entries) != 5 {
		t.Fatalf("state 3 entries len = %d, want capacity 5", len(st3.Entries))
	}
	expectedSeqs := []uint64{4, 5, 6, 7, 8}
	for i, expected := range expectedSeqs {
		if st3.Entries[i].Seq != expected {
			t.Fatalf("entry %d seq = %d, want %d", i, st3.Entries[i].Seq, expected)
		}
	}
	if st3.LastSeq != 8 {
		t.Fatalf("state 3 lastSeq = %d, want 8", st3.LastSeq)
	}
}

func TestModelLogValidation(t *testing.T) {
	store := newModelLogStore(t.TempDir(), 2000)
	handler := modelLogHandler(store)

	send := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/taa/modelLog", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	cases := []struct {
		name string
		body string
	}{
		{
			name: "missing dockerId",
			body: `{"requestId":"req-1","entries":[{"seq":1,"message":"hello"}]}`,
		},
		{
			name: "missing requestId",
			body: `{"dockerId":"docker-1","entries":[{"seq":1,"message":"hello"}]}`,
		},
		{
			name: "entries is empty",
			body: `{"dockerId":"docker-1","requestId":"req-1","entries":[]}`,
		},
		{
			name: "entry message is empty",
			body: `{"dockerId":"docker-1","requestId":"req-1","entries":[{"seq":1,"message":""}]}`,
		},
		{
			name: "entry message is whitespace",
			body: `{"dockerId":"docker-1","requestId":"req-1","entries":[{"seq":1,"message":"   "}]}`,
		},
	}

	for _, tc := range cases {
		w := send(tc.body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("case %s status = %d, want 400; body=%s", tc.name, w.Code, w.Body.String())
		}
	}
}

func TestModelLogStatusAndReset(t *testing.T) {
	store := newModelLogStore(t.TempDir(), 2000)
	logHandler := modelLogHandler(store)
	statusHandler := modelLogStatusHandler(store)
	resetHandler := modelLogResetHandler(store)

	// 发送一条日志
	reqLog := httptest.NewRequest(http.MethodPost, "/v1/taa/modelLog", strings.NewReader(`{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"taskId": "task-1",
		"seqStart": 1,
		"entries": [
			{"seq": 1, "message": "starting training", "timestamp": "2026-09-16T10:00:00Z"}
		]
	}`))
	reqLog.Header.Set("Content-Type", "application/json")
	wLog := httptest.NewRecorder()
	logHandler(wLog, reqLog)
	if wLog.Code != http.StatusOK {
		t.Fatalf("log status = %d, want 200; body=%s", wLog.Code, wLog.Body.String())
	}

	// 验证 /api/modelLog/status
	wStatus := httptest.NewRecorder()
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/modelLog/status", nil)
	statusHandler(wStatus, reqStatus)
	if wStatus.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", wStatus.Code)
	}

	var resp struct {
		Msg    string        `json:"msg"`
		Result modelLogState `json:"result"`
	}
	if err := json.NewDecoder(wStatus.Body).Decode(&resp); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if resp.Result.DockerID != "docker-1" || resp.Result.RequestID != "req-1" || resp.Result.TotalCount != 1 {
		t.Fatalf("status result mismatch: %+v", resp.Result)
	}
	if len(resp.Result.Entries) != 1 || resp.Result.Entries[0].Message != "starting training" {
		t.Fatalf("status entries mismatch: %+v", resp.Result.Entries)
	}

	// 验证 /api/modelLog/reset
	wReset := httptest.NewRecorder()
	reqReset := httptest.NewRequest(http.MethodPost, "/api/modelLog/reset", nil)
	resetHandler(wReset, reqReset)
	if wReset.Code != http.StatusOK {
		t.Fatalf("reset code = %d, want 200", wReset.Code)
	}

	stAfterReset := store.get()
	if stAfterReset.TotalCount != 0 || len(stAfterReset.Entries) != 0 || stAfterReset.DockerID != "" {
		t.Fatalf("store after reset = %+v, want empty", stAfterReset)
	}
}

