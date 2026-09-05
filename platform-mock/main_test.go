package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIndexShowsTrainingReportAndResourceInfoModules(t *testing.T) {
	if strings.Contains(indexHTML, "③ 资源下载结果上报") {
		t.Fatal("index should not show the resource download result report card")
	}
	for _, want := range []string{"③ 训练结果上报", "registerBodyBtn", "card-attestation", "attestRequestId", "attestationResult", "saveReportBtn", "reportResBodyBtn", "reportModelImportBodyBtn", "bodyModal", "importModelPublicKey", "resourceInfoResult", "testGetResourceInfo", "/v1/taa/getResourceInfo", "/v1/taa/reportModelImport"} {
		if !strings.Contains(indexHTML, want) {
			t.Fatalf("index missing %q", want)
		}
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

func TestDiscoverTAAAddrUsesGlobalTAAPort(t *testing.T) {
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

	got := discoverTAAAddr("simple-busybox", "")
	want := "http://10.244.0.49:6001"
	if got != want {
		t.Fatalf("discoverTAAAddr() = %q, want %q", got, want)
	}
}
