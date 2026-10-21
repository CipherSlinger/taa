package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"taa/internal/config"
)

// setupDataAnalysisServer builds the normal test state and switches it to the
// data-anaylsis instance type. The switch happens before the HTTP server starts,
// so no request can observe a half-configured state.
func setupDataAnalysisServer(t *testing.T) (*TAAState, *httptest.Server, string) {
	t.Helper()
	state, _ := setupTestState(t)
	root := filepath.Join(t.TempDir(), "systemAuthData")
	state.Security.ServerType = config.ServerTypeDataAnalysis
	state.Security.DataAnalysisDir = root

	mux := http.NewServeMux()
	RegisterRoutes(mux, state)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return state, server, root
}

type dataAnalysisReport struct {
	Code   int     `json:"code"`
	Msg    *string `json:"msg"`
	Report string  `json:"report"`
}

func captureDataAnalysisReports(t *testing.T, state *TAAState) <-chan dataAnalysisReport {
	t.Helper()
	ch := make(chan dataAnalysisReport, 4)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/taa/reportRes" {
			var payload dataAnalysisReport
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode reportRes payload: %v", err)
			} else {
				ch <- payload
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(platform.Close)

	state.mu.Lock()
	state.PlatformIP = platform.URL
	state.mu.Unlock()
	return ch
}

func waitDataAnalysisReport(t *testing.T, ch <-chan dataAnalysisReport) dataAnalysisReport {
	t.Helper()
	select {
	case payload := <-ch:
		return payload
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reportRes")
		return dataAnalysisReport{}
	}
}

// deliveryURL builds the data-anaylsis delivery shape: the envelope and the two
// path parameters appended with '?', plus one unrelated parameter that must
// survive the strip.
func deliveryURL(base, keyHex, fileName, code string) string {
	return base + "/data.sm4?sign=a%2Fb&dataKeyCipher=" + keyHex +
		"?fileName=" + url.QueryEscape(fileName) +
		"?dataResourceCode=" + url.QueryEscape(code)
}

func TestDataAnalysisImportExtractsArchive(t *testing.T) {
	state, server, root := setupDataAnalysisServer(t)
	reports := captureDataAnalysisReports(t, state)

	archive := buildZipArchive(t, map[string]archiveEntry{
		"a.txt":     {mode: 0o644, data: []byte("hello")},
		"sub/b.txt": {mode: 0o644, data: []byte("world")},
	})
	ciphertext, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, archive)

	var hits int32
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		q := r.URL.Query()
		for _, name := range []string{"dataKeyCipher", "fileName", "dataResourceCode"} {
			if got := q.Get(name); got != "" {
				t.Errorf("download URL carries %s=%q, want it stripped", name, got)
			}
		}
		if got := q.Get("sign"); got != "a/b" {
			t.Errorf("sign = %q, want a/b (unrelated parameters must survive)", got)
		}
		_, _ = w.Write(ciphertext)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": deliveryURL(fileServer.URL, keyHex, "数据 包.zip", "RES-001"),
		"requestId":   "req-da-zip",
		"taskId":      "task-da-zip",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	payload := waitDataAnalysisReport(t, reports)
	if payload.Code != 0 {
		t.Fatalf("reportRes code = %d, want 0 (msg=%v)", payload.Code, payload.Msg)
	}
	if payload.Report != "" {
		t.Fatalf("reportRes report = %q, want empty", payload.Report)
	}
	waitForIdle(t, state)

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("download hits = %d, want 1", got)
	}
	for name, want := range map[string]string{"a.txt": "hello", "sub/b.txt": "world"} {
		got, err := os.ReadFile(filepath.Join(root, "RES-001", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	// This instance type must not enter the training pipeline.
	state.mu.RLock()
	trainingRunning := state.TrainingRunning
	modelImported := state.ModelImported
	state.mu.RUnlock()
	if trainingRunning || modelImported {
		t.Fatalf("TrainingRunning=%v ModelImported=%v, want both false", trainingRunning, modelImported)
	}
	if _, err := os.Stat(filepath.Join(state.Security.ResultDir, "train", "training_report.json")); !os.IsNotExist(err) {
		t.Fatalf("training_report.json exists (err=%v), want no training artefacts", err)
	}
}

func TestDataAnalysisImportSavesSingleFile(t *testing.T) {
	state, server, root := setupDataAnalysisServer(t)
	reports := captureDataAnalysisReports(t, state)

	const wantName = "季度 报告+1.csv"
	content := []byte("name,value\nalpha,1\n")
	ciphertext, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, content)

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ciphertext)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": deliveryURL(fileServer.URL, keyHex, wantName, "RES-002"),
		"requestId":   "req-da-file",
		"taskId":      "task-da-file",
	})
	if api := decodeResponse(t, resp); resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}
	if payload := waitDataAnalysisReport(t, reports); payload.Code != 0 {
		t.Fatalf("reportRes code = %d, want 0 (msg=%v)", payload.Code, payload.Msg)
	}
	waitForIdle(t, state)

	got, err := os.ReadFile(filepath.Join(root, "RES-002", wantName))
	if err != nil {
		t.Fatalf("read landed file: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content = %q, want %q", got, content)
	}
}

// A .docx is a ZIP container but a document, not an archive to unpack: it must
// land as one file, not as its internal word/ tree.
func TestDataAnalysisImportKeepsDocumentContainerWhole(t *testing.T) {
	state, server, root := setupDataAnalysisServer(t)
	reports := captureDataAnalysisReports(t, state)

	docx := buildZipArchive(t, map[string]archiveEntry{
		"word/document.xml":   {mode: 0o644, data: []byte("<w:document/>")},
		"[Content_Types].xml": {mode: 0o644, data: []byte("<Types/>")},
	})
	ciphertext, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, docx)

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ciphertext)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": deliveryURL(fileServer.URL, keyHex, "分析报告.docx", "RES-003"),
		"requestId":   "req-da-docx",
		"taskId":      "task-da-docx",
	})
	if api := decodeResponse(t, resp); resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}
	if payload := waitDataAnalysisReport(t, reports); payload.Code != 0 {
		t.Fatalf("reportRes code = %d, want 0 (msg=%v)", payload.Code, payload.Msg)
	}
	waitForIdle(t, state)

	target := filepath.Join(root, "RES-003", "分析报告.docx")
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("docx was not saved as a single file: %v", err)
	}
	if string(got) != string(docx) {
		t.Fatalf("docx content changed on the way to disk")
	}
	if _, err := os.Stat(filepath.Join(root, "RES-003", "word")); !os.IsNotExist(err) {
		t.Fatalf("docx was unpacked (word/ exists), want it saved verbatim")
	}
}

func TestDataAnalysisImportReplacesPreviousContents(t *testing.T) {
	state, server, root := setupDataAnalysisServer(t)
	reports := captureDataAnalysisReports(t, state)

	stale := filepath.Join(root, "RES-004")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatalf("mkdir stale: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stale, "old.txt"), []byte("old"), 0o644); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	archive := buildZipArchive(t, map[string]archiveEntry{
		"new.txt": {mode: 0o644, data: []byte("new")},
	})
	ciphertext, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, archive)
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ciphertext)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": deliveryURL(fileServer.URL, keyHex, "replacement.zip", "RES-004"),
		"requestId":   "req-da-replace",
		"taskId":      "task-da-replace",
	})
	if api := decodeResponse(t, resp); resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}
	if payload := waitDataAnalysisReport(t, reports); payload.Code != 0 {
		t.Fatalf("reportRes code = %d, want 0 (msg=%v)", payload.Code, payload.Msg)
	}
	waitForIdle(t, state)

	if _, err := os.Stat(filepath.Join(stale, "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("old.txt survived (err=%v), want the directory replaced", err)
	}
	if _, err := os.Stat(filepath.Join(stale, "new.txt")); err != nil {
		t.Fatalf("new.txt missing: %v", err)
	}
}

func TestDataAnalysisImportRejectsBadDeliveryBeforeDownload(t *testing.T) {
	state, server, _ := setupDataAnalysisServer(t)

	_, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, []byte("payload"))

	var hits int32
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("should not be downloaded"))
	}))
	defer fileServer.Close()

	cases := []struct {
		name string
		url  string
	}{
		{"missing envelope", fileServer.URL + "/d?fileName=a.zip?dataResourceCode=c"},
		{"missing fileName", fileServer.URL + "/d?dataKeyCipher=" + keyHex + "?dataResourceCode=c"},
		{"missing dataResourceCode", fileServer.URL + "/d?dataKeyCipher=" + keyHex + "?fileName=a.zip"},
		{"no download address", "?dataKeyCipher=" + keyHex + "?fileName=a.zip?dataResourceCode=c"},
		{"duplicate fileName", fileServer.URL + "/d?dataKeyCipher=" + keyHex + "?fileName=a.zip?fileName=b.zip?dataResourceCode=c"},
		{"code traversal", deliveryURL(fileServer.URL, keyHex, "a.zip", "../evil")},
		{"code absolute", deliveryURL(fileServer.URL, keyHex, "a.zip", "/etc/passwd")},
		{"code backslash", deliveryURL(fileServer.URL, keyHex, "a.zip", `a\b`)},
		{"code NUL", deliveryURL(fileServer.URL, keyHex, "a.zip", "a\x00b")},
		{"fileName traversal", deliveryURL(fileServer.URL, keyHex, "../evil.txt", "RES-005")},
		{"fileName slash", deliveryURL(fileServer.URL, keyHex, "sub/file.txt", "RES-005")},
		{"fileName dotdot", deliveryURL(fileServer.URL, keyHex, "..", "RES-005")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
				"resourceUrl": tc.url,
				"requestId":   "req-da-bad",
				"taskId":      "task-da-bad",
			})
			if api := decodeResponse(t, resp); resp.StatusCode != http.StatusBadRequest || api.Error != http.StatusBadRequest {
				t.Fatalf("status=%d error=%d msg=%s, want 400/400", resp.StatusCode, api.Error, api.Msg)
			}
		})
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("download hits = %d, want 0: a rejected request must not download", got)
	}
}

func TestDataAnalysisImportDecryptFailureReportsEmptyBody(t *testing.T) {
	state, server, root := setupDataAnalysisServer(t)
	reports := captureDataAnalysisReports(t, state)

	_, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, []byte("data"))
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tampered-ciphertext-bytes-not-valid-gcm"))
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": deliveryURL(fileServer.URL, keyHex, "bad.zip", "RES-006"),
		"requestId":   "req-da-badkey",
		"taskId":      "task-da-badkey",
	})
	if api := decodeResponse(t, resp); resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	payload := waitDataAnalysisReport(t, reports)
	if payload.Code != 1 {
		t.Fatalf("reportRes code = %d, want 1", payload.Code)
	}
	if payload.Report != "" {
		t.Fatalf("reportRes report = %q, want empty", payload.Report)
	}
	if payload.Msg == nil || !strings.Contains(*payload.Msg, "解密资源失败") {
		t.Fatalf("reportRes msg = %v, want a decrypt failure", payload.Msg)
	}
	waitForIdle(t, state)
	if _, err := os.Stat(filepath.Join(root, "RES-006")); !os.IsNotExist(err) {
		t.Fatalf("target directory exists (err=%v), want nothing landed", err)
	}
}

func TestDataAnalysisModelImportRejected(t *testing.T) {
	_, server, _ := setupDataAnalysisServer(t)

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"requestId": "req-da-model",
		"taskId":    "task-da-model",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusBadRequest || api.Error != http.StatusBadRequest {
		t.Fatalf("status=%d error=%d, want 400/400", resp.StatusCode, api.Error)
	}
	if !strings.Contains(api.Msg, "不支持模型导入") {
		t.Fatalf("msg = %q, want it to name the unsupported model import", api.Msg)
	}
}

// The default fixture is a tee instance; the new branch must stay off it.
func TestDataAnalysisDisabledOnTee(t *testing.T) {
	state, _ := setupTestState(t)
	if state.dataAnalysisEnabled() {
		t.Fatal("dataAnalysisEnabled() = true on a default tee fixture")
	}
}
