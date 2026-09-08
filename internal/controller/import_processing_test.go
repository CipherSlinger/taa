package controller

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func createTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write zip content: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func createTestTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Size: int64(len(content)),
			Mode: 0o644,
		}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write tar content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func TestIsArchiveFile(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Gzip
	gzipData := createTestTarGz(t, map[string]string{"test.txt": "hello gzip"})
	gzipPath := filepath.Join(tmpDir, "sample.tar.gz")
	if err := os.WriteFile(gzipPath, gzipData, 0o644); err != nil {
		t.Fatalf("write gzip: %v", err)
	}
	isArchive, err := isArchiveFile(gzipPath)
	if err != nil || !isArchive {
		t.Errorf("isArchiveFile(gzip) = (%v, %v), want (true, nil)", isArchive, err)
	}

	// 2. Zip
	zipData := createTestZip(t, map[string]string{"test.txt": "hello zip"})
	zipPath := filepath.Join(tmpDir, "sample.zip")
	if err := os.WriteFile(zipPath, zipData, 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	isArchive, err = isArchiveFile(zipPath)
	if err != nil || !isArchive {
		t.Errorf("isArchiveFile(zip) = (%v, %v), want (true, nil)", isArchive, err)
	}

	// 3. Tar
	tarData := createTestTar(t, map[string]string{"test.txt": "hello tar"})
	tarPath := filepath.Join(tmpDir, "sample.tar")
	if err := os.WriteFile(tarPath, tarData, 0o644); err != nil {
		t.Fatalf("write tar: %v", err)
	}
	isArchive, err = isArchiveFile(tarPath)
	if err != nil || !isArchive {
		t.Errorf("isArchiveFile(tar) = (%v, %v), want (true, nil)", isArchive, err)
	}

	// 4. Plain text (not archive)
	txtPath := filepath.Join(tmpDir, "sample.txt")
	if err := os.WriteFile(txtPath, []byte("plain text content"), 0o644); err != nil {
		t.Fatalf("write txt: %v", err)
	}
	isArchive, err = isArchiveFile(txtPath)
	if err != nil || isArchive {
		t.Errorf("isArchiveFile(txt) = (%v, %v), want (false, nil)", isArchive, err)
	}

	// 5. Sealed ciphertext (not archive)
	state, _ := setupTestServer(t)
	sealedData := sealForTAA(t, state.SM2PrivateKey, gzipData)
	encPath := filepath.Join(tmpDir, "sample.enc")
	if err := os.WriteFile(encPath, sealedData, 0o644); err != nil {
		t.Fatalf("write enc: %v", err)
	}
	isArchive, err = isArchiveFile(encPath)
	if err != nil || isArchive {
		t.Errorf("isArchiveFile(ciphertext) = (%v, %v), want (false, nil)", isArchive, err)
	}
}

func TestResolvePlaintextResource(t *testing.T) {
	state, _ := setupTestServer(t)
	tmpDir := t.TempDir()

	plainTarGz := createTestTarGz(t, map[string]string{"data.csv": "1,2,3"})
	sealedData := sealForTAA(t, state.SM2PrivateKey, plainTarGz)

	// Case 1: URL 以 .enc 结尾，密文正常 -> 直接解密成功，isDecrypted=true
	encFilePath := filepath.Join(tmpDir, "case1.enc")
	if err := os.WriteFile(encFilePath, sealedData, 0o644); err != nil {
		t.Fatalf("write case1: %v", err)
	}
	plain1, isDecrypted1, err := state.resolvePlaintextResource("http://example.com/data.tar.gz.enc", encFilePath, "test")
	if err != nil {
		t.Fatalf("case 1 error: %v", err)
	}
	if !isDecrypted1 {
		t.Errorf("case 1 isDecrypted = false, want true")
	}
	defer os.Remove(plain1)
	if content, _ := os.ReadFile(plain1); !bytes.Equal(content, plainTarGz) {
		t.Errorf("case 1 decrypted content mismatch")
	}

	// Case 2: URL 以 .enc 结尾，损坏文件 -> 解密失败，返回包含“解密资源失败”的错误
	brokenFilePath := filepath.Join(tmpDir, "broken.enc")
	if err := os.WriteFile(brokenFilePath, []byte("broken sealed data"), 0o644); err != nil {
		t.Fatalf("write broken: %v", err)
	}
	_, _, err = state.resolvePlaintextResource("http://example.com/broken.enc", brokenFilePath, "test")
	if err == nil || !strings.Contains(err.Error(), "解密资源失败") {
		t.Errorf("case 2 want '解密资源失败', got: %v", err)
	}

	// Case 3: URL 非 .enc 后缀，文件为有效明文压缩包 -> 跳过解密，直接返回原路径，isDecrypted=false
	plainFilePath := filepath.Join(tmpDir, "data.tar.gz")
	if err := os.WriteFile(plainFilePath, plainTarGz, 0o644); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	plain3, isDecrypted3, err := state.resolvePlaintextResource("http://example.com/data.tar.gz", plainFilePath, "test")
	if err != nil {
		t.Fatalf("case 3 error: %v", err)
	}
	if isDecrypted3 {
		t.Errorf("case 3 isDecrypted = true, want false")
	}
	if plain3 != plainFilePath {
		t.Errorf("case 3 plainPath = %s, want %s", plain3, plainFilePath)
	}

	// Case 4: URL 非 .enc 后缀，文件为有效密文（如用户上传了密文但 URL 是 data.tar.gz 或 data.bin）
	// -> 检测非压缩包后尝试解密并成功解密，isDecrypted=true
	sealedNoEncPath := filepath.Join(tmpDir, "sealed_without_enc.bin")
	if err := os.WriteFile(sealedNoEncPath, sealedData, 0o644); err != nil {
		t.Fatalf("write sealedNoEnc: %v", err)
	}
	plain4, isDecrypted4, err := state.resolvePlaintextResource("http://example.com/data.tar.gz", sealedNoEncPath, "test")
	if err != nil {
		t.Fatalf("case 4 error: %v", err)
	}
	if !isDecrypted4 {
		t.Errorf("case 4 isDecrypted = false, want true")
	}
	defer os.Remove(plain4)
	if content, _ := os.ReadFile(plain4); !bytes.Equal(content, plainTarGz) {
		t.Errorf("case 4 decrypted content mismatch")
	}

	// Case 5: URL 非 .enc 后缀，文件既非压缩包也不是有效密文 -> 报错拦截
	invalidPath := filepath.Join(tmpDir, "plain.txt")
	if err := os.WriteFile(invalidPath, []byte("some invalid plain text"), 0o644); err != nil {
		t.Fatalf("write invalid: %v", err)
	}
	_, _, err = state.resolvePlaintextResource("http://example.com/plain.txt", invalidPath, "test")
	if err == nil || !strings.Contains(err.Error(), "资源非 .enc 后缀且非有效压缩包，尝试解密失败") {
		t.Errorf("case 5 want '资源非 .enc 后缀且非有效压缩包，尝试解密失败', got: %v", err)
	}
}

func TestResourceInfoHandlerDecryptsWithoutEncSuffix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python3 scripts are not supported on windows")
	}

	state, server := setupTestServer(t)

	archiveData := createTestTarGz(t, map[string]string{
		"dataset/users.csv": "user_id,name\n1,Alice\n2,Bob\n",
	})

	state.mu.RLock()
	priv := state.SM2PrivateKey
	state.mu.RUnlock()
	sealed := sealForTAA(t, priv, archiveData)

	// 提供密文，但 URL 没有 .enc 后缀
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(sealed)
	}))
	defer fileServer.Close()

	body := map[string]string{"resourceUrl": fileServer.URL + "/dataset.tar.gz"}
	resp := postJSON(t, server.URL+"/v1/taa/getResourceInfo", body)
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; msg=%s", resp.StatusCode, http.StatusOK, api.Msg)
	}
	if api.Error != 0 {
		t.Fatalf("error = %d, want 0; msg=%s", api.Error, api.Msg)
	}

	result, ok := api.Result.(string)
	if !ok {
		t.Fatalf("result type = %T, want string", api.Result)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(result), &report); err != nil {
		t.Fatalf("unmarshal result JSON: %v", err)
	}
	if report["tree"] == nil {
		t.Fatalf("result missing tree: %#v", report)
	}
}
