package controller

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	teecrypto "taa/pkg/crypto"
)

// urlKeyResource seals a plaintext archive into the new shape: the envelope goes
// into the URL, the ciphertext is downloaded on its own.
func urlKeyResource(t *testing.T, pub *teecrypto.SM2PublicKey, plaintext []byte) (ciphertext []byte, hexValue string) {
	t.Helper()
	env, err := teecrypto.SealSM2(pub, plaintext)
	if err != nil {
		t.Fatalf("SealSM2: %v", err)
	}
	return env.Ciphertext, hex.EncodeToString(env.WrappedKey[1:])
}

func TestImportDecryptsWithDataKeyCipherFromURL(t *testing.T) {
	state, server := setupTestServer(t)

	archive := buildTarGzArchive(t, map[string]archiveEntry{
		"data/sample.txt": {mode: 0o644, data: []byte("training data\n")},
	})
	ciphertext, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, archive)

	var hits int32
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if got := r.URL.Query().Get("dataKeyCipher"); got != "" {
			t.Errorf("download URL must not carry dataKeyCipher, got %q", got)
		}
		if got := r.URL.Query().Get("sign"); got != "a/b" {
			t.Errorf("sign = %q, want %q (other parameters must survive)", got, "a/b")
		}
		_, _ = w.Write(ciphertext)
	}))
	defer fileServer.Close()

	resourceURL := fileServer.URL + "/data.sm4?sign=a%2Fb&dataKeyCipher=" + keyHex

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceURL,
		"requestId":   "req-urlkey-ok",
		"taskId":      "task-urlkey-ok",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	waitForIdle(t, state)

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("download hits = %d, want 1", got)
	}

	sum := teecrypto.SM3Sum(archive)
	dataDir := filepath.Join(state.Security.DataDir, hex.EncodeToString(sum[:]))
	if _, err := os.Stat(filepath.Join(dataDir, "data", "sample.txt")); err != nil {
		t.Fatalf("decrypted archive was not extracted into %s: %v", dataDir, err)
	}
}

func TestImportRejectsBadDataKeyCipherBeforeDownloading(t *testing.T) {
	_, server := setupTestServer(t)

	var hits int32
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("ciphertext"))
	}))
	defer fileServer.Close()

	cases := []struct {
		name      string
		query     string
		wantInMsg string
	}{
		{"duplicate parameter", "?dataKeyCipher=aa&dataKeyCipher=bb", "重复出现"},
		{"empty value", "?dataKeyCipher=", "值为空"},
		{"invalid hex", "?dataKeyCipher=zz", "hex"},
		{"wrong length", "?dataKeyCipher=0011", "数据密钥信封长度无效"},
		{"envelope for another key", "?dataKeyCipher=" + otherKeyEnvelopeHex(t), "解封失败"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			atomic.StoreInt32(&hits, 0)
			id := fmt.Sprintf("urlkey-reject-%d", i)
			resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
				"resourceUrl": fileServer.URL + "/data.sm4" + tc.query,
				"requestId":   "req-" + id,
				"taskId":      "task-" + id,
			})
			api := decodeResponse(t, resp)
			if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
				t.Fatalf("status=%d error=%d msg=%s, want 400", resp.StatusCode, api.Error, api.Msg)
			}
			if !strings.Contains(api.Msg, tc.wantInMsg) {
				t.Fatalf("msg = %q, want it to contain %q", api.Msg, tc.wantInMsg)
			}
			if got := atomic.LoadInt32(&hits); got != 0 {
				t.Fatalf("download hits = %d, want 0: a bad envelope must fail before downloading", got)
			}
		})
	}
}

// otherKeyEnvelopeHex builds an envelope wrapped for a different SM2 public key,
// so that unwrapping against TAA's key fails.
func otherKeyEnvelopeHex(t *testing.T) string {
	t.Helper()
	other, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	env, err := teecrypto.SealSM2(&other.PublicKey, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("SealSM2: %v", err)
	}
	return hex.EncodeToString(env.WrappedKey[1:])
}

func TestImportFallsBackToLegacyFormatWithoutDataKeyCipher(t *testing.T) {
	state, server := setupTestServer(t)

	archive := buildTarGzArchive(t, map[string]archiveEntry{
		"data/legacy.txt": {mode: 0o644, data: []byte("legacy\n")},
	})
	sealed := sealForTAA(t, state.SM2PrivateKey, archive)

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(sealed)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": fileServer.URL + "/data.tar.gz.enc",
		"requestId":   "req-legacy-format",
		"taskId":      "task-legacy-format",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	waitForIdle(t, state)

	sum := teecrypto.SM3Sum(archive)
	dataDir := filepath.Join(state.Security.DataDir, hex.EncodeToString(sum[:]))
	if _, err := os.Stat(filepath.Join(dataDir, "data", "legacy.txt")); err != nil {
		t.Fatalf("legacy whole-file envelope was not extracted into %s: %v", dataDir, err)
	}
}

func TestImportURLKeyDecryptFailureReportsPublicKey(t *testing.T) {
	state, server := setupTestServer(t)

	type reportPayload struct {
		Code int     `json:"code"`
		Msg  *string `json:"msg"`
	}
	reportResCh := make(chan reportPayload, 1)
	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/taa/reportRes" {
			var payload reportPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode report payload: %v", err)
			} else {
				reportResCh <- payload
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platformServer.Close()

	state.mu.Lock()
	state.PlatformIP = platformServer.URL
	state.mu.Unlock()

	// The envelope itself is valid but does not pair with the response body: the
	// envelope layer passes, GCM authentication fails, and the failure lands in the
	// asynchronous report.
	_, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, []byte("data"))

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tampered-ciphertext-bytes-not-valid-gcm"))
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": fileServer.URL + "/data.sm4?dataKeyCipher=" + keyHex,
		"requestId":   "req-urlkey-gcm-fail",
		"taskId":      "task-urlkey-gcm-fail",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	select {
	case payload := <-reportResCh:
		if payload.Code != 1 {
			t.Fatalf("reportRes code = %d, want 1", payload.Code)
		}
		if payload.Msg == nil || !strings.Contains(*payload.Msg, "解密资源失败") {
			t.Fatalf("reportRes msg = %v, want decrypt failure", payload.Msg)
		}
		if !strings.Contains(*payload.Msg, "taaPublicKey:") || !strings.Contains(*payload.Msg, "-----BEGIN PUBLIC KEY-----") {
			t.Fatalf("reportRes msg missing taaPublicKey, got: %v", *payload.Msg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the urlkey decrypt failure report")
	}
}
