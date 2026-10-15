package controller

import (
	"encoding/hex"
	"encoding/json"
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

// Model delivery accepts the same two shapes as data delivery: the SM2 key envelope
// either rides in the URL (?dataKeyCipher=<hex C1C3C2>) while the file is bare
// ciphertext, or stays in the file as the legacy whole-file envelope. These tests
// pin both for /v1/taa/importModel, plus the failure reporting that only the model
// endpoint has.

func TestModelImportDecryptsWithDataKeyCipherFromURL(t *testing.T) {
	state, server := setupTestServer(t)

	archive := buildTarGzArchive(t, map[string]archiveEntry{
		"bundle/train.py": {mode: 0o755, data: []byte("print('model')\n")},
	})
	ciphertext, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, archive)

	modelImportCh := make(chan importedReportPayload, 1)
	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == reportModelImportEndpoint {
			var payload importedReportPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode reportModelImport payload: %v", err)
			} else {
				modelImportCh <- payload
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platformServer.Close()
	state.mu.Lock()
	state.PlatformIP = platformServer.URL
	state.mu.Unlock()

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

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl": fileServer.URL + "/model-package.tar.gz?sign=a%2Fb&dataKeyCipher=" + keyHex,
		"requestId":   "req-model-urlkey-ok",
		"taskId":      "task-model-urlkey-ok",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("importModel: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	waitForIdle(t, state)

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("download hits = %d, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(state.Security.ModelDir, "bundle", "train.py")); err != nil {
		t.Fatalf("decrypted model archive was not extracted into %s: %v", state.Security.ModelDir, err)
	}

	// The saved URL is the model's delivery record; the wrapped key must not be kept
	// a second time inside the sealed state.
	if saved := state.getSavedModelResourceURL(); saved != fileServer.URL+"/model-package.tar.gz?sign=a%2Fb" {
		t.Fatalf("saved model URL = %q, want the URL without the key envelope", saved)
	}

	select {
	case payload := <-modelImportCh:
		if payload.Code != 0 {
			t.Fatalf("reportModelImport code = %d msg=%v, want 0", payload.Code, payload.Msg)
		}
		sum := teecrypto.SM3Sum(archive)
		if payload.Checksum == nil || payload.Checksum["value"] != hex.EncodeToString(sum[:]) {
			t.Fatalf("reportModelImport checksum = %v, want the SM3 of the decrypted model archive", payload.Checksum)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reportModelImport")
	}
}

func TestModelImportRejectsBadDataKeyCipherBeforeDownloading(t *testing.T) {
	state, server := setupTestServer(t)

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
			id := "model-urlkey-reject-" + string(rune('a'+i))
			resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
				"resourceUrl": fileServer.URL + "/model-package.tar.gz" + tc.query,
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
			// The rejected request must leave nothing behind: the model is not
			// recorded as imported and no delivery URL is remembered.
			state.mu.RLock()
			imported, savedURL := state.ModelImported, state.SavedModelResourceURL
			state.mu.RUnlock()
			if imported || savedURL != "" {
				t.Fatalf("rejected importModel changed state: ModelImported=%v savedModelResourceURL=%q", imported, savedURL)
			}
		})
	}
}

// A resourceUrl made of nothing but the enveloped key strips down to "". The model
// endpoint treats an empty resourceUrl as "runtimeConfig only, no delivery", so
// without an explicit check a request that did deliver a key would be answered 200
// and the key silently dropped.
func TestModelImportRejectsKeyEnvelopeWithoutDownloadAddress(t *testing.T) {
	state, server := setupTestServer(t)

	// A previously imported model is what makes the runtimeConfig-only branch reachable.
	state.mu.Lock()
	state.SavedModelResourceURL = "http://platform.example/files/previous-model.tar.gz"
	state.mu.Unlock()

	_, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, []byte("model"))

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   "?dataKeyCipher=" + keyHex,
		"requestId":     "req-model-urlkey-no-address",
		"taskId":        "task-model-urlkey-no-address",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"echo hi"}, nil),
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
		t.Fatalf("status=%d error=%d msg=%s, want 400", resp.StatusCode, api.Error, api.Msg)
	}
	if !strings.Contains(api.Msg, "缺少下载地址") {
		t.Fatalf("msg = %q, want it to name the missing download address", api.Msg)
	}

	state.mu.RLock()
	imported := state.ModelImported
	state.mu.RUnlock()
	if imported {
		t.Fatal("a URL carrying a key but no download address must not mark the model imported")
	}
}

// The platform's own SM4 files carry a one-byte format version in front of the nonce
// ([version][nonce][ciphertext][tag]); TAA writes the bare layout. The GCM tag decides
// which one a file is, so a versioned body has to reach the same plaintext as a bare one
// instead of failing authentication on a nonce read one byte too early.
func TestModelImportAcceptsVersionedSm4File(t *testing.T) {
	state, server := setupTestServer(t)

	archive := buildTarGzArchive(t, map[string]archiveEntry{
		"bundle/versioned.py": {mode: 0o644, data: []byte("print('versioned model')\n")},
	})
	bare, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, archive)
	versioned := append([]byte{sm4FileVersion}, bare...)

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(versioned)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl": fileServer.URL + "/model-package.enc?dataKeyCipher=" + keyHex,
		"requestId":   "req-model-urlkey-versioned",
		"taskId":      "task-model-urlkey-versioned",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("importModel: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	waitForIdle(t, state)

	if _, err := os.Stat(filepath.Join(state.Security.ModelDir, "bundle", "versioned.py")); err != nil {
		t.Fatalf("versioned SM4 file was not decrypted and extracted into %s: %v", state.Security.ModelDir, err)
	}
}

func TestModelImportFallsBackToLegacyFormatWithoutDataKeyCipher(t *testing.T) {
	state, server := setupTestServer(t)

	archive := buildTarGzArchive(t, map[string]archiveEntry{
		"bundle/legacy.py": {mode: 0o644, data: []byte("print('legacy model')\n")},
	})
	sealed := sealForTAA(t, state.SM2PrivateKey, archive)

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(sealed)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl": fileServer.URL + "/model-package.tar.gz.enc",
		"requestId":   "req-model-legacy-format",
		"taskId":      "task-model-legacy-format",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("importModel: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	waitForIdle(t, state)

	if _, err := os.Stat(filepath.Join(state.Security.ModelDir, "bundle", "legacy.py")); err != nil {
		t.Fatalf("legacy whole-file envelope was not extracted into %s: %v", state.Security.ModelDir, err)
	}
}

// A valid envelope paired with a body it cannot open is not a request error: the
// download has already happened and the model is imported asynchronously, so the
// failure has to reach the platform through reportModelImport (the model endpoint's
// report channel) with TAA's public key, exactly as the data path reports through
// reportRes.
func TestModelImportURLKeyDecryptFailureReportsPublicKey(t *testing.T) {
	state, server := setupTestServer(t)

	modelImportCh := make(chan importedReportPayload, 1)
	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == reportModelImportEndpoint {
			var payload importedReportPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode reportModelImport payload: %v", err)
			} else {
				modelImportCh <- payload
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platformServer.Close()
	state.mu.Lock()
	state.PlatformIP = platformServer.URL
	state.mu.Unlock()

	_, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, []byte("model"))

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tampered-ciphertext-bytes-not-valid-gcm"))
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl": fileServer.URL + "/model-package.tar.gz?dataKeyCipher=" + keyHex,
		"requestId":   "req-model-urlkey-gcm-fail",
		"taskId":      "task-model-urlkey-gcm-fail",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("importModel: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	select {
	case payload := <-modelImportCh:
		if payload.Code != 1 {
			t.Fatalf("reportModelImport code = %d, want 1", payload.Code)
		}
		if payload.Msg == nil || !strings.Contains(*payload.Msg, "解密资源失败") {
			t.Fatalf("reportModelImport msg = %v, want decrypt failure", payload.Msg)
		}
		if !strings.Contains(*payload.Msg, "taaPublicKey:") || !strings.Contains(*payload.Msg, "-----BEGIN PUBLIC KEY-----") {
			t.Fatalf("reportModelImport msg missing taaPublicKey, got: %v", *payload.Msg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the urlkey model decrypt failure report")
	}
}
