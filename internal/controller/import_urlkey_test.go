package controller

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

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
