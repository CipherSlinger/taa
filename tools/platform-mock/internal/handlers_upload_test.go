package mock

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"taa/pkg/crypto"
)

// TestUploadListKeepsTheDataKeyEnvelope covers the regression behind an import
// that failed with "资源非 .enc 后缀且非有效压缩包，尝试解密失败": the upload
// response carried ?dataKeyCipher=..., but the console re-reads the file list
// from /api/uploads, which rebuilt every URL from the filename alone. The
// envelope exists only at upload time, so the listed URL was bare ciphertext
// with no way to unwrap it, and TAA fell back to treating the .sm4 body as a
// whole-file envelope.
func TestUploadListKeepsTheDataKeyEnvelope(t *testing.T) {
	taaKey := testTAAKey(t)
	pem, err := crypto.MarshalSM2PublicKeyPEM(&taaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal TAA public key: %v", err)
	}
	reg := newRegisterStateStore(t.TempDir())
	reg.set(registerState{TaaPublicKey: string(pem)})

	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newUploadTestServer(t, uploadDir, reg)
	defer server.Close()

	plaintext := []byte("model-package-plaintext")
	status, api := postMultipartUploadWithFields(t, server.URL+"/api/upload", "model.tar.gz", plaintext,
		map[string]string{"encryptMode": "urlkey"})
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("upload = %d/%d msg=%s", status, api.Error, api.Msg)
	}
	result := api.Result.(map[string]any)
	uploadedURL, _ := result["url"].(string)
	filename, _ := result["filename"].(string)
	if uploadedURL == "" || filename == "" {
		t.Fatalf("upload result lacks url/filename: %+v", result)
	}

	resp, err := http.Get(server.URL + "/api/uploads")
	if err != nil {
		t.Fatalf("list uploads: %v", err)
	}
	files := readUploadList(t, resp)
	if len(files) != 1 || files[0].Filename != filename {
		t.Fatalf("files = %+v, want one record for %s", files, filename)
	}
	if files[0].URL != uploadedURL {
		t.Fatalf("listed url = %q, want the upload url %q", files[0].URL, uploadedURL)
	}
	if !files[0].Encrypted {
		t.Errorf("listed .sm4 record is not marked encrypted")
	}

	// Prove the listed URL is usable end to end, not merely non-empty: unwrap
	// the envelope with TAA's key and decrypt the file the URL points at.
	parsed, err := url.Parse(files[0].URL)
	if err != nil {
		t.Fatalf("parse listed url: %v", err)
	}
	keyHex := parsed.Query().Get(dataKeyCipherQueryParam)
	if keyHex == "" {
		t.Fatalf("listed url carries no %s: %s", dataKeyCipherQueryParam, files[0].URL)
	}
	wrapped, err := crypto.ParseWrappedDataKeyHex(keyHex)
	if err != nil {
		t.Fatalf("parse wrapped data key: %v", err)
	}
	dataKey, err := crypto.UnwrapKeySM2(taaKey, wrapped)
	if err != nil {
		t.Fatalf("unwrap data key: %v", err)
	}

	fileResp, err := http.Get(server.URL + parsed.EscapedPath())
	if err != nil {
		t.Fatalf("download ciphertext: %v", err)
	}
	body, err := io.ReadAll(fileResp.Body)
	fileResp.Body.Close()
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if len(body) == 0 || body[0] != crypto.SM4FileVersion {
		t.Fatalf("ciphertext lacks the SM4 file version byte")
	}
	got, err := crypto.Decrypt(dataKey, body[1:])
	if err != nil {
		t.Fatalf("decrypt ciphertext: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}

	// Deleting the file must take its sidecar with it; a stale sidecar would
	// resurface if a later upload reused the name.
	req, err := http.NewRequest(http.MethodDelete, server.URL+"/api/uploads/delete?filename="+url.QueryEscape(filename), nil)
	if err != nil {
		t.Fatalf("create delete request: %v", err)
	}
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", delResp.StatusCode)
	}
	sidecar := filepath.Join(uploadDir, uploadMetaDir, filename+".json")
	if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
		t.Fatalf("sidecar %s survived the delete (err=%v)", sidecar, err)
	}
}

// TestUploadListOmitsTheEnvelopeForPlainFiles pins the other half: an
// unencrypted upload must not grow a query string, or TAA would try to unwrap a
// key that does not exist.
func TestUploadListOmitsTheEnvelopeForPlainFiles(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newUploadTestServer(t, uploadDir)
	defer server.Close()

	postMultipartUpload(t, server.URL+"/api/upload", "plain.txt", []byte("plain"))

	resp, err := http.Get(server.URL + "/api/uploads")
	if err != nil {
		t.Fatalf("list uploads: %v", err)
	}
	files := readUploadList(t, resp)
	if len(files) != 1 {
		t.Fatalf("files = %+v, want one", files)
	}
	if strings.Contains(files[0].URL, "?") {
		t.Fatalf("plain upload grew a query string: %s", files[0].URL)
	}
}
