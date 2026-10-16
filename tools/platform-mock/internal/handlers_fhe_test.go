package mock

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"taa/pkg/crypto"
)

const (
	testEvalKeyName = "1700000000000000000_eval_context.bin"
	testInputZip    = "1700000000000000001_data-input.zip"
)

func writeFHEUpload(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create upload dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatalf("write upload %s: %v", name, err)
	}
}

// recordingTAA is a stand-in for TAA's /v1/taa/import. It captures the path and
// the decoded body, and answers with the envelope a TAA would.
type recordingTAA struct {
	*httptest.Server
	path     string
	body     map[string]any
	bodyRaw  []byte
	requests int
	status   int
	response string
}

func newRecordingTAA(t *testing.T) *recordingTAA {
	t.Helper()
	rec := &recordingTAA{status: http.StatusOK, response: `{"msg":"success","result":{"taskId":"task-1"},"error":0}`}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.requests++
		rec.path = r.URL.Path
		rec.bodyRaw, _ = io.ReadAll(r.Body)
		_ = json.Unmarshal(rec.bodyRaw, &rec.body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(rec.status)
		_, _ = w.Write([]byte(rec.response))
	}))
	t.Cleanup(rec.Close)
	return rec
}

func fheSubmitBody(t *testing.T, evalKeyFile, inputZip string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"evalKeyFile": evalKeyFile,
		"inputZip":    inputZip,
		"requestId":   "req-1",
		"taskId":      "task-1",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return string(b)
}

func postFHESubmit(handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/fhe/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

func TestFHESubmitForwardsAbsoluteURLsAndKeyHash(t *testing.T) {
	uploadDir := t.TempDir()
	keyBytes := []byte("eval-context-bytes-not-a-real-key")
	writeFHEUpload(t, uploadDir, testEvalKeyName, keyBytes)
	writeFHEUpload(t, uploadDir, testInputZip, []byte("input-zip-bytes"))

	taa := newRecordingTAA(t)
	cfg := Config{Addr: ":8080", UploadDir: uploadDir}
	handler := fheSubmitHandler(cfg, taa.URL)

	w := postFHESubmit(handler, fheSubmitBody(t, testEvalKeyName, testInputZip))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if taa.requests != 1 {
		t.Fatalf("TAA requests = %d, want 1", taa.requests)
	}
	if taa.path != "/v1/taa/import" {
		t.Fatalf("TAA path = %q, want /v1/taa/import", taa.path)
	}
	if !strings.Contains(w.Body.String(), `"taskId":"task-1"`) {
		t.Fatalf("response body = %s, want the TAA response echoed back", w.Body.String())
	}

	// The URLs are what TAA downloads the eval key and the input from. A bare
	// listen address would yield a scheme-less, host-less URL, so both are
	// checked as parsed URLs, not just as strings.
	wantBase := fmt.Sprintf("http://%s/files/", platformIP(cfg.Addr))
	for _, field := range []struct {
		name string
		file string
	}{
		{"evalKeyUrl", testEvalKeyName},
		{"resourceUrl", testInputZip},
	} {
		raw, _ := taa.body[field.name].(string)
		if raw != wantBase+field.file {
			t.Errorf("%s = %q, want %q", field.name, raw, wantBase+field.file)
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Errorf("parse %s %q: %v", field.name, raw, err)
			continue
		}
		if parsed.Scheme != "http" || parsed.Host == "" {
			t.Errorf("%s %q has scheme %q and host %q, want an absolute http URL", field.name, raw, parsed.Scheme, parsed.Host)
			continue
		}
		if parsed.Port() != "8080" {
			t.Errorf("%s %q has port %q, want the mock's listen port 8080", field.name, raw, parsed.Port())
		}
	}

	sum := crypto.SM3Sum(keyBytes)
	if got, want := taa.body["evalKeyFileHash"], hex.EncodeToString(sum[:]); got != want {
		t.Errorf("evalKeyFileHash = %v, want the SM3 of the uploaded key %q", got, want)
	}
	for field, want := range map[string]any{"requestId": "req-1", "taskId": "task-1"} {
		if got := taa.body[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
}

// The hash must follow the file's contents, not its name: two uploads with the
// same name and different bytes must hash differently.
func TestFHESubmitHashTracksFileContents(t *testing.T) {
	uploadDir := t.TempDir()
	writeFHEUpload(t, uploadDir, testEvalKeyName, []byte("key-A"))
	writeFHEUpload(t, uploadDir, testInputZip, []byte("zip"))

	taa := newRecordingTAA(t)
	handler := fheSubmitHandler(Config{Addr: ":8080", UploadDir: uploadDir}, taa.URL)

	if w := postFHESubmit(handler, fheSubmitBody(t, testEvalKeyName, testInputZip)); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	first, _ := taa.body["evalKeyFileHash"].(string)

	if err := os.WriteFile(filepath.Join(uploadDir, testEvalKeyName), []byte("key-B"), 0o644); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	if w := postFHESubmit(handler, fheSubmitBody(t, testEvalKeyName, testInputZip)); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	second, _ := taa.body["evalKeyFileHash"].(string)

	if want := hex.EncodeToString(sm3HexOf(t, "key-A")); first != want {
		t.Errorf("first hash = %q, want %q", first, want)
	}
	if want := hex.EncodeToString(sm3HexOf(t, "key-B")); second != want {
		t.Errorf("second hash = %q, want %q", second, want)
	}
	if first == second {
		t.Error("the hash did not change when the key contents changed")
	}
}

func sm3HexOf(t *testing.T, content string) []byte {
	t.Helper()
	sum := crypto.SM3Sum([]byte(content))
	return sum[:]
}

func TestFHESubmitRejectsNamesThatEscapeTheUploadDir(t *testing.T) {
	uploadDir := t.TempDir()
	writeFHEUpload(t, uploadDir, testEvalKeyName, []byte("key"))
	writeFHEUpload(t, uploadDir, testInputZip, []byte("zip"))
	// A file the names below would reach if the traversal were not refused.
	outside := filepath.Join(filepath.Dir(uploadDir), "secret.bin")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write the file outside the upload dir: %v", err)
	}
	defer os.Remove(outside)

	bad := []string{
		"../secret.bin",
		"../../etc/passwd",
		"sub/other.zip",
		`sub\other.zip`,
		"/etc/passwd",
		"..",
		".",
		"",
		"   ",
	}

	taa := newRecordingTAA(t)
	handler := fheSubmitHandler(Config{Addr: ":8080", UploadDir: uploadDir}, taa.URL)

	for _, name := range bad {
		t.Run(fmt.Sprintf("evalKeyFile=%q", name), func(t *testing.T) {
			w := postFHESubmit(handler, fheSubmitBody(t, name, testInputZip))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
		})
		t.Run(fmt.Sprintf("inputZip=%q", name), func(t *testing.T) {
			w := postFHESubmit(handler, fheSubmitBody(t, testEvalKeyName, name))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
		})
	}

	if taa.requests != 0 {
		t.Fatalf("TAA requests = %d, want 0: a refused name must not reach TAA", taa.requests)
	}
}

func TestFHESubmitRejectsMissingFile(t *testing.T) {
	uploadDir := t.TempDir()
	writeFHEUpload(t, uploadDir, testInputZip, []byte("zip"))

	taa := newRecordingTAA(t)
	handler := fheSubmitHandler(Config{Addr: ":8080", UploadDir: uploadDir}, taa.URL)

	w := postFHESubmit(handler, fheSubmitBody(t, "1700000000000000000_absent.bin", testInputZip))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if taa.requests != 0 {
		t.Fatalf("TAA requests = %d, want 0", taa.requests)
	}
}

func TestFHESubmitGuardsMethodTargetAndBody(t *testing.T) {
	uploadDir := t.TempDir()
	writeFHEUpload(t, uploadDir, testEvalKeyName, []byte("key"))
	writeFHEUpload(t, uploadDir, testInputZip, []byte("zip"))
	taa := newRecordingTAA(t)

	handler := fheSubmitHandler(Config{Addr: ":8080", UploadDir: uploadDir}, taa.URL)

	getReq := httptest.NewRequest(http.MethodGet, "/api/fhe/submit", nil)
	getW := httptest.NewRecorder()
	handler(getW, getReq)
	if getW.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", getW.Code)
	}

	if w := postFHESubmit(handler, `{"evalKeyFile":`); w.Code != http.StatusBadRequest {
		t.Errorf("malformed body status = %d, want 400; body=%s", w.Code, w.Body.String())
	}

	if w := postFHESubmit(handler, `{"evalKeyFile":"`+testEvalKeyName+`","inputZip":"`+testInputZip+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("body without ids status = %d, want 400; body=%s", w.Code, w.Body.String())
	}

	noTAA := fheSubmitHandler(Config{Addr: ":8080", UploadDir: uploadDir}, "  ")
	if w := postFHESubmit(noTAA, fheSubmitBody(t, testEvalKeyName, testInputZip)); w.Code != http.StatusServiceUnavailable {
		t.Errorf("missing TAA target status = %d, want 503; body=%s", w.Code, w.Body.String())
	}

	if taa.requests != 0 {
		t.Fatalf("TAA requests = %d, want 0: no guard above may reach TAA", taa.requests)
	}
}

// The mock's own status and body are what the caller sees, so a TAA failure must
// be surfaced rather than turned into a success.
func TestFHESubmitMirrorsTAAFailure(t *testing.T) {
	uploadDir := t.TempDir()
	writeFHEUpload(t, uploadDir, testEvalKeyName, []byte("key"))
	writeFHEUpload(t, uploadDir, testInputZip, []byte("zip"))

	taa := newRecordingTAA(t)
	taa.status = http.StatusBadGateway
	taa.response = `{"msg":"import rejected","error":4}`

	handler := fheSubmitHandler(Config{Addr: ":8080", UploadDir: uploadDir}, taa.URL)
	w := postFHESubmit(handler, fheSubmitBody(t, testEvalKeyName, testInputZip))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "import rejected") {
		t.Fatalf("body = %s, want the TAA body echoed back", w.Body.String())
	}
}

// The endpoint is on the served mux, not merely defined: this drives it through
// the handler NewServer installs.
func TestFHESubmitIsRegisteredOnTheServerMux(t *testing.T) {
	uploadDir := t.TempDir()
	writeFHEUpload(t, uploadDir, testEvalKeyName, []byte("key"))
	writeFHEUpload(t, uploadDir, testInputZip, []byte("zip"))

	taa := newRecordingTAA(t)
	srv := NewServer(Config{
		Addr:      ":8080",
		StateDir:  t.TempDir(),
		UploadDir: uploadDir,
		TAATarget: taa.URL,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/fhe/submit", strings.NewReader(fheSubmitBody(t, testEvalKeyName, testInputZip)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if taa.requests != 1 || taa.path != "/v1/taa/import" {
		t.Fatalf("TAA requests = %d on %q, want 1 on /v1/taa/import", taa.requests, taa.path)
	}
}

// The submit handler turns cfg.Addr into the host TAA downloads the eval key and
// the input package from, and that host has to be resolved while the request is
// served. platformIP answers 127.0.0.1 until a non-loopback interface is up, so a
// base captured when the handler was built would serve an unreachable host to TAA
// for the whole life of the process - and those URLs are the only way TAA can
// fetch the two files.
func TestFHESubmitResolvesTheHostPerRequest(t *testing.T) {
	uploadDir := t.TempDir()
	writeFHEUpload(t, uploadDir, testEvalKeyName, []byte("key"))
	writeFHEUpload(t, uploadDir, testInputZip, []byte("zip"))

	calls := 0
	prev := platformIPForRequest
	platformIPForRequest = func(addr string) string {
		calls++
		return platformIP(addr)
	}
	t.Cleanup(func() { platformIPForRequest = prev })

	taa := newRecordingTAA(t)
	handler := fheSubmitHandler(Config{Addr: ":8080", UploadDir: uploadDir}, taa.URL)

	if calls != 0 {
		t.Fatalf("building the handler resolved the host %d times, want 0: the host must not be fixed before the request", calls)
	}
	for i := 1; i <= 2; i++ {
		if w := postFHESubmit(handler, fheSubmitBody(t, testEvalKeyName, testInputZip)); w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200; body=%s", i, w.Code, w.Body.String())
		}
	}
	if calls != 2 {
		t.Fatalf("the host was resolved %d times while serving 2 requests, want 2", calls)
	}
}

// An eval key that /api/upload encrypted is ciphertext. Hashing it would hand TAA
// the SM3 of a value it never receives, and the evalKeyUrl would carry no
// ?dataKeyCipher=, so TAA could neither unwrap nor verify the key it downloads.
// The upload directory is shared between the two endpoints, so the suffix is the
// only signal available here - and a 400 says that better than a failed key
// download does.
func TestFHESubmitRejectsAnEncryptedEvalKey(t *testing.T) {
	uploadDir := t.TempDir()
	writeFHEUpload(t, uploadDir, testEvalKeyName, []byte("plaintext key"))
	writeFHEUpload(t, uploadDir, testInputZip, []byte("zip"))

	taa := newRecordingTAA(t)
	handler := fheSubmitHandler(Config{Addr: ":8080", UploadDir: uploadDir}, taa.URL)

	// encryptMode=envelope appends ".enc", encryptMode=urlkey appends ".sm4".
	for _, name := range []string{
		"1700000000000000000_eval_context.bin.enc",
		"1700000000000000000_eval_context.bin.sm4",
		"1700000000000000000_EVAL_CONTEXT.BIN.ENC",
	} {
		writeFHEUpload(t, uploadDir, name, []byte("ciphertext"))
		t.Run(name, func(t *testing.T) {
			w := postFHESubmit(handler, fheSubmitBody(t, name, testInputZip))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
		})
	}
	if taa.requests != 0 {
		t.Fatalf("TAA requests = %d, want 0: an encrypted key must not be hashed and forwarded", taa.requests)
	}

	// The plaintext one still goes through: the guard keys on the upload's suffix,
	// not on encryption being in use at all.
	w := postFHESubmit(handler, fheSubmitBody(t, testEvalKeyName, testInputZip))
	if w.Code != http.StatusOK {
		t.Fatalf("plaintext status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if taa.requests != 1 {
		t.Fatalf("TAA requests = %d, want 1 (the plaintext key only)", taa.requests)
	}
}
