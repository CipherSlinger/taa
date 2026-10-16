package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	teecrypto "taa/pkg/crypto"
)

// TestExportIgnoresRequestPublicKeyOnFHEInstance pins the plaintext-export
// behaviour: an FHE instance exists to move ciphertext, and the platform decrypts
// it client-side, so an envelope would only put one more layer around bytes that
// are already encrypted.
func TestExportIgnoresRequestPublicKeyOnFHEInstance(t *testing.T) {
	env := newFHETestEnv(t)
	key := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n"

	if got := env.state.exportPublicKeyForRequest(&key); got != "" {
		t.Errorf("exportPublicKeyForRequest = %q, want empty on an FHE instance", got)
	}

	if got := env.state.exportPublicKeyForRequest(nil); got != "" {
		t.Errorf("exportPublicKeyForRequest(nil) = %q, want empty", got)
	}

	// The drop is announced, not silent: the caller sent a key expecting an
	// envelope, and a silent one would leave it unable to read the result.
	if n := countLogs(env.state, "忽略请求携带的 publicKey"); n != 1 {
		t.Errorf("ignoring the key was logged %d times, want 1; a silent drop hides the mismatch", n)
	}
}

// TestExportUsesRequestPublicKeyOnTEEInstance is the other half: on a tee
// instance the request's key is the export key, and the extraction must not have
// changed that.
func TestExportUsesRequestPublicKeyOnTEEInstance(t *testing.T) {
	// setupTestState is a tee boot: no FHE runner, so fheEnabled is false.
	s, _ := setupTestState(t)
	key := "  pem  "
	if got := s.exportPublicKeyForRequest(&key); got != "pem" {
		t.Errorf("exportPublicKeyForRequest = %q, want %q", got, "pem")
	}
	if got := s.exportPublicKeyForRequest(nil); got != "" {
		t.Errorf("exportPublicKeyForRequest(nil) = %q, want empty", got)
	}
	if n := countLogs(s, "忽略请求携带的 publicKey"); n != 0 {
		t.Errorf("a tee instance logged the ignore warning %d times, want 0", n)
	}
}

// TestFHEExportDropsASavedKeyEvenIfTheStateCarriesOne drives the export-side
// guard on its own: the instance type, not the sealed state, decides the envelope.
//
// The import handler no longer records a key on this instance type, so a non-empty
// ExportPublicKey can only come from state written by an older build or by a boot
// of this container as a tee instance. The phase-3 branch prefers the saved key,
// so without this guard that leftover would reseal an export that must be
// plaintext - which is the same defect from the other end.
func TestFHEExportDropsASavedKeyEvenIfTheStateCarriesOne(t *testing.T) {
	env := newFHETestEnv(t)

	key, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal SM2 public key: %v", err)
	}

	env.state.mu.Lock()
	env.state.ExportPublicKey = string(pubPEM)
	env.state.CurrentPhase = 3
	env.state.mu.Unlock()

	record := seedExportIndexRecord(t, env.state, "req-saved-key", "task-saved-key", "export-fhe-saved-key")
	if err := os.WriteFile(filepath.Join(record.ResultDir, "out.bin"), []byte("fhe-ciphertext"), 0o644); err != nil {
		t.Fatalf("write seeded out.bin: %v", err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, env.state)
	server := httptest.NewServer(mux)
	defer server.Close()

	resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
		"requestId": "req-saved-key",
		"taskId":    "task-saved-key",
	})
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read export body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export: status = %d, body = %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-TAA-Encrypted"); got == "true" {
		t.Errorf("X-TAA-Encrypted = %q, want not true (plaintext)", got)
	}
	if disp := resp.Header.Get("Content-Disposition"); strings.Contains(disp, ".enc") {
		t.Errorf("Content-Disposition = %q; a state-file key resealed the export", disp)
	}
	files := extractZipMap(t, body)
	if got, ok := files["export-fhe-saved-key/out.bin"]; !ok {
		t.Fatalf("exported zip lacks the seeded artifact; entries: %v", keysOfMap(files))
	} else if string(got) != "fhe-ciphertext" {
		t.Errorf("exported out.bin = %q, want the plaintext artifact", got)
	}
}

// The predicate is tryAcquireTask's own gate, so this returns exactly when the
// next import stops being refused with a 409: the previous import releases the
// slot in a deferred call that runs after the instance already looks idle.
func waitForImportSlot(t *testing.T, s *TAAState) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		free := s.ActiveTaskID == "" && (s.CurrentOp == "" || s.CurrentOp == "idle") && !s.isTrainingBusyLocked()
		s.mu.RUnlock()
		if free {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the previous import never released the task slot")
}

// TestFHEExportOfAPhaseThreeTaskIgnoresAPhaseOnePublicKey is the end-to-end proof
// that an fhe instance never answers an export with an envelope.
//
// The platform mock has a switch for exactly this shape
// (tools/platform-mock/internal/static/index.html, importModelUsePublicKeySwitch):
// the export public key arrives with the phase-1 model import. TAA used to save it
// right there, in the HTTP handler and long before any FHE code ran, and the
// phase-3 export prefers the saved key over the request's - so an instance type
// that never offers an envelope returned an SM2-sealed .enc anyway. Both key
// sources are covered here, because the instance type has to decide the envelope
// and neither the request nor the saved state may reintroduce one.
func TestFHEExportOfAPhaseThreeTaskIgnoresAPhaseOnePublicKey(t *testing.T) {
	env := newFHETestEnv(t)
	// Fail-closed with the check switched on, so the export below is also proof
	// that the record the import commits carries its verdict.
	env.state.Security.ResultCheck = true
	env.state.Security.LLM.FailClosed = true

	key, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal SM2 public key: %v", err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, env.state)
	server := httptest.NewServer(mux)
	defer server.Close()

	type reportPayload struct {
		Code int     `json:"code"`
		Msg  *string `json:"msg"`
	}
	reported := make(chan reportPayload, 4)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/taa/reportRes" {
			var payload reportPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
				reported <- payload
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	// ── Phase 1: the model package, carrying a public key ──
	modelPath, modelZip := writeTestZip(t, t.TempDir(), map[string]string{"server/model.bin": "fhe-model"})
	modelHash, err := sm3HexOfFile(modelPath)
	if err != nil {
		t.Fatalf("hash model package: %v", err)
	}
	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(modelZip)
	}))
	defer modelServer.Close()

	env.state.mu.Lock()
	env.state.CurrentPhase = 1
	env.state.mu.Unlock()

	modelResp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl": modelServer.URL + "/model.zip",
		"requestId":   "req-model",
		"taskId":      "task-model",
		"publicKey":   string(pubPEM),
	})
	modelBody, _ := io.ReadAll(modelResp.Body)
	modelResp.Body.Close()
	if modelResp.StatusCode != http.StatusOK {
		t.Fatalf("phase-1 model import carrying a publicKey: status = %d, body = %s", modelResp.StatusCode, modelBody)
	}

	// The key must not be recorded. Phase 3 prefers the saved key, so recording it
	// is what used to put an envelope on this instance's export. The save is
	// synchronous - it happens in the handler, before it answers - so it can be
	// read here; the warning is not, and is counted once the import has settled.
	if got := env.state.getExportPublicKey(); got != "" {
		t.Errorf("ExportPublicKey = %q after a phase-1 import that carried one; an fhe instance must not record it", got)
	}

	modelDir, err := env.runner.Layout().ModelDir(modelHash)
	if err != nil {
		t.Fatalf("ModelDir: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(modelDir, "server")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the model package to be staged into %s", modelDir)
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitForImportSlot(t, env.state)

	// Exactly one: the decision belongs to the import handler, which is where the
	// key stops being saved, and the FHE branch that runs later must not announce
	// the same decision a second time.
	if n := countLogs(env.state, "FHE 实例不提供导出信封"); n != 1 {
		t.Errorf("the ignore-publicKey warning is logged %d times, want exactly 1: %v", n, logLines(env.state))
	}

	// The platform is armed only now: the model import reported to the fixture's
	// closed port, so every report reaching this server is the data task's.
	env.state.mu.Lock()
	env.state.PlatformIP = platform.URL
	env.state.mu.Unlock()

	// ── Phase 3: the data import that runs the task, and the export that reads it ──
	env.state.mu.Lock()
	env.state.CurrentPhase = 3
	env.state.mu.Unlock()

	_, pkg := writeTestZip(t, t.TempDir(), map[string]string{"data/case.txt": "ciphertext"})
	pkgServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pkg)
	}))
	defer pkgServer.Close()

	importResp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl":     pkgServer.URL + "/in.zip",
		"requestId":       "req-data",
		"taskId":          "task-data",
		"evalKeyUrl":      env.stub.URL + "/eval_context.bin",
		"evalKeyFileHash": env.keyHash,
	})
	importBody, _ := io.ReadAll(importResp.Body)
	importResp.Body.Close()
	if importResp.StatusCode != http.StatusOK {
		t.Fatalf("data import: status = %d, body = %s", importResp.StatusCode, importBody)
	}

	select {
	case payload := <-reported:
		if payload.Code != 0 {
			msg := ""
			if payload.Msg != nil {
				msg = *payload.Msg
			}
			t.Fatalf("reportRes code = %d (msg %q), want a successful FHE run", payload.Code, msg)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the FHE import to report its result")
	}

	// The phase is what selects the branch under test: export prefers the key saved
	// at model import for a phase-3 record, and falls back to the request's only
	// when there is none.
	store, err := env.state.importIndexStore()
	if err != nil {
		t.Fatalf("importIndexStore: %v", err)
	}
	record, err := store.Lookup("req-data", "task-data")
	if err != nil {
		t.Fatalf("the data import committed no index record: %v", err)
	}
	if record.Phase != 3 {
		t.Fatalf("record phase = %d, want 3: the sealed-key branch would not be reached", record.Phase)
	}

	exportResp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
		"requestId": "req-data",
		"taskId":    "task-data",
	})
	exportBody, err := io.ReadAll(exportResp.Body)
	exportResp.Body.Close()
	if err != nil {
		t.Fatalf("read export body: %v", err)
	}
	if exportResp.StatusCode != http.StatusOK {
		t.Fatalf("export of a finished FHE task: status = %d, body = %s", exportResp.StatusCode, exportBody)
	}

	// The envelope's three traces, all of which must be absent: the filename, the
	// sealed bytes, and the log line sealing would leave behind.
	if disp := exportResp.Header.Get("Content-Disposition"); strings.Contains(disp, ".enc") {
		t.Errorf("Content-Disposition = %q; an fhe export was sealed into an envelope", disp)
	}
	if countLogs(env.state, "加密完成") != 0 {
		t.Error("an SM2 envelope was sealed for an fhe export")
	}

	// And the body has to be the plaintext result archive, readable as a zip: an
	// .enc body is a C1C3C2 blob that would fail to parse.
	files := extractZipMap(t, exportBody)
	resultName := filepath.Base(env.resultDir()) + "/output.zip"
	got, ok := files[resultName]
	if !ok {
		t.Fatalf("the exported bytes are not the result archive: no %s among %v", resultName, keysOfMap(files))
	}
	if string(got) != "DOWNLOADED-RESULT" {
		t.Errorf("exported output.zip = %q, want the service's result bytes", got)
	}
	requireLog(t, env.state, "明文导出")
}
