package mock

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"taa/pkg/crypto"
)

// twoInstanceRouting registers docker-a and docker-b behind sealed backends and
// pins docker-a as the default instance. A request that names docker-b therefore
// proves the handler used the requested identity rather than the fallback.
type twoInstanceRouting struct {
	mgr *instanceManager
}

func newTwoInstanceRouting(t *testing.T) *twoInstanceRouting {
	t.Helper()
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	t.Cleanup(func() { setPlatformKeys(prev) })

	keyA, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	keyB, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}

	mgr := newInstanceManager(t.TempDir(), Config{})
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)

	// The default instance is chosen by ReceivedAt, so it is pinned here
	// instead of depending on registration wall-clock order.
	a := mgr.lookup("docker-a").register.get()
	a.ReceivedAt = "2026-01-02T00:00:00Z"
	mgr.lookup("docker-a").register.set(a)
	b := mgr.lookup("docker-b").register.get()
	b.ReceivedAt = "2026-01-01T00:00:00Z"
	mgr.lookup("docker-b").register.set(b)

	backendA := sealedBackend(t, "a", "docker-a", keyA, ks)
	t.Cleanup(backendA.Close)
	backendB := sealedBackend(t, "b", "docker-b", keyB, ks)
	t.Cleanup(backendB.Close)
	mgr.lookup("docker-a").setTarget(backendA.URL)
	mgr.lookup("docker-b").setTarget(backendB.URL)

	return &twoInstanceRouting{mgr: mgr}
}

func TestTAAStatusHandlerUsesTheSelectedInstance(t *testing.T) {
	routing := newTwoInstanceRouting(t)
	req := httptest.NewRequest(http.MethodPost, "/api/taa/status?dockerId=docker-b", nil)
	w := httptest.NewRecorder()
	taaStatusHandler(routing.mgr)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"backend":"b"`) {
		t.Fatalf("response = %s, want backend b", body)
	}
	if !strings.Contains(body, `"echo":"{}"`) {
		t.Fatalf("forwarded body = %s, want it sealed to and opened by instance b", body)
	}
}

func TestFHESubmitHandlerUsesTheSelectedInstance(t *testing.T) {
	routing := newTwoInstanceRouting(t)
	uploadDir := t.TempDir()
	writeFHEUpload(t, uploadDir, testEvalKeyName, []byte("key"))
	writeFHEUpload(t, uploadDir, testInputZip, []byte("zip"))
	cfg := Config{Addr: ":8080", UploadDir: uploadDir}

	req := httptest.NewRequest(http.MethodPost, "/api/fhe/submit?dockerId=docker-b", strings.NewReader(fheSubmitBody(t, testEvalKeyName, testInputZip)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	fheSubmitHandler(cfg, routing.mgr)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"backend":"b"`) {
		t.Fatalf("response = %s, want backend b", body)
	}
	if !strings.Contains(body, `\"taskId\":\"task-1\"`) {
		t.Fatalf("forwarded body = %s, want it sealed to and opened by instance b", body)
	}
}

func TestTAAStatusHandlerReportsAnUnknownInstance(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/taa/status?dockerId=missing", nil)
	w := httptest.NewRecorder()
	taaStatusHandler(testManagerWith(t, "", nil))(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "指定的 dockerId 不存在") {
		t.Fatalf("body = %s, want the unknown-instance message", w.Body.String())
	}
}

func TestDynamicTAAProxyReportsAnUnknownInstance(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/health?dockerId=missing", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	dynamicTAAProxyHandler(testManagerWith(t, "", nil), newProxyPool()).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "指定的 dockerId 不存在") {
		t.Fatalf("body = %s, want the unknown-instance message", w.Body.String())
	}
}

// The mount and StripPrefix are pinned here: the instance's target comes from
// the manager NewServer builds from on-disk state, and TAA must see the path
// without the /taa prefix.
func TestServerMuxRoutesTheProxyToTheSelectedInstance(t *testing.T) {
	stateDir := t.TempDir()
	ks, err := newKeystore(stateDir, "", nil)
	if err != nil {
		t.Fatalf("create the persisted keystore: %v", err)
	}
	keyB, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}
	if err := ks.setTaaPublicKeyFor("docker-b", &keyB.PublicKey); err != nil {
		t.Fatalf("register docker-b's key: %v", err)
	}
	backend := sealedBackend(t, "b", "docker-b", keyB, ks)
	t.Cleanup(backend.Close)

	dir := filepath.Join(stateDir, instancesDirName, instanceDirName("docker-b"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create the instance directory: %v", err)
	}
	meta := instanceMeta{
		DockerID:  "docker-b",
		TaaTarget: backend.URL,
		CreatedAt: "2026-01-01T00:00:00Z",
		UpdatedAt: "2026-01-01T00:00:00Z",
	}
	if err := saveJSONFile(filepath.Join(dir, "instance.json"), meta); err != nil {
		t.Fatalf("write the instance metadata: %v", err)
	}

	prev := currentPlatformKeys()
	t.Cleanup(func() { setPlatformKeys(prev) })
	srv := NewServer(Config{Addr: ":8080", StateDir: stateDir, UploadDir: t.TempDir()})

	req := httptest.NewRequest(http.MethodPost, "/taa/v1/taa/health?dockerId=docker-b", strings.NewReader(`{"probe":1}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"backend":"b"`) {
		t.Fatalf("response = %s, want backend b", body)
	}
	if !strings.Contains(body, `"path":"/v1/taa/health"`) {
		t.Fatalf("backend path = %s, want /v1/taa/health", body)
	}
	if !strings.Contains(body, `"echo":"{\"probe\":1}"`) {
		t.Fatalf("forwarded body = %s, want it sealed to and opened by instance b", body)
	}
}
