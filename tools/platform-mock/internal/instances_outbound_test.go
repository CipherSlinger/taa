package mock

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

// sealedBackend answers every request with a sealed body that echoes which
// backend served it and what it saw, so the assertions can prove both routing
// and query stripping without shared variables.
func sealedBackend(t *testing.T, name, dockerID string, priv *crypto.SM2PrivateKey, ks *keystore) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys, err := envelope.NewKeys(&ks.platformPrivate().PublicKey, priv, ks.userIDBytes())
		if err != nil {
			t.Errorf("build keys for %s: %v", name, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		reply := fmt.Sprintf(`{"backend":%q,"path":%q,"query":%q}`, name, r.URL.Path, r.URL.RawQuery)
		sealed, err := keys.Seal([]byte(reply), dockerID)
		if err != nil {
			t.Errorf("seal the reply from %s: %v", name, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(sealed)
	}))
}

func TestTAAProxyRoutesByDockerIDAndStripsTheQuery(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

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

	backendA := sealedBackend(t, "a", "docker-a", keyA, ks)
	defer backendA.Close()
	backendB := sealedBackend(t, "b", "docker-b", keyB, ks)
	defer backendB.Close()
	mgr.lookup("docker-a").setTarget(backendA.URL)
	mgr.lookup("docker-b").setTarget(backendB.URL)

	handler := loggingReverseProxyHandler(dynamicTAAProxyHandler(mgr, newProxyPool()))
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/health?dockerId=docker-a", strings.NewReader(`{"probe":1}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"backend":"a"`) {
		t.Fatalf("response = %s, want backend a", body)
	}
	if !strings.Contains(body, `"path":"/v1/taa/health"`) {
		t.Fatalf("backend path = %s, want /v1/taa/health", body)
	}
	if strings.Contains(body, `dockerId`) {
		t.Fatalf("forwarded query still contains dockerId: %s", body)
	}
}

func TestTAAProxyFallsBackToTheDefaultInstance(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	keyA, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	mgr := newInstanceManager(t.TempDir(), Config{})
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	backend := sealedBackend(t, "a", "docker-a", keyA, ks)
	defer backend.Close()
	mgr.lookup("docker-a").setTarget(backend.URL)

	req := httptest.NewRequest(http.MethodPost, "/v1/taa/status?keep=1", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	dynamicTAAProxyHandler(mgr, newProxyPool()).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"query":"keep=1"`) {
		t.Fatalf("forwarded query = %s, want keep=1", w.Body.String())
	}
}
