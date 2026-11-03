package mock

import (
	"fmt"
	"io"
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
//
// It also opens the forwarded request with its own instance key. A request
// sealed for the wrong instance cannot be opened here, which turns a
// wrong-identity seal into a loud failure instead of a passing test.
func sealedBackend(t *testing.T, name, dockerID string, priv *crypto.SM2PrivateKey, ks *keystore) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The forwarded request is platform-direction: encrypt to TAA's key and
		// sign with the platform's. Keys.Open is the matching reader, and it is
		// keyed to this instance, so a request sealed for another instance
		// cannot be opened here.
		keys, err := envelope.NewKeys(&ks.platformPrivate().PublicKey, priv, ks.userIDBytes())
		if err != nil {
			t.Errorf("build keys for %s: %v", name, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("%s could not read the forwarded body: %v", name, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		env, err := envelope.Parse(raw)
		if err != nil {
			t.Errorf("%s received an unparseable envelope: %v", name, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		payload, err := keys.Open(env)
		if err != nil {
			t.Errorf("%s could not open the forwarded request: %v", name, err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		reply := fmt.Sprintf(`{"backend":%q,"path":%q,"query":%q,"echo":%q}`, name, r.URL.Path, r.URL.RawQuery, string(payload))
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

	// Pin which instance is the default instead of leaving it to registration
	// wall-clock order: the request below names the non-default instance, so a
	// handler that ignored ?dockerId= would route to A and fail the assertion.
	a := mgr.lookup("docker-a").register.get()
	a.ReceivedAt = "2026-01-02T00:00:00Z"
	mgr.lookup("docker-a").register.set(a)
	b := mgr.lookup("docker-b").register.get()
	b.ReceivedAt = "2026-01-01T00:00:00Z"
	mgr.lookup("docker-b").register.set(b)

	backendA := sealedBackend(t, "a", "docker-a", keyA, ks)
	defer backendA.Close()
	backendB := sealedBackend(t, "b", "docker-b", keyB, ks)
	defer backendB.Close()
	mgr.lookup("docker-a").setTarget(backendA.URL)
	mgr.lookup("docker-b").setTarget(backendB.URL)

	handler := loggingReverseProxyHandler(dynamicTAAProxyHandler(mgr, newProxyPool()))
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/health?dockerId=docker-b", strings.NewReader(`{"probe":1}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"backend"`) {
		t.Fatalf("response did not open (still sealed?): %s", body)
	}
	if !strings.Contains(body, `"backend":"b"`) {
		t.Fatalf("response = %s, want backend b", body)
	}
	if !strings.Contains(body, `"path":"/v1/taa/health"`) {
		t.Fatalf("backend path = %s, want /v1/taa/health", body)
	}
	if !strings.Contains(body, `"echo":"{\"probe\":1}"`) {
		t.Fatalf("forwarded body = %s, want it sealed to and opened by instance b", body)
	}
	if strings.Contains(body, `dockerId`) {
		t.Fatalf("response = %s, want it opened and the forwarded query free of dockerId", body)
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
