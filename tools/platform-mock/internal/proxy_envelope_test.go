package mock

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The console posts to the mock's /taa/* reverse proxy with a plaintext body.
// TAA only accepts envelopes, so the proxy has to seal on the way out and open
// the JSON response on the way back; otherwise every console action reaches TAA
// as plaintext and is rejected.
func TestTAAReverseProxySealsRequestsAndOpensResponses(t *testing.T) {
	registerTestTAAKey(t)

	var gotPlaintext []byte
	taa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/taa/health" {
			t.Errorf("path = %q, want /v1/taa/health", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the proxied body: %v", err)
			return
		}
		gotPlaintext = openAsTAA(t, body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(sealAsTAA(t, `{"msg":"success","result":{"ok":true},"error":0}`))
	}))
	defer taa.Close()

	srv := NewServer(Config{
		Addr:      ":8080",
		StateDir:  t.TempDir(),
		UploadDir: t.TempDir(),
		TAATarget: taa.URL,
	})
	registerTestTAAKey(t)

	req := httptest.NewRequest(http.MethodPost, "/taa/v1/taa/health", strings.NewReader(`{"probe":1}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if string(gotPlaintext) != `{"probe":1}` {
		t.Fatalf("TAA received %s, want the console's plaintext body", gotPlaintext)
	}
	if got := w.Body.String(); !strings.Contains(got, `"ok":true`) {
		t.Fatalf("console got %s, want the opened response body", got)
	}
}

// Without a registered TAA key the proxy has nothing to seal to. It must say so
// instead of forwarding plaintext that TAA would reject without explanation.
func TestTAAReverseProxyRefusesToForwardWithoutATAAPublicKey(t *testing.T) {
	reached := false
	taa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer taa.Close()

	// NewServer installs its own keystore with no TAA key registered, which is
	// the state a real instance is in until the first registration.
	srv := NewServer(Config{
		Addr:      ":8080",
		StateDir:  t.TempDir(),
		UploadDir: t.TempDir(),
		TAATarget: taa.URL,
	})

	req := httptest.NewRequest(http.MethodPost, "/taa/v1/taa/health", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", w.Code, w.Body.String())
	}
	if reached {
		t.Fatal("the request reached TAA; it must be refused before anything is sent")
	}
	if !strings.Contains(w.Body.String(), "no TAA public key registered") {
		t.Fatalf("body = %s, want the missing-key error", w.Body.String())
	}
}
