package mock

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

func TestTwoInstancesKeepSeparateReportState(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	setPlatformKeys(ks)
	defer setPlatformKeys(platformKeyStore())

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)

	postReport := func(priv *crypto.SM2PrivateKey, dockerID string) *httptest.ResponseRecorder {
		body := []byte(`{"dockerId":"` + dockerID + `","requestId":"req-1","taskId":"task-1","code":0,"report":"ok"}`)
		keys, err := envelope.NewKeys(&ks.platformPrivate().PublicKey, priv, ks.userIDBytes())
		if err != nil {
			t.Fatalf("build keys: %v", err)
		}
		sealed, err := keys.Seal(body, dockerID)
		if err != nil {
			t.Fatalf("seal report: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportRes", bytes.NewReader(sealed))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		reportResHandler(mgr).ServeHTTP(w, req)
		return w
	}

	if w := postReport(keyA, "docker-a"); w.Code != http.StatusOK {
		t.Fatalf("report from A: status = %d, body = %s", w.Code, w.Body.String())
	}
	if w := postReport(keyB, "docker-b"); w.Code != http.StatusOK {
		t.Fatalf("report from B: status = %d, body = %s", w.Code, w.Body.String())
	}

	if got := mgr.lookup("docker-a").reportRes.get().DockerID; got != "docker-a" {
		t.Fatalf("instance A report dockerId = %q, want docker-a", got)
	}
	if got := mgr.lookup("docker-b").reportRes.get().DockerID; got != "docker-b" {
		t.Fatalf("instance B report dockerId = %q, want docker-b", got)
	}
	if mgr.lookup("docker-a").reportRes.get().ReceivedAt == mgr.lookup("docker-b").reportRes.get().ReceivedAt {
		t.Log("both received at the same second; separation is asserted by dockerId above")
	}
}

func TestReportWithAnotherInstancesKeyIsRefused(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	setPlatformKeys(ks)
	defer setPlatformKeys(platformKeyStore())

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)

	// Hint A, sign with B.
	body := []byte(`{"dockerId":"docker-a","requestId":"req-1"}`)
	keys, err := envelope.NewKeys(&ks.platformPrivate().PublicKey, keyB, ks.userIDBytes())
	if err != nil {
		t.Fatalf("build keys: %v", err)
	}
	sealed, err := keys.Seal(body, "docker-a")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportRes", bytes.NewReader(sealed))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	reportResHandler(mgr).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", w.Code, w.Body.String())
	}
}
