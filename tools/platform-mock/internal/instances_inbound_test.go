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
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate instance A's key pair: %v", err)
	}
	keyB, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate instance B's key pair: %v", err)
	}
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

	a, b := mgr.lookup("docker-a"), mgr.lookup("docker-b")
	if a == nil || b == nil {
		t.Fatalf("instance bundles missing after registration: a=%v b=%v", a, b)
	}
	if got := a.reportRes.get().DockerID; got != "docker-a" {
		t.Fatalf("instance A report dockerId = %q, want docker-a", got)
	}
	if got := b.reportRes.get().DockerID; got != "docker-b" {
		t.Fatalf("instance B report dockerId = %q, want docker-b", got)
	}
	if a.reportRes.get().ReceivedAt == b.reportRes.get().ReceivedAt {
		t.Log("both received at the same second; separation is asserted by dockerId above")
	}
}

func TestDeriveTAATarget(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		port       string
		want       string
	}{
		{"ipv4", "10.244.0.7:54321", "6001", "http://10.244.0.7:6001"},
		{"ipv6", "[fd00::7]:54321", "6001", "http://[fd00::7]:6001"},
		{"bare ip", "10.244.0.7", "6001", "http://10.244.0.7:6001"},
		{"default port", "10.244.0.7:1234", "", "http://10.244.0.7:6001"},
		{"empty", "", "6001", ""},
		{"garbage", "not-an-address", "6001", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveTAATarget(tc.remoteAddr, tc.port); got != tc.want {
				t.Fatalf("deriveTAATarget(%q, %q) = %q, want %q", tc.remoteAddr, tc.port, got, tc.want)
			}
		})
	}
}

func TestRegistrationDerivesAndKeepsItsOwnTargetAndKey(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	mgr := newInstanceManager(t.TempDir(), Config{TAAPort: "6001"})
	keyA, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	keyB, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)

	for _, id := range []string{"docker-a", "docker-b"} {
		b := mgr.lookup(id)
		if b == nil {
			t.Fatalf("%s bundle missing", id)
		}
		// httptest.NewRequest uses 192.0.2.1:1234 as RemoteAddr.
		if got := b.target(); got != "http://192.0.2.1:6001" {
			t.Fatalf("%s target = %q, want http://192.0.2.1:6001", id, got)
		}
		if ks.taaPublicFor(id) == nil {
			t.Fatalf("%s key was not adopted", id)
		}
	}
	if ks.taaPublicFor("docker-a") == ks.taaPublicFor("docker-b") {
		t.Fatal("both instances share one key")
	}
}

func TestReportWithAnotherInstancesKeyIsRefused(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate instance A's key pair: %v", err)
	}
	keyB, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate instance B's key pair: %v", err)
	}
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
