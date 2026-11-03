package mock

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

// TestConcurrentInstancesStayIsolated registers two instances and drives their
// inbound report path plus their progress and log stores at the same time. It
// pins one keystore globally because registration and inbound verification read
// the process keystore, then restores the previous one.
func TestConcurrentInstancesStayIsolated(t *testing.T) {
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

	run := func(dockerID string, priv *crypto.SM2PrivateKey) error {
		hexKey, err := crypto.MarshalSM2PublicKeyHex(&priv.PublicKey)
		if err != nil {
			return fmt.Errorf("encode %s's public key: %w", dockerID, err)
		}
		keys, err := envelope.NewKeys(&ks.platformPrivate().PublicKey, priv, ks.userIDBytes())
		if err != nil {
			return fmt.Errorf("build envelope keys for %s: %w", dockerID, err)
		}

		registerBody := fmt.Sprintf(
			`{"dockerId":%q,"authInfo":null,"taaPublicKey":%q,"timestamp":"2026-01-01T00:00:00Z","verifiedPass":true}`,
			dockerID, hexKey,
		)
		sealed, err := keys.Seal([]byte(registerBody), dockerID)
		if err != nil {
			return fmt.Errorf("seal the registration for %s: %w", dockerID, err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/taa/register", bytes.NewReader(sealed))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		registerHandler(mgr, true).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			return fmt.Errorf("register %s: status = %d, body = %s", dockerID, w.Code, w.Body.String())
		}

		reportBody := fmt.Sprintf(
			`{"dockerId":%q,"requestId":"req-%s","taskId":"task-%s","code":0,"report":"ok"}`,
			dockerID, dockerID, dockerID,
		)
		sealedReport, err := keys.Seal([]byte(reportBody), dockerID)
		if err != nil {
			return fmt.Errorf("seal the report for %s: %w", dockerID, err)
		}
		reportReq := httptest.NewRequest(http.MethodPost, "/v1/taa/reportRes", bytes.NewReader(sealedReport))
		reportReq.Header.Set("Content-Type", "application/json")
		reportW := httptest.NewRecorder()
		reportResHandler(mgr).ServeHTTP(reportW, reportReq)
		if reportW.Code != http.StatusOK {
			return fmt.Errorf("report %s: status = %d, body = %s", dockerID, reportW.Code, reportW.Body.String())
		}

		b := mgr.lookup(dockerID)
		if b == nil {
			return fmt.Errorf("instance %s is missing after registration", dockerID)
		}
		b.progress.set(progressState{
			Received:   true,
			Accepted:   true,
			DockerID:   dockerID,
			RequestID:  "req-" + dockerID,
			TaskID:     "task-" + dockerID,
			Percent:    42,
			StatusCode: http.StatusOK,
		})
		b.modelLog.addEntries(dockerID, "req-"+dockerID, "task-"+dockerID, []modelLogEntry{
			{Seq: 1, Message: "model-" + dockerID},
		})
		b.taaLog.addEntries(dockerID, "req-"+dockerID, "task-"+dockerID, []taaLogEntry{
			{Seq: 1, Message: "taa-" + dockerID},
		})
		return nil
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, inst := range []struct {
		dockerID string
		key      *crypto.SM2PrivateKey
	}{
		{"docker-a", keyA},
		{"docker-b", keyB},
	} {
		wg.Add(1)
		go func(dockerID string, key *crypto.SM2PrivateKey) {
			defer wg.Done()
			errs <- run(dockerID, key)
		}(inst.dockerID, inst.key)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	a, b := mgr.lookup("docker-a"), mgr.lookup("docker-b")
	if a == nil || b == nil {
		t.Fatalf("instance bundles missing: a=%v b=%v", a, b)
	}

	wantA, err := crypto.MarshalSM2PublicKeyHex(&keyA.PublicKey)
	if err != nil {
		t.Fatalf("encode A's public key: %v", err)
	}
	wantB, err := crypto.MarshalSM2PublicKeyHex(&keyB.PublicKey)
	if err != nil {
		t.Fatalf("encode B's public key: %v", err)
	}
	if got, _ := crypto.MarshalSM2PublicKeyHex(ks.taaPublicFor("docker-a")); got != wantA {
		t.Fatalf("docker-a key = %q, want its own key", got)
	}
	if got, _ := crypto.MarshalSM2PublicKeyHex(ks.taaPublicFor("docker-b")); got != wantB {
		t.Fatalf("docker-b key = %q, want its own key", got)
	}
	if a.register.get().TaaPublicKey != wantA || b.register.get().TaaPublicKey != wantB {
		t.Fatal("registration state carries another instance's public key")
	}

	if a.reportRes.get().RequestID != "req-docker-a" || a.reportRes.get().DockerID != "docker-a" {
		t.Fatalf("A report = %+v, want req-docker-a", a.reportRes.get())
	}
	if b.reportRes.get().RequestID != "req-docker-b" || b.reportRes.get().DockerID != "docker-b" {
		t.Fatalf("B report = %+v, want req-docker-b", b.reportRes.get())
	}
	if a.reportRes.get().RequestID == b.reportRes.get().RequestID {
		t.Fatal("both instances hold the same report")
	}

	if a.progress.get().RequestID != "req-docker-a" || b.progress.get().RequestID != "req-docker-b" {
		t.Fatalf("progress crossed instances: a=%+v b=%+v", a.progress.get(), b.progress.get())
	}

	if got := a.modelLog.get(); got.RequestID != "req-docker-a" || len(got.Entries) != 1 || got.Entries[0].Message != "model-docker-a" {
		t.Fatalf("A model log = %+v", got)
	}
	if got := b.modelLog.get(); got.RequestID != "req-docker-b" || len(got.Entries) != 1 || got.Entries[0].Message != "model-docker-b" {
		t.Fatalf("B model log = %+v", got)
	}
	if got := a.taaLog.get(); got.RequestID != "req-docker-a" || len(got.Entries) != 1 || got.Entries[0].Message != "taa-docker-a" {
		t.Fatalf("A taa log = %+v", got)
	}
	if got := b.taaLog.get(); got.RequestID != "req-docker-b" || len(got.Entries) != 1 || got.Entries[0].Message != "taa-docker-b" {
		t.Fatalf("B taa log = %+v", got)
	}
}
