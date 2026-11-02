package platform_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"taa/internal/platform"
)

// TestSendPlatformJSONSealsWhenInstalled pins the seam at the bottom of the
// send path: every reporting function ends here, so this is the one place that
// has to seal.
func TestSendPlatformJSONSealsWhenInstalled(t *testing.T) {
	platform.SetOutboundEnvelope(func(plain []byte) ([]byte, error) {
		return append([]byte(`{"cipher":"c","sign":"s","from":"sealed"}`), plain[:0]...), nil
	})
	t.Cleanup(func() { platform.SetOutboundEnvelope(nil) })

	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := platform.SendPlatformJSON(context.Background(), nil, server.URL, []byte(`{"business":true}`)); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got["from"] != "sealed" {
		t.Fatalf("payload reached the platform unsealed: %#v", got)
	}
	if _, leaked := got["business"]; leaked {
		t.Fatalf("plaintext business field reached the platform: %#v", got)
	}
}

// TestSendPlatformJSONSecondSealFailureSendsNothing pins the fail-closed rule:
// a sealing error must not degrade to the plaintext path.
func TestSendPlatformJSONSecondSealFailureSendsNothing(t *testing.T) {
	platform.SetOutboundEnvelope(func([]byte) ([]byte, error) {
		return nil, errors.New("seal boom")
	})
	t.Cleanup(func() { platform.SetOutboundEnvelope(nil) })

	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := platform.SendPlatformJSON(context.Background(), nil, server.URL, []byte(`{"business":true}`))
	if err == nil {
		t.Fatal("expected a sealing error")
	}
	if reached {
		t.Fatal("payload was sent after sealing failed; the fallback must not exist")
	}
}

// TestSendPlatformJSONUnsealedWhenNoSealer keeps the package usable on its own
// (and keeps the pre-existing package tests meaningful).
func TestSendPlatformJSONUnsealedWhenNoSealer(t *testing.T) {
	platform.SetOutboundEnvelope(nil)

	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := platform.SendPlatformJSON(context.Background(), nil, server.URL, []byte(`{"business":true}`)); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got["business"] != true {
		t.Fatalf("unsealed send changed the payload: %#v", got)
	}
}
