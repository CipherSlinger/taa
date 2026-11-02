package envelope

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// TestSealForPlatformOpensOnTAASide pins the direction the test helpers rely
// on: what SealForPlatform produces is exactly what Keys.Open accepts.
func TestSealForPlatformOpensOnTAASide(t *testing.T) {
	taaSide, p := fixture(t, nil)
	plaintext := []byte(`{"phase":2,"requestId":"req-1"}`)

	sealed, err := SealForPlatform(p.priv, p.taaPub, taaSide.UserID, plaintext)
	if err != nil {
		t.Fatalf("SealForPlatform: %v", err)
	}
	env, err := Parse(sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := taaSide.Open(env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("Open returned %q, want %q", got, plaintext)
	}
}

// TestOpenFromPlatformOpensWhatTAASealed is the other direction: a message TAA
// sent can be read back with the platform's private key.
func TestOpenFromPlatformOpensWhatTAASealed(t *testing.T) {
	taaSide, p := fixture(t, nil)
	plaintext := []byte(`{"msg":"ok","result":null,"error":0}`)

	sealed, err := taaSide.Seal(plaintext, "docker-1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env, err := Parse(sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if env.DockerID != "docker-1" {
		t.Fatalf("DockerID = %q, want the value Seal was given", env.DockerID)
	}
	got, err := OpenFromPlatform(p.priv, p.taaPub, taaSide.UserID, env)
	if err != nil {
		t.Fatalf("OpenFromPlatform: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("OpenFromPlatform returned %q, want %q", got, plaintext)
	}
}

// TestSealForPlatformRejectsWrongKeys covers the pairing mistake the API exists
// to prevent: a well-formed envelope that can never open.
func TestSealForPlatformRejectsWrongKeys(t *testing.T) {
	_, p := fixture(t, nil)
	other, err := newPeerKeys(t)
	if err != nil {
		t.Fatalf("generate other keys: %v", err)
	}

	if _, err := SealForPlatform(nil, p.taaPub, nil, []byte("x")); err == nil {
		t.Fatal("expected a nil platform private key to be rejected")
	}
	if _, err := SealForPlatform(p.priv, nil, nil, []byte("x")); err == nil {
		t.Fatal("expected a nil TAA public key to be rejected")
	}
	if _, err := OpenFromPlatform(other.priv, p.taaPub, nil, mustEnvelope(t, p, []byte("x"))); err == nil {
		t.Fatal("expected a foreign platform key not to open a TAA message")
	}
}

// TestSealForPlatformHonoursUserID pins that a mismatched identity is caught
// on TAA's side rather than silently accepted.
func TestSealForPlatformHonoursUserID(t *testing.T) {
	taaSide, p := fixture(t, []byte("platform-identity"))
	sealed, err := SealForPlatform(p.priv, p.taaPub, nil, []byte("x"))
	if err != nil {
		t.Fatalf("SealForPlatform: %v", err)
	}
	env, err := Parse(sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := taaSide.Open(env); err == nil {
		t.Fatal("expected the default identity to be rejected when the TAA side uses another one")
	}
}

func newPeerKeys(t *testing.T) (*peer, error) {
	t.Helper()
	fixtureKeys, p := fixture(t, nil)
	_ = fixtureKeys
	return p, nil
}

func mustEnvelope(t *testing.T, p *peer, plaintext []byte) *Envelope {
	t.Helper()
	sealed, err := SealForPlatform(p.priv, p.taaPub, nil, plaintext)
	if err != nil {
		t.Fatalf("SealForPlatform: %v", err)
	}
	env, err := Parse(sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return env
}

// TestSealForPlatformCipherLayout keeps the mock and the tests producing the
// same byte layout the real platform receives: raw C1C3C2, base64 once.
func TestSealForPlatformCipherLayout(t *testing.T) {
	_, p := fixture(t, nil)
	sealed, err := SealForPlatform(p.priv, p.taaPub, nil, []byte("hello"))
	if err != nil {
		t.Fatalf("SealForPlatform: %v", err)
	}
	var raw struct {
		Cipher string `json:"cipher"`
		Sign   string `json:"sign"`
	}
	if err := json.Unmarshal(sealed, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cipher, err := base64.StdEncoding.DecodeString(raw.Cipher)
	if err != nil {
		t.Fatalf("cipher is not base64: %v", err)
	}
	if len(cipher) != 1+64+32+len("hello") || cipher[0] != 4 {
		t.Fatalf("cipher is not a C1C3C2 point: length %d, first byte %#x", len(cipher), cipher[0])
	}
}
