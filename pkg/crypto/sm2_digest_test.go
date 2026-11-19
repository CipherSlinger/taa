package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestSM2DigestMatchesGmsm pins sm2Digest to gmsm's ZA/msgHash computation. A
// divergence here would silently make HCT-signed data unverifiable by every
// existing peer (platform envelopes, attestation, sealed state).
func TestSM2DigestMatchesGmsm(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	pub := &priv.PublicKey
	gmsmPub := toGmsmPublicKey(pub)

	longID := make([]byte, 8191) // gmsm's upper bound, exclusive
	if _, err := rand.Read(longID); err != nil {
		t.Fatalf("random long ID: %v", err)
	}
	msg1K := make([]byte, 1024)
	if _, err := rand.Read(msg1K); err != nil {
		t.Fatalf("random message: %v", err)
	}

	ids := []struct {
		name string
		uid  []byte
	}{
		{"empty-uses-default", nil},
		{"default-explicit", []byte(SM2DefaultUserID)},
		{"custom", []byte("alice@example.com")},
		{"8191-bytes", longID},
	}
	msgs := []struct {
		name string
		msg  []byte
	}{
		{"empty", nil},
		{"abc", []byte("abc")},
		{"1KiB", msg1K},
	}

	for _, id := range ids {
		for _, m := range msgs {
			want, err := gmsmPub.Sm3Digest(m.msg, id.uid)
			if err != nil {
				t.Fatalf("%s/%s: gmsm Sm3Digest: %v", id.name, m.name, err)
			}
			got, err := sm2Digest(pub, id.uid, m.msg)
			if err != nil {
				t.Fatalf("%s/%s: sm2Digest: %v", id.name, m.name, err)
			}
			if !bytes.Equal(got[:], leftPad32(want)) {
				t.Fatalf("%s/%s: digest mismatch\n got %x\nwant %x", id.name, m.name, got, want)
			}
		}
	}
}

func TestSM2DigestRejectsOversizedID(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	if _, err := sm2Digest(&priv.PublicKey, make([]byte, 8192), nil); err == nil {
		t.Fatal("expected error for 8192-byte user ID")
	}
}
