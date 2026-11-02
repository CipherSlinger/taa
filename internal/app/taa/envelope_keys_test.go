package taa

import (
	"strings"
	"testing"

	"taa/internal/config"
	teecrypto "taa/pkg/crypto"
)

func TestResolveEnvelopeKeys(t *testing.T) {
	taaKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate TAA key: %v", err)
	}
	platformKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate platform key: %v", err)
	}
	platformHex, err := teecrypto.MarshalSM2PublicKeyHex(&platformKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal platform public key: %v", err)
	}

	t.Run("empty ID falls back to the protocol default", func(t *testing.T) {
		keys, err := resolveEnvelopeKeys(config.StartupConfig{PlatformPublicKey: platformHex}, taaKey)
		if err != nil {
			t.Fatalf("resolveEnvelopeKeys() error = %v", err)
		}
		if string(keys.UserID) != string(teecrypto.SM2DefaultUserID) {
			t.Fatalf("UserID = %q, want the protocol default %q", keys.UserID, teecrypto.SM2DefaultUserID)
		}
		if keys.PlatformPub.X.Cmp(platformKey.PublicKey.X) != 0 || keys.PlatformPub.Y.Cmp(platformKey.PublicKey.Y) != 0 {
			t.Fatal("platform public key was not parsed into the key material")
		}
		if keys.TAAPriv != taaKey {
			t.Fatal("TAA private key was not carried into the key material")
		}
	})

	t.Run("explicit ID is used verbatim", func(t *testing.T) {
		// Whitespace is part of the ID, not formatting: trimming it here would
		// produce a value that never matches the platform's without any
		// indication on this side.
		keys, err := resolveEnvelopeKeys(config.StartupConfig{
			PlatformPublicKey: platformHex,
			PlatformSM2ID:     " platform-id ",
		}, taaKey)
		if err != nil {
			t.Fatalf("resolveEnvelopeKeys() error = %v", err)
		}
		if string(keys.UserID) != " platform-id " {
			t.Fatalf("UserID = %q, want it verbatim", keys.UserID)
		}
	})

	t.Run("missing environment variable is fatal", func(t *testing.T) {
		_, err := resolveEnvelopeKeys(config.StartupConfig{}, taaKey)
		if err == nil {
			t.Fatal("expected a missing platform public key to be rejected")
		}
		if !strings.Contains(err.Error(), "PLATFORM_PUBLIC_KEY") {
			t.Fatalf("error does not name the setting: %v", err)
		}
	})

	t.Run("unparseable key is fatal", func(t *testing.T) {
		for _, bad := range []string{"not-hex", "04aabb", "04" + strings.Repeat("00", 64)} {
			if _, err := resolveEnvelopeKeys(config.StartupConfig{PlatformPublicKey: bad}, taaKey); err == nil {
				t.Fatalf("expected %q to be rejected", bad)
			}
		}
	})

	t.Run("missing TAA key is fatal", func(t *testing.T) {
		if _, err := resolveEnvelopeKeys(config.StartupConfig{PlatformPublicKey: platformHex}, nil); err == nil {
			t.Fatal("expected a nil TAA private key to be rejected")
		}
	})
}
