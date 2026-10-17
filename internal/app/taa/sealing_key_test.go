package taa

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"taa/internal/config"
	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
)

func testHardwareKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xa0 + i)
	}
	return key
}

func TestResolveStateSealingKey_SM2MatchesLegacyDerivation(t *testing.T) {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}

	key, source, err := resolveStateSealingKey(config.StateSealingKeySourceSM2, priv, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if source != store.KeySourceSM2 {
		t.Fatalf("source = %q, want %q", source, store.KeySourceSM2)
	}
	if want := store.DeriveSealingKey(priv); !bytes.Equal(key, want) {
		t.Fatalf("key does not match the legacy derivation")
	}
}

func TestResolveStateSealingKey_CSVHWDerivesFromFetchedKey(t *testing.T) {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	wantKey := testHardwareKey()

	fetch := func(buf []byte) error {
		copy(buf, wantKey)
		return nil
	}
	hwKey, err := fetchStartupHardwareKey(fetch)
	if err != nil {
		t.Fatalf("fetch hardware key: %v", err)
	}
	key, source, err := resolveStateSealingKey(config.StateSealingKeySourceCSVHW, priv, hwKey)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if source != store.KeySourceCSVHW {
		t.Fatalf("source = %q, want %q", source, store.KeySourceCSVHW)
	}
	want, err := teecrypto.DeriveSealingKeyFromCSV(wantKey)
	if err != nil {
		t.Fatalf("expected derivation: %v", err)
	}
	if !bytes.Equal(key, want) {
		t.Fatalf("key does not match the CSV derivation")
	}
}

func TestFetchStartupHardwareKey_FailureIsFatal(t *testing.T) {
	hwKey, err := fetchStartupHardwareKey(
		func([]byte) error { return errors.New("open /dev/csv-guest: no such file") })
	if err == nil {
		t.Fatal("expected the fetch failure to abort startup")
	}
	if hwKey != nil {
		t.Fatalf("a fatal fetch must not return a key, got %x", hwKey)
	}
}

func TestResolveStateSealingKey_CSVHWRejectsAllZeroKey(t *testing.T) {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}

	hwKey, err := fetchStartupHardwareKey(func(buf []byte) error {
		clear(buf)
		return nil
	})
	if err != nil {
		t.Fatalf("fetch hardware key: %v", err)
	}
	_, _, err = resolveStateSealingKey(config.StateSealingKeySourceCSVHW, priv, hwKey)
	if !errors.Is(err, teecrypto.ErrInvalidCSVSealingKey) {
		t.Fatalf("expected ErrInvalidCSVSealingKey, got %v", err)
	}
}

func TestSealingKeyFingerprintIsStableAndSized(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	fp := sealingKeyFingerprint(key)
	if len(fp) != 16 {
		t.Fatalf("fingerprint %q has %d hex chars, want 16", fp, len(fp))
	}
	if got := sealingKeyFingerprint(key); got != fp {
		t.Fatalf("fingerprint is not stable: %q then %q", fp, got)
	}
	if other := sealingKeyFingerprint(bytes.Repeat([]byte{0x22}, 16)); other == fp {
		t.Fatalf("different keys share a fingerprint: %q", fp)
	}

	sum := teecrypto.SM3Sum(key)
	if want := hex.EncodeToString(sum[:8]); fp != want {
		t.Fatalf("fingerprint = %q, want the first 8 bytes of SM3 = %q", fp, want)
	}
}

func TestResolveStateSealingKey_RejectsUnknownAndEmptySource(t *testing.T) {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}

	for _, source := range []string{"", "hsm", "CSV-HW"} {
		if _, _, err := resolveStateSealingKey(source, priv, nil); err == nil {
			t.Fatalf("source %q: expected an error", source)
		}
	}
}
