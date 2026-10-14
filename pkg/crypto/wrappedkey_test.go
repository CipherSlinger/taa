package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseWrappedDataKeyHex(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	dataKey, err := GenerateSM4Key()
	if err != nil {
		t.Fatalf("GenerateSM4Key: %v", err)
	}
	wrapped, err := WrapKeySM2(&priv.PublicKey, dataKey)
	if err != nil {
		t.Fatalf("WrapKeySM2: %v", err)
	}
	if len(wrapped) != SM2WrappedKeySize {
		t.Fatalf("wrapped length = %d, want %d", len(wrapped), SM2WrappedKeySize)
	}

	t.Run("112 bytes without the prefix gets it restored", func(t *testing.T) {
		got, err := ParseWrappedDataKeyHex(hex.EncodeToString(wrapped[1:]))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(wrapped) {
			t.Fatalf("restored envelope differs from the original")
		}
	})

	t.Run("113 bytes with the prefix is accepted as-is", func(t *testing.T) {
		got, err := ParseWrappedDataKeyHex(hex.EncodeToString(wrapped))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(wrapped) {
			t.Fatalf("envelope differs from the original")
		}
	})

	t.Run("the parsed envelope unwraps back to the data key", func(t *testing.T) {
		got, err := ParseWrappedDataKeyHex(hex.EncodeToString(wrapped[1:]))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		key, err := UnwrapKeySM2(priv, got)
		if err != nil {
			t.Fatalf("UnwrapKeySM2: %v", err)
		}
		if string(key) != string(dataKey) {
			t.Fatalf("unwrapped key differs from the original")
		}
	})

	t.Run("113 bytes with a wrong first byte is rejected", func(t *testing.T) {
		bad := append([]byte{0x03}, wrapped[1:]...)
		_, err := ParseWrappedDataKeyHex(hex.EncodeToString(bad))
		if err == nil {
			t.Fatal("expected error for a 113-byte envelope without the 0x04 prefix")
		}
	})

	t.Run("wrong lengths are rejected", func(t *testing.T) {
		for _, n := range []int{0, 111, 114} {
			if _, err := ParseWrappedDataKeyHex(hex.EncodeToString(make([]byte, n))); err == nil {
				t.Fatalf("length %d: expected error", n)
			}
		}
	})

	t.Run("invalid hex is rejected", func(t *testing.T) {
		if _, err := ParseWrappedDataKeyHex("zz"); err == nil {
			t.Fatal("expected error for invalid hex")
		}
		if _, err := ParseWrappedDataKeyHex("abc"); err == nil {
			t.Fatal("expected error for odd-length hex")
		}
	})

	t.Run("the error message carries the offending length", func(t *testing.T) {
		_, err := ParseWrappedDataKeyHex(hex.EncodeToString(make([]byte, 114)))
		if err == nil || !strings.Contains(err.Error(), "114") {
			t.Fatalf("err = %v, want it to mention 114", err)
		}
	})
}
