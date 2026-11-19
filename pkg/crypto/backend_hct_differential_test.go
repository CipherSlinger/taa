//go:build linux && amd64

package crypto

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
)

// TestHCTBackendDifferential runs the real helper against libhct and compares
// every operation with the built-in gmsm backend. It is skipped unless
// HCT_TEST_HELPER points at a helper built with -tags hct.
//
//	HCT_TEST_HELPER=/tmp/taa-hct-helper \
//	HCT_TEST_LOADER=/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
//	HCT_TEST_LIBDIR=/path/to/opt/hygon/hct/lib64 \
//	go test ./pkg/crypto -run TestHCTBackendDifferential -v
func TestHCTBackendDifferential(t *testing.T) {
	helper := os.Getenv("HCT_TEST_HELPER")
	if helper == "" {
		t.Skip("HCT_TEST_HELPER not set")
	}
	libdir := os.Getenv("HCT_TEST_LIBDIR")
	if libdir == "" {
		t.Fatal("HCT_TEST_LIBDIR must be set with HCT_TEST_HELPER")
	}
	hctBackend, closeFn, err := openHCTBackend(HCTConfig{
		HelperPath: helper,
		LoaderPath: os.Getenv("HCT_TEST_LOADER"),
		LibDir:     libdir,
		Accel:      "sw",
	})
	if err != nil {
		t.Fatalf("openHCTBackend: %v", err)
	}
	defer closeFn()
	ref := Backend(builtinBackend{})
	_ = hctBackend

	t.Run("SM3", func(t *testing.T) {
		for _, n := range []int{0, 1, 55, 56, 64, 1 << 20, 3<<20 + 17} {
			data := make([]byte, n)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("rand: %v", err)
			}
			got, err := hctBackend.SM3Sum(data)
			if err != nil {
				t.Fatalf("hct SM3Sum(%d): %v", n, err)
			}
			want, err := ref.SM3Sum(data)
			if err != nil {
				t.Fatalf("ref SM3Sum: %v", err)
			}
			if got != want {
				t.Fatalf("SM3(%d bytes) mismatch\n got %x\nwant %x", n, got, want)
			}
		}
	})

	t.Run("SM3Stream", func(t *testing.T) {
		data := make([]byte, 2<<20+3)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand: %v", err)
		}
		st, err := hctBackend.NewSM3Stream()
		if err != nil {
			t.Fatalf("NewSM3Stream: %v", err)
		}
		for off := 0; off < len(data); off += 700_001 {
			end := off + 700_001
			if end > len(data) {
				end = len(data)
			}
			if _, err := st.Write(data[off:end]); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		if _, err := st.Write(nil); err != nil {
			t.Fatalf("zero-length Write: %v", err)
		}
		got, err := st.Sum()
		if err != nil {
			t.Fatalf("Sum: %v", err)
		}
		want, err := ref.SM3Sum(data)
		if err != nil {
			t.Fatalf("ref SM3Sum: %v", err)
		}
		if got != want {
			t.Fatalf("streaming SM3 mismatch")
		}
	})

	t.Run("HMACSM3", func(t *testing.T) {
		for _, keyLen := range []int{1, 16, 32, 64, 128} {
			key := make([]byte, keyLen)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("rand: %v", err)
			}
			data := []byte("hmac differential payload")
			got, err := hctBackend.HMACSM3(key, data)
			if err != nil {
				t.Fatalf("hct HMACSM3(key %d): %v", keyLen, err)
			}
			want, err := ref.HMACSM3(key, data)
			if err != nil {
				t.Fatalf("ref HMACSM3: %v", err)
			}
			if got != want {
				t.Fatalf("HMAC-SM3(key %d) mismatch", keyLen)
			}
		}
	})

	t.Run("GCM", func(t *testing.T) {
		key := make([]byte, SM4KeySize)
		nonce := make([]byte, 12)
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("rand: %v", err)
		}
		for _, n := range []int{0, 1, 16, 4096, 2<<20 + 7} {
			plain := make([]byte, n)
			if _, err := rand.Read(plain); err != nil {
				t.Fatalf("rand: %v", err)
			}
			aad := []byte("aad-bytes")

			hctG, err := hctBackend.NewGCM(key)
			if err != nil {
				t.Fatalf("NewGCM: %v", err)
			}
			got, err := hctG.Seal(nil, nonce, plain, aad)
			if err != nil {
				t.Fatalf("hct Seal(%d): %v", n, err)
			}
			refG, err := ref.NewGCM(key)
			if err != nil {
				t.Fatalf("ref NewGCM: %v", err)
			}
			want, err := refG.Seal(nil, nonce, plain, aad)
			if err != nil {
				t.Fatalf("ref Seal: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("GCM Seal(%d) differs", n)
			}

			pt, err := refG.Open(nil, nonce, got, aad)
			if err != nil || !bytes.Equal(pt, plain) {
				t.Fatalf("builtin cannot open hct ciphertext (%d): %v", n, err)
			}
			pt, err = hctG.Open(nil, nonce, want, aad)
			if err != nil || !bytes.Equal(pt, plain) {
				t.Fatalf("hct cannot open builtin ciphertext (%d): %v", n, err)
			}

			bad := append([]byte(nil), got...)
			bad[len(bad)-1] ^= 1
			if _, err := hctG.Open(nil, nonce, bad, aad); err == nil {
				t.Fatalf("hct accepted a tampered tag (%d)", n)
			}
		}
	})

	t.Run("SM2", func(t *testing.T) {
		priv, err := hctBackend.GenerateSM2KeyPair()
		if err != nil {
			t.Fatalf("hct keygen: %v", err)
		}
		// The generated key pair must be usable by gmsm too.
		if err := validateSM2PrivateKey(priv); err != nil {
			t.Fatalf("hct key pair invalid: %v", err)
		}
		msg := []byte("SM2 differential message")
		r, s, err := hctBackend.SignSM2(priv, nil, msg)
		if err != nil {
			t.Fatalf("hct sign: %v", err)
		}
		if !ref.VerifySM2(&priv.PublicKey, nil, msg, r, s) {
			t.Fatal("builtin cannot verify an HCT signature")
		}
		r2, s2, err := ref.SignSM2(priv, nil, msg)
		if err != nil {
			t.Fatalf("builtin sign: %v", err)
		}
		if !hctBackend.VerifySM2(&priv.PublicKey, nil, msg, r2, s2) {
			t.Fatal("HCT cannot verify a builtin signature")
		}
		customID := []byte("custom-user-id@taa")
		r3, s3, err := hctBackend.SignSM2(priv, customID, msg)
		if err != nil {
			t.Fatalf("hct sign (custom ID): %v", err)
		}
		if !ref.VerifySM2(&priv.PublicKey, customID, msg, r3, s3) {
			t.Fatal("builtin cannot verify an HCT signature with a custom user ID")
		}

		ct, err := hctBackend.EncryptSM2(&priv.PublicKey, msg)
		if err != nil {
			t.Fatalf("hct encrypt: %v", err)
		}
		pt, err := ref.DecryptSM2(priv, ct)
		if err != nil || !bytes.Equal(pt, msg) {
			t.Fatalf("builtin cannot decrypt HCT ciphertext: %v", err)
		}
		ct2, err := ref.EncryptSM2(&priv.PublicKey, msg)
		if err != nil {
			t.Fatalf("builtin encrypt: %v", err)
		}
		pt, err = hctBackend.DecryptSM2(priv, ct2)
		if err != nil || !bytes.Equal(pt, msg) {
			t.Fatalf("HCT cannot decrypt builtin ciphertext: %v", err)
		}
	})
}
