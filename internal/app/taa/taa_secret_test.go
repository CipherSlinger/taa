package taa

import (
	"encoding/hex"
	"strings"
	"testing"

	teecrypto "taa/pkg/crypto"
)

func TestDeriveTAASecretSM4KeyMatchesProtocol(t *testing.T) {
	hwKey := testHardwareKey()
	const contract = "contract-123"

	got, err := deriveTAASecretSM4Key(hwKey, contract)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got) != taaSecretSM4KeySize {
		t.Fatalf("derived key length = %d, want %d", len(got), taaSecretSM4KeySize)
	}

	// Pinned vector: SM3(hwKey || "contract-123")[:16], cross-checked with
	// `printf ... | openssl dgst -sm3`.
	const want = "f6ab3a88bec5b52eeabf24a0cbf23e09"
	if hex.EncodeToString(got) != want {
		t.Fatalf("derived key = %x, want %s", got, want)
	}

	material := append(append([]byte{}, hwKey...), []byte(contract)...)
	sum := teecrypto.SM3Sum(material)
	if hex.EncodeToString(got) != hex.EncodeToString(sum[:taaSecretSM4KeySize]) {
		t.Fatal("derived key is not the first 16 bytes of SM3(hwKey || contract)")
	}
}

func TestDeriveTAASecretSM4KeyRejectsWrongHardwareKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33} {
		if _, err := deriveTAASecretSM4Key(make([]byte, size), "c"); err == nil {
			t.Fatalf("%d-byte hardware key: expected an error", size)
		}
	}
}

func TestSealOpenTAASecretKeyRoundTrip(t *testing.T) {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	hwKey := testHardwareKey()
	const contract = "contract-123"

	encoded, err := sealTAASecretKey(hwKey, contract, priv)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(encoded) != 2*taaSecretKeyCiphertextSize {
		t.Fatalf("hex length = %d, want %d", len(encoded), 2*taaSecretKeyCiphertextSize)
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		t.Fatalf("ciphertext is not hex: %v", err)
	}

	recovered, err := openTAASecretKey(hwKey, contract, encoded)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if recovered.D.Cmp(priv.D) != 0 {
		t.Fatal("recovered scalar differs from the original")
	}
	if recovered.PublicKey.X.Cmp(priv.PublicKey.X) != 0 ||
		recovered.PublicKey.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("recovered public key differs from the original")
	}
}

func TestOpenTAASecretKeyRejectsMismatchedInputs(t *testing.T) {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	hwKey := testHardwareKey()
	const contract = "contract-123"

	encoded, err := sealTAASecretKey(hwKey, contract, priv)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	tampered := []byte(strings.TrimSpace(encoded))
	if tampered[10] == '0' {
		tampered[10] = '1'
	} else {
		tampered[10] = '0'
	}

	shortKey := append([]byte{}, hwKey...)
	shortKey[0] ^= 0xff

	sk, err := deriveTAASecretSM4Key(hwKey, contract)
	if err != nil {
		t.Fatalf("derive sk: %v", err)
	}
	zeroScalar, err := teecrypto.Encrypt(sk, make([]byte, teecrypto.SM2ScalarSize))
	if err != nil {
		t.Fatalf("encrypt zero scalar: %v", err)
	}

	cases := []struct {
		name     string
		hwKey    []byte
		contract string
		encoded  string
	}{
		{name: "wrong contract", hwKey: hwKey, contract: "other-contract", encoded: encoded},
		{name: "wrong hardware key", hwKey: shortKey, contract: contract, encoded: encoded},
		{name: "tampered ciphertext", hwKey: hwKey, contract: contract, encoded: string(tampered)},
		{name: "not hex", hwKey: hwKey, contract: contract, encoded: "zz" + encoded[2:]},
		{name: "truncated ciphertext", hwKey: hwKey, contract: contract, encoded: encoded[:len(encoded)-2]},
		{name: "zero scalar", hwKey: hwKey, contract: contract, encoded: hex.EncodeToString(zeroScalar)},
		{name: "empty", hwKey: hwKey, contract: contract, encoded: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := openTAASecretKey(tc.hwKey, tc.contract, tc.encoded); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSealTAASecretKeyRejectsMissingPrivateKey(t *testing.T) {
	if _, err := sealTAASecretKey(testHardwareKey(), "c", nil); err == nil {
		t.Fatal("expected an error for a nil private key")
	}
	if _, err := sealTAASecretKey(testHardwareKey(), "c", &teecrypto.SM2PrivateKey{}); err == nil {
		t.Fatal("expected an error for a private key without a scalar")
	}
}
