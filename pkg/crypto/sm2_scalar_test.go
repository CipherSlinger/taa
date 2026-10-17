package crypto

import (
	"math/big"
	"testing"
)

func TestNewSM2PrivateKeyFromScalarRoundTrip(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	scalar := priv.ScalarBytes()
	if len(scalar) != SM2ScalarSize {
		t.Fatalf("ScalarBytes length = %d, want %d", len(scalar), SM2ScalarSize)
	}

	recovered, err := NewSM2PrivateKeyFromScalar(scalar)
	if err != nil {
		t.Fatalf("NewSM2PrivateKeyFromScalar: %v", err)
	}
	if recovered.D.Cmp(priv.D) != 0 {
		t.Fatalf("recovered scalar differs from the original")
	}
	if recovered.PublicKey.X.Cmp(priv.PublicKey.X) != 0 ||
		recovered.PublicKey.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatalf("recovered public key differs from the original")
	}
}

func TestScalarBytesLeftPadsSmallValues(t *testing.T) {
	scalar := make([]byte, SM2ScalarSize)
	scalar[SM2ScalarSize-1] = 1

	priv, err := NewSM2PrivateKeyFromScalar(scalar)
	if err != nil {
		t.Fatalf("NewSM2PrivateKeyFromScalar: %v", err)
	}
	if !priv.D.IsInt64() || priv.D.Int64() != 1 {
		t.Fatalf("D = %s, want 1", priv.D)
	}
	if got := priv.ScalarBytes(); string(got) != string(scalar) {
		t.Fatalf("ScalarBytes = %x, want %x", got, scalar)
	}
}

func TestNewSM2PrivateKeyFromScalarRejectsInvalidScalars(t *testing.T) {
	zero := make([]byte, SM2ScalarSize)
	order := make([]byte, SM2ScalarSize)
	sm2Curve.Params().N.FillBytes(order)
	tooLarge := new(big.Int).Add(sm2Curve.Params().N, big.NewInt(1)).Bytes()

	cases := []struct {
		name   string
		scalar []byte
	}{
		{name: "nil", scalar: nil},
		{name: "empty", scalar: []byte{}},
		{name: "31 bytes", scalar: make([]byte, SM2ScalarSize-1)},
		{name: "33 bytes", scalar: make([]byte, SM2ScalarSize+1)},
		{name: "zero", scalar: zero},
		{name: "equals N", scalar: order},
		{name: "larger than N", scalar: tooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSM2PrivateKeyFromScalar(tc.scalar); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestScalarBytesNilReceiver(t *testing.T) {
	var priv *SM2PrivateKey
	if got := priv.ScalarBytes(); got != nil {
		t.Fatalf("ScalarBytes on a nil key = %x, want nil", got)
	}
}
