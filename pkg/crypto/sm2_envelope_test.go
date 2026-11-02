package crypto

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// ── ParseSM2PublicKeyHex ─────────────────────────────────────────────────

func TestParseSM2PublicKeyHexRoundTrip(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	point, err := marshalSM2Point(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshalSM2Point: %v", err)
	}
	if len(point) != sm2PointSize {
		t.Fatalf("point length = %d, want %d", len(point), sm2PointSize)
	}

	parsed, err := ParseSM2PublicKeyHex(hex.EncodeToString(point))
	if err != nil {
		t.Fatalf("ParseSM2PublicKeyHex: %v", err)
	}
	if parsed.X.Cmp(priv.PublicKey.X) != 0 || parsed.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatalf("parsed public key differs from the original")
	}
}

// The platform publishes the key as hex, and an operator pasting it into an
// env file routinely leaves a trailing newline. Trimming is the only leniency
// applied; the point itself is still validated.
func TestParseSM2PublicKeyHexTrimsWhitespace(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	point, err := marshalSM2Point(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshalSM2Point: %v", err)
	}

	parsed, err := ParseSM2PublicKeyHex("  " + hex.EncodeToString(point) + "\n")
	if err != nil {
		t.Fatalf("ParseSM2PublicKeyHex: %v", err)
	}
	if parsed.X.Cmp(priv.PublicKey.X) != 0 {
		t.Fatalf("parsed public key differs from the original")
	}
}

func TestParseSM2PublicKeyHexRejectsBadInput(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	point, err := marshalSM2Point(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshalSM2Point: %v", err)
	}
	good := hex.EncodeToString(point)

	compressed := good[:2] + good[2:66] // 33-byte compressed form
	notOnCurve := "04" + good[2:66] + hex.EncodeToString(make([]byte, 32))

	cases := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t"},
		{"not hex", "zzzz"},
		{"odd length", good[:len(good)-1]},
		{"compressed form", compressed},
		{"point off the curve", notOnCurve},
		{"x coordinate out of range", "04" + hex.EncodeToString(make([]byte, 32)) + good[66:]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSM2PublicKeyHex(tc.value); err == nil {
				t.Fatalf("ParseSM2PublicKeyHex(%q) = nil error, want an error", tc.value)
			}
		})
	}
}

// ── DER signature ────────────────────────────────────────────────────────

func TestSM2SignatureDERRoundTrip(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	msg := []byte(`{"phase":2}`)

	r, s, err := SignSM2Signature(priv, SM2DefaultUserID, msg)
	if err != nil {
		t.Fatalf("SignSM2Signature: %v", err)
	}

	der, err := MarshalSM2SignatureDER(r, s)
	if err != nil {
		t.Fatalf("MarshalSM2SignatureDER: %v", err)
	}
	gotR, gotS, err := UnmarshalSM2SignatureDER(der)
	if err != nil {
		t.Fatalf("UnmarshalSM2SignatureDER: %v", err)
	}
	if gotR.Cmp(r) != 0 || gotS.Cmp(s) != 0 {
		t.Fatalf("round trip changed the signature: got (%v,%v), want (%v,%v)", gotR, gotS, r, s)
	}

	// The whole point of the DER layer is that the decoded pair still verifies.
	if !VerifySM2Signature(&priv.PublicKey, SM2DefaultUserID, msg, gotR, gotS) {
		t.Fatalf("signature no longer verifies after DER round trip")
	}
}

func TestUnmarshalSM2SignatureDERRejectsTrailingBytes(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	r, s, err := SignSM2Signature(priv, SM2DefaultUserID, []byte("m"))
	if err != nil {
		t.Fatalf("SignSM2Signature: %v", err)
	}
	der, err := MarshalSM2SignatureDER(r, s)
	if err != nil {
		t.Fatalf("MarshalSM2SignatureDER: %v", err)
	}

	if _, _, err := UnmarshalSM2SignatureDER(append(der, 0x00)); err == nil {
		t.Fatalf("UnmarshalSM2SignatureDER accepted trailing bytes, want an error")
	}
}

func TestUnmarshalSM2SignatureDERRejectsGarbage(t *testing.T) {
	for _, input := range [][]byte{nil, {}, {0x30}, {0x02, 0x01, 0x05}} {
		if _, _, err := UnmarshalSM2SignatureDER(input); err == nil {
			t.Fatalf("UnmarshalSM2SignatureDER(% x) = nil error, want an error", input)
		}
	}
}

func TestMarshalSM2SignatureDERRejectsNilComponents(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	r, s, err := SignSM2Signature(priv, SM2DefaultUserID, []byte("m"))
	if err != nil {
		t.Fatalf("SignSM2Signature: %v", err)
	}

	if _, err := MarshalSM2SignatureDER(nil, s); err == nil {
		t.Fatalf("MarshalSM2SignatureDER(nil, s) = nil error, want an error")
	}
	if _, err := MarshalSM2SignatureDER(r, nil); err == nil {
		t.Fatalf("MarshalSM2SignatureDER(r, nil) = nil error, want an error")
	}
}

// ── user ID ──────────────────────────────────────────────────────────────

// The ID is folded into the signed digest, so two peers using different IDs
// produce signatures neither can verify. This is the behaviour the envelope
// layer depends on: there is no "close enough", only match or mismatch.
func TestSM2SignatureRequiresMatchingUserID(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	msg := []byte(`{"phase":2}`)
	otherID := []byte("taa-platform-user")

	r, s, err := SignSM2Signature(priv, SM2DefaultUserID, msg)
	if err != nil {
		t.Fatalf("SignSM2Signature: %v", err)
	}

	if !VerifySM2Signature(&priv.PublicKey, SM2DefaultUserID, msg, r, s) {
		t.Fatalf("signature did not verify under the ID it was signed with")
	}
	if VerifySM2Signature(&priv.PublicKey, otherID, msg, r, s) {
		t.Fatalf("signature verified under a different user ID, want failure")
	}
}

// SM2 signatures carry a random nonce, so signing the same message twice yields
// different bytes. Any test that wants to assert "same ID was used" must do it
// by verification, never by comparing signatures.
func TestSM2SignatureIsRandomised(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	msg := []byte("same message")

	r1, s1, err := SignSM2Signature(priv, SM2DefaultUserID, msg)
	if err != nil {
		t.Fatalf("SignSM2Signature: %v", err)
	}
	r2, s2, err := SignSM2Signature(priv, SM2DefaultUserID, msg)
	if err != nil {
		t.Fatalf("SignSM2Signature: %v", err)
	}
	if r1.Cmp(r2) == 0 && s1.Cmp(s2) == 0 {
		t.Fatalf("two signatures over the same message are identical; the nonce is not random")
	}
}

func TestSM2DefaultUserIDValue(t *testing.T) {
	if got := string(SM2DefaultUserID); got != "1234567812345678" {
		t.Fatalf("SM2DefaultUserID = %q, want %q", got, "1234567812345678")
	}
}

// ── MarshalSM2PublicKeyHex ───────────────────────────────────────────────

// The published form is exactly the uncompressed point: 130 lowercase hex
// characters. Anything else is rejected by ParseSM2PublicKeyHex, so the
// encoder has to produce this and nothing more (no prefix, no padding).
func TestMarshalSM2PublicKeyHexShape(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	got, err := MarshalSM2PublicKeyHex(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalSM2PublicKeyHex: %v", err)
	}
	if len(got) != 2*sm2PointSize {
		t.Fatalf("hex length = %d, want %d", len(got), 2*sm2PointSize)
	}
	if !strings.HasPrefix(got, "04") {
		t.Fatalf("hex does not start with the uncompressed-point tag: %q", got[:2])
	}
	if strings.ToLower(got) != got {
		t.Fatalf("hex is not lowercase: %q", got)
	}

	parsed, err := ParseSM2PublicKeyHex(got)
	if err != nil {
		t.Fatalf("ParseSM2PublicKeyHex: %v", err)
	}
	if parsed.X.Cmp(priv.PublicKey.X) != 0 || parsed.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("round trip changed the public key")
	}
}

// A key that is not a valid curve point must not be rendered: the string it
// produced would look publishable but no peer could ever use it.
func TestMarshalSM2PublicKeyHexRejectsOffCurvePoint(t *testing.T) {
	pub := &SM2PublicKey{X: big.NewInt(1), Y: big.NewInt(1)}
	if _, err := MarshalSM2PublicKeyHex(pub); err == nil {
		t.Fatal("expected an off-curve point to be rejected")
	}
	if _, err := MarshalSM2PublicKeyHex(nil); err == nil {
		t.Fatal("expected a nil key to be rejected")
	}
}
