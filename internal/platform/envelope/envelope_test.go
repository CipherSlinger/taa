package envelope

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	teecrypto "taa/pkg/crypto"
)

// ── test peer ────────────────────────────────────────────────────────────
//
// Seal and Open are not inverses of each other, and that is the protocol, not
// an omission. TAA seals TO the platform (encrypt with the platform public key,
// sign with its own private key) and opens FROM the platform (decrypt with its
// own private key, verify with the platform public key). A round trip therefore
// needs both parties, not one.
//
// peer is the platform's half of the exchange: it holds the platform private
// key and TAA's public key, exactly the material the real platform has after
// registration.

type peer struct {
	priv   *teecrypto.SM2PrivateKey // platform private key
	taaPub *teecrypto.SM2PublicKey  // TAA public key, learned at registration
	userID []byte
}

// fixture builds a TAA-side Keys plus the matching peer, sharing one user ID.
func fixture(t *testing.T, userID []byte) (*Keys, *peer) {
	t.Helper()

	platformPriv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate platform key: %v", err)
	}
	taaPriv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate TAA key: %v", err)
	}

	taaSide, err := NewKeys(&platformPriv.PublicKey, taaPriv, userID)
	if err != nil {
		t.Fatalf("NewKeys: %v", err)
	}
	p := &peer{priv: platformPriv, taaPub: &taaPriv.PublicKey, userID: taaSide.UserID}
	return taaSide, p
}

// seal builds a message the platform would send to TAA: encrypted to TAA's
// public key, signed with the platform private key.
func (p *peer) seal(t *testing.T, plaintext []byte) *Envelope {
	t.Helper()
	ciphertext, err := teecrypto.EncryptSM2(p.taaPub, plaintext)
	if err != nil {
		t.Fatalf("peer encrypt: %v", err)
	}
	r, s, err := teecrypto.SignSM2Signature(p.priv, p.userID, plaintext)
	if err != nil {
		t.Fatalf("peer sign: %v", err)
	}
	der, err := teecrypto.MarshalSM2SignatureDER(r, s)
	if err != nil {
		t.Fatalf("peer marshal signature: %v", err)
	}
	return &Envelope{
		Cipher: base64.StdEncoding.EncodeToString(ciphertext),
		Sign:   base64.StdEncoding.EncodeToString(der),
	}
}

// open reads what TAA sealed: decrypt with the platform private key, verify
// with TAA's public key. This is the platform's receive path.
func (p *peer) open(t *testing.T, env *Envelope) []byte {
	t.Helper()
	ciphertext, err := base64.StdEncoding.DecodeString(env.Cipher)
	if err != nil {
		t.Fatalf("peer decode cipher: %v", err)
	}
	plaintext, err := teecrypto.DecryptSM2(p.priv, ciphertext)
	if err != nil {
		t.Fatalf("peer decrypt: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(env.Sign)
	if err != nil {
		t.Fatalf("peer decode sign: %v", err)
	}
	r, s, err := teecrypto.UnmarshalSM2SignatureDER(der)
	if err != nil {
		t.Fatalf("peer decode signature: %v", err)
	}
	if !teecrypto.VerifySM2Signature(p.taaPub, p.userID, plaintext, r, s) {
		t.Fatalf("peer could not verify TAA's signature")
	}
	return plaintext
}

const sampleBody = `{"phase":2,"note":"中文也要能过"}`

// ── outbound (TAA seals → platform opens) ────────────────────────────────

func TestSealProducesWhatThePlatformCanOpen(t *testing.T) {
	keys, p := fixture(t, nil)

	sealed, err := keys.Seal([]byte(sampleBody), "dock-1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// The outer shape is the contract: dockerId, cipher, sign and nothing else.
	var outer map[string]any
	if err := json.Unmarshal(sealed, &outer); err != nil {
		t.Fatalf("sealed output is not JSON: %v", err)
	}
	for _, field := range []string{"dockerId", "cipher", "sign"} {
		if _, ok := outer[field]; !ok {
			t.Fatalf("sealed output is missing %q: %s", field, sealed)
		}
	}
	if len(outer) != 3 {
		t.Fatalf("sealed output has %d fields, want exactly 3: %s", len(outer), sealed)
	}
	if outer["dockerId"] != "dock-1" {
		t.Fatalf("dockerId = %v, want dock-1", outer["dockerId"])
	}

	env, err := Parse(sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := string(p.open(t, env)); got != sampleBody {
		t.Fatalf("platform read %q, want %q", got, sampleBody)
	}
}

// ── inbound (platform seals → TAA opens) ─────────────────────────────────

func TestOpenAcceptsWhatThePlatformSealed(t *testing.T) {
	keys, p := fixture(t, nil)

	got, err := keys.Open(p.seal(t, []byte(sampleBody)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != sampleBody {
		t.Fatalf("Open returned %q, want %q", got, sampleBody)
	}
}

// The plaintext must not survive in the outer JSON. A weak check, but it is the
// one thing that would go unnoticed if encryption silently regressed to a
// pass-through.
func TestSealDoesNotLeakPlaintext(t *testing.T) {
	keys, _ := fixture(t, nil)
	sealed, err := keys.Seal([]byte(`{"secret":"do-not-leak"}`), "dock-1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(string(sealed), "do-not-leak") {
		t.Fatalf("plaintext appears in the sealed output: %s", sealed)
	}
}

// Cipher is base64 of the raw C1C3C2 point, not hex and not base64-of-hex.
// A double-encoded cipher still "looks fine" until it reaches the platform.
func TestSealCipherIsRawC1C3C2Base64(t *testing.T) {
	keys, _ := fixture(t, nil)
	sealed, err := keys.Seal([]byte(sampleBody), "dock-1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env, err := Parse(sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(env.Cipher)
	if err != nil {
		t.Fatalf("cipher is not base64: %v", err)
	}
	// 04 || x1(32) || y1(32) || c3(32) || c2(len)
	if want := 1 + 32 + 32 + 32 + len(sampleBody); len(raw) != want {
		t.Fatalf("cipher length = %d, want %d", len(raw), want)
	}
	if raw[0] != 0x04 {
		t.Fatalf("cipher does not start with the uncompressed point marker: 0x%02x", raw[0])
	}
}

// ── rejection paths ──────────────────────────────────────────────────────

// Re-encrypting different content under TAA's public key is exactly what anyone
// who can read the platform public key can do. The ciphertext is valid; only
// the signature can catch it.
func TestOpenRejectsReEncryptedBody(t *testing.T) {
	keys, p := fixture(t, nil)
	env := p.taaPubEnv(t, keys)

	forged, err := teecrypto.EncryptSM2(p.taaPub, []byte(`{"phase":3}`))
	if err != nil {
		t.Fatalf("EncryptSM2: %v", err)
	}
	env.Cipher = base64.StdEncoding.EncodeToString(forged)

	if _, err := keys.Open(env); err == nil {
		t.Fatalf("Open accepted a re-encrypted body under the original signature")
	}
}

func TestOpenRejectsTamperedSignature(t *testing.T) {
	keys, p := fixture(t, nil)
	env := p.taaPubEnv(t, keys)

	der, err := base64.StdEncoding.DecodeString(env.Sign)
	if err != nil {
		t.Fatalf("sign is not base64: %v", err)
	}
	der[len(der)-1] ^= 0xff
	env.Sign = base64.StdEncoding.EncodeToString(der)

	if _, err := keys.Open(env); err == nil {
		t.Fatalf("Open accepted a corrupted signature")
	}
}

func TestOpenRejectsWrongPlatformKey(t *testing.T) {
	keys, p := fixture(t, nil)
	env := p.taaPubEnv(t, keys)

	// Same TAA key (so decryption still succeeds), different platform identity:
	// the signature verify is the only thing that can catch this.
	otherPriv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	wrong, err := NewKeys(&otherPriv.PublicKey, keys.TAAPriv, nil)
	if err != nil {
		t.Fatalf("NewKeys: %v", err)
	}
	if _, err := wrong.Open(env); err == nil {
		t.Fatalf("Open accepted an envelope signed by an unknown platform key")
	}
}

func TestOpenRejectsWrongTAAKey(t *testing.T) {
	keys, p := fixture(t, nil)
	env := p.taaPubEnv(t, keys)

	otherPriv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	wrong, err := NewKeys(keys.PlatformPub, otherPriv, nil)
	if err != nil {
		t.Fatalf("NewKeys: %v", err)
	}
	if _, err := wrong.Open(env); err == nil {
		t.Fatalf("Open accepted an envelope addressed to a different TAA key")
	}
}

// The ID is part of the key material, so a peer configured with a different
// PLATFORM_SM2_ID cannot verify our signature. This is the failure mode an
// operator sees when the two sides disagree, and it must not be mistakable for
// success.
func TestOpenRejectsMismatchedUserID(t *testing.T) {
	keys, p := fixture(t, nil)
	env := p.taaPubEnv(t, keys)

	wrong, err := NewKeys(keys.PlatformPub, keys.TAAPriv, []byte("a-different-id"))
	if err != nil {
		t.Fatalf("NewKeys: %v", err)
	}
	if _, err := wrong.Open(env); err == nil {
		t.Fatalf("Open verified a signature under a different SM2 user ID")
	}
}

func TestOpenRejectsMalformedEnvelopes(t *testing.T) {
	keys, _ := fixture(t, nil)
	cases := []struct {
		name string
		env  *Envelope
	}{
		{"nil envelope", nil},
		{"empty cipher", &Envelope{Sign: "AAAA"}},
		{"empty sign", &Envelope{Cipher: "AAAA"}},
		{"cipher not base64", &Envelope{Cipher: "!!!", Sign: "AAAA"}},
		{"sign not base64", &Envelope{Cipher: "AAAA", Sign: "!!!"}},
		// Short ciphertexts used to panic inside gmsm rather than error out.
		{"one byte cipher", &Envelope{Cipher: "BA==", Sign: "AAAA"}},
		{"three byte cipher", &Envelope{Cipher: base64.StdEncoding.EncodeToString([]byte{0x04, 0x01, 0x02}), Sign: "AAAA"}},
		{"zero filled 96 bytes", &Envelope{
			Cipher: base64.StdEncoding.EncodeToString(make([]byte, 96)),
			Sign:   base64.StdEncoding.EncodeToString([]byte{0x30, 0x00}),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keys.Open(tc.env); err == nil {
				t.Fatalf("Open(%+v) = nil error, want an error", tc.env)
			}
		})
	}
}

func TestParseRejectsNonEnvelopes(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"plain business body", `{"phase":2}`},
		{"empty object", `{}`},
		{"only dockerId", `{"dockerId":"dock-1"}`},
		{"not json", `phase=2`},
		{"empty body", ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.body)); err == nil {
				t.Fatalf("Parse(%q) = nil error, want an error", tc.body)
			}
		})
	}
}

// ── keys ─────────────────────────────────────────────────────────────────

func TestNewKeysDefaultsUserID(t *testing.T) {
	keys, _ := fixture(t, nil)
	if string(keys.UserID) != string(teecrypto.SM2DefaultUserID) {
		t.Fatalf("UserID = %q, want the protocol default %q", keys.UserID, teecrypto.SM2DefaultUserID)
	}
}

// The ID is used verbatim: no trimming. A value with whitespace is a different
// ID, and silently normalising it would make the two sides disagree in a way
// that only shows up as "signature invalid" on the other end.
func TestNewKeysKeepsUserIDVerbatim(t *testing.T) {
	id := []byte(" 1234567812345678 ")
	keys, _ := fixture(t, id)
	if string(keys.UserID) != string(id) {
		t.Fatalf("UserID = %q, want %q unchanged", keys.UserID, id)
	}
}

func TestNewKeysCopiesUserID(t *testing.T) {
	id := []byte("1234567812345678")
	keys, _ := fixture(t, id)
	id[0] = 'X'
	if keys.UserID[0] == 'X' {
		t.Fatalf("Keys.UserID aliases the caller's slice")
	}
}

func TestNewKeysRejectsMissingKeys(t *testing.T) {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	if _, err := NewKeys(nil, priv, nil); err == nil {
		t.Fatalf("NewKeys accepted a nil platform key")
	}
	if _, err := NewKeys(&priv.PublicKey, nil, nil); err == nil {
		t.Fatalf("NewKeys accepted a nil TAA key")
	}
}

func TestSealRejectsEmptyPlaintext(t *testing.T) {
	keys, _ := fixture(t, nil)
	if _, err := keys.Seal(nil, "dock-1"); err == nil {
		t.Fatalf("Seal accepted an empty plaintext")
	}
}

// taaPubEnv returns a fresh envelope from the peer addressed to this TAA
// instance, so a test can corrupt one field without affecting the others.
func (p *peer) taaPubEnv(t *testing.T, _ *Keys) *Envelope {
	t.Helper()
	return p.seal(t, []byte(sampleBody))
}
