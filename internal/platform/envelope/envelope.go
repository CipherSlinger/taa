// Package envelope implements the TAA ↔ control platform message envelope:
// the business JSON is encrypted with the platform's SM2 public key and signed
// with TAA's SM2 private key, then carried as {dockerId, cipher, sign}.
//
// The package is deliberately transport-agnostic. It turns plaintext bytes into
// the outer JSON and back; it does not know about HTTP, routes, or retries. The
// wire contract it implements is documented in docs/taa-agent-delivery.md.
package envelope

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	teecrypto "taa/pkg/crypto"
)

// Envelope is the outer message both directions share.
//
// DockerID is sent by TAA and ignored on receipt: the platform addresses the
// instance by the endpoint it used, so a value in the body would be a second,
// unverified source of the same identity.
type Envelope struct {
	DockerID string `json:"dockerId,omitempty"`
	Cipher   string `json:"cipher"`
	Sign     string `json:"sign"`
}

// Keys holds everything needed to seal and open one instance's messages.
//
// All three fields are fixed at startup and read-only afterwards. Keeping them
// together matters for UserID: signing and verifying MUST use the same identity,
// and SM2 folds it into the digest (ZA = SM3(ENTLA || ID_A || ... a call with a
// mismatched ID produces a well-formed signature that simply never verifies).
// Making it part of the key material removes any way to pass the wrong one.
type Keys struct {
	PlatformPub *teecrypto.SM2PublicKey
	TAAPriv     *teecrypto.SM2PrivateKey
	UserID      []byte
}

// NewKeys builds the read-only key material, defaulting the SM2 identity.
//
// An empty userID means "use the protocol default", which is not an error: the
// default is a defined protocol value, not a missing setting. Anything else is
// used verbatim — no trimming, because an ID with stray whitespace is a
// different ID, and silently trimming it would hide a configuration mismatch
// that the receiving side reports only as "signature invalid".
func NewKeys(platformPub *teecrypto.SM2PublicKey, taaPriv *teecrypto.SM2PrivateKey, userID []byte) (*Keys, error) {
	if platformPub == nil {
		return nil, errors.New("envelope: platform public key is required")
	}
	if taaPriv == nil {
		return nil, errors.New("envelope: TAA private key is required")
	}
	if len(userID) == 0 {
		userID = teecrypto.SM2DefaultUserID
	}
	id := make([]byte, len(userID))
	copy(id, userID)
	return &Keys{PlatformPub: platformPub, TAAPriv: taaPriv, UserID: id}, nil
}

// Seal encrypts plaintext to the platform and signs it with TAA's key.
// The returned bytes are the outer JSON object, ready to POST.
//
// The signature covers the plaintext, not the ciphertext. Signing the
// ciphertext would let anyone who can encrypt to the platform public key mint a
// message TAA's own routes would accept.
func (k *Keys) Seal(plaintext []byte, dockerID string) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("envelope: plaintext is empty")
	}

	ciphertext, err := teecrypto.EncryptSM2(k.PlatformPub, plaintext)
	if err != nil {
		return nil, fmt.Errorf("envelope: encrypt: %w", err)
	}

	r, s, err := teecrypto.SignSM2Signature(k.TAAPriv, k.UserID, plaintext)
	if err != nil {
		return nil, fmt.Errorf("envelope: sign: %w", err)
	}
	der, err := teecrypto.MarshalSM2SignatureDER(r, s)
	if err != nil {
		return nil, fmt.Errorf("envelope: encode signature: %w", err)
	}

	return json.Marshal(Envelope{
		DockerID: dockerID,
		Cipher:   base64.StdEncoding.EncodeToString(ciphertext),
		Sign:     base64.StdEncoding.EncodeToString(der),
	})
}

// Open decrypts and verifies an inbound envelope, returning the plaintext.
//
// The order is fixed and load-bearing: decrypt, verify the signature over the
// decrypted bytes, and only then hand the bytes back. Callers parse JSON from
// the result; verifying after parsing (or re-serialising and verifying the
// re-serialised form) changes the bytes and the signature never matches.
//
// A nil return means both the decryption and the signature check passed. An
// error covers every other case, including a well-formed envelope with a bad
// signature, which is the shape an attacker can produce cheaply.
func (k *Keys) Open(env *Envelope) ([]byte, error) {
	if env == nil {
		return nil, errors.New("envelope: nil envelope")
	}
	if env.Cipher == "" {
		return nil, errors.New("envelope: missing cipher")
	}
	if env.Sign == "" {
		return nil, errors.New("envelope: missing sign")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(env.Cipher)
	if err != nil {
		return nil, fmt.Errorf("envelope: decode cipher: %w", err)
	}
	plaintext, err := teecrypto.DecryptSM2(k.TAAPriv, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("envelope: decrypt: %w", err)
	}

	der, err := base64.StdEncoding.DecodeString(env.Sign)
	if err != nil {
		return nil, fmt.Errorf("envelope: decode sign: %w", err)
	}
	r, s, err := teecrypto.UnmarshalSM2SignatureDER(der)
	if err != nil {
		return nil, fmt.Errorf("envelope: decode signature: %w", err)
	}
	if !teecrypto.VerifySM2Signature(k.PlatformPub, k.UserID, plaintext, r, s) {
		return nil, errors.New("envelope: signature verification failed")
	}

	return plaintext, nil
}

// Parse reads the outer JSON. It is separate from Open so a caller can tell
// "this is not an envelope at all" from "this is an envelope that failed to
// open" — the two deserve different responses while the platform is being
// migrated.
func Parse(body []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("envelope: parse: %w", err)
	}
	if env.Cipher == "" || env.Sign == "" {
		return nil, errors.New("envelope: missing cipher or sign")
	}
	return &env, nil
}
