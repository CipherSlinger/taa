package envelope

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	teecrypto "taa/pkg/crypto"
)

// SealForPlatform produces an envelope on the platform's behalf: encrypted to
// TAA's public key and signed with the platform's private key.
//
// It is the mirror image of Keys.Seal, which only ever produces TAA's half of
// the conversation. Keeping both directions in one package means a caller
// cannot pair the wrong key with the wrong direction, which yields a
// well-formed message that simply never opens.
//
// Production code does not call this; it exists for tools/platform-mock and for
// tests playing the platform's role. It lives in the package rather than a
// _test file because the mock is a separate module and cannot import test
// files.
//
// userID nil means the protocol default. A deployment that sets
// PLATFORM_SM2_ID must pass the same value here, or the signature will not
// verify on TAA's side.
func SealForPlatform(platformPriv *teecrypto.SM2PrivateKey, taaPub *teecrypto.SM2PublicKey, userID []byte, plaintext []byte) ([]byte, error) {
	return sealWith(platformPriv, taaPub, userIDOrDefault(userID), plaintext, "")
}

// OpenFromPlatform opens a message TAA sealed, using the platform's private key
// and TAA's public key. Same asymmetry as SealForPlatform.
func OpenFromPlatform(platformPriv *teecrypto.SM2PrivateKey, taaPub *teecrypto.SM2PublicKey, userID []byte, env *Envelope) ([]byte, error) {
	if platformPriv == nil {
		return nil, errors.New("envelope: platform private key is required")
	}
	if taaPub == nil {
		return nil, errors.New("envelope: TAA public key is required")
	}
	return openWith(platformPriv, taaPub, userIDOrDefault(userID), env)
}

// userIDOrDefault resolves nil to the protocol identity. It returns the
// caller's slice unchanged (not a copy): callers of sealWith/openWith do not
// retain it, and Keys.NewKeys owns the copy for the long-lived case.
func userIDOrDefault(userID []byte) []byte {
	if len(userID) == 0 {
		return teecrypto.SM2DefaultUserID
	}
	return userID
}

func sealWith(senderPriv *teecrypto.SM2PrivateKey, recipientPub *teecrypto.SM2PublicKey, userID []byte, plaintext []byte, dockerID string) ([]byte, error) {
	if senderPriv == nil {
		return nil, errors.New("envelope: sender private key is required")
	}
	if recipientPub == nil {
		return nil, errors.New("envelope: recipient public key is required")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("envelope: plaintext is empty")
	}

	ciphertext, err := teecrypto.EncryptSM2(recipientPub, plaintext)
	if err != nil {
		return nil, fmt.Errorf("envelope: encrypt: %w", err)
	}
	r, s, err := teecrypto.SignSM2Signature(senderPriv, userID, plaintext)
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

func openWith(recipientPriv *teecrypto.SM2PrivateKey, senderPub *teecrypto.SM2PublicKey, userID []byte, env *Envelope) ([]byte, error) {
	if env == nil {
		return nil, errors.New("envelope: nil envelope")
	}
	if env.Cipher == "" || env.Sign == "" {
		return nil, errors.New("envelope: missing cipher or sign")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(env.Cipher)
	if err != nil {
		return nil, fmt.Errorf("envelope: decode cipher: %w", err)
	}
	plaintext, err := teecrypto.DecryptSM2(recipientPriv, ciphertext)
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
	if !teecrypto.VerifySM2Signature(senderPub, userID, plaintext, r, s) {
		return nil, errors.New("envelope: signature verification failed")
	}
	return plaintext, nil
}
