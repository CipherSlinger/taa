package taa

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	teecrypto "taa/pkg/crypto"
	"taa/pkg/csvattest"
)

const (
	// taaSecretKeyEnv carries a previously reported taaSecretKey back into the
	// instance after its key directory was lost.
	taaSecretKeyEnv = "TAASECRETKEY"

	// taaSecretKeyCiphertextSize is nonce(12) || scalar(32) || tag(16).
	taaSecretKeyCiphertextSize = 12 + teecrypto.SM2ScalarSize + 16

	// taaSecretSM4KeySize is the truncated SM3 digest used as the SM4 key.
	taaSecretSM4KeySize = 16
)

// deriveTAASecretSM4Key derives the SM4 key that wraps the TAA SM2 private key:
// SM3(hardware key || CONTRACT)[:16]. The construction is a wire contract with
// the platform, so it must not add a domain label or a separator.
func deriveTAASecretSM4Key(hwKey []byte, contract string) ([]byte, error) {
	if len(hwKey) != csvattest.SealingKeySize {
		return nil, fmt.Errorf("derive taaSecretKey: hardware key length %d, want %d",
			len(hwKey), csvattest.SealingKeySize)
	}

	material := make([]byte, 0, len(hwKey)+len(contract))
	material = append(material, hwKey...)
	material = append(material, contract...)
	defer clear(material)

	sum := teecrypto.SM3Sum(material)
	defer clear(sum[:])

	key := make([]byte, taaSecretSM4KeySize)
	copy(key, sum[:taaSecretSM4KeySize])
	return key, nil
}

// sealTAASecretKey wraps the raw 32-byte scalar of the TAA SM2 private key and
// returns the lowercase hex ciphertext reported to the platform.
func sealTAASecretKey(hwKey []byte, contract string, priv *teecrypto.SM2PrivateKey) (string, error) {
	if priv == nil || priv.D == nil {
		return "", errors.New("seal taaSecretKey: private key is empty")
	}

	sk, err := deriveTAASecretSM4Key(hwKey, contract)
	if err != nil {
		return "", err
	}
	defer clear(sk)

	scalar := priv.ScalarBytes()
	defer clear(scalar)

	ciphertext, err := teecrypto.Encrypt(sk, scalar)
	if err != nil {
		return "", fmt.Errorf("seal taaSecretKey: %w", err)
	}
	return hex.EncodeToString(ciphertext), nil
}

// openTAASecretKey reverses sealTAASecretKey and rebuilds the public key from
// the recovered scalar. Every failure is fatal for the caller: a silently
// ignored recovery request would register a key the platform does not expect.
func openTAASecretKey(hwKey []byte, contract, encoded string) (*teecrypto.SM2PrivateKey, error) {
	ciphertext, err := hex.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", taaSecretKeyEnv, err)
	}
	if len(ciphertext) != taaSecretKeyCiphertextSize {
		return nil, fmt.Errorf("%s decodes to %d bytes, want %d",
			taaSecretKeyEnv, len(ciphertext), taaSecretKeyCiphertextSize)
	}

	sk, err := deriveTAASecretSM4Key(hwKey, contract)
	if err != nil {
		return nil, err
	}
	defer clear(sk)

	plaintext, err := teecrypto.Decrypt(sk, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", taaSecretKeyEnv, err)
	}
	defer clear(plaintext)

	priv, err := teecrypto.NewSM2PrivateKeyFromScalar(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parse recovered SM2 private key: %w", err)
	}
	return priv, nil
}
