package taa

import (
	"fmt"
	"log"
	"strings"

	"taa/internal/config"
	"taa/internal/platform/envelope"
	teecrypto "taa/pkg/crypto"
)

// resolveEnvelopeKeys assembles the TAA <-> platform envelope key material from
// the startup config and this instance's SM2 key pair.
//
// A missing or unparseable platform public key is a startup error, not a
// warning. There is no plaintext mode to fall back to: the platform will
// reject an unsealed request anyway, so continuing would only turn "this
// instance cannot talk to the platform" into a series of runtime failures
// after the process has already reported itself ready.
//
// An empty SM2 ID is not an error. It means the protocol default, which is a
// defined value rather than a missing setting (see envelope.NewKeys).
func resolveEnvelopeKeys(cfg config.StartupConfig, taaKey *teecrypto.SM2PrivateKey) (*envelope.Keys, error) {
	if taaKey == nil {
		return nil, fmt.Errorf("build envelope key material: TAA private key is missing")
	}

	rawKey := strings.TrimSpace(cfg.PlatformPublicKey)
	if rawKey == "" {
		return nil, fmt.Errorf("PLATFORM_PUBLIC_KEY is not set and platform.publicKey is absent from the startup config: " +
			"the control platform's SM2 public key is required to seal and verify every message")
	}
	platformPub, err := teecrypto.ParseSM2PublicKeyHex(rawKey)
	if err != nil {
		return nil, fmt.Errorf("parse the platform SM2 public key: %w", err)
	}

	// The ID is used verbatim: it is a protocol parameter, and whitespace in it
	// is a different ID, not a formatting mistake. Trimming would hide a
	// mismatch that the receiving side only reports as "signature invalid".
	keys, err := envelope.NewKeys(platformPub, taaKey, []byte(cfg.PlatformSM2ID))
	if err != nil {
		return nil, fmt.Errorf("build envelope key material: %w", err)
	}

	// Log the effective ID: it is a public parameter, and a mismatch is
	// invisible on this side - the only symptom is that the platform rejects our
	// signatures - so the value has to be visible to compare against the
	// platform's configuration.
	log.Printf("[INFO] [envelope] SM2 identity in effect: %q", string(keys.UserID))
	return keys, nil
}
