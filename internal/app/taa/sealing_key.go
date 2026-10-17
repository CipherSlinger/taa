package taa

import (
	"errors"
	"fmt"

	"taa/internal/config"
	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
	"taa/pkg/csvattest"
)

// hardwareSealingKeyFetcher fills keyBuf with the 32-byte Hygon CSV hardware
// sealing key. It is a function type so tests can run without a CSV device.
type hardwareSealingKeyFetcher func(keyBuf []byte) error

// fetchCSVHardwareSealingKey reads the sealing key from /dev/csv-guest.
func fetchCSVHardwareSealingKey(keyBuf []byte) error {
	return csvattest.NewClient().GetSealingKeyIOCTL(keyBuf)
}

// resolveStateSealingKey returns the 16-byte SM4 key that seals the persistent
// state, together with the source it came from.
//
// csv-hw has no fallback: a missing device, a failed ioctl, or an unusable key
// aborts startup. sm2 keeps the legacy derivation.
func resolveStateSealingKey(
	source string,
	privKey *teecrypto.SM2PrivateKey,
	fetch hardwareSealingKeyFetcher,
) ([]byte, store.KeySource, error) {
	switch source {
	case config.StateSealingKeySourceSM2:
		key := store.DeriveSealingKey(privKey)
		if len(key) != 16 {
			return nil, "", fmt.Errorf("derive SM2 state sealing key: invalid length %d", len(key))
		}
		return key, store.KeySourceSM2, nil

	case config.StateSealingKeySourceCSVHW:
		if fetch == nil {
			return nil, "", errors.New("csv-hw state sealing key source requires a hardware fetcher")
		}
		hwKey := make([]byte, csvattest.SealingKeySize)
		defer clear(hwKey)
		if err := fetch(hwKey); err != nil {
			return nil, "", fmt.Errorf("acquire CSV hardware sealing key via /dev/csv-guest: %w", err)
		}
		key, err := teecrypto.DeriveSealingKeyFromCSV(hwKey)
		if err != nil {
			return nil, "", fmt.Errorf("derive state sealing key from CSV hardware key: %w", err)
		}
		return key, store.KeySourceCSVHW, nil

	default:
		return nil, "", fmt.Errorf("unsupported storage.stateSealingKeySource %q", source)
	}
}
