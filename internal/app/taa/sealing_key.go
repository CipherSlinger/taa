package taa

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"

	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
	"taa/pkg/csvattest"
)

// csvGuestDevicePath is the Hygon CSV guest node. Its presence is how TAA tells
// a confidential guest from an ordinary container: the node can only be created
// where the csv-guest driver is loaded, which is the guest kernel.
const csvGuestDevicePath = "/dev/csv-guest"

// hardwareSealingKeyFetcher fills keyBuf with the 32-byte Hygon CSV hardware
// sealing key. It is a function type so tests can run without a CSV device.
type hardwareSealingKeyFetcher func(keyBuf []byte) error

// detectStateSealingKeySource picks where the state sealing key should come
// from. A missing device node means this process is not inside a CSV guest, so
// the SM2 derivation is the only source available. Any other stat failure is
// treated as "the guest is there but the node is unreadable": the csv-hw path
// then fails at the fetch, which is what keeps a degraded guest from silently
// falling back to the weaker key.
func detectStateSealingKeySource(devicePath string) store.KeySource {
	if _, err := os.Stat(devicePath); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return store.KeySourceCSVHW
	}
	return store.KeySourceSM2
}

// fetchCSVHardwareSealingKey reads the sealing key from /dev/csv-guest.
func fetchCSVHardwareSealingKey(keyBuf []byte) error {
	return csvattest.NewClient().GetSealingKeyIOCTL(keyBuf)
}

// sealingKeyFingerprint returns a stable, non-reversible identifier for a key:
// the first 8 bytes of its SM3 digest, in hex. Two runs can be compared with it
// without exposing the key itself.
func sealingKeyFingerprint(key []byte) string {
	sum := teecrypto.SM3Sum(key)
	return fmt.Sprintf("%x", sum[:8])
}

// fetchStartupHardwareKey fetches the CSV hardware sealing key exactly once per
// startup. The caller owns the returned buffer and must clear it.
//
// There is no fallback: a missing device or a failed ioctl aborts startup.
func fetchStartupHardwareKey(fetch hardwareSealingKeyFetcher) ([]byte, error) {
	if fetch == nil {
		return nil, errors.New("csv-hw state sealing key source requires a hardware fetcher")
	}
	hwKey := make([]byte, teecrypto.CSVSealingKeySize)
	if err := fetch(hwKey); err != nil {
		clear(hwKey)
		return nil, fmt.Errorf("acquire CSV hardware sealing key via /dev/csv-guest: %w", err)
	}
	log.Printf("csv hardware sealing key fingerprint: %s", sealingKeyFingerprint(hwKey))
	return hwKey, nil
}

// resolveStateSealingKey returns the 16-byte SM4 key that seals the persistent
// state, together with the source it came from. hwKey is nil unless the source
// is csv-hw; it is fetched once by fetchStartupHardwareKey and shared with the
// taaSecretKey path.
func resolveStateSealingKey(
	source store.KeySource,
	privKey *teecrypto.SM2PrivateKey,
	hwKey []byte,
) ([]byte, store.KeySource, error) {
	switch source {
	case store.KeySourceSM2:
		key := store.DeriveSealingKey(privKey)
		if len(key) != 16 {
			return nil, "", fmt.Errorf("derive SM2 state sealing key: invalid length %d", len(key))
		}
		return key, store.KeySourceSM2, nil

	case store.KeySourceCSVHW:
		if len(hwKey) != teecrypto.CSVSealingKeySize {
			return nil, "", fmt.Errorf("csv-hw state sealing key source requires a %d-byte hardware key (got %d)",
				teecrypto.CSVSealingKeySize, len(hwKey))
		}
		key, err := teecrypto.DeriveSealingKeyFromCSV(hwKey)
		if err != nil {
			return nil, "", fmt.Errorf("derive state sealing key from CSV hardware key: %w", err)
		}
		return key, store.KeySourceCSVHW, nil

	default:
		return nil, "", fmt.Errorf("unsupported state sealing key source %q", source)
	}
}
