package store

import (
	"errors"
	"fmt"
)

// KeySource identifies where the sealing key of a state file came from.
type KeySource string

const (
	// KeySourceSM2 is the legacy derivation from the SM2 private scalar.
	KeySourceSM2 KeySource = "sm2"
	// KeySourceCSVHW is the Hygon CSV hardware sealing key.
	KeySourceCSVHW KeySource = "csv-hw"
)

const (
	sealedStateMagic      = "TAAS"
	sealedStateHeaderSize = 8
	sealedStateFormatV1   = 1

	keySourceByteSM2   = 1
	keySourceByteCSVHW = 2
)

// ErrKeySourceMismatch reports a state file sealed with a different key source
// than the one the store is configured to use.
var ErrKeySourceMismatch = errors.New("sealed state key source mismatch")

func validKeySource(source KeySource) bool {
	_, ok := source.headerByte()
	return ok
}

func (s KeySource) headerByte() (byte, bool) {
	switch s {
	case KeySourceSM2:
		return keySourceByteSM2, true
	case KeySourceCSVHW:
		return keySourceByteCSVHW, true
	default:
		return 0, false
	}
}

func keySourceFromHeaderByte(b byte) (KeySource, bool) {
	switch b {
	case keySourceByteSM2:
		return KeySourceSM2, true
	case keySourceByteCSVHW:
		return KeySourceCSVHW, true
	default:
		return "", false
	}
}

// buildSealedStateHeader returns the 8-byte plaintext header for source.
func buildSealedStateHeader(source KeySource) ([]byte, error) {
	sourceByte, ok := source.headerByte()
	if !ok {
		return nil, fmt.Errorf("unsupported state key source %q", source)
	}

	header := make([]byte, sealedStateHeaderSize)
	copy(header[0:4], sealedStateMagic)
	header[4] = sealedStateFormatV1
	header[5] = sourceByte
	return header, nil
}

// splitSealedStateFile returns the stored key source and the SM4-GCM payload.
//
// Only a file whose header fields all validate is treated as the new format.
// Anything else is a legacy file, implicitly sealed with the SM2-derived key,
// and is returned unchanged. A legacy file starts with 12 random nonce bytes,
// so a full-header false positive is vanishingly unlikely.
func splitSealedStateFile(raw []byte) (KeySource, []byte) {
	if len(raw) >= sealedStateHeaderSize &&
		string(raw[0:4]) == sealedStateMagic &&
		raw[4] == sealedStateFormatV1 &&
		raw[6] == 0 && raw[7] == 0 {
		if source, ok := keySourceFromHeaderByte(raw[5]); ok {
			return source, raw[sealedStateHeaderSize:]
		}
	}
	return KeySourceSM2, raw
}
