package attestation

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Binary layout of the CSV attestation report. The same offsets are declared as
// OffsetReport* in sdk/attestation, which verifies the identical report format.
const (
	// reportSize is the full report size in bytes.
	reportSize = 0x9f4

	// Field offsets within the report.
	offsetUserData = 0x040
	offsetMNonce   = 0x080
	offsetDigest   = 0x090
	offsetANonce   = 0x0bc
	offsetChipID   = 0x974

	// Field lengths in bytes.
	sizeUserData = 64
	sizeMNonce   = 16
	sizeDigest   = 32
	sizeANonce   = 4
	sizeChipID   = 64
)

// ReportValues contains the key fields extracted from an attestation report,
// already restored from their ANONCE mask.
// These fields are sent as JSON in the attestationValues field during registration.
type ReportValues struct {
	UserData string `json:"userdata"` // 64 bytes, hex encoded: TAA SM2 public key X||Y
	MNonce   string `json:"mnonce"`   // 16 bytes, hex encoded
	Digest   string `json:"digest"`   // 32 bytes, hex encoded
	ChipID   string `json:"chipId"`   // ASCII string, trailing NUL padding removed
}

// ExtractReportValues parses an attestation report file, restores the key fields
// from their ANONCE mask, and returns them as a JSON-encoded string.
func ExtractReportValues(reportPath string) (string, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return "", fmt.Errorf("read report file: %w", err)
	}

	if len(data) < reportSize {
		return "", fmt.Errorf("report too short: %d bytes, expected at least %d", len(data), reportSize)
	}

	// ANONCE itself is stored unmasked and is the key for every other field.
	anonce := binary.LittleEndian.Uint32(data[offsetANonce : offsetANonce+sizeANonce])
	userData := unmaskWords(data[offsetUserData:offsetUserData+sizeUserData], anonce)
	mnonce := unmaskWords(data[offsetMNonce:offsetMNonce+sizeMNonce], anonce)
	digest := unmaskWords(data[offsetDigest:offsetDigest+sizeDigest], anonce)
	chipID := unmaskWords(data[offsetChipID:offsetChipID+sizeChipID], anonce)

	values := ReportValues{
		UserData: hex.EncodeToString(userData),
		MNonce:   hex.EncodeToString(mnonce),
		Digest:   hex.EncodeToString(digest),
		ChipID:   strings.TrimRight(string(chipID), "\x00"),
	}

	jsonBytes, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("marshal report values: %w", err)
	}

	return string(jsonBytes), nil
}

func unmaskWords(masked []byte, anonce uint32) []byte {
	out := make([]byte, len(masked))
	for i := 0; i < len(masked); i += 4 {
		word := binary.LittleEndian.Uint32(masked[i : i+4])
		binary.LittleEndian.PutUint32(out[i:i+4], word^anonce)
	}
	return out
}
