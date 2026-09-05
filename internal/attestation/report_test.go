package attestation

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractReportValuesUnmasksFieldsAndReturnsChipIDASCII(t *testing.T) {
	const anonce uint32 = 0xa1b2c3d4

	report := make([]byte, 0x9f4)
	binary.LittleEndian.PutUint32(report[0x0bc:0x0c0], anonce)

	userData := make([]byte, 64)
	for i := range userData {
		userData[i] = byte(i + 1)
	}
	mnonce := []byte("nonce-1234567890")
	digest := []byte("0123456789abcdef0123456789abcdef")
	chipID := append([]byte("CSV-CHIP-ASCII-001"), make([]byte, 64-len("CSV-CHIP-ASCII-001"))...)

	putMaskedWords(report[0x040:0x040+64], userData, anonce)
	putMaskedWords(report[0x080:0x080+16], mnonce, anonce)
	putMaskedWords(report[0x090:0x090+32], digest, anonce)
	putMaskedWords(report[0x974:0x974+64], chipID, anonce)

	reportPath := filepath.Join(t.TempDir(), "attestation.report")
	if err := os.WriteFile(reportPath, report, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	valuesJSON, err := ExtractReportValues(reportPath)
	if err != nil {
		t.Fatalf("ExtractReportValues() error = %v", err)
	}

	var values ReportValues
	if err := json.Unmarshal([]byte(valuesJSON), &values); err != nil {
		t.Fatalf("unmarshal values: %v", err)
	}

	wantUserData := "0102030405060708090a0b0c0d0e0f10" +
		"1112131415161718191a1b1c1d1e1f20" +
		"2122232425262728292a2b2c2d2e2f30" +
		"3132333435363738393a3b3c3d3e3f40"
	if values.UserData != wantUserData {
		t.Fatalf("userdata = %q, want %q", values.UserData, wantUserData)
	}
	if values.MNonce != hex.EncodeToString(mnonce) {
		t.Fatalf("mnonce = %q, want %q", values.MNonce, hex.EncodeToString(mnonce))
	}
	if values.Digest != hex.EncodeToString(digest) {
		t.Fatalf("digest = %q, want %q", values.Digest, hex.EncodeToString(digest))
	}
	if values.ChipID != "CSV-CHIP-ASCII-001" {
		t.Fatalf("chipId = %q, want ASCII chip id", values.ChipID)
	}
	if strings.HasPrefix(values.ChipID, hex.EncodeToString([]byte("CSV-CHIP"))) {
		t.Fatalf("chipId = %q, should not be hex encoded", values.ChipID)
	}
}

func putMaskedWords(dst, src []byte, anonce uint32) {
	for i := 0; i < len(src); i += 4 {
		word := binary.LittleEndian.Uint32(src[i : i+4])
		binary.LittleEndian.PutUint32(dst[i:i+4], word^anonce)
	}
}
