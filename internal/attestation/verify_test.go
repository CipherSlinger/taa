package attestation

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	taacrypto "taa/pkg/crypto"
	"taa/pkg/csvattest"
)

func leftPad32(in []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(in):], in)
	return out
}

func createTestSignedReport(t *testing.T) []byte {
	t.Helper()
	pek, err := taacrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("failed to generate SM2 key pair: %v", err)
	}

	pekCert := make([]byte, csvattest.CSVCertSize)
	binary.LittleEndian.PutUint32(pekCert[csvattest.OffsetCSVPubKeyUsage:], csvattest.KeyUsagePEK)
	binary.LittleEndian.PutUint32(pekCert[csvattest.OffsetCSVSig1Usage:], csvattest.KeyUsageInvalid)
	binary.LittleEndian.PutUint32(pekCert[csvattest.OffsetCSVSig2Usage:], csvattest.KeyUsageInvalid)

	binary.LittleEndian.PutUint32(pekCert[csvattest.OffsetCSVPubKey:], csvattest.CurveIDSM2)
	copy(pekCert[csvattest.OffsetCSVPubKey+csvattest.OffsetECCPubKeyQX:], csvattest.ReverseCopy(leftPad32(pek.PublicKey.X.Bytes())))
	copy(pekCert[csvattest.OffsetCSVPubKey+csvattest.OffsetECCPubKeyQY:], csvattest.ReverseCopy(leftPad32(pek.PublicKey.Y.Bytes())))
	binary.LittleEndian.PutUint16(pekCert[csvattest.OffsetCSVPubKey+csvattest.OffsetECCPubKeyUserID:], uint16(len("test-sm2-user")))
	copy(pekCert[csvattest.OffsetCSVPubKey+csvattest.OffsetECCPubKeyUserID+2:], "test-sm2-user")

	report := make([]byte, csvattest.ReportSize)
	anonce := uint32(0x11223344)
	binary.LittleEndian.PutUint32(report[csvattest.OffsetANonce:], anonce)
	copy(report[csvattest.OffsetUserData:csvattest.OffsetUserData+64], csvattest.UnmaskWords(bytes.Repeat([]byte{0xA5}, 64), anonce))
	copy(report[csvattest.OffsetMNonce:csvattest.OffsetMNonce+16], csvattest.UnmaskWords([]byte("0123456789abcdef"), anonce))
	copy(report[csvattest.OffsetMeasure:csvattest.OffsetMeasure+32], csvattest.UnmaskWords(bytes.Repeat([]byte{0x5A}, 32), anonce))
	copy(report[csvattest.OffsetPEKCert:csvattest.OffsetPEKCert+csvattest.CSVCertSize], csvattest.UnmaskWords(pekCert, anonce))
	copy(report[csvattest.OffsetChipID:csvattest.OffsetChipID+64], csvattest.UnmaskWords(append([]byte("TESTCHIP0001"), make([]byte, 52)...), anonce))

	r, s, err := taacrypto.SignSM2Signature(pek, []byte("test-sm2-user"), report[:csvattest.SignedSize])
	if err != nil {
		t.Fatalf("failed to sign SM2 data: %v", err)
	}
	copy(report[csvattest.OffsetReportSig1+csvattest.OffsetHygonSigR:], csvattest.ReverseCopy(leftPad32(r.Bytes())))
	copy(report[csvattest.OffsetReportSig1+csvattest.OffsetHygonSigS:], csvattest.ReverseCopy(leftPad32(s.Bytes())))
	return report
}

func TestVerifyReport_ShortBuffer(t *testing.T) {
	shortBuf := make([]byte, csvattest.ReportSize-1)
	_, err := VerifyReport(shortBuf, "some/hrk.cert", "some/hsk_cek.cert")
	if err == nil {
		t.Fatal("VerifyReport() with short buffer expected error, got nil")
	}
	if !errors.Is(err, csvattest.ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}

func TestVerifyReport_MissingCerts(t *testing.T) {
	// 1. With validly signed report, missing cert files should fail during cert loading.
	signedReport := createTestSignedReport(t)
	_, err := VerifyReport(signedReport, "/nonexistent/hrk.cert", "/nonexistent/hsk_cek.cert")
	if err == nil {
		t.Fatal("VerifyReport() with nonexistent cert files expected error, got nil")
	}
	if !strings.Contains(err.Error(), "load certs from files") {
		t.Fatalf("expected cert loading error, got: %v", err)
	}

	// 2. Empty paths should also return an error.
	_, err = VerifyReport(signedReport, "", "")
	if err == nil {
		t.Fatal("VerifyReport() with empty paths expected error, got nil")
	}
}

func TestVerifyReport_EmptyCertPaths(t *testing.T) {
	dummyReport := make([]byte, csvattest.ReportSize)
	tests := []struct {
		name       string
		hrkPath    string
		hskCekPath string
	}{
		{"both empty", "", ""},
		{"hrk empty", "", "some/hsk_cek.cert"},
		{"hskCek empty", "some/hrk.cert", ""},
		{"both whitespace", "   ", "   "},
		{"hrk whitespace", "\t", "some/hsk_cek.cert"},
		{"hskCek whitespace", "some/hrk.cert", "  \n  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyReport(dummyReport, tt.hrkPath, tt.hskCekPath)
			if err == nil {
				t.Fatalf("expected error for empty cert path, got nil")
			}
			if !strings.Contains(err.Error(), "both HRK and HSK/CEK certificate paths must be specified") {
				t.Fatalf("expected error requiring both cert paths, got: %v", err)
			}
		})
	}
}

func TestVerifyReport_ValidCertPaths(t *testing.T) {
	hrkPath := filepath.Join("..", "..", "deploy", "certs", "hrk.cert")
	hskCekPath := filepath.Join("..", "..", "deploy", "certs", "hsk_cek.cert")
	if _, err := os.Stat(hrkPath); err != nil {
		if _, errRoot := os.Stat("deploy/certs/hrk.cert"); errRoot == nil {
			hrkPath = "deploy/certs/hrk.cert"
			hskCekPath = "deploy/certs/hsk_cek.cert"
		} else {
			t.Skip("deploy certs not present, skipping test")
		}
	}

	dummyReport := make([]byte, csvattest.ReportSize)
	res, err := VerifyReport(dummyReport, hrkPath, hskCekPath)
	if err == nil {
		t.Fatal("expected parse/signature error with zeroed report, got nil")
	}
	if res == nil {
		t.Log("res is nil as expected on parse failure")
	}
}
