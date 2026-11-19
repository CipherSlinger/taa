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
	_, err := VerifyReport(shortBuf)
	if err == nil {
		t.Fatal("VerifyReport() with short buffer expected error, got nil")
	}
	if !errors.Is(err, csvattest.ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}

// useCertDirs points the chain lookup at an explicit directory for one test.
func useCertDirs(t *testing.T, dirs ...string) {
	t.Helper()
	old := CertificateChainDirs
	CertificateChainDirs = dirs
	t.Cleanup(func() { CertificateChainDirs = old })
}

// copyFixtureCerts copies the repository's vendor certificate fixtures into a
// temporary directory and returns it.
func copyFixtureCerts(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"hrk.cert", "hsk_cek.cert"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "certs", name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	return dir
}

// TestVerifyReport_RequiresCertificateChain pins the deliberate presence of the
// chain check: a report whose PEK is valid still fails when no HRK/HSK-CEK pair
// is installed, because signature-only verification does not say the report
// came from a genuine platform. The report's own signature is still checked
// first, so the verdict distinguishes "chain missing" from "report forged".
func TestVerifyReport_RequiresCertificateChain(t *testing.T) {
	useCertDirs(t, t.TempDir())

	res, err := VerifyReport(createTestSignedReport(t))
	if err == nil {
		t.Fatal("VerifyReport() without a certificate chain expected error, got nil")
	}
	if !strings.Contains(err.Error(), "hrk.cert") {
		t.Fatalf("error = %v, want it to name the missing hrk.cert", err)
	}
	if res == nil || !res.ReportVerified {
		t.Error("the report's own signature should have verified before the chain lookup failed")
	}
}

// TestVerifyReport_RejectsUnanchoredChain uses the repository's real vendor
// chain: the test report carries a freshly generated PEK that the fixture CEK
// never signed, so the chain must not verify.
func TestVerifyReport_RejectsUnanchoredChain(t *testing.T) {
	useCertDirs(t, copyFixtureCerts(t))

	res, err := VerifyReport(createTestSignedReport(t))
	if err == nil {
		t.Fatal("VerifyReport() with a PEK outside the fixture chain expected error, got nil")
	}
	if !strings.Contains(err.Error(), "PEK") {
		t.Fatalf("error = %v, want a PEK signature failure from the chain walk", err)
	}
	if res == nil || !res.ReportVerified {
		t.Error("the report's own signature should have verified before the chain walk failed")
	}
	if res != nil && res.ChainVerified {
		t.Error("ChainVerified = true, want false for a PEK outside the chain")
	}
}

// TestCertificateChainPathsPrefersInstalledDirectory pins the search order the
// packaging paths rely on: the image directory wins over the checkout fixtures.
func TestCertificateChainPathsPrefersInstalledDirectory(t *testing.T) {
	installed := copyFixtureCerts(t)
	checkout := copyFixtureCerts(t)
	useCertDirs(t, installed, checkout)

	hrk, hskCek, err := CertificateChainPaths()
	if err != nil {
		t.Fatalf("CertificateChainPaths() error = %v", err)
	}
	if hrk != filepath.Join(installed, "hrk.cert") {
		t.Errorf("hrk path = %q, want %q", hrk, filepath.Join(installed, "hrk.cert"))
	}
	if hskCek != filepath.Join(installed, "hsk_cek.cert") {
		t.Errorf("hsk_cek path = %q, want %q", hskCek, filepath.Join(installed, "hsk_cek.cert"))
	}
}

// TestCertificateChainPathsSkipsIncompleteDirectory pins that a directory with
// only one of the two files is skipped rather than accepted half a chain.
func TestCertificateChainPathsSkipsIncompleteDirectory(t *testing.T) {
	incomplete := t.TempDir()
	if err := os.WriteFile(filepath.Join(incomplete, "hrk.cert"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write hrk.cert: %v", err)
	}
	complete := copyFixtureCerts(t)
	useCertDirs(t, incomplete, complete)

	hrk, _, err := CertificateChainPaths()
	if err != nil {
		t.Fatalf("CertificateChainPaths() error = %v", err)
	}
	if hrk != filepath.Join(complete, "hrk.cert") {
		t.Errorf("hrk path = %q, want the complete directory %q", hrk, filepath.Join(complete, "hrk.cert"))
	}
}

func TestVerifyReport_RejectsTamperedReport(t *testing.T) {
	report := createTestSignedReport(t)
	// Any byte inside the signed region changes what the PEK signature covers.
	report[csvattest.OffsetMeasure] ^= 0xFF

	if _, err := VerifyReport(report); err == nil {
		t.Fatal("VerifyReport() with tampered report expected error, got nil")
	}
}
