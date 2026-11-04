package attestation

import (
	"bytes"
	"encoding/binary"
	"errors"
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

// TestVerifyReport_VerifiesWithoutCertificates pins the deliberate absence of a
// certificate-chain check: the report verifies on its own, using only the PEK
// certificate it carries. No HRK/HSK/CEK files exist on this machine, which is
// what an initrd built for one device must also be able to do on another.
func TestVerifyReport_VerifiesWithoutCertificates(t *testing.T) {
	res, err := VerifyReport(createTestSignedReport(t))
	if err != nil {
		t.Fatalf("VerifyReport() error = %v, want nil", err)
	}
	if !res.ReportVerified {
		t.Error("ReportVerified = false, want true")
	}
	if res.ChainVerified {
		t.Error("ChainVerified = true, want false: the certificate chain must not be walked")
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
