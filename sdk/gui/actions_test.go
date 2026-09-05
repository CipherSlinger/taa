package main

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"teecrypto/attestation"
	"taa/crypto"
)

func TestEncryptDecryptTextSM4(t *testing.T) {
	key, err := generateSM4KeyBase64()
	if err != nil {
		t.Fatalf("生成 SM4 密钥失败: %v", err)
	}
	plaintext := "可信数字空间: GUI 文本加解密测试"

	ciphertext, err := encryptTextSM4(key, plaintext)
	if err != nil {
		t.Fatalf("SM4 加密失败: %v", err)
	}
	got, err := decryptTextSM4(key, ciphertext)
	if err != nil {
		t.Fatalf("SM4 解密失败: %v", err)
	}
	if got != plaintext {
		t.Fatalf("明文不匹配: %q", got)
	}
}

func TestGenerateSM2KeyPEM(t *testing.T) {
	publicPEM, privatePEM, err := generateSM2KeyPEM()
	if err != nil {
		t.Fatalf("生成 SM2 密钥失败: %v", err)
	}
	if _, err := crypto.ParseSM2PublicKeyPEM([]byte(publicPEM)); err != nil {
		t.Fatalf("解析公钥失败: %v", err)
	}
	if _, err := crypto.ParseSM2PrivateKeyPEM([]byte(privatePEM)); err != nil {
		t.Fatalf("解析私钥失败: %v", err)
	}
}

func TestSealOpenEnvelope(t *testing.T) {
	publicPEM, privatePEM, err := generateSM2KeyPEM()
	if err != nil {
		t.Fatalf("生成 SM2 密钥失败: %v", err)
	}
	plaintext := "可信数字空间: GUI 信封加密测试"

	envelopeBin, err := sealText(publicPEM, plaintext)
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	if len(envelopeBin) == 0 {
		t.Fatal("信封二进制数据为空")
	}
	got, err := openEnvelope(privatePEM, envelopeBin)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	if got != plaintext {
		t.Fatalf("明文不匹配: %q", got)
	}
}

func TestInvalidBase64(t *testing.T) {
	if _, err := encryptTextSM4("not-base64", "plaintext"); err == nil {
		t.Fatal("无效 Base64 SM4 密钥应失败")
	}
	key, err := generateSM4KeyBase64()
	if err != nil {
		t.Fatalf("生成 SM4 密钥失败: %v", err)
	}
	if _, err := decryptTextSM4(key, "not-base64"); err == nil {
		t.Fatal("无效 Base64 密文应失败")
	}
}

func TestInvalidEnvelopeData(t *testing.T) {
	_, privatePEM, err := generateSM2KeyPEM()
	if err != nil {
		t.Fatalf("生成 SM2 密钥失败: %v", err)
	}
	if _, err := openEnvelope(privatePEM, []byte("bad")); err == nil {
		t.Fatal("无效信封数据应失败")
	}
}

func TestFileSM4RoundTrip(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "plain.txt")
	original := []byte("可信数字空间: 文件 SM4测试\x00二进制")
	if err := os.WriteFile(sourcePath, original, 0o644); err != nil {
		t.Fatalf("写入源文件失败: %v", err)
	}

	input, err := loadFileArtifact(sourcePath)
	if err != nil {
		t.Fatalf("加载源文件失败: %v", err)
	}
	key, err := generateSM4KeyBase64()
	if err != nil {
		t.Fatalf("生成 SM4 密钥失败: %v", err)
	}

	encrypted, err := encryptSM4File(key, input)
	if err != nil {
		t.Fatalf("文件加密失败: %v", err)
	}
	if got, want := filepath.Base(encrypted.OutputPath), "plain.txt.enc"; got != want {
		t.Fatalf("加密输出文件名不匹配: got %q want %q", got, want)
	}
	if _, err := saveFileArtifact(encrypted); err != nil {
		t.Fatalf("保存加密文件失败: %v", err)
	}

	encryptedInput, err := loadFileArtifact(encrypted.OutputPath)
	if err != nil {
		t.Fatalf("重新加载加密文件失败: %v", err)
	}
	decrypted, err := decryptSM4File(key, encryptedInput)
	if err != nil {
		t.Fatalf("文件解密失败: %v", err)
	}
	if got, want := filepath.Base(decrypted.OutputPath), "plain.txt"; got != want {
		t.Fatalf("解密输出文件名不匹配: got %q want %q", got, want)
	}
	if !bytes.Equal(decrypted.Data, original) {
		t.Fatalf("解密后文件内容不匹配: %q", decrypted.Data)
	}
}

func TestFileSealOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "payload.txt")
	original := []byte("可信数字空间: 文件信封加密测试")
	if err := os.WriteFile(sourcePath, original, 0o644); err != nil {
		t.Fatalf("写入源文件失败: %v", err)
	}

	input, err := loadFileArtifact(sourcePath)
	if err != nil {
		t.Fatalf("加载源文件失败: %v", err)
	}
	publicPEM, privatePEM, err := generateSM2KeyPEM()
	if err != nil {
		t.Fatalf("生成 SM2 密钥失败: %v", err)
	}

	enveloped, err := sealFile(publicPEM, input)
	if err != nil {
		t.Fatalf("Seal 文件失败: %v", err)
	}
	if got, want := filepath.Base(enveloped.OutputPath), "payload.txt.enc"; got != want {
		t.Fatalf("Seal 输出文件名不匹配: got %q want %q", got, want)
	}
	if _, err := saveFileArtifact(enveloped); err != nil {
		t.Fatalf("保存信封文件失败: %v", err)
	}

	envelopeInput, err := loadFileArtifact(enveloped.OutputPath)
	if err != nil {
		t.Fatalf("重新加载信封文件失败: %v", err)
	}
	opened, err := openEnvelopeFile(privatePEM, envelopeInput)
	if err != nil {
		t.Fatalf("Open 文件失败: %v", err)
	}
	if got, want := filepath.Base(opened.OutputPath), "payload.txt"; got != want {
		t.Fatalf("Open 输出文件名不匹配: got %q want %q", got, want)
	}
	if !bytes.Equal(opened.Data, original) {
		t.Fatalf("解密后文件内容不匹配: %q", opened.Data)
	}
}

func TestOutputPathRules(t *testing.T) {
	dir := t.TempDir()
	if got, want := deriveSealOutputPath(filepath.Join(dir, "a.txt")), filepath.Join(dir, "a.txt.enc"); got != want {
		t.Fatalf("Seal 输出路径不匹配: got %q want %q", got, want)
	}
	if got, want := deriveOpenOutputPath(filepath.Join(dir, "a.txt.enc")), filepath.Join(dir, "a.txt"); got != want {
		t.Fatalf("Open 输出路径不匹配: got %q want %q", got, want)
	}
	if got, want := deriveOpenOutputPath(filepath.Join(dir, "a.bin")), filepath.Join(dir, "a.bin.dec"); got != want {
		t.Fatalf("Open 默认输出路径不匹配: got %q want %q", got, want)
	}
}

func TestInvalidFileInputs(t *testing.T) {
	if _, err := encryptSM4File("not-base64", nil); err == nil {
		t.Fatal("无效 SM4 密钥应失败")
	}
	if _, err := decryptSM4File("not-base64", nil); err == nil {
		t.Fatal("无效 SM4 密钥应失败")
	}
	if _, err := sealFile("not pem", nil); err == nil {
		t.Fatal("无效 SM2 公钥应失败")
	}
	if _, err := openEnvelopeFile("not pem", nil); err == nil {
		t.Fatal("无效 SM2 私钥应失败")
	}
}

func TestVerifyAttestationReportRequiresReportFile(t *testing.T) {
	if _, err := verifyAttestationReport(" ", false); err == nil {
		t.Fatal("空报告文件应失败")
	}
}

func TestVerifyAttestationReportBuiltIn(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.cert")
	report, _ := newTestAttestationReport(t, false)
	if err := os.WriteFile(reportPath, report, 0o644); err != nil {
		t.Fatalf("写入报告文件失败: %v", err)
	}

	output, err := verifyAttestationReport(reportPath, false)
	if err != nil {
		t.Fatalf("内置报告验证失败: %v\n%s", err, output)
	}
	for _, want := range []string{"UserData (hex):", "MNonce (hex):", "Digest (hex):", "报告签名: 验证通过", "证书链: 未验证"} {
		if !strings.Contains(output, want) {
			t.Fatalf("验证输出缺少 %q: %s", want, output)
		}
	}
}

func TestVerifyAttestationReportTamperedFails(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.cert")
	report, _ := newTestAttestationReport(t, false)
	report[0x40] ^= 0xFF
	if err := os.WriteFile(reportPath, report, 0o644); err != nil {
		t.Fatalf("写入报告文件失败: %v", err)
	}

	output, err := verifyAttestationReport(reportPath, false)
	if err == nil {
		t.Fatalf("篡改报告后应验证失败: %s", output)
	}
	if !strings.Contains(output, "MNonce (hex):") || !strings.Contains(output, "报告签名: 验证失败") {
		t.Fatalf("失败时应保留已提取报告信息: %s", output)
	}
}

func TestVerifyAttestationReportBuiltInChainDownloadsCerts(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.cert")
	report, certs := newTestAttestationReport(t, true)
	if err := os.WriteFile(reportPath, report, 0o644); err != nil {
		t.Fatalf("写入报告文件失败: %v", err)
	}
	hskCek := append(append([]byte(nil), certs.hsk...), certs.cek...)
	requested := map[string]bool{}
	withMockDownload(t, func(rawURL string, expectedSize int) ([]byte, error) {
		requested[rawURL] = true
		switch rawURL {
		case attestation.HRKCertURL:
			return certs.hrk, nil
		case attestation.KDSCertURL + "TESTCHIP0001":
			return hskCek, nil
		default:
			t.Fatalf("unexpected download URL: %s", rawURL)
			return nil, nil
		}
	})

	output, err := verifyAttestationReport(reportPath, true)
	if err != nil {
		t.Fatalf("内置远程证书链验证失败: %v\n%s", err, output)
	}
	for _, want := range []string{"证书来源: 远程下载", "证书链: 验证通过", "ChipID: TESTCHIP0001", "HRK 证书:", "CEK 证书:", "PEK 证书:"} {
		if !strings.Contains(output, want) {
			t.Fatalf("验证输出缺少 %q: %s", want, output)
		}
	}
	if !requested[attestation.HRKCertURL] || !requested[attestation.KDSCertURL+"TESTCHIP0001"] {
		t.Fatalf("未请求预期证书 URL: %#v", requested)
	}
}

func TestVerifyAttestationReportBuiltInChainLocalFallback(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.cert")
	report, certs := newTestAttestationReport(t, true)
	if err := os.WriteFile(reportPath, report, 0o644); err != nil {
		t.Fatalf("写入报告文件失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hrk.cert"), certs.hrk, 0o644); err != nil {
		t.Fatalf("写入 HRK 证书失败: %v", err)
	}
	hskCek := append(append([]byte(nil), certs.hsk...), certs.cek...)
	if err := os.WriteFile(filepath.Join(dir, "hsk_cek.cert"), hskCek, 0o644); err != nil {
		t.Fatalf("写入 HSK/CEK 证书失败: %v", err)
	}
	withMockDownload(t, func(rawURL string, expectedSize int) ([]byte, error) {
		return nil, os.ErrNotExist
	})

	output, err := verifyAttestationReport(reportPath, true)
	if err != nil {
		t.Fatalf("内置证书链验证失败: %v\n%s", err, output)
	}
	for _, want := range []string{"证书来源: 本地文件（远程下载失败后回退）", "下载说明:", "证书链: 验证通过"} {
		if !strings.Contains(output, want) {
			t.Fatalf("验证输出缺少 %q: %s", want, output)
		}
	}
}

func TestVerifyAttestationReportBuiltInChainFailsWithoutRemoteOrLocalCerts(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.cert")
	report, _ := newTestAttestationReport(t, true)
	if err := os.WriteFile(reportPath, report, 0o644); err != nil {
		t.Fatalf("写入报告文件失败: %v", err)
	}
	withMockDownload(t, func(rawURL string, expectedSize int) ([]byte, error) {
		return nil, os.ErrNotExist
	})

	output, err := verifyAttestationReport(reportPath, true)
	if err == nil {
		t.Fatalf("远程和本地证书均不可用时应失败: %s", output)
	}
	if !strings.Contains(err.Error(), "chip_id=TESTCHIP0001") {
		t.Fatalf("错误信息应包含 ChipID: %v", err)
	}
	if !strings.Contains(output, "证书链: 验证失败") {
		t.Fatalf("输出应标记证书链失败: %s", output)
	}
}

func TestDownloadHygonCert(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write(bytes.Repeat([]byte{0xA5}, 16))
		case "/short":
			_, _ = w.Write([]byte{0xA5})
		default:
			http.Error(w, "missing", http.StatusNotFound)
		}
	}))
	defer server.Close()

	data, err := attestation.DownloadCert(server.URL+"/ok", 8)
	if err != nil {
		t.Fatalf("下载证书失败: %v", err)
	}
	if len(data) != 8 {
		t.Fatalf("应截取预期证书长度: %d", len(data))
	}
	if _, err := attestation.DownloadCert(server.URL+"/short", 8); err == nil {
		t.Fatal("短响应应失败")
	}
	if _, err := attestation.DownloadCert(server.URL+"/missing", 8); err == nil {
		t.Fatal("非 200 响应应失败")
	}
}

func withMockDownload(t *testing.T, fn func(string, int) ([]byte, error)) {
	t.Helper()
	old := attestation.DownloadCertFunc
	attestation.DownloadCertFunc = fn
	t.Cleanup(func() { attestation.DownloadCertFunc = old })
}

type testAttestationCerts struct {
	hrk []byte
	hsk []byte
	cek []byte
}

func newTestSM2KeyForGUI(t *testing.T) *crypto.SM2PrivateKey {
	t.Helper()
	key, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("生成 SM2 测试密钥失败: %v", err)
	}
	return key
}

func newTestAttestationReport(t *testing.T, withChain bool) ([]byte, *testAttestationCerts) {
	t.Helper()
	pek := newTestSM2KeyForGUI(t)
	pekCert := newTestCSVCert(t, pek, attestation.KeyUsagePEK)

	var certs *testAttestationCerts
	if withChain {
		hrk := newTestSM2KeyForGUI(t)
		hsk := newTestSM2KeyForGUI(t)
		cek := newTestSM2KeyForGUI(t)
		hrkCert := newTestRootCert(t, hrk, attestation.KeyUsageHRK, hrk)
		hskCert := newTestRootCert(t, hsk, attestation.KeyUsageHSK, hrk)
		cekCert := newTestCSVCert(t, cek, attestation.KeyUsageCEK)
		binary.LittleEndian.PutUint32(cekCert[attestation.OffsetCSVSig1Usage:], attestation.KeyUsageHSK)
		binary.LittleEndian.PutUint32(cekCert[attestation.OffsetCSVSig2Usage:], attestation.KeyUsageInvalid)
		signHygonData(t, hsk, cekCert[:attestation.OffsetCSVSig1Usage], cekCert[attestation.OffsetCSVSig1:])
		binary.LittleEndian.PutUint32(pekCert[attestation.OffsetCSVSig1Usage:], attestation.KeyUsageCEK)
		signHygonData(t, cek, pekCert[:attestation.OffsetCSVSig1Usage], pekCert[attestation.OffsetCSVSig1:])
		certs = &testAttestationCerts{hrk: hrkCert, hsk: hskCert, cek: cekCert}
	}

	report := make([]byte, attestation.ReportSize)
	anonce := uint32(0x11223344)
	binary.LittleEndian.PutUint32(report[attestation.OffsetReportANonce:], anonce)
	copyMasked(report[attestation.OffsetReportUserData:attestation.OffsetReportUserData+64], bytes.Repeat([]byte{0xA5}, 64), anonce)
	copyMasked(report[attestation.OffsetReportMNonce:attestation.OffsetReportMNonce+16], []byte("0123456789abcdef"), anonce)
	copyMasked(report[attestation.OffsetReportDigest:attestation.OffsetReportDigest+32], bytes.Repeat([]byte{0x5A}, 32), anonce)
	copyMasked(report[attestation.OffsetReportPEKCert:attestation.OffsetReportPEKCert+attestation.CSVCertSize], pekCert, anonce)
	copyMasked(report[attestation.OffsetReportChipID:attestation.OffsetReportChipID+64], append([]byte("TESTCHIP0001"), make([]byte, 52)...), anonce)
	signHygonData(t, pek, report[:attestation.SignedSize], report[attestation.OffsetReportSig1:])
	return report, certs
}

func newTestRootCert(t *testing.T, key *crypto.SM2PrivateKey, usage uint32, signer *crypto.SM2PrivateKey) []byte {
	t.Helper()
	cert := make([]byte, attestation.HrkCertSize)
	binary.LittleEndian.PutUint32(cert[attestation.OffsetRootKeyUsage:], usage)
	putHygonPubKey(cert[attestation.OffsetRootPubKey:], &key.PublicKey, []byte("test-sm2-user"))
	signHygonData(t, signer, cert[:attestation.OffsetRootSig], cert[attestation.OffsetRootSig:])
	return cert
}

func newTestCSVCert(t *testing.T, key *crypto.SM2PrivateKey, usage uint32) []byte {
	t.Helper()
	cert := make([]byte, attestation.CSVCertSize)
	binary.LittleEndian.PutUint32(cert[attestation.OffsetCSVPubKeyUsage:], usage)
	binary.LittleEndian.PutUint32(cert[attestation.OffsetCSVSig1Usage:], attestation.KeyUsageInvalid)
	binary.LittleEndian.PutUint32(cert[attestation.OffsetCSVSig2Usage:], attestation.KeyUsageInvalid)
	putHygonPubKey(cert[attestation.OffsetCSVPubKey:], &key.PublicKey, []byte("test-sm2-user"))
	return cert
}

func signHygonData(t *testing.T, key *crypto.SM2PrivateKey, msg []byte, sig []byte) {
	t.Helper()
	r, s, err := crypto.SignSM2Signature(key, []byte("test-sm2-user"), msg)
	if err != nil {
		t.Fatalf("SM2 签名失败: %v", err)
	}
	copy(sig[attestation.OffsetHygonSigR:attestation.OffsetHygonSigR+32], attestation.ReverseCopy(leftPad32Test(r.Bytes())))
	copy(sig[attestation.OffsetHygonSigS:attestation.OffsetHygonSigS+32], attestation.ReverseCopy(leftPad32Test(s.Bytes())))
}

func putHygonPubKey(dst []byte, pub *crypto.SM2PublicKey, userID []byte) {
	binary.LittleEndian.PutUint32(dst, attestation.CurveIDSM2)
	copy(dst[attestation.OffsetECCPubKeyQX:attestation.OffsetECCPubKeyQX+32], attestation.ReverseCopy(leftPad32Test(pub.X.Bytes())))
	copy(dst[attestation.OffsetECCPubKeyQY:attestation.OffsetECCPubKeyQY+32], attestation.ReverseCopy(leftPad32Test(pub.Y.Bytes())))
	binary.LittleEndian.PutUint16(dst[attestation.OffsetECCPubKeyUserID:], uint16(len(userID)))
	copy(dst[attestation.OffsetECCPubKeyUserID+2:], userID)
}

func copyMasked(dst, src []byte, anonce uint32) {
	for i := 0; i < len(src); i += 4 {
		word := binary.LittleEndian.Uint32(src[i:]) ^ anonce
		binary.LittleEndian.PutUint32(dst[i:], word)
	}
}

func leftPad32Test(in []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(in):], in)
	return out
}
