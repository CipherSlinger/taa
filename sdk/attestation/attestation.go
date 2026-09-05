// Package attestation provides CSV attestation report verification for Hygon TEE.
package attestation

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"taa/crypto"
)

const (
	ReportSize     = 0x9f4
	SignedSize     = 0xb4
	HrkCertSize    = 0x340
	CSVCertSize    = 0x824
	HskCekSize     = HrkCertSize + CSVCertSize
	HRKCertURL     = "https://cert.hygon.cn/hrk"
	KDSCertURL     = "https://cert.hygon.cn/hsk_cek?snumber="

	OffsetReportPubkeyDigest = 0x000
	OffsetReportVMID         = 0x020
	OffsetReportVMVersion    = 0x030
	OffsetReportUserData     = 0x040
	OffsetReportMNonce       = 0x080
	OffsetReportDigest       = 0x090
	OffsetReportPolicy       = 0x0b0
	OffsetReportSigUsage     = 0x0b4
	OffsetReportSigAlgo      = 0x0b8
	OffsetReportANonce       = 0x0bc
	OffsetReportSig1         = 0x0c0
	OffsetReportPEKCert      = 0x150
	OffsetReportChipID       = 0x974
	OffsetReportReserved2    = 0x9b4
	OffsetReportMAC          = 0x9d4

	OffsetRootKeyUsage = 0x024
	OffsetRootPubKey   = 0x040
	OffsetRootSig      = 0x240

	OffsetCSVPubKeyUsage = 0x008
	OffsetCSVPubKey      = 0x010
	OffsetCSVSig1Usage   = 0x414
	OffsetCSVSig1        = 0x41c
	OffsetCSVSig2Usage   = 0x61c
	OffsetCSVSig2        = 0x624

	OffsetECCPubKeyQX     = 0x004
	OffsetECCPubKeyQY     = 0x04c
	OffsetECCPubKeyUserID = 0x094
	OffsetHygonSigR       = 0x000
	OffsetHygonSigS       = 0x048

	KeyUsageHRK     = 0x0
	KeyUsageHSK     = 0x13
	KeyUsageInvalid = 0x1000
	KeyUsagePEK     = 0x1002
	KeyUsageCEK     = 0x1004
	CurveIDSM2      = 0x3
)

var DownloadCertFunc = DownloadCert

type VerificationResult struct {
	ReportSize        int
	PubkeyDigest      []byte
	VMID              []byte
	VMVersion         []byte
	UserData          []byte
	MNonce            []byte
	Digest            []byte
	Policy            uint32
	SigUsage          uint32
	SigAlgo           uint32
	ANonce            uint32
	Signature         []byte
	PEKCert           []byte
	ChipID            []byte
	ChipIDASCII       string
	Reserved2         []byte
	MAC               []byte
	PEKDetails        CSVCertDetails
	ReportVerified    bool
	ChainVerified     bool
	ChainSource       string
	ChainDownloadNote string
	HRKURL            string
	HSKCEKURL         string
	CertDetails       *CertChainDetails
}

type PubKeyDetails struct {
	CurveID   uint32
	UserID    string
	UserIDHex string
	QXHex     string
	QYHex     string
}

type RootCertDetails struct {
	KeyUsage              uint32
	PubKey                PubKeyDetails
	SelfSignatureVerified bool
	SignedByHRKVerified   bool
}

type CSVCertDetails struct {
	PubKeyUsage         uint32
	Sig1Usage           uint32
	Sig2Usage           uint32
	PubKey              PubKeyDetails
	SignedByHSKVerified bool
	SignedByCEKVerified bool
}

type CertChainDetails struct {
	HRK RootCertDetails
	HSK RootCertDetails
	CEK CSVCertDetails
	PEK CSVCertDetails
}

type CertChainInput struct {
	HRK          []byte
	HSKCEK       []byte
	Source       string
	DownloadNote string
	HRKURL       string
	HSKCEKURL    string
}

func VerifyReport(reportFile string, verifyChain bool) (*VerificationResult, error) {
	reportFile = strings.TrimSpace(reportFile)
	if reportFile == "" {
		return nil, errors.New("报告文件不能为空")
	}
	data, err := os.ReadFile(reportFile)
	if err != nil {
		return nil, fmt.Errorf("读取报告文件失败: %w", err)
	}
	return VerifyReportData(data, filepath.Dir(reportFile), verifyChain)
}

func VerifyReportData(data []byte, certDir string, verifyChain bool) (*VerificationResult, error) {
	if len(data) < ReportSize {
		return nil, fmt.Errorf("报告长度不足: %d bytes, 需要至少 %d bytes", len(data), ReportSize)
	}
	report := data[:ReportSize]
	anonce := binary.LittleEndian.Uint32(report[OffsetReportANonce:])

	pubkeyDigest := make([]byte, 32)
	copy(pubkeyDigest, report[OffsetReportPubkeyDigest:OffsetReportPubkeyDigest+32])

	vmID := make([]byte, 16)
	copy(vmID, report[OffsetReportVMID:OffsetReportVMID+16])

	vmVersion := make([]byte, 16)
	copy(vmVersion, report[OffsetReportVMVersion:OffsetReportVMVersion+16])

	signature := make([]byte, 144)
	copy(signature, report[OffsetReportSig1:OffsetReportSig1+144])

	reserved2 := make([]byte, 32)
	copy(reserved2, report[OffsetReportReserved2:OffsetReportReserved2+32])

	mac := make([]byte, 32)
	copy(mac, report[OffsetReportMAC:OffsetReportMAC+32])

	userData := UnmaskWords(report[OffsetReportUserData:OffsetReportUserData+64], anonce)
	mnonce := UnmaskWords(report[OffsetReportMNonce:OffsetReportMNonce+16], anonce)
	digest := UnmaskWords(report[OffsetReportDigest:OffsetReportDigest+32], anonce)
	chipID := UnmaskWords(report[OffsetReportChipID:OffsetReportChipID+64], anonce)
	pekCert := UnmaskWords(report[OffsetReportPEKCert:OffsetReportPEKCert+CSVCertSize], anonce)

	policy := binary.LittleEndian.Uint32(UnmaskWords(report[OffsetReportPolicy:OffsetReportPolicy+4], anonce))
	sigUsage := binary.LittleEndian.Uint32(UnmaskWords(report[OffsetReportSigUsage:OffsetReportSigUsage+4], anonce))
	sigAlgo := binary.LittleEndian.Uint32(UnmaskWords(report[OffsetReportSigAlgo:OffsetReportSigAlgo+4], anonce))

	result := &VerificationResult{
		ReportSize:   len(report),
		PubkeyDigest: pubkeyDigest,
		VMID:         vmID,
		VMVersion:    vmVersion,
		UserData:     userData,
		MNonce:       mnonce,
		Digest:       digest,
		Policy:       policy,
		SigUsage:     sigUsage,
		SigAlgo:      sigAlgo,
		ANonce:       anonce,
		Signature:    signature,
		PEKCert:      pekCert,
		ChipID:       chipID,
		Reserved2:    reserved2,
		MAC:          mac,
		HRKURL:       HRKCertURL,
	}

	chipIDASCII, err := ChipIDASCII(result.ChipID)
	if err != nil {
		return result, fmt.Errorf("解析 ChipID 失败: %w", err)
	}
	result.ChipIDASCII = chipIDASCII
	result.HSKCEKURL = KDSCertURL + url.QueryEscape(chipIDASCII)

	pekDetails, err := ParseCSVCertDetails(pekCert)
	if err != nil {
		return result, fmt.Errorf("解析报告内 PEK 证书失败: %w", err)
	}
	result.PEKDetails = pekDetails

	pekPub, err := parseHygonPubKey(pekCert[OffsetCSVPubKey:])
	if err != nil {
		return result, fmt.Errorf("解析报告内 PEK 公钥失败: %w", err)
	}

	r, s := ParseHygonSignature(report[OffsetReportSig1:])
	if !crypto.VerifySM2Signature(pekPub.Key, pekPub.UserID, report[:SignedSize], r, s) {
		return result, errors.New("报告签名验证失败")
	}
	result.ReportVerified = true

	if verifyChain {
		certs, err := LoadCertChain(certDir, chipIDASCII)
		if err != nil {
			return result, err
		}
		result.ChainSource = certs.Source
		result.ChainDownloadNote = certs.DownloadNote
		result.HRKURL = certs.HRKURL
		result.HSKCEKURL = certs.HSKCEKURL
		details, err := VerifyCertChain(certs, pekCert)
		if details != nil {
			result.CertDetails = details
			result.PEKDetails = details.PEK
		}
		if err != nil {
			return result, err
		}
		result.ChainVerified = true
	}
	return result, nil
}

func LoadCertChain(certDir string, chipIDASCII string) (*CertChainInput, error) {
	hrkURL := HRKCertURL
	hskCekURL := KDSCertURL + url.QueryEscape(chipIDASCII)
	hrk, hrkErr := DownloadCertFunc(hrkURL, HrkCertSize)
	hskCek, hskCekErr := DownloadCertFunc(hskCekURL, HskCekSize)
	if hrkErr == nil && hskCekErr == nil {
		return &CertChainInput{HRK: hrk, HSKCEK: hskCek, Source: "远程下载", HRKURL: hrkURL, HSKCEKURL: hskCekURL}, nil
	}

	local, localErr := LoadLocalCertChain(certDir)
	if localErr == nil {
		local.Source = "本地文件（远程下载失败后回退）"
		local.DownloadNote = fmt.Sprintf("远程下载失败: HRK=%v; HSK/CEK=%v", hrkErr, hskCekErr)
		local.HRKURL = hrkURL
		local.HSKCEKURL = hskCekURL
		return local, nil
	}
	return nil, fmt.Errorf("下载证书失败且本地证书不可用(chip_id=%s): HRK 下载=%v; HSK/CEK 下载=%v; 本地=%v", chipIDASCII, hrkErr, hskCekErr, localErr)
}

func LoadLocalCertChain(certDir string) (*CertChainInput, error) {
	hrkPath := filepath.Join(certDir, "hrk.cert")
	hskCekPath := filepath.Join(certDir, "hsk_cek.cert")
	hrk, err := readFixedFile(hrkPath, HrkCertSize)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", hrkPath, err)
	}
	hskCek, err := readFixedFile(hskCekPath, HskCekSize)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", hskCekPath, err)
	}
	return &CertChainInput{HRK: hrk, HSKCEK: hskCek, Source: "本地文件"}, nil
}

func DownloadCert(rawURL string, expectedSize int) ([]byte, error) {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP 状态码 %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(expectedSize+4096)))
	if err != nil {
		return nil, err
	}
	if len(data) < expectedSize {
		return nil, fmt.Errorf("证书长度不足: %d bytes, 需要至少 %d bytes", len(data), expectedSize)
	}
	return data[:expectedSize], nil
}

func VerifyCertChain(certs *CertChainInput, pekCert []byte) (*CertChainDetails, error) {
	if len(certs.HRK) < HrkCertSize {
		return nil, fmt.Errorf("hrk.cert 长度不足: %d", len(certs.HRK))
	}
	if len(certs.HSKCEK) < HskCekSize {
		return nil, fmt.Errorf("hsk_cek.cert 长度不足: %d", len(certs.HSKCEK))
	}
	hrk := certs.HRK[:HrkCertSize]
	hsk := certs.HSKCEK[:HrkCertSize]
	cek := certs.HSKCEK[HrkCertSize:HskCekSize]

	details := &CertChainDetails{}
	var err error
	details.HRK, err = ParseRootCertDetails(hrk)
	if err != nil {
		return details, fmt.Errorf("解析 HRK 证书失败: %w", err)
	}
	details.HSK, err = ParseRootCertDetails(hsk)
	if err != nil {
		return details, fmt.Errorf("解析 HSK 证书失败: %w", err)
	}
	details.CEK, err = ParseCSVCertDetails(cek)
	if err != nil {
		return details, fmt.Errorf("解析 CEK 证书失败: %w", err)
	}
	details.PEK, err = ParseCSVCertDetails(pekCert)
	if err != nil {
		return details, fmt.Errorf("解析 PEK 证书失败: %w", err)
	}

	if details.HRK.KeyUsage != KeyUsageHRK {
		return details, fmt.Errorf("HRK key_usage 无效: 0x%x", details.HRK.KeyUsage)
	}
	if details.HSK.KeyUsage != KeyUsageHSK {
		return details, fmt.Errorf("HSK key_usage 无效: 0x%x", details.HSK.KeyUsage)
	}
	if details.CEK.PubKeyUsage != KeyUsageCEK {
		return details, fmt.Errorf("CEK pubkey_usage 无效: 0x%x", details.CEK.PubKeyUsage)
	}
	if details.CEK.Sig1Usage != KeyUsageHSK {
		return details, fmt.Errorf("CEK sig1_usage 无效: 0x%x", details.CEK.Sig1Usage)
	}
	if details.CEK.Sig2Usage != KeyUsageInvalid {
		return details, fmt.Errorf("CEK sig2_usage 无效: 0x%x", details.CEK.Sig2Usage)
	}
	if details.PEK.PubKeyUsage != KeyUsagePEK {
		return details, fmt.Errorf("PEK pubkey_usage 无效: 0x%x", details.PEK.PubKeyUsage)
	}

	hrkPub, err := parseHygonPubKey(hrk[OffsetRootPubKey:])
	if err != nil {
		return details, fmt.Errorf("解析 HRK 公钥失败: %w", err)
	}
	hskPub, err := parseHygonPubKey(hsk[OffsetRootPubKey:])
	if err != nil {
		return details, fmt.Errorf("解析 HSK 公钥失败: %w", err)
	}
	cekPub, err := parseHygonPubKey(cek[OffsetCSVPubKey:])
	if err != nil {
		return details, fmt.Errorf("解析 CEK 公钥失败: %w", err)
	}

	details.HRK.SelfSignatureVerified = verifyHygonSignature(hrkPub, hrk[:OffsetRootSig], hrk[OffsetRootSig:])
	if !details.HRK.SelfSignatureVerified {
		return details, errors.New("HRK 自签名验证失败")
	}
	details.HSK.SignedByHRKVerified = verifyHygonSignature(hrkPub, hsk[:OffsetRootSig], hsk[OffsetRootSig:])
	if !details.HSK.SignedByHRKVerified {
		return details, errors.New("HRK 验证 HSK 签名失败")
	}
	details.CEK.SignedByHSKVerified = verifyHygonSignature(hskPub, cek[:OffsetCSVSig1Usage], cek[OffsetCSVSig1:])
	if !details.CEK.SignedByHSKVerified {
		return details, errors.New("HSK 验证 CEK 签名失败")
	}
	details.PEK.SignedByCEKVerified = verifyHygonSignature(cekPub, pekCert[:OffsetCSVSig1Usage], pekCert[OffsetCSVSig1:])
	if !details.PEK.SignedByCEKVerified {
		return details, errors.New("CEK 验证 PEK 签名失败")
	}
	return details, nil
}

type hygonPubKey struct {
	Key     *crypto.SM2PublicKey
	UserID  []byte
	Details PubKeyDetails
}

func parseHygonPubKey(data []byte) (*hygonPubKey, error) {
	if len(data) < OffsetECCPubKeyUserID+256 {
		return nil, errors.New("公钥数据长度不足")
	}
	curveID := binary.LittleEndian.Uint32(data)
	if curveID != CurveIDSM2 {
		return nil, fmt.Errorf("不支持的曲线 ID: 0x%x", curveID)
	}
	xBytes := ReverseCopy(data[OffsetECCPubKeyQX : OffsetECCPubKeyQX+32])
	yBytes := ReverseCopy(data[OffsetECCPubKeyQY : OffsetECCPubKeyQY+32])
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	uidData := data[OffsetECCPubKeyUserID:]
	uidLen := int(binary.LittleEndian.Uint16(uidData))
	if uidLen > len(uidData)-2 {
		return nil, fmt.Errorf("SM2 user id 长度无效: %d", uidLen)
	}
	userID := append([]byte(nil), uidData[2:2+uidLen]...)
	return &hygonPubKey{
		Key:    &crypto.SM2PublicKey{X: x, Y: y},
		UserID: userID,
		Details: PubKeyDetails{
			CurveID:   curveID,
			UserID:    string(userID),
			UserIDHex: hex.EncodeToString(userID),
			QXHex:     hex.EncodeToString(xBytes),
			QYHex:     hex.EncodeToString(yBytes),
		},
	}, nil
}

func ParseRootCertDetails(cert []byte) (RootCertDetails, error) {
	if len(cert) < HrkCertSize {
		return RootCertDetails{}, fmt.Errorf("证书长度不足: %d", len(cert))
	}
	pub, err := parseHygonPubKey(cert[OffsetRootPubKey:])
	if err != nil {
		return RootCertDetails{}, err
	}
	return RootCertDetails{KeyUsage: binary.LittleEndian.Uint32(cert[OffsetRootKeyUsage:]), PubKey: pub.Details}, nil
}

func ParseCSVCertDetails(cert []byte) (CSVCertDetails, error) {
	if len(cert) < CSVCertSize {
		return CSVCertDetails{}, fmt.Errorf("证书长度不足: %d", len(cert))
	}
	pub, err := parseHygonPubKey(cert[OffsetCSVPubKey:])
	if err != nil {
		return CSVCertDetails{}, err
	}
	return CSVCertDetails{
		PubKeyUsage: binary.LittleEndian.Uint32(cert[OffsetCSVPubKeyUsage:]),
		Sig1Usage:   binary.LittleEndian.Uint32(cert[OffsetCSVSig1Usage:]),
		Sig2Usage:   binary.LittleEndian.Uint32(cert[OffsetCSVSig2Usage:]),
		PubKey:      pub.Details,
	}, nil
}

func verifyHygonSignature(pub *hygonPubKey, msg []byte, sig []byte) bool {
	r, s := ParseHygonSignature(sig)
	return crypto.VerifySM2Signature(pub.Key, pub.UserID, msg, r, s)
}

func ParseHygonSignature(sig []byte) (*big.Int, *big.Int) {
	r := new(big.Int).SetBytes(ReverseCopy(sig[OffsetHygonSigR : OffsetHygonSigR+32]))
	s := new(big.Int).SetBytes(ReverseCopy(sig[OffsetHygonSigS : OffsetHygonSigS+32]))
	return r, s
}

func ChipIDASCII(chipID []byte) (string, error) {
	trimmed := strings.TrimSpace(strings.TrimRight(string(chipID), "\x00"))
	if trimmed == "" {
		return "", errors.New("ChipID 为空")
	}
	for _, b := range []byte(trimmed) {
		if b < 0x20 || b > 0x7e {
			return "", fmt.Errorf("ChipID 包含不可打印字符: 0x%02x", b)
		}
	}
	return trimmed, nil
}

func UnmaskWords(data []byte, anonce uint32) []byte {
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 4 {
		word := binary.LittleEndian.Uint32(data[i:]) ^ anonce
		binary.LittleEndian.PutUint32(out[i:], word)
	}
	return out
}

func readFixedFile(path string, size int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < size {
		return nil, fmt.Errorf("文件长度不足: %d bytes, 需要至少 %d bytes", len(data), size)
	}
	return data[:size], nil
}

func ReverseCopy(in []byte) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[len(in)-1-i]
	}
	return out
}
