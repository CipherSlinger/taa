package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"teecrypto/attestation"
)

// Local type aliases for backward compatibility with GUI code
type attestationVerificationResult = attestation.VerificationResult
type parsedPubKeyDetails = attestation.PubKeyDetails
type parsedRootCertDetails = attestation.RootCertDetails
type parsedCSVCertDetails = attestation.CSVCertDetails
type parsedCertChainDetails = attestation.CertChainDetails
type hygonCertChainInput = attestation.CertChainInput

func verifyAttestationReport(reportFile string, verifyChain bool) (string, error) {
	result, err := attestation.VerifyReport(reportFile, verifyChain)
	output := formatAttestationVerificationOutput(reportFile, verifyChain, result)
	return output, err
}

func verifyAttestationReportStructured(reportFile string, verifyChain bool) (*attestationVerificationResult, error) {
	return attestation.VerifyReport(reportFile, verifyChain)
}

func formatAttestationVerificationOutput(reportFile string, verifyChain bool, result *attestationVerificationResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "报告文件: %s\n", reportFile)
	if result == nil {
		return b.String()
	}
	fmt.Fprintf(&b, "报告长度: %d bytes\n", result.ReportSize)
	fmt.Fprintf(&b, "ANonce: 0x%08x\n", result.ANonce)
	writeWrappedValue(&b, "UserData (hex)", hex.EncodeToString(result.UserData), 64, "  ")
	writeWrappedValue(&b, "MNonce (hex)", hex.EncodeToString(result.MNonce), 64, "  ")
	writeWrappedValue(&b, "Digest (hex)", hex.EncodeToString(result.Digest), 64, "  ")
	fmt.Fprintf(&b, "ChipID: %s\n", result.ChipIDASCII)
	writeWrappedValue(&b, "ChipID Hex", hex.EncodeToString(result.ChipID), 64, "  ")
	writeCSVCertDetails(&b, "报告内 PEK 证书", result.PEKDetails)
	if result.ReportVerified {
		b.WriteString("报告签名: 验证通过\n")
	} else {
		b.WriteString("报告签名: 验证失败\n")
	}

	if verifyChain {
		fmt.Fprintf(&b, "证书来源: %s\n", result.ChainSource)
		writeWrappedValue(&b, "HRK URL", result.HRKURL, 80, "  ")
		writeWrappedValue(&b, "HSK/CEK URL", result.HSKCEKURL, 80, "  ")
		if result.ChainDownloadNote != "" {
			writeWrappedValue(&b, "下载说明", result.ChainDownloadNote, 80, "  ")
		}
		if result.CertDetails != nil {
			writeRootCertDetails(&b, "HRK 证书", result.CertDetails.HRK)
			writeRootCertDetails(&b, "HSK 证书", result.CertDetails.HSK)
			writeCSVCertDetails(&b, "CEK 证书", result.CertDetails.CEK)
			writeCSVCertDetails(&b, "PEK 证书", result.CertDetails.PEK)
		}
		if result.ChainVerified {
			b.WriteString("证书链: 验证通过\n")
		} else {
			b.WriteString("证书链: 验证失败\n")
		}
	} else {
		b.WriteString("证书链: 未验证\n")
	}
	return b.String()
}

func writeRootCertDetails(b *strings.Builder, title string, cert parsedRootCertDetails) {
	fmt.Fprintf(b, "\n%s:\n", title)
	fmt.Fprintf(b, "  KeyUsage: 0x%x\n", cert.KeyUsage)
	writePubKeyDetails(b, cert.PubKey)
	fmt.Fprintf(b, "  自签名: %s\n", yesNo(cert.SelfSignatureVerified))
	fmt.Fprintf(b, "  HRK 签名: %s\n", yesNo(cert.SignedByHRKVerified))
}

func writeCSVCertDetails(b *strings.Builder, title string, cert parsedCSVCertDetails) {
	fmt.Fprintf(b, "\n%s:\n", title)
	fmt.Fprintf(b, "  PubKeyUsage: 0x%x\n", cert.PubKeyUsage)
	fmt.Fprintf(b, "  Sig1Usage: 0x%x\n", cert.Sig1Usage)
	fmt.Fprintf(b, "  Sig2Usage: 0x%x\n", cert.Sig2Usage)
	writePubKeyDetails(b, cert.PubKey)
	fmt.Fprintf(b, "  HSK 签名: %s\n", yesNo(cert.SignedByHSKVerified))
	fmt.Fprintf(b, "  CEK 签名: %s\n", yesNo(cert.SignedByCEKVerified))
}

func writePubKeyDetails(b *strings.Builder, pub parsedPubKeyDetails) {
	fmt.Fprintf(b, "  CurveID: 0x%x\n", pub.CurveID)
	fmt.Fprintf(b, "  UserID: %s\n", pub.UserID)
	writeWrappedValue(b, "  UserID Hex", pub.UserIDHex, 64, "    ")
	writeWrappedValue(b, "  QX", pub.QXHex, 64, "    ")
	writeWrappedValue(b, "  QY", pub.QYHex, 64, "    ")
}

func writeWrappedValue(b *strings.Builder, label, value string, width int, continuationIndent string) {
	if value == "" {
		fmt.Fprintf(b, "%s: \n", label)
		return
	}
	fmt.Fprintf(b, "%s: ", label)
	for len(value) > width {
		b.WriteString(value[:width])
		b.WriteString("\n")
		b.WriteString(continuationIndent)
		value = value[width:]
	}
	b.WriteString(value)
	b.WriteString("\n")
}

func yesNo(v bool) string {
	if v {
		return "验证通过"
	}
	return "验证失败"
}

type attestationFieldRow struct {
	Name  string
	Value string
}

func buildAttestationFieldRows(reportFile string, verifyChain bool, result *attestationVerificationResult) []attestationFieldRow {
	rows := []attestationFieldRow{
		{Name: "报告文件", Value: ""},
		{Name: "报告长度", Value: ""},
		{Name: "PUBKEY_DIGEST (0x000)", Value: ""},
		{Name: "ID (0x020)", Value: ""},
		{Name: "Version (0x030)", Value: ""},
		{Name: "USERDATA (0x040)", Value: ""},
		{Name: "MNONCE (0x080)", Value: ""},
		{Name: "DIGEST (0x090)", Value: ""},
		{Name: "POLICY (0x0B0)", Value: ""},
		{Name: "SIG_USAGE (0x0B4)", Value: ""},
		{Name: "SIG_ALGO (0x0B8)", Value: ""},
		{Name: "ANONCE (0x0BC)", Value: ""},
		{Name: "Signature (0x0C0)", Value: ""},
		{Name: "PEK_CERT (0x150)", Value: ""},
		{Name: "CHIP_ID (0x974)", Value: ""},
		{Name: "Reserved2 (0x9B4)", Value: ""},
		{Name: "MAC (0x9D4)", Value: ""},
		{Name: "报告签名", Value: ""},
		{Name: "", Value: ""},
		{Name: "报告内 PEK 证书 PubKeyUsage", Value: ""},
		{Name: "报告内 PEK 证书 Sig1Usage", Value: ""},
		{Name: "报告内 PEK 证书 Sig2Usage", Value: ""},
		{Name: "报告内 PEK 证书 CurveID", Value: ""},
		{Name: "报告内 PEK 证书 UserID", Value: ""},
		{Name: "报告内 PEK 证书 UserID Hex", Value: ""},
		{Name: "报告内 PEK 证书 QX", Value: ""},
		{Name: "报告内 PEK 证书 QY", Value: ""},
	}

	if verifyChain {
		rows = append(rows,
			attestationFieldRow{Name: "", Value: ""},
			attestationFieldRow{Name: "证书来源", Value: ""},
			attestationFieldRow{Name: "HRK URL", Value: ""},
			attestationFieldRow{Name: "HSK/CEK URL", Value: ""},
			attestationFieldRow{Name: "下载说明", Value: ""},
			attestationFieldRow{Name: "", Value: ""},
			attestationFieldRow{Name: "HRK 证书 KeyUsage", Value: ""},
			attestationFieldRow{Name: "HRK 证书 CurveID", Value: ""},
			attestationFieldRow{Name: "HRK 证书 UserID", Value: ""},
			attestationFieldRow{Name: "HRK 证书 UserID Hex", Value: ""},
			attestationFieldRow{Name: "HRK 证书 QX", Value: ""},
			attestationFieldRow{Name: "HRK 证书 QY", Value: ""},
			attestationFieldRow{Name: "HRK 证书 自签名", Value: ""},
			attestationFieldRow{Name: "", Value: ""},
			attestationFieldRow{Name: "HSK 证书 KeyUsage", Value: ""},
			attestationFieldRow{Name: "HSK 证书 CurveID", Value: ""},
			attestationFieldRow{Name: "HSK 证书 UserID", Value: ""},
			attestationFieldRow{Name: "HSK 证书 UserID Hex", Value: ""},
			attestationFieldRow{Name: "HSK 证书 QX", Value: ""},
			attestationFieldRow{Name: "HSK 证书 QY", Value: ""},
			attestationFieldRow{Name: "HSK 证书 HRK 签名", Value: ""},
			attestationFieldRow{Name: "", Value: ""},
			attestationFieldRow{Name: "CEK 证书 PubKeyUsage", Value: ""},
			attestationFieldRow{Name: "CEK 证书 Sig1Usage", Value: ""},
			attestationFieldRow{Name: "CEK 证书 Sig2Usage", Value: ""},
			attestationFieldRow{Name: "CEK 证书 CurveID", Value: ""},
			attestationFieldRow{Name: "CEK 证书 UserID", Value: ""},
			attestationFieldRow{Name: "CEK 证书 UserID Hex", Value: ""},
			attestationFieldRow{Name: "CEK 证书 QX", Value: ""},
			attestationFieldRow{Name: "CEK 证书 QY", Value: ""},
			attestationFieldRow{Name: "CEK 证书 HSK 签名", Value: ""},
			attestationFieldRow{Name: "", Value: ""},
			attestationFieldRow{Name: "PEK 证书 PubKeyUsage", Value: ""},
			attestationFieldRow{Name: "PEK 证书 Sig1Usage", Value: ""},
			attestationFieldRow{Name: "PEK 证书 Sig2Usage", Value: ""},
			attestationFieldRow{Name: "PEK 证书 CurveID", Value: ""},
			attestationFieldRow{Name: "PEK 证书 UserID", Value: ""},
			attestationFieldRow{Name: "PEK 证书 UserID Hex", Value: ""},
			attestationFieldRow{Name: "PEK 证书 QX", Value: ""},
			attestationFieldRow{Name: "PEK 证书 QY", Value: ""},
			attestationFieldRow{Name: "PEK 证书 CEK 签名", Value: ""},
			attestationFieldRow{Name: "", Value: ""},
			attestationFieldRow{Name: "证书链", Value: ""},
		)
	} else {
		rows = append(rows, attestationFieldRow{Name: "证书链", Value: "未验证"})
	}

	if result == nil {
		if reportFile != "" {
			rows[0].Value = reportFile
		}
		return rows
	}

	rows[0].Value = reportFile
	rows[1].Value = fmt.Sprintf("%d bytes", result.ReportSize)
	rows[2].Value = hex.EncodeToString(result.PubkeyDigest)
	rows[3].Value = hex.EncodeToString(result.VMID)
	rows[4].Value = hex.EncodeToString(result.VMVersion)
	rows[5].Value = hex.EncodeToString(result.UserData)
	rows[6].Value = hex.EncodeToString(result.MNonce)
	rows[7].Value = hex.EncodeToString(result.Digest)
	rows[8].Value = fmt.Sprintf("0x%08x", result.Policy)
	rows[9].Value = fmt.Sprintf("0x%08x", result.SigUsage)
	rows[10].Value = fmt.Sprintf("0x%08x", result.SigAlgo)
	rows[11].Value = fmt.Sprintf("0x%08x", result.ANonce)
	rows[12].Value = hex.EncodeToString(result.Signature)
	rows[13].Value = fmt.Sprintf("%d bytes", len(result.PEKCert))
	rows[14].Value = fmt.Sprintf("%s (%s)", result.ChipIDASCII, hex.EncodeToString(result.ChipID))
	rows[15].Value = hex.EncodeToString(result.Reserved2)
	rows[16].Value = hex.EncodeToString(result.MAC)
	rows[17].Value = yesNo(result.ReportVerified)

	rows[19].Value = fmt.Sprintf("0x%x", result.PEKDetails.PubKeyUsage)
	rows[20].Value = fmt.Sprintf("0x%x", result.PEKDetails.Sig1Usage)
	rows[21].Value = fmt.Sprintf("0x%x", result.PEKDetails.Sig2Usage)
	rows[22].Value = fmt.Sprintf("0x%x", result.PEKDetails.PubKey.CurveID)
	rows[23].Value = result.PEKDetails.PubKey.UserID
	rows[24].Value = result.PEKDetails.PubKey.UserIDHex
	rows[25].Value = result.PEKDetails.PubKey.QXHex
	rows[26].Value = result.PEKDetails.PubKey.QYHex

	if verifyChain {
		idx := 28
		rows[idx].Value = valueOrDefault(result.ChainSource, "未验证")
		rows[idx+1].Value = result.HRKURL
		rows[idx+2].Value = result.HSKCEKURL
		rows[idx+3].Value = result.ChainDownloadNote

		if result.CertDetails != nil {
			idx += 5
			rows[idx].Value = fmt.Sprintf("0x%x", result.CertDetails.HRK.KeyUsage)
			rows[idx+1].Value = fmt.Sprintf("0x%x", result.CertDetails.HRK.PubKey.CurveID)
			rows[idx+2].Value = result.CertDetails.HRK.PubKey.UserID
			rows[idx+3].Value = result.CertDetails.HRK.PubKey.UserIDHex
			rows[idx+4].Value = result.CertDetails.HRK.PubKey.QXHex
			rows[idx+5].Value = result.CertDetails.HRK.PubKey.QYHex
			rows[idx+6].Value = yesNo(result.CertDetails.HRK.SelfSignatureVerified)

			idx += 8
			rows[idx].Value = fmt.Sprintf("0x%x", result.CertDetails.HSK.KeyUsage)
			rows[idx+1].Value = fmt.Sprintf("0x%x", result.CertDetails.HSK.PubKey.CurveID)
			rows[idx+2].Value = result.CertDetails.HSK.PubKey.UserID
			rows[idx+3].Value = result.CertDetails.HSK.PubKey.UserIDHex
			rows[idx+4].Value = result.CertDetails.HSK.PubKey.QXHex
			rows[idx+5].Value = result.CertDetails.HSK.PubKey.QYHex
			rows[idx+6].Value = yesNo(result.CertDetails.HSK.SignedByHRKVerified)

			idx += 8
			rows[idx].Value = fmt.Sprintf("0x%x", result.CertDetails.CEK.PubKeyUsage)
			rows[idx+1].Value = fmt.Sprintf("0x%x", result.CertDetails.CEK.Sig1Usage)
			rows[idx+2].Value = fmt.Sprintf("0x%x", result.CertDetails.CEK.Sig2Usage)
			rows[idx+3].Value = fmt.Sprintf("0x%x", result.CertDetails.CEK.PubKey.CurveID)
			rows[idx+4].Value = result.CertDetails.CEK.PubKey.UserID
			rows[idx+5].Value = result.CertDetails.CEK.PubKey.UserIDHex
			rows[idx+6].Value = result.CertDetails.CEK.PubKey.QXHex
			rows[idx+7].Value = result.CertDetails.CEK.PubKey.QYHex
			rows[idx+8].Value = yesNo(result.CertDetails.CEK.SignedByHSKVerified)

			idx += 10
			rows[idx].Value = fmt.Sprintf("0x%x", result.CertDetails.PEK.PubKeyUsage)
			rows[idx+1].Value = fmt.Sprintf("0x%x", result.CertDetails.PEK.Sig1Usage)
			rows[idx+2].Value = fmt.Sprintf("0x%x", result.CertDetails.PEK.Sig2Usage)
			rows[idx+3].Value = fmt.Sprintf("0x%x", result.CertDetails.PEK.PubKey.CurveID)
			rows[idx+4].Value = result.CertDetails.PEK.PubKey.UserID
			rows[idx+5].Value = result.CertDetails.PEK.PubKey.UserIDHex
			rows[idx+6].Value = result.CertDetails.PEK.PubKey.QXHex
			rows[idx+7].Value = result.CertDetails.PEK.PubKey.QYHex
			rows[idx+8].Value = yesNo(result.CertDetails.PEK.SignedByCEKVerified)

			idx += 10
			rows[idx].Value = yesNo(result.ChainVerified)
		}
	} else {
		rows[len(rows)-1].Value = "未验证"
	}
	return rows
}

func appendCSVCertRows(rows []attestationFieldRow, prefix string, cert parsedCSVCertDetails) []attestationFieldRow {
	rows = append(rows,
		attestationFieldRow{Name: prefix + " PubKeyUsage", Value: fmt.Sprintf("0x%x", cert.PubKeyUsage)},
		attestationFieldRow{Name: prefix + " Sig1Usage", Value: fmt.Sprintf("0x%x", cert.Sig1Usage)},
		attestationFieldRow{Name: prefix + " Sig2Usage", Value: fmt.Sprintf("0x%x", cert.Sig2Usage)},
	)
	rows = appendPubKeyRows(rows, prefix, cert.PubKey)

	if strings.Contains(prefix, "CEK") {
		rows = append(rows, attestationFieldRow{Name: prefix + " HSK 签名", Value: yesNo(cert.SignedByHSKVerified)})
	} else if strings.Contains(prefix, "PEK") {
		rows = append(rows, attestationFieldRow{Name: prefix + " CEK 签名", Value: yesNo(cert.SignedByCEKVerified)})
	} else {
		rows = append(rows,
			attestationFieldRow{Name: prefix + " HSK 签名", Value: yesNo(cert.SignedByHSKVerified)},
			attestationFieldRow{Name: prefix + " CEK 签名", Value: yesNo(cert.SignedByCEKVerified)},
		)
	}
	return rows
}

func appendRootCertRows(rows []attestationFieldRow, prefix string, cert parsedRootCertDetails) []attestationFieldRow {
	rows = append(rows, attestationFieldRow{Name: prefix + " KeyUsage", Value: fmt.Sprintf("0x%x", cert.KeyUsage)})
	rows = appendPubKeyRows(rows, prefix, cert.PubKey)

	if strings.Contains(prefix, "HRK") {
		rows = append(rows, attestationFieldRow{Name: prefix + " 自签名", Value: yesNo(cert.SelfSignatureVerified)})
	} else if strings.Contains(prefix, "HSK") {
		rows = append(rows, attestationFieldRow{Name: prefix + " HRK 签名", Value: yesNo(cert.SignedByHRKVerified)})
	} else {
		rows = append(rows,
			attestationFieldRow{Name: prefix + " 自签名", Value: yesNo(cert.SelfSignatureVerified)},
			attestationFieldRow{Name: prefix + " HRK 签名", Value: yesNo(cert.SignedByHRKVerified)},
		)
	}
	return rows
}

func appendPubKeyRows(rows []attestationFieldRow, prefix string, pub parsedPubKeyDetails) []attestationFieldRow {
	return append(rows,
		attestationFieldRow{Name: prefix + " CurveID", Value: fmt.Sprintf("0x%x", pub.CurveID)},
		attestationFieldRow{Name: prefix + " UserID", Value: pub.UserID},
		attestationFieldRow{Name: prefix + " UserID Hex", Value: pub.UserIDHex},
		attestationFieldRow{Name: prefix + " QX", Value: pub.QXHex},
		attestationFieldRow{Name: prefix + " QY", Value: pub.QYHex},
	)
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
