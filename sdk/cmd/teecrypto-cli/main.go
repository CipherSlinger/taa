// Command teecrypto-cli provides a subcommand-based CLI for use as an Electron backend.
//
// Usage:
//
//	teecrypto-cli genkey --output <dir>
//	teecrypto-cli encrypt --input <path> --pubkey <pem_or_file> --output <path>
//	teecrypto-cli decrypt --input <path> --privkey <pem_or_file> --output <path>
//	teecrypto-cli verify --report <path> [--chain]
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"teecrypto/attestation"
	"taa/crypto"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "genkey":
		cmdGenKey(os.Args[2:])
	case "encrypt":
		cmdEncrypt(os.Args[2:])
	case "decrypt":
		cmdDecrypt(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "readfile":
		cmdReadFile(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `用法: teecrypto-cli <命令> [选项]

命令:
  genkey    生成 SM2 密钥对
  encrypt   加密文件或文件夹
  decrypt   解密文件
  verify    验证远程报告
  readfile  读取文件内容（用于导入 PEM）

运行 teecrypto-cli <命令> --help 查看命令帮助。`)
}

// ─── genkey ────────────────────────────────────────────────────────

func cmdGenKey(args []string) {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	outputDir := fs.String("output", ".", "输出目录")
	memory := fs.Bool("memory", false, "在内存中生成，输出 PEM 文本而非文件路径")
	fs.Parse(args)

	priv, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		exitErr("生成密钥对失败", err)
	}

	pubPEM, err := crypto.MarshalSM2PublicKeyPEM(&priv.PublicKey)
	if err != nil {
		exitErr("序列化公钥失败", err)
	}

	prvPEM, err := crypto.MarshalSM2PrivateKeyPEM(priv)
	if err != nil {
		exitErr("序列化私钥失败", err)
	}

	if *memory {
		outputJSON(map[string]string{
			"publicKey":  string(pubPEM),
			"privateKey": string(prvPEM),
		})
		return
	}

	pubPath := filepath.Join(*outputDir, "public.pem")
	prvPath := filepath.Join(*outputDir, "private.pem")

	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		exitErr("写入公钥文件失败", err)
	}
	if err := os.WriteFile(prvPath, prvPEM, 0600); err != nil {
		exitErr("写入私钥文件失败", err)
	}

	outputJSON(map[string]string{
		"publicKey":  pubPath,
		"privateKey": prvPath,
	})
}

// ─── encrypt ───────────────────────────────────────────────────────

func cmdEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	inputPath := fs.String("input", "", "输入文件或文件夹路径")
	pubKeyArg := fs.String("pubkey", "", "公钥 PEM 文本或文件路径")
	outputPath := fs.String("output", "", "输出密文路径")
	fs.Parse(args)

	if *inputPath == "" || *pubKeyArg == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "错误: --input, --pubkey, --output 均为必填")
		os.Exit(1)
	}

	pubPEM, err := resolvePEM(*pubKeyArg)
	if err != nil {
		exitErr("解析公钥失败", err)
	}

	pub, err := crypto.ParseSM2PublicKeyPEM(pubPEM)
	if err != nil {
		exitErr("解析公钥 PEM 失败", err)
	}

	// Check if input is a directory → archive first
	info, err := os.Stat(*inputPath)
	if err != nil {
		exitErr("读取输入路径失败", err)
	}

	var plaintext []byte
	if info.IsDir() {
		// Create tar.gz archive of the folder
		tmpArchive := filepath.Join(os.TempDir(), "teecrypto_encrypt_tmp.tar.gz")
		defer os.Remove(tmpArchive)

		if err := crypto.CreateTarGzArchive([]string{*inputPath}, tmpArchive); err != nil {
			exitErr("创建归档失败", err)
		}

		plaintext, err = os.ReadFile(tmpArchive)
		if err != nil {
			exitErr("读取归档失败", err)
		}
	} else {
		plaintext, err = os.ReadFile(*inputPath)
		if err != nil {
			exitErr("读取输入文件失败", err)
		}
	}

	sealed, err := crypto.SealSM2SM4GCM(pub, plaintext)
	if err != nil {
		exitErr("加密失败", err)
	}

	if err := os.WriteFile(*outputPath, sealed, 0644); err != nil {
		exitErr("写入输出文件失败", err)
	}

	outputJSON(map[string]interface{}{
		"outputPath": *outputPath,
		"inputSize":  len(plaintext),
		"outputSize": len(sealed),
		"isArchive":  info.IsDir(),
	})
}

// ─── decrypt ───────────────────────────────────────────────────────

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	inputPath := fs.String("input", "", "输入密文路径")
	privKeyArg := fs.String("privkey", "", "私钥 PEM 文本或文件路径")
	outputPath := fs.String("output", "", "输出路径")
	fs.Parse(args)

	if *inputPath == "" || *privKeyArg == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "错误: --input, --privkey, --output 均为必填")
		os.Exit(1)
	}

	privPEM, err := resolvePEM(*privKeyArg)
	if err != nil {
		exitErr("解析私钥失败", err)
	}

	priv, err := crypto.ParseSM2PrivateKeyPEM(privPEM)
	if err != nil {
		exitErr("解析私钥 PEM 失败", err)
	}

	encData, err := os.ReadFile(*inputPath)
	if err != nil {
		exitErr("读取密文文件失败", err)
	}

	plaintext, err := crypto.OpenSM2SM4GCM(priv, encData)
	if err != nil {
		exitErr("解密失败", err)
	}

	// Try to detect if it's a tar.gz archive and extract
	isArchive := isTarGz(plaintext)

	if isArchive {
		if err := crypto.ExtractTarGzReader(bytes.NewReader(plaintext), *outputPath); err != nil {
			exitErr("解压归档失败", err)
		}
	} else {
		if err := os.WriteFile(*outputPath, plaintext, 0644); err != nil {
			exitErr("写入输出文件失败", err)
		}
	}

	outputJSON(map[string]interface{}{
		"outputPath": *outputPath,
		"inputSize":  len(encData),
		"outputSize": len(plaintext),
		"isArchive":  isArchive,
	})
}

// ─── verify ────────────────────────────────────────────────────────

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	reportPath := fs.String("report", "", "报告文件路径")
	verifyChain := fs.Bool("chain", false, "验证证书链")
	fs.Parse(args)

	if *reportPath == "" {
		fmt.Fprintln(os.Stderr, "错误: --report 为必填")
		os.Exit(1)
	}

	result, err := attestation.VerifyReport(*reportPath, *verifyChain)

	// Build JSON output even if there's an error (partial result may be useful)
	fields := buildFieldRows(*reportPath, *verifyChain, result)

	resp := map[string]interface{}{
		"fields": fields,
	}
	if err != nil {
		resp["error"] = err.Error()
	}

	outputJSON(resp)
	if err != nil {
		os.Exit(1)
	}
}

// ─── readfile ──────────────────────────────────────────────────────

func cmdReadFile(args []string) {
	fs := flag.NewFlagSet("readfile", flag.ExitOnError)
	path := fs.String("path", "", "文件路径")
	fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "错误: --path 为必填")
		os.Exit(1)
	}

	data, err := os.ReadFile(*path)
	if err != nil {
		exitErr("读取文件失败", err)
	}

	// Output raw content to stdout (for PEM import)
	fmt.Print(string(data))
}

// ─── Helpers ───────────────────────────────────────────────────────

func resolvePEM(arg string) ([]byte, error) {
	// If arg looks like a PEM string, use it directly
	if strings.HasPrefix(strings.TrimSpace(arg), "-----BEGIN") {
		return []byte(arg), nil
	}
	// Otherwise treat as file path
	return os.ReadFile(arg)
}

func isTarGz(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

func exitErr(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}

func outputJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

type fieldRow struct {
	Name  string
	Value string
}

func buildFieldRows(reportFile string, verifyChain bool, result *attestation.VerificationResult) []map[string]string {
	var rows []fieldRow
	if result == nil {
		rows = append(rows, fieldRow{Name: "报告文件", Value: reportFile})
		return convertRows(rows)
	}

	hex := func(b []byte) string { return fmt.Sprintf("%x", b) }

	rows = append(rows,
		fieldRow{Name: "报告文件", Value: reportFile},
		fieldRow{Name: "报告长度", Value: fmt.Sprintf("%d bytes", result.ReportSize)},
		fieldRow{Name: "PUBKEY_DIGEST (0x000)", Value: hex(result.PubkeyDigest)},
		fieldRow{Name: "ID (0x020)", Value: hex(result.VMID)},
		fieldRow{Name: "Version (0x030)", Value: hex(result.VMVersion)},
		fieldRow{Name: "USERDATA (0x040)", Value: hex(result.UserData)},
		fieldRow{Name: "MNONCE (0x080)", Value: hex(result.MNonce)},
		fieldRow{Name: "DIGEST (0x090)", Value: hex(result.Digest)},
		fieldRow{Name: "POLICY (0x0B0)", Value: fmt.Sprintf("0x%08x", result.Policy)},
		fieldRow{Name: "SIG_USAGE (0x0B4)", Value: fmt.Sprintf("0x%08x", result.SigUsage)},
		fieldRow{Name: "SIG_ALGO (0x0B8)", Value: fmt.Sprintf("0x%08x", result.SigAlgo)},
		fieldRow{Name: "ANONCE (0x0BC)", Value: fmt.Sprintf("0x%08x", result.ANonce)},
		fieldRow{Name: "Signature (0x0C0)", Value: hex(result.Signature)},
		fieldRow{Name: "PEK_CERT (0x150)", Value: fmt.Sprintf("%d bytes", len(result.PEKCert))},
		fieldRow{Name: "CHIP_ID (0x974)", Value: fmt.Sprintf("%s (%s)", result.ChipIDASCII, hex(result.ChipID))},
		fieldRow{Name: "Reserved2 (0x9B4)", Value: hex(result.Reserved2)},
		fieldRow{Name: "MAC (0x9D4)", Value: hex(result.MAC)},
	)

	verified := "验证失败"
	if result.ReportVerified {
		verified = "验证通过"
	}
	rows = append(rows, fieldRow{Name: "报告签名", Value: verified})
	rows = append(rows, fieldRow{Name: "", Value: ""}) // separator

	// PEK certificate details
	rows = append(rows,
		fieldRow{Name: "PEK PubKeyUsage", Value: fmt.Sprintf("0x%x", result.PEKDetails.PubKeyUsage)},
		fieldRow{Name: "PEK Sig1Usage", Value: fmt.Sprintf("0x%x", result.PEKDetails.Sig1Usage)},
		fieldRow{Name: "PEK Sig2Usage", Value: fmt.Sprintf("0x%x", result.PEKDetails.Sig2Usage)},
		fieldRow{Name: "PEK CurveID", Value: fmt.Sprintf("0x%x", result.PEKDetails.PubKey.CurveID)},
		fieldRow{Name: "PEK UserID", Value: result.PEKDetails.PubKey.UserID},
		fieldRow{Name: "PEK UserID Hex", Value: result.PEKDetails.PubKey.UserIDHex},
		fieldRow{Name: "PEK QX", Value: result.PEKDetails.PubKey.QXHex},
		fieldRow{Name: "PEK QY", Value: result.PEKDetails.PubKey.QYHex},
	)

	if verifyChain {
		rows = append(rows, fieldRow{Name: "", Value: ""}) // separator
		chainVerified := "验证失败"
		if result.ChainVerified {
			chainVerified = "验证通过"
		}
		rows = append(rows,
			fieldRow{Name: "证书来源", Value: valueOrDefault(result.ChainSource, "未知")},
			fieldRow{Name: "HRK URL", Value: result.HRKURL},
			fieldRow{Name: "HSK/CEK URL", Value: result.HSKCEKURL},
		)
		if result.ChainDownloadNote != "" {
			rows = append(rows, fieldRow{Name: "下载说明", Value: result.ChainDownloadNote})
		}

		if result.CertDetails != nil {
			rows = append(rows, fieldRow{Name: "", Value: ""}) // separator
			// HRK
			rows = append(rows,
				fieldRow{Name: "HRK KeyUsage", Value: fmt.Sprintf("0x%x", result.CertDetails.HRK.KeyUsage)},
				fieldRow{Name: "HRK UserID", Value: result.CertDetails.HRK.PubKey.UserID},
				fieldRow{Name: "HRK QX", Value: result.CertDetails.HRK.PubKey.QXHex},
				fieldRow{Name: "HRK QY", Value: result.CertDetails.HRK.PubKey.QYHex},
			)
			hrkSelf := "验证失败"
			if result.CertDetails.HRK.SelfSignatureVerified {
				hrkSelf = "验证通过"
			}
			rows = append(rows, fieldRow{Name: "HRK 自签名", Value: hrkSelf})

			rows = append(rows, fieldRow{Name: "", Value: ""})
			// HSK
			rows = append(rows,
				fieldRow{Name: "HSK KeyUsage", Value: fmt.Sprintf("0x%x", result.CertDetails.HSK.KeyUsage)},
				fieldRow{Name: "HSK UserID", Value: result.CertDetails.HSK.PubKey.UserID},
				fieldRow{Name: "HSK QX", Value: result.CertDetails.HSK.PubKey.QXHex},
				fieldRow{Name: "HSK QY", Value: result.CertDetails.HSK.PubKey.QYHex},
			)
			hskSig := "验证失败"
			if result.CertDetails.HSK.SignedByHRKVerified {
				hskSig = "验证通过"
			}
			rows = append(rows, fieldRow{Name: "HSK HRK签名", Value: hskSig})

			rows = append(rows, fieldRow{Name: "", Value: ""})
			// CEK
			rows = append(rows,
				fieldRow{Name: "CEK PubKeyUsage", Value: fmt.Sprintf("0x%x", result.CertDetails.CEK.PubKeyUsage)},
				fieldRow{Name: "CEK UserID", Value: result.CertDetails.CEK.PubKey.UserID},
				fieldRow{Name: "CEK QX", Value: result.CertDetails.CEK.PubKey.QXHex},
				fieldRow{Name: "CEK QY", Value: result.CertDetails.CEK.PubKey.QYHex},
			)
			cekSig := "验证失败"
			if result.CertDetails.CEK.SignedByHSKVerified {
				cekSig = "验证通过"
			}
			rows = append(rows, fieldRow{Name: "CEK HSK签名", Value: cekSig})

			rows = append(rows, fieldRow{Name: "", Value: ""})
			// PEK (chain)
			rows = append(rows,
				fieldRow{Name: "PEK (chain) UserID", Value: result.CertDetails.PEK.PubKey.UserID},
				fieldRow{Name: "PEK (chain) QX", Value: result.CertDetails.PEK.PubKey.QXHex},
				fieldRow{Name: "PEK (chain) QY", Value: result.CertDetails.PEK.PubKey.QYHex},
			)
			pekSig := "验证失败"
			if result.CertDetails.PEK.SignedByCEKVerified {
				pekSig = "验证通过"
			}
			rows = append(rows, fieldRow{Name: "PEK CEK签名", Value: pekSig})
		}

		rows = append(rows, fieldRow{Name: "", Value: ""})
		rows = append(rows, fieldRow{Name: "证书链", Value: chainVerified})
	} else {
		rows = append(rows, fieldRow{Name: "证书链", Value: "未验证"})
	}

	return convertRows(rows)
}

func convertRows(rows []fieldRow) []map[string]string {
	out := make([]map[string]string, len(rows))
	for i, r := range rows {
		out[i] = map[string]string{"name": r.Name, "value": r.Value}
		if r.Name == "" {
			out[i]["separator"] = "true"
		}
	}
	return out
}

func valueOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
