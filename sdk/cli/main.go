package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"taa/crypto"
)

// fatal 打印错误信息并退出程序。
func fatal(format string, args ...any) {
	fmt.Printf("错误: "+format+"\n", args...)
	os.Exit(1)
}

// sm2Seal 读取公钥和明文，执行 SM2+SM4-GCM 加密，返回密文数据。
func sm2Seal(pubPEM, plaintext []byte) []byte {
	pub, err := crypto.ParseSM2PublicKeyPEM(pubPEM)
	if err != nil {
		fatal("解析公钥失败: %v", err)
	}
	sealed, err := crypto.SealSM2SM4GCM(pub, plaintext)
	if err != nil {
		fatal("加密失败: %v", err)
	}
	return sealed
}

// sm2Open 读取私钥和密文数据，直接解密 SM2+SM4-GCM 密文，返回明文。
func sm2Open(privPEM, encData []byte) []byte {
	priv, err := crypto.ParseSM2PrivateKeyPEM(privPEM)
	if err != nil {
		fatal("解析私钥失败: %v", err)
	}
	plaintext, err := crypto.OpenSM2SM4GCM(priv, encData)
	if err != nil {
		fatal("解密失败: %v", err)
	}
	return plaintext
}

// writeFile 将数据写入指定路径，失败时退出。
func writeFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0644); err != nil {
		fatal("写入输出文件失败: %v", err)
	}
}

// readFile 读取指定路径的文件，失败时退出。
func readFile(path, desc string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("读取%s失败: %v", desc, err)
	}
	return data
}

func main() {
	keyFlag := flag.String("key", "", "密钥文件路径 (.pem)")
	inputFlag := flag.String("input", "", "输入文件路径")
	outputFlag := flag.String("output", "", "输出文件路径（可选）")
	modeFlag := flag.String("mode", "", "操作模式: encrypt 或 decrypt")
	flag.Usage = func() {
		fmt.Println("格物平台加密工具 — SM2 信封加密 CLI")
		fmt.Println()
		fmt.Println("用法:")
		fmt.Println("  teecrypto-cli [选项]")
		fmt.Println()
		fmt.Println("不带参数时自动扫描程序所在目录，交互式选择文件。")
		fmt.Println()
		fmt.Println("选项:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  teecrypto-cli -key pub.pem -input secret.txt")
		fmt.Println("  teecrypto-cli -key priv.pem -input secret.txt.enc -mode decrypt")
		fmt.Println("  teecrypto-cli -key pub.pem -input data.bin -output data.enc")
	}
	flag.Parse()

	if *keyFlag != "" && *inputFlag != "" {
		runDirect(*keyFlag, *inputFlag, *outputFlag, *modeFlag)
		return
	}

	runInteractive()
}

// runDirect 非交互模式：根据命令行参数直接执行加密或解密
func runDirect(keyPath, inputPath, outputPath, mode string) {
	if mode == "" {
		if strings.ToLower(filepath.Ext(inputPath)) == ".enc" {
			mode = "decrypt"
		} else {
			mode = "encrypt"
		}
	}

	keyData := readFile(keyPath, "密钥文件")
	inputData := readFile(inputPath, "输入文件")

	switch mode {
	case "encrypt":
		outputData := sm2Seal(keyData, inputData)
		if outputPath == "" {
			outputPath = inputPath + ".enc"
		}
		writeFile(outputPath, outputData)
		fmt.Printf("✓ 加密成功: %s → %s (%d bytes)\n", filepath.Base(inputPath), filepath.Base(outputPath), len(outputData))

	case "decrypt":
		plaintext := sm2Open(keyData, inputData)
		if outputPath == "" {
			outputPath = strings.TrimSuffix(inputPath, filepath.Ext(inputPath))
			if outputPath == inputPath {
				outputPath += ".dec"
			}
		}
		writeFile(outputPath, plaintext)
		fmt.Printf("✓ 解密成功: %s → %s (%d bytes)\n", filepath.Base(inputPath), filepath.Base(outputPath), len(plaintext))

	default:
		fatal("未知操作模式 %q，请使用 encrypt 或 decrypt", mode)
	}
}

// runInteractive 交互式模式：自动扫描程序所在目录
func runInteractive() {
	exePath, err := os.Executable()
	if err != nil {
		fatal("获取程序路径失败: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	files, err := os.ReadDir(exeDir)
	if err != nil {
		fatal("读取目录失败: %v", err)
	}

	var pemFiles, encFiles, regularFiles []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		ext := strings.ToLower(filepath.Ext(name))
		switch {
		case ext == ".pem":
			pemFiles = append(pemFiles, name)
		case ext == ".enc":
			encFiles = append(encFiles, name)
		case ext != ".exe" && ext != ".bat" && ext != ".md" && ext != ".sh" &&
			strings.ToLower(name) != "encrypt.bat":
			regularFiles = append(regularFiles, name)
		}
	}

	if len(pemFiles) == 0 {
		fmt.Println("错误: 当前目录下未找到 .pem 密钥文件")
		fmt.Println("请将 .pem 密钥文件放在程序同目录下")
		pause()
		os.Exit(1)
	}

	keyFile := selectFile(pemFiles, "密钥文件 (.pem)")

	if len(encFiles) == 0 && len(regularFiles) == 0 {
		fmt.Println("错误: 当前目录下未找到可处理的文件")
		fmt.Println("加密模式: 需要普通文件 + .pem 公钥")
		fmt.Println("解密模式: 需要 .enc 文件 + .pem 私钥")
		pause()
		os.Exit(1)
	}

	if len(encFiles) > 0 && len(regularFiles) > 0 {
		fmt.Println("检测到两种类型的文件，请选择操作:")
		fmt.Println()
		fmt.Println("  1. 加密 - 将普通文件加密为 .enc 密文")
		fmt.Println("  2. 解密 - 将 .enc 密文解密为普通文件")
		fmt.Println()
		choice := promptChoice("请输入数字选择操作", 1, 2)
		if choice == 1 {
			encryptFile(exeDir, keyFile, selectFile(regularFiles, "待加密文件"))
		} else {
			decryptFile(exeDir, keyFile, selectFile(encFiles, "密文文件 (.enc)"))
		}
		return
	}

	if len(encFiles) > 0 {
		decryptFile(exeDir, keyFile, selectFile(encFiles, "密文文件 (.enc)"))
		return
	}

	encryptFile(exeDir, keyFile, selectFile(regularFiles, "待加密文件"))
}

func selectFile(files []string, fileType string) string {
	if len(files) == 1 {
		fmt.Printf("✓ 检测到%s: %s\n", fileType, files[0])
		fmt.Println()
		return files[0]
	}

	fmt.Printf("检测到 %d 个%s，请选择要处理的文件:\n", len(files), fileType)
	fmt.Println()
	for i, file := range files {
		fmt.Printf("  %d. %s\n", i+1, file)
	}
	fmt.Println()

	choice := promptChoice("请输入文件编号", 1, len(files))
	fmt.Printf("✓ 已选择: %s\n", files[choice-1])
	fmt.Println()
	return files[choice-1]
}

func promptChoice(prompt string, min, max int) int {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s (%d-%d): ", prompt, min, max)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		choice, err := strconv.Atoi(input)
		if err != nil {
			fmt.Printf("输入无效，请输入数字 %d 到 %d\n", min, max)
			continue
		}
		if choice < min || choice > max {
			fmt.Printf("选择超出范围，请输入 %d 到 %d 之间的数字\n", min, max)
			continue
		}
		return choice
	}
}

func pause() {
	fmt.Println()
	fmt.Print("按回车键退出...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func encryptFile(exeDir, keyFile, inputFile string) {
	fmt.Println("========================================")
	fmt.Println("  格物平台加密工具 - 加密模式")
	fmt.Println("========================================")
	fmt.Println()

	keyPath := filepath.Join(exeDir, keyFile)
	inputPath := filepath.Join(exeDir, inputFile)

	pubPEM := readFile(keyPath, "公钥文件")
	inputData := readFile(inputPath, "输入文件")
	outputData := sm2Seal(pubPEM, inputData)

	outputFile := inputFile + ".enc"
	outputPath := filepath.Join(exeDir, outputFile)
	writeFile(outputPath, outputData)

	fmt.Println("✓ 加密成功")
	fmt.Printf("  公钥: %s\n", keyFile)
	fmt.Printf("  输入: %s (%d bytes)\n", inputFile, len(inputData))
	fmt.Printf("  输出: %s (%d bytes)\n", outputFile, len(outputData))
	fmt.Println()
	fmt.Println("========================================")
	pause()
}

func decryptFile(exeDir, keyFile, encFile string) {
	fmt.Println("========================================")
	fmt.Println("  格物平台加密工具 - 解密模式")
	fmt.Println("========================================")
	fmt.Println()

	keyPath := filepath.Join(exeDir, keyFile)
	encPath := filepath.Join(exeDir, encFile)

	privPEM := readFile(keyPath, "私钥文件")
	encData := readFile(encPath, "密文文件")
	plaintext := sm2Open(privPEM, encData)

	outputFile := strings.TrimSuffix(encFile, filepath.Ext(encFile))
	outputPath := filepath.Join(exeDir, outputFile)
	if _, err := os.Stat(outputPath); err == nil {
		ext := filepath.Ext(outputFile)
		base := strings.TrimSuffix(outputFile, ext)
		outputFile = base + "_decrypted" + ext
		outputPath = filepath.Join(exeDir, outputFile)
	}
	writeFile(outputPath, plaintext)

	fmt.Println("✓ 解密成功")
	fmt.Printf("  私钥: %s\n", keyFile)
	fmt.Printf("  输入: %s (%d bytes)\n", encFile, len(encData))
	fmt.Printf("  输出: %s (%d bytes)\n", outputFile, len(plaintext))
	fmt.Println()
	fmt.Println("========================================")
	pause()
}
