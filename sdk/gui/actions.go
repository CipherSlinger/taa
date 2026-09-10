package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"taa/pkg/crypto"
)

func generateSM4KeyBase64() (string, error) {
	key, err := crypto.GenerateSM4Key()
	if err != nil {
		return "", err
	}
	return encodeBase64(key), nil
}

func encryptTextSM4(keyBase64 string, plaintext string) (string, error) {
	key, err := decodeBase64Field("SM4 密钥", keyBase64)
	if err != nil {
		return "", err
	}
	ciphertext, err := crypto.Encrypt(key, []byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("SM4 加密失败: %w", err)
	}
	return encodeBase64(ciphertext), nil
}

func decryptTextSM4(keyBase64 string, ciphertextBase64 string) (string, error) {
	key, err := decodeBase64Field("SM4 密钥", keyBase64)
	if err != nil {
		return "", err
	}
	ciphertext, err := decodeBase64Field("SM4 密文", ciphertextBase64)
	if err != nil {
		return "", err
	}
	plaintext, err := crypto.Decrypt(key, ciphertext)
	if err != nil {
		return "", fmt.Errorf("SM4 解密失败: %w", err)
	}
	return string(plaintext), nil
}

func generateSM2KeyPEM() (string, string, error) {
	priv, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		return "", "", fmt.Errorf("生成 SM2 密钥对失败: %w", err)
	}
	publicPEM, err := crypto.MarshalSM2PublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}
	privatePEM, err := crypto.MarshalSM2PrivateKeyPEM(priv)
	if err != nil {
		return "", "", err
	}
	return string(publicPEM), string(privatePEM), nil
}

func sealText(publicPEM string, plaintext string) ([]byte, error) {
	pub, err := crypto.ParseSM2PublicKeyPEM([]byte(strings.TrimSpace(publicPEM)))
	if err != nil {
		return nil, fmt.Errorf("解析 SM2 公钥失败: %w", err)
	}
	sealed, err := crypto.SealSM2SM4GCM(pub, []byte(plaintext))
	if err != nil {
		return nil, fmt.Errorf("SM2+SM4-GCM 加密失败: %w", err)
	}
	return sealed, nil
}

func openEnvelope(privatePEM string, data []byte) (string, error) {
	priv, err := crypto.ParseSM2PrivateKeyPEM([]byte(strings.TrimSpace(privatePEM)))
	if err != nil {
		return "", fmt.Errorf("解析 SM2 私钥失败: %w", err)
	}
	plaintext, err := crypto.OpenSM2SM4GCM(priv, data)
	if err != nil {
		return "", fmt.Errorf("SM2+SM4-GCM 解密失败: %w", err)
	}
	return string(plaintext), nil
}

func decodeBase64Field(name string, value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("%s 不能为空", name)
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%s 不是有效的 Base64: %w", name, err)
	}
	return decoded, nil
}

func encodeBase64(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

type FileArtifact struct {
	Name       string
	SourcePath string
	OutputPath string
	SavedPath  string
	Data       []byte
}

func loadFileArtifact(path string) (*FileArtifact, error) {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" {
		return nil, errors.New("文件路径不能为空")
	}
	data, err := os.ReadFile(cleaned)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}
	return &FileArtifact{
		Name:       filepath.Base(cleaned),
		SourcePath: cleaned,
		Data:       data,
	}, nil
}

func saveFileArtifact(artifact *FileArtifact) (string, error) {
	if artifact == nil {
		return "", errors.New("文件结果为空")
	}
	if artifact.OutputPath == "" {
		return "", errors.New("未指定保存路径")
	}
	if err := os.MkdirAll(filepath.Dir(artifact.OutputPath), 0o755); err != nil {
		return "", fmt.Errorf("创建输出目录失败: %w", err)
	}
	if err := os.WriteFile(artifact.OutputPath, artifact.Data, 0o644); err != nil {
		return "", fmt.Errorf("保存文件失败: %w", err)
	}
	artifact.SavedPath = artifact.OutputPath
	return artifact.OutputPath, nil
}

func encryptSM4File(keyBase64 string, input *FileArtifact) (*FileArtifact, error) {
	if input == nil {
		return nil, errors.New("请先拖入输入文件")
	}
	key, err := decodeBase64Field("SM4 密钥", keyBase64)
	if err != nil {
		return nil, err
	}
	ciphertext, err := crypto.Encrypt(key, input.Data)
	if err != nil {
		return nil, fmt.Errorf("SM4 文件加密失败: %w", err)
	}
	outputPath := deriveSealOutputPath(input.SourcePath)
	return &FileArtifact{
		Name:       filepath.Base(outputPath),
		SourcePath: input.SourcePath,
		OutputPath: outputPath,
		Data:       ciphertext,
	}, nil
}

func decryptSM4File(keyBase64 string, input *FileArtifact) (*FileArtifact, error) {
	if input == nil {
		return nil, errors.New("请先拖入输入文件")
	}
	key, err := decodeBase64Field("SM4 密钥", keyBase64)
	if err != nil {
		return nil, err
	}
	plaintext, err := crypto.Decrypt(key, input.Data)
	if err != nil {
		return nil, fmt.Errorf("SM4 文件解密失败: %w", err)
	}
	outputPath := deriveOpenOutputPath(input.SourcePath)
	return &FileArtifact{
		Name:       filepath.Base(outputPath),
		SourcePath: input.SourcePath,
		OutputPath: outputPath,
		Data:       plaintext,
	}, nil
}

func sealFile(publicPEM string, input *FileArtifact) (*FileArtifact, error) {
	if input == nil {
		return nil, errors.New("请先选择输入文件")
	}
	pub, err := crypto.ParseSM2PublicKeyPEM([]byte(strings.TrimSpace(publicPEM)))
	if err != nil {
		return nil, fmt.Errorf("解析 SM2 公钥失败: %w", err)
	}
	data, err := crypto.SealSM2SM4GCM(pub, input.Data)
	if err != nil {
		return nil, fmt.Errorf("SM2+SM4-GCM 文件加密失败: %w", err)
	}
	outputPath := deriveSealOutputPath(input.SourcePath)
	return &FileArtifact{
		Name:       filepath.Base(outputPath),
		SourcePath: input.SourcePath,
		OutputPath: outputPath,
		Data:       data,
	}, nil
}

func openEnvelopeFile(privatePEM string, input *FileArtifact) (*FileArtifact, error) {
	if input == nil {
		return nil, errors.New("请先选择输入文件")
	}
	priv, err := crypto.ParseSM2PrivateKeyPEM([]byte(strings.TrimSpace(privatePEM)))
	if err != nil {
		return nil, fmt.Errorf("解析 SM2 私钥失败: %w", err)
	}
	plaintext, err := crypto.OpenSM2SM4GCM(priv, input.Data)
	if err != nil {
		return nil, fmt.Errorf("SM2+SM4-GCM 文件解密失败: %w", err)
	}
	outputPath := deriveOpenOutputPath(input.SourcePath)
	return &FileArtifact{
		Name:       filepath.Base(outputPath),
		SourcePath: input.SourcePath,
		OutputPath: outputPath,
		Data:       plaintext,
	}, nil
}

func deriveSealOutputPath(sourcePath string) string {
	return sameDirOutputPath(sourcePath, filepath.Base(sourcePath)+".enc")
}

func deriveFolderSealOutputPath(sourcePath string) string {
	// For folders, output name is foldername.tar.gz.enc
	base := filepath.Base(sourcePath)
	return sameDirOutputPath(sourcePath, base+".tar.gz.enc")
}

func deriveOpenOutputPath(sourcePath string) string {
	base := filepath.Base(sourcePath)
	if strings.HasSuffix(base, ".enc") {
		base = strings.TrimSuffix(base, ".enc")
	} else {
		base += ".dec"
	}
	return sameDirOutputPath(sourcePath, base)
}

func sameDirOutputPath(sourcePath, baseName string) string {
	if strings.TrimSpace(sourcePath) == "" {
		return baseName
	}
	return filepath.Join(filepath.Dir(sourcePath), baseName)
}

func encryptFileAction(filePath, publicPEM string) (*FileArtifact, error) {
	// Check if input is a file or folder
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("访问输入路径失败: %w", err)
	}

	var input *FileArtifact

	if !info.IsDir() && isCompressedFile(filePath) {
		// Single already-compressed file: skip tar.gz wrapping, encrypt directly
		input, err = loadFileArtifact(filePath)
		if err != nil {
			return nil, err
		}
		// Verify with magic bytes: if the file extension claims "compressed"
		// but the content doesn't match any known archive signature, wrap it
		// in tar.gz anyway so decrypt always gets a recognised format.
		if !isArchiveData(input.Data) {
			input, err = wrapInTarGz(filePath)
			if err != nil {
				return nil, err
			}
		}
	} else {
		input, err = wrapInTarGz(filePath)
		if err != nil {
			return nil, err
		}
	}

	// Encrypt the data
	result, err := sealFile(publicPEM, input)
	if err != nil {
		return nil, err
	}

	// Update paths to reflect original input
	result.SourcePath = filePath
	if info.IsDir() {
		result.OutputPath = deriveFolderSealOutputPath(filePath)
	} else {
		result.OutputPath = deriveSealOutputPath(filePath)
	}
	result.Name = filepath.Base(result.OutputPath)

	return result, nil
}

// wrapInTarGz compresses the file or folder at filePath into a tar.gz artifact.
func wrapInTarGz(filePath string) (*FileArtifact, error) {
	var data bytes.Buffer
	if err := crypto.CreateTarGzArchiveWriter([]string{filePath}, &data); err != nil {
		return nil, fmt.Errorf("压缩失败: %w", err)
	}
	return &FileArtifact{
		Name:       filepath.Base(filePath) + ".tar.gz",
		SourcePath: filePath,
		Data:       data.Bytes(),
	}, nil
}

// compressedExts lists file extensions that are already compressed or archived.
// Kept at package level to avoid per-call slice allocation.
var compressedExts = []string{
	".tar.gz", ".tgz",
	".tar.bz2", ".tbz2",
	".tar.xz", ".txz",
	".tar.zst",
	".tar.lz4",
	".gz", ".bz2", ".xz", ".zst", ".zstd",
	".lz4", ".lz", ".lzo",
	".zip", ".rar", ".7z",
	".cab", ".arj",
}

// isCompressedFile reports whether the file at path is already in a compressed
// or archive format, based on its extension.
func isCompressedFile(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range compressedExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// isArchiveData checks the first few bytes of data against known archive
// magic numbers. Used to verify that a file whose extension claims "compressed"
// actually contains compressed content.
func isArchiveData(data []byte) bool {
	return isGzipData(data) || isZipData(data) ||
		isBzip2Data(data) || isXzData(data) ||
		isRarData(data) || is7zData(data)
}

func isBzip2Data(data []byte) bool {
	return len(data) >= 3 && data[0] == 'B' && data[1] == 'Z' && data[2] == 'h'
}

func isXzData(data []byte) bool {
	return len(data) >= 6 &&
		data[0] == 0xfd && data[1] == '7' && data[2] == 'z' &&
		data[3] == 'X' && data[4] == 'Z' && data[5] == 0x00
}

func isRarData(data []byte) bool {
	return len(data) >= 7 &&
		data[0] == 'R' && data[1] == 'a' && data[2] == 'r' &&
		data[3] == '!' && data[4] == 0x1a && data[5] == 0x07
}

func is7zData(data []byte) bool {
	return len(data) >= 6 &&
		data[0] == '7' && data[1] == 'z' && data[2] == 0xbc &&
		data[3] == 0xaf && data[4] == 0x27 && data[5] == 0x1c
}

func decryptFileAction(filePath, privatePEM string) (*FileArtifact, error) {
	// Load the encrypted file
	input, err := loadFileArtifact(filePath)
	if err != nil {
		return nil, err
	}

	// Decrypt the envelope
	decryptedArtifact, err := openEnvelopeFile(privatePEM, input)
	if err != nil {
		return nil, err
	}

	// Determine suggested output name
	outputName := filepath.Base(filePath)
	if strings.HasSuffix(outputName, ".enc") {
		outputName = strings.TrimSuffix(outputName, ".enc")
	} else {
		outputName += ".dec"
	}

	// Detect archive format by magic bytes and extract accordingly.
	// gzip (0x1f 0x8b) → tar.gz extraction
	// zip  (PK\x03\x04) → zip extraction (from memory, no temp file)
	// otherwise          → raw file, return bytes for save dialog
	data := decryptedArtifact.Data

	var tempSourcePath string
	switch {
	case isGzipData(data):
		tempSourcePath, err = extractGzipToTempDir(data)
	case isZipData(data):
		tempSourcePath, err = extractZipToTempDir(data)
	}
	if err != nil {
		return nil, err
	}
	if tempSourcePath != "" {
		return &FileArtifact{
			Name:       outputName,
			SourcePath: filePath,
			OutputPath: tempSourcePath,
			Data:       data, // keep raw archive bytes so we can re-extract if temp dir is lost
		}, nil
	}

	// Raw file — return decrypted bytes directly for saving
	return &FileArtifact{
		Name:       outputName,
		SourcePath: filePath,
		OutputPath: "", // caller will set via save dialog
		Data:       data,
	}, nil
}

// isGzipData reports whether data begins with the gzip magic number (0x1f 0x8b).
func isGzipData(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// isZipData reports whether data begins with the zip local-file header
// signature (PK\x03\x04, i.e. 0x50 0x4b 0x03 0x04).
func isZipData(data []byte) bool {
	return len(data) >= 4 &&
		data[0] == 0x50 && data[1] == 0x4b &&
		data[2] == 0x03 && data[3] == 0x04
}

// extractGzipToTempDir extracts gzip/tar.gz data (from memory) into a temp
// directory and returns the path to the extracted content.
func extractGzipToTempDir(data []byte) (string, error) {
	extractDir, err := os.MkdirTemp("", "teecrypto_extract_*")
	if err != nil {
		return "", fmt.Errorf("创建临时目录失败: %w", err)
	}

	if err := crypto.ExtractTarGzReader(bytes.NewReader(data), extractDir); err != nil {
		return "", fmt.Errorf("解压 tar.gz 归档失败: %w", err)
	}

	return resolveExtractedPath(extractDir)
}

// extractZipToTempDir extracts zip data (from memory) into a temp directory
// and returns the path to the extracted content.
func extractZipToTempDir(data []byte) (string, error) {
	extractDir, err := os.MkdirTemp("", "teecrypto_extract_*")
	if err != nil {
		return "", fmt.Errorf("创建临时目录失败: %w", err)
	}

	if err := crypto.ExtractZipArchive(data, extractDir); err != nil {
		return "", fmt.Errorf("解压 zip 归档失败: %w", err)
	}

	return resolveExtractedPath(extractDir)
}

// resolveExtractedPath returns the single extracted entry's path when the
// directory contains exactly one item, otherwise returns the directory itself.
func resolveExtractedPath(extractDir string) (string, error) {
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return "", fmt.Errorf("读取解压目录失败: %w", err)
	}
	if len(entries) == 1 {
		return filepath.Join(extractDir, entries[0].Name()), nil
	}
	return extractDir, nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func copyDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dst, srcInfo.Mode())
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			err = copyDir(srcPath, dstPath)
		} else {
			err = copyFile(srcPath, dstPath)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// moveExtractedContent moves extracted files from temp location to final destination.
// Directory contents are merged into the destination; the destination folder is never deleted.
func moveExtractedContent(srcPath, dstPath string) error {
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("访问源文件失败: %w", err)
	}

	if srcInfo.IsDir() {
		if err := copyDir(srcPath, dstPath); err != nil {
			return fmt.Errorf("复制目录失败: %w", err)
		}
		os.RemoveAll(srcPath)
		return nil
	}

	// Single file: prefer fast rename, fall back to copy across devices.
	if err := os.Rename(srcPath, dstPath); err != nil {
		if err := copyFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("复制文件失败: %w", err)
		}
		os.Remove(srcPath)
	}
	return nil
}

func readPEMFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("读取 PEM 文件失败: %w", err)
	}
	return string(data), nil
}
