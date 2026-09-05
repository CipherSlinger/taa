package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTarGzEncryptionDecryption(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a test folder with some files
	testFolder := filepath.Join(tempDir, "test_folder")
	err := os.MkdirAll(testFolder, 0755)
	if err != nil {
		t.Fatalf("创建测试文件夹失败: %v", err)
	}

	// Create some test files
	testFile1 := filepath.Join(testFolder, "file1.txt")
	err = os.WriteFile(testFile1, []byte("Hello from file 1"), 0644)
	if err != nil {
		t.Fatalf("创建测试文件1失败: %v", err)
	}

	testFile2 := filepath.Join(testFolder, "file2.txt")
	err = os.WriteFile(testFile2, []byte("Hello from file 2"), 0644)
	if err != nil {
		t.Fatalf("创建测试文件2失败: %v", err)
	}

	// Create a subdirectory with a file
	subDir := filepath.Join(testFolder, "subdir")
	err = os.MkdirAll(subDir, 0755)
	if err != nil {
		t.Fatalf("创建子目录失败: %v", err)
	}

	testFile3 := filepath.Join(subDir, "file3.txt")
	err = os.WriteFile(testFile3, []byte("Hello from file 3 in subdirectory"), 0644)
	if err != nil {
		t.Fatalf("创建测试文件3失败: %v", err)
	}

	// Generate SM2 key pair
	publicPEM, privatePEM, err := generateSM2KeyPEM()
	if err != nil {
		t.Fatalf("生成 SM2 密钥对失败: %v", err)
	}

	// Encrypt the folder
	encryptedArtifact, err := encryptFileAction(testFolder, publicPEM)
	if err != nil {
		t.Fatalf("加密文件夹失败: %v", err)
	}

	// Save the encrypted file to disk
	_, err = saveFileArtifact(encryptedArtifact)
	if err != nil {
		t.Fatalf("保存加密文件失败: %v", err)
	}

	// Verify the encrypted file exists
	if _, err := os.Stat(encryptedArtifact.OutputPath); os.IsNotExist(err) {
		t.Fatalf("加密文件不存在: %s", encryptedArtifact.OutputPath)
	}

	// Verify the output path has .tar.gz.enc extension
	if filepath.Ext(encryptedArtifact.OutputPath) != ".enc" {
		t.Errorf("加密文件扩展名错误，期望 .enc，实际 %s", filepath.Ext(encryptedArtifact.OutputPath))
	}

	// Decrypt the file
	decryptedArtifact, err := decryptFileAction(encryptedArtifact.OutputPath, privatePEM)
	if err != nil {
		t.Fatalf("解密文件失败: %v", err)
	}

	// Verify the decrypted output exists
	if _, err := os.Stat(decryptedArtifact.OutputPath); os.IsNotExist(err) {
		t.Fatalf("解密输出不存在: %s", decryptedArtifact.OutputPath)
	}

	// Verify the decrypted content matches the original
	// Check file1.txt
	decryptedFile1 := filepath.Join(decryptedArtifact.OutputPath, "file1.txt")
	content1, err := os.ReadFile(decryptedFile1)
	if err != nil {
		t.Fatalf("读取解密文件1失败: %v", err)
	}
	if string(content1) != "Hello from file 1" {
		t.Errorf("解密文件1内容不匹配，期望 'Hello from file 1'，实际 '%s'", string(content1))
	}

	// Check file2.txt
	decryptedFile2 := filepath.Join(decryptedArtifact.OutputPath, "file2.txt")
	content2, err := os.ReadFile(decryptedFile2)
	if err != nil {
		t.Fatalf("读取解密文件2失败: %v", err)
	}
	if string(content2) != "Hello from file 2" {
		t.Errorf("解密文件2内容不匹配，期望 'Hello from file 2'，实际 '%s'", string(content2))
	}

	// Check file3.txt in subdirectory
	decryptedFile3 := filepath.Join(decryptedArtifact.OutputPath, "subdir", "file3.txt")
	content3, err := os.ReadFile(decryptedFile3)
	if err != nil {
		t.Fatalf("读取解密文件3失败: %v", err)
	}
	if string(content3) != "Hello from file 3 in subdirectory" {
		t.Errorf("解密文件3内容不匹配，期望 'Hello from file 3 in subdirectory'，实际 '%s'", string(content3))
	}

	t.Logf("测试通过！加密文件: %s，解密输出: %s", encryptedArtifact.OutputPath, decryptedArtifact.OutputPath)
}

func TestSingleFileTarGzEncryption(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a single test file
	testFile := filepath.Join(tempDir, "single_file.txt")
	originalContent := "This is a single file for testing tar.gz encryption"
	err := os.WriteFile(testFile, []byte(originalContent), 0644)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	// Generate SM2 key pair
	publicPEM, privatePEM, err := generateSM2KeyPEM()
	if err != nil {
		t.Fatalf("生成 SM2 密钥对失败: %v", err)
	}

	// Encrypt the single file
	encryptedArtifact, err := encryptFileAction(testFile, publicPEM)
	if err != nil {
		t.Fatalf("加密文件失败: %v", err)
	}

	// Save the encrypted file to disk
	_, err = saveFileArtifact(encryptedArtifact)
	if err != nil {
		t.Fatalf("保存加密文件失败: %v", err)
	}

	// Decrypt the file
	decryptedArtifact, err := decryptFileAction(encryptedArtifact.OutputPath, privatePEM)
	if err != nil {
		t.Fatalf("解密文件失败: %v", err)
	}

	// Verify the decrypted content matches the original
	decryptedFile := decryptedArtifact.OutputPath
	content, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("读取解密文件失败: %v", err)
	}
	if string(content) != originalContent {
		t.Errorf("解密文件内容不匹配，期望 '%s'，实际 '%s'", originalContent, string(content))
	}

	t.Logf("单文件测试通过！加密文件: %s，解密文件: %s", encryptedArtifact.OutputPath, decryptedArtifact.OutputPath)
}
