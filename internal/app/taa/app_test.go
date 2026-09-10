package taa

import (
	"bytes"
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	teecrypto "taa/pkg/crypto"
	"taa/internal/codeaudit"
	"taa/internal/config"
)

// TestDeriveUserDataAndKeyPair 校验国密 SM2 密钥生成与 UserData 派生逻辑：
// 生成的密钥对应可用于派生出恰好 64 字节的 UserData（前 32 字节 X，后 32 字节 Y）。
func TestDeriveUserDataAndKeyPair(t *testing.T) {
	keyPair, err := generateTAAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair failed: %v", err)
	}
	if keyPair.PrivateKey == nil {
		t.Fatalf("expected non-nil private key")
	}
	if keyPair.PublicKeyPEM == "" {
		t.Fatalf("expected non-empty public key PEM")
	}

	userData, err := deriveUserData(&keyPair.PrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("derive user data failed: %v", err)
	}
	if len(userData) != 64 {
		t.Fatalf("expected 64 bytes userdata, got %d", len(userData))
	}
}

// TestDeriveUserDataNilPublicKey 校验缺失公钥坐标时返回错误而非 panic
func TestDeriveUserDataNilPublicKey(t *testing.T) {
	if _, err := deriveUserData(nil); err == nil {
		t.Fatalf("expected error for nil public key")
	}
}

// TestDeriveUserDataExcessiveCoordinateLength 校验公钥坐标长度超过 32 字节时返回错误而非 panic
func TestDeriveUserDataExcessiveCoordinateLength(t *testing.T) {
	hugeVal := new(big.Int).Lsh(big.NewInt(1), 260) // > 32 字节
	pub := &teecrypto.SM2PublicKey{
		X: hugeVal,
		Y: big.NewInt(1),
	}
	if _, err := deriveUserData(pub); err == nil {
		t.Fatalf("expected error when coordinate length exceeds 32 bytes")
	}
}

// TestCheckKeyFileExists_DirectoryTargetFails 校验路径为目录时 checkKeyFileExists 严格返回错误而非假定存在
func TestCheckKeyFileExists_DirectoryTargetFails(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub-dir")
	if err := os.Mkdir(subDir, 0o700); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	exists, err := checkKeyFileExists(subDir)
	if err == nil {
		t.Fatalf("expected error when key file target is a directory, got exists=%v", exists)
	}
	if !strings.Contains(err.Error(), "found directory") {
		t.Fatalf("expected 'found directory' error message, got: %v", err)
	}
}

// TestBuildSecurityConfig 校验启动配置到控制器 SecurityConfig 的字段映射是否正确
func TestBuildSecurityConfig(t *testing.T) {
	cfg := config.StartupConfig{
		EnableSecurityScan: true,
		ModelDir:           "/opt/taa/models",
		EnableResultCheck:  true,
		DataDir:            "/opt/taa/data",
		ResultDir:          "/opt/taa/results",
		ModelInputDir:      "/opt/taa/models/input",
		ModelOutputDir:     "/opt/taa/models/output",
		EnableLLM:          true,
		LLMEndpoint:        "127.0.0.1:11434",
		LLMModel:           "qwen2.5-coder:0.5b",
		LLMPolicy:          "strict",
		LLMFailClosed:      true,
	}

	sec := buildSecurityConfig(cfg)

	if sec.ScanEnabled != cfg.EnableSecurityScan {
		t.Errorf("ScanEnabled = %v, want %v", sec.ScanEnabled, cfg.EnableSecurityScan)
	}
	if sec.ModelDir != cfg.ModelDir {
		t.Errorf("ModelDir = %q, want %q", sec.ModelDir, cfg.ModelDir)
	}
	if sec.ResultCheck != cfg.EnableResultCheck {
		t.Errorf("ResultCheck = %v, want %v", sec.ResultCheck, cfg.EnableResultCheck)
	}
	if sec.DataDir != cfg.DataDir {
		t.Errorf("DataDir = %q, want %q", sec.DataDir, cfg.DataDir)
	}
	if sec.ResultDir != cfg.ResultDir {
		t.Errorf("ResultDir = %q, want %q", sec.ResultDir, cfg.ResultDir)
	}
	if sec.ModelInputDir != cfg.ModelInputDir {
		t.Errorf("ModelInputDir = %q, want %q", sec.ModelInputDir, cfg.ModelInputDir)
	}
	if sec.ModelOutputDir != cfg.ModelOutputDir {
		t.Errorf("ModelOutputDir = %q, want %q", sec.ModelOutputDir, cfg.ModelOutputDir)
	}

	wantLLM := codeaudit.LLMConfig{
		Enabled:     cfg.EnableLLM,
		Endpoint:    cfg.LLMEndpoint,
		Model:       cfg.LLMModel,
		Timeout:     60 * time.Second,
		MaxFindings: 20,
		Policy:      cfg.LLMPolicy,
		FailClosed:  cfg.LLMFailClosed,
	}
	if sec.LLM.Enabled != wantLLM.Enabled {
		t.Errorf("LLM.Enabled = %v, want %v", sec.LLM.Enabled, wantLLM.Enabled)
	}
	if sec.LLM.Endpoint != wantLLM.Endpoint {
		t.Errorf("LLM.Endpoint = %q, want %q", sec.LLM.Endpoint, wantLLM.Endpoint)
	}
	if sec.LLM.Model != wantLLM.Model {
		t.Errorf("LLM.Model = %q, want %q", sec.LLM.Model, wantLLM.Model)
	}
	if sec.LLM.Timeout != wantLLM.Timeout {
		t.Errorf("LLM.Timeout = %v, want %v", sec.LLM.Timeout, wantLLM.Timeout)
	}
	if sec.LLM.MaxFindings != wantLLM.MaxFindings {
		t.Errorf("LLM.MaxFindings = %d, want %d", sec.LLM.MaxFindings, wantLLM.MaxFindings)
	}
	if sec.LLM.Policy != wantLLM.Policy {
		t.Errorf("LLM.Policy = %q, want %q", sec.LLM.Policy, wantLLM.Policy)
	}
	if sec.LLM.FailClosed != wantLLM.FailClosed {
		t.Errorf("LLM.FailClosed = %v, want %v", sec.LLM.FailClosed, wantLLM.FailClosed)
	}
}

// TestRunConfigNotFound 校验配置文件不存在时 Run 返回错误
func TestRunConfigNotFound(t *testing.T) {
	ctx := context.Background()
	err := Run(ctx, filepath.Join(t.TempDir(), "nonexistent-config.json"), "")
	if err == nil {
		t.Fatal("expected error when config file does not exist")
	}
	if !strings.Contains(err.Error(), "load startup config") {
		t.Fatalf("expected 'load startup config' error, got: %v", err)
	}
}

// TestEnsureQwenAvailableCancelledContext 校验上下文被取消时 ensureQwenAvailable 能够立即退出而非挂起
func TestEnsureQwenAvailableCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		ensureQwenAvailable(ctx, "http://127.0.0.1:65534", "test-model", t.TempDir())
		close(done)
	}()

	select {
	case <-done:
		// 成功快速返回
	case <-time.After(2 * time.Second):
		t.Fatal("ensureQwenAvailable did not return promptly with cancelled context")
	}
}

func TestLoadOrGenerateTAAKeyPair_FirstBoot(t *testing.T) {
	keysDir := t.TempDir()

	keyPair, loaded, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("first boot loadOrGenerateTAAKeyPair failed: %v", err)
	}
	if loaded {
		t.Fatalf("expected loaded=false on first boot, got loaded=true")
	}
	if keyPair == nil || keyPair.PrivateKey == nil || keyPair.PublicKeyPEM == "" {
		t.Fatalf("expected non-nil keyPair with valid keys")
	}

	privPath := filepath.Join(keysDir, defaultSM2PrivateKeyFile)
	pubPath := filepath.Join(keysDir, defaultSM2PublicKeyFile)

	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("private key file does not exist: %v", err)
	}
	if privInfo.Mode().Perm() != 0o600 {
		t.Errorf("private key perm = %o, want 0600", privInfo.Mode().Perm())
	}

	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("public key file does not exist: %v", err)
	}
	if pubInfo.Mode().Perm() != 0o644 {
		t.Errorf("public key perm = %o, want 0644", pubInfo.Mode().Perm())
	}

	userData, err := deriveUserData(&keyPair.PrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("deriveUserData failed: %v", err)
	}
	if len(userData) != 64 {
		t.Fatalf("expected 64 bytes userdata, got %d", len(userData))
	}
}

func TestLoadOrGenerateTAAKeyPair_RebootPersistenceAndCryptoRoundTrip(t *testing.T) {
	keysDir := t.TempDir()

	// 第 1 次启动：生成并落盘
	keyPair1, loaded1, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil || loaded1 {
		t.Fatalf("first boot failed: loaded=%v, err=%v", loaded1, err)
	}

	// 使用启动 1 派生的公钥加密一段业务数据（模拟外部平台或客户端信封加密请求）
	plaintext := []byte("confidential-model-dataset-payload-2026")
	sealed, err := teecrypto.SealSM2SM4GCM(&keyPair1.PrivateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SealSM2SM4GCM failed: %v", err)
	}

	// 第 2 次启动（模拟重启）：检测到目录中已有密钥，自动加载
	keyPair2, loaded2, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("second boot loadOrGenerateTAAKeyPair failed: %v", err)
	}
	if !loaded2 {
		t.Fatalf("expected loaded=true on reboot, got loaded=false")
	}

	// 验证公私钥内容完全一致
	if keyPair1.PrivateKey.D.Cmp(keyPair2.PrivateKey.D) != 0 {
		t.Fatalf("private key D coordinate mismatch after reboot")
	}
	if keyPair1.PublicKeyPEM != keyPair2.PublicKeyPEM {
		t.Fatalf("public key PEM mismatch after reboot")
	}

	// 使用重启后加载的私钥解密先前加密的数据包，确保历史解密能力一致
	decrypted, err := teecrypto.OpenSM2SM4GCM(keyPair2.PrivateKey, sealed)
	if err != nil {
		t.Fatalf("OpenSM2SM4GCM with rebooted key failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestLoadOrGenerateTAAKeyPair_TightensPermissionsOnReboot(t *testing.T) {
	keysDir := t.TempDir()

	// 首次启动生成
	_, _, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("first boot failed: %v", err)
	}

	privPath := filepath.Join(keysDir, defaultSM2PrivateKeyFile)

	// 模拟外部意外将私钥修改为过于宽松的权限 0666，目录修改为 0777
	if err := os.Chmod(privPath, 0o666); err != nil {
		t.Fatalf("chmod private key failed: %v", err)
	}
	if err := os.Chmod(keysDir, 0o777); err != nil {
		t.Fatalf("chmod keysDir failed: %v", err)
	}

	// 重启加载时应自动收紧权限
	_, loaded, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("reboot failed: %v", err)
	}
	if !loaded {
		t.Fatalf("expected loaded=true on reboot")
	}

	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat private key failed: %v", err)
	}
	if privInfo.Mode().Perm() != 0o600 {
		t.Errorf("expected private key permission tightened to 0600, got %o", privInfo.Mode().Perm())
	}

	dirInfo, err := os.Stat(keysDir)
	if err != nil {
		t.Fatalf("stat keysDir failed: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("expected keysDir permission tightened to 0700, got %o", dirInfo.Mode().Perm())
	}
}

func TestLoadOrGenerateTAAKeyPair_MissingPublicKey_SelfHealing(t *testing.T) {
	keysDir := t.TempDir()

	keyPairOrig, _, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("initial generation failed: %v", err)
	}

	// 模拟公钥意外丢失
	pubPath := filepath.Join(keysDir, defaultSM2PublicKeyFile)
	if err := os.Remove(pubPath); err != nil {
		t.Fatalf("remove public key failed: %v", err)
	}

	// 重启应触发自愈，从私钥重新导出并写入公钥
	keyPairHealed, loaded, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("self-healing load failed: %v", err)
	}
	if !loaded {
		t.Fatalf("expected loaded=true when self-healing from existing private key")
	}
	if keyPairHealed.PublicKeyPEM != keyPairOrig.PublicKeyPEM {
		t.Fatalf("healed public key does not match original public key")
	}

	// 检查公钥文件已被重建
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("healed public key file does not exist: %v", err)
	}
	if pubInfo.Mode().Perm() != 0o644 {
		t.Errorf("healed public key perm = %o, want 0644", pubInfo.Mode().Perm())
	}
}

func TestLoadOrGenerateTAAKeyPair_MissingPrivateKey_Fails(t *testing.T) {
	keysDir := t.TempDir()

	_, _, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("initial generation failed: %v", err)
	}

	// 模拟私钥丢失而公钥残留
	privPath := filepath.Join(keysDir, defaultSM2PrivateKeyFile)
	if err := os.Remove(privPath); err != nil {
		t.Fatalf("remove private key failed: %v", err)
	}

	// 重启必须 Fail-Closed，拒绝重新生成覆写
	_, _, err = loadOrGenerateTAAKeyPair(keysDir)
	if err == nil {
		t.Fatalf("expected error when private key is missing but public key exists, got nil")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("expected 'refusing to overwrite' error, got: %v", err)
	}
}

func TestLoadOrGenerateTAAKeyPair_CorruptedFile_Fails(t *testing.T) {
	keysDir := t.TempDir()
	privPath := filepath.Join(keysDir, defaultSM2PrivateKeyFile)
	pubPath := filepath.Join(keysDir, defaultSM2PublicKeyFile)

	if err := os.WriteFile(privPath, []byte("NOT_A_VALID_PEM_PRIVATE_KEY"), 0o600); err != nil {
		t.Fatalf("write invalid private key: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte("NOT_A_VALID_PEM_PUBLIC_KEY"), 0o644); err != nil {
		t.Fatalf("write invalid public key: %v", err)
	}

	_, _, err := loadOrGenerateTAAKeyPair(keysDir)
	if err == nil {
		t.Fatalf("expected error for corrupted key files, got nil")
	}
}

func TestLoadOrGenerateTAAKeyPair_KeyMismatch_Fails(t *testing.T) {
	keysDir := t.TempDir()

	// 生成密钥对 A 与 B
	pairA, err := generateTAAKeyPair()
	if err != nil {
		t.Fatalf("generate pair A: %v", err)
	}
	pairB, err := generateTAAKeyPair()
	if err != nil {
		t.Fatalf("generate pair B: %v", err)
	}

	privPEM, err := teecrypto.MarshalSM2PrivateKeyPEM(pairA.PrivateKey)
	if err != nil {
		t.Fatalf("marshal pair A private key: %v", err)
	}

	// 故意组合 Pair A 私钥与 Pair B 公钥
	privPath := filepath.Join(keysDir, defaultSM2PrivateKeyFile)
	pubPath := filepath.Join(keysDir, defaultSM2PublicKeyFile)
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatalf("write pair A private key: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(pairB.PublicKeyPEM), 0o644); err != nil {
		t.Fatalf("write pair B public key: %v", err)
	}

	_, _, err = loadOrGenerateTAAKeyPair(keysDir)
	if err == nil {
		t.Fatalf("expected error for mismatched key pair, got nil")
	}
	if !strings.Contains(err.Error(), "key mismatch") {
		t.Fatalf("expected 'key mismatch' error, got: %v", err)
	}
}
