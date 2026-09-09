package taa

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
