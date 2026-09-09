package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadStartupConfigFallsBackToIdentityEnvironment(t *testing.T) {
	t.Setenv("PLATFORM_IP", "env-platform:8080")
	t.Setenv("DOCKER_ID", "env-docker")
	t.Setenv("CONTRACT", "env-contract")

	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"addr": ":7001",
		"securityScan": false,
		"modelDir": "/tmp/models",
		"resultCheck": false,
		"dataDir": "/tmp/data",
		"resultDir": "/tmp/results",
		"llm": {
			"enabled": false,
			"endpoint": "http://llm.example:11434",
			"model": "qwen-test",
			"policy": "gate",
			"failClosed": false
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.PlatformIP != "env-platform:8080" {
		t.Fatalf("PlatformIP = %q, want env fallback", cfg.PlatformIP)
	}
	if cfg.DockerID != "env-docker" {
		t.Fatalf("DockerID = %q, want env fallback", cfg.DockerID)
	}
	if cfg.Contract != "env-contract" {
		t.Fatalf("Contract = %q, want env fallback", cfg.Contract)
	}
}

func TestLoadStartupConfigUsesIdentityFromFile(t *testing.T) {
	t.Setenv("PLATFORM_IP", "env-platform:8080")
	t.Setenv("DOCKER_ID", "env-docker")
	t.Setenv("CONTRACT", "env-contract")

	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"addr": ":7001",
		"platformIP": "file-platform:8080",
		"dockerID": "file-docker",
		"contract": "file-contract"
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.PlatformIP != "file-platform:8080" {
		t.Fatalf("PlatformIP = %q, want file value", cfg.PlatformIP)
	}
	if cfg.DockerID != "file-docker" {
		t.Fatalf("DockerID = %q, want file value", cfg.DockerID)
	}
	if cfg.Contract != "file-contract" {
		t.Fatalf("Contract = %q, want file value", cfg.Contract)
	}
}

func TestLoadStartupConfigAppliesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.Addr != ":6001" {
		t.Fatalf("Addr = %q, want default", cfg.Addr)
	}
	if !cfg.EnableSecurityScan {
		t.Fatalf("EnableSecurityScan = false, want default true")
	}
	if cfg.ModelDir != "/opt/taa/models" {
		t.Fatalf("ModelDir = %q, want default", cfg.ModelDir)
	}
	if !cfg.EnableResultCheck {
		t.Fatalf("EnableResultCheck = false, want default true")
	}
	if cfg.DataDir != "/opt/taa/data" {
		t.Fatalf("DataDir = %q, want default", cfg.DataDir)
	}
	if cfg.ResultDir != "/opt/taa/results" {
		t.Fatalf("ResultDir = %q, want default", cfg.ResultDir)
	}
	if cfg.ModelInputDir != "/opt/taa/input" {
		t.Fatalf("ModelInputDir = %q, want default", cfg.ModelInputDir)
	}
	if cfg.ModelOutputDir != "/opt/taa/output" {
		t.Fatalf("ModelOutputDir = %q, want default", cfg.ModelOutputDir)
	}
	if !cfg.EnableLLM {
		t.Fatalf("EnableLLM = false, want default true")
	}
	if cfg.LLMEndpoint != "http://127.0.0.1:11434" {
		t.Fatalf("LLMEndpoint = %q, want default", cfg.LLMEndpoint)
	}
	if cfg.LLMModel != "qwen2.5-coder:0.5b" {
		t.Fatalf("LLMModel = %q, want default", cfg.LLMModel)
	}
	if cfg.LLMPolicy != "assist" {
		t.Fatalf("LLMPolicy = %q, want default", cfg.LLMPolicy)
	}
	if !cfg.LLMFailClosed {
		t.Fatalf("LLMFailClosed = false, want default true")
	}
}

func TestLoadStartupConfigReadsLLMDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"llm": {
			"dir": "/opt/taa/ollama-qwen"
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.LLMDir != "/opt/taa/ollama-qwen" {
		t.Fatalf("LLMDir = %q, want file value", cfg.LLMDir)
	}
}

func TestLoadStartupConfigDoesNotReadOtherRuntimeEnvironment(t *testing.T) {
	t.Setenv("SECURITY_SCAN", "false")
	t.Setenv("RESULT_CHECK", "false")
	t.Setenv("SECURITY_LLM_VERIFY", "false")
	t.Setenv("SECURITY_LLM_ENDPOINT", "http://env-llm:11434")
	t.Setenv("SECURITY_LLM_MODEL", "env-model")
	t.Setenv("SECURITY_LLM_POLICY", "gate")
	t.Setenv("SECURITY_LLM_FAIL_CLOSED", "false")
	t.Setenv("MODEL_DIR", "/env/models")
	t.Setenv("DATA_DIR", "/env/data")
	t.Setenv("RESULT_DIR", "/env/results")
	t.Setenv("OLLAMA_DIR", "/env/ollama")

	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if !cfg.EnableSecurityScan || !cfg.EnableResultCheck || !cfg.EnableLLM || !cfg.LLMFailClosed {
		t.Fatalf("boolean runtime config unexpectedly read from environment: %+v", cfg)
	}
	if cfg.ModelDir != "/opt/taa/models" || cfg.DataDir != "/opt/taa/data" || cfg.ResultDir != "/opt/taa/results" {
		t.Fatalf("directory runtime config unexpectedly read from environment: %+v", cfg)
	}
	if cfg.LLMEndpoint != "http://127.0.0.1:11434" || cfg.LLMModel != "qwen2.5-coder:0.5b" || cfg.LLMPolicy != "assist" || cfg.LLMDir != "" {
		t.Fatalf("LLM runtime config unexpectedly read from environment: %+v", cfg)
	}
}

func TestLoadStartupConfigMissingFileReturnsError(t *testing.T) {
	_, err := LoadStartupConfig(filepath.Join(t.TempDir(), DefaultFileName))
	if err == nil {
		t.Fatal("LoadStartupConfig() error = nil, want missing file error")
	}
}

func writeTestConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
