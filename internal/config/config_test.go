package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if cfg.MaxFileBytes != DefaultMaxFileBytes {
		t.Fatalf("MaxFileBytes = %d, want default %d", cfg.MaxFileBytes, DefaultMaxFileBytes)
	}
	if cfg.MaxResultBytes != DefaultMaxResultBytes {
		t.Fatalf("MaxResultBytes = %d, want default %d", cfg.MaxResultBytes, DefaultMaxResultBytes)
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
	if cfg.ModelOutputDir != "/opt/taa/output/result" {
		t.Fatalf("ModelOutputDir = %q, want default", cfg.ModelOutputDir)
	}
	if cfg.ModelLogDir != "/opt/taa/output/log/train.jsonl" {
		t.Fatalf("ModelLogDir = %q, want default", cfg.ModelLogDir)
	}
	if cfg.ModelProgressDir != "/opt/taa/output/progress/progress.json" {
		t.Fatalf("ModelProgressDir = %q, want default", cfg.ModelProgressDir)
	}
	if cfg.ModelCheckpointDir != "/opt/taa/checkpoint" {
		t.Fatalf("ModelCheckpointDir = %q, want default", cfg.ModelCheckpointDir)
	}
	if cfg.KeysDir != "/opt/taa/keys" {
		t.Fatalf("KeysDir = %q, want default", cfg.KeysDir)
	}
	if !cfg.EnableLLM {
		t.Fatalf("EnableLLM = false, want default true")
	}
	if cfg.LLMEndpoint != "https://127.0.0.1:8443" {
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
	if cfg.AttestationHRKCertPath == "" || cfg.AttestationHSKCekCertPath == "" {
		t.Fatalf("Attestation cert paths unexpectedly empty: hrk=%q, hsk=%q", cfg.AttestationHRKCertPath, cfg.AttestationHSKCekCertPath)
	}
}

func TestLoadStartupConfigReadsKeysDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"keysDir": ".local/taa/keys"
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.KeysDir != ".local/taa/keys" {
		t.Fatalf("KeysDir = %q, want file value", cfg.KeysDir)
	}
}

func TestLoadStartupConfigReadsMaxFileBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"maxFileBytes": 5368709120
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.MaxFileBytes != 5368709120 {
		t.Fatalf("MaxFileBytes = %d, want 5368709120", cfg.MaxFileBytes)
	}
	if cfg.MaxResultBytes != 5368709120 {
		t.Fatalf("MaxResultBytes = %d, want 5368709120", cfg.MaxResultBytes)
	}
}

func TestLoadStartupConfigReadsMaxResultBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"maxResultBytes": 5368709120
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.MaxFileBytes != 5368709120 {
		t.Fatalf("MaxFileBytes = %d, want 5368709120", cfg.MaxFileBytes)
	}
	if cfg.MaxResultBytes != 5368709120 {
		t.Fatalf("MaxResultBytes = %d, want 5368709120", cfg.MaxResultBytes)
	}
}

func TestLoadStartupConfigMaxFileBytesPrecedence(t *testing.T) {
	t.Run("resultCheck.maxFileBytes takes precedence over all", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path, `{
			"maxResultBytes": 100,
			"maxFileBytes": 200,
			"security": {
				"maxFileBytes": 300,
				"resultCheck": {
					"maxFileBytes": 400
				}
			}
		}`)

		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig() error = %v", err)
		}
		if cfg.MaxFileBytes != 400 || cfg.MaxResultBytes != 400 {
			t.Fatalf("MaxFileBytes = %d, MaxResultBytes = %d, want 400", cfg.MaxFileBytes, cfg.MaxResultBytes)
		}
	})

	t.Run("security.maxFileBytes takes precedence over root", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path, `{
			"maxResultBytes": 100,
			"maxFileBytes": 200,
			"security": {
				"maxFileBytes": 300
			}
		}`)

		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig() error = %v", err)
		}
		if cfg.MaxFileBytes != 300 || cfg.MaxResultBytes != 300 {
			t.Fatalf("MaxFileBytes = %d, MaxResultBytes = %d, want 300", cfg.MaxFileBytes, cfg.MaxResultBytes)
		}
	})

	t.Run("root maxFileBytes takes precedence over legacy maxResultBytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path, `{
			"maxResultBytes": 100,
			"maxFileBytes": 200
		}`)

		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig() error = %v", err)
		}
		if cfg.MaxFileBytes != 200 || cfg.MaxResultBytes != 200 {
			t.Fatalf("MaxFileBytes = %d, MaxResultBytes = %d, want 200", cfg.MaxFileBytes, cfg.MaxResultBytes)
		}
	})
}

func TestLoadStartupConfigIgnoresWhitespaceKeysDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"keysDir": "   \t  "
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.KeysDir != "/opt/taa/keys" {
		t.Fatalf("KeysDir = %q, want default /opt/taa/keys", cfg.KeysDir)
	}
}

func TestLoadStartupConfigReadsLLMDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"llm": {
			"dir": "/opt/taa/ollama"
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.LLMDir != "/opt/taa/ollama" {
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
	t.Setenv("KEYS_DIR", "/env/keys")

	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if !cfg.EnableSecurityScan || !cfg.EnableResultCheck || !cfg.EnableLLM || !cfg.LLMFailClosed {
		t.Fatalf("boolean runtime config unexpectedly read from environment: %+v", cfg)
	}
	if cfg.ModelDir != "/opt/taa/models" || cfg.DataDir != "/opt/taa/data" || cfg.ResultDir != "/opt/taa/results" || cfg.KeysDir != "/opt/taa/keys" {
		t.Fatalf("directory runtime config unexpectedly read from environment: %+v", cfg)
	}
	if cfg.LLMEndpoint != "https://127.0.0.1:8443" || cfg.LLMModel != "qwen2.5-coder:0.5b" || cfg.LLMPolicy != "assist" || cfg.LLMDir != "" {
		t.Fatalf("LLM runtime config unexpectedly read from environment: %+v", cfg)
	}
}

func TestLoadStartupConfigMissingFileReturnsError(t *testing.T) {
	_, err := LoadStartupConfig(filepath.Join(t.TempDir(), DefaultFileName))
	if err == nil {
		t.Fatal("LoadStartupConfig() error = nil, want missing file error")
	}
}

func TestLoadStartupConfigReadsAttestationCertPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"attestation": {
			"hrkCertPath": "/custom/path/hrk.cert",
			"hskCekCertPath": "/custom/path/hsk_cek.cert"
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.AttestationHRKCertPath != "/custom/path/hrk.cert" {
		t.Errorf("AttestationHRKCertPath = %q, want %q", cfg.AttestationHRKCertPath, "/custom/path/hrk.cert")
	}
	if cfg.AttestationHSKCekCertPath != "/custom/path/hsk_cek.cert" {
		t.Errorf("AttestationHSKCekCertPath = %q, want %q", cfg.AttestationHSKCekCertPath, "/custom/path/hsk_cek.cert")
	}
}

func TestLoadStartupConfigAttestationTrimWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"attestation": {
			"hrkCertPath": "  /trimmed/hrk.cert  ",
			"hskCekCertPath": "  /trimmed/hsk_cek.cert  "
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.AttestationHRKCertPath != "/trimmed/hrk.cert" {
		t.Errorf("AttestationHRKCertPath = %q, want %q", cfg.AttestationHRKCertPath, "/trimmed/hrk.cert")
	}
	if cfg.AttestationHSKCekCertPath != "/trimmed/hsk_cek.cert" {
		t.Errorf("AttestationHSKCekCertPath = %q, want %q", cfg.AttestationHSKCekCertPath, "/trimmed/hsk_cek.cert")
	}
}

func TestLoadStartupConfigTemplateFiles(t *testing.T) {
	templates := []struct {
		relPath                string
		wantAddr               string
		wantModelDir           string
		wantDataDir            string
		wantResultDir          string
		wantKeysDir            string
		wantHRK                string
		wantHSKCek             string
		wantMaxResultBytes     int64
		wantModelInputDir      string
		wantModelOutputDir     string
		wantModelLogDir        string
		wantModelProgressDir   string
		wantModelCheckpointDir string
		wantSecurityScan       bool
		wantResultCheck        bool
		wantPlatformIP         string
		wantDockerID           string
		// wantLLMTimeoutMs pins the per-request inference budget a template sets.
		// Zero means "not asserted". The docker template needs a budget that
		// covers a cold model load on CPU-only inference; see
		// .claude/specs/2026-10-08-llm-timeout-layering-design.md.
		wantLLMTimeoutMs int64
	}{
		{
			relPath:                "../../configs/taa-production.json",
			wantAddr:               ":6001",
			wantModelDir:           "/root/taa/models",
			wantDataDir:            "/root/taa/data",
			wantResultDir:          "/root/taa/results",
			wantKeysDir:            "/opt/taa/keys",
			wantHRK:                "/root/taa/certs/hrk.cert",
			wantHSKCek:             "/root/taa/certs/hsk_cek.cert",
			wantMaxResultBytes:     3221225472,
			wantModelInputDir:      "/opt/taa/input",
			wantModelOutputDir:     "/opt/taa/output/result",
			wantModelLogDir:        "/opt/taa/output/log/train.jsonl",
			wantModelProgressDir:   "/opt/taa/output/progress/progress.json",
			wantModelCheckpointDir: "/opt/taa/checkpoint",
			wantSecurityScan:       true,
			wantResultCheck:        true,
			wantPlatformIP:         "",
			wantDockerID:           "",
		},
		{
			relPath:                "../../configs/taa-docker.json",
			wantAddr:               ":6001",
			wantModelDir:           "/root/taa/models",
			wantDataDir:            "/root/taa/data",
			wantResultDir:          "/root/taa/results",
			wantKeysDir:            "/opt/taa/keys",
			wantHRK:                "/root/taa/certs/hrk.cert",
			wantHSKCek:             "/root/taa/certs/hsk_cek.cert",
			wantMaxResultBytes:     3221225472,
			wantModelInputDir:      "/opt/taa/input",
			wantModelOutputDir:     "/opt/taa/output/result",
			wantModelLogDir:        "/opt/taa/output/log/train.jsonl",
			wantModelProgressDir:   "/opt/taa/output/progress/progress.json",
			wantModelCheckpointDir: "/opt/taa/checkpoint",
			wantSecurityScan:       true,
			wantResultCheck:        true,
			wantPlatformIP:         "127.0.0.1:18080",
			wantDockerID:           "taa-env-slim-v2",
			wantLLMTimeoutMs:       120000,
		},
	}

	for _, tc := range templates {
		t.Run(filepath.Base(tc.relPath), func(t *testing.T) {
			cfg, err := LoadStartupConfig(tc.relPath)
			if err != nil {
				t.Fatalf("LoadStartupConfig(%s) error = %v", tc.relPath, err)
			}
			if cfg.Addr != tc.wantAddr {
				t.Errorf("Addr = %q, want %q", cfg.Addr, tc.wantAddr)
			}
			if cfg.ModelDir != tc.wantModelDir {
				t.Errorf("ModelDir = %q, want %q", cfg.ModelDir, tc.wantModelDir)
			}
			if cfg.DataDir != tc.wantDataDir {
				t.Errorf("DataDir = %q, want %q", cfg.DataDir, tc.wantDataDir)
			}
			if cfg.ResultDir != tc.wantResultDir {
				t.Errorf("ResultDir = %q, want %q", cfg.ResultDir, tc.wantResultDir)
			}
			if cfg.KeysDir != tc.wantKeysDir {
				t.Errorf("KeysDir = %q, want %q", cfg.KeysDir, tc.wantKeysDir)
			}
			if cfg.AttestationHRKCertPath != tc.wantHRK {
				t.Errorf("AttestationHRKCertPath = %q, want %q", cfg.AttestationHRKCertPath, tc.wantHRK)
			}
			if cfg.AttestationHSKCekCertPath != tc.wantHSKCek {
				t.Errorf("AttestationHSKCekCertPath = %q, want %q", cfg.AttestationHSKCekCertPath, tc.wantHSKCek)
			}
			if cfg.MaxFileBytes != tc.wantMaxResultBytes {
				t.Errorf("MaxFileBytes = %d, want %d", cfg.MaxFileBytes, tc.wantMaxResultBytes)
			}
			if cfg.MaxResultBytes != tc.wantMaxResultBytes {
				t.Errorf("MaxResultBytes = %d, want %d", cfg.MaxResultBytes, tc.wantMaxResultBytes)
			}
			if cfg.ModelInputDir != tc.wantModelInputDir {
				t.Errorf("ModelInputDir = %q, want %q", cfg.ModelInputDir, tc.wantModelInputDir)
			}
			if cfg.ModelOutputDir != tc.wantModelOutputDir {
				t.Errorf("ModelOutputDir = %q, want %q", cfg.ModelOutputDir, tc.wantModelOutputDir)
			}
			if cfg.ModelLogDir != tc.wantModelLogDir {
				t.Errorf("ModelLogDir = %q, want %q", cfg.ModelLogDir, tc.wantModelLogDir)
			}
			if cfg.ModelProgressDir != tc.wantModelProgressDir {
				t.Errorf("ModelProgressDir = %q, want %q", cfg.ModelProgressDir, tc.wantModelProgressDir)
			}
			if cfg.ModelCheckpointDir != tc.wantModelCheckpointDir {
				t.Errorf("ModelCheckpointDir = %q, want %q", cfg.ModelCheckpointDir, tc.wantModelCheckpointDir)
			}
			if cfg.EnableSecurityScan != tc.wantSecurityScan {
				t.Errorf("EnableSecurityScan = %v, want %v", cfg.EnableSecurityScan, tc.wantSecurityScan)
			}
			if cfg.EnableResultCheck != tc.wantResultCheck {
				t.Errorf("EnableResultCheck = %v, want %v", cfg.EnableResultCheck, tc.wantResultCheck)
			}
			if tc.wantPlatformIP != "" && cfg.PlatformIP != tc.wantPlatformIP {
				t.Errorf("PlatformIP = %q, want %q", cfg.PlatformIP, tc.wantPlatformIP)
			}
			if tc.wantDockerID != "" && cfg.DockerID != tc.wantDockerID {
				t.Errorf("DockerID = %q, want %q", cfg.DockerID, tc.wantDockerID)
			}
			if tc.wantLLMTimeoutMs != 0 && cfg.LLMTimeoutMs != tc.wantLLMTimeoutMs {
				t.Errorf("LLMTimeoutMs = %d, want %d", cfg.LLMTimeoutMs, tc.wantLLMTimeoutMs)
			}
		})
	}
}

func TestLoadStartupConfig_ModularSections(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"server": {
			"addr": ":8088"
		},
		"platform": {
			"ip": "platform.local:9090",
			"dockerID": "pod-12345",
			"contract": "contract-abc"
		},
		"storage": {
			"model": "/data/storage/models",
			"data": "/data/storage/datasets",
			"result": "/data/storage/results",
			"keys": "/data/storage/keys"
		},
		"security": {
			"codeScan": false,
			"resultCheck": {
				"enabled": false,
				"maxFileBytes": 1048576
			}
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.Addr != ":8088" {
		t.Errorf("Addr = %q, want :8088", cfg.Addr)
	}
	if cfg.PlatformIP != "platform.local:9090" {
		t.Errorf("PlatformIP = %q, want platform.local:9090", cfg.PlatformIP)
	}
	if cfg.DockerID != "pod-12345" {
		t.Errorf("DockerID = %q, want pod-12345", cfg.DockerID)
	}
	if cfg.Contract != "contract-abc" {
		t.Errorf("Contract = %q, want contract-abc", cfg.Contract)
	}
	if cfg.ModelDir != "/data/storage/models" {
		t.Errorf("ModelDir = %q, want /data/storage/models", cfg.ModelDir)
	}
	if cfg.DataDir != "/data/storage/datasets" {
		t.Errorf("DataDir = %q, want /data/storage/datasets", cfg.DataDir)
	}
	if cfg.ResultDir != "/data/storage/results" {
		t.Errorf("ResultDir = %q, want /data/storage/results", cfg.ResultDir)
	}
	if cfg.KeysDir != "/data/storage/keys" {
		t.Errorf("KeysDir = %q, want /data/storage/keys", cfg.KeysDir)
	}
	if cfg.EnableSecurityScan {
		t.Errorf("EnableSecurityScan = true, want false")
	}
	if cfg.EnableResultCheck {
		t.Errorf("EnableResultCheck = true, want false")
	}
	if cfg.MaxFileBytes != 1048576 {
		t.Errorf("MaxFileBytes = %d, want 1048576", cfg.MaxFileBytes)
	}
	if cfg.MaxResultBytes != 1048576 {
		t.Errorf("MaxResultBytes = %d, want 1048576", cfg.MaxResultBytes)
	}
}

func TestLoadStartupConfig_ResultCheckBooleanCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"security": {
			"codeScan": true,
			"resultCheck": false
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if !cfg.EnableSecurityScan {
		t.Errorf("EnableSecurityScan = false, want true")
	}
	if cfg.EnableResultCheck {
		t.Errorf("EnableResultCheck = true, want false")
	}
}

func TestLoadStartupConfigReadsModelSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"model": {
			"input": "/custom/input",
			"checkpoint": "/custom/checkpoint",
			"output": {
				"result": "/custom/output/result",
				"log": "/custom/output/log",
				"progress": "/custom/output/progress"
			}
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.ModelInputDir != "/custom/input" {
		t.Errorf("ModelInputDir = %q, want %q", cfg.ModelInputDir, "/custom/input")
	}
	if cfg.ModelCheckpointDir != "/custom/checkpoint" {
		t.Errorf("ModelCheckpointDir = %q, want %q", cfg.ModelCheckpointDir, "/custom/checkpoint")
	}
	if cfg.ModelOutputDir != "/custom/output/result" {
		t.Errorf("ModelOutputDir = %q, want %q", cfg.ModelOutputDir, "/custom/output/result")
	}
	if cfg.ModelLogDir != "/custom/output/log" {
		t.Errorf("ModelLogDir = %q, want %q", cfg.ModelLogDir, "/custom/output/log")
	}
	if cfg.ModelProgressDir != "/custom/output/progress" {
		t.Errorf("ModelProgressDir = %q, want %q", cfg.ModelProgressDir, "/custom/output/progress")
	}
}

func TestLoadStartupConfigModelTrimWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"model": {
			"dir": "  /trimmed/models  ",
			"input": "  /trimmed/input  ",
			"checkpoint": "  /trimmed/checkpoint  ",
			"output": {
				"result": "  /trimmed/output/result  ",
				"log": "  /trimmed/output/log  ",
				"progress": "  /trimmed/output/progress  "
			}
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.ModelDir != "/trimmed/models" {
		t.Errorf("ModelDir = %q, want /trimmed/models", cfg.ModelDir)
	}
	if cfg.ModelInputDir != "/trimmed/input" {
		t.Errorf("ModelInputDir = %q, want /trimmed/input", cfg.ModelInputDir)
	}
	if cfg.ModelCheckpointDir != "/trimmed/checkpoint" {
		t.Errorf("ModelCheckpointDir = %q, want /trimmed/checkpoint", cfg.ModelCheckpointDir)
	}
	if cfg.ModelOutputDir != "/trimmed/output/result" {
		t.Errorf("ModelOutputDir = %q, want /trimmed/output/result", cfg.ModelOutputDir)
	}
	if cfg.ModelLogDir != "/trimmed/output/log" {
		t.Errorf("ModelLogDir = %q, want /trimmed/output/log", cfg.ModelLogDir)
	}
	if cfg.ModelProgressDir != "/trimmed/output/progress" {
		t.Errorf("ModelProgressDir = %q, want /trimmed/output/progress", cfg.ModelProgressDir)
	}
}

func TestLoadStartupConfigModelBackwardCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"modelInputDir": "/legacy/input",
		"modelOutputDir": "/legacy/output/result",
		"modelLogDir": "/legacy/output/log",
		"modelProgressDir": "/legacy/output/progress",
		"modelCheckpointDir": "/legacy/checkpoint"
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.ModelInputDir != "/legacy/input" {
		t.Errorf("ModelInputDir = %q, want /legacy/input", cfg.ModelInputDir)
	}
	if cfg.ModelCheckpointDir != "/legacy/checkpoint" {
		t.Errorf("ModelCheckpointDir = %q, want /legacy/checkpoint", cfg.ModelCheckpointDir)
	}
	if cfg.ModelOutputDir != "/legacy/output/result" {
		t.Errorf("ModelOutputDir = %q, want /legacy/output/result", cfg.ModelOutputDir)
	}
	if cfg.ModelLogDir != "/legacy/output/log" {
		t.Errorf("ModelLogDir = %q, want /legacy/output/log", cfg.ModelLogDir)
	}
	if cfg.ModelProgressDir != "/legacy/output/progress" {
		t.Errorf("ModelProgressDir = %q, want /legacy/output/progress", cfg.ModelProgressDir)
	}
}

func TestLoadStartupConfigModelOverridesLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"modelInputDir": "/legacy/input",
		"modelOutputDir": "/legacy/output/result",
		"modelLogDir": "/legacy/output/log",
		"modelProgressDir": "/legacy/output/progress",
		"modelCheckpointDir": "/legacy/checkpoint",
		"model": {
			"input": "/modern/input",
			"checkpoint": "/modern/checkpoint",
			"output": {
				"result": "/modern/output/result",
				"log": "/modern/output/log",
				"progress": "/modern/output/progress"
			}
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.ModelInputDir != "/modern/input" {
		t.Errorf("ModelInputDir = %q, want /modern/input", cfg.ModelInputDir)
	}
	if cfg.ModelCheckpointDir != "/modern/checkpoint" {
		t.Errorf("ModelCheckpointDir = %q, want /modern/checkpoint", cfg.ModelCheckpointDir)
	}
	if cfg.ModelOutputDir != "/modern/output/result" {
		t.Errorf("ModelOutputDir = %q, want /modern/output/result", cfg.ModelOutputDir)
	}
	if cfg.ModelLogDir != "/modern/output/log" {
		t.Errorf("ModelLogDir = %q, want /modern/output/log", cfg.ModelLogDir)
	}
	if cfg.ModelProgressDir != "/modern/output/progress" {
		t.Errorf("ModelProgressDir = %q, want /modern/output/progress", cfg.ModelProgressDir)
	}
}

func TestStartupConfig_InferenceOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"llm": {
			"enabled": true,
			"transport": "teetls",
			"endpoint": "https://127.0.0.1:8443",
			"attestationMode": "permissive",
			"hrkCertPath": "/custom/hrk.cert",
			"hskCekCertPath": "/custom/hsk_cek.cert",
			"expectedMeasurements": ["deadbeef01234567"],
			"requireMutualAttest": true,
			"insecureSkipVerify": true,
			"model": "qwen2.5-coder:3b",
			"policy": "gate",
			"failClosed": true,
			"authToken": "secret-token",
			"requestTimeoutMs": 15000,
			"allowedHosts": ["127.0.0.1", "inference-host"],
			"circuitBreakerThreshold": 5,
			"cooldownSec": 45
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.LLMTransport != "teetls" {
		t.Errorf("got transport %q, want 'teetls'", cfg.LLMTransport)
	}
	if cfg.LLMEndpoint != "https://127.0.0.1:8443" {
		t.Errorf("got endpoint %q, want 'https://127.0.0.1:8443'", cfg.LLMEndpoint)
	}
	if cfg.LLMAttestationMode != "permissive" {
		t.Errorf("got attestationMode %q, want 'permissive'", cfg.LLMAttestationMode)
	}
	if cfg.LLMHRKCertPath != "/custom/hrk.cert" {
		t.Errorf("got hrkCertPath %q, want '/custom/hrk.cert'", cfg.LLMHRKCertPath)
	}
	if cfg.LLMHSKCekCertPath != "/custom/hsk_cek.cert" {
		t.Errorf("got hskCekCertPath %q, want '/custom/hsk_cek.cert'", cfg.LLMHSKCekCertPath)
	}
	if len(cfg.LLMExpectedMeasurements) != 1 || cfg.LLMExpectedMeasurements[0] != "deadbeef01234567" {
		t.Errorf("got expectedMeasurements %v, want ['deadbeef01234567']", cfg.LLMExpectedMeasurements)
	}
	if !cfg.LLMRequireMutualAttest {
		t.Errorf("got requireMutualAttest false, want true")
	}
	if !cfg.LLMInsecureSkipVerify {
		t.Errorf("got insecureSkipVerify false, want true")
	}
	if cfg.LLMAuthToken != "secret-token" {
		t.Errorf("got token %q", cfg.LLMAuthToken)
	}
	if cfg.LLMTimeoutMs != 15000 {
		t.Errorf("got timeout %d, want 15000", cfg.LLMTimeoutMs)
	}
	if len(cfg.LLMAllowedHosts) != 2 || cfg.LLMAllowedHosts[0] != "127.0.0.1" || cfg.LLMAllowedHosts[1] != "inference-host" {
		t.Errorf("got allowedHosts %v", cfg.LLMAllowedHosts)
	}
	if cfg.LLMCircuitBreakerThreshold != 5 {
		t.Errorf("got threshold %d, want 5", cfg.LLMCircuitBreakerThreshold)
	}
	if cfg.LLMCooldownSec != 45 {
		t.Errorf("got cooldown %d, want 45", cfg.LLMCooldownSec)
	}
}

func TestStartupConfig_InferenceDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.LLMTransport != "teetls" {
		t.Errorf("got default transport %q, want 'teetls'", cfg.LLMTransport)
	}
	if cfg.LLMEndpoint != "https://127.0.0.1:8443" {
		t.Errorf("got default endpoint %q, want 'https://127.0.0.1:8443'", cfg.LLMEndpoint)
	}
	if cfg.LLMAttestationMode != "strict" {
		t.Errorf("got default attestationMode %q, want 'strict'", cfg.LLMAttestationMode)
	}
	if cfg.LLMHRKCertPath == "" || cfg.LLMHSKCekCertPath == "" {
		t.Errorf("got empty default cert paths: hrk=%q, hsk=%q", cfg.LLMHRKCertPath, cfg.LLMHSKCekCertPath)
	}
	if cfg.LLMExpectedMeasurements != nil {
		t.Errorf("got default expectedMeasurements %v, want nil", cfg.LLMExpectedMeasurements)
	}
	if cfg.LLMRequireMutualAttest {
		t.Errorf("got default requireMutualAttest true, want false")
	}
	if cfg.LLMInsecureSkipVerify {
		t.Errorf("got default insecureSkipVerify true, want false")
	}
	if cfg.LLMAuthToken != "" {
		t.Errorf("got default token %q, want empty", cfg.LLMAuthToken)
	}
	if cfg.LLMTimeoutMs != 30000 {
		t.Errorf("got default timeout %d, want 30000", cfg.LLMTimeoutMs)
	}
	if cfg.LLMCircuitBreakerThreshold != 3 {
		t.Errorf("got default threshold %d, want 3", cfg.LLMCircuitBreakerThreshold)
	}
	if cfg.LLMCooldownSec != 30 {
		t.Errorf("got default cooldown %d, want 30", cfg.LLMCooldownSec)
	}
}

// TestLoadStartupConfigRejectsUnknownLLMPolicy guards the audit gate against a
// silently ineffective policy: an unrecognized value used to be stored verbatim
// and then matched neither "gate" nor "assist" in the audit arbitration,
// falling back to assist behaviour (HIGH-only blocking) without any signal.
func TestLoadStartupConfigRejectsUnknownLLMPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"llm": {
			"policy": "enforce"
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err == nil {
		t.Fatalf("LoadStartupConfig() error = nil, want rejection of unknown llm policy; got policy %q", cfg.LLMPolicy)
	}
	if !strings.Contains(err.Error(), "enforce") {
		t.Fatalf("error %q should name the rejected value", err)
	}
}

func TestLoadStartupConfigNormalizesLLMPolicy(t *testing.T) {
	for _, policy := range []string{"assist", "gate", "GATE", " gate ", ""} {
		t.Run("policy="+policy, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), DefaultFileName)
			writeTestConfig(t, path, fmt.Sprintf(`{"llm":{"policy":%q}}`, policy))

			cfg, err := LoadStartupConfig(path)
			if err != nil {
				t.Fatalf("LoadStartupConfig() error = %v, want nil for supported value", err)
			}

			want := strings.ToLower(strings.TrimSpace(policy))
			if want == "" {
				want = "assist"
			}
			if cfg.LLMPolicy != want {
				t.Fatalf("LLMPolicy = %q, want %q", cfg.LLMPolicy, want)
			}
		})
	}
}

// TestLoadStartupConfigRejectsUnknownCodeScanEngine is the same guard as the
// policy one above, for the Tier 1 engine. An unrecognized engine name must not
// be stored verbatim: the scan would then run the regex baseline while the
// deployment believes it enabled Semgrep, and the audit report's engine field
// would honestly say "regex" — a field nobody reads.
func TestLoadStartupConfigRejectsUnknownCodeScanEngine(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"security": {
			"codeScanEngine": "semgrep-cli"
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err == nil {
		t.Fatalf("LoadStartupConfig() error = nil, want rejection of unknown engine; got engine %q", cfg.CodeScanEngine)
	}
	if !strings.Contains(err.Error(), "semgrep-cli") {
		t.Fatalf("error %q should name the rejected value", err)
	}
	// The error has to say what is accepted, or the operator has to read the
	// source to fix the config.
	for _, want := range []string{"regex", "semgrep"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should list the accepted engine %q", err, want)
		}
	}
}

func TestLoadStartupConfigNormalizesCodeScanEngine(t *testing.T) {
	for _, engine := range []string{"regex", "semgrep", "SEMGREP", " semgrep ", ""} {
		t.Run("engine="+engine, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), DefaultFileName)
			writeTestConfig(t, path, fmt.Sprintf(`{"security":{"codeScanEngine":%q}}`, engine))

			cfg, err := LoadStartupConfig(path)
			if err != nil {
				t.Fatalf("LoadStartupConfig() error = %v, want nil for supported value", err)
			}

			want := strings.ToLower(strings.TrimSpace(engine))
			if want == "" {
				// Default is semgrep following formal production integration.
				want = "semgrep"
			}
			if cfg.CodeScanEngine != want {
				t.Fatalf("CodeScanEngine = %q, want %q", cfg.CodeScanEngine, want)
			}
		})
	}
}

// TestLoadStartupConfigReadsSemgrepRulesPath pins that the rules location is
// deployment-settable. The adapter's built-in default is relative to the
// repository root, which is not where a container runs, so a deployment that
// selects Semgrep has to be able to say where the rules are.
func TestLoadStartupConfigReadsSemgrepRulesPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"security": {
			"codeScanEngine": "semgrep",
			"semgrepRulesPath": "/opt/taa/semgrep/rules.yaml"
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.SemgrepRulesPath != "/opt/taa/semgrep/rules.yaml" {
		t.Fatalf("SemgrepRulesPath = %q, want the configured path", cfg.SemgrepRulesPath)
	}
}

// TestLoadStartupConfigLeavesSemgrepRulesPathUnset guards the default against
// being written down twice. The path default lives in the codeaudit package
// next to the engine that uses it; repeating the literal here would let the two
// drift, and the config layer has no way to notice.
func TestLoadStartupConfigLeavesSemgrepRulesPathUnset(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"security":{"codeScanEngine":"regex"}}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.SemgrepRulesPath != "" {
		t.Fatalf("SemgrepRulesPath = %q, want empty so the engine's own default applies", cfg.SemgrepRulesPath)
	}
}

// TestLoadStartupConfigLeavesTheSemgrepTimeoutAtZeroForTheEngineToResolve
// pins where the default lives. Zero is not "no timeout": it is "not
// configured", and the adapter turns it into its own default. Writing the
// seconds into the config layer as well would put the same number in two
// places, and the one that is actually enforced is the adapter's.
func TestLoadStartupConfigLeavesTheSemgrepTimeoutAtZeroForTheEngineToResolve(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"security":{"codeScanEngine":"semgrep"}}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.SemgrepTimeout != 0 {
		t.Fatalf("SemgrepTimeout = %v, want 0 so the engine's own default applies", cfg.SemgrepTimeout)
	}
}

func TestLoadStartupConfigReadsTheSemgrepTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"security": {
			"codeScanEngine": "semgrep",
			"semgrepTimeoutSeconds": 45
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.SemgrepTimeout != 45*time.Second {
		t.Fatalf("SemgrepTimeout = %v, want 45s", cfg.SemgrepTimeout)
	}
}

// TestLoadStartupConfigRejectsANonPositiveSemgrepTimeout pins that a deadline
// the daemon cannot honour fails where it is written.
//
// A negative deadline is not a shorter scan: it is a scan that is already
// expired, so every import would fail closed with the model code deleted, and
// the configuration that caused it would be the one line nobody re-reads. The
// failure has to land on the operator's config, not on every import.
func TestLoadStartupConfigRejectsANonPositiveSemgrepTimeout(t *testing.T) {
	for _, seconds := range []string{"-1", "-300"} {
		t.Run("seconds="+seconds, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), DefaultFileName)
			writeTestConfig(t, path, fmt.Sprintf(`{
				"security": {
					"codeScanEngine": "semgrep",
					"semgrepTimeoutSeconds": %s
				}
			}`, seconds))

			cfg, err := LoadStartupConfig(path)
			if err == nil {
				t.Fatalf("LoadStartupConfig() error = nil, want rejection; got timeout %v", cfg.SemgrepTimeout)
			}
			if !strings.Contains(err.Error(), "semgrepTimeoutSeconds") {
				t.Fatalf("error %q should name the offending key", err)
			}
		})
	}
}

func writeTestConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
