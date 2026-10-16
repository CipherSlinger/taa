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
		"codeAudit": {
			"llm": {
				"enabled": false,
				"endpoint": "http://llm.example:11434",
				"model": "qwen-test",
				"policy": "gate",
				"failClosed": false
			}
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
	if !cfg.EnableCodeAudit {
		t.Fatalf("EnableCodeAudit = false, want default true")
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
	if cfg.ModelLogDir != "/opt/taa/output/log" {
		t.Fatalf("ModelLogDir = %q, want default", cfg.ModelLogDir)
	}
	if cfg.ModelProgressDir != "/opt/taa/output/progress/progress.json" {
		t.Fatalf("ModelProgressDir = %q, want default", cfg.ModelProgressDir)
	}
	if cfg.KeysDir != "/root/taa/keys" {
		t.Fatalf("KeysDir = %q, want default", cfg.KeysDir)
	}
	if !cfg.LLM.Enabled {
		t.Fatalf("LLM.Enabled = false, want default true")
	}
	if cfg.LLM.Endpoint != "https://127.0.0.1:8443" {
		t.Fatalf("LLM.Endpoint = %q, want default", cfg.LLM.Endpoint)
	}
	if cfg.LLM.Model != "qwen2.5-coder:0.5b" {
		t.Fatalf("LLM.Model = %q, want default", cfg.LLM.Model)
	}
	if cfg.LLM.Policy != "assist" {
		t.Fatalf("LLM.Policy = %q, want default", cfg.LLM.Policy)
	}
	if !cfg.LLM.FailClosed {
		t.Fatalf("LLM.FailClosed = false, want default true")
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
			"codeAudit": {
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
			"codeAudit": {
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
	if cfg.KeysDir != "/root/taa/keys" {
		t.Fatalf("KeysDir = %q, want default /root/taa/keys", cfg.KeysDir)
	}
}

func TestLoadStartupConfigReadsLLMDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"codeAudit": {
			"llm": {
				"dir": "/opt/taa/ollama"
			}
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.LLM.Dir != "/opt/taa/ollama" {
		t.Fatalf("LLM.Dir = %q, want file value", cfg.LLM.Dir)
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

	if !cfg.EnableCodeAudit || !cfg.EnableResultCheck || !cfg.LLM.Enabled || !cfg.LLM.FailClosed {
		t.Fatalf("boolean runtime config unexpectedly read from environment: %+v", cfg)
	}
	if cfg.ModelDir != "/opt/taa/models" || cfg.DataDir != "/opt/taa/data" || cfg.ResultDir != "/opt/taa/results" || cfg.KeysDir != "/root/taa/keys" {
		t.Fatalf("directory runtime config unexpectedly read from environment: %+v", cfg)
	}
	if cfg.LLM.Endpoint != "https://127.0.0.1:8443" || cfg.LLM.Model != "qwen2.5-coder:0.5b" || cfg.LLM.Policy != "assist" || cfg.LLM.Dir != "" {
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
		relPath              string
		wantAddr             string
		wantModelDir         string
		wantDataDir          string
		wantResultDir        string
		wantKeysDir          string
		wantHRK              string
		wantHSKCek           string
		wantMaxResultBytes   int64
		wantModelInputDir    string
		wantModelOutputDir   string
		wantModelLogDir      string
		wantModelProgressDir string
		wantCodeAudit        bool
		wantResultCheck      bool
		wantPlatformIP       string
		wantDockerID         string
		// wantLLMTimeoutMs pins the per-request inference budget a template sets.
		// Zero means "not asserted". The docker template needs a budget that
		// covers a cold model load on CPU-only inference; see
		// .claude/specs/2026-10-08-llm-timeout-layering-design.md.
		wantLLMTimeoutMs int64
		// wantSemgrepRulesPath and wantLLMModel are asserted because both differ
		// from the code defaults (empty, and qwen2.5-coder:0.5b). They are what
		// makes this test evidence that the codeAudit block is read as a block:
		// a config whose inner sections went unread would still satisfy every
		// other assertion here, since those pin values the defaults already have.
		wantSemgrepRulesPath string
		wantLLMModel         string
	}{
		{
			relPath:              "../../configs/taa-production.json",
			wantAddr:             ":6001",
			wantModelDir:         "/root/taa/models",
			wantDataDir:          "/root/taa/data",
			wantResultDir:        "/root/taa/results",
			wantKeysDir:          "/root/taa/keys",
			wantHRK:              "/root/taa/certs/hrk.cert",
			wantHSKCek:           "/root/taa/certs/hsk_cek.cert",
			wantMaxResultBytes:   3221225472,
			wantModelInputDir:    "/opt/taa/input",
			wantModelOutputDir:   "/opt/taa/output/result",
			wantModelLogDir:      "/opt/taa/output/log",
			wantModelProgressDir: "/opt/taa/output/progress/progress.json",
			wantCodeAudit:        true,
			wantResultCheck:      true,
			wantPlatformIP:       "",
			wantDockerID:         "",
			wantSemgrepRulesPath: "/opt/taa/semgrep/rules",
			wantLLMModel:         "qwen2.5-coder:7b",
		},
		{
			relPath:              "../../configs/taa-docker.json",
			wantAddr:             ":6001",
			wantModelDir:         "/root/taa/models",
			wantDataDir:          "/root/taa/data",
			wantResultDir:        "/root/taa/results",
			wantKeysDir:          "/root/taa/keys",
			wantHRK:              "/root/taa/certs/hrk.cert",
			wantHSKCek:           "/root/taa/certs/hsk_cek.cert",
			wantMaxResultBytes:   3221225472,
			wantModelInputDir:    "/opt/taa/input",
			wantModelOutputDir:   "/opt/taa/output/result",
			wantModelLogDir:      "/opt/taa/output/log",
			wantModelProgressDir: "/opt/taa/output/progress/progress.json",
			wantCodeAudit:        true,
			wantResultCheck:      true,
			wantPlatformIP:       "127.0.0.1:18080",
			wantDockerID:         "taa-env-slim-v2",
			wantLLMTimeoutMs:     120000,
			wantSemgrepRulesPath: "/opt/taa/semgrep/rules",
			wantLLMModel:         "qwen2.5-coder:7b",
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
			if cfg.EnableCodeAudit != tc.wantCodeAudit {
				t.Errorf("EnableCodeAudit = %v, want %v", cfg.EnableCodeAudit, tc.wantCodeAudit)
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
			if tc.wantLLMTimeoutMs != 0 && cfg.LLM.TimeoutMs != tc.wantLLMTimeoutMs {
				t.Errorf("LLM.TimeoutMs = %d, want %d", cfg.LLM.TimeoutMs, tc.wantLLMTimeoutMs)
			}
			if cfg.SemgrepRulesPath != tc.wantSemgrepRulesPath {
				t.Errorf("SemgrepRulesPath = %q, want %q", cfg.SemgrepRulesPath, tc.wantSemgrepRulesPath)
			}
			if cfg.LLM.Model != tc.wantLLMModel {
				t.Errorf("LLM.Model = %q, want %q", cfg.LLM.Model, tc.wantLLMModel)
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
		"codeAudit": {
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
	if cfg.EnableCodeAudit {
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
		"codeAudit": {
			"codeScan": true,
			"resultCheck": false
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if !cfg.EnableCodeAudit {
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
		"modelProgressDir": "/legacy/output/progress"
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.ModelInputDir != "/legacy/input" {
		t.Errorf("ModelInputDir = %q, want /legacy/input", cfg.ModelInputDir)
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
		"model": {
			"input": "/modern/input",
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
		"codeAudit": {
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
				"temperature": 0.3,
				"failClosed": true,
				"authToken": "secret-token",
				"requestTimeoutMs": 15000,
				"allowedHosts": ["127.0.0.1", "inference-host"],
				"circuitBreakerThreshold": 5,
				"cooldownSec": 45
			}
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.LLM.Transport != "teetls" {
		t.Errorf("got transport %q, want 'teetls'", cfg.LLM.Transport)
	}
	if cfg.LLM.Endpoint != "https://127.0.0.1:8443" {
		t.Errorf("got endpoint %q, want 'https://127.0.0.1:8443'", cfg.LLM.Endpoint)
	}
	if cfg.LLM.AttestationMode != "permissive" {
		t.Errorf("got attestationMode %q, want 'permissive'", cfg.LLM.AttestationMode)
	}
	if cfg.LLM.HRKCertPath != "/custom/hrk.cert" {
		t.Errorf("got hrkCertPath %q, want '/custom/hrk.cert'", cfg.LLM.HRKCertPath)
	}
	if cfg.LLM.HSKCekCertPath != "/custom/hsk_cek.cert" {
		t.Errorf("got hskCekCertPath %q, want '/custom/hsk_cek.cert'", cfg.LLM.HSKCekCertPath)
	}
	if len(cfg.LLM.ExpectedMeasurements) != 1 || cfg.LLM.ExpectedMeasurements[0] != "deadbeef01234567" {
		t.Errorf("got expectedMeasurements %v, want ['deadbeef01234567']", cfg.LLM.ExpectedMeasurements)
	}
	if !cfg.LLM.RequireMutualAttest {
		t.Errorf("got requireMutualAttest false, want true")
	}
	if !cfg.LLM.InsecureSkipVerify {
		t.Errorf("got insecureSkipVerify false, want true")
	}
	if cfg.LLM.AuthToken != "secret-token" {
		t.Errorf("got token %q", cfg.LLM.AuthToken)
	}
	if cfg.LLM.TimeoutMs != 15000 {
		t.Errorf("got timeout %d, want 15000", cfg.LLM.TimeoutMs)
	}
	if len(cfg.LLM.AllowedHosts) != 2 || cfg.LLM.AllowedHosts[0] != "127.0.0.1" || cfg.LLM.AllowedHosts[1] != "inference-host" {
		t.Errorf("got allowedHosts %v", cfg.LLM.AllowedHosts)
	}
	if cfg.LLM.CircuitBreakerThreshold != 5 {
		t.Errorf("got threshold %d, want 5", cfg.LLM.CircuitBreakerThreshold)
	}
	if cfg.LLM.CooldownSec != 45 {
		t.Errorf("got cooldown %d, want 45", cfg.LLM.CooldownSec)
	}
	if cfg.LLM.Temperature == nil {
		t.Fatalf("got nil temperature, want 0.3")
	}
	if *cfg.LLM.Temperature != 0.3 {
		t.Errorf("got temperature %v, want 0.3", *cfg.LLM.Temperature)
	}
}

func TestStartupConfig_InferenceDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.LLM.Transport != "teetls" {
		t.Errorf("got default transport %q, want 'teetls'", cfg.LLM.Transport)
	}
	if cfg.LLM.Endpoint != "https://127.0.0.1:8443" {
		t.Errorf("got default endpoint %q, want 'https://127.0.0.1:8443'", cfg.LLM.Endpoint)
	}
	if cfg.LLM.AttestationMode != "strict" {
		t.Errorf("got default attestationMode %q, want 'strict'", cfg.LLM.AttestationMode)
	}
	if cfg.LLM.HRKCertPath == "" || cfg.LLM.HSKCekCertPath == "" {
		t.Errorf("got empty default cert paths: hrk=%q, hsk=%q", cfg.LLM.HRKCertPath, cfg.LLM.HSKCekCertPath)
	}
	if cfg.LLM.ExpectedMeasurements != nil {
		t.Errorf("got default expectedMeasurements %v, want nil", cfg.LLM.ExpectedMeasurements)
	}
	if cfg.LLM.RequireMutualAttest {
		t.Errorf("got default requireMutualAttest true, want false")
	}
	if cfg.LLM.InsecureSkipVerify {
		t.Errorf("got default insecureSkipVerify true, want false")
	}
	if cfg.LLM.AuthToken != "" {
		t.Errorf("got default token %q, want empty", cfg.LLM.AuthToken)
	}
	if cfg.LLM.TimeoutMs != 30000 {
		t.Errorf("got default timeout %d, want 30000", cfg.LLM.TimeoutMs)
	}
	if cfg.LLM.CircuitBreakerThreshold != 3 {
		t.Errorf("got default threshold %d, want 3", cfg.LLM.CircuitBreakerThreshold)
	}
	if cfg.LLM.CooldownSec != 30 {
		t.Errorf("got default cooldown %d, want 30", cfg.LLM.CooldownSec)
	}
	if cfg.LLM.Temperature != nil {
		t.Errorf("got default temperature %v, want nil (unset, leaving the choice to the inference service)", *cfg.LLM.Temperature)
	}
}

// TestLoadStartupConfigExplicitZeroTemperature pins the nil-vs-zero distinction
// for the sampling temperature.
//
// Every other numeric field in the llm section is guarded with "> 0", because
// zero there means "unset, use the default". For temperature that reading is
// wrong: zero is the value the audit actually wants (deterministic decoding),
// so it has to be expressible. A "> 0" guard would silently turn an explicit 0
// into "unspecified", which happens to reach the same result today only because
// the service default is also 0 - the configuration would be lying about what it
// asked for, and would start meaning something different the day that default
// changes.
func TestLoadStartupConfigExplicitZeroTemperature(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"codeAudit":{"llm":{"temperature":0}}}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.LLM.Temperature == nil {
		t.Fatalf("got nil temperature, want an explicit 0")
	}
	if *cfg.LLM.Temperature != 0 {
		t.Errorf("got temperature %v, want 0", *cfg.LLM.Temperature)
	}
}

// TestLoadStartupConfigRejectsUnknownLLMPolicy guards the audit gate against a
// silently ineffective policy: an unrecognized value used to be stored verbatim
// and then matched neither "gate" nor "assist" in the audit arbitration,
// falling back to assist behaviour (HIGH-only blocking) without any signal.
func TestLoadStartupConfigRejectsUnknownLLMPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"codeAudit": {
			"llm": {
				"policy": "enforce"
			}
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err == nil {
		t.Fatalf("LoadStartupConfig() error = nil, want rejection of unknown llm policy; got policy %q", cfg.LLM.Policy)
	}
	if !strings.Contains(err.Error(), "enforce") {
		t.Fatalf("error %q should name the rejected value", err)
	}
}

func TestLoadStartupConfigNormalizesLLMPolicy(t *testing.T) {
	for _, policy := range []string{"assist", "gate", "GATE", " gate ", ""} {
		t.Run("policy="+policy, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), DefaultFileName)
			writeTestConfig(t, path, fmt.Sprintf(`{"codeAudit":{"llm":{"policy":%q}}}`, policy))

			cfg, err := LoadStartupConfig(path)
			if err != nil {
				t.Fatalf("LoadStartupConfig() error = %v, want nil for supported value", err)
			}

			want := strings.ToLower(strings.TrimSpace(policy))
			if want == "" {
				want = "assist"
			}
			if cfg.LLM.Policy != want {
				t.Fatalf("LLM.Policy = %q, want %q", cfg.LLM.Policy, want)
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
		"codeAudit": {
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
			writeTestConfig(t, path, fmt.Sprintf(`{"codeAudit":{"codeScanEngine":%q}}`, engine))

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
		"codeAudit": {
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
	writeTestConfig(t, path, `{"codeAudit":{"codeScanEngine":"regex"}}`)

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
	writeTestConfig(t, path, `{"codeAudit":{"codeScanEngine":"semgrep"}}`)

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
		"codeAudit": {
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
// expired, so every import would fail closed, and
// the configuration that caused it would be the one line nobody re-reads. The
// failure has to land on the operator's config, not on every import.
func TestLoadStartupConfigRejectsANonPositiveSemgrepTimeout(t *testing.T) {
	for _, seconds := range []string{"-1", "-300"} {
		t.Run("seconds="+seconds, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), DefaultFileName)
			writeTestConfig(t, path, fmt.Sprintf(`{
				"codeAudit": {
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

func TestValidateLLMTemperature(t *testing.T) {
	temp := func(v float32) *float32 { return &v }

	cases := []struct {
		name    string
		temp    *float32
		wantErr bool
	}{
		{"unset", nil, false},
		{"zero is greedy decoding, not unset", temp(0), false},
		{"low", temp(0.1), false},
		{"upper bound inclusive", temp(2), false},
		{"above upper bound", temp(2.1), true},
		{"negative", temp(-0.1), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := "nil"
			if tc.temp != nil {
				got = fmt.Sprintf("%v", *tc.temp)
			}
			err := validateLLMTemperature(StartupConfig{LLM: LLMConfig{Temperature: tc.temp}})
			if tc.wantErr && err == nil {
				t.Fatalf("validateLLMTemperature(%s) = nil, want error", got)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateLLMTemperature(%s) = %v, want nil", got, err)
			}
		})
	}
}

// TestLoadStartupConfigRejectsOutOfRangeLLMTemperature checks the validator is
// actually on the load path, not merely correct in isolation.
func TestLoadStartupConfigRejectsOutOfRangeLLMTemperature(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"codeAudit":{"llm":{"temperature":3}}}`)

	if _, err := LoadStartupConfig(path); err == nil {
		t.Fatalf("LoadStartupConfig() = nil error, want rejection of temperature 3")
	}
}

// TestBinaryAuditConfigDefaultsAndOverrides pins the switch that makes this
// feature reversible: the channel is on unless a deployment says otherwise, and
// every limit can be moved without touching code.
func TestBinaryAuditConfigDefaultsAndOverrides(t *testing.T) {
	t.Run("absent means enabled with the adapter's defaults", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path, `{"codeAudit":{"codeScanEngine":"regex"}}`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		if !cfg.BinaryAuditEnabled {
			t.Error("BinaryAuditEnabled = false when the section is absent; the default must be on")
		}
		if cfg.BinaryAuditMaxArchiveMembers != 0 {
			t.Errorf("BinaryAuditMaxArchiveMembers = %d, want 0 (meaning \"use the codeaudit default\")",
				cfg.BinaryAuditMaxArchiveMembers)
		}
	})

	t.Run("an explicit false disables it", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path, `{"codeAudit":{"binaryAudit":{"enabled":false}}}`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		if cfg.BinaryAuditEnabled {
			t.Error("BinaryAuditEnabled = true after an explicit false")
		}
	})

	t.Run("limits are read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path,
			`{"codeAudit":{"binaryAudit":{"maxArchiveMembers":17,"highEntropyThreshold":7.25}}}`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		if cfg.BinaryAuditMaxArchiveMembers != 17 {
			t.Errorf("BinaryAuditMaxArchiveMembers = %d, want 17", cfg.BinaryAuditMaxArchiveMembers)
		}
		if cfg.BinaryAuditHighEntropyThreshold != 7.25 {
			t.Errorf("BinaryAuditHighEntropyThreshold = %v, want 7.25", cfg.BinaryAuditHighEntropyThreshold)
		}
	})

	t.Run("a limit that cannot mean what it says is rejected rather than read as a default", func(t *testing.T) {
		// The guarantee is the load path's: LoadStartupConfig runs
		// validateStartupConfig before anything reads the value, so a negative
		// never reaches the normalizer. codeaudit's own normalizer tests "<= 0",
		// so a negative arriving by any other route - a hand-built StartupConfig -
		// would be replaced by the default instead of rejected.
		//
		// Every guard is driven rather than one of them: they are separate
		// branches, and a test that named only the first stays green with the
		// other five deleted.
		for _, tc := range []struct {
			name  string
			audit string
		}{
			{"a negative member count", `"maxArchiveMembers":-1`},
			{"a negative finding budget", `"maxFindings":-1`},
			{"a negative full-scan budget", `"maxFullScanBytes":-1`},
			{"a negative stream budget", `"maxStreamBytes":-1`},
			{"an entropy threshold below zero", `"highEntropyThreshold":-0.5`},
			{"an entropy threshold above eight", `"highEntropyThreshold":8.5`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), DefaultFileName)
				writeTestConfig(t, path, `{"codeAudit":{"binaryAudit":{`+tc.audit+`}}}`)
				if _, err := LoadStartupConfig(path); err == nil {
					t.Errorf("%s was accepted; it would be normalised to the default and the operator would never know", tc.audit)
				}
			})
		}
	})

	t.Run("the full-scan threshold is carried through", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path, `{"codeAudit":{"binaryAudit":{"maxFullScanBytes":134217728}}}`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		if cfg.BinaryAuditMaxFullScanBytes != 134217728 {
			t.Errorf("BinaryAuditMaxFullScanBytes = %d, want 134217728", cfg.BinaryAuditMaxFullScanBytes)
		}
	})
}

// TestLoadStartupConfigRejectsRemovedKeys pins the failure mode that replaced a
// silent one.
//
// encoding/json drops a key it does not recognise, so before this rejection a
// config still written against the old layout loaded without complaint - and
// every setting under the old keys was discarded, leaving the audit on defaults
// (the regex baseline, the local inference endpoint) with nothing in the log to
// say so. The rejection has to name the key to edit, and it has to name both
// when both are present, so an operator fixes the file in one pass.
func TestLoadStartupConfigRejectsRemovedKeys(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "the old security block",
			content: `{"security":{"codeScanEngine":"semgrep"}}`,
			want:    []string{`"security"`, `"codeAudit"`},
		},
		{
			name:    "a top-level llm block",
			content: `{"llm":{"endpoint":"https://10.0.0.1:8443"}}`,
			want:    []string{`"llm"`, `"codeAudit.llm"`},
		},
		{
			name:    "both at once, reported together",
			content: `{"security":{"codeScan":true},"llm":{"enabled":true}}`,
			want:    []string{`"security"`, `"codeAudit"`, `"llm"`, `"codeAudit.llm"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), DefaultFileName)
			writeTestConfig(t, path, tc.content)

			_, err := LoadStartupConfig(path)
			if err == nil {
				t.Fatal("LoadStartupConfig() error = nil, want rejection of the removed key")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %s", err, want)
				}
			}
		})
	}
}

// TestLoadStartupConfigAcceptsExplicitNullRemovedKeys pins the boundary of the
// rejection above: an explicit null carries no settings, so a config that writes
// one loses nothing by loading and must not be failed for it.
func TestLoadStartupConfigAcceptsExplicitNullRemovedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"security":null,"llm":null}`)

	if _, err := LoadStartupConfig(path); err != nil {
		t.Fatalf("LoadStartupConfig() error = %v, want nil for explicit nulls", err)
	}
}
