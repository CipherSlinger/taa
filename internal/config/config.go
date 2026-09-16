package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const DefaultFileName = "taa-config.json"

type StartupConfig struct {
	Addr                      string
	PlatformIP                string
	DockerID                  string
	Contract                  string
	EnableSecurityScan        bool
	ModelDir                  string
	EnableResultCheck         bool
	DataDir                   string
	ResultDir                 string
	ModelInputDir             string
	ModelOutputDir            string
	ModelLogDir               string
	ModelProgressDir          string
	KeysDir                   string
	AttestationHRKCertPath    string
	AttestationHSKCekCertPath string
	EnableLLM                 bool
	LLMEndpoint               string
	LLMModel                  string
	LLMPolicy                 string
	LLMFailClosed             bool
	LLMDir                    string
}

type startupConfigFile struct {
	Addr               string                       `json:"addr"`
	PlatformIP         string                       `json:"platformIP"`
	DockerID           string                       `json:"dockerID"`
	Contract           string                       `json:"contract"`
	EnableSecurityScan *bool                        `json:"securityScan"`
	ModelDir           string                       `json:"modelDir"`
	EnableResultCheck  *bool                        `json:"resultCheck"`
	DataDir            string                       `json:"dataDir"`
	ResultDir          string                       `json:"resultDir"`
	ModelInputDir      string                       `json:"modelInputDir"`
	ModelOutputDir     string                       `json:"modelOutputDir"`
	ModelLogDir        string                       `json:"modelLogDir"`
	ModelProgressDir   string                       `json:"modelProgressDir"`
	KeysDir            string                       `json:"keysDir"`
	Attestation        startupAttestationConfigFile `json:"attestation"`
	LLM                startupLLMConfigFile         `json:"llm"`
}

type startupAttestationConfigFile struct {
	HRKCertPath    string `json:"hrkCertPath"`
	HSKCekCertPath string `json:"hskCekCertPath"`
}

type startupLLMConfigFile struct {
	Enabled    *bool  `json:"enabled"`
	Endpoint   string `json:"endpoint"`
	Model      string `json:"model"`
	Policy     string `json:"policy"`
	FailClosed *bool  `json:"failClosed"`
	Dir        string `json:"dir"`
}

func LoadStartupConfig(path string) (StartupConfig, error) {
	cfg := defaultStartupConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return StartupConfig{}, fmt.Errorf("read startup config %s: %w", path, err)
	}

	var fileCfg startupConfigFile
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		return StartupConfig{}, fmt.Errorf("parse startup config %s: %w", path, err)
	}

	applyStartupConfigFile(&cfg, fileCfg)
	return cfg, nil
}

func defaultStartupConfig() StartupConfig {
	hrkDefault := "/root/taa/certs/hrk.cert"
	hskDefault := "/root/taa/certs/hsk_cek.cert"
	if _, err := os.Stat(hrkDefault); err != nil {
		if _, localErr := os.Stat("deploy/certs/hrk.cert"); localErr == nil {
			hrkDefault = "deploy/certs/hrk.cert"
			hskDefault = "deploy/certs/hsk_cek.cert"
		}
	}

	return StartupConfig{
		Addr:                      ":6001",
		PlatformIP:                os.Getenv("PLATFORM_IP"),
		DockerID:                  os.Getenv("DOCKER_ID"),
		Contract:                  os.Getenv("CONTRACT"),
		EnableSecurityScan:        true,
		ModelDir:                  "/opt/taa/models",
		EnableResultCheck:         true,
		DataDir:                   "/opt/taa/data",
		ResultDir:                 "/opt/taa/results",
		ModelInputDir:             "/opt/taa/input",
		ModelOutputDir:            "/opt/taa/output/result",
		ModelLogDir:               "/opt/taa/output/log",
		ModelProgressDir:          "/opt/taa/output/progress",
		KeysDir:                   "/opt/taa/keys",
		AttestationHRKCertPath:    hrkDefault,
		AttestationHSKCekCertPath: hskDefault,
		EnableLLM:                 true,
		LLMEndpoint:               "http://127.0.0.1:11434",
		LLMModel:                  "qwen2.5-coder:0.5b",
		LLMPolicy:                 "assist",
		LLMFailClosed:             true,
	}
}

func applyStartupConfigFile(cfg *StartupConfig, fileCfg startupConfigFile) {
	if fileCfg.Addr != "" {
		cfg.Addr = fileCfg.Addr
	}
	if fileCfg.PlatformIP != "" {
		cfg.PlatformIP = fileCfg.PlatformIP
	}
	if fileCfg.DockerID != "" {
		cfg.DockerID = fileCfg.DockerID
	}
	if fileCfg.Contract != "" {
		cfg.Contract = fileCfg.Contract
	}
	if fileCfg.EnableSecurityScan != nil {
		cfg.EnableSecurityScan = *fileCfg.EnableSecurityScan
	}
	if fileCfg.ModelDir != "" {
		cfg.ModelDir = fileCfg.ModelDir
	}
	if fileCfg.EnableResultCheck != nil {
		cfg.EnableResultCheck = *fileCfg.EnableResultCheck
	}
	if fileCfg.DataDir != "" {
		cfg.DataDir = fileCfg.DataDir
	}
	if fileCfg.ResultDir != "" {
		cfg.ResultDir = fileCfg.ResultDir
	}
	if fileCfg.ModelInputDir != "" {
		cfg.ModelInputDir = fileCfg.ModelInputDir
	}
	if fileCfg.ModelOutputDir != "" {
		cfg.ModelOutputDir = fileCfg.ModelOutputDir
	}
	if fileCfg.ModelLogDir != "" {
		cfg.ModelLogDir = fileCfg.ModelLogDir
	}
	if fileCfg.ModelProgressDir != "" {
		cfg.ModelProgressDir = fileCfg.ModelProgressDir
	}
	if strings.TrimSpace(fileCfg.KeysDir) != "" {
		cfg.KeysDir = strings.TrimSpace(fileCfg.KeysDir)
	}
	if trimmed := strings.TrimSpace(fileCfg.Attestation.HRKCertPath); trimmed != "" {
		cfg.AttestationHRKCertPath = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Attestation.HSKCekCertPath); trimmed != "" {
		cfg.AttestationHSKCekCertPath = trimmed
	}
	if fileCfg.LLM.Enabled != nil {
		cfg.EnableLLM = *fileCfg.LLM.Enabled
	}
	if fileCfg.LLM.Endpoint != "" {
		cfg.LLMEndpoint = fileCfg.LLM.Endpoint
	}
	if fileCfg.LLM.Model != "" {
		cfg.LLMModel = fileCfg.LLM.Model
	}
	if fileCfg.LLM.Policy != "" {
		cfg.LLMPolicy = fileCfg.LLM.Policy
	}
	if fileCfg.LLM.FailClosed != nil {
		cfg.LLMFailClosed = *fileCfg.LLM.FailClosed
	}
	if fileCfg.LLM.Dir != "" {
		cfg.LLMDir = fileCfg.LLM.Dir
	}
}
