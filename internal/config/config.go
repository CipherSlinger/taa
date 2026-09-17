package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	DefaultFileName       = "taa-config.json"
	DefaultMaxResultBytes = 3 * 1024 * 1024 * 1024 // 3 GB
)

type StartupConfig struct {
	Addr                      string
	PlatformIP                string
	DockerID                  string
	Contract                  string
	EnableSecurityScan        bool
	ModelDir                  string
	EnableResultCheck         bool
	MaxResultBytes            int64
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
	LLMTransport              string
	LLMEndpoint               string
	LLMUDSPath                string
	LLMAuthToken              string
	LLMTimeoutMs              int64
	LLMAllowedHosts           []string
	LLMCircuitBreakerThreshold int
	LLMCooldownSec            int
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
	MaxFileBytes       *int64                       `json:"maxFileBytes"`
	MaxResultBytes     *int64                       `json:"maxResultBytes"`
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
	Enabled                 *bool    `json:"enabled"`
	Transport               string   `json:"transport"`
	Endpoint                string   `json:"endpoint"`
	UDSPath                 string   `json:"udsPath"`
	AuthToken               string   `json:"authToken"`
	RequestTimeoutMs        int64    `json:"requestTimeoutMs"`
	AllowedHosts            []string `json:"allowedHosts"`
	CircuitBreakerThreshold int      `json:"circuitBreakerThreshold"`
	CooldownSec             int      `json:"cooldownSec"`
	Model                   string   `json:"model"`
	Policy                  string   `json:"policy"`
	FailClosed              *bool    `json:"failClosed"`
	Dir                     string   `json:"dir"`
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
		MaxResultBytes:            DefaultMaxResultBytes,
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
		LLMTransport:              "http",
		LLMEndpoint:               "http://127.0.0.1:11434",
		LLMUDSPath:                "",
		LLMAuthToken:              "",
		LLMTimeoutMs:              30000,
		LLMAllowedHosts:           nil,
		LLMCircuitBreakerThreshold: 3,
		LLMCooldownSec:            30,
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
	if fileCfg.MaxFileBytes != nil {
		cfg.MaxResultBytes = *fileCfg.MaxFileBytes
	} else if fileCfg.MaxResultBytes != nil {
		cfg.MaxResultBytes = *fileCfg.MaxResultBytes
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
	if fileCfg.LLM.Transport != "" {
		cfg.LLMTransport = strings.TrimSpace(fileCfg.LLM.Transport)
	} else if fileCfg.LLM.UDSPath != "" || strings.HasPrefix(strings.ToLower(fileCfg.LLM.Endpoint), "unix://") {
		cfg.LLMTransport = "uds"
	}
	if fileCfg.LLM.Endpoint != "" {
		cfg.LLMEndpoint = fileCfg.LLM.Endpoint
	}
	if fileCfg.LLM.UDSPath != "" {
		cfg.LLMUDSPath = strings.TrimSpace(fileCfg.LLM.UDSPath)
	}
	if fileCfg.LLM.AuthToken != "" {
		cfg.LLMAuthToken = fileCfg.LLM.AuthToken
	}
	if fileCfg.LLM.RequestTimeoutMs > 0 {
		cfg.LLMTimeoutMs = fileCfg.LLM.RequestTimeoutMs
	}
	if len(fileCfg.LLM.AllowedHosts) > 0 {
		cfg.LLMAllowedHosts = fileCfg.LLM.AllowedHosts
	}
	if fileCfg.LLM.CircuitBreakerThreshold > 0 {
		cfg.LLMCircuitBreakerThreshold = fileCfg.LLM.CircuitBreakerThreshold
	}
	if fileCfg.LLM.CooldownSec > 0 {
		cfg.LLMCooldownSec = fileCfg.LLM.CooldownSec
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
