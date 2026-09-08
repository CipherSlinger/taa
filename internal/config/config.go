package config

import (
	"encoding/json"
	"fmt"
	"os"
)

const DefaultFileName = "taa-config.json"

type StartupConfig struct {
	Addr               string
	PlatformIP         string
	DockerID           string
	Contract           string
	EnableSecurityScan bool
	ModelDir           string
	EnableResultCheck  bool
	DataDir            string
	ResultDir          string
	EnableLLM          bool
	LLMEndpoint        string
	LLMModel           string
	LLMPolicy          string
	LLMFailClosed      bool
	LLMDir             string
}

type startupConfigFile struct {
	Addr               string               `json:"addr"`
	PlatformIP         string               `json:"platformIP"`
	DockerID           string               `json:"dockerID"`
	Contract           string               `json:"contract"`
	EnableSecurityScan *bool                `json:"securityScan"`
	ModelDir           string               `json:"modelDir"`
	EnableResultCheck  *bool                `json:"resultCheck"`
	DataDir            string               `json:"dataDir"`
	ResultDir          string               `json:"resultDir"`
	LLM                startupLLMConfigFile `json:"llm"`
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
	return StartupConfig{
		Addr:               ":6001",
		PlatformIP:         os.Getenv("PLATFORM_IP"),
		DockerID:           os.Getenv("DOCKER_ID"),
		Contract:           os.Getenv("CONTRACT"),
		EnableSecurityScan: true,
		ModelDir:           "/opt/taa/models",
		EnableResultCheck:  true,
		DataDir:            "/opt/taa/data",
		ResultDir:          "/opt/taa/results",
		EnableLLM:          true,
		LLMEndpoint:        "http://127.0.0.1:11434",
		LLMModel:           "qwen2.5-coder:0.5b",
		LLMPolicy:          "assist",
		LLMFailClosed:      true,
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
