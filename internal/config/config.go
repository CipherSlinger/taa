package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	DefaultFileName       = "taa-config.json"
	DefaultMaxFileBytes   = 3 * 1024 * 1024 * 1024 // 3 GB
	DefaultMaxResultBytes = DefaultMaxFileBytes
)

type StartupConfig struct {
	Addr               string
	PlatformIP         string
	DockerID           string
	Contract           string
	EnableSecurityScan bool
	// CodeScanEngine selects the Tier 1 static engine ("regex" or "semgrep").
	// The default stays "regex" until the holdout evidence passes (spec §6.5).
	CodeScanEngine string
	// SemgrepRulesPath is the rules file or directory for the semgrep engine,
	// passed through as --config. Empty means the engine's own default, which is
	// relative to the repository root and therefore useless in a container: a
	// deployment that selects semgrep is expected to set this.
	SemgrepRulesPath string
	// SemgrepTimeout bounds one semgrep scan. It is not a scan budget but a
	// safety net: an import waits on this scan, and the adapter turns an expired
	// deadline into a failed scan, which the audit fails closed on. Zero means
	// the adapter's own default (codeaudit.DefaultSemgrepTimeout), which is where
	// the enforced number lives; a negative value is rejected at load time.
	SemgrepTimeout             time.Duration
	ModelDir                   string
	EnableResultCheck          bool
	MaxFileBytes               int64
	MaxResultBytes             int64
	DataDir                    string
	ResultDir                  string
	ModelInputDir              string
	ModelOutputDir             string
	ModelLogDir                string
	ModelProgressDir           string
	ModelCheckpointDir         string
	KeysDir                    string
	AttestationHRKCertPath     string
	AttestationHSKCekCertPath  string
	EnableLLM                  bool
	LLMTransport               string
	LLMEndpoint                string
	LLMAttestationMode         string
	LLMHRKCertPath             string
	LLMHSKCekCertPath          string
	LLMExpectedMeasurements    []string
	LLMRequireMutualAttest     bool
	LLMInsecureSkipVerify      bool
	LLMAuthToken               string
	LLMTimeoutMs               int64
	LLMAllowedHosts            []string
	LLMCircuitBreakerThreshold int
	LLMCooldownSec             int
	LLMModel                   string
	LLMPolicy                  string
	LLMFailClosed              bool
	LLMDir                     string
}

type startupConfigFile struct {
	Server      startupServerConfigFile      `json:"server"`
	Platform    startupPlatformConfigFile    `json:"platform"`
	Storage     startupStorageConfigFile     `json:"storage"`
	Model       startupModelConfigFile       `json:"model"`
	Security    startupSecurityConfigFile    `json:"security"`
	Attestation startupAttestationConfigFile `json:"attestation"`
	LLM         startupLLMConfigFile         `json:"llm"`

	// Legacy flat fields for backward compatibility
	Addr               string `json:"addr"`
	PlatformIP         string `json:"platformIP"`
	DockerID           string `json:"dockerID"`
	Contract           string `json:"contract"`
	EnableSecurityScan *bool  `json:"securityScan"`
	ModelDir           string `json:"modelDir"`
	EnableResultCheck  *bool  `json:"resultCheck"`
	MaxFileBytes       *int64 `json:"maxFileBytes"`
	MaxResultBytes     *int64 `json:"maxResultBytes"`
	DataDir            string `json:"dataDir"`
	ResultDir          string `json:"resultDir"`
	ModelInputDir      string `json:"modelInputDir"`
	ModelOutputDir     string `json:"modelOutputDir"`
	ModelLogDir        string `json:"modelLogDir"`
	ModelProgressDir   string `json:"modelProgressDir"`
	ModelCheckpointDir string `json:"modelCheckpointDir"`
	KeysDir            string `json:"keysDir"`
}

type startupServerConfigFile struct {
	Addr string `json:"addr"`
}

type startupPlatformConfigFile struct {
	IP       string `json:"ip"`
	Endpoint string `json:"endpoint"`
	DockerID string `json:"dockerID"`
	Contract string `json:"contract"`
}

type startupStorageConfigFile struct {
	Model     string `json:"model"`
	Data      string `json:"data"`
	Result    string `json:"result"`
	Keys      string `json:"keys"`
	ModelDir  string `json:"modelDir"`
	DataDir   string `json:"dataDir"`
	ResultDir string `json:"resultDir"`
	KeysDir   string `json:"keysDir"`
}

type startupSecurityConfigFile struct {
	CodeScan         *bool  `json:"codeScan"`
	Scan             *bool  `json:"scan"`
	CodeScanEngine   string `json:"codeScanEngine"`
	SemgrepRulesPath string `json:"semgrepRulesPath"`
	// SemgrepTimeoutSeconds is a whole-scan deadline in seconds. Absent or zero
	// means the adapter's default; zero is not read as "no deadline", because an
	// unbounded scan is a hung import rather than a faster one.
	SemgrepTimeoutSeconds int                          `json:"semgrepTimeoutSeconds"`
	ResultCheck           startupResultCheckConfigFile `json:"resultCheck"`
	MaxFileBytes          *int64                       `json:"maxFileBytes"`
}

type startupResultCheckConfigFile struct {
	Enabled      *bool  `json:"enabled"`
	MaxFileBytes *int64 `json:"maxFileBytes"`
}

func (r *startupResultCheckConfigFile) UnmarshalJSON(data []byte) error {
	var asBool bool
	if err := json.Unmarshal(data, &asBool); err == nil {
		r.Enabled = &asBool
		return nil
	}
	type rawResultCheck startupResultCheckConfigFile
	var raw rawResultCheck
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = startupResultCheckConfigFile(raw)
	return nil
}

type startupModelConfigFile struct {
	Dir        string                       `json:"dir"`
	Input      string                       `json:"input"`
	Checkpoint string                       `json:"checkpoint"`
	Output     startupModelOutputConfigFile `json:"output"`
}

type startupModelOutputConfigFile struct {
	Result   string `json:"result"`
	Log      string `json:"log"`
	Progress string `json:"progress"`
}

type startupAttestationConfigFile struct {
	HRKCertPath    string `json:"hrkCertPath"`
	HSKCekCertPath string `json:"hskCekCertPath"`
}

type startupLLMConfigFile struct {
	Enabled                 *bool    `json:"enabled"`
	Transport               string   `json:"transport"`
	Endpoint                string   `json:"endpoint"`
	AttestationMode         string   `json:"attestationMode"`
	HRKCertPath             string   `json:"hrkCertPath"`
	HSKCekCertPath          string   `json:"hskCekCertPath"`
	ExpectedMeasurements    []string `json:"expectedMeasurements"`
	RequireMutualAttest     *bool    `json:"requireMutualAttest"`
	InsecureSkipVerify      *bool    `json:"insecureSkipVerify"`
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
	if err := validateStartupConfig(cfg); err != nil {
		return StartupConfig{}, err
	}
	return cfg, nil
}

// llmPolicies lists the arbitration modes understood by the audit code
// (see codeaudit.LLMConfig.Policy). Any other value matches neither the gate
// nor the assist branch, silently degrading a blocking gate to assist
// behaviour, so it is rejected at load time instead.
var llmPolicies = []string{"assist", "gate"}

// staticEngines lists the Tier 1 engines understood by the audit code (see
// codeaudit.NewEngine). The list is repeated here rather than imported, because
// the config package deliberately does not depend on the audit package. An
// unrecognized name matches no branch in the engine selector, so it is rejected
// at load time instead of silently scanning with the regex baseline while the
// deployment believes otherwise.
var staticEngines = []string{"regex", "semgrep"}

func validateStartupConfig(cfg StartupConfig) error {
	if err := validateCodeScanEngine(cfg); err != nil {
		return err
	}
	if err := validateSemgrepTimeout(cfg); err != nil {
		return err
	}
	return validateLLMPolicy(cfg)
}

// validateSemgrepTimeout rejects a deadline the adapter cannot honour. A
// negative duration is not a shorter scan: the deadline is already expired when
// the scan starts, so every import fails closed and its model code is deleted,
// and the cause is a line of configuration nothing re-reads. The failure belongs
// on the configuration, where an operator sees it at startup.
func validateSemgrepTimeout(cfg StartupConfig) error {
	if cfg.SemgrepTimeout < 0 {
		return fmt.Errorf("semgrepTimeoutSeconds in startup config must not be negative: got %d",
			int64(cfg.SemgrepTimeout/time.Second))
	}
	return nil
}

func validateCodeScanEngine(cfg StartupConfig) error {
	for _, engine := range staticEngines {
		if cfg.CodeScanEngine == engine {
			return nil
		}
	}
	return fmt.Errorf("unsupported code scan engine %q in startup config: must be one of %s",
		cfg.CodeScanEngine, strings.Join(staticEngines, ", "))
}

func validateLLMPolicy(cfg StartupConfig) error {
	for _, policy := range llmPolicies {
		if cfg.LLMPolicy == policy {
			return nil
		}
	}
	return fmt.Errorf("unsupported llm policy %q in startup config: must be one of %s",
		cfg.LLMPolicy, strings.Join(llmPolicies, ", "))
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
		Addr:                       ":6001",
		PlatformIP:                 os.Getenv("PLATFORM_IP"),
		DockerID:                   os.Getenv("DOCKER_ID"),
		Contract:                   os.Getenv("CONTRACT"),
		EnableSecurityScan:         true,
		CodeScanEngine:             "regex",
		ModelDir:                   "/opt/taa/models",
		EnableResultCheck:          true,
		MaxFileBytes:               DefaultMaxFileBytes,
		MaxResultBytes:             DefaultMaxResultBytes,
		DataDir:                    "/opt/taa/data",
		ResultDir:                  "/opt/taa/results",
		ModelInputDir:              "/opt/taa/input",
		ModelOutputDir:             "/opt/taa/output/result",
		ModelLogDir:                "/opt/taa/output/log/train.jsonl",
		ModelProgressDir:           "/opt/taa/output/progress/progress.json",
		ModelCheckpointDir:         "/opt/taa/checkpoint",
		KeysDir:                    "/opt/taa/keys",
		AttestationHRKCertPath:     hrkDefault,
		AttestationHSKCekCertPath:  hskDefault,
		EnableLLM:                  true,
		LLMTransport:               "teetls",
		LLMEndpoint:                "https://127.0.0.1:8443",
		LLMAttestationMode:         "strict",
		LLMHRKCertPath:             hrkDefault,
		LLMHSKCekCertPath:          hskDefault,
		LLMExpectedMeasurements:    nil,
		LLMRequireMutualAttest:     false,
		LLMInsecureSkipVerify:      false,
		LLMAuthToken:               "",
		LLMTimeoutMs:               30000,
		LLMAllowedHosts:            nil,
		LLMCircuitBreakerThreshold: 3,
		LLMCooldownSec:             30,
		LLMModel:                   "qwen2.5-coder:0.5b",
		LLMPolicy:                  "assist",
		LLMFailClosed:              true,
	}
}

func applyStartupConfigFile(cfg *StartupConfig, fileCfg startupConfigFile) {
	if trimmed := strings.TrimSpace(fileCfg.Addr); trimmed != "" {
		cfg.Addr = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Server.Addr); trimmed != "" {
		cfg.Addr = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.PlatformIP); trimmed != "" {
		cfg.PlatformIP = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Platform.IP); trimmed != "" {
		cfg.PlatformIP = trimmed
	} else if trimmed := strings.TrimSpace(fileCfg.Platform.Endpoint); trimmed != "" {
		cfg.PlatformIP = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.DockerID); trimmed != "" {
		cfg.DockerID = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Platform.DockerID); trimmed != "" {
		cfg.DockerID = trimmed
	}

	if fileCfg.Contract != "" {
		cfg.Contract = fileCfg.Contract
	}
	if fileCfg.Platform.Contract != "" {
		cfg.Contract = fileCfg.Platform.Contract
	}

	if fileCfg.EnableSecurityScan != nil {
		cfg.EnableSecurityScan = *fileCfg.EnableSecurityScan
	}
	if fileCfg.Security.Scan != nil {
		cfg.EnableSecurityScan = *fileCfg.Security.Scan
	}
	if fileCfg.Security.CodeScan != nil {
		cfg.EnableSecurityScan = *fileCfg.Security.CodeScan
	}

	if trimmed := strings.ToLower(strings.TrimSpace(fileCfg.Security.CodeScanEngine)); trimmed != "" {
		cfg.CodeScanEngine = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Security.SemgrepRulesPath); trimmed != "" {
		cfg.SemgrepRulesPath = trimmed
	}
	if seconds := fileCfg.Security.SemgrepTimeoutSeconds; seconds != 0 {
		cfg.SemgrepTimeout = time.Duration(seconds) * time.Second
	}

	if trimmed := strings.TrimSpace(fileCfg.ModelDir); trimmed != "" {
		cfg.ModelDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Dir); trimmed != "" {
		cfg.ModelDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.ModelDir); trimmed != "" {
		cfg.ModelDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.Model); trimmed != "" {
		cfg.ModelDir = trimmed
	}

	if fileCfg.EnableResultCheck != nil {
		cfg.EnableResultCheck = *fileCfg.EnableResultCheck
	}
	if fileCfg.Security.ResultCheck.Enabled != nil {
		cfg.EnableResultCheck = *fileCfg.Security.ResultCheck.Enabled
	}

	if fileCfg.MaxResultBytes != nil {
		cfg.MaxFileBytes = *fileCfg.MaxResultBytes
	}
	if fileCfg.MaxFileBytes != nil {
		cfg.MaxFileBytes = *fileCfg.MaxFileBytes
	}
	if fileCfg.Security.MaxFileBytes != nil {
		cfg.MaxFileBytes = *fileCfg.Security.MaxFileBytes
	}
	if fileCfg.Security.ResultCheck.MaxFileBytes != nil {
		cfg.MaxFileBytes = *fileCfg.Security.ResultCheck.MaxFileBytes
	}
	cfg.MaxResultBytes = cfg.MaxFileBytes

	if trimmed := strings.TrimSpace(fileCfg.DataDir); trimmed != "" {
		cfg.DataDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.DataDir); trimmed != "" {
		cfg.DataDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.Data); trimmed != "" {
		cfg.DataDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.ResultDir); trimmed != "" {
		cfg.ResultDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.ResultDir); trimmed != "" {
		cfg.ResultDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.Result); trimmed != "" {
		cfg.ResultDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.KeysDir); trimmed != "" {
		cfg.KeysDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.KeysDir); trimmed != "" {
		cfg.KeysDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.Keys); trimmed != "" {
		cfg.KeysDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.ModelInputDir); trimmed != "" {
		cfg.ModelInputDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Input); trimmed != "" {
		cfg.ModelInputDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.ModelOutputDir); trimmed != "" {
		cfg.ModelOutputDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Output.Result); trimmed != "" {
		cfg.ModelOutputDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.ModelLogDir); trimmed != "" {
		cfg.ModelLogDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Output.Log); trimmed != "" {
		cfg.ModelLogDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.ModelProgressDir); trimmed != "" {
		cfg.ModelProgressDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Output.Progress); trimmed != "" {
		cfg.ModelProgressDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.ModelCheckpointDir); trimmed != "" {
		cfg.ModelCheckpointDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Checkpoint); trimmed != "" {
		cfg.ModelCheckpointDir = trimmed
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
	}
	if fileCfg.LLM.Endpoint != "" {
		cfg.LLMEndpoint = fileCfg.LLM.Endpoint
	}
	if trimmed := strings.TrimSpace(fileCfg.LLM.AttestationMode); trimmed != "" {
		cfg.LLMAttestationMode = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.LLM.HRKCertPath); trimmed != "" {
		cfg.LLMHRKCertPath = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.LLM.HSKCekCertPath); trimmed != "" {
		cfg.LLMHSKCekCertPath = trimmed
	}
	if len(fileCfg.LLM.ExpectedMeasurements) > 0 {
		cfg.LLMExpectedMeasurements = fileCfg.LLM.ExpectedMeasurements
	}
	if fileCfg.LLM.RequireMutualAttest != nil {
		cfg.LLMRequireMutualAttest = *fileCfg.LLM.RequireMutualAttest
	}
	if fileCfg.LLM.InsecureSkipVerify != nil {
		cfg.LLMInsecureSkipVerify = *fileCfg.LLM.InsecureSkipVerify
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
		cfg.LLMPolicy = strings.ToLower(strings.TrimSpace(fileCfg.LLM.Policy))
	}
	if fileCfg.LLM.FailClosed != nil {
		cfg.LLMFailClosed = *fileCfg.LLM.FailClosed
	}
	if fileCfg.LLM.Dir != "" {
		cfg.LLMDir = fileCfg.LLM.Dir
	}
}
