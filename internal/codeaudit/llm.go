package codeaudit

import (
	"context"
	"encoding/json"
	"time"

	"taa/teellm"
	"taa/teetls"
)

// LLMConfig controls the local LLM verifier.
type LLMConfig struct {
	Enabled                 bool
	Transport               string
	Endpoint                string
	AuthToken               string
	Model                   string
	Timeout                 time.Duration
	MaxFindings             int
	Policy                  string
	FailClosed              bool
	AllowedHosts            []string
	CircuitBreakerThreshold int
	CooldownSec             int

	// TEE-TLS configuration
	TEETLS               *teetls.Config
	AttestationMode      string
	HRKCertPath          string
	HSKCekCertPath       string
	ExpectedMeasurements []string
	RequireMutualAttest  bool
	InsecureSkipVerify   bool
}

// DefaultLLMConfig returns safe default configuration.
func DefaultLLMConfig() LLMConfig {
	return LLMConfig{
		Enabled:                 true,
		Transport:               "teetls",
		Endpoint:                "https://127.0.0.1:8443",
		Model:                   "qwen2.5-coder:0.5b",
		Timeout:                 30 * time.Second,
		MaxFindings:             20,
		Policy:                  "assist",
		FailClosed:              true,
		CircuitBreakerThreshold: 3,
		CooldownSec:             30,
		AttestationMode:         "strict",
	}
}

// LLMDecision represents a structured decision for test mocks and legacy parsers.
type LLMDecision struct {
	Verdict string `json:"verdict"` // MALICIOUS / SUSPICIOUS / BENIGN / UNCERTAIN
	Reason  string `json:"reason"`
	Risk    string `json:"risk"`
}

// LLMClient abstracts the standardized inference client interface.
type LLMClient = teellm.Client

// FileAnalyzer defines an optional interface for file-level analysis.
type FileAnalyzer interface {
	AnalyzeFile(ctx context.Context, prompt string) (FileSummary, error)
}

// NewInferenceClient constructs a standardized inference client based on LLMConfig.
func NewInferenceClient(cfg LLMConfig) (LLMClient, error) {
	var teeTLSConfig *teetls.Config
	if cfg.TEETLS != nil {
		teeTLSConfig = cfg.TEETLS
	} else if cfg.Transport == "teetls" || cfg.Transport == "https" || cfg.Transport == "" {
		mode := teetls.ModeStrict
		if cfg.AttestationMode == "permissive" {
			mode = teetls.ModePermissive
		}
		teeTLSConfig = &teetls.Config{
			Mode:                          mode,
			InsecureSkipAttestationVerify: cfg.InsecureSkipVerify,
			ExpectedMeasurements:          cfg.ExpectedMeasurements,
			VerifyMutualAttestation:       cfg.RequireMutualAttest,
		}
		if cfg.HRKCertPath != "" || cfg.HSKCekCertPath != "" {
			teeTLSConfig.EvidenceProvider = teetls.NewHygonHardwareProvider("", cfg.HRKCertPath, cfg.HSKCekCertPath)
		}
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return teellm.NewClient(teellm.Config{
		Endpoint:                       cfg.Endpoint,
		Timeout:                        timeout,
		AllowedHosts:                   cfg.AllowedHosts,
		TEETLS:                         teeTLSConfig,
		CircuitBreakerFailureThreshold: cfg.CircuitBreakerThreshold,
		CircuitBreakerCooldown:         time.Duration(cfg.CooldownSec) * time.Second,
	})
}

// NewOllamaClient provides backward compatibility, returning an LLMClient via NewInferenceClient.
func NewOllamaClient(endpoint, model string, timeout time.Duration) LLMClient {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client, err := NewInferenceClient(LLMConfig{
		Endpoint:           endpoint,
		Model:              model,
		Timeout:            timeout,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	return client
}

// parseDecision extracts a JSON decision from raw text response.
func parseDecision(raw string) LLMDecision {
	start := -1
	end := -1
	depth := 0
	for i, ch := range raw {
		switch ch {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i + 1
			}
		}
		if start >= 0 && end > start {
			break
		}
	}
	if start < 0 || end <= start {
		return LLMDecision{Verdict: "UNCERTAIN", Reason: "unable to parse model output"}
	}

	var decision LLMDecision
	if err := json.Unmarshal([]byte(raw[start:end]), &decision); err != nil {
		return LLMDecision{Verdict: "UNCERTAIN", Reason: "model output json parse error"}
	}

	switch decision.Verdict {
	case "MALICIOUS", "SUSPICIOUS", "BENIGN", "UNCERTAIN":
		// valid
	default:
		decision.Verdict = "UNCERTAIN"
	}
	return decision
}

// parseFileSummary extracts a FileSummary JSON from raw text response.
func parseFileSummary(raw string) FileSummary {
	start := -1
	end := -1
	depth := 0
	for i, ch := range raw {
		switch ch {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i + 1
			}
		}
		if start >= 0 && end > start {
			break
		}
	}
	if start < 0 || end <= start {
		return FileSummary{RiskLevel: "UNCERTAIN", Summary: "unable to parse model output"}
	}

	var summary FileSummary
	if err := json.Unmarshal([]byte(raw[start:end]), &summary); err != nil {
		return FileSummary{RiskLevel: "UNCERTAIN", Summary: "model output json parse error"}
	}

	switch summary.RiskLevel {
	case "HIGH", "MEDIUM", "LOW", "UNCERTAIN":
		// valid
	default:
		summary.RiskLevel = "UNCERTAIN"
	}
	return summary
}
