package codeaudit

import (
	"context"
	"encoding/json"
	"time"

	"taa/internal/inference"
)

// LLMConfig controls the local LLM verifier.
type LLMConfig struct {
	Enabled                 bool
	Transport               string
	Endpoint                string
	UDSPath                 string
	AuthToken               string
	Model                   string
	Timeout                 time.Duration
	MaxFindings             int
	Policy                  string
	FailClosed              bool
	AllowedHosts            []string
	CircuitBreakerThreshold int
	CooldownSec             int
}

// DefaultLLMConfig returns safe default configuration.
func DefaultLLMConfig() LLMConfig {
	return LLMConfig{
		Enabled:                 true,
		Transport:               "http",
		Endpoint:                "http://127.0.0.1:11434",
		Model:                   "qwen2.5-coder:0.5b",
		Timeout:                 30 * time.Second,
		MaxFindings:             20,
		Policy:                  "assist",
		FailClosed:              true,
		CircuitBreakerThreshold: 3,
		CooldownSec:             30,
	}
}

// LLMDecision represents a structured decision for test mocks and legacy parsers.
type LLMDecision struct {
	Verdict string `json:"verdict"` // MALICIOUS / SUSPICIOUS / BENIGN / UNCERTAIN
	Reason  string `json:"reason"`
	Risk    string `json:"risk"`
}

// LLMClient abstracts the standardized inference client interface.
type LLMClient = inference.InferenceClient

// FileAnalyzer defines an optional interface for file-level analysis.
type FileAnalyzer interface {
	AnalyzeFile(ctx context.Context, prompt string) (FileSummary, error)
}

// NewInferenceClient constructs a standardized inference client based on LLMConfig.
func NewInferenceClient(cfg LLMConfig) (LLMClient, error) {
	return inference.NewClient(inference.Config{
		Transport:               cfg.Transport,
		Endpoint:                cfg.Endpoint,
		UDSPath:                 cfg.UDSPath,
		AuthToken:               cfg.AuthToken,
		Timeout:                 cfg.Timeout,
		AllowedHosts:            cfg.AllowedHosts,
		CircuitBreakerThreshold: cfg.CircuitBreakerThreshold,
		CooldownSec:             cfg.CooldownSec,
	})
}

// NewOllamaClient provides backward compatibility, returning an InferenceClient via inference.NewClient.
func NewOllamaClient(endpoint, model string, timeout time.Duration) LLMClient {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client, err := inference.NewClient(inference.Config{
		Transport: "http",
		Endpoint:  endpoint,
		Timeout:   timeout,
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
