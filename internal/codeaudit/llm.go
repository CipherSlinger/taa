package codeaudit

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/CipherSlinger/teellm"
	"github.com/CipherSlinger/teetls"
)

// llmArbitrationPolicy is the mode sent to the inference service and the only
// arbitration the audit applies: the LLM's verdict decides a static HIGH, and
// MEDIUM findings still block. It is a constant rather than a setting because a
// deployment must not be able to turn the LLM's decision back into advisory.
const llmArbitrationPolicy = teellm.PolicyModeGate

// LLMConfig controls the local LLM verifier.
type LLMConfig struct {
	Enabled bool
	// AttestationEnabled selects the transport: true uses TEE-TLS and verifies
	// the gateway's CSV attestation, false uses ordinary TLS with no
	// attestation.
	AttestationEnabled bool
	Endpoint           string
	AuthToken          string
	Model              string
	// Timeout bounds one verification request. Zero disables the bounds: a
	// verdict on this CPU-only inference service can take minutes, and a
	// deadline shorter than the generation itself turns every finding into a
	// transport failure (recorded as SERVICE_UNAVAILABLE / UNCERTAIN) rather
	// than a verdict. The health check keeps its own, separate budget.
	Timeout                 time.Duration
	MaxFindings             int
	FailClosed              bool
	AllowedHosts            []string
	CircuitBreakerThreshold int
	CooldownSec             int

	// Temperature is the sampling temperature sent in the verify request.
	// nil leaves the choice to the inference service, which decodes
	// deterministically (temperature 0) so that the same finding yields the
	// same verdict. A non-nil value overrides that and re-enables sampling:
	// identical findings may then be judged differently, and under fail-closed
	// a single MALICIOUS draw blocks the import.
	Temperature *float32

	// TEE-TLS configuration
	TEETLS *teetls.Config
	// AttestationMeasurement is the measurement digest expected in the
	// inference service's attestation report. Empty skips the measurement
	// check and logs a warning; the trust chain and key binding are still
	// verified.
	AttestationMeasurement string
	HRKCertPath            string
	HSKCekCertPath         string
	RequireMutualAttest    bool
	InsecureSkipVerify     bool
}

// DefaultLLMConfig returns safe default configuration.
func DefaultLLMConfig() LLMConfig {
	return LLMConfig{
		Enabled:            true,
		AttestationEnabled: true,
		Endpoint:           "https://127.0.0.1:8443",
		Model:              "qwen2.5-coder:0.5b",
		// No request deadline by default: the verifier cannot know how long a
		// verdict takes on the deployment's hardware, and cutting it short is
		// misreported as the service being unavailable.
		Timeout:                 0,
		MaxFindings:             0,
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
type LLMClient = teellm.Client

// FileAnalyzer defines an optional interface for file-level analysis.
type FileAnalyzer interface {
	AnalyzeFile(ctx context.Context, prompt string) (FileSummary, error)
}

// buildTEETLSConfig derives the TEE-TLS client configuration. A non-empty
// measurement turns the comparison into a hard requirement; without one the
// handshake still verifies the trust chain and key binding, but the measurement
// comparison is skipped. The skip is logged rather than silent.
func buildTEETLSConfig(cfg LLMConfig) *teetls.Config {
	if cfg.TEETLS != nil {
		return cfg.TEETLS
	}
	if !cfg.AttestationEnabled {
		return nil
	}

	mode := teetls.ModePermissive
	var expected []string
	if m := strings.TrimSpace(cfg.AttestationMeasurement); m != "" {
		mode = teetls.ModeStrict
		expected = []string{m}
	} else {
		log.Printf("[WARN] [codeaudit] attestation.measurement is empty; skipping the inference service measurement check")
	}
	teeTLSConfig := &teetls.Config{
		Mode:                          mode,
		InsecureSkipAttestationVerify: cfg.InsecureSkipVerify,
		ExpectedMeasurements:          expected,
		VerifyMutualAttestation:       cfg.RequireMutualAttest,
	}
	if cfg.HRKCertPath != "" || cfg.HSKCekCertPath != "" {
		teeTLSConfig.EvidenceProvider = teetls.NewHygonHardwareProvider("", cfg.HRKCertPath, cfg.HSKCekCertPath)
	}
	return teeTLSConfig
}

// NewInferenceClient constructs a standardized inference client based on LLMConfig.
func NewInferenceClient(cfg LLMConfig) (LLMClient, error) {
	teeTLSConfig := buildTEETLSConfig(cfg)

	return teellm.NewClient(teellm.Config{
		Endpoint:                       cfg.Endpoint,
		Timeout:                        cfg.Timeout,
		AllowedHosts:                   cfg.AllowedHosts,
		TEETLS:                         teeTLSConfig,
		CircuitBreakerFailureThreshold: cfg.CircuitBreakerThreshold,
		CircuitBreakerCooldown:         time.Duration(cfg.CooldownSec) * time.Second,
	})
}

// NewOllamaClient provides backward compatibility, returning an LLMClient via NewInferenceClient.
// A zero timeout means no request deadline.
func NewOllamaClient(endpoint, model string, timeout time.Duration) LLMClient {
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
