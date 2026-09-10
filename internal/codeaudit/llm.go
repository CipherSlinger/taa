package codeaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// LLMConfig controls the local LLM verifier.
type LLMConfig struct {
	Enabled     bool          // 是否启用 LLM 语义验证
	Endpoint    string        // Ollama/llama.cpp 本地 HTTP 端点
	Model       string        // 模型名，如 qwen2.5-coder:0.5b
	Timeout     time.Duration // 单次推理超时
	MaxFindings int           // 最多分析多少个 finding
	Policy      string        // "assist"（仅标注，不改变阻断）或 "gate"（可降级放行）
	FailClosed  bool          // LLM 不可用时是否阻断导入
}

// DefaultLLMConfig returns a sensible default configuration.
func DefaultLLMConfig() LLMConfig {
	return LLMConfig{
		Enabled:     true,
		Endpoint:    "http://127.0.0.1:11434",
		Model:       "qwen2.5-coder:0.5b",
		Timeout:     120 * time.Second,
		MaxFindings: 20,
		Policy:      "assist",
		FailClosed:  true,
	}
}

// LLMDecision is the structured response from the LLM.
type LLMDecision struct {
	Verdict string `json:"verdict"` // MALICIOUS / SUSPICIOUS / BENIGN / UNCERTAIN
	Reason  string `json:"reason"`
	Risk    string `json:"risk"`
}

// LLMClient abstracts the local LLM inference backend.
type LLMClient interface {
	VerifyFinding(ctx context.Context, prompt string) (LLMDecision, error)
	AnalyzeFile(ctx context.Context, prompt string) (FileSummary, error)
}

// OllamaClient talks to a local Ollama server via its REST API.
type OllamaClient struct {
	endpoint string
	model    string
	client   *http.Client
}

// NewOllamaClient creates a client for the given Ollama endpoint.
func NewOllamaClient(endpoint, model string, timeout time.Duration) *OllamaClient {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &OllamaClient{
		endpoint: endpoint,
		model:    model,
		client:   &http.Client{Timeout: timeout},
	}
}

// ollamaGenerateRequest is the request body for Ollama's /api/generate endpoint.
type ollamaGenerateRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	Stream  bool           `json:"stream"`
	Think   *bool          `json:"think,omitempty"`
	Options map[string]any `json:"options,omitempty"`
}

// ollamaGenerateResponse is the response body from Ollama's /api/generate endpoint.
type ollamaGenerateResponse struct {
	Response string `json:"response"`
}

func (c *OllamaClient) VerifyFinding(ctx context.Context, prompt string) (LLMDecision, error) {
	noThink := false
	reqBody, err := json.Marshal(ollamaGenerateRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: false,
		Think:  &noThink,
		Options: map[string]any{
			"temperature": 0.1,
			"num_predict": 160,
		},
	})
	if err != nil {
		return LLMDecision{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/api/generate", bytes.NewReader(reqBody))
	if err != nil {
		return LLMDecision{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return LLMDecision{}, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return LLMDecision{}, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	var genResp ollamaGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		return LLMDecision{}, fmt.Errorf("decode response: %w", err)
	}

	return parseDecision(genResp.Response), nil
}

// parseDecision extracts a JSON decision from the LLM's raw text response.
func parseDecision(raw string) LLMDecision {
	// Find the first {...} block in the response.
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
		return LLMDecision{Verdict: "UNCERTAIN", Reason: "无法解析模型输出"}
	}

	var decision LLMDecision
	if err := json.Unmarshal([]byte(raw[start:end]), &decision); err != nil {
		return LLMDecision{Verdict: "UNCERTAIN", Reason: "模型输出 JSON 解析失败"}
	}

	// Normalize verdict.
	switch decision.Verdict {
	case "MALICIOUS", "SUSPICIOUS", "BENIGN", "UNCERTAIN":
		// valid
	default:
		decision.Verdict = "UNCERTAIN"
	}
	return decision
}


// AnalyzeFile runs a file-level analysis prompt and returns a FileSummary.
func (c *OllamaClient) AnalyzeFile(ctx context.Context, prompt string) (FileSummary, error) {
	noThink := false
	reqBody, err := json.Marshal(ollamaGenerateRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: false,
		Think:  &noThink,
		Options: map[string]any{
			"temperature": 0.1,
			"num_predict": 160,
		},
	})
	if err != nil {
		return FileSummary{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/api/generate", bytes.NewReader(reqBody))
	if err != nil {
		return FileSummary{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return FileSummary{}, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return FileSummary{}, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	var genResp ollamaGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		return FileSummary{}, fmt.Errorf("decode response: %w", err)
	}

	return parseFileSummary(genResp.Response), nil
}

// parseFileSummary extracts a FileSummary JSON from the LLM's raw text response.
func parseFileSummary(raw string) FileSummary {
	// Find the first {...} block in the response.
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
		return FileSummary{RiskLevel: "UNCERTAIN", Summary: "无法解析模型输出"}
	}

	var summary FileSummary
	if err := json.Unmarshal([]byte(raw[start:end]), &summary); err != nil {
		return FileSummary{RiskLevel: "UNCERTAIN", Summary: "模型输出 JSON 解析失败"}
	}

	// Normalize risk_level.
	switch summary.RiskLevel {
	case "HIGH", "MEDIUM", "LOW", "UNCERTAIN":
		// valid
	default:
		summary.RiskLevel = "UNCERTAIN"
	}
	return summary
}
