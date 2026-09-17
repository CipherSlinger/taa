package inference_test

import (
	"encoding/json"
	"testing"

	"taa/internal/inference"
)

func TestConstants(t *testing.T) {
	if inference.CurrentProtocolVersion != "taa-isp/v1" {
		t.Errorf("expected taa-isp/v1, got %s", inference.CurrentProtocolVersion)
	}

	// Actions
	if inference.ActionVerifyFinding != "VERIFY_FINDING" {
		t.Errorf("unexpected ActionVerifyFinding: %s", inference.ActionVerifyFinding)
	}
	if inference.ActionAnalyzeFile != "ANALYZE_FILE" {
		t.Errorf("unexpected ActionAnalyzeFile: %s", inference.ActionAnalyzeFile)
	}
	if inference.ActionHealthCheck != "HEALTH_CHECK" {
		t.Errorf("unexpected ActionHealthCheck: %s", inference.ActionHealthCheck)
	}

	// Verdicts
	if inference.VerdictMalicious != "MALICIOUS" {
		t.Errorf("unexpected VerdictMalicious: %s", inference.VerdictMalicious)
	}
	if inference.VerdictSuspicious != "SUSPICIOUS" {
		t.Errorf("unexpected VerdictSuspicious: %s", inference.VerdictSuspicious)
	}
	if inference.VerdictBenign != "BENIGN" {
		t.Errorf("unexpected VerdictBenign: %s", inference.VerdictBenign)
	}
	if inference.VerdictUncertain != "UNCERTAIN" {
		t.Errorf("unexpected VerdictUncertain: %s", inference.VerdictUncertain)
	}

	// Statuses
	if inference.StatusSuccess != "SUCCESS" {
		t.Errorf("unexpected StatusSuccess: %s", inference.StatusSuccess)
	}
	if inference.StatusInvalidRequest != "INVALID_REQUEST" {
		t.Errorf("unexpected StatusInvalidRequest: %s", inference.StatusInvalidRequest)
	}
	if inference.StatusUnauthorized != "UNAUTHORIZED" {
		t.Errorf("unexpected StatusUnauthorized: %s", inference.StatusUnauthorized)
	}
	if inference.StatusServiceOverloaded != "SERVICE_OVERLOADED" {
		t.Errorf("unexpected StatusServiceOverloaded: %s", inference.StatusServiceOverloaded)
	}
	if inference.StatusModelNotFound != "MODEL_NOT_FOUND" {
		t.Errorf("unexpected StatusModelNotFound: %s", inference.StatusModelNotFound)
	}
	if inference.StatusInternalError != "INTERNAL_ERROR" {
		t.Errorf("unexpected StatusInternalError: %s", inference.StatusInternalError)
	}
	if inference.StatusServiceUnavailable != "SERVICE_UNAVAILABLE" {
		t.Errorf("unexpected StatusServiceUnavailable: %s", inference.StatusServiceUnavailable)
	}

	// PolicyMode
	if inference.PolicyModeGate != "gate" {
		t.Errorf("unexpected PolicyModeGate: %s", inference.PolicyModeGate)
	}
	if inference.PolicyModeAssist != "assist" {
		t.Errorf("unexpected PolicyModeAssist: %s", inference.PolicyModeAssist)
	}
}

func TestRequestEnvelope_Serialization(t *testing.T) {
	req := inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-001",
		TaskID:          "task-001",
		Timestamp:       1789728000,
		Nonce:           "abcdef1234567890",
		DeadlineMs:      30000,
		Auth: inference.AuthConfig{
			AuthType: "token",
			Token:    "secret-token",
		},
		ModelRef: inference.ModelReference{
			Name:             "qwen2.5:7b",
			Tag:              "latest",
			MinContextTokens: 4096,
		},
		Action: inference.ActionVerifyFinding,
		FindingPayload: &inference.FindingPayload{
			RuleID:      "TAA-SEC-001",
			Category:    "command_injection",
			Severity:    "HIGH",
			Description: "Unsanitized command execution",
			Target: inference.CodeTarget{
				FilePath:      "train.py",
				Line:          42,
				CodeSnippet:   "os.system(cmd)",
				ContextBefore: "cmd = req.get('cmd')",
				ContextAfter:  "return res",
				ContentSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		Policy: inference.PolicyOptions{
			Mode:                 inference.PolicyModeGate,
			EnableReasoningChain: true,
			Temperature:          0.1,
			MaxCompletionTokens:  1024,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request envelope failed: %v", err)
	}

	// Verify JSON keys
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to raw map failed: %v", err)
	}

	expectedKeys := []string{
		"protocolVersion", "requestId", "taskId", "timestamp", "nonce",
		"deadlineMs", "auth", "modelRef", "action", "findingPayload", "policy",
	}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing key in JSON: %s", key)
		}
	}

	// Check nested auth keys
	authMap, ok := raw["auth"].(map[string]interface{})
	if !ok || authMap["authType"] != "token" || authMap["token"] != "secret-token" {
		t.Errorf("unexpected auth map: %v", raw["auth"])
	}

	// Check nested modelRef keys
	modelMap, ok := raw["modelRef"].(map[string]interface{})
	if !ok || modelMap["name"] != "qwen2.5:7b" || modelMap["tag"] != "latest" || int(modelMap["minContextTokens"].(float64)) != 4096 {
		t.Errorf("unexpected modelRef map: %v", raw["modelRef"])
	}

	// Check nested findingPayload and target
	findingMap, ok := raw["findingPayload"].(map[string]interface{})
	if !ok || findingMap["ruleId"] != "TAA-SEC-001" {
		t.Errorf("unexpected findingPayload map: %v", raw["findingPayload"])
	}
	targetMap, ok := findingMap["target"].(map[string]interface{})
	if !ok || targetMap["filePath"] != "train.py" || int(targetMap["line"].(float64)) != 42 || targetMap["contentSha256"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("unexpected target map: %v", findingMap["target"])
	}

	// Check policy keys
	policyMap, ok := raw["policy"].(map[string]interface{})
	if !ok || policyMap["mode"] != "gate" || policyMap["enableReasoningChain"] != true || int(policyMap["maxCompletionTokens"].(float64)) != 1024 {
		t.Errorf("unexpected policy map: %v", raw["policy"])
	}

	// Unmarshal back to struct
	var parsed inference.RequestEnvelope
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal request envelope failed: %v", err)
	}

	if parsed.ProtocolVersion != inference.CurrentProtocolVersion {
		t.Errorf("got protocol %s, want %s", parsed.ProtocolVersion, inference.CurrentProtocolVersion)
	}
	if parsed.FindingPayload == nil || parsed.FindingPayload.Target.Line != 42 {
		t.Errorf("got line %v, want 42", parsed.FindingPayload)
	}
	if parsed.Auth.Token != "secret-token" {
		t.Errorf("got token %s, want secret-token", parsed.Auth.Token)
	}
	if parsed.Policy.MaxCompletionTokens != 1024 {
		t.Errorf("got max completion tokens %d, want 1024", parsed.Policy.MaxCompletionTokens)
	}
}

func TestResponseEnvelope_Serialization(t *testing.T) {
	resp := inference.ResponseEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-001",
		Status:          inference.StatusSuccess,
		ErrorMessage:    "",
		Decision: &inference.DecisionResult{
			Verdict:              inference.VerdictMalicious,
			Confidence:           0.95,
			RiskLevel:            "HIGH",
			ReasonCode:           "CONFIRMED_COMMAND_INJECTION",
			Explanation:          "Command injection flaw confirmed",
			SuggestedRemediation: "Use exec.Command with separated arguments",
			ReasoningChain:       "Step 1: check input...",
		},
		Metrics: inference.Metrics{
			LatencyMs:        125,
			PromptTokens:     350,
			CompletionTokens: 80,
		},
		EngineInfo: inference.EngineInfo{
			Backend:     "ollama",
			ModelLoaded: "qwen2.5:7b",
			ModelDigest: "sha256:1234567890abcdef",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response envelope failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to raw map failed: %v", err)
	}

	expectedKeys := []string{
		"protocolVersion", "requestId", "status", "decision", "metrics", "engineInfo",
	}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing key in JSON: %s", key)
		}
	}

	// Check decision JSON tags
	decMap, ok := raw["decision"].(map[string]interface{})
	if !ok {
		t.Fatalf("decision field missing or invalid: %v", raw["decision"])
	}
	decKeys := []string{
		"verdict", "confidence", "riskLevel", "reasonCode", "explanation", "suggestedRemediation", "reasoningChain",
	}
	for _, k := range decKeys {
		if _, ok := decMap[k]; !ok {
			t.Errorf("missing decision key in JSON: %s", k)
		}
	}

	// Check metrics JSON tags
	metricsMap, ok := raw["metrics"].(map[string]interface{})
	if !ok || int(metricsMap["latencyMs"].(float64)) != 125 || int(metricsMap["promptTokens"].(float64)) != 350 || int(metricsMap["completionTokens"].(float64)) != 80 {
		t.Errorf("unexpected metrics map: %v", raw["metrics"])
	}

	// Check engineInfo JSON tags
	engineMap, ok := raw["engineInfo"].(map[string]interface{})
	if !ok || engineMap["backend"] != "ollama" || engineMap["modelLoaded"] != "qwen2.5:7b" || engineMap["modelDigest"] != "sha256:1234567890abcdef" {
		t.Errorf("unexpected engineInfo map: %v", raw["engineInfo"])
	}

	var parsed inference.ResponseEnvelope
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal response envelope failed: %v", err)
	}

	if parsed.Decision == nil || parsed.Decision.Verdict != inference.VerdictMalicious {
		t.Errorf("got verdict %v, want %s", parsed.Decision, inference.VerdictMalicious)
	}
	if parsed.Metrics.LatencyMs != 125 {
		t.Errorf("got latencyMs %d, want 125", parsed.Metrics.LatencyMs)
	}
	if parsed.EngineInfo.Backend != "ollama" {
		t.Errorf("got backend %s, want ollama", parsed.EngineInfo.Backend)
	}
}
