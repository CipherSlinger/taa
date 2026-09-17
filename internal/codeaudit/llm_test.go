package codeaudit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"taa/internal/inference"
)

// ── parseDecision tests ──────────────────────────────────

func TestParseDecisionValidJSON(t *testing.T) {
	raw := `Based on the code analysis, here is my assessment:
{"verdict": "MALICIOUS", "reason": "code transmits training data to external server", "risk": "training data could be exfiltrated"}
Some trailing text.`
	d := parseDecision(raw)
	if d.Verdict != "MALICIOUS" {
		t.Fatalf("verdict = %s, want MALICIOUS", d.Verdict)
	}
	if d.Reason == "" {
		t.Fatal("reason should not be empty")
	}
}

func TestParseDecisionInvalidJSON(t *testing.T) {
	d := parseDecision("I cannot determine the verdict.")
	if d.Verdict != "UNCERTAIN" {
		t.Fatalf("verdict = %s, want UNCERTAIN for unparseable output", d.Verdict)
	}
}

func TestParseDecisionInvalidVerdict(t *testing.T) {
	raw := `{"verdict": "HACKED", "reason": "test", "risk": ""}`
	d := parseDecision(raw)
	if d.Verdict != "UNCERTAIN" {
		t.Fatalf("verdict = %s, want UNCERTAIN for invalid verdict", d.Verdict)
	}
}

// ── Mock LLM client ──────────────────────────────────────

type mockLLMClient struct {
	decisions     []LLMDecision
	fileSummaries []FileSummary
	callCount     int
	fileCallCount int
}

func (m *mockLLMClient) VerifyFinding(_ context.Context, _ *inference.RequestEnvelope) (*inference.ResponseEnvelope, error) {
	if m.callCount >= len(m.decisions) {
		return &inference.ResponseEnvelope{
			ProtocolVersion: inference.CurrentProtocolVersion,
			Status:          inference.StatusSuccess,
			Decision: &inference.DecisionResult{
				Verdict:     "UNCERTAIN",
				Explanation: "no more mock decisions",
			},
		}, nil
	}
	d := m.decisions[m.callCount]
	m.callCount++
	return &inference.ResponseEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		Status:          inference.StatusSuccess,
		Decision: &inference.DecisionResult{
			Verdict:     d.Verdict,
			Explanation: d.Reason,
			RiskLevel:   d.Risk,
		},
	}, nil
}

func (m *mockLLMClient) HealthCheck(_ context.Context) error {
	return nil
}

func (m *mockLLMClient) Close() error {
	return nil
}

func (m *mockLLMClient) AnalyzeFile(_ context.Context, _ string) (FileSummary, error) {
	if m.fileCallCount >= len(m.fileSummaries) {
		return FileSummary{RiskLevel: "UNCERTAIN", Summary: "no more mock summaries"}, nil
	}
	s := m.fileSummaries[m.fileCallCount]
	m.fileCallCount++
	return s, nil
}

// ── Mock Inference Client ────────────────────────────────

type mockInferenceClient struct {
	verdict string
	err     error
}

func (m *mockInferenceClient) VerifyFinding(ctx context.Context, req *inference.RequestEnvelope) (*inference.ResponseEnvelope, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &inference.ResponseEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		Status:          inference.StatusSuccess,
		Decision: &inference.DecisionResult{
			Verdict:     m.verdict,
			Confidence:  0.9,
			RiskLevel:   "HIGH",
			Explanation: "mock explanation",
		},
	}, nil
}

func (m *mockInferenceClient) HealthCheck(ctx context.Context) error { return m.err }
func (m *mockInferenceClient) Close() error                           { return nil }

// ── VerifyReport tests ───────────────────────────────────

func TestVerifyReportAssistPolicy(t *testing.T) {
	report := &Report{
		HighCount:   2,
		MediumCount: 0,
		Passed:      false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
			{File: "a.py", Line: 5, RuleID: "CMD_001", Severity: SeverityHigh, CodeSnippet: "subprocess.run(cmd)"},
		},
	}

	mock := &mockLLMClient{
		decisions: []LLMDecision{
			{Verdict: "BENIGN", Reason: "sends model metrics only"},
			{Verdict: "BENIGN", Reason: "runs local test script"},
		},
	}

	cfg := LLMConfig{Enabled: true, Policy: "assist", MaxFindings: 10}
	result, err := VerifyReport(context.Background(), report, cfg, mock)
	if err != nil {
		t.Fatal(err)
	}

	// Assist mode: LLM verdicts are recorded but do not change Passed.
	if result.Passed {
		t.Fatal("assist mode should not change Passed even if LLM says BENIGN")
	}
	if result.Findings[0].LLMVerdict != "BENIGN" {
		t.Fatalf("finding[0] verdict = %s, want BENIGN", result.Findings[0].LLMVerdict)
	}
	if result.Findings[1].LLMVerdict != "BENIGN" {
		t.Fatalf("finding[1] verdict = %s, want BENIGN", result.Findings[1].LLMVerdict)
	}
}

func TestVerifyReportGatePolicyDowngradesBenign(t *testing.T) {
	report := &Report{
		HighCount:   2,
		MediumCount: 0,
		Passed:      false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
			{File: "a.py", Line: 5, RuleID: "CMD_001", Severity: SeverityHigh, CodeSnippet: "subprocess.run(cmd)"},
		},
	}

	mock := &mockLLMClient{
		decisions: []LLMDecision{
			{Verdict: "BENIGN", Reason: "metrics only"},
			{Verdict: "BENIGN", Reason: "test execution"},
		},
	}

	cfg := LLMConfig{Enabled: true, Policy: "gate", MaxFindings: 10}
	result, err := VerifyReport(context.Background(), report, cfg, mock)
	if err != nil {
		t.Fatal(err)
	}

	// Gate mode: both HIGH findings downgraded to BENIGN -> should pass.
	if !result.Passed {
		t.Fatal("gate mode should pass when all HIGH findings are BENIGN")
	}
	if result.HighCount != 0 {
		t.Fatalf("highCount = %d, want 0 after downgrade", result.HighCount)
	}
}

func TestVerifyReportGatePolicyBlocksMalicious(t *testing.T) {
	report := &Report{
		HighCount:   1,
		MediumCount: 0,
		Passed:      false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url, data=raw_data)"},
		},
	}

	mock := &mockLLMClient{
		decisions: []LLMDecision{
			{Verdict: "MALICIOUS", Reason: "sends raw training data to external server", Risk: "data exfiltration"},
		},
	}

	cfg := LLMConfig{Enabled: true, Policy: "gate", MaxFindings: 10}
	result, err := VerifyReport(context.Background(), report, cfg, mock)
	if err != nil {
		t.Fatal(err)
	}

	if result.Passed {
		t.Fatal("gate mode should block when LLM says MALICIOUS")
	}
	if result.Findings[0].LLMRisk != "data exfiltration" {
		t.Fatalf("risk = %s, want data exfiltration", result.Findings[0].LLMRisk)
	}
}

func TestVerifyReportDisabled(t *testing.T) {
	report := &Report{Passed: false, HighCount: 1, Findings: []Finding{{Severity: SeverityHigh}}}
	cfg := LLMConfig{Enabled: false}
	result, err := VerifyReport(context.Background(), report, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Findings[0].LLMVerdict != "" {
		t.Fatal("LLM should not be called when disabled")
	}
}

func TestVerifyReportMaxFindingsCap(t *testing.T) {
	findings := make([]Finding, 10)
	for i := range findings {
		findings[i] = Finding{File: "x.py", Line: i + 1, Severity: SeverityHigh}
	}
	report := &Report{HighCount: 10, Passed: false, Findings: findings}

	mock := &mockLLMClient{
		decisions: make([]LLMDecision, 10),
	}
	for i := range mock.decisions {
		mock.decisions[i] = LLMDecision{Verdict: "BENIGN", Reason: "ok"}
	}

	cfg := LLMConfig{Enabled: true, Policy: "gate", MaxFindings: 3}
	_, err := VerifyReport(context.Background(), report, cfg, mock)
	if err != nil {
		t.Fatal(err)
	}

	if mock.callCount != 3 {
		t.Fatalf("expected 3 LLM calls (MaxFindings=3), got %d", mock.callCount)
	}
}

// ── Standardized Inference Client Tests ───────────────────

func TestVerifyReport_InferenceClient_Malicious(t *testing.T) {
	report := &Report{
		HighCount: 1,
		Passed:    false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
		},
	}
	client := &mockInferenceClient{verdict: inference.VerdictMalicious}
	cfg := LLMConfig{Enabled: true, Policy: "gate", MaxFindings: 10}

	res, err := VerifyReport(context.Background(), report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Passed {
		t.Fatal("expected report to not pass when verdict is MALICIOUS in gate mode")
	}
	if res.Findings[0].LLMVerdict != inference.VerdictMalicious {
		t.Fatalf("verdict = %s, want %s", res.Findings[0].LLMVerdict, inference.VerdictMalicious)
	}
}

func TestVerifyReport_InferenceClient_BenignDowngrade(t *testing.T) {
	report := &Report{
		HighCount: 1,
		Passed:    false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
		},
	}
	client := &mockInferenceClient{verdict: inference.VerdictBenign}
	cfg := LLMConfig{Enabled: true, Policy: "gate", MaxFindings: 10}

	res, err := VerifyReport(context.Background(), report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Passed {
		t.Fatal("expected report to pass when HIGH finding downgraded to BENIGN in gate mode")
	}
	if res.HighCount != 0 {
		t.Fatalf("HighCount = %d, want 0", res.HighCount)
	}
	if res.Findings[0].LLMVerdict != inference.VerdictBenign {
		t.Fatalf("verdict = %s, want %s", res.Findings[0].LLMVerdict, inference.VerdictBenign)
	}
}

func TestVerifyReport_InferenceClient_CircuitOpen_GateFailClosed(t *testing.T) {
	report := &Report{
		HighCount: 1,
		Passed:    false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
		},
	}
	client := &mockInferenceClient{err: inference.ErrCircuitOpen}
	cfg := LLMConfig{Enabled: true, Policy: "gate", MaxFindings: 10}

	res, err := VerifyReport(context.Background(), report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Passed {
		t.Fatal("expected report to fail closed when circuit is open in gate mode")
	}
	if res.Findings[0].LLMVerdict != "UNCERTAIN" {
		t.Fatalf("verdict = %s, want UNCERTAIN", res.Findings[0].LLMVerdict)
	}
	if res.Findings[0].LLMReason != "SERVICE_UNAVAILABLE: circuit breaker open" {
		t.Fatalf("reason = %s, want SERVICE_UNAVAILABLE: circuit breaker open", res.Findings[0].LLMReason)
	}
}

func TestVerifyReport_InferenceClient_CircuitOpen_AssistDegraded(t *testing.T) {
	report := &Report{
		HighCount:   0,
		MediumCount: 1,
		Passed:      true,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "DYN_001", Severity: SeverityMedium, CodeSnippet: "eval(expr)"},
		},
	}
	client := &mockInferenceClient{err: inference.ErrCircuitOpen}
	cfg := LLMConfig{Enabled: true, Policy: "assist", MaxFindings: 10}

	res, err := VerifyReport(context.Background(), report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.LLMDegraded {
		t.Fatal("expected LLMDegraded = true in assist mode on inference error")
	}
	if !res.Passed {
		t.Fatal("expected Passed to be preserved from static scan (true for medium-only findings)")
	}
	if res.Findings[0].LLMVerdict != "UNCERTAIN" {
		t.Fatalf("verdict = %s, want UNCERTAIN", res.Findings[0].LLMVerdict)
	}
	if res.Findings[0].LLMReason != "SERVICE_UNAVAILABLE: circuit breaker open" {
		t.Fatalf("reason = %s, want SERVICE_UNAVAILABLE: circuit breaker open", res.Findings[0].LLMReason)
	}
}

// ── OllamaClient adapter tests with httptest ─────────────

func TestOllamaClientSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/verify" {
			json.NewEncoder(w).Encode(inference.ResponseEnvelope{
				ProtocolVersion: inference.CurrentProtocolVersion,
				Status:          inference.StatusSuccess,
				Decision: &inference.DecisionResult{
					Verdict:     inference.VerdictBenign,
					Explanation: "safe code",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "test-model", 5*time.Second)
	if client == nil {
		t.Fatal("client should not be nil")
	}
	defer client.Close()

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-1",
		Timestamp:       time.Now().Unix(),
		Action:          inference.ActionVerifyFinding,
	}
	resp, err := client.VerifyFinding(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision == nil || resp.Decision.Verdict != inference.VerdictBenign {
		t.Fatalf("verdict = %v, want BENIGN", resp.Decision)
	}
}

func TestOllamaClientServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "test-model", 1*time.Second)
	if client == nil {
		t.Fatal("client should not be nil")
	}
	defer client.Close()

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-1",
		Timestamp:       time.Now().Unix(),
		Action:          inference.ActionVerifyFinding,
	}
	_, err := client.VerifyFinding(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

// ── CheckImportWithLLM end-to-end ────────────────────────

func TestCheckImportWithLLMDisabled(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "clean.py", "import torch\nmodel = torch.nn.Linear(10, 2)\n")

	cfg := LLMConfig{Enabled: false}
	passed, report, err := CheckImportWithLLM(context.Background(), dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !passed {
		t.Fatal("clean code should pass")
	}
	if report == nil {
		t.Fatal("report should not be nil")
	}
}

func TestCheckImportWithLLMEmptyDir(t *testing.T) {
	passed, report, err := CheckImportWithLLM(context.Background(), "", LLMConfig{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !passed {
		t.Fatal("empty dir should pass")
	}
	if report != nil {
		t.Fatal("report should be nil for empty dir")
	}
}

func TestCheckImportWithLLMGateDowngrade(t *testing.T) {
	// Create a file that triggers NET_001 (HIGH)
	dir := t.TempDir()
	writeTestFile(t, dir, "metrics.py", `
import requests

def report_metrics(acc, loss):
    url = "http://monitoring.local/api/metrics"
    requests.post(url, json={"acc": acc, "loss": loss})
`)

	// Mock server that returns BENIGN
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/verify" {
			json.NewEncoder(w).Encode(inference.ResponseEnvelope{
				ProtocolVersion: inference.CurrentProtocolVersion,
				Status:          inference.StatusSuccess,
				Decision: &inference.DecisionResult{
					Verdict:     inference.VerdictBenign,
					Explanation: "metrics reporting only",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := LLMConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		Model:       "test-model",
		Timeout:     5 * time.Second,
		MaxFindings: 10,
		Policy:      "gate",
		FailClosed:  true,
	}

	passed, report, err := CheckImportWithLLM(context.Background(), dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !passed {
		t.Fatalf("gate policy with BENIGN verdict should pass, report: %+v", report)
	}
	if len(report.Findings) == 0 {
		t.Fatal("should have at least one finding")
	}
	if report.Findings[0].LLMVerdict != "BENIGN" {
		t.Fatalf("finding verdict = %s, want BENIGN", report.Findings[0].LLMVerdict)
	}
}

func TestSummarizeLLMVerdicts(t *testing.T) {
	report := &Report{
		Findings: []Finding{
			{LLMVerdict: "BENIGN"},
			{LLMVerdict: "BENIGN"},
			{LLMVerdict: "MALICIOUS"},
			{LLMVerdict: ""}, // not analyzed
		},
	}
	summary := SummarizeLLMVerdicts(report)
	if summary == "" {
		t.Fatal("summary should not be empty")
	}
	if !containsStr(summary, "BENIGN=2") || !containsStr(summary, "MALICIOUS=1") {
		t.Fatalf("summary = %q, want BENIGN=2 and MALICIOUS=1", summary)
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ── parseFileSummary tests ────────────────────────────────

func TestParseFileSummaryValidJSON(t *testing.T) {
	raw := `Analysis result:
{"risk_level": "HIGH", "summary": "exfiltration risk", "chained": true, "exfiltration": true}
End.`
	s := parseFileSummary(raw)
	if s.RiskLevel != "HIGH" {
		t.Fatalf("risk_level = %s, want HIGH", s.RiskLevel)
	}
	if !s.Chained {
		t.Fatal("chained should be true")
	}
	if !s.Exfiltration {
		t.Fatal("exfiltration should be true")
	}
}

func TestParseFileSummaryInvalidJSON(t *testing.T) {
	s := parseFileSummary("I cannot determine the risk level.")
	if s.RiskLevel != "UNCERTAIN" {
		t.Fatalf("risk_level = %s, want UNCERTAIN", s.RiskLevel)
	}
}

func TestParseFileSummaryInvalidRiskLevel(t *testing.T) {
	raw := `{"risk_level": "EXTREME", "summary": "test", "chained": false, "exfiltration": false}`
	s := parseFileSummary(raw)
	if s.RiskLevel != "UNCERTAIN" {
		t.Fatalf("risk_level = %s, want UNCERTAIN for invalid value", s.RiskLevel)
	}
}
