package codeaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CipherSlinger/teellm"
	"github.com/CipherSlinger/teetls"
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
	// filePrompts records the text of every file-level prompt, so a test can
	// assert what the model was shown rather than only what it answered.
	filePrompts []string
}

func (m *mockLLMClient) VerifyFinding(_ context.Context, _ *teellm.RequestEnvelope) (*teellm.ResponseEnvelope, error) {
	if m.callCount >= len(m.decisions) {
		return &teellm.ResponseEnvelope{
			ProtocolVersion: teellm.CurrentProtocolVersion,
			Status:          teellm.StatusSuccess,
			Decision: &teellm.DecisionResult{
				Verdict:     "UNCERTAIN",
				Explanation: "no more mock decisions",
			},
		}, nil
	}
	d := m.decisions[m.callCount]
	m.callCount++
	return &teellm.ResponseEnvelope{
		ProtocolVersion: teellm.CurrentProtocolVersion,
		Status:          teellm.StatusSuccess,
		Decision: &teellm.DecisionResult{
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

func (m *mockLLMClient) AnalyzeFile(_ context.Context, prompt string) (FileSummary, error) {
	m.filePrompts = append(m.filePrompts, prompt)
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

func (m *mockInferenceClient) VerifyFinding(ctx context.Context, req *teellm.RequestEnvelope) (*teellm.ResponseEnvelope, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &teellm.ResponseEnvelope{
		ProtocolVersion: teellm.CurrentProtocolVersion,
		Status:          teellm.StatusSuccess,
		Decision: &teellm.DecisionResult{
			Verdict:     m.verdict,
			Confidence:  0.9,
			RiskLevel:   "HIGH",
			Explanation: "mock explanation",
		},
	}, nil
}

func (m *mockInferenceClient) HealthCheck(ctx context.Context) error { return m.err }
func (m *mockInferenceClient) Close() error                          { return nil }

// ── VerifyReport tests ───────────────────────────────────

func TestVerifyReportAssistPolicy(t *testing.T) {
	// ScanComplete models the engine having stamped a completed scan. The
	// completeness fields are not optional detail: VerifyReport's recalculation
	// withholds a pass from a report that cannot prove it looked, and the
	// field's zero value means "did not complete", so a bare literal would
	// decide every one of these fixtures as blocked.
	report := &Report{
		ScanComplete: true,
		HighCount:    2,
		MediumCount:  0,
		Passed:       false,
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
		ScanComplete: true,
		HighCount:    2,
		MediumCount:  0,
		Passed:       false,
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
		ScanComplete: true,
		HighCount:    1,
		MediumCount:  0,
		Passed:       false,
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
	report := &Report{ScanComplete: true, Passed: false, HighCount: 1, Findings: []Finding{{Severity: SeverityHigh}}}
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
	// A cap of 0 (or anything negative) means "no cap": VerifyReport turns a
	// non-positive limit into len(report.Findings). That is what makes removing
	// the production cap a one-value change rather than a signature change, so
	// the boundary is pinned here rather than left to the reader of verifier.go.
	cases := []struct {
		name        string
		maxFindings int
		wantCalls   int
	}{
		{"explicit cap still applies", 3, 3},
		{"zero verifies every finding", 0, 10},
		{"negative verifies every finding", -1, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := make([]Finding, 10)
			for i := range findings {
				findings[i] = Finding{File: "x.py", Line: i + 1, Severity: SeverityHigh}
			}
			report := &Report{ScanComplete: true, HighCount: 10, Passed: false, Findings: findings}

			mock := &mockLLMClient{decisions: make([]LLMDecision, 10)}
			for i := range mock.decisions {
				mock.decisions[i] = LLMDecision{Verdict: "BENIGN", Reason: "ok"}
			}

			cfg := LLMConfig{Enabled: true, Policy: "gate", MaxFindings: tc.maxFindings}
			if _, err := VerifyReport(context.Background(), report, cfg, mock); err != nil {
				t.Fatal(err)
			}

			if mock.callCount != tc.wantCalls {
				t.Fatalf("MaxFindings=%d: got %d LLM calls, want %d", tc.maxFindings, mock.callCount, tc.wantCalls)
			}
			// An uncapped run must leave real verdicts on the tail. A capped run
			// leaves the empty string there, which is exactly the state the old
			// production value of 20 produced for findings 21 and beyond.
			if tc.wantCalls == len(findings) {
				for i, f := range report.Findings {
					if f.LLMVerdict == "" {
						t.Errorf("finding %d left unverified: LLMVerdict is empty", i)
					}
				}
			}
		})
	}
}

// ── Standardized Inference Client Tests ───────────────────

func TestVerifyReport_InferenceClient_Malicious(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		HighCount:    1,
		Passed:       false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
		},
	}
	client := &mockInferenceClient{verdict: teellm.VerdictMalicious}
	cfg := LLMConfig{Enabled: true, Policy: "gate", MaxFindings: 10}

	res, err := VerifyReport(context.Background(), report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Passed {
		t.Fatal("expected report to not pass when verdict is MALICIOUS in gate mode")
	}
	if res.Findings[0].LLMVerdict != teellm.VerdictMalicious {
		t.Fatalf("verdict = %s, want %s", res.Findings[0].LLMVerdict, teellm.VerdictMalicious)
	}
}

func TestVerifyReport_InferenceClient_BenignDowngrade(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		HighCount:    1,
		Passed:       false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
		},
	}
	client := &mockInferenceClient{verdict: teellm.VerdictBenign}
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
	if res.Findings[0].LLMVerdict != teellm.VerdictBenign {
		t.Fatalf("verdict = %s, want %s", res.Findings[0].LLMVerdict, teellm.VerdictBenign)
	}
}

func TestVerifyReport_InferenceClient_CircuitOpen_GateFailClosed(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		HighCount:    1,
		Passed:       false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
		},
	}
	client := &mockInferenceClient{err: teellm.ErrCircuitOpen}
	cfg := LLMConfig{Enabled: true, Policy: "gate", FailClosed: true, MaxFindings: 10}

	res, err := VerifyReport(context.Background(), report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.LLMDegraded {
		t.Fatal("expected LLMDegraded = true in gate mode on inference error")
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

func TestVerifyReport_InferenceClient_GateFailOpen(t *testing.T) {
	// Medium-only finding: static scan passes.
	report := &Report{
		ScanComplete: true,
		HighCount:    0,
		MediumCount:  1,
		Passed:       true,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "DYN_001", Severity: SeverityMedium, CodeSnippet: "eval(expr)"},
		},
	}
	client := &mockInferenceClient{err: teellm.ErrCircuitOpen}
	// FailClosed: false -> fallback to static scan result
	cfg := LLMConfig{Enabled: true, Policy: "gate", FailClosed: false, MaxFindings: 10}

	res, err := VerifyReport(context.Background(), report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.LLMDegraded {
		t.Fatal("expected LLMDegraded = true when inference fails in gate mode")
	}
	if !res.Passed {
		t.Fatal("expected report to pass (fallback to static scan) when FailClosed=false and only medium findings exist")
	}
	if res.Findings[0].LLMVerdict != "UNCERTAIN" {
		t.Fatalf("verdict = %s, want UNCERTAIN", res.Findings[0].LLMVerdict)
	}
}

func TestSynthesizeFileSummary_BenignExfilIgnored(t *testing.T) {
	findings := []Finding{
		{
			File:        "exfil.py",
			Line:        10,
			RuleID:      "EXF_001",
			Category:    "数据外传风险",
			Severity:    SeverityHigh,
			LLMVerdict:  "BENIGN",
			CodeSnippet: "requests.post(metric_server, data=acc)",
		},
	}

	summary := synthesizeFileSummary("exfil.py", findings)
	if summary.Exfiltration {
		t.Fatal("expected Exfiltration = false when finding is BENIGN")
	}
	if summary.RiskLevel != "LOW" {
		t.Fatalf("expected RiskLevel = LOW, got %s", summary.RiskLevel)
	}
	if summary.Chained {
		t.Fatal("expected Chained = false when finding is BENIGN")
	}
}

type mockNilDecisionClient struct{}

func (m *mockNilDecisionClient) VerifyFinding(_ context.Context, _ *teellm.RequestEnvelope) (*teellm.ResponseEnvelope, error) {
	return &teellm.ResponseEnvelope{
		ProtocolVersion: teellm.CurrentProtocolVersion,
		Status:          teellm.StatusSuccess,
		Decision:        nil,
	}, nil
}
func (m *mockNilDecisionClient) HealthCheck(_ context.Context) error { return nil }
func (m *mockNilDecisionClient) Close() error                        { return nil }

func TestVerifyReport_NilDecisionTreatedAsFailure(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		HighCount:    1,
		Passed:       false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
		},
	}
	client := &mockNilDecisionClient{}
	cfg := LLMConfig{Enabled: true, Policy: "gate", FailClosed: true, MaxFindings: 10}

	res, err := VerifyReport(context.Background(), report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.LLMDegraded {
		t.Fatal("expected LLMDegraded = true on nil decision")
	}
	if res.Passed {
		t.Fatal("expected report to fail closed on nil decision")
	}
	if res.Findings[0].LLMVerdict != "UNCERTAIN" {
		t.Fatalf("verdict = %s, want UNCERTAIN", res.Findings[0].LLMVerdict)
	}
	if res.Findings[0].LLMReason != "SERVICE_UNAVAILABLE: empty decision payload" {
		t.Fatalf("reason = %s, want SERVICE_UNAVAILABLE: empty decision payload", res.Findings[0].LLMReason)
	}
}

type mockCaptureEnvelopeClient struct {
	capturedReq *teellm.RequestEnvelope
}

func (m *mockCaptureEnvelopeClient) VerifyFinding(_ context.Context, req *teellm.RequestEnvelope) (*teellm.ResponseEnvelope, error) {
	m.capturedReq = req
	return &teellm.ResponseEnvelope{
		ProtocolVersion: teellm.CurrentProtocolVersion,
		Status:          teellm.StatusSuccess,
		Decision: &teellm.DecisionResult{
			Verdict: teellm.VerdictBenign,
		},
	}, nil
}
func (m *mockCaptureEnvelopeClient) HealthCheck(_ context.Context) error { return nil }
func (m *mockCaptureEnvelopeClient) Close() error                        { return nil }

func TestVerifyReport_ModelRefPopulated(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		HighCount:    1,
		Passed:       false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
		},
	}
	client := &mockCaptureEnvelopeClient{}
	cfg := LLMConfig{Enabled: true, Policy: "gate", Model: "qwen2.5-coder:0.5b", MaxFindings: 10}

	_, err := VerifyReport(context.Background(), report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.capturedReq == nil || client.capturedReq.ModelRef == nil {
		t.Fatal("expected ModelRef to be populated")
	}
	if client.capturedReq.ModelRef.Name != "qwen2.5-coder:0.5b" {
		t.Fatalf("ModelRef.Name = %s, want qwen2.5-coder:0.5b", client.capturedReq.ModelRef.Name)
	}
}

// TestVerifyReport_PolicyTemperature pins the wire form of the sampling
// temperature, in both states.
//
// The unset case is the default deployment and the load-bearing one: nil must
// stay nil so the field is omitted from the request body entirely, leaving the
// inference service on its own deterministic default. If this ever started
// sending an explicit value, the default would become two places that have to
// agree instead of one.
func TestVerifyReport_PolicyTemperature(t *testing.T) {
	temp := func(v float32) *float32 { return &v }

	for _, tc := range []struct {
		name  string
		given *float32
	}{
		{"unset leaves the policy temperature nil", nil},
		{"explicit zero is carried, not dropped", temp(0)},
		{"non-zero is carried", temp(0.3)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := &Report{
				ScanComplete: true,
				HighCount:    1,
				Findings: []Finding{
					{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
				},
			}
			client := &mockCaptureEnvelopeClient{}
			cfg := LLMConfig{Enabled: true, Policy: "assist", MaxFindings: 10, Temperature: tc.given}

			if _, err := VerifyReport(context.Background(), report, cfg, client); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client.capturedReq == nil {
				t.Fatal("expected the request to be captured")
			}

			got := client.capturedReq.Policy.Temperature
			switch {
			case tc.given == nil && got != nil:
				t.Fatalf("Policy.Temperature = %v, want nil", *got)
			case tc.given != nil && got == nil:
				t.Fatalf("Policy.Temperature = nil, want %v", *tc.given)
			case tc.given != nil && *got != *tc.given:
				t.Fatalf("Policy.Temperature = %v, want %v", *got, *tc.given)
			}
		})
	}
}

func TestVerifyReport_ContextCancelled(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		HighCount:    2,
		Passed:       false,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post(url)"},
			{File: "b.py", Line: 2, RuleID: "CMD_001", Severity: SeverityHigh, CodeSnippet: "os.system(cmd)"},
		},
	}
	client := &mockInferenceClient{verdict: teellm.VerdictBenign}
	cfg := LLMConfig{Enabled: true, Policy: "gate", FailClosed: true, MaxFindings: 10}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := VerifyReport(ctx, report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.LLMDegraded {
		t.Fatal("expected LLMDegraded = true when context is canceled")
	}
	for i, f := range res.Findings {
		if f.LLMVerdict != "UNCERTAIN" {
			t.Fatalf("finding[%d].LLMVerdict = %s, want UNCERTAIN", i, f.LLMVerdict)
		}
		if !containsStr(f.LLMReason, "context canceled") {
			t.Fatalf("finding[%d].LLMReason = %s, want context canceled", i, f.LLMReason)
		}
	}
}

func TestVerifyReport_InferenceClient_CircuitOpen_AssistDegraded(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		HighCount:    0,
		MediumCount:  1,
		Passed:       true,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "DYN_001", Severity: SeverityMedium, CodeSnippet: "eval(expr)"},
		},
	}
	client := &mockInferenceClient{err: teellm.ErrCircuitOpen}
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

func TestVerifyReport_InferenceClient_CircuitOpen_AssistFailClosed(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		HighCount:    0,
		MediumCount:  1,
		Passed:       true,
		Findings: []Finding{
			{File: "a.py", Line: 1, RuleID: "DYN_001", Severity: SeverityMedium, CodeSnippet: "eval(expr)"},
		},
	}
	client := &mockInferenceClient{err: teellm.ErrCircuitOpen}
	cfg := LLMConfig{Enabled: true, Policy: "assist", FailClosed: true, MaxFindings: 10}

	res, err := VerifyReport(context.Background(), report, cfg, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.LLMDegraded {
		t.Fatal("expected LLMDegraded = true in assist mode on inference error")
	}
	if res.Passed {
		t.Fatal("expected Passed = false when FailClosed=true in assist mode and inference fails")
	}
	if res.Findings[0].LLMVerdict != "UNCERTAIN" {
		t.Fatalf("verdict = %s, want UNCERTAIN", res.Findings[0].LLMVerdict)
	}
}

func newTestTEETLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	mockProv := teetls.NewMockEvidenceProvider()
	listener, err := teetls.Listen("tcp", "127.0.0.1:0", &teetls.Config{
		Mode:             teetls.ModeStrict,
		EvidenceProvider: mockProv,
	})
	if err != nil {
		t.Fatalf("failed to create teetls listener: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	server.URL = "https://" + server.Listener.Addr().String()
	return server
}

// ── OllamaClient adapter tests with httptest ─────────────

func TestOllamaClientSuccess(t *testing.T) {
	server := newTestTEETLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/verify" {
			json.NewEncoder(w).Encode(teellm.ResponseEnvelope{
				ProtocolVersion: teellm.CurrentProtocolVersion,
				Status:          teellm.StatusSuccess,
				Decision: &teellm.DecisionResult{
					Verdict:     teellm.VerdictBenign,
					Explanation: "safe code",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewInferenceClient(LLMConfig{Endpoint: server.URL, Model: "test-model", Timeout: 5 * time.Second, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("NewInferenceClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
	defer client.Close()

	req := &teellm.RequestEnvelope{
		ProtocolVersion: teellm.CurrentProtocolVersion,
		RequestID:       "req-1",
		Timestamp:       time.Now().Unix(),
		Action:          teellm.ActionVerifyFinding,
	}
	resp, err := client.VerifyFinding(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision == nil || resp.Decision.Verdict != teellm.VerdictBenign {
		t.Fatalf("verdict = %v, want BENIGN", resp.Decision)
	}
}

func TestOllamaClientServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "test-model", 1*time.Second)
	if client == nil {
		t.Fatal("client should not be nil")
	}
	defer client.Close()

	req := &teellm.RequestEnvelope{
		ProtocolVersion: teellm.CurrentProtocolVersion,
		RequestID:       "req-1",
		Timestamp:       time.Now().Unix(),
		Action:          teellm.ActionVerifyFinding,
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
	passed, report, err := CheckImportWithLLM(context.Background(), dir, DefaultEngine(), cfg)
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
	passed, report, err := CheckImportWithLLM(context.Background(), "", DefaultEngine(), LLMConfig{Enabled: true})
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
	server := newTestTEETLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/verify" {
			json.NewEncoder(w).Encode(teellm.ResponseEnvelope{
				ProtocolVersion: teellm.CurrentProtocolVersion,
				Status:          teellm.StatusSuccess,
				Decision: &teellm.DecisionResult{
					Verdict:     teellm.VerdictBenign,
					Explanation: "metrics reporting only",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := LLMConfig{
		Enabled:            true,
		Endpoint:           server.URL,
		Model:              "test-model",
		Timeout:            5 * time.Second,
		MaxFindings:        10,
		Policy:             "gate",
		FailClosed:         true,
		InsecureSkipVerify: true,
	}

	passed, report, err := CheckImportWithLLM(context.Background(), dir, DefaultEngine(), cfg)
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
		ScanComplete: true,
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

// TestBinaryFilePromptCarriesEvidenceAndNotRawBytes pins what the model is shown
// for a binary file.
//
// The source prompt cannot be reused: it opens by telling the model it is looking
// at a Python source file and wraps the content in a python fence. Handing it
// extracted evidence under that framing asks the model to judge one thing while
// telling it another, and the answer is uninterpretable either way. The binary
// prompt therefore states what the lines are, and the test pins that the state-
// ment, the evidence, and the absence of the source framing all survive.
func TestBinaryFilePromptCarriesEvidenceAndNotRawBytes(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"socket", "connect"},
		needed:  []string{"libcurl.so.4"},
	}))

	mock := &mockLLMClient{fileSummaries: []FileSummary{{RiskLevel: "HIGH", Summary: "外联"}}}
	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: true, Policy: "assist", Model: "test"},
		Binary: DefaultBinaryConfig(),
	}
	if _, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, mock); err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}

	if len(mock.filePrompts) != 1 {
		t.Fatalf("file prompts = %d, want 1", len(mock.filePrompts))
	}
	prompt := mock.filePrompts[0]
	for _, want := range []string{"libevil.so", "[dynsym] connect", "[needed] libcurl.so.4"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("binary prompt is missing %q; prompt was:\n%s", want, prompt)
		}
	}
	// Pin a rendered listing line rather than a heading word: "证据" alone is
	// satisfied by "## 证据说明", which says nothing about what the model was
	// shown. A listing line carries the index and its source tag, so this asserts
	// the shape the model actually reads.
	if !regexp.MustCompile(`(?m)^\d+\t\[dynsym\] connect$`).MatchString(prompt) {
		t.Errorf("binary prompt has no rendered dynsym line for connect; prompt was:\n%s", prompt)
	}
	if strings.Contains(prompt, "```python") {
		t.Errorf("binary prompt reuses the Python fence; the model is told the wrong thing about its input:\n%s", prompt)
	}
	// The name claims raw bytes are not carried, so assert it: the ELF header magic
	// is the file's first four bytes, and a prompt that had dumped the file instead
	// of its extracted evidence would carry them.
	if strings.Contains(prompt, "\x7fELF") {
		t.Errorf("binary prompt carries the file's raw header bytes; the model was given the file rather than its evidence:\n%s", prompt)
	}
}

// TestSourceFilePromptIsUnchangedByTheBinaryChannel pins that adding the binary
// channel did not change what the source channel asks: a source file still
// reaches the model through the source prompt, Python fence and all. That is the
// whole of the claim. The non-inferiority measurement (see corpus_parity_test.go)
// compares the two static engines' findings, not the file-level prompt, so it
// neither rests on the source prompt being unchanged nor would be moved by a
// change here.
func TestSourceFilePromptIsUnchangedByTheBinaryChannel(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\nos.system(cmd)\n")

	mock := &mockLLMClient{fileSummaries: []FileSummary{{RiskLevel: "HIGH", Summary: "x"}}}
	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: true, Policy: "assist", Model: "test"},
		Binary: DefaultBinaryConfig(),
	}
	if _, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, mock); err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if len(mock.filePrompts) != 1 {
		t.Fatalf("file prompts = %d, want 1", len(mock.filePrompts))
	}
	if !strings.Contains(mock.filePrompts[0], "```python") {
		t.Errorf("the source prompt lost its Python fence:\n%s", mock.filePrompts[0])
	}
}

// TestBinaryFilePromptExcerptKeepsStructuralEvidenceUnderSymbolFlood pins the
// contract of RenderExcerpt: a symbol-dense file must still reach the model with
// its structural evidence.
//
// Finalize sorts by (Offset, Source, Text), and every structured line carries
// offset 0, so within offset 0 the sort falls through to the source name and
// dynsym leads. A plain prefix of that listing - which is what Render takes -
// therefore fills with dynsym lines on a file with many imports and shows the
// model none of the section, entropy or DT_NEEDED evidence its rubric needs. The
// fixture carries more imports than the prompt's budget so that a prefix would
// be dynsym and nothing else; the test asserts the structural lines survive.
func TestBinaryFilePromptExcerptKeepsStructuralEvidenceUnderSymbolFlood(t *testing.T) {
	dir := t.TempDir()

	// The import list is sized from binaryFilePromptMaxLines rather than a
	// literal, so the fixture keeps exceeding the budget if that constant changes
	// and the test cannot silently stop exercising the flood it describes. The
	// first import fires a rule, which is what makes the file eligible for
	// file-level analysis at all; the rest are filler that would fill a prefix.
	imports := make([]string, 0, binaryFilePromptMaxLines+10)
	imports = append(imports, "system")
	for i := 0; i < binaryFilePromptMaxLines+9; i++ {
		imports = append(imports, fmt.Sprintf("sym_%04d", i))
	}
	writeTestBytes(t, dir, "libflood.so", elfFixtureBytes(t, elfSpec{
		imports:  imports,
		needed:   []string{"libc.so.6"},
		text:     uniformBytes(512),
		textExec: true,
	}))

	mock := &mockLLMClient{fileSummaries: []FileSummary{{RiskLevel: "LOW", Summary: "x"}}}
	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: true, Policy: "assist", Model: "test"},
		Binary: DefaultBinaryConfig(),
	}
	if _, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, mock); err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if len(mock.filePrompts) != 1 {
		t.Fatalf("file prompts = %d, want 1", len(mock.filePrompts))
	}
	prompt := mock.filePrompts[0]

	// Assert on the rendered line shape, not on a heading: each listing line is
	// "序号\t[来源] 内容".
	matches := func(re string) bool {
		return regexp.MustCompile(re).MatchString(prompt)
	}
	if !matches(`(?m)^\d+\t\[dynsym\] `) {
		t.Fatalf("fixture produced no dynsym line; the test is not exercising the flood it describes:\n%s", prompt)
	}
	if !matches(`(?m)^\d+\t\[entropy\] `) {
		t.Errorf("a symbol-dense file reached the model without its entropy verdict:\n%s", prompt)
	}
	if !matches(`(?m)^\d+\t\[needed\] libc\.so\.6$`) {
		t.Errorf("a symbol-dense file reached the model without its DT_NEEDED evidence:\n%s", prompt)
	}

	// The excerpt is bounded: the listing lines it carries do not exceed the cap,
	// and because the listing is longer than the cap the omission marker is shown
	// so the model knows the listing is partial.
	listingLines := regexp.MustCompile(`(?m)^\d+\t\[`).FindAllString(prompt, -1)
	if n := len(listingLines); n > binaryFilePromptMaxLines {
		t.Errorf("excerpt carries %d listing lines, over the %d cap:\n%s", n, binaryFilePromptMaxLines, prompt)
	}
	if !matches(`\.\.\. \(\d+ more evidence line\(s\) not shown\)`) {
		t.Errorf("excerpt of an over-budget listing has no omission marker:\n%s", prompt)
	}
}
