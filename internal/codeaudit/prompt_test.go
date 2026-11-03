package codeaudit

import (
	"strings"
	"testing"
)

func TestBuildFindingPromptCarriesEveryField(t *testing.T) {
	f := Finding{
		RuleID:        "EMB_003",
		Category:      "exfiltration",
		Severity:      SeverityHigh,
		Description:   "documented rule text",
		File:          "train.py",
		Line:          42,
		CodeSnippet:   "print(dataset)",
		ContextBefore: "before line",
		ContextAfter:  "after line",
	}
	got := BuildFindingPrompt(f, f.ContextAfter)

	for _, want := range []string{
		"train.py", "第 42 行", "before line", "print(dataset)", "after line",
		"EMB_003", "exfiltration", SeverityHigh, "documented rule text",
		"良性判定规则优先", "请严格按以下 JSON 格式回答",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt is missing %q", want)
		}
	}
}

func TestBuildFindingPromptUsesProvidedContextAfter(t *testing.T) {
	f := Finding{File: "a.py", Line: 1, CodeSnippet: "x", ContextBefore: "b", ContextAfter: "original"}
	got := BuildFindingPrompt(f, "cp3 evidence")
	if !strings.Contains(got, "cp3 evidence") || strings.Contains(got, "original") {
		t.Fatalf("prompt must use the provided contextAfter:\n%s", got)
	}
}
