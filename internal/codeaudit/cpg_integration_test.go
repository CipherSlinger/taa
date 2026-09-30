package codeaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// crossServiceClient reads a credential and posts it to the sidecar.
const crossServiceClient = `import os

import requests


def send_telemetry():
    payload = os.environ["API_KEY"]
    requests.post("http://sidecar:8080/v1/telemetry", json=payload)
`

// crossServiceServer receives that payload and runs it.
const crossServiceServer = `import os

from flask import Flask, request

app = Flask(__name__)


@app.post("/v1/telemetry")
def telemetry():
    data = request.get_json()
    os.system(data)
`

// writeCrossServiceSample lays out the two-service sample and returns its root
// and the file list a scan would walk.
func writeCrossServiceSample(t *testing.T) (string, []string) {
	t.Helper()

	root := t.TempDir()
	clientDir := filepath.Join(root, "service_a")
	serverDir := filepath.Join(root, "service_b")
	for _, dir := range []string{clientDir, serverDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	client := filepath.Join(clientDir, "client.py")
	server := filepath.Join(serverDir, "server.py")
	if err := os.WriteFile(client, []byte(crossServiceClient), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(server, []byte(crossServiceServer), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, []string{client, server}
}

// crossServiceClientLine is the line of the requests.post call, which is the
// finding a Tier 1 engine reports for the client half of the flow.
func crossServiceClientLine() int {
	for i, line := range strings.Split(crossServiceClient, "\n") {
		if strings.Contains(line, "requests.post") {
			return i + 1
		}
	}
	return 0
}

// TestCPGIntegration_SynthesizesCrossServiceFinding is the end-to-end property:
// a credential read in one service and executed in another is reported as one
// system-level finding. Neither Tier 1 engine can produce it, because in each
// file the code is unremarkable.
func TestCPGIntegration_SynthesizesCrossServiceFinding(t *testing.T) {
	root, targets := writeCrossServiceSample(t)

	// A finding on the client is what triggers the pass; the graph supplies the
	// rest.
	seed := []Finding{{
		File:   targets[0],
		Line:   crossServiceClientLine(),
		RuleID: "NET_001",
	}}

	got := enrichFindingsWithCPG(root, targets, seed)

	var synth *Finding
	for i := range got {
		if got[i].RuleID == CrossServiceRuleID {
			synth = &got[i]
			break
		}
	}
	if synth == nil {
		t.Fatalf("no %s finding was synthesized; findings: %+v", CrossServiceRuleID, got)
	}

	if synth.Engine != EngineNameCPG {
		t.Errorf("Engine = %q, want %q", synth.Engine, EngineNameCPG)
	}
	if !synth.IsCrossFile {
		t.Errorf("IsCrossFile must be set: the flow spans service_a and service_b")
	}
	if !synth.IsMicroservice {
		t.Errorf("IsMicroservice must be set: the flow crosses an HTTP boundary")
	}
	if synth.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want %q; the gate blocks on HIGH and a level of its own would block nothing",
			synth.Severity, SeverityHigh)
	}
	if !strings.Contains(synth.CPGEvidence, "[Deep Audit Inter-Procedural Taint Trajectory]") {
		t.Errorf("CPGEvidence is not a trajectory:\n%s", synth.CPGEvidence)
	}
	if len(synth.TaintTrace) < 3 {
		t.Errorf("TaintTrace has %d step(s), want the whole chain: %+v", len(synth.TaintTrace), synth.TaintTrace)
	}
	if synth.Line == 0 || synth.File == "" {
		t.Errorf("the synthesized finding must be anchored at its sink, got %s:%d", synth.File, synth.Line)
	}
}

// TestCPGIntegration_EnrichesTheFindingOnThePath checks the other half of the
// fusion: the Tier 1 finding the flow passes through carries the trajectory, so
// the LLM sees the whole chain rather than one end of it.
func TestCPGIntegration_EnrichesTheFindingOnThePath(t *testing.T) {
	root, targets := writeCrossServiceSample(t)
	seed := []Finding{{
		File:   targets[0],
		Line:   crossServiceClientLine(),
		RuleID: "NET_001",
	}}

	got := enrichFindingsWithCPG(root, targets, seed)

	if got[0].CPGEvidence == "" {
		t.Fatalf("the client finding carries no CPG evidence: %+v", got[0])
	}
	if len(got[0].TaintTrace) == 0 {
		t.Errorf("the client finding carries no structured trace")
	}
	if !got[0].IsMicroservice {
		t.Errorf("the client finding must be marked as crossing a service")
	}
}

// TestCPGIntegration_CleanScanBypassesTheGraph pins the fast path. A scan with
// nothing to explain must not parse anything: the graph is the expensive part,
// and most imports are clean.
func TestCPGIntegration_CleanScanBypassesTheGraph(t *testing.T) {
	root, targets := writeCrossServiceSample(t)

	got := enrichFindingsWithCPG(root, targets, nil)

	if len(got) != 0 {
		t.Fatalf("a scan with no findings produced %d finding(s)", len(got))
	}
}

// TestCPGIntegration_SingleFileFlowIsLeftAlone pins the boundary of the pass. A
// source and a sink in one function are already fully described by that
// function's own context; rewriting it would make the Tier 2 prompt depend on
// the engine, which is the one difference the arm comparison must be free of.
func TestCPGIntegration_SingleFileFlowIsLeftAlone(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "single.py")
	source := "import os\nimport subprocess\n\n\ndef run():\n    cmd = os.environ[\"CMD\"]\n    subprocess.run(cmd, shell=True)\n"
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}

	var line int
	for i, l := range strings.Split(source, "\n") {
		if strings.Contains(l, "subprocess.run") {
			line = i + 1
		}
	}

	seed := []Finding{{File: path, Line: line, RuleID: "CMD_001", ContextBefore: "physical"}}
	got := enrichFindingsWithCPG(root, []string{path}, seed)

	if len(got) != 1 {
		t.Fatalf("a single-file flow must not synthesize a finding, got %d finding(s): %+v", len(got), got)
	}
	if got[0].CPGEvidence != "" {
		t.Errorf("a single-file flow must not rewrite the finding's context:\n%s", got[0].CPGEvidence)
	}
	if got[0].ContextBefore != "physical" {
		t.Errorf("ContextBefore = %q, want it untouched", got[0].ContextBefore)
	}
}

// TestCPGIntegration_ThroughTheSemgrepEngine drives the whole pipeline: the
// engine's own findings are what trigger the pass, so the wiring inside scan is
// covered and not just the helper.
func TestCPGIntegration_ThroughTheSemgrepEngine(t *testing.T) {
	semgrepCLI(t)

	root, _ := writeCrossServiceSample(t)
	engine := NewSemgrepEngine(DefaultScanner(), repoSemgrepRules(t), SemgrepLimits{})

	report, err := engine.ScanDirectory(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var synth *Finding
	for i := range report.Findings {
		if report.Findings[i].RuleID == CrossServiceRuleID {
			synth = &report.Findings[i]
			break
		}
	}
	if synth == nil {
		t.Fatalf("the scan did not synthesize %s; findings: %+v", CrossServiceRuleID, report.Findings)
	}
	if synth.Engine != EngineNameCPG {
		t.Errorf("Engine = %q, want %q", synth.Engine, EngineNameCPG)
	}
	// A synthesized HIGH finding has to reach the gate, or the boundary-crossing
	// defect is detected and then passed anyway.
	if report.HighCount == 0 || report.Passed {
		t.Errorf("HighCount = %d, Passed = %v; a synthesized HIGH finding must block",
			report.HighCount, report.Passed)
	}
	if !report.ScanComplete {
		t.Errorf("ScanComplete = false on a report that returned")
	}
}
