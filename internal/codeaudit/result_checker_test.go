package codeaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResultCheckerDetectsPlaintextCSV(t *testing.T) {
	dir := t.TempDir()
	// Create a "result" file that contains CSV training data
	resultContent := []byte("some binary model data...\n" +
		"id,label,image\n" +
		"001,DN,img_001.jpg\n" +
		"002,NDRD,img_002.jpg\n" +
		"more binary data...")
	resultPath := filepath.Join(dir, "model_result.bin")
	if err := os.WriteFile(resultPath, resultContent, 0o644); err != nil {
		t.Fatal(err)
	}

	checker := DefaultResultChecker()
	report, err := checker.CheckFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected result check to FAIL for plaintext CSV in result")
	}
	assertResultHasCheck(t, report, "plaintext_section")
}

func TestResultCheckerDetectsSecrets(t *testing.T) {
	dir := t.TempDir()
	resultContent := []byte("model weights binary..." +
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----\n" +
		"more binary...")
	resultPath := filepath.Join(dir, "exported.bin")
	if err := os.WriteFile(resultPath, resultContent, 0o644); err != nil {
		t.Fatal(err)
	}

	checker := DefaultResultChecker()
	report, err := checker.CheckFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected result check to FAIL for embedded private key")
	}
	assertResultHasCheck(t, report, "plaintext_section")
}

func TestResultCheckerDetectsDataFingerprint(t *testing.T) {
	dir := t.TempDir()

	// Create a "data" directory with a training CSV
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create a CSV with enough content for a 64-byte fingerprint
	csvContent := strings.Repeat("id,label,image_path,patient_name,diagnosis\n", 5) +
		strings.Repeat("001,DN,/data/img/001.jpg,张三,糖尿病肾病\n", 10)
	if err := os.WriteFile(filepath.Join(dataDir, "training.csv"), []byte(csvContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a "result" file that contains the exact data file content
	resultContent := append([]byte("model_output_header..."), []byte(csvContent)...)
	resultContent = append(resultContent, []byte("...model_output_footer")...)
	resultPath := filepath.Join(dir, "result.bin")
	if err := os.WriteFile(resultPath, resultContent, 0o644); err != nil {
		t.Fatal(err)
	}

	checker := &ResultChecker{DataDir: dataDir, MaxResultBytes: 1024 * 1024}
	report, err := checker.CheckFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected result check to FAIL for data fingerprint match")
	}
	assertResultHasCheck(t, report, "data_fingerprint")
}

func TestResultCheckerDetectsSizeAnomaly(t *testing.T) {
	dir := t.TempDir()
	// Create a result file larger than the limit
	resultContent := make([]byte, 2048) // 2KB
	resultPath := filepath.Join(dir, "big_result.bin")
	if err := os.WriteFile(resultPath, resultContent, 0o644); err != nil {
		t.Fatal(err)
	}

	checker := &ResultChecker{MaxResultBytes: 1024} // limit = 1KB
	report, err := checker.CheckFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	// Size anomaly is MEDIUM, so it should still pass but with warnings
	if !report.Passed {
		t.Fatal("size anomaly alone should not cause failure (MEDIUM only)")
	}
	assertResultHasCheck(t, report, "size_anomaly")
}

func TestResultCheckerCleanResultPasses(t *testing.T) {
	dir := t.TempDir()
	// Create a clean binary result (model weights only)
	resultContent := []byte{
		0x80, 0x02, 0x00, 0x00, // some binary header
		0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFE, 0xFD, 0xFC,
	}
	resultContent = append(resultContent, make([]byte, 256)...) // pad with zeros
	resultPath := filepath.Join(dir, "model_weights.pth")
	if err := os.WriteFile(resultPath, resultContent, 0o644); err != nil {
		t.Fatal(err)
	}

	checker := DefaultResultChecker()
	report, err := checker.CheckFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("clean result should pass, got warnings: %+v", report.Warnings)
	}
	if len(report.Warnings) != 0 {
		t.Fatalf("expected 0 warnings, got %d", len(report.Warnings))
	}
}

func TestResultCheckerDirectory(t *testing.T) {
	dir := t.TempDir()
	// Clean file
	if err := os.WriteFile(filepath.Join(dir, "model.pth"), []byte{0x80, 0x02}, 0o644); err != nil {
		t.Fatal(err)
	}
	// Dirty file with CSV header
	if err := os.WriteFile(filepath.Join(dir, "data_leak.bin"),
		[]byte("binary...id,label,image\n...more"), 0o644); err != nil {
		t.Fatal(err)
	}

	checker := DefaultResultChecker()
	report, err := checker.CheckDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("directory with leaked data should fail")
	}
}

func TestResultCheckerNonExistentFile(t *testing.T) {
	checker := DefaultResultChecker()
	_, err := checker.CheckFile("/nonexistent/file.bin")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

// ── helpers ──────────────────────────────────────────────

func assertResultHasCheck(t *testing.T, report *ResultCheckReport, check string) {
	t.Helper()
	for _, w := range report.Warnings {
		if w.Check == check {
			return
		}
	}
	var checks []string
	for _, w := range report.Warnings {
		checks = append(checks, w.Check)
	}
	t.Fatalf("expected warning with check %q, got: %v", check, checks)
}
