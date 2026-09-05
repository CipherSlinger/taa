package attestation

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenerateCreatesAttestationReport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell helper test requires a Unix-like shell")
	}

	tmpDir := t.TempDir()
	helper := filepath.Join(tmpDir, "fake-helper.sh")
	script := "#!/bin/sh\nset -eu\nprintf 'report-body' > report.cert\nprintf 'nonce-body' > nonce.bin\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "nested", "attestation.report")
	if err := Generate(context.Background(), Config{OutputPath: outputPath, HelperPath: helper, WorkingDir: filepath.Dir(outputPath)}); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output report: %v", err)
	}
	if string(data) != "report-body" {
		t.Fatalf("output report = %q", string(data))
	}
}

func TestGenerateMissingHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell helper test requires a Unix-like shell")
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.cert")
	err := Generate(context.Background(), Config{OutputPath: outputPath, HelperPath: filepath.Join(tmpDir, "missing-helper")})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error = %v, want not found", err)
	}
}

func TestGetAttestationUsesEnvUserData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("helper binary test requires a Unix-like shell")
	}

	helperRel := filepath.Clean(filepath.Join("..", "..", "attestation", "get-attestation"))
	helper, err := filepath.Abs(helperRel)
	if err != nil {
		t.Fatalf("resolve helper path: %v", err)
	}
	if _, err := os.Stat(helper); err != nil {
		t.Skipf("helper binary not available: %v", err)
	}

	expected := []byte("userdata-from-env")
	userdata := make([]byte, 64)
	copy(userdata, expected)

	cmd := exec.Command(helper)
	cmd.Dir = filepath.Dir(helper)
	cmd.Env = []string{"ATTESTATION_USERDATA=" + hex.EncodeToString(userdata)}
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected helper to fail in this environment, output:\n%s", output)
	}

	// The helper prints the hex dump via csv_data_dump("data", ...).
	// Verify the hex-encoded userdata appears in the output.
	want := hex.EncodeToString(userdata)
	if !strings.Contains(string(output), want) {
		t.Fatalf("helper output does not contain hex userdata %q:\n%s", want, output)
	}
}
