package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"taa/attestation/csv_go"
)

var errFakeVerify = errors.New("fake verify failed")

type fakeCSV struct {
	reportErr error
	verifyErr error
	keyErr    error
}

func (f fakeCSV) GetAttestationReportIOCTL(reportBuf, nonce []byte) error {
	if f.reportErr != nil {
		return f.reportErr
	}
	copy(reportBuf, bytes.Repeat([]byte{0x5a}, csvgo.ReportSize))
	clear(reportBuf[csvgo.OffsetReserved2 : csvgo.OffsetReserved2+csvgo.SealingKeySize])
	return nil
}

func (f fakeCSV) VerifyAttestationReport(reportBuf []byte, verifyChain bool) error {
	return f.verifyErr
}

func (f fakeCSV) GetSealingKeyIOCTL(keyBuf []byte) error {
	if f.keyErr != nil {
		return f.keyErr
	}
	copy(keyBuf, bytes.Repeat([]byte{0x7b}, csvgo.SealingKeySize))
	return nil
}

func TestRunSmokeWritesSuccessfulResult(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "smoke.json")
	result, err := runSmoke(context.Background(), smokeConfig{
		OutputPath: outPath,
		DevicePath: "/tmp/csv-guest",
		Rand:       bytes.NewReader(bytes.Repeat([]byte{0x11}, csvgo.NonceSize)),
		CSV:        fakeCSV{},
	})
	if err != nil {
		t.Fatalf("runSmoke() error = %v", err)
	}
	if result.Status != "pass" {
		t.Fatalf("result.Status = %q, want pass", result.Status)
	}
	if result.ReportSize != csvgo.ReportSize {
		t.Fatalf("result.ReportSize = %d, want %d", result.ReportSize, csvgo.ReportSize)
	}
	if result.SealingKeySize != csvgo.SealingKeySize {
		t.Fatalf("result.SealingKeySize = %d, want %d", result.SealingKeySize, csvgo.SealingKeySize)
	}
	assertStep(t, result, "get_attestation_report_ioctl", "pass")
	assertStep(t, result, "verify_attestation_report", "pass")
	assertStep(t, result, "get_sealing_key_ioctl", "pass")

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read result file: %v", err)
	}
	var fromFile smokeResult
	if err := json.Unmarshal(data, &fromFile); err != nil {
		t.Fatalf("unmarshal result file: %v", err)
	}
	if fromFile.Status != "pass" || fromFile.NonceHex != "11111111111111111111111111111111" {
		t.Fatalf("unexpected result file: %+v", fromFile)
	}
}

func TestRunSmokeWritesFailureResult(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "smoke.json")
	result, err := runSmoke(context.Background(), smokeConfig{
		OutputPath: outPath,
		Rand:       bytes.NewReader(bytes.Repeat([]byte{0x11}, csvgo.NonceSize)),
		CSV:        fakeCSV{verifyErr: errFakeVerify},
	})
	if err == nil {
		t.Fatalf("runSmoke() error = nil, want non-nil")
	}
	if result.Status != "fail" {
		t.Fatalf("result.Status = %q, want fail", result.Status)
	}
	assertStep(t, result, "get_attestation_report_ioctl", "pass")
	assertStep(t, result, "verify_attestation_report", "fail")

	data, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("read result file: %v", readErr)
	}
	if !bytes.Contains(data, []byte(errFakeVerify.Error())) {
		t.Fatalf("result file does not include verify error: %s", data)
	}
}

func assertStep(t *testing.T, result *smokeResult, name, status string) {
	t.Helper()
	for _, step := range result.Steps {
		if step.Name == name {
			if step.Status != status {
				t.Fatalf("step %s status = %q, want %q", name, step.Status, status)
			}
			return
		}
	}
	t.Fatalf("step %s not found in %+v", name, result.Steps)
}
