package attestation

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"taa/pkg/csvattest"
)

// UserDataSize is the required size of the USERDATA field in the attestation report.
const UserDataSize = csvattest.UserDataSize

// NonceSize is the required size of the Nonce field in the attestation report.
const NonceSize = csvattest.NonceSize

// ReportSize is the expected size in bytes of the CSV attestation report.
const ReportSize = csvattest.ReportSize

// Config contains parameters for generating an attestation report.
type Config struct {
	OutputPath string
	DevicePath string
	UserData   []byte
	Nonce      []byte
}

type reportFetcherFunc func(ctx context.Context, devicePath string, userData, nonce []byte) ([]byte, error)

var defaultReportFetcher reportFetcherFunc = func(ctx context.Context, devicePath string, userData, nonce []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var opts []csvattest.Option
	if trimmed := strings.TrimSpace(devicePath); trimmed != "" {
		opts = append(opts, csvattest.WithDevicePath(trimmed))
	}
	if len(userData) > 0 {
		opts = append(opts, csvattest.WithUserData(userData))
	}

	client := csvattest.NewClient(opts...)
	reportBuf := make([]byte, csvattest.ReportSize)
	if err := client.GetAttestationReportIOCTL(reportBuf, nonce); err != nil {
		return nil, err
	}
	return reportBuf, nil
}

// SetReportFetcherForTest sets the report fetcher function used by Generate and returns a restore function.
func SetReportFetcherForTest(fn func(ctx context.Context, devicePath string, userData, nonce []byte) ([]byte, error)) func() {
	prev := defaultReportFetcher
	defaultReportFetcher = fn
	return func() {
		defaultReportFetcher = prev
	}
}

// Generate creates a CSV attestation report using pure Go and writes it to OutputPath.
func Generate(ctx context.Context, cfg Config) error {
	if ctx == nil {
		ctx = context.Background()
	}

	outputPathValue := strings.TrimSpace(cfg.OutputPath)
	if outputPathValue == "" {
		return fmt.Errorf("attestation output path is required")
	}
	outputPath, err := filepath.Abs(outputPathValue)
	if err != nil {
		return fmt.Errorf("resolve attestation output path: %w", err)
	}

	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create attestation directory: %w", err)
	}

	if len(cfg.UserData) > 0 {
		if len(cfg.UserData) != UserDataSize {
			return fmt.Errorf("UserData must be exactly %d bytes, got %d", UserDataSize, len(cfg.UserData))
		}
	}

	nonce := cfg.Nonce
	if len(nonce) > 0 {
		if len(nonce) != NonceSize {
			return fmt.Errorf("Nonce must be exactly %d bytes, got %d", NonceSize, len(nonce))
		}
	} else {
		nonce = make([]byte, NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("generate random nonce: %w", err)
		}
	}

	noncePath := filepath.Join(outputDir, "nonce.bin")
	if err := os.WriteFile(noncePath, nonce, 0o600); err != nil {
		return fmt.Errorf("write nonce to %q: %w", noncePath, err)
	}

	fetcher := defaultReportFetcher
	if fetcher == nil {
		return fmt.Errorf("attestation report fetcher is not configured")
	}

	report, err := fetcher(ctx, cfg.DevicePath, cfg.UserData, nonce)
	if err != nil {
		return fmt.Errorf("generate attestation report: %w", err)
	}

	if len(report) != ReportSize {
		return fmt.Errorf("invalid attestation report size: got %d bytes, want %d", len(report), ReportSize)
	}

	tmpFile, err := os.CreateTemp(outputDir, ".attestation-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary attestation report: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(report); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write attestation report: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync attestation report: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temporary attestation report: %w", err)
	}

	if err := os.Rename(tmpPath, outputPath); err != nil {
		return fmt.Errorf("move attestation report to %q: %w", outputPath, err)
	}
	tmpPath = ""

	return nil
}
