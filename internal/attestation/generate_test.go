package attestation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateValidations(t *testing.T) {
	tmpDir := t.TempDir()
	validOutputPath := filepath.Join(tmpDir, "report.bin")

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "empty output path",
			cfg:     Config{OutputPath: ""},
			wantErr: "attestation output path is required",
		},
		{
			name:    "whitespace output path",
			cfg:     Config{OutputPath: "   "},
			wantErr: "attestation output path is required",
		},
		{
			name: "userdata too short",
			cfg: Config{
				OutputPath: validOutputPath,
				UserData:   []byte("short-userdata"),
			},
			wantErr: fmt.Sprintf("UserData must be exactly %d bytes", UserDataSize),
		},
		{
			name: "userdata too long",
			cfg: Config{
				OutputPath: validOutputPath,
				UserData:   bytes.Repeat([]byte{0x01}, UserDataSize+1),
			},
			wantErr: fmt.Sprintf("UserData must be exactly %d bytes", UserDataSize),
		},
		{
			name: "nonce too short",
			cfg: Config{
				OutputPath: validOutputPath,
				Nonce:      []byte("short-nonce"),
			},
			wantErr: fmt.Sprintf("Nonce must be exactly %d bytes", NonceSize),
		},
		{
			name: "nonce too long",
			cfg: Config{
				OutputPath: validOutputPath,
				Nonce:      bytes.Repeat([]byte{0x02}, NonceSize+1),
			},
			wantErr: fmt.Sprintf("Nonce must be exactly %d bytes", NonceSize),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Generate(context.Background(), tc.cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want containing %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestGenerateWithMockFetcher(t *testing.T) {
	oldFetcher := defaultReportFetcher
	t.Cleanup(func() { defaultReportFetcher = oldFetcher })

	t.Run("explicit userdata and nonce", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "out", "report.bin")

		wantUserData := bytes.Repeat([]byte{0xaa}, UserDataSize)
		wantNonce := []byte("0123456789abcdef")
		mockReport := bytes.Repeat([]byte{0x55}, ReportSize)
		customDevice := "/dev/custom-csv-device"

		var called bool
		defaultReportFetcher = func(ctx context.Context, devicePath string, userData, nonce []byte) ([]byte, error) {
			called = true
			if devicePath != customDevice {
				return nil, fmt.Errorf("devicePath = %q, want %q", devicePath, customDevice)
			}
			if !bytes.Equal(userData, wantUserData) {
				return nil, fmt.Errorf("userData mismatch")
			}
			if !bytes.Equal(nonce, wantNonce) {
				return nil, fmt.Errorf("nonce mismatch")
			}
			return mockReport, nil
		}

		err := Generate(context.Background(), Config{
			OutputPath: outputPath,
			DevicePath: customDevice,
			UserData:   wantUserData,
			Nonce:      wantNonce,
		})
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if !called {
			t.Fatal("expected mock report fetcher to be called")
		}

		gotReport, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("read output report: %v", err)
		}
		if !bytes.Equal(gotReport, mockReport) {
			t.Fatalf("output report content mismatch")
		}

		noncePath := filepath.Join(filepath.Dir(outputPath), "nonce.bin")
		gotNonce, err := os.ReadFile(noncePath)
		if err != nil {
			t.Fatalf("read nonce.bin: %v", err)
		}
		if !bytes.Equal(gotNonce, wantNonce) {
			t.Fatalf("nonce.bin content mismatch: got %x, want %x", gotNonce, wantNonce)
		}
	})

	t.Run("auto generated nonce", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "report.bin")
		mockReport := bytes.Repeat([]byte{0x77}, ReportSize)

		var capturedNonce []byte
		defaultReportFetcher = func(ctx context.Context, devicePath string, userData, nonce []byte) ([]byte, error) {
			capturedNonce = append([]byte(nil), nonce...)
			return mockReport, nil
		}

		err := Generate(context.Background(), Config{
			OutputPath: outputPath,
		})
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if len(capturedNonce) != NonceSize {
			t.Fatalf("captured nonce length = %d, want %d", len(capturedNonce), NonceSize)
		}

		noncePath := filepath.Join(filepath.Dir(outputPath), "nonce.bin")
		savedNonce, err := os.ReadFile(noncePath)
		if err != nil {
			t.Fatalf("read nonce.bin: %v", err)
		}
		if !bytes.Equal(savedNonce, capturedNonce) {
			t.Fatalf("saved nonce != captured nonce: got %x, want %x", savedNonce, capturedNonce)
		}
	})

	t.Run("fetcher returns error", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "report.bin")

		expectedErr := errors.New("ioctl device failure")
		defaultReportFetcher = func(ctx context.Context, devicePath string, userData, nonce []byte) ([]byte, error) {
			return nil, expectedErr
		}

		err := Generate(context.Background(), Config{
			OutputPath: outputPath,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, expectedErr) && !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Fatalf("error = %v, want containing %q", err, expectedErr.Error())
		}
	})

	t.Run("fetcher returns invalid report size", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "report.bin")

		defaultReportFetcher = func(ctx context.Context, devicePath string, userData, nonce []byte) ([]byte, error) {
			return make([]byte, 100), nil
		}

		err := Generate(context.Background(), Config{
			OutputPath: outputPath,
		})
		if err == nil {
			t.Fatal("expected invalid report size error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid attestation report size") {
			t.Fatalf("error = %v, want containing 'invalid attestation report size'", err)
		}
	})
}

func TestGenerateMissingDevice(t *testing.T) {
	tmpDir := t.TempDir()
	missingDevice := filepath.Join(tmpDir, "nonexistent-device-node")
	outputPath := filepath.Join(tmpDir, "report.cert")

	err := Generate(context.Background(), Config{
		OutputPath: outputPath,
		DevicePath: missingDevice,
	})
	if err == nil {
		t.Fatal("expected error when using nonexistent device path, got nil")
	}

	if !strings.Contains(err.Error(), missingDevice) {
		t.Fatalf("error = %q, want containing missing device path %q", err.Error(), missingDevice)
	}
}
