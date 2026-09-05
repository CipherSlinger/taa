package attestation

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// UserDataSize is the required size of the USERDATA field in the attestation report.
const UserDataSize = 64

type Config struct {
	OutputPath string
	HelperPath string
	Mode       string
	WorkingDir string
	// UserData is an optional 64-byte user-defined data that will be written to
	// the attestation report's USERDATA field. If empty, the helper uses its default.
	// If provided, it must be exactly UserDataSize bytes.
	UserData []byte
	// Nonce is an optional caller-supplied nonce (typically 16 bytes).
	// When non-nil it is written to nonce.bin in the helper's working directory
	// before the helper runs, so the helper can embed it in the attestation report.
	Nonce []byte
}

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

	workDir := strings.TrimSpace(cfg.WorkingDir)
	if workDir == "" {
		workDir = filepath.Dir(outputPath)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("create attestation workdir: %w", err)
	}

	helperPath, helperName, err := resolveHelper(workDir, cfg.HelperPath, cfg.Mode)
	if err != nil {
		return err
	}

	noncePath := filepath.Join(workDir, "nonce.bin")
	if len(cfg.Nonce) > 0 {
		if err := os.WriteFile(noncePath, cfg.Nonce, 0o600); err != nil {
			return fmt.Errorf("write nonce to %q: %w", noncePath, err)
		}
	}

	generatedPath := filepath.Join(workDir, "report.cert")
	if err := os.Remove(generatedPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale attestation report %q: %w", generatedPath, err)
	}
	if generatedPath != outputPath {
		if err := os.Remove(outputPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale attestation report %q: %w", outputPath, err)
		}
	}

	cmd := exec.CommandContext(ctx, helperPath)
	cmd.Dir = workDir

	// 通过环境变量传递 userdata（64 字节）
	if len(cfg.UserData) > 0 {
		if len(cfg.UserData) != UserDataSize {
			return fmt.Errorf("UserData must be exactly %d bytes, got %d", UserDataSize, len(cfg.UserData))
		}
		cmd.Env = append(os.Environ(), "ATTESTATION_USERDATA="+hex.EncodeToString(cfg.UserData))
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		if trimmed := strings.TrimSpace(out.String()); trimmed != "" {
			log.Printf("attestation helper %s output:\n%s", helperName, trimmed)
		}
		return fmt.Errorf("run attestation helper %q: %w", helperPath, err)
	}
	if trimmed := strings.TrimSpace(out.String()); trimmed != "" {
		log.Printf("attestation helper %s output:\n%s", helperName, trimmed)
	}

	if _, err := os.Stat(generatedPath); err != nil {
		return fmt.Errorf("attestation helper did not produce %q: %w", generatedPath, err)
	}

	if generatedPath != outputPath {
		if err := os.Rename(generatedPath, outputPath); err != nil {
			return fmt.Errorf("move attestation report to %q: %w", outputPath, err)
		}
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("verify attestation report %q: %w", outputPath, err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("attestation report %q is empty", outputPath)
	}

	return nil
}

func resolveHelper(workDir, explicitHelper, mode string) (string, string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if explicitHelper = strings.TrimSpace(explicitHelper); explicitHelper != "" {
		if path, ok := resolveCandidate(workDir, explicitHelper); ok {
			return path, filepath.Base(path), nil
		}
		return "", "", fmt.Errorf("attestation helper %q not found", explicitHelper)
	}

	var candidates []string
	switch mode {
	case "", "auto", "ioctl":
		candidates = []string{"get-attestation", "ioctl-get-attestation", "vmmcall-get-attestation"}
	case "vmmcall":
		candidates = []string{"vmmcall-get-attestation"}
	default:
		return "", "", fmt.Errorf("unsupported attestation mode %q", mode)
	}

	for _, candidate := range candidates {
		if path, ok := resolveCandidate(workDir, candidate); ok {
			return path, filepath.Base(path), nil
		}
	}
	return "", "", fmt.Errorf("no attestation helper found for mode %q", mode)
}

func resolveCandidate(workDir, candidate string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", false
	}

	if filepath.IsAbs(candidate) {
		if fileExists(candidate) {
			return candidate, true
		}
		return "", false
	}

	if strings.ContainsRune(candidate, os.PathSeparator) {
		joined := filepath.Clean(filepath.Join(workDir, candidate))
		if fileExists(joined) {
			return joined, true
		}
	}

	joined := filepath.Join(workDir, filepath.Base(candidate))
	if fileExists(joined) {
		return joined, true
	}

	if path, err := exec.LookPath(candidate); err == nil {
		return path, true
	}

	return "", false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
