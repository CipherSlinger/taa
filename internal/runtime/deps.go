package runtime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// pipBinary is a package-level variable so tests can point it at a stub. The installer tests
// stay hermetic through it: they must not need a real pip or a network.
var pipBinary = "pip3"

// InstallWheelhouse installs an offline wheelhouse into target as a non-root, zero-network
// operation.
//
// --target is used rather than unpacking the wheels by hand because the .dist-info metadata
// has to be correct (the torch ecosystem queries importlib.metadata at runtime) and the wheel
// *.data/ layout has to be placed per spec. --no-index makes the install zero-network: an
// incomplete closure fails here instead of surfacing as an ImportError mid-training.
//
// On failure target may be left partially populated. Cleanup belongs to the caller -- the
// import pipeline removes depsDir/<hash> wholesale so no half-installed set survives.
func InstallWheelhouse(ctx context.Context, wheelhouse, target string) error {
	if strings.TrimSpace(wheelhouse) == "" {
		return fmt.Errorf("wheelhouse dir is required")
	}
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("target dir is required")
	}
	requirements := filepath.Join(wheelhouse, "requirements.txt")
	if _, err := os.Stat(requirements); err != nil {
		return fmt.Errorf("requirements.txt not found in wheelhouse: %w", err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("create target dir: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	args := []string{
		"install",
		"--no-index",
		"--no-cache-dir",
		"--disable-pip-version-check",
		"--find-links", wheelhouse,
		"--target", target,
		"-r", requirements,
	}

	cmd := exec.CommandContext(ctx, pipBinary, args...)
	cmd.Env = append(os.Environ(),
		"PIP_NO_INDEX=1",
		"PIP_DISABLE_PIP_VERSION_CHECK=1",
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pip install failed: %w: %s", err, tailLines(output.String(), 40))
	}
	return nil
}

// tailLines keeps only the last few lines of command output: pip states its reason at the
// end, while a long successful run can produce far more than is worth carrying into an error.
func tailLines(s string, max int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > max {
		lines = lines[len(lines)-max:]
	}
	return strings.Join(lines, "\n")
}
