package runtime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
	// A directory named requirements.txt satisfies a bare os.Stat but makes pip fail with
	// "[Errno 21] Is a directory", so require a regular file before spawning pip.
	reqInfo, err := os.Stat(requirements)
	if err != nil {
		return fmt.Errorf("requirements.txt not found in wheelhouse: %w", err)
	}
	if !reqInfo.Mode().IsRegular() {
		return fmt.Errorf("依赖包内的 requirements.txt 不是普通文件")
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
	// CommandContext kills only the direct child. With Stdout set to a bytes.Buffer, Wait also
	// waits for the output pipe to reach EOF, so a grandchild that inherited that pipe would
	// keep Wait blocked without bound. WaitDelay bounds that wait; once it expires, Wait
	// returns with ErrWaitDelay instead of hanging a shutdown indefinitely.
	cmd.WaitDelay = 30 * time.Second
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Run(); err != nil {
		// A cancellation must not be reported as a dependency-install failure: the direct
		// child's ExitError ("signal: killed") does not match context.Canceled, so check
		// ctx.Err() first. Same shape as runSemgrepCLI in internal/codeaudit.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("pip install cancelled: %w", ctxErr)
		}
		return fmt.Errorf("pip install failed: %w: %s", err, tailLines(output.String(), 40))
	}
	return nil
}

// tailLines keeps only the last limit lines of command output: pip states its reason at the
// end, while a long successful run can produce far more than is worth carrying into an error.
//
// A truncated result is prefixed with a marker so an operator can tell "pip printed limit
// lines" from "we cut its output down to limit". A non-positive limit yields "" rather than
// panicking on an out-of-range slice.
func tailLines(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
		return "…(truncated)\n" + strings.Join(lines, "\n")
	}
	return strings.Join(lines, "\n")
}
