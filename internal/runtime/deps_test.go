package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWheelhouseFailsOnMissingRequirements(t *testing.T) {
	err := InstallWheelhouse(context.Background(), t.TempDir(), filepath.Join(t.TempDir(), "target"))
	if err == nil {
		t.Fatal("expected error for a wheelhouse without requirements.txt")
	}
}

func TestInstallWheelhouseRejectsEmptyArgs(t *testing.T) {
	if err := InstallWheelhouse(context.Background(), "", "/tmp/x"); err == nil {
		t.Fatal("expected error for empty wheelhouse")
	}
	if err := InstallWheelhouse(context.Background(), "/tmp/x", ""); err == nil {
		t.Fatal("expected error for empty target")
	}
}

// stubPip writes a fake pip3 that runs the given shell body, and points the package-level
// pipBinary at it for the rest of the test. This is what keeps the installer tests hermetic:
// they must not depend on a real pip, on network access, or on the machine's Python.
func stubPip(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pip3-stub")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	original := pipBinary
	pipBinary = path
	t.Cleanup(func() { pipBinary = original })
}

func TestInstallWheelhousePassesOfflineFlags(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("STUB_ARGS_FILE", argsFile)
	stubPip(t, `printf '%s\n' "$@" > "$STUB_ARGS_FILE"`)

	wh := t.TempDir()
	if err := os.WriteFile(filepath.Join(wh, "requirements.txt"), []byte("wheel\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")

	if err := InstallWheelhouse(context.Background(), wh, target); err != nil {
		t.Fatalf("InstallWheelhouse: %v", err)
	}

	recorded, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("stub did not record args: %v", err)
	}
	args := string(recorded)

	// --no-index is precisely what makes the install zero-network. Drop it and an incomplete
	// closure silently resolves from an index instead of failing fast, which is the one
	// property this whole path exists to guarantee -- so pin every load-bearing flag.
	for _, want := range []string{
		"install", "--no-index", "--find-links", wh, "--target", target,
		"-r", filepath.Join(wh, "requirements.txt"),
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("pip args missing %q; got:\n%s", want, args)
		}
	}
}

func TestInstallWheelhouseSurfacesPipFailureTail(t *testing.T) {
	stubPip(t, "echo \"ERROR: No matching distribution found for torch\" >&2\nexit 1")

	wh := t.TempDir()
	if err := os.WriteFile(filepath.Join(wh, "requirements.txt"), []byte("torch\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}

	err := InstallWheelhouse(context.Background(), wh, filepath.Join(t.TempDir(), "target"))
	if err == nil {
		t.Fatal("expected error when pip exits non-zero")
	}
	// pip explains itself on its last lines; tailLines exists to carry exactly that through,
	// because the operator only ever sees this error string.
	if !strings.Contains(err.Error(), "No matching distribution found for torch") {
		t.Fatalf("error does not carry pip's reason: %v", err)
	}
}
