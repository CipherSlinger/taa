package taa

import (
	"fmt"
	"os"
	"testing"
)

// TestMain gives this package a private temporary directory.
//
// The crash-recovery path deletes leftover download and extraction fragments
// from os.TempDir() at startup — that is correct in a container, where the
// process owns the temp directory, but it is destructive when the whole test
// binary shares /tmp with another package's test binary running in parallel
// under `go test ./...`. The FHE key cache downloads into that same directory,
// so its in-flight file was being removed mid-download and the failure surfaced
// as an unrelated "no such file or directory" in whichever package lost the
// race.
//
// Pointing TMPDIR at a per-package directory keeps the cleanup working (it is
// still exercised, just against files this package created) while making the
// isolation structural instead of a matter of timing.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "taa-app-tests-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp dir: %v\n", err)
		os.Exit(1)
	}
	previous, hadPrevious := os.LookupEnv("TMPDIR")
	if err := os.Setenv("TMPDIR", dir); err != nil {
		fmt.Fprintf(os.Stderr, "set TMPDIR: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	if hadPrevious {
		_ = os.Setenv("TMPDIR", previous)
	} else {
		_ = os.Unsetenv("TMPDIR")
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
