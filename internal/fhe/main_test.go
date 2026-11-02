package fhe

import (
	"fmt"
	"os"
	"testing"
)

// TestMain gives this package a private temporary directory.
//
// The key cache streams eval keys into os.TempDir(). Sharing that directory with
// other packages under `go test ./...` made the download dependent on what else
// is running: the crash-recovery tests remove leftover download fragments from
// the same directory at startup, and a download in flight here would vanish
// mid-stream. Isolating TMPDIR per package removes the cross-package coupling
// without weakening the cleanup these tests exercise.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "taa-fhe-tests-*")
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
