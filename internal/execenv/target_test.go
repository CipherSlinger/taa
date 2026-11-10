package execenv

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalTargetIdentity(t *testing.T) {
	target := NewLocalTarget()
	if target.Name() != "local" {
		t.Fatalf("Name()=%q, want local", target.Name())
	}
	for _, p := range []string{"/opt/taa/input", "relative/dir", ""} {
		if got := target.Resolve(p); got != p {
			t.Fatalf("Resolve(%q)=%q, want identity", p, got)
		}
		if got, err := target.Visible(p); err != nil || got != p {
			t.Fatalf("Visible(%q)=(%q, %v), want identity", p, got, err)
		}
	}
}

func TestLocalTargetBaseEnvIsTheProcessEnv(t *testing.T) {
	t.Setenv("TAA_TEST_MARKER", "present")
	found := false
	for _, kv := range NewLocalTarget().BaseEnv() {
		if kv == "TAA_TEST_MARKER=present" {
			found = true
		}
	}
	if !found {
		t.Fatal("the local target must run with the process environment")
	}
}

func TestLocalTargetPrepareCreatesOutputDir(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "nested", "result")
	if err := NewLocalTarget().Prepare(context.Background(), Spec{OutputDir: outputDir}); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	info, err := os.Stat(outputDir)
	if err != nil {
		t.Fatalf("output dir was not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", outputDir)
	}
}

func TestLocalTargetPrepareReportsFailure(t *testing.T) {
	// A file where the output directory should be must surface as an error, not
	// as a run that starts and then cannot write.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := NewLocalTarget().Prepare(context.Background(), Spec{OutputDir: filepath.Join(blocker, "result")})
	if err == nil {
		t.Fatal("expected an error when the output dir cannot be created")
	}
}

func TestLocalTargetCleanupIsNoop(t *testing.T) {
	// Cleanup must be safe even when nothing was prepared: it runs on the
	// failure paths too.
	NewLocalTarget().Cleanup(context.Background(), Spec{})
}

func TestLocalTargetCommand(t *testing.T) {
	workDir := t.TempDir()
	cmd := NewLocalTarget().Command(context.Background(), "printf 'ok'", workDir)
	if got := cmd.Args; len(got) != 3 || got[0] != "/bin/sh" || got[1] != "-c" || got[2] != "printf 'ok'" {
		t.Fatalf("unexpected argv: %#v", got)
	}
	if cmd.Dir != workDir {
		t.Fatalf("Dir=%q, want %q", cmd.Dir, workDir)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatal("the command must start its own process group so a stop can kill the tree")
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running the command: %v", err)
	}
	if string(out) != "ok" {
		t.Fatalf("output=%q, want ok", out)
	}
}
