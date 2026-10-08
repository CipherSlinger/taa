package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstallWheelhouseFailsOnMissingRequirements(t *testing.T) {
	err := InstallWheelhouse(context.Background(), t.TempDir(), filepath.Join(t.TempDir(), "target"))
	if err == nil {
		t.Fatal("expected error for a wheelhouse without requirements.txt")
	}
}

// A directory named requirements.txt satisfies a bare os.Stat; only the regular-file guard
// rejects it before pip is spawned.
func TestInstallWheelhouseRejectsRequirementsDirectory(t *testing.T) {
	wh := t.TempDir()
	if err := os.Mkdir(filepath.Join(wh, "requirements.txt"), 0o755); err != nil {
		t.Fatalf("mkdir requirements.txt: %v", err)
	}
	err := InstallWheelhouse(context.Background(), wh, filepath.Join(t.TempDir(), "target"))
	if err == nil {
		t.Fatal("expected error when requirements.txt is a directory")
	}
	if !strings.Contains(err.Error(), "不是普通文件") {
		t.Fatalf("error does not come from the regular-file guard: %v", err)
	}
}

// Each case asserts the empty-argument guard's own message. Without that, deleting a guard
// still passes: the downstream requirements.txt Stat fails too, just for a different reason.
func TestInstallWheelhouseRejectsEmptyArgs(t *testing.T) {
	err := InstallWheelhouse(context.Background(), "", "/tmp/x")
	if err == nil {
		t.Fatal("expected error for empty wheelhouse")
	}
	if !strings.Contains(err.Error(), "is required") {
		t.Fatalf("error does not come from the empty-wheelhouse guard: %v", err)
	}

	err = InstallWheelhouse(context.Background(), "/tmp/x", "")
	if err == nil {
		t.Fatal("expected error for empty target")
	}
	if !strings.Contains(err.Error(), "is required") {
		t.Fatalf("error does not come from the empty-target guard: %v", err)
	}
}

// stubPip writes a fake pip3 that runs the given shell body, and points the package-level
// pipBinary at it for the rest of the test. This is what keeps the installer tests hermetic:
// they must not depend on a real pip, on network access, or on the machine's Python.
//
// pipBinary is a package-level variable, so tests in this package must not call t.Parallel:
// two parallel tests would race on it and one would end up running the other's stub. The same
// holds for pipWaitDelay, which a test shrinks to observe the wait bound.
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

// A cancellation must reach the caller recognisably: the child's ExitError ("signal: killed")
// does not match context.Canceled, so without the ctx.Err() check a shutdown or task cancel
// would be reported to the platform as a real dependency-install failure.
func TestInstallWheelhouseReportsCancellation(t *testing.T) {
	// exec replaces the stub shell with sleep, so killing the direct child closes the output
	// pipe and Wait returns promptly instead of waiting out WaitDelay.
	stubPip(t, "exec sleep 30")

	wh := t.TempDir()
	if err := os.WriteFile(filepath.Join(wh, "requirements.txt"), []byte("torch\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	err := InstallWheelhouse(ctx, wh, filepath.Join(t.TempDir(), "target"))
	if err == nil {
		t.Fatal("expected error when the context is cancelled mid-install")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled install must unwrap to context.Canceled; got: %v", err)
	}
}

// WaitDelay is the only thing between a leaked grandchild that inherited the output pipe and
// an unbounded hang in Wait, so it is pinned here rather than trusted. The stub exits at once
// while backgrounding a sleep that keeps the inherited stdout/stderr write-end open: the exact
// shape of the leak the bound exists for.
//
// The contract is two-way: with WaitDelay in place the call returns in roughly pipWaitDelay;
// without it, Wait blocks until the grandchild exits (about 8s), which the 5s bound catches.
// The assertion is the wall-clock bound, not errors.Is(err, exec.ErrWaitDelay): the timer starts
// when Wait observes the child has exited, and for a child that already exited non-zero Wait
// returns the *ExitError rather than the sentinel, so asserting on the sentinel would fail
// spuriously.
func TestInstallWheelhouseBoundsWaitOnLeakedGrandchild(t *testing.T) {
	// Non-interactive sh does not wait for background jobs, so sh exits immediately with status
	// 1 while "sleep 8" keeps the inherited output pipe write-end open.
	stubPip(t, "sleep 8 &\nexit 1")

	original := pipWaitDelay
	pipWaitDelay = 300 * time.Millisecond
	defer func() { pipWaitDelay = original }()

	wh := t.TempDir()
	if err := os.WriteFile(filepath.Join(wh, "requirements.txt"), []byte("torch\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}

	start := time.Now()
	err := InstallWheelhouse(context.Background(), wh, filepath.Join(t.TempDir(), "target"))
	elapsed := time.Since(start)
	t.Logf("install returned in %s with pipWaitDelay=%s", elapsed, pipWaitDelay)

	if err == nil {
		t.Fatal("expected an error when pip exits non-zero")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("install took %s; WaitDelay did not bound the wait on the leaked output pipe", elapsed)
	}
}

func TestInstallWheelhousePassesOfflineFlags(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	envFile := filepath.Join(t.TempDir(), "env.txt")
	t.Setenv("STUB_ARGS_FILE", argsFile)
	t.Setenv("STUB_ENV_FILE", envFile)
	stubPip(t, `env > "$STUB_ENV_FILE"
printf '%s\n' "$@" > "$STUB_ARGS_FILE"`)

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
		"install", "--no-index", "--no-cache-dir", "--disable-pip-version-check",
		"--find-links", wh, "--target", target,
		"-r", filepath.Join(wh, "requirements.txt"),
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("pip args missing %q; got:\n%s", want, args)
		}
	}

	// PIP_NO_INDEX=1 is a second line of defence, independent of the flag: losing either one
	// silently restores index access, so pin the environment too.
	recordedEnv, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("stub did not record env: %v", err)
	}
	if !strings.Contains(string(recordedEnv), "PIP_NO_INDEX=1") {
		t.Fatalf("pip environment is missing PIP_NO_INDEX=1; got:\n%s", recordedEnv)
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

// The truncation also has to be pinned at its call site, not only in tailLines: swap the
// call for a bare output.String() and a runaway pip log (hundreds of lines) is carried whole
// into the operator's error message.
func TestInstallWheelhouseTruncatesPipFailureTail(t *testing.T) {
	stubPip(t, `i=1; while [ $i -le 50 ]; do echo "L-$i-END"; i=$((i+1)); done; exit 1`)

	wh := t.TempDir()
	if err := os.WriteFile(filepath.Join(wh, "requirements.txt"), []byte("torch\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}

	err := InstallWheelhouse(context.Background(), wh, filepath.Join(t.TempDir(), "target"))
	if err == nil {
		t.Fatal("expected error when pip exits non-zero")
	}
	msg := err.Error()

	if !strings.Contains(msg, "…(truncated)") {
		t.Fatalf("truncated tail is not marked: %v", msg)
	}
	if !strings.Contains(msg, "L-50-END") {
		t.Fatalf("the last line was cut: %v", msg)
	}
	// The last 40 of 50 lines are 11..50, so the first 10 must be gone.
	if !strings.Contains(msg, "L-11-END") {
		t.Fatalf("the 40-line window starts too late: %v", msg)
	}
	if strings.Contains(msg, "L-1-END") || strings.Contains(msg, "L-10-END") {
		t.Fatalf("output was not cut to the tail: %v", msg)
	}
}

// tailLines is what the operator reads in the failure path, so its contract is pinned here:
// rewrite the call site to a bare output.String() and these cases stop passing.
func TestTailLines(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		limit int
		want  string
	}{
		{"empty output", "", 5, ""},
		{"fewer lines than the limit", "a\nb\nc", 5, "a\nb\nc"},
		{"exactly the limit", "a\nb\nc", 3, "a\nb\nc"},
		{"more than the limit", "a\nb\nc\nd", 2, "…(truncated)\nc\nd"},
		{"trailing newline trimmed", "a\nb\n", 5, "a\nb"},
		{"zero limit", "a\nb", 0, ""},
		{"negative limit", "a\nb", -1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tailLines(tc.in, tc.limit); got != tc.want {
				t.Fatalf("tailLines(%q, %d) = %q; want %q", tc.in, tc.limit, got, tc.want)
			}
		})
	}
}
