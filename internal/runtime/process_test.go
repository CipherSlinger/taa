package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestTrainingControlLifecycle(t *testing.T) {
	control := NewTrainingControl()
	if control.IsCancelled() {
		t.Fatal("new control should not be cancelled")
	}

	cmd := control.RequestStop()
	if cmd != nil {
		t.Fatalf("expected nil cmd from empty control, got %v", cmd)
	}
	if !control.IsCancelled() {
		t.Fatal("control should be cancelled after RequestStop")
	}

	control.Finish()
	control.Finish() // idempotent
	select {
	case <-control.Done():
	default:
		t.Fatal("Done() channel should be closed")
	}
}

func TestTrainingControlStartCommandAfterCancelled(t *testing.T) {
	control := NewTrainingControl()
	control.RequestStop()

	cmd := exec.Command("true")
	if err := control.StartCommand(cmd); !errors.Is(err, context.Canceled) {
		t.Fatalf("StartCommand on cancelled control error = %v, want context.Canceled", err)
	}
}

func TestTrainingControlCommandRegistration(t *testing.T) {
	control := NewTrainingControl()
	cmd := exec.Command("sleep", "30")
	if err := control.StartCommand(cmd); err != nil {
		t.Fatalf("StartCommand failed: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	if got := control.CurrentCmd(); got != cmd {
		t.Fatalf("CurrentCmd = %p, want %p", got, cmd)
	}
	if got := control.RequestStop(); got != cmd {
		t.Fatalf("RequestStop = %p, want %p", got, cmd)
	}

	control.ClearCommand(cmd)
	if got := control.CurrentCmd(); got != nil {
		t.Fatalf("CurrentCmd after ClearCommand = %p, want nil", got)
	}
}

func TestKillProcessGroup(t *testing.T) {
	// nil safe
	if err := KillProcessGroup(nil); err != nil {
		t.Fatalf("KillProcessGroup(nil) failed: %v", err)
	}
	cmd := exec.Command("sleep", "30")
	// inactive cmd safe
	if err := KillProcessGroup(cmd); err != nil {
		t.Fatalf("KillProcessGroup(inactive) failed: %v", err)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() {
		_ = cmd.Wait()
	}()

	// kill process
	if err := KillProcessGroup(cmd); err != nil {
		t.Fatalf("KillProcessGroup failed: %v", err)
	}
}

func TestRunRuntimeConfigExecution(t *testing.T) {
	tmpDir := t.TempDir()
	modelDir := filepath.Join(tmpDir, "model")
	dataDir := filepath.Join(tmpDir, "data")
	outputDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(modelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := RuntimeConfig{
		Commands: []string{
			"echo 'hello from model' > <output>/result.txt",
			"echo $CUSTOM_VAR >> <output>/result.txt",
		},
	}
	env := map[string]string{
		"CUSTOM_VAR": "custom_val_42",
	}

	out, err := RunRuntimeConfig(cfg, env, modelDir, dataDir, outputDir, "task-test-run", "2026-09-16T00:00:00Z")
	if err != nil {
		t.Fatalf("RunRuntimeConfig failed: %v\noutput: %s", err, out)
	}

	resBytes, err := os.ReadFile(filepath.Join(outputDir, "result.txt"))
	if err != nil {
		t.Fatalf("read result.txt failed: %v", err)
	}
	content := string(resBytes)
	if !filepath.IsAbs(outputDir) {
		t.Fatal("outputDir is not absolute")
	}
	if expected := "hello from model\ncustom_val_42\n"; content != expected {
		t.Fatalf("unexpected content: %q, want %q", content, expected)
	}
}

func TestRunRuntimeConfigCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	modelDir := filepath.Join(tmpDir, "model")
	dataDir := filepath.Join(tmpDir, "data")
	outputDir := filepath.Join(tmpDir, "output")
	_ = os.MkdirAll(modelDir, 0o755)

	control := NewTrainingControl()
	cfg := RuntimeConfig{
		Commands: []string{"sleep 30"},
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := RunRuntimeConfigWithControl(control, cfg, nil, modelDir, dataDir, outputDir, "task-cancel", "2026-09-16T00:00:00Z")
		errCh <- err
	}()

	// Wait for process to start
	var cmd *exec.Cmd
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cmd = control.CurrentCmd()
		if cmd != nil && cmd.Process != nil && cmd.Process.Pid > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		t.Fatal("command was not started in time")
	}

	stoppedCmd := control.RequestStop()
	if stoppedCmd != cmd {
		t.Fatalf("RequestStop returned %p, want %p", stoppedCmd, cmd)
	}
	_ = KillProcessGroup(stoppedCmd)

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunRuntimeConfigWithControl did not return in time after cancellation")
	}
}
