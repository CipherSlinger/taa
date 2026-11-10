package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"taa/internal/config"
	"taa/internal/deployment"
	"taa/internal/execenv"
)

func executionTestState(t *testing.T, mode string, shape deployment.Shape) *TAAState {
	t.Helper()
	state := NewTAAState("", "", "docker-exec", nil, nil, SecurityConfig{
		Execution: config.ExecutionConfig{Mode: mode},
	})
	state.SetDeployment(deployment.Result{Shape: shape, Explicit: true})
	return state
}

// stubDiscovery replaces the discovery seam for one test. It records whether it
// was called, so a mode that must not probe can be asserted to have stayed put.
func stubDiscovery(t *testing.T, target *execenv.ContainerTarget, err error) *bool {
	t.Helper()
	called := false
	original := discoverContainer
	discoverContainer = func(context.Context, execenv.Options) (*execenv.ContainerTarget, error) {
		called = true
		return target, err
	}
	t.Cleanup(func() { discoverContainer = original })
	return &called
}

func TestSelectExecutionTargetLocalModeDoesNotDiscover(t *testing.T) {
	called := stubDiscovery(t, nil, errors.New("must not be called"))
	state := executionTestState(t, config.ExecutionModeLocal, deployment.Initrd)

	target, err := state.selectExecutionTarget(context.Background())
	if err != nil {
		t.Fatalf("local mode must not fail: %v", err)
	}
	if target.Name() != "local" {
		t.Fatalf("local mode selected %q", target.Name())
	}
	if *called {
		t.Fatal("local mode must not probe for a container: it is the rollback path")
	}
}

func TestSelectExecutionTargetAutoStaysLocalOffInitrd(t *testing.T) {
	called := stubDiscovery(t, nil, errors.New("must not be called"))
	state := executionTestState(t, config.ExecutionModeAuto, deployment.Container)

	target, err := state.selectExecutionTarget(context.Background())
	if err != nil {
		t.Fatalf("auto mode off initrd must not fail: %v", err)
	}
	if target.Name() != "local" {
		t.Fatalf("auto mode off initrd selected %q", target.Name())
	}
	if *called {
		t.Fatal("a container deployment already runs inside the container; discovery is unnecessary")
	}
}

func TestSelectExecutionTargetAutoFallsBackWithAWarning(t *testing.T) {
	stubDiscovery(t, nil, errors.New("no container mount namespace found"))
	state := executionTestState(t, config.ExecutionModeAuto, deployment.Initrd)

	target, err := state.selectExecutionTarget(context.Background())
	if err != nil {
		t.Fatalf("auto mode must fall back rather than fail: %v", err)
	}
	if target.Name() != "local" {
		t.Fatalf("fallback selected %q", target.Name())
	}
	entries := state.Logs.All()
	if !hasLogMessage(entries, "回退到 local") {
		t.Fatalf("the fallback must be reported on the platform channel, got %+v", entries)
	}
}

func TestSelectExecutionTargetContainerModeFailsClosed(t *testing.T) {
	discoveryErr := errors.New("no container mount namespace found")
	stubDiscovery(t, nil, discoveryErr)
	state := executionTestState(t, config.ExecutionModeContainer, deployment.Initrd)

	if _, err := state.selectExecutionTarget(context.Background()); !errors.Is(err, discoveryErr) {
		t.Fatalf("container mode must fail when discovery does, got %v", err)
	}
}

func TestExecutionPathsDefaultsAndOverrides(t *testing.T) {
	defaults := execenv.DefaultContainerPaths()
	if got := executionPaths(config.ExecutionConfig{}); got != defaults {
		t.Fatalf("empty overrides must keep the packaged contract, got %+v", got)
	}

	paths := executionPaths(config.ExecutionConfig{
		ModelDir: "/srv/model/code", InputDir: "/srv/model/data",
	})
	if paths.ModelDir != "/srv/model/code" || paths.InputDir != "/srv/model/data" {
		t.Fatalf("overrides not applied: %+v", paths)
	}
	if paths.OutputDir != defaults.OutputDir || paths.ProgressPath != defaults.ProgressPath {
		t.Fatalf("unset paths must keep their default: %+v", paths)
	}
}

func hasLogMessage(entries []LogEntry, substring string) bool {
	for _, entry := range entries {
		if strings.Contains(entry.Message, substring) {
			return true
		}
	}
	return false
}
