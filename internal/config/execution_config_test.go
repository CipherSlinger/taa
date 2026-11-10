package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func loadExecutionConfig(t *testing.T, content string) (StartupConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, content)
	return LoadStartupConfig(path)
}

func TestExecutionDefaultsToAuto(t *testing.T) {
	cfg, err := loadExecutionConfig(t, `{}`)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.Execution.Mode != ExecutionModeAuto {
		t.Fatalf("Execution.Mode = %q, want %q", cfg.Execution.Mode, ExecutionModeAuto)
	}
	if cfg.Execution.ModelDir != "" || cfg.Execution.ProgressPath != "" {
		t.Fatalf("path overrides must start empty so the storage contract applies: %+v", cfg.Execution)
	}
}

func TestExecutionModeIsCaseAndSpaceInsensitive(t *testing.T) {
	cfg, err := loadExecutionConfig(t, `{"runtime":{"execution":{"mode":"  CONTAINER "}}}`)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.Execution.Mode != ExecutionModeContainer {
		t.Fatalf("Execution.Mode = %q, want %q", cfg.Execution.Mode, ExecutionModeContainer)
	}
}

func TestExecutionRejectsUnknownMode(t *testing.T) {
	_, err := loadExecutionConfig(t, `{"runtime":{"execution":{"mode":"docker"}}}`)
	if err == nil {
		t.Fatal("an unknown execution mode must be rejected at load")
	}
	if !strings.Contains(err.Error(), "runtime.execution.mode") {
		t.Fatalf("the message must name the key, got %v", err)
	}
}

func TestExecutionAppliesPathOverrides(t *testing.T) {
	cfg, err := loadExecutionConfig(t, `{
		"runtime": {"execution": {
			"mode": "container",
			"containerId": " abc123 ",
			"modelDir": "/srv/model",
			"inputDir": "/srv/input",
			"outputDir": "/srv/out",
			"logDir": "/srv/log",
			"progressPath": "/srv/progress/p.json"
		}}
	}`)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	want := ExecutionConfig{
		Mode:         ExecutionModeContainer,
		ContainerID:  "abc123",
		ModelDir:     "/srv/model",
		InputDir:     "/srv/input",
		OutputDir:    "/srv/out",
		LogDir:       "/srv/log",
		ProgressPath: "/srv/progress/p.json",
	}
	if cfg.Execution != want {
		t.Fatalf("Execution = %+v, want %+v", cfg.Execution, want)
	}
}

func TestExecutionRejectsUnsafePaths(t *testing.T) {
	cases := map[string]string{
		"relative":        `{"runtime":{"execution":{"modelDir":"srv/model"}}}`,
		"dot-carrying":    `{"runtime":{"execution":{"inputDir":"/srv/../etc"}}}`,
		"filesystem-root": `{"runtime":{"execution":{"logDir":"/"}}}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadExecutionConfig(t, content)
			if err == nil {
				t.Fatal("an unsafe execution path must be rejected at load: it is cleared before each run")
			}
			if !strings.Contains(err.Error(), "runtime.execution.") {
				t.Fatalf("the message must name the key, got %v", err)
			}
		})
	}
}
