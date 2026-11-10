package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"taa/internal/execenv"
)

func TestRunRuntimeConfigWithTargetLocalMatchesLegacy(t *testing.T) {
	// The target seam must be a pure refactor: routing the same configuration
	// through LocalTarget produces the same file, the same environment and the
	// same command resolution as the legacy entry point.
	cases := []struct {
		name string
		run  func(cfg RuntimeConfig, env map[string]string, modelDir, dataDir, outputDir string) (string, error)
	}{
		{"legacy", func(cfg RuntimeConfig, env map[string]string, modelDir, dataDir, outputDir string) (string, error) {
			return RunRuntimeConfig(cfg, env, modelDir, dataDir, outputDir, "task-target", "2026-11-10T00:00:00Z")
		}},
		{"target", func(cfg RuntimeConfig, env map[string]string, modelDir, dataDir, outputDir string) (string, error) {
			target := execenv.NewLocalTarget()
			spec := execenv.Spec{ModelDir: modelDir, DataDir: dataDir, OutputDir: outputDir}
			if err := target.Prepare(context.Background(), spec); err != nil {
				return "", err
			}
			return RunRuntimeConfigWithTarget(nil, target, cfg, env, modelDir, dataDir, outputDir, "task-target", "2026-11-10T00:00:00Z")
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			modelDir := filepath.Join(root, "model")
			dataDir := filepath.Join(root, "data")
			outputDir := filepath.Join(root, "output")
			if err := os.MkdirAll(modelDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(dataDir, 0o755); err != nil {
				t.Fatal(err)
			}

			cfg := RuntimeConfig{Commands: []string{
				"printf '%s' \"$TAA_TASK_ID\" > <output>/id.txt",
				"printf '%s' \"$TAA_INPUT_DIR\" > <output>/input.txt",
			}}
			out, err := c.run(cfg, nil, modelDir, dataDir, outputDir)
			if err != nil {
				t.Fatalf("run failed: %v\noutput: %s", err, out)
			}

			id, err := os.ReadFile(filepath.Join(outputDir, "id.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if string(id) != "task-target" {
				t.Fatalf("TAA_TASK_ID=%q, want task-target", id)
			}
			in, err := os.ReadFile(filepath.Join(outputDir, "input.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if string(in) != dataDir {
				t.Fatalf("TAA_INPUT_DIR=%q, want %q", in, dataDir)
			}
		})
	}
}

func TestRunRuntimeConfigWithTargetRefusesNilTarget(t *testing.T) {
	_, err := RunRuntimeConfigWithTarget(nil, nil, RuntimeConfig{Commands: []string{"true"}}, nil, "", "", "", "", "")
	if err == nil {
		t.Fatal("expected an error when no target is given")
	}
}
