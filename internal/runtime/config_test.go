package runtime

import (
	"path/filepath"
	"testing"
)

func TestParseRuntimeConfigValid(t *testing.T) {
	raw := `{"commands": ["python train.py --data <input> --out <output>"], "env": "{\"EPOCHS\": \"10\"}"}`
	cfg, env, err := ParseRuntimeConfig(raw)
	if err != nil {
		t.Fatalf("ParseRuntimeConfig failed: %v", err)
	}
	if len(cfg.Commands) != 1 || cfg.Commands[0] != "python train.py --data <input> --out <output>" {
		t.Fatalf("unexpected commands: %v", cfg.Commands)
	}
	if env["EPOCHS"] != "10" {
		t.Fatalf("unexpected env: %v", env)
	}
}

func TestParseRuntimeConfigObjectEnv(t *testing.T) {
	raw := `{"commands": ["echo 1"], "env": {"LR": "0.001", "BATCH": 32}}`
	cfg, env, err := ParseRuntimeConfig(raw)
	if err != nil {
		t.Fatalf("ParseRuntimeConfig with object env failed: %v", err)
	}
	if len(cfg.Commands) != 1 || cfg.Commands[0] != "echo 1" {
		t.Fatalf("unexpected commands: %v", cfg.Commands)
	}
	if env["LR"] != "0.001" || env["BATCH"] != "32" {
		t.Fatalf("unexpected env: %v", env)
	}
}

func TestParseRuntimeConfigErrors(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty string", ""},
		{"whitespace only", "   \t\n "},
		{"empty commands", `{"commands": []}`},
		{"blank command", `{"commands": ["echo 1", "  "]}`},
		{"invalid json", `{commands:}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseRuntimeConfig(tt.raw)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestResolveRuntimeString(t *testing.T) {
	dataDir := "/data/train"
	outputDir := "/out/task-1/result"
	expectedLogDir := filepath.Join(filepath.Dir(outputDir), "log")
	expectedProgressDir := filepath.Join(filepath.Dir(outputDir), "progress")

	tests := []struct {
		input    string
		expected string
	}{
		{"python train.py --data <input> --out <output>", "python train.py --data /data/train --out /out/task-1/result"},
		{"<INPUT> <OUTPUT> <in> <out> <IN> <OUT>", "/data/train /out/task-1/result /data/train /out/task-1/result /data/train /out/task-1/result"},
		{"log at /opt/taa/output/log/app.log", "log at " + expectedLogDir + "/app.log"},
		{"progress at /opt/taa/output/progress/run.json", "progress at " + expectedProgressDir + "/run.json"},
		{"result at /opt/taa/output/result/weights.bin", "result at /out/task-1/result/weights.bin"},
		{"output at /opt/taa/output/model.pt", "output at /out/task-1/result/model.pt"},
		{"data at /opt/taa/input/dataset.csv", "data at /data/train/dataset.csv"},
		{"custom prefix /opt/taa/output_suffix/foo", "custom prefix /opt/taa/output_suffix/foo"},
	}

	for _, tt := range tests {
		got := ResolveRuntimeString(tt.input, dataDir, outputDir)
		if got != tt.expected {
			t.Errorf("ResolveRuntimeString(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestResolveRuntimeCommandsAndEnv(t *testing.T) {
	dataDir := "/data"
	outputDir := "/out/res"

	cmds := []string{"train --in <input>", "eval --out <output>"}
	resolvedCmds := ResolveRuntimeCommands(cmds, dataDir, outputDir)
	if resolvedCmds[0] != "train --in /data" || resolvedCmds[1] != "eval --out /out/res" {
		t.Fatalf("unexpected resolved commands: %v", resolvedCmds)
	}

	env := map[string]string{
		"DATA": "<input>/sub",
		"OUT":  "<output>/models",
	}
	resolvedEnv := ResolveRuntimeEnv(env, dataDir, outputDir)
	if resolvedEnv["DATA"] != "/data/sub" || resolvedEnv["OUT"] != "/out/res/models" {
		t.Fatalf("unexpected resolved env: %v", resolvedEnv)
	}
}

func TestMergedRuntimeEnv(t *testing.T) {
	userEnv := map[string]string{
		"MY_CUSTOM_VAR": "custom_value",
	}
	sysEnv := map[string]string{
		"TAA_TASK_ID": "task-test-123",
	}
	merged := MergedRuntimeEnv(userEnv, sysEnv)

	foundCustom := false
	foundTaskID := false
	for _, kv := range merged {
		if kv == "MY_CUSTOM_VAR=custom_value" {
			foundCustom = true
		}
		if kv == "TAA_TASK_ID=task-test-123" {
			foundTaskID = true
		}
	}
	if !foundCustom || !foundTaskID {
		t.Fatalf("merged env missing expected variables: foundCustom=%v, foundTaskID=%v", foundCustom, foundTaskID)
	}
}
