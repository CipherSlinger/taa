package runtime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
)

// RunRuntimeConfig 在目标环境下执行运行配置命令序列
func RunRuntimeConfig(cfg RuntimeConfig, env map[string]string, modelDir, dataDir, outputDir, taskID, startedAt string) (string, error) {
	return RunRuntimeConfigWithControl(nil, cfg, env, modelDir, dataDir, outputDir, taskID, startedAt)
}

// RunRuntimeConfigWithControl 支持受控生命周期的运行配置执行器
func RunRuntimeConfigWithControl(control ProcessController, cfg RuntimeConfig, env map[string]string, modelDir, dataDir, outputDir, taskID, startedAt string) (string, error) {
	if isNilControl(control) {
		control = nil
	}
	if control != nil && control.IsCancelled() {
		return "", context.Canceled
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	commandLine := strings.Join(ResolveRuntimeCommands(cfg.Commands, dataDir, outputDir), " && ")
	ctx := context.Background()
	if control != nil {
		ctx = control.Ctx()
	}

	checkpointDir := "/opt/taa/checkpoint"
	if v, ok := env["TAA_CHECKPOINT_DIR"]; ok && strings.TrimSpace(v) != "" {
		checkpointDir = strings.TrimSpace(v)
	} else if v, ok := env["TAA_MODEL_CHECKPOINT_DIR"]; ok && strings.TrimSpace(v) != "" {
		checkpointDir = strings.TrimSpace(v)
	} else if v, ok := env["CIPHERFLOW_CHECKPOINT_DIR"]; ok && strings.TrimSpace(v) != "" {
		checkpointDir = strings.TrimSpace(v)
	}

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", commandLine)
	// Set Setpgid: true to ensure an independent process group for full SIGKILL cascading cleanup
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Dir = modelDir
	cmd.Env = MergedRuntimeEnv(ResolveRuntimeEnv(env, dataDir, outputDir), map[string]string{
		"TAA_TASK_ID":               taskID,
		"TAA_STARTED_AT":            startedAt,
		"TAA_DATA_DIR":              dataDir,
		"TAA_INPUT_DIR":             dataDir,
		"TAA_MODEL_INPUT_DIR":       dataDir,
		"TAA_MODEL_OUTPUT_DIR":      outputDir,
		"TAA_OUTPUT_DIR":            outputDir,
		"TAA_CHECKPOINT_DIR":        checkpointDir,
		"TAA_MODEL_CHECKPOINT_DIR":  checkpointDir,
		"CIPHERFLOW_CHECKPOINT_DIR": checkpointDir,
	})

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if control != nil {
		if err := control.StartCommand(cmd); err != nil {
			return "", err
		}
		defer control.ClearCommand(cmd)
	} else if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("runtimeConfig command exited with error: %w", err)
	}

	err := cmd.Wait()
	if control != nil && control.IsCancelled() {
		return output.String(), context.Canceled
	}
	if err != nil {
		return output.String(), fmt.Errorf("runtimeConfig command exited with error: %w", err)
	}
	return output.String(), nil
}

func isNilControl(c ProcessController) bool {
	if c == nil {
		return true
	}
	v := reflect.ValueOf(c)
	return (v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface) && v.IsNil()
}

// MergedRuntimeEnv 合并当前进程环境变量与自定义业务环境变量
func MergedRuntimeEnv(userEnv, systemEnv map[string]string) []string {
	merged := map[string]string{}
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			merged[key] = value
		}
	}
	for k, v := range userEnv {
		merged[k] = v
	}
	for k, v := range systemEnv {
		merged[k] = v
	}
	result := make([]string, 0, len(merged))
	for k, v := range merged {
		result = append(result, k+"="+v)
	}
	return result
}
