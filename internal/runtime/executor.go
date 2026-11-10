package runtime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"

	"taa/internal/execenv"
)

// RunRuntimeConfig executes the runtimeConfig command sequence locally.
func RunRuntimeConfig(cfg RuntimeConfig, env map[string]string, modelDir, dataDir, outputDir, taskID, startedAt string) (string, error) {
	return RunRuntimeConfigWithControl(nil, cfg, env, modelDir, dataDir, outputDir, taskID, startedAt)
}

// RunRuntimeConfigWithControl executes the runtimeConfig locally under a
// controllable lifecycle. It is the local target's entry point: the target
// prepares the environment and then runs it.
func RunRuntimeConfigWithControl(control ProcessController, cfg RuntimeConfig, env map[string]string, modelDir, dataDir, outputDir, taskID, startedAt string) (string, error) {
	target := execenv.NewLocalTarget()
	spec := execenv.Spec{ModelDir: modelDir, DataDir: dataDir, OutputDir: outputDir}
	if err := target.Prepare(context.Background(), spec); err != nil {
		return "", err
	}
	return RunRuntimeConfigWithTarget(control, target, cfg, env, modelDir, dataDir, outputDir, taskID, startedAt)
}

// RunRuntimeConfigWithTarget executes the runtimeConfig through the given
// target. The directories are the ones the executed process will see, so a
// caller using a non-local target resolves them first; the target's Prepare
// must already have run, because only it knows how to create them in its own
// view. The legacy entry points above wrap this with LocalTarget.
func RunRuntimeConfigWithTarget(control ProcessController, target execenv.Target, cfg RuntimeConfig, env map[string]string, modelDir, dataDir, outputDir, taskID, startedAt string) (string, error) {
	if target == nil {
		return "", fmt.Errorf("runtimeConfig execution target is not set")
	}
	if isNilControl(control) {
		control = nil
	}
	if control != nil && control.IsCancelled() {
		return "", context.Canceled
	}

	commandLine := strings.Join(ResolveRuntimeCommands(cfg.Commands, dataDir, outputDir), " && ")
	ctx := context.Background()
	if control != nil {
		ctx = control.Ctx()
	}

	cmd := target.Command(ctx, commandLine, modelDir)
	cmd.Env = MergedRuntimeEnv(ResolveRuntimeEnv(env, dataDir, outputDir), map[string]string{
		"TAA_TASK_ID":          taskID,
		"TAA_STARTED_AT":       startedAt,
		"TAA_DATA_DIR":         dataDir,
		"TAA_INPUT_DIR":        dataDir,
		"TAA_MODEL_INPUT_DIR":  dataDir,
		"TAA_MODEL_OUTPUT_DIR": outputDir,
		"TAA_OUTPUT_DIR":       outputDir,
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
