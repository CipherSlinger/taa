package controller

import (
	"context"
	"fmt"
	"strings"

	"taa/internal/config"
	"taa/internal/deployment"
	"taa/internal/execenv"
)

// discoverContainer is execenv.Discover by default. It is a variable so a test
// can decide the outcome without a container being present; production never
// replaces it.
var discoverContainer = execenv.Discover

// selectExecutionTarget decides where one training run executes.
//
// It runs per task, not at startup, because on an initrd deployment the
// container does not exist yet when TAA starts: the guest init launches TAA
// before kata-agent, and the container is created later. A target discovered at
// startup would therefore always be absent on exactly the deployment the seam
// exists for.
//
// The policy is read from the startup config and the deployment shape; the mode
// is reported on the platform log channel every time, because "the model ran in
// the wrong place" is the first thing to check when a task misbehaves, and the
// container is never named anywhere else.
func (s *TAAState) selectExecutionTarget(ctx context.Context) (execenv.Target, error) {
	if injected := s.injectedExecutionTarget(); injected != nil {
		return injected, nil
	}

	exec := s.Security.Execution
	mode := strings.ToLower(strings.TrimSpace(exec.Mode))
	if mode == "" {
		mode = config.ExecutionModeAuto
	}
	shape := s.Deployment().Shape

	if mode == config.ExecutionModeLocal {
		s.Logs.Add(LogInfo, "exec", "模型执行环境: local (mode=local, deployment=%s)", shape)
		return execenv.NewLocalTarget(), nil
	}
	if mode != config.ExecutionModeAuto && mode != config.ExecutionModeContainer {
		// The configuration layer rejects this at startup; reaching it means the
		// state was built by something other than the daemon.
		return nil, fmt.Errorf("未知的模型执行模式 %q", mode)
	}
	if mode == config.ExecutionModeAuto && shape != deployment.Initrd {
		s.Logs.Add(LogInfo, "exec", "模型执行环境: local (mode=auto, deployment=%s: 非 initrd 部署)", shape)
		return execenv.NewLocalTarget(), nil
	}

	paths := executionPaths(exec)
	target, err := discoverContainer(ctx, execenv.Options{
		ContainerID: exec.ContainerID,
		Paths:       paths,
	})
	if err != nil {
		if mode == config.ExecutionModeContainer {
			s.Logs.Add(LogError, "exec",
				"模型执行环境: 未找到可用容器，mode=container 要求容器执行，任务失败: %v", err)
			return nil, err
		}
		s.Logs.Add(LogWarn, "exec",
			"模型执行环境: 未找到可用容器，auto 模式回退到 local 执行。若模型依赖镜像内的解释器，本次任务可能失败: %v", err)
		return execenv.NewLocalTarget(), nil
	}

	s.Logs.Add(LogInfo, "exec",
		"模型执行环境: container (pid=%d, rootfs=%s, 契约路径: model=%s input=%s output=%s log=%s progress=%s)",
		target.PID(), target.RootFS(),
		paths.ModelDir, paths.InputDir, paths.OutputDir, paths.LogDir, paths.ProgressPath)
	return target, nil
}

// executionPaths turns the configured overrides into the container-side
// contract. An empty override keeps the packaged default, so a deployment that
// says nothing executes against the same paths every image ships.
func executionPaths(exec config.ExecutionConfig) execenv.Paths {
	paths := execenv.DefaultContainerPaths()
	for _, field := range []struct {
		dst *string
		src string
	}{
		{&paths.ModelDir, exec.ModelDir},
		{&paths.InputDir, exec.InputDir},
		{&paths.OutputDir, exec.OutputDir},
		{&paths.LogDir, exec.LogDir},
		{&paths.ProgressPath, exec.ProgressPath},
	} {
		if trimmed := strings.TrimSpace(field.src); trimmed != "" {
			*field.dst = trimmed
		}
	}
	return paths
}
