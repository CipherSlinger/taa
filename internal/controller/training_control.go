package controller

import (
	"context"
	"os/exec"
	"sync"
	"taa/internal/runtime"
)

// trainingControl 兼容包装器，实现 runtime.ProcessController 接口
type trainingControl struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	cmd        *exec.Cmd
	cancelled  bool
	done       chan struct{}
	finishOnce sync.Once
}

var _ runtime.ProcessController = (*trainingControl)(nil)

func newTrainingControl() *trainingControl {
	ctx, cancel := context.WithCancel(context.Background())
	return &trainingControl{
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
}

func (c *trainingControl) Ctx() context.Context {
	if c == nil {
		return context.Background()
	}
	return c.ctx
}

func (c *trainingControl) Done() <-chan struct{} {
	if c == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return c.done
}

func (c *trainingControl) IsCancelled() bool {
	return c.isCancelled()
}

func (c *trainingControl) isCancelled() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancelled
}

func (c *trainingControl) RequestStop() *exec.Cmd {
	return c.requestStop()
}

func (c *trainingControl) requestStop() *exec.Cmd {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cancelled = true
	c.cancel()
	return c.cmd
}

func (c *trainingControl) StartCommand(cmd *exec.Cmd) error {
	return c.startCommand(cmd)
}

func (c *trainingControl) startCommand(cmd *exec.Cmd) error {
	if c == nil {
		if cmd != nil {
			return cmd.Start()
		}
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancelled {
		return context.Canceled
	}

	c.cmd = cmd
	if err := cmd.Start(); err != nil {
		c.cmd = nil
		return err
	}
	return nil
}

func (c *trainingControl) ClearCommand(cmd *exec.Cmd) {
	c.clearCommand(cmd)
}

func (c *trainingControl) clearCommand(cmd *exec.Cmd) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cmd == cmd {
		c.cmd = nil
	}
}

// currentCommand returns the process bound to this handle, or nil when none is
// bound. The field is cleared right after the process exits and is reaped
// (ClearCommand follows Wait), so nil means the process is gone even while the
// pipeline around it is still unwinding. The stop path uses that difference to
// tell "cleanup is slow" from "the process survived SIGKILL".
func (c *trainingControl) currentCommand() *exec.Cmd {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmd
}

func (c *trainingControl) Finish() {
	c.finish()
}

// finish releases anyone waiting on done. A cancelled task that never started a
// process finishes here too, so a stop answered with no process to kill does not
// leave requestStop's cancel context unreleased.
func (c *trainingControl) finish() {
	if c == nil {
		return
	}
	c.finishOnce.Do(func() {
		c.cancel()
		close(c.done)
	})
}
