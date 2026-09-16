package controller

import (
	"context"
	"os/exec"
	"sync"
)

type trainingControl struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	cmd        *exec.Cmd
	cancelled  bool
	done       chan struct{}
	finishOnce sync.Once
}

func newTrainingControl() *trainingControl {
	ctx, cancel := context.WithCancel(context.Background())
	return &trainingControl{
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
}

func (c *trainingControl) isCancelled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancelled
}

func (c *trainingControl) requestStop() *exec.Cmd {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cancelled = true
	c.cancel()
	return c.cmd
}

func (c *trainingControl) startCommand(cmd *exec.Cmd) error {
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

func (c *trainingControl) clearCommand(cmd *exec.Cmd) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cmd == cmd {
		c.cmd = nil
	}
}

func (c *trainingControl) finish() {
	c.finishOnce.Do(func() {
		close(c.done)
	})
}
