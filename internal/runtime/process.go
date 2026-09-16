package runtime

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"syscall"
)

// ProcessController 定义受控子进程的生命周期管理接口
type ProcessController interface {
	Ctx() context.Context
	Done() <-chan struct{}
	IsCancelled() bool
	RequestStop() *exec.Cmd
	StartCommand(cmd *exec.Cmd) error
	ClearCommand(cmd *exec.Cmd)
	Finish()
}

// TrainingControl 维护训练子进程生命周期与异步取消控制
type TrainingControl struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	cmd        *exec.Cmd
	cancelled  bool
	done       chan struct{}
	finishOnce sync.Once
}

// NewTrainingControl 创建新的训练控制句柄
func NewTrainingControl() *TrainingControl {
	ctx, cancel := context.WithCancel(context.Background())
	return &TrainingControl{
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
}

// Ctx 返回控制上下文
func (c *TrainingControl) Ctx() context.Context {
	if c == nil {
		return context.Background()
	}
	return c.ctx
}

// Done 返回完成通道
func (c *TrainingControl) Done() <-chan struct{} {
	if c == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return c.done
}

// IsCancelled 检查当前是否已被取消
func (c *TrainingControl) IsCancelled() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancelled
}

// RequestStop 发起终止请求，触发上下文取消并返回当前绑定的进程指针
func (c *TrainingControl) RequestStop() *exec.Cmd {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cancelled = true
	c.cancel()
	return c.cmd
}

// StartCommand 启动命令并与当前控制器安全绑定
func (c *TrainingControl) StartCommand(cmd *exec.Cmd) error {
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

// ClearCommand 清除进程绑定引用
func (c *TrainingControl) ClearCommand(cmd *exec.Cmd) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cmd == cmd {
		c.cmd = nil
	}
}

// CurrentCmd 返回当前正在执行的进程命令（并发安全）
func (c *TrainingControl) CurrentCmd() *exec.Cmd {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmd
}

// Finish 标记训练执行结束，关闭 done 通道
func (c *TrainingControl) Finish() {
	if c == nil {
		return
	}
	c.finishOnce.Do(func() {
		close(c.done)
	})
}

// KillProcessGroup 级联清理进程及其所属的整个独立进程组（负 PID 发送 SIGKILL）
func KillProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return nil
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
