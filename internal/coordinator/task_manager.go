package coordinator

import (
	"fmt"
	"log"
	"sync"
	"time"

	"taa/internal/runtime"
	"taa/internal/store"
	pkgerrors "taa/pkg/errors"
)

// TaskManager 管理任务排他互斥锁、在飞状态快照与执行生命周期
type TaskManager struct {
	mu              sync.RWMutex
	tokenCounter    int64
	activeToken     int64
	activeTask      *store.ActiveTaskSnapshot
	trainingControl *runtime.TrainingControl
	trainingRunning bool
}

// NewTaskManager 创建任务管理器
func NewTaskManager() *TaskManager {
	return &TaskManager{}
}

// AcquireTaskLock 尝试获取排他任务锁，若已有任务在飞则返回 CodeConflict 错误
func (m *TaskManager) AcquireTaskLock(requestID, taskID, taskType string, phase int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeToken != 0 || m.activeTask != nil {
		currentTask := ""
		if m.activeTask != nil {
			currentTask = m.activeTask.TaskID
		}
		return 0, pkgerrors.New(pkgerrors.CodeConflict,
			fmt.Sprintf("当前已有任务正在执行中 (taskId=%s)，请等待完成后再提交", currentTask))
	}

	m.tokenCounter++
	token := m.tokenCounter
	m.activeToken = token
	m.activeTask = &store.ActiveTaskSnapshot{
		TaskID:           taskID,
		RequestID:        requestID,
		Type:             taskType,
		Phase:            phase,
		RecoveryAttempts: 0,
		StartedAt:        time.Now().UTC(),
	}
	if taskType == "training" {
		m.trainingRunning = true
	}
	return token, nil
}

// ReleaseTaskLock 释放排他任务锁
func (m *TaskManager) ReleaseTaskLock(token int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeToken == token {
		m.activeToken = 0
		m.activeTask = nil
		m.trainingRunning = false
		if m.trainingControl != nil {
			m.trainingControl.Finish()
			m.trainingControl = nil
		}
	}
}

// PromoteToTraining 将当前在飞的任务快照类型升级为 "training"
func (m *TaskManager) PromoteToTraining() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeTask == nil {
		return pkgerrors.New(pkgerrors.CodeInternal, "没有处于在飞状态的任务可提升为训练")
	}
	m.activeTask.Type = "training"
	m.trainingRunning = true
	return nil
}

// EnsureTrainingControl 获取或创建当前训练的中止控制句柄
func (m *TaskManager) EnsureTrainingControl() *runtime.TrainingControl {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.trainingControl == nil {
		m.trainingControl = runtime.NewTrainingControl()
	}
	return m.trainingControl
}

// StopTraining 主动发起停止训练操作并杀灭当前绑定的孤儿进程组
func (m *TaskManager) StopTraining() bool {
	m.mu.Lock()
	ctrl := m.trainingControl
	m.mu.Unlock()

	if ctrl == nil || ctrl.IsCancelled() {
		return false
	}
	cmd := ctrl.RequestStop()
	if cmd != nil {
		_ = runtime.KillProcessGroup(cmd)
	}
	return true
}

// GetActiveTask 获取当前在飞任务的只读快照副本
func (m *TaskManager) GetActiveTask() *store.ActiveTaskSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeTask == nil {
		return nil
	}
	cloned := *m.activeTask
	return &cloned
}

// SetActiveTask 覆盖恢复在飞任务快照（用于自愈或状态重建）
func (m *TaskManager) SetActiveTask(task *store.ActiveTaskSnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if task == nil {
		m.activeTask = nil
		m.activeToken = 0
		m.trainingRunning = false
		return
	}
	cloned := *task
	m.activeTask = &cloned
	m.tokenCounter++
	m.activeToken = m.tokenCounter
	if task.Type == "training" {
		m.trainingRunning = true
	}
}

// IsBusy 检查当前是否���任务正在执行
func (m *TaskManager) IsBusy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeToken != 0 || m.activeTask != nil
}

// IsTrainingRunning 检查当前是否正有训练任务在执行
func (m *TaskManager) IsTrainingRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.trainingRunning
}

// RunAsyncSafe 安全异步执行任务，内置 panic 捕获与自动释放锁保护
func (m *TaskManager) RunAsyncSafe(token int64, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[TASK PANIC RECOVERED] token=%d, panic: %v", token, r)
			}
			m.ReleaseTaskLock(token)
		}()
		fn()
	}()
}
