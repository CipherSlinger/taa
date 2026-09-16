package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"taa/internal/runtime"
	"taa/internal/store"
	"taa/pkg/utils"
)

const maxCrashRecoveryAttempts = 3

// ReconcileCrashRecovery 执行启动崩溃自愈流水线（规则 1~9）
func (c *Coordinator) ReconcileRecovery(ctx context.Context) error {
	if c.stateStore == nil {
		return nil
	}
	persistent, err := c.stateStore.UnsealState()
	if err != nil {
		return fmt.Errorf("unseal persistent state during recovery: %w", err)
	}
	if persistent == nil || persistent.ActiveTask == nil {
		return nil
	}

	activeTask := persistent.ActiveTask
	taskID := activeTask.TaskID
	requestID := activeTask.RequestID
	log.Printf("[RECOVERY] 发现异常中断的在飞任务: taskId=%s, requestId=%s, type=%s, attempts=%d",
		taskID, requestID, activeTask.Type, activeTask.RecoveryAttempts)

	// ------------------------------------------------------------------------
	// 规约 3 熔断保护 (Circuit Breaker)
	// ------------------------------------------------------------------------
	if activeTask.RecoveryAttempts >= maxCrashRecoveryAttempts {
		log.Printf("[RECOVERY CIRCUIT BREAKER] 任务 %s 连续自愈失败达到上限 (%d 次)，归档死信队列并复位",
			taskID, activeTask.RecoveryAttempts)
		c.archiveDeadLetter(activeTask)
		persistent.ActiveTask = nil
		_ = c.stateStore.SealState(persistent)
		c.taskManager.SetActiveTask(nil)
		c.phaseState.SetCurrentOp("idle")
		return nil
	}

	// 自愈次数递增并立即持久化，防止自愈自身崩溃导致死循环
	activeTask.RecoveryAttempts++
	_ = c.stateStore.SealState(persistent)

	// ------------------------------------------------------------------------
	// 规约 1 安全隔离：若为 model_import 崩溃，强制物理清空模型目录
	// ------------------------------------------------------------------------
	if activeTask.Type == "model_import" {
		log.Printf("[RECOVERY SEC-ISOLATION] 清理未审计代码目录: %s", c.security.ModelDir)
		_ = os.RemoveAll(c.security.ModelDir)
		_ = os.MkdirAll(c.security.ModelDir, 0o755)
		c.phaseState.SetModelImported(false, "")
	}

	// ------------------------------------------------------------------------
	// 规约 6 脏环境清理：清空输入/输出目录与 /tmp 临时碎片
	// ------------------------------------------------------------------------
	_ = os.RemoveAll(c.security.GetModelInputDir())
	_ = os.MkdirAll(c.security.GetModelInputDir(), 0o755)
	_ = os.RemoveAll(c.security.GetModelOutputDir())
	_ = os.MkdirAll(c.security.GetModelOutputDir(), 0o755)
	c.cleanTempFragments()

	// ------------------------------------------------------------------------
	// 规约 6/9 孤儿进程回收：扫描并杀灭孤儿训练进程
	// ------------------------------------------------------------------------
	c.killOrphanProcesses()

	// ------------------------------------------------------------------------
	// 规约 4 索引清洗与黑匣子归档
	// ------------------------------------------------------------------------
	resultDir := filepath.Join(c.security.ResultDir, fmt.Sprintf("%s_%s", requestID, taskID))
	if c.indexStore != nil {
		_ = c.indexStore.Purge(requestID, taskID)
	}
	if _, err := os.Stat(resultDir); err == nil {
		archiveDir := filepath.Join(filepath.Dir(resultDir), fmt.Sprintf(".failed-%s-%d", taskID, time.Now().Unix()))
		_ = os.Rename(resultDir, archiveDir)
		resultDir = archiveDir
	}
	_ = os.MkdirAll(resultDir, 0o755)

	// ------------------------------------------------------------------------
	// 规约 5 产物规范补齐：生成标准 Schema 1.0 失败占位报告
	// ------------------------------------------------------------------------
	startedAt := activeTask.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC().Add(-1 * time.Minute)
	}
	finishedAt := time.Now().UTC()
	crashReport, _ := runtime.BuildCrashFailureReport(
		taskID,
		startedAt,
		finishedAt,
		"TAA 异常崩溃重启，执行已被安全终止 (Process Interrupted by Crash)",
		c.phaseState.ModelChecksum(),
		c.phaseState.DataChecksum(),
	)
	_ = utils.WriteJSONFile(filepath.Join(resultDir, "training_report.json"), crashReport, 0o644)

	// ------------------------------------------------------------------------
	// 规约 7 双轨补偿投递：前置同步极速通道(2s) + 后台容错退避重试
	// ------------------------------------------------------------------------
	c.dispatchCompensatoryReport(requestID, taskID, crashReport)

	// ------------------------------------------------------------------------
	// 规约 8 任务解封与状态复位
	// ------------------------------------------------------------------------
	persistent.ActiveTask = nil
	_ = c.stateStore.SealState(persistent)
	c.taskManager.SetActiveTask(nil)
	c.phaseState.SetCurrentOp("idle")

	log.Printf("[RECOVERY] 任务 %s 崩溃自愈流程完成，状态已成功重置", taskID)
	return nil
}

func (c *Coordinator) archiveDeadLetter(task *store.ActiveTaskSnapshot) {
	deadLetterPath := filepath.Join(c.security.ResultDir, fmt.Sprintf(".dead-letter-%s-%d.json", task.TaskID, time.Now().Unix()))
	_ = utils.WriteJSONFile(deadLetterPath, task, 0o644)
}

func (c *Coordinator) cleanTempFragments() {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "taa-download-") || strings.HasPrefix(name, "extract-") || strings.HasSuffix(name, ".extract") {
			_ = os.RemoveAll(filepath.Join(os.TempDir(), name))
		}
	}
}

func (c *Coordinator) killOrphanProcesses() {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	selfPid := os.Getpid()
	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == selfPid {
			continue
		}
		cmdlineBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		cmdline := string(cmdlineBytes)
		if strings.Contains(cmdline, "python") || strings.Contains(cmdline, "torch") || strings.Contains(cmdline, "train.py") {
			log.Printf("[RECOVERY] 终止孤儿训练进程: pid=%d, cmd=%s", pid, cmdline)
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

func (c *Coordinator) dispatchCompensatoryReport(requestID, taskID string, report map[string]any) {
	if c.platformClient == nil {
		return
	}

	reportJSON := ""
	if b, err := json.Marshal(report); err == nil {
		reportJSON = string(b)
	}

	// 同步极速通道 (2s 硬超时)
	fastCtx, fastCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer fastCancel()

	err := c.platformClient.ReportRes(fastCtx, requestID, taskID, 1, "TAA 异常崩溃重启，执行已被安全终止", reportJSON)
	if err == nil {
		log.Printf("[RECOVERY REPORT] 同步极速上报成功: taskId=%s", taskID)
		return
	}

	// 离线后台退避通道 (最多 60s)
	go func() {
		log.Printf("[RECOVERY REPORT] 切换至离线后台退避重试: taskId=%s", taskID)
		backoff := 2 * time.Second
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(backoff)
			retryCtx, retryCancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := c.platformClient.ReportRes(retryCtx, requestID, taskID, 1, "TAA 异常崩溃重启，执行已被安全终止", reportJSON)
			retryCancel()
			if err == nil {
				log.Printf("[RECOVERY REPORT] 离线后台重试成功: taskId=%s", taskID)
				return
			}
			backoff *= 2
			if backoff > 15*time.Second {
				backoff = 15 * time.Second
			}
		}
		log.Printf("[RECOVERY REPORT] 离线后台重试超时放弃: taskId=%s", taskID)
	}()
}
