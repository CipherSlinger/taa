package taa

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

	"taa/internal/controller"
	"taa/pkg/utils"
)

// maxCrashRecoveryAttempts 自愈熔断阈值（连续失败达 3 次触发熔断）
const maxCrashRecoveryAttempts = 3

// reconcileCrashRecovery 实现启动自愈（Fast-Fail）完备机制与二次崩溃熔断保护流水线。
// 当 TAA 冷启动发现持久化存储中存在 RUNNING 状态的在飞任务时触发执行：
//
// 1. 规约 3 熔断保护：若 activeTask.RecoveryAttempts >= 3，归档为 .dead-letter 并清除任务，复位退出；
// 2. 规约 1 安全隔离：若为 model_import 崩溃，强制物理清空 modelDir 未审计代码并重置 ModelImported = false；
// 3. 规约 6 脏环境清理：清空输入输出目录，扫描清除 /tmp/taa-download-* 与 /tmp/*.extract-* 残留碎片；
// 4. 规约 6/9 孤儿进程回收：扫描并杀灭残留的训练孤儿进程树（python/torch等），释放 GPU 显存；
// 5. 规约 4 索引清洗与归档：调用 Purge 清除孤儿索引，重命名产物目录为 .failed-<taskId>-<timestamp> 黑匣子留存；
// 6. 规约 5 产物规范补齐：调用 controller.BuildCrashFailureReport 生成标准 Schema 1.0 占位报告并落盘；
// 7. 规约 7 双轨补偿投递：前置同步极速通道(2s硬超时) + 离线后台容错重试(指数退避最多60s)，不阻塞启动；
// 8. 规约 7/8 任务解封与状态复位：持久化擦除 ActiveTask 并密封落盘，内存复位 CurrentOp = idle。
func reconcileCrashRecovery(ctx context.Context, state *controller.TAAState, store *controller.StateStore, activeTask *controller.ActiveTaskSnapshot) error {
	if activeTask == nil {
		return nil
	}

	taskID := activeTask.TaskID
	requestID := activeTask.RequestID
	log.Printf("[RECOVERY] starting crash recovery reconciliation: taskId=%s, requestId=%s, type=%s, attempts=%d",
		taskID, requestID, activeTask.Type, activeTask.RecoveryAttempts)

	// ------------------------------------------------------------------------
	// 规约 3 熔断保护 (Circuit Breaker)
	// ------------------------------------------------------------------------
	if activeTask.RecoveryAttempts >= maxCrashRecoveryAttempts {
		log.Printf("[RECOVERY CIRCUIT BREAKER] task %s reached max recovery attempts (%d), archiving to dead-letter",
			taskID, activeTask.RecoveryAttempts)
		if state != nil && state.Logs != nil {
			state.Logs.Add(controller.LogError, "recovery",
				"自愈熔断保护触发: 任务 %s 连续自愈失败达 %d 次，隔离至死信队列", taskID, activeTask.RecoveryAttempts)
		}

		deadLetterDir := activeTask.ResultDir
		if deadLetterDir == "" && state != nil {
			deadLetterDir = state.Security.ResultDir
		}
		if deadLetterDir != "" {
			deadLetterPath := filepath.Join(deadLetterDir, fmt.Sprintf(".dead-letter-%s.json", taskID))
			payload := map[string]any{
				"task":        activeTask,
				"archived_at": utils.FormatISO8601(time.Now()),
				"reason":      "recovery attempts exceeded limit (circuit breaker tripped)",
			}
			if err := utils.WriteJSONFile(deadLetterPath, payload, 0o600); err != nil {
				log.Printf("WARNING: write dead-letter file %s failed: %v", deadLetterPath, err)
			} else {
				log.Printf("[RECOVERY CIRCUIT BREAKER] dead-letter archived to %s", deadLetterPath)
			}
		}

		// 内存状态复位并密封落盘
		resetRecoveryTaskState(state, store)
		return nil
	}

	// 未达到熔断阈值，自愈尝试计数原子累加并先落盘持久化
	activeTask.RecoveryAttempts++
	if store != nil {
		if pState := store.GetState(); pState != nil {
			pState.ActiveTask = activeTask
			if err := store.SealState(pState); err != nil {
				log.Printf("WARNING: update recovery attempts seal failed: %v", err)
			}
		}
	}

	// ------------------------------------------------------------------------
	// 规约 1 安全隔离 (Model Import Security Isolation)
	// ------------------------------------------------------------------------
	if activeTask.Type == "model_import" {
		if state != nil {
			if state.Security.ModelDir != "" {
				log.Printf("[RECOVERY] cleaning un-audited code directory: %s", state.Security.ModelDir)
				if err := utils.CleanDir(state.Security.ModelDir); err != nil {
					log.Printf("WARNING: clean model dir %s failed: %v", state.Security.ModelDir, err)
				}
			}
			state.UpdateImportState(true, false, activeTask.Phase)
		}
	}

	// ------------------------------------------------------------------------
	// 规约 6 脏环境清理 (Dirty Environment Cleanup)
	// ------------------------------------------------------------------------
	inputDir := "/opt/taa/input"
	outputDir := "/opt/taa/output"
	if state != nil {
		if d := state.Security.GetModelInputDir(); d != "" {
			inputDir = d
		}
		if d := state.Security.GetModelOutputDir(); d != "" {
			outputDir = d
		}
	}
	if err := utils.CleanDir(inputDir); err != nil {
		log.Printf("WARNING: clean input dir %s failed: %v", inputDir, err)
	}
	if err := utils.CleanDir(outputDir); err != nil {
		log.Printf("WARNING: clean output dir %s failed: %v", outputDir, err)
	}
	cleanTempFragments()

	// ------------------------------------------------------------------------
	// 规约 6/9 孤儿进程回收 (Orphan Process Reclamation)
	// ------------------------------------------------------------------------
	killOrphanTrainingProcesses()

	// ------------------------------------------------------------------------
	// 规约 4 索引清洗与归档 (Import Index Purge & Blackbox Archival)
	// ------------------------------------------------------------------------
	var archivedResultDir string
	if state != nil {
		if indexStore, err := state.ImportIndexStore(); err == nil && indexStore != nil {
			if purgeErr := indexStore.Purge(activeTask.RequestID, activeTask.TaskID); purgeErr != nil {
				log.Printf("WARNING: purge import index record failed: %v", purgeErr)
			}
		}
	}

	if activeTask.ResultDir != "" {
		tID := activeTask.TaskID
		if tID == "" {
			tID = activeTask.RequestID
		}
		if fi, err := os.Stat(activeTask.ResultDir); err == nil && fi.IsDir() {
			if archiveDir, err := utils.ArchiveFailedDir(activeTask.ResultDir, tID); err == nil && archiveDir != "" {
				archivedResultDir = archiveDir
				log.Printf("[RECOVERY] archived failed result dir to blackbox: %s", archiveDir)
			} else {
				archivedResultDir = activeTask.ResultDir
			}
		} else {
			// 若 ResultDir 已被 Purge 重命名，寻找其生成的 .failed-<taskId>-* 归档黑匣子目录
			parentDir := filepath.Dir(activeTask.ResultDir)
			matches, _ := filepath.Glob(filepath.Join(parentDir, fmt.Sprintf(".failed-%s-*", tID)))
			if len(matches) > 0 {
				archivedResultDir = matches[len(matches)-1]
				log.Printf("[RECOVERY] detected existing blackbox archive dir: %s", archivedResultDir)
			}
		}
	}

	// ------------------------------------------------------------------------
	// 规约 5 产物规范补齐 (Placeholder Report Generation)
	// ------------------------------------------------------------------------
	var modelChecksum, dataChecksum map[string]any
	if state != nil {
		modelChecksum = state.GetModelChecksum()
		dataChecksum = state.GetDataChecksum()
	}
	startedAt := activeTask.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	finishedAt := time.Now().UTC()
	failureReason := "TAA 异常崩溃重启，执行已被安全终止 (Process Interrupted by Crash)"

	reportMap, err := controller.BuildCrashFailureReport(activeTask.TaskID, startedAt, finishedAt, failureReason, modelChecksum, dataChecksum)
	var reportJSON string
	if err == nil && reportMap != nil {
		if b, mErr := json.Marshal(reportMap); mErr == nil {
			reportJSON = string(b)
		}
	}
	if reportJSON == "" {
		reportJSON = fmt.Sprintf(`{"schema_version":"1.0","training_task":{"task_id":%q,"status":"failed","exit_code":137,"failure_reason":%q}}`,
			activeTask.TaskID, failureReason)
	}

	// 报告应保存至黑匣子归档目录（若存在），否则保存至 ResultDir
	targetReportDir := archivedResultDir
	if targetReportDir == "" {
		targetReportDir = activeTask.ResultDir
	}
	if targetReportDir == "" && state != nil && state.Security.ResultDir != "" {
		targetReportDir = state.Security.ResultDir
	}

	if targetReportDir != "" && reportMap != nil {
		reportFile := filepath.Join(targetReportDir, "training_report.json")
		if writeErr := utils.WriteJSONFile(reportFile, reportMap, 0o644); writeErr != nil {
			log.Printf("WARNING: write training_report.json to %s failed: %v", reportFile, writeErr)
		} else {
			log.Printf("[RECOVERY] generated standard crash report at %s", reportFile)
		}
	}

	// ------------------------------------------------------------------------
	// 规约 7 双轨补偿投递 (Dual-Track Drain: Fast-Sync + Detached-Async)
	// ------------------------------------------------------------------------
	platformIP := ""
	dockerID := ""
	if state != nil {
		platformIP = state.PlatformIP
		dockerID = state.DockerID
	}

	if platformIP != "" && dockerID != "" && (activeTask.RequestID != "" || activeTask.TaskID != "") {
		fastSyncCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		msg := "TAA 异常崩溃重启，训练执行已被安全终止，请重新下发"
		if activeTask.Type == "model_import" {
			msg = "TAA 异常崩溃重启，模型导入与代码审计中断，请重新下发"
		}
		syncErr := controller.ReportTaskOutcome(fastSyncCtx, platformIP, dockerID, activeTask.RequestID, activeTask.TaskID, activeTask.Type, 1, msg, reportJSON)
		cancel()

		if syncErr != nil {
			log.Printf("[RECOVERY FAST-SYNC] fast-sync report failed or timed out: %v; dispatching to detached background worker", syncErr)
			dispatchDetachedCompensationWorker(platformIP, dockerID, activeTask.RequestID, activeTask.TaskID, activeTask.Type, reportJSON)
		} else {
			log.Printf("[RECOVERY FAST-SYNC] fast-sync report succeeded for task %s", activeTask.TaskID)
		}
	}

	// ------------------------------------------------------------------------
	// 规约 7 任务解封与落盘 + 规约 8 状态复位
	// ------------------------------------------------------------------------
	resetRecoveryTaskState(state, store)

	log.Printf("[RECOVERY] crash recovery reconciliation completed for task %s", taskID)
	return nil
}

func resetRecoveryTaskState(state *controller.TAAState, store *controller.StateStore) {
	if state != nil {
		state.ResetActiveTask()
	} else if store != nil {
		if pState := store.GetState(); pState != nil {
			pState.ActiveTask = nil
			pState.TrainingRunning = false
			if err := store.SealState(pState); err != nil {
				log.Printf("WARNING: seal state after crash recovery failed: %v", err)
			}
		}
	}
}

// cleanTempFragments 扫描清除 /tmp/taa-download-* 与 /tmp/*.extract-* 残留碎片文件
func cleanTempFragments() {
	patterns := []string{
		filepath.Join(os.TempDir(), "taa-download-*"),
		filepath.Join(os.TempDir(), "*.extract-*"),
		"/tmp/taa-download-*",
		"/tmp/*.extract-*",
	}
	seen := make(map[string]struct{})
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			if removeErr := os.RemoveAll(match); removeErr == nil {
				log.Printf("[RECOVERY] cleaned temp fragment: %s", match)
			}
		}
	}
}

// killOrphanTrainingProcesses 扫描并杀灭残留的训练孤儿进程树（如 python/torch 脚本进程），释放 GPU 显存
func killOrphanTrainingProcesses() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	myPID := os.Getpid()
	myPPID := os.Getppid()

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == myPID || pid == myPPID {
			continue
		}

		cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		cmdline := string(cmdlineBytes)
		cmdlineLower := strings.ToLower(cmdline)

		// 排除操作系统自带的系统管理守护服务
		if strings.Contains(cmdlineLower, "networkd-dispatcher") ||
			strings.Contains(cmdlineLower, "unattended-upgrade") ||
			strings.Contains(cmdlineLower, "systemd") ||
			strings.Contains(cmdlineLower, "cloud-init") {
			continue
		}

		// 匹配训练相关进程特征（PyTorch, Torchrun, 训练脚本, 或带显存计算命令）
		isTraining := strings.Contains(cmdlineLower, "torchrun") ||
			strings.Contains(cmdlineLower, "train.py") ||
			strings.Contains(cmdlineLower, "train_mock") ||
			strings.Contains(cmdlineLower, "python-mock-train") ||
			(strings.Contains(cmdlineLower, "python") && (strings.Contains(cmdlineLower, "torch") ||
				strings.Contains(cmdlineLower, "train") ||
				strings.Contains(cmdlineLower, "cuda") ||
				strings.Contains(cmdlineLower, "/opt/taa") ||
				strings.Contains(cmdlineLower, "models")))

		if !isTraining {
			continue
		}

		log.Printf("[RECOVERY] killing orphan training process: pid=%d, cmd=%s", pid, cmdline)
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Kill()
		}
		if pgid, err := syscall.Getpgid(pid); err == nil && pgid > 1 && pgid != myPID {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	}
}

// dispatchDetachedCompensationWorker 转交后台 goroutine 执行指数退避重试（最多持续 60 秒），自愈流水线不阻塞
func dispatchDetachedCompensationWorker(platformIP, dockerID, requestID, taskID, taskType, reportJSON string) {
	go func() {
		deadline := time.Now().Add(60 * time.Second)
		backoff := 1 * time.Second
		maxBackoff := 8 * time.Second

		msg := "TAA 异常崩溃重启，训练执行已被安全终止，请重新下发"
		if taskType == "model_import" {
			msg = "TAA 异常崩溃重启，模型导入与代码审计中断，请重新下发"
		}

		for {
			if time.Now().After(deadline) {
				log.Printf("[DETACHED RECOVERY] compensation report timed out after 60s for task %s", taskID)
				return
			}

			reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := controller.ReportTaskOutcome(reqCtx, platformIP, dockerID, requestID, taskID, taskType, 1, msg, reportJSON)
			cancel()

			if err == nil {
				log.Printf("[DETACHED RECOVERY] compensation report succeeded for task %s", taskID)
				return
			}

			log.Printf("[DETACHED RECOVERY] compensation report retry failed: %v; next backoff=%v", err, backoff)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}()
}
