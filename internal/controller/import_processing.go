package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"taa/internal/codeaudit"
	"taa/internal/resource"
	"taa/internal/runtime"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
	"taa/pkg/utils"

	"github.com/CipherSlinger/teellm"
)

func (s *TAAState) processImportedResource(req importRequest, phase int, isModel bool, ciphertextPath string, dataKey []byte) {
	startedAt := time.Now().UTC()
	PhaseSeparator(fmt.Sprintf("Phase %d Import: taskId=%s", phase, req.TaskID))
	s.Logs.Add(LogInfo, "import", "收到资源导入请求: taskId=%s, requestId=%s, phase=%d, isModel=%v", req.TaskID, req.RequestID, phase, isModel)

	defer os.Remove(ciphertextPath)

	StepSeparator("Decrypt")
	s.setCurrentOp("decrypting")
	var plaintextPath string
	var isDecrypted bool
	var err error
	if len(dataKey) > 0 {
		plaintextPath, isDecrypted, err = s.resolvePlaintextResourceWithDataKey(dataKey, ciphertextPath)
	} else {
		plaintextPath, isDecrypted, err = s.resolvePlaintextResource(req.ResourceURL, ciphertextPath, "decrypt")
	}
	if err != nil {
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, isModel, startedAt, err.Error())
		return
	}
	if isDecrypted {
		defer os.Remove(plaintextPath)
	}

	// An fhe instance hands the resolved resource straight to the FHE service
	// instead of the training pipeline. The branch sits here, after decryption, so
	// the two instance types share one download/decode path and one concurrency
	// gate, and diverge only in what they do with the bytes.
	if s.fheEnabled() {
		s.processImportedResourceFHE(req, phase, isModel, plaintextPath, startedAt)
		return
	}

	trainRecord := ImportIndexRecord{}
	if isModel {
		size, hash, err := teecrypto.HashFileSM3(plaintextPath)
		if err != nil {
			s.Logs.Add(LogError, "hash", "计算模型压缩包哈希失败: %v", err)
			s.setCurrentOp("idle")
			s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("计算模型压缩包哈希失败: %v", err))
			return
		}
		s.setModelChecksum(map[string]any{
			"size":      size,
			"algorithm": "sm3",
			"value":     hash,
		})
		s.Logs.Add(LogInfo, "hash", "计算模型压缩包哈希成功: %s (%d bytes)", hash, size)

		s.Logs.Add(LogInfo, "extract", "开始解压到: %s", s.Security.ModelDir)
		if err := extractArchiveToDir(s.Security.ModelDir, plaintextPath); err != nil {
			s.Logs.Add(LogError, "extract", "解压失败: %v", err)
			s.setCurrentOp("idle")
			s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("解压资源失败: %v", err))
			return
		}
		s.Logs.Add(LogInfo, "extract", "解压成功")

		// ── Stage 1: Report model import result immediately upon decompression ──
		checksum := map[string]any{
			"size":      size,
			"algorithm": "sm3",
			"value":     hash,
		}
		s.reportModelImportAsync(req.RequestID, req.TaskID, 0, "模型导入成功", checksum)

		// ── Stage 2: Record the model and the audit owed for it, then launch it ──
		// The model is recorded as imported and the audit as outstanding in one
		// sealed write: the audit runs in a goroutine that outlives this task, so
		// the on-disk marker is the only thing that can tell a later restart that
		// an audit was owed for this model and never reached a verdict.
		s.beginModelImportAndAudit(req, phase)

		// Decouples auditing from task pipeline so data import and training are not blocked.
		s.launchModelAudit(req)
		s.Logs.Add(LogInfo, "import", "阶段%d: 模型导入完成，代码审计已在后台异步启动（结论仅作参考），等待数据下发后执行训练: taskId=%s", phase, req.TaskID)
		s.setCurrentOp("idle")
		return
	} else {
		size, hash, err := teecrypto.HashFileSM3(plaintextPath)
		if err != nil {
			s.Logs.Add(LogError, "hash", "计算压缩包哈希失败: %v", err)
			s.setCurrentOp("idle")
			s.reportImportFailure(req, phase, false, startedAt, fmt.Sprintf("计算压缩包哈希失败: %v", err))
			return
		}
		s.setDataChecksum(map[string]any{
			"size":      size,
			"algorithm": "sm3",
			"value":     hash,
		})

		dataDir := dataDirForHash(s.Security.DataDir, hash)
		trainRecord = ImportIndexRecord{
			RequestID: req.RequestID,
			TaskID:    req.TaskID,
			Hash:      hash,
			DataDir:   dataDir,
			ResultDir: resultDirForRequestTask(s.Security.ResultDir, req.RequestID, req.TaskID),
			Phase:     phase,
		}

		extracted, err := ensureArchiveExtractedIntoDir(dataDir, plaintextPath)
		if err != nil {
			s.Logs.Add(LogError, "extract", "展开 hash 数据目录失败: %v", err)
			s.setCurrentOp("idle")
			s.reportImportFailure(req, phase, false, startedAt, fmt.Sprintf("展开 hash 数据目录失败: %v", err))
			return
		}
		if extracted {
			s.Logs.Add(LogInfo, "extract", "hash 数据目录创建完成: %s", dataDir)
		} else {
			s.Logs.Add(LogInfo, "extract", "hash 数据目录已存在，复用: %s", dataDir)
		}

		store, err := s.importIndexStore()
		if err != nil {
			s.Logs.Add(LogError, "index", "加载导入索引失败: %v", err)
			s.setCurrentOp("idle")
			s.reportImportFailure(req, phase, false, startedAt, fmt.Sprintf("加载导入索引失败: %v", err))
			return
		}
		if err := store.Commit(trainRecord); err != nil {
			s.Logs.Add(LogError, "index", "保存导入索引失败: %v", err)
			s.setCurrentOp("idle")
			s.reportImportFailure(req, phase, false, startedAt, fmt.Sprintf("保存导入索引失败: %v", err))
			return
		}
		s.saveDataSuccess(trainRecord)
		s.Logs.Add(LogInfo, "index", "导入索引写入成功: requestId=%s taskId=%s hash=%s", req.RequestID, req.TaskID, hash)
	}

	// 模型导入（带 URL）完成后，仅设置并保存模型就绪状态，绝不触发训练任务
	if isModel {
		s.Logs.Add(LogInfo, "import", "阶段%d: 模型导入与安全审计完成，等待数据下发后执行训练: taskId=%s", phase, req.TaskID)
		s.setCurrentOp("idle")
		return
	}

	// ── 只有下发数据时，才触发训练任务，并做前置准备条件检查 ──
	// 1. 检查模型是否已就绪及是否在飞
	s.mu.RLock()
	modelImported := s.ModelImported
	modelInProgress := (s.activeTask != nil && s.activeTask.Type == "model_import")
	isBusy := s.isTrainingBusyLocked()
	runtimeConfigRaw := s.RuntimeConfig
	s.mu.RUnlock()

	if !modelImported {
		s.Logs.Add(LogInfo, "import", "阶段%d: 数据导入完成，等待模型导入后执行训练", phase)
		s.setCurrentOp("idle")
		return
	}
	if modelInProgress {
		s.Logs.Add(LogInfo, "import", "阶段%d: 数据导入完成，模型仍在导入传输中，等待模型就绪后执行训练", phase)
		s.setCurrentOp("idle")
		return
	}
	if isBusy {
		s.Logs.Add(LogInfo, "import", "阶段%d: 数据导入完成，已有训练任务正在执行中，跳过重复触发训练", phase)
		s.setCurrentOp("idle")
		return
	}

	// 2. 检查运行配置 runtimeConfig 是否有效
	if strings.TrimSpace(runtimeConfigRaw) == "" {
		s.Logs.Add(LogError, "train", "runtimeConfig 不能为空")
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, false, startedAt, "runtimeConfig 不能为空")
		return
	}
	cfg, env, err := parseRuntimeConfig(runtimeConfigRaw)
	if err != nil {
		s.Logs.Add(LogError, "train", "%v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, false, startedAt, err.Error())
		return
	}
	if len(cfg.Commands) == 0 {
		s.Logs.Add(LogError, "train", "runtimeConfig.commands 不能为空")
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, false, startedAt, "runtimeConfig.commands 不能为空")
		return
	}

	// 3. 提升为训练独占任务
	if err := s.promoteCurrentTaskToTraining(); err != nil {
		s.Logs.Add(LogError, "train", "提升为训练任务失败: %v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, false, startedAt, err.Error())
		return
	}

	trainRecord, _ = s.resolveTrainingRecord(req, false)
	trainReq := req
	if trainReq.TaskID == "" {
		if trainRecord.TaskID != "" {
			trainReq.TaskID = trainRecord.TaskID
		} else if trainReq.RequestID != "" {
			trainReq.TaskID = trainReq.RequestID
		}
	}
	if trainReq.RequestID == "" && trainRecord.RequestID != "" {
		trainReq.RequestID = trainRecord.RequestID
	}

	// The import phase holds the whole ciphertext and its plaintext in memory at
	// once. Both are garbage by now -- the decrypt helpers drop their references
	// before returning -- but Go only reclaims them at its next GC trigger, and the
	// trainer runs as a child process whose allocations never trigger this one. A
	// forced GC plus a return of the freed pages to the OS keeps the import peak
	// from overlapping the training peak in the same cgroup.
	debug.FreeOSMemory()
	s.Logs.Add(LogInfo, "import", "导入阶段结束，已释放导入占用的内存")

	s.executeTraining(trainReq, phase, trainRecord, cfg, env, startedAt)
}

func (s *TAAState) ensureTrainingControl(trainReq importRequest, phase int, trainRecord ImportIndexRecord, startedAt time.Time) *trainingControl {
	s.mu.Lock()
	defer s.mu.Unlock()

	control := s.trainingControl
	if control == nil {
		control = newTrainingControl()
		s.trainingControl = control
	}

	s.TrainingRunning = true
	s.CurrentOp = "training"
	if s.ActiveTaskID == "" {
		s.ActiveTaskID = trainReq.TaskID
	}
	if s.ActiveRequestID == "" {
		s.ActiveRequestID = trainReq.RequestID
	}

	if s.activeTask == nil {
		resultDir := trainRecord.ResultDir
		if resultDir == "" {
			resultDir = resultDirForRequestTask(s.Security.ResultDir, trainReq.RequestID, trainReq.TaskID)
		}
		if startedAt.IsZero() {
			startedAt = time.Now().UTC()
		}
		s.activeTask = &ActiveTaskSnapshot{
			RequestID: trainReq.RequestID,
			TaskID:    trainReq.TaskID,
			Type:      "training",
			Phase:     phase,
			Status:    "RUNNING",
			ResultDir: resultDir,
			StartedAt: startedAt.UTC(),
		}
	} else {
		s.activeTask.Type = "training"
		if s.activeTask.RequestID == "" {
			s.activeTask.RequestID = trainReq.RequestID
		}
		if s.activeTask.TaskID == "" {
			s.activeTask.TaskID = trainReq.TaskID
		}
		if s.activeTask.ResultDir == "" {
			s.activeTask.ResultDir = trainRecord.ResultDir
		}
	}

	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "训练控制状态持久化失败: %v", err)
	}
	return control
}

func (s *TAAState) finishTrainingControl(control *trainingControl) {
	if control == nil {
		return
	}

	s.mu.Lock()
	if s.trainingControl == control {
		s.trainingControl = nil
		s.activeTask = nil
		s.ActiveTaskID = ""
		s.ActiveRequestID = ""
		s.activeToken = 0
		s.CurrentOp = "idle"
		s.TrainingRunning = false
		if err := s.sealStateLocked(); err != nil {
			s.Logs.Add(LogError, "state", "训练控制状态清理持久化失败: %v", err)
		}
	}
	s.mu.Unlock()
	control.finish()
}

func (s *TAAState) executeTraining(trainReq importRequest, phase int, trainRecord ImportIndexRecord, cfg runtimeConfig, env map[string]string, startedAt time.Time) {
	control := s.ensureTrainingControl(trainReq, phase, trainRecord, startedAt)
	defer s.finishTrainingControl(control)

	checkCancelled := func() bool {
		return control.isCancelled()
	}
	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}

	trainOutputDir := trainRecord.ResultDir
	if trainOutputDir == "" {
		trainOutputDir = resultDirForRequestTask(s.Security.ResultDir, trainReq.RequestID, trainReq.TaskID)
	}
	trainDataDir := trainRecord.DataDir
	if trainDataDir == "" {
		if trainRecord.Hash != "" {
			trainDataDir = dataDirForHash(s.Security.DataDir, trainRecord.Hash)
		} else {
			trainDataDir = s.Security.DataDir
		}
	}

	modelInputDir := s.Security.GetModelInputDir()
	modelOutputDir := s.Security.GetModelOutputDir()

	StepSeparator("Stage Input Data")
	s.setCurrentOp("staging")
	s.Logs.Add(LogInfo, "train", "准备模型输入目录: %s (源数据目录: %s)", modelInputDir, trainDataDir)
	if err := os.MkdirAll(modelInputDir, 0o755); err != nil {
		if checkCancelled() {
			s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
			return
		}
		s.Logs.Add(LogError, "train", "创建模型输入目录失败: %v", err)
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("创建模型输入目录失败: %v", err))
		return
	}
	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	if err := cleanDirContents(modelInputDir); err != nil {
		if checkCancelled() {
			s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
			return
		}
		s.Logs.Add(LogError, "train", "清空模型输入目录失败: %v", err)
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("清空模型输入目录失败: %v", err))
		return
	}
	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	if err := copyDir(modelInputDir, trainDataDir); err != nil {
		if checkCancelled() {
			s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
			return
		}
		s.Logs.Add(LogError, "train", "复制训练数据到模型输入目录失败: %v", err)
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("复制训练数据到模型输入目录失败: %v", err))
		return
	}
	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	s.Logs.Add(LogInfo, "train", "训练数据已复制到模型输入目录: %s", modelInputDir)

	if err := os.MkdirAll(modelOutputDir, 0o755); err != nil {
		if checkCancelled() {
			s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
			return
		}
		s.Logs.Add(LogError, "train", "创建模型输出目录失败: %v", err)
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("创建模型输出目录失败: %v", err))
		return
	}
	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	if err := cleanDirContents(modelOutputDir); err != nil {
		if checkCancelled() {
			s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
			return
		}
		s.Logs.Add(LogError, "train", "清空模型输出目录失败: %v", err)
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("清空模型输出目录失败: %v", err))
		return
	}

	for name, target := range map[string]string{
		"模型日志": s.Security.GetModelLogDir(),
		"模型进度": s.Security.GetModelProgressDir(),
	} {
		if filepath.Ext(target) != "" {
			parentDir := filepath.Dir(target)
			if err := os.MkdirAll(parentDir, 0o755); err != nil {
				if checkCancelled() {
					s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
					return
				}
				s.Logs.Add(LogError, "train", "创建%s父目录失败: %v", name, err)
				s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("创建%s父目录失败: %v", name, err))
				return
			}
			_ = os.Remove(target)
		} else {
			if err := os.MkdirAll(target, 0o755); err != nil {
				if checkCancelled() {
					s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
					return
				}
				s.Logs.Add(LogError, "train", "创建%s目录失败: %v", name, err)
				s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("创建%s目录失败: %v", name, err))
				return
			}
			if checkCancelled() {
				s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
				return
			}
			if err := cleanDirContents(target); err != nil {
				if checkCancelled() {
					s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
					return
				}
				s.Logs.Add(LogError, "train", "清空%s目录失败: %v", name, err)
				s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("清空%s目录失败: %v", name, err))
				return
			}
		}
	}

	if env == nil {
		env = make(map[string]string)
	}
	env["TAA_LOG_DIR"] = s.Security.GetModelLogDir()
	env["TAA_PROGRESS_DIR"] = s.Security.GetModelProgressDir()

	watcher := s.startModelReportWatcher(context.Background(), trainReq.RequestID, trainReq.TaskID)
	defer func() {
		if checkCancelled() {
			watcher.StopWithoutFlush()
			return
		}
		watcher.Stop()
	}()

	StepSeparator("Run runtimeConfig")
	s.setCurrentOp("training")
	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	resolvedCommands := resolveRuntimeCommands(cfg.Commands, modelInputDir, modelOutputDir)
	s.Logs.Add(LogInfo, "train", "开始执行 runtimeConfig: commands=%d, envKeys=%v, 输入目录: %s (源hash=%s), 输出目录: %s",
		len(cfg.Commands), envKeys(env), modelInputDir, trainRecord.Hash, modelOutputDir)
	for i, cmd := range resolvedCommands {
		s.Logs.Add(LogInfo, "train", "  [cmd %d] %s", i+1, cmd)
	}
	output, err := runRuntimeConfigWithControl(control, cfg, env, s.Security.ModelDir, modelInputDir, modelOutputDir, trainReq.TaskID, startedAt.UTC().Format(time.RFC3339))
	if checkCancelled() || errors.Is(err, context.Canceled) {
		watcher.StopWithoutFlush()
	} else {
		watcher.Stop()
	}
	if err != nil {
		if checkCancelled() || errors.Is(err, context.Canceled) {
			s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
			return
		}
		s.Logs.Add(LogError, "train", "执行 runtimeConfig 失败: %v\noutput: %s", err, output)
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("执行 runtimeConfig 失败: %v", err))
		return
	}
	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	s.Logs.Add(LogInfo, "train", "runtimeConfig 执行成功")

	StepSeparator("Collect Output Results")
	s.Logs.Add(LogInfo, "train", "从模型输出目录拷贝产物到结果目录: %s -> %s", modelOutputDir, trainOutputDir)
	if err := os.MkdirAll(trainOutputDir, 0o755); err != nil {
		if checkCancelled() {
			s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
			return
		}
		s.Logs.Add(LogError, "train", "创建结果目录失败: %v", err)
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("创建结果目录失败: %v", err))
		return
	}
	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	if err := copyDir(trainOutputDir, modelOutputDir); err != nil {
		if checkCancelled() {
			s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
			return
		}
		s.Logs.Add(LogError, "train", "拷贝训练产物失败: %v", err)
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("拷贝训练产物失败: %v", err))
		return
	}
	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	s.Logs.Add(LogInfo, "train", "训练产物拷贝完成: %s", trainOutputDir)

	if modelInputDir != trainDataDir {
		_ = cleanDirContents(modelInputDir)
	}
	if modelOutputDir != trainOutputDir {
		_ = cleanDirContents(modelOutputDir)
	}

	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}

	// Plaintext leakage check on the finished artifacts. It runs before the report
	// is written (so training_report.json itself is not scanned) and its verdict is
	// persisted on the import index record, which is what the export handler reads
	// later. Deliberately non-fatal: a failing or impossible check must not turn a
	// successful training run into a failure, so every error below only warns.
	var trainResultCheck *resource.ResultCheckVerdict
	if s.Security.ResultCheck {
		StepSeparator("Result Leakage Check")
		s.Logs.Add(LogInfo, "resultcheck", "训练结束，执行结果明文泄露检查: resultDir=%s", trainOutputDir)
		verdict := s.runResultCheck(trainOutputDir)
		trainResultCheck = verdict
		switch {
		case verdict.Error != "":
			s.Logs.Add(LogError, "resultcheck", "结果明文泄露检查执行失败: %s", verdict.Error)
		case !verdict.Passed:
			s.Logs.Add(LogError, "resultcheck", "结果明文泄露检查未通过: %s", strings.Join(verdict.Details, "; "))
		default:
			s.Logs.Add(LogInfo, "resultcheck", "结果明文泄露检查通过")
		}
		if store, err := s.importIndexStore(); err != nil {
			s.Logs.Add(LogWarn, "resultcheck", "加载导入索引失败，检查裁决未能落盘: %v", err)
		} else if err := store.SetResultCheck(trainReq.RequestID, trainReq.TaskID, verdict); err != nil {
			s.Logs.Add(LogWarn, "resultcheck", "保存检查裁决失败: %v", err)
		}
	}

	// The model's 100% was held back for exactly this point: the platform must not be
	// told the task is over while the artifacts are still being collected and checked.
	// Released whatever the verdict says - a leak is reported as a rejected run through
	// reportRes, it does not make the run stop short of its end. A cancelled task and
	// every failure before here return without reaching this line, and the held snapshot
	// goes with them.
	if !checkCancelled() {
		watcher.reportDeferredProgress(context.Background())
	}

	StepSeparator("Build & Upload Report")
	s.setCurrentOp("reporting")
	s.Logs.Add(LogInfo, "report", "生成训练报告: taskId=%s", trainReq.TaskID)
	finishedAt := time.Now().UTC()

	// A result directory the leakage check found to hold the training data is reported as
	// a rejected run: the platform gets code 2 plus the reason in msg, and the report body
	// says status "failed" with the same reason. exit_code stays 0 - the training process
	// itself exited cleanly, it is its artifacts that are refused. result_files is dropped
	// by AttachResultFiles, previews included.
	status, exitCode, failureReason, code, msg := "succeeded", 0, "", 0, ""
	if resultLeakDetected(trainResultCheck) {
		status = "failed"
		failureReason = resultLeakText(resultLeakBaseReason, trainResultCheck)
		code = reportCodeResultLeak
		msg = resultLeakText(resultLeakBaseMsg, trainResultCheck)
		s.Logs.Add(LogError, "report", "训练结果被拒: %s", failureReason)
	}

	report, err := s.buildAndSaveTrainingReport(trainReq.TaskID, startedAt, finishedAt, status, exitCode, failureReason, s.getLastAudit(), true, trainOutputDir, trainResultCheck)
	if err != nil {
		if checkCancelled() {
			s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
			return
		}
		s.Logs.Add(LogError, "report", "生成训练报告失败: %v", err)
		return
	}
	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	s.Logs.Add(LogInfo, "report", "训练报告生成成功并写入 training_report.json (%d bytes)", len(report))

	s.Logs.Add(LogInfo, "report", "上报训练结果到平台: code=%d, taskId=%s", code, trainReq.TaskID)

	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	s.reportTrainingAsync(trainReq.RequestID, trainReq.TaskID, code, msg, string(report))
	s.setCurrentOp("idle")
	s.Logs.Add(LogInfo, "import", "资源导入流程完成: taskId=%s", trainReq.TaskID)
}

// launchModelAudit starts the model security audit asynchronously in the background.
// This decouples code auditing from the main task pipeline, allowing subsequent data
// imports and training tasks to proceed concurrently without mutual exclusion conflicts.
//
// The verdict is advisory: it is reported to the platform as a reference result and
// changes nothing about what TAA imports or executes. A failing audit neither rolls
// back the import nor stops a training run that is already executing, so the model
// package and its bundled dependency libraries always stay exactly as uploaded.
//
// The audit's in-memory and durable markers are set by beginModelImportAndAudit,
// which must have sealed before this is called: the marker is what tells a later
// restart that an audit was owed for this model.
func (s *TAAState) launchModelAudit(req importRequest) {
	s.runAsyncSafe("modelAudit", func() {
		s.clearAuditState()
	}, func() {
		if !s.auditAndReportModelImport(req) {
			s.Logs.Add(LogWarn, "import", "模型代码审计未通过，结论仅作参考，不阻断导入与训练: taskId=%s", req.TaskID)
		}
	})
}

// auditAndReportModelImport 对解压后的模型代码执行安全审计（静态扫描 + 可选 LLM 语义验证），
// 并将审计结果通过 /v1/taa/reportAudit 上报平台。返回是否审计通过。
//
// The audit reads, judges and reports; it never writes to, deletes, or modifies
// what it reads. The verdict is advisory - the caller only logs it - so the model
// package and its bundled dependency libraries stay exactly as uploaded, and the
// import remains usable whatever the verdict says.
func (s *TAAState) auditAndReportModelImport(req importRequest) bool {
	// Cleared as soon as a verdict exists, not when the goroutine unwinds. The
	// unwind happens after the platform report, so a crash in between would leave
	// a pending marker for a model that had in fact been adjudicated — and the
	// next restart would report the same interrupted audit a second time.
	defer s.concludeAuditPending()

	s.setLastAudit(nil)
	if !s.Security.ScanEnabled {
		s.Logs.Add(LogInfo, "audit", "安全扫描未启用，跳过模型代码审计")
		return true
	}

	cfg := s.Security.LLM
	StepSeparator("Code Audit")
	s.setCurrentAuditOp("auditing")
	defer s.setCurrentAuditOp("idle")
	s.Logs.Add(LogInfo, "audit", "开始模型代码审计: engine=%s, dir=%s, llmEnabled=%v, policy=%s, failClosed=%v",
		engineName(s.Security.Engine), s.Security.ModelDir, cfg.Enabled, cfg.Policy, cfg.FailClosed)

	llmClient := newLLMClient(cfg)

	// fail-closed：LLM 启用且要求不可用时阻断时，先探测 LLM 可用性；
	// 若不可用则直接判定失败，避免降级为纯静态扫描静默放行。
	if cfg.Enabled && cfg.FailClosed && !isLLMServiceAvailable(llmClient, cfg.Endpoint, cfg.Model) {
		s.Logs.Add(LogError, "audit", "LLM 服务不可用，按 fail-closed 策略上报失败: endpoint=%s model=%s", cfg.Endpoint, cfg.Model)
		s.Logs.Add(LogWarn, "audit", "审计未通过：仅上报结论，未删除或改动模型包与依赖库: dir=%s", s.Security.ModelDir)
		s.reportAuditAsync(req.RequestID, req.TaskID, 2, "LLM 服务不可用，按 fail-closed 策略上报失败", "")
		return false
	}

	audit, err := codeaudit.GenerateAuditReport(context.Background(), s.Security.ModelDir, s.Security.Engine,
		codeaudit.AuditConfig{LLM: cfg, Binary: s.Security.Binary}, llmClient)
	if err != nil {
		s.Logs.Add(LogError, "audit", "模型代码审计失败: %v", err)
		s.Logs.Add(LogWarn, "audit", "审计未通过：仅上报结论，未删除或改动模型包与依赖库: dir=%s", s.Security.ModelDir)
		s.reportAuditAsync(req.RequestID, req.TaskID, 2, fmt.Sprintf("代码审计失败: %v", err), "")
		return false
	}
	s.setLastAudit(audit)

	code := 0
	msg := audit.Conclusion.Summary
	passed := audit.Conclusion.Passed
	if !passed {
		code = 1
		s.Logs.Add(LogWarn, "audit", "审计未通过：仅上报结论，未删除或改动模型包与依赖库: dir=%s", s.Security.ModelDir)
	}
	s.Logs.Add(LogInfo, "audit", "审计完成: passed=%v, riskLevel=%s, totalFindings=%d",
		audit.Conclusion.Passed, audit.Conclusion.RiskLevel, audit.Conclusion.Statistics.Total())
	if audit.ScanMetadata.Binary != nil {
		b := audit.ScanMetadata.Binary
		s.Logs.Add(LogInfo, "audit", "二进制审计: files=%d kinds=%v boundedExecutable=%d boundedData=%d incomplete=%d errored=%v findingsCapped=%v findingsDropped=%d",
			b.FilesCount, b.Kinds, b.BoundedExecutable, b.BoundedData, b.Incomplete, b.Errored, b.FindingsCapped, b.FindingsDropped)
	}

	s.reportAuditAsync(req.RequestID, req.TaskID, code, msg, auditReportJSON(audit))
	return passed
}

// engineName reports the configured Tier 1 engine for a log line, tolerating the
// unset case.
//
// The audit-start line is written before the audit's own nil-engine check, so an
// unguarded Name() call here would panic inside the audit path instead of failing
// the import: a misconfigured deployment would take down the request that was
// supposed to be rejected. Nil is named rather than omitted so the operator sees
// which configuration is missing.
func engineName(engine codeaudit.StaticEngine) string {
	if engine == nil {
		return "unset"
	}
	return engine.Name()
}

// resolveModelChecksum 获取模型压缩包 SM3 校验和，若未缓存则回退扫描模型目录计算 SM3 校验和。
// 该逻辑与训练结果上报（reportRes）中 training_task.model_checksum 的解析逻辑完全一致。
func (s *TAAState) resolveModelChecksum() map[string]any {
	modelChecksum := s.getModelChecksum()
	if modelChecksum == nil {
		var err error
		modelChecksum, err = buildDirectoryChecksum(s.Security.ModelDir, "sm3")
		if err != nil {
			return nil
		}
	}
	if modelChecksum != nil && modelChecksum["value"] == "N/A" {
		return nil
	}
	return modelChecksum
}

// reportModelImportAsync 异步将模型导入及完整性校验结果上报平台。
func (s *TAAState) reportModelImportAsync(requestID, taskID string, code int, msg string, checksum ...map[string]any) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()

	var cs map[string]any
	if len(checksum) > 0 {
		cs = checksum[0]
	} else if code == 0 {
		cs = s.resolveModelChecksum()
	}

	log.Printf("reportModelImportAsync: scheduling model import upload, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, hasChecksum=%v",
		platformIP, dockerID, requestID, taskID, code, cs != nil)
	go func() {
		if err := ReportModelImport(context.Background(), platformIP, dockerID, requestID, taskID, code, msg, cs); err != nil {
			log.Printf("reportModelImportAsync: report model import result failed: requestID=%s taskID=%s, err=%v", requestID, taskID, err)
		} else {
			log.Printf("reportModelImportAsync: report model import result succeeded: requestID=%s taskID=%s", requestID, taskID)
		}
	}()
}

// reportAuditAsync 异步将模型代码安全审计结果上报平台。
func (s *TAAState) reportAuditAsync(requestID, taskID string, code int, msg, report string) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()

	log.Printf("reportAuditAsync: scheduling audit report upload, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, reportLen=%d",
		platformIP, dockerID, requestID, taskID, code, len(report))
	go func() {
		if err := ReportAudit(context.Background(), platformIP, dockerID, requestID, taskID, code, msg, report); err != nil {
			log.Printf("reportAuditAsync: report audit result failed: requestID=%s taskID=%s, err=%v", requestID, taskID, err)
		} else {
			log.Printf("reportAuditAsync: report audit result succeeded: requestID=%s taskID=%s", requestID, taskID)
		}
	}()
}

// newLLMClient creates an inference client based on configuration; returns nil if disabled or endpoint is empty.
func newLLMClient(cfg codeaudit.LLMConfig) codeaudit.LLMClient {
	if cfg.Enabled && strings.TrimSpace(cfg.Endpoint) != "" {
		client, err := codeaudit.NewInferenceClient(cfg)
		if err != nil {
			log.Printf("newLLMClient: failed to construct inference client: %v", err)
			return nil
		}
		return client
	}
	return nil
}

// auditLLMHealthCheckTimeout bounds the fail-closed readiness probe that runs
// before an audit.
//
// It tracks the client's own health budget rather than an ordinary request
// timeout, because the probe is not a ping: a cold inference service loads the
// model before answering /healthz. Cutting the probe off mid-load does not just
// fail the attempt, it cancels the load, so a short budget makes the gate
// unwinnable on a cold start rather than merely slow.
const auditLLMHealthCheckTimeout = teellm.DefaultHealthCheckTimeout

// isLLMServiceAvailable probes whether the inference service is healthy and reachable.
// It prioritizes standard TEE-LLM client health checking (/healthz over TEE-TLS),
// and falls back to legacy raw Ollama probe (/api/tags) if client creation failed but endpoint is HTTP.
func isLLMServiceAvailable(client codeaudit.LLMClient, endpoint, model string) bool {
	if client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), auditLLMHealthCheckTimeout)
		defer cancel()
		if err := client.HealthCheck(ctx); err != nil {
			log.Printf("isLLMServiceAvailable: health check failed: endpoint=%s model=%s timeout=%s error=%v",
				endpoint, model, auditLLMHealthCheckTimeout, err)
			return false
		}
		return true
	}
	return llmAvailable(endpoint, model)
}

// auditReportJSON is implemented in codeaudit_projection.go.

// llmAvailable probes whether Ollama daemon is ready and the model can execute inference.
// It is the legacy fallback used when the TEE-LLM client could not be built, so it
// talks to the daemon over plain HTTP.
//
// The two calls it makes are not the same kind of call and do not share a budget.
// Listing tags is a cheap inventory read that a short timeout keeps honest; the
// generate probe makes the daemon load the model, which on a cold daemon takes
// seconds, and cutting it off cancels the load it was waiting on. One timeout for
// both is wrong in both directions - too short to survive a cold load, too long to
// be a sensible ping budget.
func llmAvailable(endpoint, model string) bool {
	if strings.TrimSpace(endpoint) == "" {
		return false
	}
	base := endpoint
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	base = strings.TrimRight(base, "/")

	tagsClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := tagsClient.Get(base + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	if model != "" && !strings.Contains(string(body), model) {
		return false
	}

	// Active generate probe to verify tensor weights can be mapped and executed.
	if model != "" {
		probeClient := &http.Client{Timeout: auditLLMHealthCheckTimeout}
		probePayload := fmt.Sprintf(`{"model":%q,"prompt":"ping","stream":false,"options":{"num_predict":1}}`, model)
		genResp, err := probeClient.Post(base+"/api/generate", "application/json", strings.NewReader(probePayload))
		if err != nil {
			return false
		}
		defer genResp.Body.Close()
		if genResp.StatusCode != http.StatusOK {
			return false
		}
	}

	return true
}

func (s *TAAState) reportImportFailure(req importRequest, phase int, isModel bool, startedAt time.Time, reason string) {
	s.Logs.Add(LogError, "import", "导入失败: %s", reason)
	s.clearImportedState(isModel, phase)
	if !isModel {
		if store, err := s.importIndexStore(); err == nil {
			store.Rollback(req.RequestID, req.TaskID)
		}
	}
	if isModel {
		s.reportModelImportAsync(req.RequestID, req.TaskID, 1, reason)
		s.setCurrentOp("idle")
		return
	}
	resultDir := filepath.Join(s.Security.ResultDir, "train")
	if phase == 1 {
		resultDir = filepath.Join(s.Security.ResultDir, "debug")
	}
	s.reportTrainingFailureFromResult(req, startedAt, reason, s.getLastAudit(), true, resultDir)
	s.setCurrentOp("idle")
}

func resourceURLHasEncSuffix(resourceURL string) bool {
	return resource.ResourceURLHasEncSuffix(resourceURL)
}

// isArchiveFile 检查文件是否为已知明文压缩包格式（ZIP / GZIP / TAR）。
func isArchiveFile(filePath string) (bool, error) {
	return resource.IsArchiveFile(filePath)
}

// resolvePlaintextResource 决策并准备资源的明文文件路径。
// 判断策略：
// 1. 若 resourceURL 以 .enc 结尾，直接判定为密文并解密；
// 2. 若非 .enc 结尾，检测文件头部是否为明文压缩包（ZIP / GZIP / TAR）：
//   - 若是压缩包，判定为明文，直接返回原路径（isDecrypted = false）；
//   - 若非压缩包，尝试作为密文解密：
//   - 解密成功返回明文临时文件路径（isDecrypted = true）；
//   - 解密失败返回错误。
//
// 调用方注意：若 isDecrypted 为 true，调用方需负责清理返回的 plainPath（例如 defer os.Remove(plainPath)）。
func (s *TAAState) resolvePlaintextResource(resourceURL, downloadedPath, logScope string) (string, bool, error) {
	if resourceURLHasEncSuffix(resourceURL) {
		s.Logs.Add(LogInfo, logScope, "资源 URL 以 .enc 结尾，开始解密资源: %s", downloadedPath)
		decryptedPath, err := s.decryptResourceToTempFile(downloadedPath)
		if err != nil {
			s.Logs.Add(LogError, logScope, "解密失败: %v", err)
			if pubKey := s.getTAAPublicKeyPEM(); pubKey != "" {
				return "", false, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("解密资源失败: %v, taaPublicKey: %s", err, pubKey), err)
			}
			return "", false, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("解密资源失败: %v", err), err)
		}
		s.Logs.Add(LogInfo, logScope, "解密成功 -> %s", decryptedPath)
		return decryptedPath, true, nil
	}

	isArchive, err := isArchiveFile(downloadedPath)
	if err != nil {
		s.Logs.Add(LogError, logScope, "检测资源格式失败: %v", err)
		return "", false, fmt.Errorf("检测资源格式失败: %w", err)
	}
	if isArchive {
		s.Logs.Add(LogInfo, logScope, "资源 URL 非 .enc 后缀且检测到明文压缩包格式，跳过解密: %s", resourceURL)
		return downloadedPath, false, nil
	}

	s.Logs.Add(LogInfo, logScope, "资源 URL 非 .enc 后缀且未检测到压缩包魔数，尝试作为密文解密: %s", downloadedPath)
	decryptedPath, err := s.decryptResourceToTempFile(downloadedPath)
	if err != nil {
		s.Logs.Add(LogError, logScope, "尝试解密失败: %v", err)
		if pubKey := s.getTAAPublicKeyPEM(); pubKey != "" {
			return "", false, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("资源非 .enc 后缀且非有效压缩包，尝试解密失败: %v, taaPublicKey: %s", err, pubKey), err)
		}
		return "", false, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("资源非 .enc 后缀且非有效压缩包，尝试解密失败: %v", err), err)
	}
	s.Logs.Add(LogInfo, logScope, "尝试解密成功 -> %s", decryptedPath)
	return decryptedPath, true, nil
}

// resolvePlaintextResourceWithDataKey resolves a ciphertext-only resource using the
// data key envelope carried by the delivery URL.
//
// It sits next to the legacy path in resolvePlaintextResource. The envelope was
// already unwrapped into dataKey by the caller during the synchronous phase, and
// there is no archive-magic probing here: carrying an envelope declares the payload
// to be ciphertext, so failing to open it is a failure and never a silent
// re-classification as plaintext. The error carries the TAA public key so the
// platform can tell which key should have wrapped the envelope.
func (s *TAAState) resolvePlaintextResourceWithDataKey(dataKey []byte, ciphertextPath string) (string, bool, error) {
	decryptedPath, err := s.decryptCiphertextWithDataKey(dataKey, ciphertextPath)
	if err != nil {
		s.Logs.Add(LogError, "decrypt", "数据密钥解密失败: %v", err)
		if pubKey := s.getTAAPublicKeyPEM(); pubKey != "" {
			return "", false, pkgerrors.Wrap(pkgerrors.CodeInternal,
				fmt.Sprintf("解密资源失败: %v, taaPublicKey: %s", err, pubKey), err)
		}
		return "", false, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("解密资源失败: %v", err), err)
	}
	s.Logs.Add(LogInfo, "decrypt", "使用 URL 携带的数据密钥信封解密成功 -> %s", decryptedPath)
	return decryptedPath, true, nil
}

func (s *TAAState) clearImportedState(isModel bool, phase int) {
	s.updateImportState(isModel, false, phase)
}

func (s *TAAState) reportTrainingFailureFromResult(req importRequest, startedAt time.Time, reason string, audit *codeaudit.AuditReport, includeAudit bool, resultDir string) {
	s.Logs.Add(LogError, "import", "训练流程失败: %s", reason)
	s.Logs.Add(LogInfo, "report", "生成失败报告: taskId=%s", req.TaskID)
	finishedAt := time.Now().UTC()
	report, err := s.buildAndSaveTrainingReport(req.TaskID, startedAt, finishedAt, "failed", 1, reason, audit, includeAudit, resultDir, nil)
	if err != nil {
		s.Logs.Add(LogError, "report", "生成失败报告失败: %v", err)
		return
	}
	s.Logs.Add(LogInfo, "report", "上报训练失败结果到平台: code=1, taskId=%s", req.TaskID)

	s.reportTrainingAsync(req.RequestID, req.TaskID, 1, reason, string(report))
	s.setCurrentOp("idle")
}

func extractArchiveToDir(dst, filePath string) error {
	return resource.ExtractArchiveToDir(dst, filePath)
}

func extractArchiveFile(dst, filePath string) error {
	return resource.ExtractArchiveFile(dst, filePath)
}

func extractZipArchive(dst string, data []byte) error {
	return resource.ExtractZipArchive(dst, data)
}

func chmodScripts(root string) error {
	return resource.ChmodScripts(root)
}

func extractTarStream(dst string, src io.Reader) error {
	return resource.ExtractTarStream(dst, src)
}

func safeJoinWithBase(baseDir, baseAbs, name string) (string, error) {
	return resource.SafeJoinWithBase(baseDir, baseAbs, name)
}

func (s *TAAState) buildAndSaveTrainingReport(taskID string, startedAt, finishedAt time.Time, status string, exitCode int, failureReason string, audit *codeaudit.AuditReport, includeAudit bool, resultDir string, resultCheck *resource.ResultCheckVerdict) ([]byte, error) {
	trainingResult, err := loadTrainingResult(filepath.Join(resultDir, "training_result.json"))
	if err != nil {
		return nil, err
	}

	modelChecksum := s.getModelChecksum()
	if modelChecksum == nil {
		var err error
		modelChecksum, err = buildDirectoryChecksum(s.Security.ModelDir, "sm3")
		if err != nil {
			return nil, err
		}
	}

	dataChecksum := s.getDataChecksum()

	report, err := buildTrainingReport(taskID, startedAt, finishedAt, status, exitCode, failureReason, modelChecksum, dataChecksum, trainingResult, audit, includeAudit)
	if err != nil {
		return nil, err
	}
	if err := AttachResultFiles(report, resultDir, resultCheck); err != nil {
		s.Logs.Add(LogWarn, "report", "生成结果目录结构树失败，报告中省略 result_files: %v", err)
	}
	if err := writeJSONFile(filepath.Join(resultDir, trainingReportFileName), report); err != nil {
		return nil, err
	}
	return json.Marshal(report)
}

func buildDirectoryChecksum(dir, algorithm string) (map[string]any, error) {
	return resource.BuildDirectoryChecksum(dir, algorithm)
}

func loadTrainingResult(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("read training_result.json: %w", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse training_result.json: %w", err)
	}
	if result == nil {
		result = map[string]any{}
	}
	return result, nil
}

// BuildCrashFailureReport 构造崩溃/异常自愈场景下的标准 Schema 1.0 失败报告。
// resultDir 非空时附上结果目录结构树，与正常完成路径的报告结构保持一致。
func BuildCrashFailureReport(taskID string, startedAt, finishedAt time.Time, failureReason string, modelChecksum, dataChecksum map[string]any, resultDir string) (map[string]any, error) {
	report, err := runtime.BuildCrashFailureReport(taskID, startedAt, finishedAt, failureReason, modelChecksum, dataChecksum)
	if err != nil {
		return nil, err
	}
	if attachErr := AttachResultFiles(report, resultDir, nil); attachErr != nil {
		log.Printf("WARNING: build result_files for crash report failed: %v", attachErr)
	}
	return report, nil
}

func buildTrainingReport(taskID string, startedAt, finishedAt time.Time, status string, exitCode int, failureReason string, modelChecksum map[string]any, dataChecksum map[string]any, trainingResult map[string]any, audit *codeaudit.AuditReport, includeAudit bool) (map[string]any, error) {
	var auditSection map[string]any
	if includeAudit && audit != nil {
		auditSection = projectCodeAuditSection(audit)
	}
	return runtime.BuildTrainingReport(taskID, startedAt, finishedAt, status, exitCode, failureReason, modelChecksum, dataChecksum, trainingResult, auditSection)
}

func cleanDatasetField(src map[string]any) map[string]any {
	return runtime.CleanDatasetField(src)
}

func objectField(src map[string]any, key string) map[string]any {
	return runtime.ObjectField(src, key)
}

func durationSeconds(startedAt, finishedAt time.Time) int64 {
	return runtime.DurationSeconds(startedAt, finishedAt)
}

func writeJSONFile(path string, payload any) error {
	return utils.WriteJSONFile(path, payload, 0o644)
}

func newTrainingReportID(now time.Time) string {
	return runtime.NewTrainingReportID(now)
}

func nullableString(v string) any {
	return runtime.NullableString(v)
}
