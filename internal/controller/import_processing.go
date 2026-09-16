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
	"strings"
	"time"

	"taa/internal/codeaudit"
	"taa/internal/resource"
	"taa/internal/runtime"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
	"taa/pkg/utils"
)

func (s *TAAState) processImportedResource(req importRequest, phase int, isModel bool, ciphertextPath string) {
	startedAt := time.Now().UTC()
	PhaseSeparator(fmt.Sprintf("Phase %d Import: taskId=%s", phase, req.TaskID))
	s.Logs.Add(LogInfo, "import", "收到资源导入请求: taskId=%s, requestId=%s, phase=%d, isModel=%v", req.TaskID, req.RequestID, phase, isModel)

	defer os.Remove(ciphertextPath)

	StepSeparator("Decrypt")
	s.setCurrentOp("decrypting")
	plaintextPath, isDecrypted, err := s.resolvePlaintextResource(req.ResourceURL, ciphertextPath, "decrypt")
	if err != nil {
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, isModel, startedAt, err.Error())
		return
	}
	if isDecrypted {
		defer os.Remove(plaintextPath)
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

		// ── 阶段一：模型解封解密与解压完成，立马上报模型导入结果与 checksum ──
		checksum := map[string]any{
			"size":      size,
			"algorithm": "sm3",
			"value":     hash,
		}
		s.reportModelImportAsync(req.RequestID, req.TaskID, 0, "模型导入成功", checksum)

		// ── 阶段二：对解压后的模型代码执行安全审计并上报 reportAudit ──
		if !s.auditAndReportModelImport(req) {
			s.Logs.Add(LogError, "import", "模型安全审计未通过，终止导入流程并清除模型代码: taskId=%s", req.TaskID)
			s.clearImportedState(true, phase)
			s.setCurrentOp("idle")
			return
		}
		s.saveModelSuccess(req.ResourceURL)
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
	modelInProgress := (s.activeTask != nil && s.activeTask.Type == "model_import") || s.CurrentOp == "auditing"
	isBusy := s.isTrainingBusyLocked()
	runtimeConfigRaw := s.RuntimeConfig
	s.mu.RUnlock()

	if !modelImported {
		s.Logs.Add(LogInfo, "import", "阶段%d: 数据导入完成，等待模型导入后执行训练", phase)
		s.setCurrentOp("idle")
		return
	}
	if modelInProgress {
		s.Logs.Add(LogInfo, "import", "阶段%d: 数据导入完成，模型仍在导入审计中，等待模型就绪后执行训练", phase)
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

	for name, dir := range map[string]string{
		"模型输出": modelOutputDir,
		"模型日志": s.Security.GetModelLogDir(),
		"模型进度": s.Security.GetModelProgressDir(),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
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
		if err := cleanDirContents(dir); err != nil {
			if checkCancelled() {
				s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
				return
			}
			s.Logs.Add(LogError, "train", "清空%s目录失败: %v", name, err)
			s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("清空%s目录失败: %v", name, err))
			return
		}
	}

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
	StepSeparator("Build & Upload Report")
	s.setCurrentOp("reporting")
	s.Logs.Add(LogInfo, "report", "生成训练报告: taskId=%s", trainReq.TaskID)
	finishedAt := time.Now().UTC()
	report, err := s.buildAndSaveTrainingReport(trainReq.TaskID, startedAt, finishedAt, "succeeded", 0, "", s.getLastAudit(), true, trainOutputDir)
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

	s.Logs.Add(LogInfo, "report", "上报训练结果到平台: code=0, taskId=%s", trainReq.TaskID)

	if checkCancelled() {
		s.Logs.Add(LogInfo, "train", "训练任务已中止: taskId=%s", trainReq.TaskID)
		return
	}
	s.reportTrainingAsync(trainReq.RequestID, trainReq.TaskID, 0, "", string(report))
	s.setCurrentOp("idle")
	s.Logs.Add(LogInfo, "import", "资源导入流程完成: taskId=%s", trainReq.TaskID)
}

// auditAndReportModelImport 对解压后的模型代码执行安全审计（静态扫描 + 可选 LLM 语义验证），
// 并将审计结果通过 /v1/taa/reportAudit 上报平台。返回是否审计通过。
func (s *TAAState) auditAndReportModelImport(req importRequest) bool {
	s.setLastAudit(nil)
	if !s.Security.ScanEnabled {
		s.Logs.Add(LogInfo, "audit", "安全扫描未启用，跳过模型代码审计")
		return true
	}

	cfg := s.Security.LLM
	StepSeparator("Code Audit")
	s.setCurrentOp("auditing")
	s.Logs.Add(LogInfo, "audit", "开始模型代码审计: dir=%s, llmEnabled=%v, policy=%s, failClosed=%v",
		s.Security.ModelDir, cfg.Enabled, cfg.Policy, cfg.FailClosed)

	// fail-closed：LLM 启用且要求不可用时阻断时，先探测 LLM 可用性；
	// 若不可用则直接判定失败，避免降级为纯静态扫描静默放行。
	if cfg.Enabled && cfg.FailClosed && !llmAvailable(cfg.Endpoint, cfg.Model) {
		s.Logs.Add(LogError, "audit", "LLM 服务不可用，按 fail-closed 策略上报失败: endpoint=%s model=%s", cfg.Endpoint, cfg.Model)
		if err := cleanDirContents(s.Security.ModelDir); err != nil {
			s.Logs.Add(LogError, "audit", "物理清除已解压模型代码失败: %v", err)
		}
		s.reportAuditAsync(req.RequestID, req.TaskID, 2, "LLM 服务不可用，按 fail-closed 策略上报失败", "")
		s.setCurrentOp("idle")
		return false
	}

	audit, err := codeaudit.GenerateAuditReport(context.Background(), s.Security.ModelDir, cfg, newLLMClient(cfg))
	if err != nil {
		s.Logs.Add(LogError, "audit", "模型代码审计失败: %v", err)
		if err := cleanDirContents(s.Security.ModelDir); err != nil {
			s.Logs.Add(LogError, "audit", "物理清除已解压模型代码失败: %v", err)
		}
		s.reportAuditAsync(req.RequestID, req.TaskID, 2, fmt.Sprintf("代码审计失败: %v", err), "")
		s.setCurrentOp("idle")
		return false
	}
	s.setLastAudit(audit)

	code := 0
	msg := audit.Conclusion.Summary
	passed := audit.Conclusion.Passed
	if !passed {
		code = 1
		if err := cleanDirContents(s.Security.ModelDir); err != nil {
			s.Logs.Add(LogError, "audit", "物理清除已解压模型代码失败: %v", err)
		}
	}
	s.Logs.Add(LogInfo, "audit", "审计完成: passed=%v, riskLevel=%s, totalFindings=%d",
		audit.Conclusion.Passed, audit.Conclusion.RiskLevel, audit.Conclusion.Statistics.Total())

	s.reportAuditAsync(req.RequestID, req.TaskID, code, msg, auditReportJSON(audit))
	s.setCurrentOp("idle")
	return passed
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

// newLLMClient 根据配置创建 LLM 客户端；未启用或未配置端点时返回 nil（仅静态扫描）。
func newLLMClient(cfg codeaudit.LLMConfig) codeaudit.LLMClient {
	if cfg.Enabled && cfg.Endpoint != "" {
		return codeaudit.NewOllamaClient(cfg.Endpoint, cfg.Model, cfg.Timeout)
	}
	return nil
}

// auditReportJSON is implemented in codeaudit_projection.go.

// llmAvailable 探测 Ollama 服务是否就绪且模型已加载。
// 仅用于 fail-closed 预检，使用较短的超时避免长时间阻塞。
func llmAvailable(endpoint, model string) bool {
	if strings.TrimSpace(endpoint) == "" {
		return false
	}
	base := endpoint
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(strings.TrimRight(base, "/") + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	return strings.Contains(string(body), model) || model == ""
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

func (s *TAAState) clearImportedState(isModel bool, phase int) {
	s.updateImportState(isModel, false, phase)
}

func (s *TAAState) reportTrainingFailureFromResult(req importRequest, startedAt time.Time, reason string, audit *codeaudit.AuditReport, includeAudit bool, resultDir string) {
	s.Logs.Add(LogError, "import", "训练流程失败: %s", reason)
	s.Logs.Add(LogInfo, "report", "生成失败报告: taskId=%s", req.TaskID)
	finishedAt := time.Now().UTC()
	report, err := s.buildAndSaveTrainingReport(req.TaskID, startedAt, finishedAt, "failed", 1, reason, audit, includeAudit, resultDir)
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

func writeExtractedFileWithLimit(target string, src io.Reader, mode os.FileMode, maxBytes int64) (int64, error) {
	return resource.WriteExtractedFileWithLimit(target, src, mode, maxBytes)
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

func (s *TAAState) buildAndSaveTrainingReport(taskID string, startedAt, finishedAt time.Time, status string, exitCode int, failureReason string, audit *codeaudit.AuditReport, includeAudit bool, resultDir string) ([]byte, error) {
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
	if err := writeJSONFile(filepath.Join(resultDir, "training_report.json"), report); err != nil {
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

// BuildCrashFailureReport 构造崩溃/异常自愈场景下的标准 Schema 1.0 失败报告
func BuildCrashFailureReport(taskID string, startedAt, finishedAt time.Time, failureReason string, modelChecksum, dataChecksum map[string]any) (map[string]any, error) {
	return runtime.BuildCrashFailureReport(taskID, startedAt, finishedAt, failureReason, modelChecksum, dataChecksum)
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
