package controller

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"taa/internal/codeaudit"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
	filetree "taa/pkg/filetree"
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

	if isModel {
		latestRecord, ok := s.getLatestDataRecord()
		if !ok || (latestRecord.DataDir == "" && latestRecord.Hash == "") {
			s.Logs.Add(LogInfo, "import", "阶段%d: 模型导入完成，等待数据导入后执行训练", phase)
			s.setCurrentOp("idle")
			return
		}
		s.mu.RLock()
		isBusy := s.isTrainingBusyLocked()
		s.mu.RUnlock()
		if isBusy {
			s.Logs.Add(LogInfo, "import", "阶段%d: 模型导入完成，已有训练任务正在执行中，跳过重复触发训练", phase)
			s.setCurrentOp("idle")
			return
		}
	} else {
		s.mu.RLock()
		modelImported := s.ModelImported
		modelInProgress := (s.activeTask != nil && s.activeTask.Type == "model_import") || s.CurrentOp == "auditing"
		isBusy := s.isTrainingBusyLocked()
		s.mu.RUnlock()
		if !modelImported || modelInProgress || isBusy {
			if isBusy {
				s.Logs.Add(LogInfo, "import", "阶段%d: 数据导入完成，已有训练任务正在执行中，跳过重复触发训练", phase)
			} else if modelInProgress {
				s.Logs.Add(LogInfo, "import", "阶段%d: 数据导入完成，模型仍在导入审计中，等待模型就绪后执行训练", phase)
			} else {
				s.Logs.Add(LogInfo, "import", "阶段%d: 数据导入完成，等待模型导入后执行训练", phase)
			}
			s.setCurrentOp("idle")
			return
		}
	}

	trainRecord, _ = s.resolveTrainingRecord(req, isModel)
	trainReq := req
	if isModel {
		if trainRecord.RequestID != "" {
			trainReq.RequestID = trainRecord.RequestID
		}
		if trainRecord.TaskID != "" {
			trainReq.TaskID = trainRecord.TaskID
		}
	}
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

	s.mu.RLock()
	runtimeConfigRaw := s.RuntimeConfig
	s.mu.RUnlock()
	cfg, env, err := parseRuntimeConfig(runtimeConfigRaw)
	if err != nil {
		s.Logs.Add(LogError, "train", "%v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(trainReq, phase, false, startedAt, err.Error())
		return
	}

	if err := s.promoteCurrentTaskToTraining(); err != nil {
		s.Logs.Add(LogError, "train", "提升为训练任务失败: %v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(trainReq, phase, false, startedAt, err.Error())
		return
	}

	s.executeTraining(trainReq, phase, trainRecord, cfg, env, startedAt)
}

func (s *TAAState) trainOnLatestData(req importRequest, phase int, latestRecord ImportIndexRecord, cfg runtimeConfig, env map[string]string) {
	trainReq := req
	trainRecord := latestRecord
	trainRecord.Phase = phase

	// 自动补齐 taskId / requestId：若当前请求未显式指定，优先继承最新数据记录；依然为空时以对方兜底
	if trainReq.TaskID == "" {
		if latestRecord.TaskID != "" {
			trainReq.TaskID = latestRecord.TaskID
		} else if trainReq.RequestID != "" {
			trainReq.TaskID = trainReq.RequestID
		}
	}
	if trainReq.RequestID == "" && latestRecord.RequestID != "" {
		trainReq.RequestID = latestRecord.RequestID
	}

	startedAt := time.Now().UTC()
	PhaseSeparator(fmt.Sprintf("Phase %d Train On Latest Data: taskId=%s", phase, trainReq.TaskID))
	s.Logs.Add(LogInfo, "train", "开始基于最新数据执行训练: taskId=%s, requestId=%s, phase=%d, dataHash=%s",
		trainReq.TaskID, trainReq.RequestID, phase, latestRecord.Hash)

	// 判断是否指定了新的 requestId 或 taskId
	isNewRequest := (trainReq.RequestID != "" && trainReq.RequestID != latestRecord.RequestID) ||
		(trainReq.TaskID != "" && trainReq.TaskID != latestRecord.TaskID)

	if isNewRequest {
		trainRecord.RequestID = trainReq.RequestID
		trainRecord.TaskID = trainReq.TaskID
		trainRecord.ResultDir = resultDirForRequestTask(s.Security.ResultDir, trainReq.RequestID, trainReq.TaskID)

		store, err := s.importIndexStore()
		if err == nil {
			_ = store.Reserve(trainReq.RequestID, trainReq.TaskID)
			_ = store.Commit(trainRecord)
		}
		s.setLatestDataRecord(trainRecord)
	}

	s.executeTraining(trainReq, phase, trainRecord, cfg, env, startedAt)
}

func (s *TAAState) executeTraining(trainReq importRequest, phase int, trainRecord ImportIndexRecord, cfg runtimeConfig, env map[string]string, startedAt time.Time) {
	defer func() {
		s.mu.Lock()
		s.TrainingRunning = false
		_ = s.sealStateLocked()
		s.mu.Unlock()
	}()

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
		s.Logs.Add(LogError, "train", "创建模型输入目录失败: %v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("创建模型输入目录失败: %v", err))
		return
	}
	if err := cleanDirContents(modelInputDir); err != nil {
		s.Logs.Add(LogError, "train", "清空模型输入目录失败: %v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("清空模型输入目录失败: %v", err))
		return
	}
	if err := copyDir(modelInputDir, trainDataDir); err != nil {
		s.Logs.Add(LogError, "train", "复制训练数据到模型输入目录失败: %v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("复制训练数据到模型输入目录失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "train", "训练数据已复制到模型输入目录: %s", modelInputDir)

	if err := os.MkdirAll(modelOutputDir, 0o755); err != nil {
		s.Logs.Add(LogError, "train", "创建模型输出���录失败: %v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("创建模型输出目录失败: %v", err))
		return
	}
	if err := cleanDirContents(modelOutputDir); err != nil {
		s.Logs.Add(LogError, "train", "清空模型输出目录失败: %v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("清空模型输出目录失败: %v", err))
		return
	}

	StepSeparator("Run runtimeConfig")
	s.setCurrentOp("training")
	resolvedCommands := resolveRuntimeCommands(cfg.Commands, modelInputDir, modelOutputDir)
	s.Logs.Add(LogInfo, "train", "开始执行 runtimeConfig: commands=%d, envKeys=%v, 输入目录: %s (源hash=%s), 输出目录: %s",
		len(cfg.Commands), envKeys(env), modelInputDir, trainRecord.Hash, modelOutputDir)
	for i, cmd := range resolvedCommands {
		s.Logs.Add(LogInfo, "train", "  [cmd %d] %s", i+1, cmd)
	}
	if output, err := runRuntimeConfig(cfg, env, s.Security.ModelDir, modelInputDir, modelOutputDir, trainReq.TaskID, startedAt.UTC().Format(time.RFC3339)); err != nil {
		s.Logs.Add(LogError, "train", "执行 runtimeConfig 失败: %v\noutput: %s", err, output)
		s.setCurrentOp("idle")
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("执行 runtimeConfig 失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "train", "runtimeConfig 执行成功")

	StepSeparator("Collect Output Results")
	s.Logs.Add(LogInfo, "train", "从模型输出目录拷贝产物到结果目录: %s -> %s", modelOutputDir, trainOutputDir)
	if err := os.MkdirAll(trainOutputDir, 0o755); err != nil {
		s.Logs.Add(LogError, "train", "创建结果目录失败: %v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("创建结果目录失败: %v", err))
		return
	}
	if err := copyDir(trainOutputDir, modelOutputDir); err != nil {
		s.Logs.Add(LogError, "train", "拷贝训练产物失败: %v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(trainReq, phase, false, startedAt, fmt.Sprintf("拷贝训练产物失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "train", "训练产物拷贝完成: %s", trainOutputDir)

	if modelInputDir != trainDataDir {
		_ = cleanDirContents(modelInputDir)
	}
	if modelOutputDir != trainOutputDir {
		_ = cleanDirContents(modelOutputDir)
	}

	StepSeparator("Build & Upload Report")
	s.setCurrentOp("reporting")
	s.Logs.Add(LogInfo, "report", "生成训练报告: taskId=%s", trainReq.TaskID)
	finishedAt := time.Now().UTC()
	report, err := s.buildAndSaveTrainingReport(trainReq.TaskID, startedAt, finishedAt, "succeeded", 0, "", s.getLastAudit(), true, trainOutputDir)
	if err != nil {
		s.Logs.Add(LogError, "report", "生成训练报告失败: %v", err)
		s.setCurrentOp("idle")
		return
	}
	s.Logs.Add(LogInfo, "report", "训练报告生成成功并写入 training_report.json (%d bytes)", len(report))

	s.Logs.Add(LogInfo, "report", "上报训练结果到平台: code=0, taskId=%s", trainReq.TaskID)

	s.reportTrainingAsync(trainReq.RequestID, trainReq.TaskID, 0, "", string(report))
	s.setCurrentOp("idle")
	s.Logs.Add(LogInfo, "import", "资源导入流程完成: taskId=%s", trainReq.TaskID)
}

// auditAndReportModelImport 对解压后的模型代码执行安全审计（静态扫描 + 可选 LLM 语义验证），
// 并将审计结果通过 /v1/taa/reportModelImport 上报平台。返回是否审计通过。
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
		s.reportModelImportAsync(req.RequestID, req.TaskID, 2, "LLM 服务不可用，按 fail-closed 策略上报失败", "")
		s.setCurrentOp("idle")
		return false
	}

	audit, err := codeaudit.GenerateAuditReport(context.Background(), s.Security.ModelDir, cfg, newLLMClient(cfg))
	if err != nil {
		s.Logs.Add(LogError, "audit", "模型代码审计失败: %v", err)
		if err := cleanDirContents(s.Security.ModelDir); err != nil {
			s.Logs.Add(LogError, "audit", "物理清除已解压模型代码失败: %v", err)
		}
		s.reportModelImportAsync(req.RequestID, req.TaskID, 2, fmt.Sprintf("代码审计失败: %v", err), "")
		s.setCurrentOp("idle")
		return false
	}
	s.setLastAudit(audit)

	code := 0
	msg := audit.Conclusion.Summary
	passed := audit.Conclusion.Passed
	if !passed {
		code = 2
		if err := cleanDirContents(s.Security.ModelDir); err != nil {
			s.Logs.Add(LogError, "audit", "物理清除已解压模型代码失败: %v", err)
		}
	}
	s.Logs.Add(LogInfo, "audit", "审计完成: passed=%v, riskLevel=%s, totalFindings=%d",
		audit.Conclusion.Passed, audit.Conclusion.RiskLevel, audit.Conclusion.Statistics.TotalFindings)

	s.reportModelImportAsync(req.RequestID, req.TaskID, code, msg, auditReportJSON(audit))
	s.setCurrentOp("idle")
	return passed
}

// reportModelImportAsync 异步将模型代码审计结果上报平台，避免阻塞导入流程。
func (s *TAAState) reportModelImportAsync(requestID, taskID string, code int, msg, report string) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()
	log.Printf("reportModelImportAsync: scheduling audit report upload, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, reportLen=%d",
		platformIP, dockerID, requestID, taskID, code, len(report))
	go func() {
		if err := ReportModelImport(context.Background(), platformIP, dockerID, requestID, taskID, code, msg, report); err != nil {
			log.Printf("reportModelImportAsync: report audit result failed: requestID=%s taskID=%s, err=%v", requestID, taskID, err)
		} else {
			log.Printf("reportModelImportAsync: report audit result succeeded: requestID=%s taskID=%s", requestID, taskID)
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
		s.reportModelImportAsync(req.RequestID, req.TaskID, 1, reason, "")
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
	path := resourceURL
	if u, err := url.Parse(resourceURL); err == nil && u.Path != "" {
		path = u.Path
	}
	return strings.HasSuffix(strings.ToLower(path), ".enc")
}

// isArchiveFile 检查文件是否为已知明文压缩包格式（ZIP / GZIP / TAR）。
func isArchiveFile(filePath string) (bool, error) {
	return filetree.IsArchiveFile(filePath)
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
	if strings.TrimSpace(dst) == "" {
		return fmt.Errorf("MODEL_DIR is required")
	}

	parent := filepath.Dir(dst)
	base := filepath.Base(dst)
	tmpDir, err := os.MkdirTemp(parent, base+".extract-*")
	if err != nil {
		return fmt.Errorf("create temp extraction dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := extractArchiveFile(tmpDir, filePath); err != nil {
		return err
	}

	// 给所有 .sh 文件补可执行权限（兼容 Windows 打包的归档）
	if err := chmodScripts(tmpDir); err != nil {
		return fmt.Errorf("chmod scripts: %w", err)
	}

	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("clear model dir: %w", err)
	}
	if err := os.Rename(tmpDir, dst); err != nil {
		return fmt.Errorf("move extracted package into model dir: %w", err)
	}
	return nil
}

// extractArchiveFile 从磁盘文件解压，根据 magic bytes 自动检测格式。
// tar/tar.gz 流式读取；zip 需要随机访问，加载到内存。
func extractArchiveFile(dst, filePath string) error {
	log.Printf("extractArchiveFile: dst=%s, filePath=%s", dst, filePath)

	// 读取文件头部用于格式检测。
	hdr := make([]byte, 512)
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	n, _ := f.Read(hdr)
	f.Close()
	hdr = hdr[:n]

	log.Printf("extractArchiveFile: read %d bytes header, first 4 bytes: %x", n, hdr[:min(4, len(hdr))])

	if n >= 2 {
		// ZIP: starts with "PK" (0x50 0x4B)
		if hdr[0] == 0x50 && hdr[1] == 0x4B {
			log.Printf("extractArchiveFile: detected ZIP format")
			data, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}
			return extractZipArchive(dst, data)
		}
		// gzip: starts with 0x1F 0x8B — 流式读取
		if hdr[0] == 0x1F && hdr[1] == 0x8B {
			log.Printf("extractArchiveFile: detected gzip format, extracting...")
			f, err := os.Open(filePath)
			if err != nil {
				return err
			}
			defer f.Close()
			gz, err := gzip.NewReader(f)
			if err != nil {
				return err
			}
			defer gz.Close()
			err = extractTarStream(dst, gz)
			if err != nil {
				return err
			}
			// Count extracted files
			count := 0
			filepath.Walk(dst, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					count++
				}
				return nil
			})
			log.Printf("extractArchiveFile: gzip extraction complete, %d files extracted to %s", count, dst)
			return nil
		}
	}
	// tar: check for "ustar" magic at offset 257 — 流式读取
	if n >= 263 && string(hdr[257:262]) == "ustar" {
		f, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()
		return extractTarStream(dst, f)
	}

	// Fallback: 尝试 zip（需要内存）和流式 tar.gz/tar
	// 先尝试 zip
	if data, err := os.ReadFile(filePath); err == nil {
		if err := extractZipArchive(dst, data); err == nil {
			return nil
		}
	}
	// 尝试流式 tar.gz
	if f, err := os.Open(filePath); err == nil {
		if gz, err := gzip.NewReader(f); err == nil {
			err = extractTarStream(dst, gz)
			gz.Close()
			f.Close()
			if err == nil {
				return nil
			}
		} else {
			f.Close()
		}
	}
	// 尝试流式 tar
	if f, err := os.Open(filePath); err == nil {
		err = extractTarStream(dst, f)
		f.Close()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("unsupported archive format or extract failed")
}

const maxExtractBytes int64 = 2 << 30 // 2 GB

func extractZipArchive(dst string, data []byte) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	baseAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	var totalExtractedBytes int64
	for _, f := range r.File {
		target, err := safeJoinWithBase(dst, baseAbs, f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		remain := maxExtractBytes - totalExtractedBytes
		if remain < 0 {
			rc.Close()
			_ = cleanDirContents(dst)
			return fmt.Errorf("解压累计字节超过上限 %d bytes", maxExtractBytes)
		}
		written, err := writeExtractedFileWithLimit(target, rc, f.Mode(), remain)
		rc.Close()
		if err != nil {
			_ = cleanDirContents(dst)
			return err
		}
		totalExtractedBytes += written
	}
	return nil
}

func writeExtractedFileWithLimit(target string, src io.Reader, mode os.FileMode, maxBytes int64) (int64, error) {
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return 0, err
	}
	lr := io.LimitReader(src, maxBytes+1)
	n, err := io.Copy(out, lr)
	closeErr := out.Close()
	if err != nil {
		_ = os.Remove(target)
		return n, err
	}
	if closeErr != nil {
		_ = os.Remove(target)
		return n, closeErr
	}
	if n > maxBytes {
		_ = os.Remove(target)
		return n, fmt.Errorf("解压数据超过配额上限 %d bytes", maxExtractBytes)
	}
	return n, nil
}

// chmodScripts walks a directory and adds the executable bit (+x) to all .sh files.
// This fixes archives created on Windows or without proper Unix permissions.
func chmodScripts(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(info.Name()) == ".sh" {
			mode := info.Mode() | 0o111 // add execute bit for owner/group/other
			if err := os.Chmod(path, mode); err != nil {
				return fmt.Errorf("chmod %s: %w", path, err)
			}
			log.Printf("chmodScripts: added +x to %s (was %o, now %o)", path, info.Mode(), mode)
		}
		return nil
	})
}

func extractTarStream(dst string, src io.Reader) error {
	baseAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	var totalExtractedBytes int64
	tr := tar.NewReader(src)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		target, err := safeJoinWithBase(dst, baseAbs, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, hdr.FileInfo().Mode()); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			remain := maxExtractBytes - totalExtractedBytes
			if remain < 0 {
				_ = cleanDirContents(dst)
				return fmt.Errorf("解压累计字节超过上限 %d bytes", maxExtractBytes)
			}
			written, err := writeExtractedFileWithLimit(target, tr, hdr.FileInfo().Mode(), remain)
			if err != nil {
				_ = cleanDirContents(dst)
				return err
			}
			totalExtractedBytes += written
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("unsupported archive entry type for %s", hdr.Name)
		default:
			// Ignore other entry types.
		}
	}
}

func safeJoinWithBase(baseDir, baseAbs, name string) (string, error) {
	normalized := strings.ReplaceAll(name, "\\", "/")
	cleaned := filepath.Clean(filepath.FromSlash(normalized))
	if cleaned == "." || cleaned == string(filepath.Separator) {
		return baseDir, nil
	}
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("archive entry has absolute path: %s", name)
	}
	full := filepath.Join(baseDir, cleaned)
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if fullAbs != baseAbs && !strings.HasPrefix(fullAbs, baseAbs+string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry escapes destination: %s", name)
	}
	return full, nil
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
	if strings.TrimSpace(dir) == "" {
		return map[string]any{"size": 0, "algorithm": algorithm, "value": "N/A"}, nil
	}

	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{"size": 0, "algorithm": algorithm, "value": "N/A"}, nil
		}
		return nil, fmt.Errorf("stat directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", dir)
	}

	h := teecrypto.NewSM3()
	files := make([]string, 0)
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var totalSize int64
	buf := make([]byte, 64*1024)
	for _, fpath := range files {
		rel, err := filepath.Rel(dir, fpath)
		if err != nil {
			return nil, fmt.Errorf("resolve relative path for %s: %w", fpath, err)
		}
		h.Write([]byte(filepath.ToSlash(rel)))
		h.Write([]byte{0})

		info, err := os.Lstat(fpath)
		if err != nil {
			return nil, fmt.Errorf("stat file %s: %w", fpath, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		totalSize += info.Size()

		f, err := os.Open(fpath)
		if err != nil {
			return nil, fmt.Errorf("open file %s: %w", fpath, err)
		}
		for {
			n, readErr := f.Read(buf)
			if n > 0 {
				if _, writeErr := h.Write(buf[:n]); writeErr != nil {
					f.Close()
					return nil, fmt.Errorf("hash file %s: %w", fpath, writeErr)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				f.Close()
				return nil, fmt.Errorf("read file %s: %w", fpath, readErr)
			}
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("close file %s: %w", fpath, err)
		}
	}

	return map[string]any{
		"size":      totalSize,
		"algorithm": algorithm,
		"value":     fmt.Sprintf("%x", h.Sum(nil)),
	}, nil
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
	if dataChecksum == nil {
		dataChecksum = map[string]any{
			"algorithm": "sm3",
			"value":     "N/A",
		}
	}
	if strings.TrimSpace(failureReason) == "" {
		failureReason = "TAA 异常崩溃重启，执行已被安全终止 (Process Interrupted by Crash)"
	}
	return buildTrainingReport(taskID, startedAt, finishedAt, "failed", 137, failureReason, modelChecksum, dataChecksum, nil, nil, false)
}

func buildTrainingReport(taskID string, startedAt, finishedAt time.Time, status string, exitCode int, failureReason string, modelChecksum map[string]any, dataChecksum map[string]any, trainingResult map[string]any, audit *codeaudit.AuditReport, includeAudit bool) (map[string]any, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		taskID = "task-" + finishedAt.UTC().Format("20060102-150405")
	}
	if status == "" {
		status = "succeeded"
	}
	if status != "succeeded" && strings.TrimSpace(failureReason) == "" {
		failureReason = "训练流程失败"
	}

	trainingTaskSource := objectField(trainingResult, "training_task")
	trainingTask := make(map[string]any, len(trainingTaskSource)+7)
	for key, value := range trainingTaskSource {
		if value != nil {
			trainingTask[key] = value
		}
	}
	trainingTask["task_id"] = taskID
	trainingTask["started_at"] = startedAt.UTC().Format(time.RFC3339)
	trainingTask["finished_at"] = finishedAt.UTC().Format(time.RFC3339)
	trainingTask["duration_seconds"] = durationSeconds(startedAt, finishedAt)
	trainingTask["status"] = status
	trainingTask["exit_code"] = exitCode
	trainingTask["failure_reason"] = nullableString(failureReason)

	trainingTaskMetrics := objectField(trainingTaskSource, "metrics")
	if len(trainingTaskMetrics) == 0 {
		trainingTaskMetrics = objectField(trainingResult, "metrics")
	}
	if len(trainingTaskMetrics) > 0 {
		trainingTask["metrics"] = trainingTaskMetrics
	}

	if modelChecksum != nil {
		trainingTask["model_checksum"] = modelChecksum
	}

	dataset := cleanDatasetField(objectField(trainingResult, "dataset"))
	if dataChecksum != nil {
		dataset["checksum"] = dataChecksum
	}

	report := map[string]any{
		"report_id":      newTrainingReportID(finishedAt),
		"generated_at":   finishedAt.UTC().Format(time.RFC3339),
		"schema_version": "1.0",
		"training_task":  trainingTask,
		"dataset":        dataset,
	}

	if includeAudit && audit != nil {
		if projected := projectCodeAuditSection(audit); projected != nil {
			report["codeaudit"] = projected
		}
	}

	return report, nil
}

func cleanDatasetField(src map[string]any) map[string]any {
	if len(src) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		if k == "data_structure" {
			continue
		}
		out[k] = v
	}
	return out
}

func objectField(src map[string]any, key string) map[string]any {
	if src == nil {
		return map[string]any{}
	}
	if v, ok := src[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func durationSeconds(startedAt, finishedAt time.Time) int64 {
	if startedAt.IsZero() || finishedAt.IsZero() {
		return 0
	}
	d := int64(finishedAt.Sub(startedAt).Seconds())
	if d < 0 {
		return 0
	}
	return d
}

func writeJSONFile(path string, payload any) error {
	return utils.WriteJSONFile(path, payload, 0o644)
}

func newTrainingReportID(now time.Time) string {
	stamp := now.UTC().Format("20060102-150405")
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("train-report-%s-00000000", stamp)
	}
	return fmt.Sprintf("train-report-%s-%x", stamp, b[:])
}

func nullableString(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}
