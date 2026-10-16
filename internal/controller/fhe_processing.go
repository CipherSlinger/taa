package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"taa/internal/fhe"
	"taa/internal/platform"
	"taa/internal/resource"
	teecrypto "taa/pkg/crypto"
)

// reportCodeFHEFailure is the /v1/taa/reportRes code for a failed FHE task. It is
// deliberately its own code rather than reusing the training-failure one: the two
// instance types fail for different reasons, and a single code would make the
// platform's log unable to tell them apart. 3 is the next free number after
// reportCodeResultLeak, whose definition stays in result_files.go together with
// the other codes.
const reportCodeFHEFailure = 3

// validateFHEFields enforces the two eval key fields against the instance type.
//
// On an fhe instance both are mandatory: this instance exists to run FHE tasks,
// so an import without them has no meaning. On a tee instance their presence is
// an error rather than something to ignore - silently dropping them would let the
// platform believe an FHE task was submitted when nothing was.
func (s *TAAState) validateFHEFields(req importRequest) error {
	hasURL := strings.TrimSpace(req.EvalKeyURL) != ""
	hasHash := strings.TrimSpace(req.EvalKeyFileHash) != ""

	if !s.fheEnabled() {
		if hasURL || hasHash {
			return fmt.Errorf("本实例类型为 tee，不接受 evalKeyUrl / evalKeyFileHash 字段")
		}
		return nil
	}
	if !hasURL || !hasHash {
		return fmt.Errorf("本实例类型为 fhe，evalKeyUrl 与 evalKeyFileHash 必须同时提供")
	}
	if !fhe.ValidHash(req.EvalKeyFileHash) {
		return fmt.Errorf("evalKeyFileHash 必须是 64 位小写十六进制 SM3 摘要")
	}
	return nil
}

// processImportedResourceFHE runs the FHE branch of an import.
//
// A model package is staged into the shared directory and activated; a data
// package is staged as a task input and submitted, which is what triggers FHE
// execution - the platform does not call switch to start a run.
func (s *TAAState) processImportedResourceFHE(req importRequest, phase int, isModel bool, plaintextPath string, startedAt time.Time) {
	runner := s.fheRunner()
	if runner == nil {
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, isModel, startedAt, "FHE 运行器未初始化")
		return
	}
	defer s.setCurrentOp("idle")

	if isModel {
		s.importFHEModel(req, phase, plaintextPath, startedAt, runner)
		return
	}
	s.executeFHETask(req, phase, plaintextPath, startedAt, runner)
}

// importFHEModel stages a model package into the shared directory and activates it.
//
// It deliberately does not go through beginModelImportAndAudit: an FHE model is a
// set of FHE layers and parameters the runtime loads, not user-supplied
// executable code, so there is no code audit to owe and no audit state to record.
//
// The export public key is not this function's to decline. The key travels in the
// request, and the request is read by modelImportHandler, which is where an fhe
// instance stops saving it - skipping this call never was what kept the
// model-import path envelope-free, and warning here would have announced a
// decision made somewhere else, after it had already been made.
func (s *TAAState) importFHEModel(req importRequest, phase int, plaintextPath string, startedAt time.Time, runner *fhe.Runner) {
	size, hash, err := teecrypto.HashFileSM3(plaintextPath)
	if err != nil {
		s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("计算模型包哈希失败: %v", err))
		return
	}
	s.setModelChecksum(map[string]any{"size": size, "algorithm": "sm3", "value": hash})

	layout := runner.Layout()
	modelDir, err := layout.ModelDir(hash)
	if err != nil {
		s.reportImportFailure(req, phase, true, startedAt, err.Error())
		return
	}
	if err := os.MkdirAll(modelDir, 0o755); err != nil {
		s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("创建模型目录失败: %v", err))
		return
	}
	if err := extractArchiveToDir(modelDir, plaintextPath); err != nil {
		s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("解压模型包失败: %v", err))
		return
	}
	// The package layout is the delivery bundle's, not ours to guess: an archive
	// without server/ is the wrong package, and inventing a level for it would
	// surface much later as an activation failure.
	if _, err := os.Stat(filepath.Join(modelDir, "server")); err != nil {
		s.reportImportFailure(req, phase, true, startedAt, "模型包结构不符：解压后缺少 server/ 目录")
		return
	}
	s.Logs.Add(LogInfo, "importModel", "FHE 模型已落盘: modelId=%s, dir=%s", hash, modelDir)

	s.reportModelImportAsync(req.RequestID, req.TaskID, 0, "模型导入成功", map[string]any{
		"size": size, "algorithm": "sm3", "value": hash,
	})

	if runner.Config().ActivateModelOnImport {
		ctx, cancel := context.WithTimeout(context.Background(), runner.Config().RequestTimeout)
		err := runner.Client().ActivateModel(ctx, hash)
		cancel()
		if err != nil {
			// Activation is idempotent and retried on the next import, so a failure
			// here is reported but does not fail the import: the model is on disk and
			// the service also loads it lazily on the first task.
			s.Logs.Add(LogWarn, "importModel", "FHE 模型激活失败(将在首次任务时重试): modelId=%s, err=%v", hash, err)
		} else {
			s.Logs.Add(LogInfo, "importModel", "FHE 模型已激活: modelId=%s", hash)
		}
	}

	s.Logs.Add(LogInfo, "import", "阶段%d: FHE 模型导入完成(免代码审计)，等待数据下发触发 FHE 任务: taskId=%s", phase, req.TaskID)
}

// executeFHETask stages the input archive, submits the FHE task, waits for its
// terminal state, and writes the result into the task's ResultDir.
//
// The result archive is kept byte-for-byte under its delivery-bundle name
// output.zip, alongside a training_report.json written by the same helper the
// training path uses. Reusing that report is what lets export work unchanged:
// it requires training_report.json to exist, and it is the same file the
// platform already knows how to read.
func (s *TAAState) executeFHETask(req importRequest, phase int, plaintextPath string, startedAt time.Time, runner *fhe.Runner) {
	isArchive, err := isArchiveFile(plaintextPath)
	if err != nil || !isArchive {
		s.reportImportFailure(req, phase, false, startedAt, "输入包不是压缩包，FHE 任务输入必须是 zip")
		return
	}

	s.mu.RLock()
	modelHash := ""
	if v, ok := s.ModelChecksum["value"].(string); ok {
		modelHash = v
	}
	s.mu.RUnlock()
	if modelHash == "" {
		s.reportImportFailure(req, phase, false, startedAt, "尚未导入模型：FHE 任务需要先通过 importModel 下发模型包")
		return
	}

	resultDir := resultDirForRequestTask(s.Security.ResultDir, req.RequestID, req.TaskID)
	if err := os.MkdirAll(resultDir, 0o755); err != nil {
		s.reportImportFailure(req, phase, false, startedAt, fmt.Sprintf("创建结果目录失败: %v", err))
		return
	}

	spec := fhe.TaskSpec{
		TaskID:       req.TaskID,
		RequestID:    req.RequestID,
		UserID:       req.EvalKeyFileHash,
		ModelID:      modelHash,
		EvalKeyHash:  req.EvalKeyFileHash,
		EvalKeyURL:   req.EvalKeyURL,
		InputZipPath: plaintextPath,
	}

	s.setFHEActiveTask(req.TaskID)
	defer s.clearFHEActiveTask(req.TaskID)
	s.promoteCurrentTaskToFHE()

	s.Logs.Add(LogInfo, "fhe", "开始执行 FHE 任务: taskId=%s, userId=%s, modelId=%s", req.TaskID, spec.UserID, spec.ModelID)
	outcome, execErr := runner.Execute(context.Background(), spec, func(done, total int) {
		if total <= 0 {
			return
		}
		s.reportFHEProgress(req.RequestID, req.TaskID, float64(done)/float64(total)*100)
	})

	status, failureReason, code, msg := "succeeded", "", 0, ""
	if execErr != nil {
		status = "failed"
		failureReason = execErr.Error()
		code = reportCodeFHEFailure
		msg = fmt.Sprintf("FHE 任务失败: %s", execErr.Error())
		s.Logs.Add(LogError, "fhe", "FHE 任务失败: taskId=%s, err=%v", req.TaskID, execErr)
	} else {
		s.Logs.Add(LogInfo, "fhe", "FHE 任务完成: taskId=%s, cases=%d, failed=%d", req.TaskID, outcome.Total, outcome.Failed)
	}

	// The ciphertext result is not scanned for plaintext leakage: the artifacts
	// are FHE ciphertexts, which is exactly what this instance exists to move.
	if execErr == nil {
		dst := filepath.Join(resultDir, "output.zip")
		if _, err := runner.CopyResult(context.Background(), spec, outcome, dst); err != nil {
			status = "failed"
			failureReason = fmt.Sprintf("取回 FHE 结果失败: %v", err)
			code = reportCodeFHEFailure
			msg = failureReason
			s.Logs.Add(LogError, "fhe", "取回 FHE 结果失败: taskId=%s, err=%v", req.TaskID, err)
		} else {
			s.Logs.Add(LogInfo, "fhe", "FHE 结果已落盘: %s", dst)
		}
	}

	// The verdict export reads under fail-closed. A missing verdict would turn a
	// correct export into a 500, so it is recorded even though no scan ran.
	verdict := &resource.ResultCheckVerdict{
		Passed:    true,
		Details:   []string{"skipped: FHE ciphertext result"},
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// The import index record, and then the verdict attached to it, in that order:
	// export resolves both ResultDir and the verdict through this record, and
	// SetResultCheck refuses to attach one to a record that was never committed.
	// Without the record there is no way to retrieve a result at all - the import
	// handler reserved the ids, and a reservation alone is not lookup-able.
	//
	// Only a run that produced a result archive gets a record. A failed run leaves
	// nothing to export, and committing it would both stamp the "passed, skipped"
	// verdict above onto artifacts that were never produced and consume the
	// requestId/taskId for the life of the process. Those paths release the
	// reservation the handler took instead, so the platform can submit the same
	// ids again.
	if status != "succeeded" {
		if store, err := s.importIndexStore(); err == nil {
			store.Rollback(req.RequestID, req.TaskID)
		}
	} else {
		// Hash is the FHE model digest rather than a digest of the data package:
		// the training path records the resource it staged for the run, and on this
		// instance the run is bound to a model - the same digest the task carried
		// as model_id. DataDir stays empty on purpose: the training path points it
		// at the directory the data package was extracted into (keyed by Hash), and
		// this path extracts nothing into a hash directory - the input package is
		// published to the runner's per-task input file, and Hash here is the
		// model's, so a path derived from it would name a directory that does not
		// exist. Phase is the phase the import ran under, as on the training path:
		// export reads 0 as "use whatever phase the instance is in now", which
		// would let a later phase change pick a different export key.
		record := ImportIndexRecord{
			RequestID: req.RequestID,
			TaskID:    req.TaskID,
			Hash:      modelHash,
			ResultDir: resultDir,
			Phase:     phase,
		}
		store, err := s.importIndexStore()
		if err != nil {
			s.Logs.Add(LogWarn, "fhe", "加载导入索引失败，结果将无法通过 export 取回: %v", err)
		} else if err := store.Commit(record); err != nil {
			s.Logs.Add(LogWarn, "fhe", "保存导入索引失败，结果将无法通过 export 取回: %v", err)
			store.Rollback(req.RequestID, req.TaskID)
		} else if err := store.SetResultCheck(req.RequestID, req.TaskID, verdict); err != nil {
			s.Logs.Add(LogWarn, "fhe", "保存跳过裁决失败: %v", err)
		}
	}

	report, err := s.buildAndSaveTrainingReport(req.TaskID, startedAt, time.Now().UTC(), status, 0, failureReason, s.getLastAudit(), false, resultDir, verdict)
	if err != nil {
		s.Logs.Add(LogError, "fhe", "生成结果报告失败: %v", err)
		return
	}
	s.reportTrainingAsync(req.RequestID, req.TaskID, code, msg, string(report))
	s.Logs.Add(LogInfo, "import", "FHE 导入流程完成: taskId=%s, phase=%d", req.TaskID, phase)
}

// promoteCurrentTaskToFHE marks the in-flight import as a running task.
//
// It sets CurrentOp to "training" and nothing else. That string is load-bearing:
// isTrainingBusyLocked（route.go:673）keys on it, so without it a status query
// during an FHE run would report the instance as free while a task is using the
// GPU. It is deliberately the existing value rather than a new "fhe" one, because
// effectiveOpLocked returns CurrentOp verbatim to the platform and a value the
// platform has never seen would be a status it cannot render.
//
// TrainingRunning stays false on purpose: no training process exists, and setting
// that flag would make stopTraining try to kill a process group that is not there.
// The FHE task is tracked by fheActiveTaskID instead, which is what stopTraining
// checks first.
//
// activeTask.Type is likewise left alone. tryAcquireTask already set it to
// "data_import" or "training", and it is echoed to the platform as taskType by
// the panic-recovery path（route.go:890）, so overwriting it with a new string
// would send an unknown task type on the one path that is already going wrong.
func (s *TAAState) promoteCurrentTaskToFHE() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentOp = "training"
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "task", "持久化 FHE 任务状态失败: %v", err)
	}
}

// reportFHEProgress forwards a task's percentage to the platform.
func (s *TAAState) reportFHEProgress(requestID, taskID string, percent float64) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()
	if platformIP == "" {
		return
	}
	go func() {
		if err := platform.ReportProgress(context.Background(), platformIP, dockerID, requestID, taskID, percent, time.Now().UTC()); err != nil {
			s.Logs.Add(LogWarn, "fhe", "上报 FHE 任务进度失败: %v", err)
		}
	}()
}
