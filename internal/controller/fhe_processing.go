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

// fheResultArchiveName is the file name the FHE service gives its result
// archive. executeFHETask stores the service's bytes under this name and export
// reads them back unchanged, so both ends have to agree on it.
const fheResultArchiveName = "output.zip"

// validateFHEFields enforces the two eval key fields against the instance type.
//
// On an fhe instance both are mandatory: this instance exists to run FHE tasks,
// so an import without them has no meaning. On a tee instance their presence is
// an error rather than something to ignore - silently dropping them would let the
// platform believe an FHE task was submitted when nothing was.
//
// An fhe import also needs a taskId. The FHE service keys the task, its input
// directory and its results by that id, so a request carrying only a requestId
// has nothing to submit under. Rejecting it here answers 400 instead of letting
// the async stage discover it and report a failure.
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
	if strings.TrimSpace(req.TaskID) == "" {
		return fmt.Errorf("本实例类型为 fhe，taskId 不能为空")
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
	// MkdirShared, not MkdirAll: the service reads this package out of the shared
	// directory as another user, so <data>/models and <data>/models/<hash> have to
	// be enterable by it, and MkdirAll applies the process umask to the mode it is
	// given. The extracted tree below is fixed separately, after extraction.
	if err := layout.MkdirShared(modelDir); err != nil {
		s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("创建模型目录失败: %v", err))
		return
	}
	if err := extractArchiveToDir(modelDir, plaintextPath); err != nil {
		s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("解压模型包失败: %v", err))
		return
	}
	// Extraction decides the modes of everything under here, and it decides them
	// against the service: it replaces modelDir with a directory os.MkdirTemp made
	// (0700 regardless of umask) and writes each member with the mode the archive
	// carries, masked by the umask. Left alone, the package stages successfully,
	// activates, and is then unreadable to the process that was asked to load it.
	if err := layout.MakeTreeShared(modelDir); err != nil {
		s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("设置模型目录权限失败: %v", err))
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
	// The defer is the backstop, and clearing twice is harmless: clearFHEActiveTask
	// is a no-op unless the id still matches. Nothing below returns early before
	// the explicit clear at the end of Execute, so its live purpose is the panic
	// path - Execute unwinding through here releases the id instead of leaving it
	// set on an instance that has no task running.
	defer s.clearFHEActiveTask(req.TaskID)
	s.promoteCurrentTaskToFHE()

	s.Logs.Add(LogInfo, "fhe", "开始执行 FHE 任务: taskId=%s, userId=%s, modelId=%s", req.TaskID, spec.UserID, spec.ModelID)
	// The model runs inside the FHE service, so the training-side log watcher
	// (which tails ModelLogDir) has nothing to read here. The service's task log
	// is the training terminal log for this instance, and polling it is what
	// keeps the platform's log view populated while Execute blocks.
	stopLogs := s.startFHELogPoller(runner, req.RequestID, req.TaskID, spec.UserID)
	defer stopLogs()
	outcome, execErr := runner.Execute(context.Background(), spec, func(done, total int) {
		if total <= 0 {
			return
		}
		s.reportFHEProgress(req.RequestID, req.TaskID, float64(done)/float64(total)*100)
	})
	// Released the moment the run stops being cancellable, which is here: Execute
	// drops the run from the runner's in-flight table before it returns, so from
	// now on Runner.Cancel refuses the id - deliberately, because it cannot scope a
	// task it does not track to a tenant. Keeping the task marked active through
	// the result landing below (a multi-gigabyte copy or download) and the platform
	// reporting would answer a stop arriving there with a 500 for a run that in
	// fact succeeded. Cleared here, that stop falls through to the handler's
	// "不存在训练任务", which is the truth.
	s.clearFHEActiveTask(req.TaskID)

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
		dst := filepath.Join(resultDir, fheResultArchiveName)
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

	// Progress normally reaches 100% on the poll that observes the terminal
	// state, but the service's callback can resolve the run first, and the
	// callback path never polls again. Report the final percentage explicitly so
	// a finished task never leaves the platform's progress bar short of 100.
	if status == "succeeded" {
		s.reportFHEProgress(req.RequestID, req.TaskID, 100)
	}

	// The verdict export reads under fail-closed. A missing verdict would turn a
	// correct export into a 500, so it is recorded even though no scan ran.
	verdict := &resource.ResultCheckVerdict{
		Passed:    true,
		Details:   []string{"skipped: FHE ciphertext result"},
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Everything the record promises is produced first, and the record is committed
	// once, at the end, carrying the verdict with it.
	//
	// The order is the point. Export resolves the result directory, the report and
	// the verdict through this one record, so a record that exists before its
	// report does is a record export cannot honour: os.Stat answers 404 and the
	// platform never gets its report. And a verdict attached in a second call after
	// the commit is a window in which a committed record has none, which under
	// Security.ResultCheck is a permanent 500 at export. Both windows consumed the
	// requestId/taskId as well, so neither could be retried. Failing before the
	// commit leaves no record at all, and the rollback below - the same one the
	// failed-run paths use - puts the ids back in circulation.
	report, err := s.buildAndSaveTrainingReport(req.TaskID, startedAt, time.Now().UTC(), status, 0, failureReason, s.getLastAudit(), false, resultDir, verdict)
	if err != nil {
		s.Logs.Add(LogError, "fhe", "生成结果报告失败: %v", err)
		if store, storeErr := s.importIndexStore(); storeErr == nil {
			store.Rollback(req.RequestID, req.TaskID)
		}
		return
	}

	// Only a run that produced a result archive gets a record. A failed run leaves
	// nothing to export, and committing it would both stamp the "passed, skipped"
	// verdict above onto artifacts that were never produced and consume the
	// requestId/taskId for good: a committed record is durable, and the only thing
	// that removes one is the crash-recovery Purge for that exact task, which a
	// failed FHE run is not. Those paths release the reservation the handler took
	// instead, so the platform can submit the same ids again.
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
		//
		// The verdict travels in the record rather than being attached to it
		// afterwards. Committing it this way is what SetResultCheck would have
		// done - it looks the record up and replaces it in the same three places,
		// and sameImportIndexRecord ignores ResultCheck on purpose, so nothing
		// separates the two outcomes - minus its second durable write, which is the
		// step that could fail on its own.
		record := ImportIndexRecord{
			RequestID:   req.RequestID,
			TaskID:      req.TaskID,
			Hash:        modelHash,
			ResultDir:   resultDir,
			Phase:       phase,
			ResultCheck: verdict,
		}
		store, err := s.importIndexStore()
		if err != nil {
			s.Logs.Add(LogWarn, "fhe", "加载导入索引失败，结果将无法通过 export 取回: %v", err)
		} else if err := store.Commit(record); err != nil {
			s.Logs.Add(LogWarn, "fhe", "保存导入索引失败，结果将无法通过 export 取回: %v", err)
			store.Rollback(req.RequestID, req.TaskID)
		}
	}

	s.reportTrainingAsync(req.RequestID, req.TaskID, code, msg, string(report))
	s.Logs.Add(LogInfo, "import", "FHE 导入流程完成: taskId=%s, phase=%d", req.TaskID, phase)
}

// promoteCurrentTaskToFHE marks the in-flight import as a running task.
//
// It sets CurrentOp to "training" and nothing else. That string is load-bearing:
// isTrainingBusyLocked（route.go:723）keys on it, so without it a status query
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
