package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"taa/internal/codeaudit"
	"taa/internal/resource"
	"taa/internal/runtime"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
	"taa/pkg/utils"
)

// TrainingImportParams 封装数据导入与训练触发参数
type TrainingImportParams struct {
	RequestID   string
	TaskID      string
	Phase       int
	ResourceURL string
}

// ExecuteTrainingImportFlow 执行数据导入、去重解压与模型训练完整异步流水线
func (c *Coordinator) ExecuteTrainingImportFlow(ctx context.Context, params TrainingImportParams) error {
	startedAt := time.Now().UTC()
	c.phaseState.SetCurrentOp("downloading")

	defer func() {
		c.phaseState.SetCurrentOp("idle")
	}()

	// 1. 下载加密数据资源包
	ciphertextPath, _, err := resource.DownloadToTempFile(params.ResourceURL, resource.DefaultMaxDownloadBytes)
	if err != nil {
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, false, startedAt, fmt.Sprintf("下载数据资源失败: %v", err))
		return err
	}
	defer os.Remove(ciphertextPath)

	// 2. 解密信封
	c.phaseState.SetCurrentOp("decrypting")
	plainPath, isDecrypted, err := resource.ResolvePlaintextResource(params.ResourceURL, ciphertextPath, c.sm2PrivateKey)
	if err != nil {
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, false, startedAt, fmt.Sprintf("解密数据信封失败: %v", err))
		return err
	}
	if isDecrypted {
		defer os.Remove(plainPath)
	}

	// 3. 计算数据包 SM3 哈希并校验
	size, hash, err := teecrypto.HashFileSM3(plainPath)
	if err != nil {
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, false, startedAt, fmt.Sprintf("计算数据哈希失败: %v", err))
		return err
	}
	dataChecksum := map[string]any{
		"size":      size,
		"algorithm": "sm3",
		"value":     hash,
	}
	c.phaseState.SetDataChecksum(dataChecksum)

	// 4. 数据解压与哈希去重
	c.phaseState.SetCurrentOp("extracting")
	dataDir := filepath.Join(c.security.DataDir, hash)
	resultDir := filepath.Join(c.security.ResultDir, fmt.Sprintf("%s_%s", params.RequestID, params.TaskID))
	trainRecord := resource.ImportIndexRecord{
		RequestID: params.RequestID,
		TaskID:    params.TaskID,
		Hash:      hash,
		DataDir:   dataDir,
		ResultDir: resultDir,
		Phase:     params.Phase,
	}

	_, err = resource.EnsureArchiveExtractedIntoDir(dataDir, plainPath)
	if err != nil {
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, false, startedAt, fmt.Sprintf("展开数据目录失败: %v", err))
		return err
	}

	// 5. 写入导入索引引擎
	if c.indexStore != nil {
		if err := c.indexStore.Commit(trainRecord); err != nil {
			c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, false, startedAt, fmt.Sprintf("保存数据索引失败: %v", err))
			return err
		}
	}
	c.phaseState.SetDataRecords(trainRecord, trainRecord)

	// 6. 检查前置条件：若模型尚未导入，则仅完成数据存储，等待模型导入
	if !c.phaseState.IsModelImported() {
		return nil
	}

	// 7. 解析运行配置
	rawConfig := c.phaseState.RuntimeConfig()
	if strings.TrimSpace(rawConfig) == "" {
		errCfg := pkgerrors.New(pkgerrors.CodeInvalidArgument, "runtimeConfig 不能为空")
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, false, startedAt, errCfg.Error())
		return errCfg
	}
	cfg, env, err := runtime.ParseRuntimeConfig(rawConfig)
	if err != nil {
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, false, startedAt, err.Error())
		return err
	}

	// 8. 升级为训练在飞任务
	if err := c.taskManager.PromoteToTraining(); err != nil {
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, false, startedAt, err.Error())
		return err
	}
	_ = c.phaseState.SealState(c.taskManager.GetActiveTask())

	// 9. 执行训练
	c.phaseState.SetCurrentOp("training")
	control := c.taskManager.EnsureTrainingControl()
	defer control.Finish()

	return c.runTrainingWithTelemetry(ctx, control, cfg, env, trainRecord, startedAt)
}

func (c *Coordinator) runTrainingWithTelemetry(ctx context.Context, control *runtime.TrainingControl, cfg runtime.RuntimeConfig, env map[string]string, record resource.ImportIndexRecord, startedAt time.Time) error {
	inputDir := c.security.GetModelInputDir()
	outputDir := c.security.GetModelOutputDir()
	logDir := c.security.GetModelLogDir()
	progressDir := c.security.GetModelProgressDir()

	// 准备输入数据目录（拷贝）
	_ = os.RemoveAll(inputDir)
	_ = os.MkdirAll(inputDir, 0o755)
	if err := utils.CopyDir(inputDir, record.DataDir); err != nil {
		c.reportImportFailure(record.RequestID, record.TaskID, record.Phase, false, startedAt, fmt.Sprintf("复制训练数据失败: %v", err))
		return err
	}

	// 准备输出与遥测目录
	_ = os.RemoveAll(outputDir)
	_ = os.MkdirAll(outputDir, 0o755)
	_ = os.RemoveAll(logDir)
	_ = os.MkdirAll(logDir, 0o755)
	_ = os.RemoveAll(progressDir)
	_ = os.MkdirAll(progressDir, 0o755)

	// 启动后台遥测推送协程
	telemetryCtx, cancelTelemetry := context.WithCancel(ctx)
	defer cancelTelemetry()

	var telemetryWg sync.WaitGroup
	telemetryWg.Add(1)
	go func() {
		defer telemetryWg.Done()
		c.runTelemetryWatcher(telemetryCtx, record.RequestID, record.TaskID, logDir, progressDir)
	}()

	// 运行模型训练进程组
	runOut, runErr := runtime.RunRuntimeConfigWithControl(control, cfg, env, c.security.ModelDir, inputDir, outputDir, record.TaskID, startedAt.Format(time.RFC3339))
	cancelTelemetry()
	telemetryWg.Wait()

	finishedAt := time.Now().UTC()

	// 检查取消
	if control != nil && control.IsCancelled() {
		return context.Canceled
	}

	exitCode := 0
	status := "succeeded"
	failureReason := ""
	if runErr != nil {
		status = "failed"
		exitCode = 1
		failureReason = runErr.Error()
	}

	// 拷贝产物至结果目录
	_ = os.MkdirAll(record.ResultDir, 0o755)
	_ = utils.CopyDir(record.ResultDir, outputDir)

	// 生成训练报告
	trainResult, _ := runtime.LoadTrainingResult(filepath.Join(outputDir, "training_result.json"))
	var auditSection map[string]any
	if lastAudit := c.phaseState.LastAudit(); lastAudit != nil {
		auditSection = projectAuditToMap(lastAudit)
	}

	report, _ := runtime.BuildTrainingReport(record.TaskID, startedAt, finishedAt, status, exitCode, failureReason, c.phaseState.ModelChecksum(), c.phaseState.DataChecksum(), trainResult, auditSection)
	_ = utils.WriteJSONFile(filepath.Join(record.ResultDir, "training_report.json"), report, 0o644)

	// 上报结果到管控平台
	if c.platformClient != nil {
		code := 0
		if status != "succeeded" {
			code = 1
		}
		reportJSON := ""
		if b, err := json.Marshal(report); err == nil {
			reportJSON = string(b)
		}
		_ = c.platformClient.ReportRes(ctx, record.RequestID, record.TaskID, code, failureReason, reportJSON)
	}

	if runErr != nil {
		return fmt.Errorf("训练命令执行失败: %w, 输出: %s", runErr, runOut)
	}
	return nil
}

func (c *Coordinator) runTelemetryWatcher(ctx context.Context, requestID, taskID, logDir, progressDir string) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	logReader := runtime.NewJSONLLogReader(logDir)
	var lastProgressKey string

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 扫描并推送增量模型日志
			if newLogs, err := logReader.ReadNew(); err == nil && len(newLogs) > 0 {
				if c.platformClient != nil {
					_ = c.platformClient.ReportModelLog(ctx, requestID, taskID, newLogs[0].Seq, newLogs)
				}
			}
			// 扫描并推送进度快照
			if snapshot, ok, err := runtime.ReadLatestProgress(progressDir); err == nil && ok && snapshot.Key != lastProgressKey {
				lastProgressKey = snapshot.Key
				if c.platformClient != nil {
					_ = c.platformClient.ReportProgress(ctx, requestID, taskID, snapshot.Percent, snapshot.Timestamp)
				}
			}
		}
	}
}

// ExecuteTrainingRun 封装独立的训练执行过程（支持直接测试调用）
func ExecuteTrainingRun(control *runtime.TrainingControl, cfg runtime.RuntimeConfig, env map[string]string, modelDir, inputDir, outputDir, resultDir, taskID string) (string, error) {
	_ = os.MkdirAll(outputDir, 0o755)
	out, err := runtime.RunRuntimeConfigWithControl(control, cfg, env, modelDir, inputDir, outputDir, taskID, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return out, err
	}
	_ = os.MkdirAll(resultDir, 0o755)
	_ = utils.CopyDir(resultDir, outputDir)
	return out, nil
}

func projectAuditToMap(audit *codeaudit.AuditReport) map[string]any {
	if audit == nil {
		return nil
	}
	var fileReports any
	if audit.FileReports != nil {
		fileReports = cloneFileReports(audit.FileReports)
	}
	return map[string]any{
		"conclusion":   audit.Conclusion,
		"file_reports": fileReports,
	}
}

func cloneFileReports(src []codeaudit.FileReport) []codeaudit.FileReport {
	if src == nil {
		return nil
	}
	out := make([]codeaudit.FileReport, len(src))
	for i := range src {
		out[i] = src[i]
		if src[i].Findings != nil {
			out[i].Findings = append([]codeaudit.Finding{}, src[i].Findings...)
		}
	}
	return out
}
