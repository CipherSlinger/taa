package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"taa/internal/codeaudit"
	"taa/internal/resource"
	"taa/internal/runtime"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

// ModelImportParams 封装模型导入参数
type ModelImportParams struct {
	RequestID   string
	TaskID      string
	Phase       int
	ResourceURL string
}

// ExecuteModelImportFlow 执行模型导入核心异步流水线
func (c *Coordinator) ExecuteModelImportFlow(ctx context.Context, params ModelImportParams) error {
	startedAt := time.Now().UTC()
	c.phaseState.SetCurrentOp("downloading")

	defer func() {
		c.phaseState.SetCurrentOp("idle")
	}()

	// 1. 下载加密资源包
	ciphertextPath, _, err := resource.DownloadToTempFile(params.ResourceURL, resource.DefaultMaxDownloadBytes)
	if err != nil {
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, true, startedAt, fmt.Sprintf("下载模型资源失败: %v", err))
		return err
	}
	defer os.Remove(ciphertextPath)

	// 2. 解密信封
	c.phaseState.SetCurrentOp("decrypting")
	plainPath, isDecrypted, err := resource.ResolvePlaintextResource(params.ResourceURL, ciphertextPath, c.sm2PrivateKey)
	if err != nil {
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, true, startedAt, fmt.Sprintf("解密模型信封失败: %v", err))
		return err
	}
	if isDecrypted {
		defer os.Remove(plainPath)
	}

	// 3. 计算模型包 SM3 哈希并校验
	size, hash, err := teecrypto.HashFileSM3(plainPath)
	if err != nil {
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, true, startedAt, fmt.Sprintf("计算模型哈希失败: %v", err))
		return err
	}
	checksum := map[string]any{
		"size":      size,
		"algorithm": "sm3",
		"value":     hash,
	}
	c.phaseState.SetModelChecksum(checksum)

	// 4. 解压至模型目录（防 Zip-Slip 路径逃逸与 Zip-Bomb 膨胀）
	c.phaseState.SetCurrentOp("extracting")
	_ = os.RemoveAll(c.security.ModelDir)
	_ = os.MkdirAll(c.security.ModelDir, 0o755)
	if err := resource.ExtractArchiveToDir(c.security.ModelDir, plainPath); err != nil {
		c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, true, startedAt, fmt.Sprintf("解压模型资源失败: %v", err))
		return err
	}

	// 5. 阶段一完成：立即向平台上报模型导入成功与 checksum
	if c.platformClient != nil {
		_ = c.platformClient.ReportModelImport(ctx, params.RequestID, params.TaskID, 0, "模型导入成功", checksum)
	}

	// 6. 阶段二：代码安全审计
	c.phaseState.SetCurrentOp("auditing")
	if c.security.ScanEnabled {
		var llmClient codeaudit.LLMClient
		if c.security.LLM.Enabled && c.security.LLM.Endpoint != "" {
			llmClient = codeaudit.NewOllamaClient(c.security.LLM.Endpoint, c.security.LLM.Model, c.security.LLM.Timeout)
		}
		auditReport, scanErr := codeaudit.GenerateAuditReport(ctx, c.security.ModelDir, c.security.LLM, llmClient)
		if scanErr != nil {
			c.reportAuditFailure(params.RequestID, params.TaskID, scanErr.Error())
			_ = os.RemoveAll(c.security.ModelDir)
			return scanErr
		}

		c.phaseState.SetLastAudit(auditReport)

		reportJSON := ""
		if b, err := json.Marshal(auditReport); err == nil {
			reportJSON = string(b)
		}

		if c.platformClient != nil {
			code := 0
			msg := ""
			if !auditReport.Conclusion.Passed {
				code = 1
			}
			msg = auditReport.Conclusion.Summary
			_ = c.platformClient.ReportAudit(ctx, params.RequestID, params.TaskID, code, msg, reportJSON)
		}

		if !auditReport.Conclusion.Passed {
			_ = os.RemoveAll(c.security.ModelDir)
			errReject := pkgerrors.New(pkgerrors.CodeInternal, "模型代码安全审计未通过")
			c.reportImportFailure(params.RequestID, params.TaskID, params.Phase, true, startedAt, errReject.Error())
			return errReject
		}
	}

	// 7. 保存模型导入就绪状态
	c.phaseState.SetModelImported(true, params.ResourceURL)
	return nil
}

func (c *Coordinator) reportImportFailure(requestID, taskID string, phase int, isModel bool, startedAt time.Time, reason string) {
	if c.platformClient == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if isModel {
		_ = c.platformClient.ReportModelImport(ctx, requestID, taskID, 1, reason, nil)
	} else {
		// 生成失败 Schema 1.0 报告
		dataChecksum := c.phaseState.DataChecksum()
		modelChecksum := c.phaseState.ModelChecksum()
		report, _ := runtime.BuildCrashFailureReport(taskID, startedAt, time.Now().UTC(), reason, modelChecksum, dataChecksum)
		reportJSON := ""
		if b, err := json.Marshal(report); err == nil {
			reportJSON = string(b)
		}
		_ = c.platformClient.ReportRes(ctx, requestID, taskID, 1, reason, reportJSON)
	}
}

func (c *Coordinator) reportAuditFailure(requestID, taskID, reason string) {
	if c.platformClient == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.platformClient.ReportAudit(ctx, requestID, taskID, 1, reason, "")
}
