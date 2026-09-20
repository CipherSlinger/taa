package coordinator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"taa/internal/resource"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

// ExportParams 封装导出请求参数
type ExportParams struct {
	Phase     int
	RequestID string
	TaskID    string
	PublicKey string
}

// ExecuteExportFlow 执行阶段 3 / 阶段 4 产物信封加密导出流程
func (c *Coordinator) ExecuteExportFlow(params ExportParams) ([]byte, error) {
	pubKeyPEM := strings.TrimSpace(params.PublicKey)
	if params.Phase == 3 {
		// 阶段 3 产物必须使用阶段 1 导入的公钥加密导出
		savedKey := c.phaseState.ExportPublicKey()
		if savedKey == "" {
			return nil, pkgerrors.New(pkgerrors.CodeInvalidArgument, "阶段 3 产物必须使用阶段 1 导入的公钥加密导出，但此前未保存过公钥")
		}
		pubKeyPEM = savedKey
	} else if params.Phase == 4 {
		if pubKeyPEM == "" {
			return nil, pkgerrors.New(pkgerrors.CodeInvalidArgument, "publicKey 不能为空: 阶段 4 必须显式提供导出公钥")
		}
	} else {
		return nil, pkgerrors.New(pkgerrors.CodeInvalidArgument, fmt.Sprintf("当前阶段 %d 不支持导出，仅阶段 3 与阶段 4 支持导出", params.Phase))
	}

	// 解析目标结果目录
	resultDir := c.resolveExportResultDir(params.RequestID, params.TaskID)
	if _, err := os.Stat(resultDir); err != nil {
		return nil, pkgerrors.New(pkgerrors.CodeNotFound, fmt.Sprintf("未找到对应任务的产物目录: %s", resultDir))
	}

	return ExportResultToEnvelopeWithLimit(resultDir, pubKeyPEM, c.security.GetMaxFileBytes())
}

func (c *Coordinator) resolveExportResultDir(requestID, taskID string) string {
	if requestID != "" && taskID != "" {
		direct := filepath.Join(c.security.ResultDir, fmt.Sprintf("%s_%s", requestID, taskID))
		if _, err := os.Stat(direct); err == nil {
			return direct
		}
	}
	if c.indexStore != nil {
		if rec, err := c.indexStore.Lookup(requestID, taskID); err == nil && rec.ResultDir != "" {
			return rec.ResultDir
		}
		if latest, ok := c.indexStore.Latest(); ok && latest.ResultDir != "" {
			return latest.ResultDir
		}
	}
	latestRec := c.phaseState.LatestDataRecord()
	if latestRec.ResultDir != "" {
		return latestRec.ResultDir
	}
	return filepath.Join(c.security.ResultDir, fmt.Sprintf("%s_%s", requestID, taskID))
}

// ExportResultToEnvelope packages and SM2-SM4 envelope encrypts the result directory with default limit.
func ExportResultToEnvelope(resultDir string, pubKeyPEM string) ([]byte, error) {
	return ExportResultToEnvelopeWithLimit(resultDir, pubKeyPEM, DefaultMaxFileBytes)
}

// ExportResultToEnvelopeWithLimit packages and SM2-SM4 envelope encrypts the result directory,
// enforcing maxBytes on both zip and ciphertext outputs.
func ExportResultToEnvelopeWithLimit(resultDir string, pubKeyPEM string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFileBytes
	}
	pubKey, err := teecrypto.ParseSM2PublicKeyPEM([]byte(pubKeyPEM))
	if err != nil {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("解析导出 SM2 公钥失败: %v", err), err)
	}

	zipData, err := resource.CompressDirToZip(resultDir)
	if err != nil {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("压缩产物目录失败: %v", err), err)
	}
	if int64(len(zipData)) > maxBytes {
		return nil, pkgerrors.Errorf(pkgerrors.CodeInvalidArgument, "导出产物大小超过限制: %d bytes, 上限 %d bytes", len(zipData), maxBytes)
	}

	envelopeData, err := teecrypto.SealSM2SM4GCM(pubKey, zipData)
	if err != nil {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("SM2-SM4 信封加密失败: %v", err), err)
	}
	if int64(len(envelopeData)) > maxBytes {
		return nil, pkgerrors.Errorf(pkgerrors.CodeInvalidArgument, "导出加密产物大小超过限制: %d bytes, 上限 %d bytes", len(envelopeData), maxBytes)
	}
	return envelopeData, nil
}
