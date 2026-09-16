package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"taa/internal/resource"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
	"taa/pkg/utils"
)

type exportRequest struct {
	PublicKey *string `json:"publicKey"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
}

// compressDirToZip 将目录压缩为 zip 格式的字节切片，并对软链接进行越界安全校验。
func compressDirToZip(srcDir string) ([]byte, error) {
	return resource.CompressDirToZip(srcDir)
}

func safeFilenamePart(value string) string {
	res := utils.SafeFilename(value)
	if res == "default" {
		return "request"
	}
	return res
}

func (s *TAAState) exportHandler(w http.ResponseWriter, r *http.Request) {
	var req exportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.TaskID = strings.TrimSpace(req.TaskID)
	if req.RequestID == "" && req.TaskID == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "requestId 和 taskId 不能同时为空"))
		return
	}

	store, err := s.importIndexStore()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("加载导入索引失败: %v", err), err))
		return
	}

	record, err := store.Lookup(req.RequestID, req.TaskID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
	}

	if _, err := os.Stat(filepath.Join(record.ResultDir, "training_report.json")); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("结果文件不存在: %s", filepath.Join(record.ResultDir, "training_report.json")))
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("检查结果文件失败: %v", err))
		return
	}

	s.mu.RLock()
	currentPhase := s.CurrentPhase
	savedPublicKey := s.ExportPublicKey
	s.mu.RUnlock()

	recordPhase := record.Phase
	if recordPhase == 0 {
		recordPhase = currentPhase
	}

	s.Logs.Add(LogInfo, "export", "收到导出请求: requestId=%s, taskId=%s, hash=%s, resultDir=%s, recordPhase=%d, currentPhase=%d",
		req.RequestID, req.TaskID, record.Hash, record.ResultDir, recordPhase, currentPhase)

	// ── 确定公钥和是否加密 ──
	var pubKeyPEM string
	var encrypt bool

	switch recordPhase {
	case 1, 2:
		if req.PublicKey != nil && strings.TrimSpace(*req.PublicKey) != "" {
			pubKeyPEM = strings.TrimSpace(*req.PublicKey)
			encrypt = true
			s.Logs.Add(LogInfo, "export", "阶段%d: 使用请求中的 publicKey 加密 (长度=%d)", recordPhase, len(pubKeyPEM))
		} else {
			s.Logs.Add(LogInfo, "export", "阶段%d: 未传入 publicKey，返回明文", recordPhase)
		}

	case 3:
		if savedPublicKey == "" {
			s.Logs.Add(LogError, "export", "阶段3: ExportPublicKey 为空，无法加密导出")
			writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "阶段 3 产物必须使用阶段 1 导入的公钥加密导出"))
			return
		}
		pubKeyPEM = savedPublicKey
		encrypt = true
		s.Logs.Add(LogInfo, "export", "阶段3: 使用阶段1保存的 ExportPublicKey 加密 (长度=%d)\n%s", len(pubKeyPEM), pubKeyPEM)

	default:
		s.Logs.Add(LogError, "export", "不支持的阶段: %d", recordPhase)
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, fmt.Sprintf("当前阶段 %d 不支持导出", recordPhase)))
		return
	}

	resultData, err := resource.CompressDirToZip(record.ResultDir)
	if err != nil {
		s.Logs.Add(LogError, "export", "压缩结果目录失败: %v", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("压缩结果目录失败: %v", err))
		return
	}

	filename := filepath.Base(record.ResultDir) + ".zip"

	if encrypt {
		pub, err := teecrypto.ParseSM2PublicKeyPEM([]byte(pubKeyPEM))
		if err != nil {
			s.Logs.Add(LogError, "export", "publicKey 解析失败: %v", err)
			writeError(w, http.StatusBadRequest, fmt.Sprintf("publicKey 解析失败: %v", err))
			return
		}
		sealed, err := teecrypto.SealSM2SM4GCM(pub, resultData)
		if err != nil {
			s.Logs.Add(LogError, "export", "加密失败: %v", err)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("加密失败: %v", err))
			return
		}
		filename += ".enc"
		s.Logs.Add(LogInfo, "export", "加密完成: 明文=%d bytes, 密文=%d bytes, taskId=%s, filename=%s", len(resultData), len(sealed), req.TaskID, filename)
		writeFileStream(w, req.TaskID, filename, true, int64(len(sealed)), bytes.NewReader(sealed), "导出加密结果失败")
		return
	}

	s.Logs.Add(LogInfo, "export", "明文导出: 大小=%d bytes, taskId=%s, filename=%s", len(resultData), req.TaskID, filename)
	writeFileStream(w, req.TaskID, filename, false, int64(len(resultData)), bytes.NewReader(resultData), "导出明文结果失败")
}
