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
// skipRootNames 见 resource.CompressDirToZip：列出根目录下不进导出清单的文件名。
func compressDirToZip(srcDir string, skipRootNames ...string) ([]byte, error) {
	return resource.CompressDirToZip(srcDir, skipRootNames...)
}

func safeFilenamePart(value string) string {
	res := utils.SafeFilename(value)
	if res == "default" {
		return "request"
	}
	return res
}

// exportPublicKeyForRequest resolves the public key an export should encrypt to.
//
// A server.type=fhe instance always returns empty: it never records an export
// public key, and the export envelope is out of scope for this instance type. A
// key carried in the request would otherwise reintroduce the envelope, so it is
// ignored with a warning rather than silently honoured - the caller expects an
// envelope when it sends one, and a silent drop would leave it unable to read the
// result.
func (s *TAAState) exportPublicKeyForRequest(req *string) string {
	if s.fheEnabled() {
		if req != nil && strings.TrimSpace(*req) != "" {
			s.Logs.Add(LogWarn, "export", "FHE 实例不提供导出信封，忽略请求携带的 publicKey")
		}
		return ""
	}
	if req == nil {
		return ""
	}
	return strings.TrimSpace(*req)
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

	if _, err := os.Stat(filepath.Join(record.ResultDir, trainingReportFileName)); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("结果文件不存在: %s", filepath.Join(record.ResultDir, trainingReportFileName)))
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("检查结果文件失败: %v", err))
		return
	}

	s.mu.RLock()
	currentPhase := s.CurrentPhase
	s.mu.RUnlock()

	savedPublicKey := s.getExportPublicKey()
	// The phase-3 branch below prefers the saved key, so the instance type has to
	// decide it here too. An fhe instance must not encrypt, and this field
	// outlives the code that used to record it: it is part of the sealed state, so
	// a value written by an older build - or by a boot of this container as a tee
	// instance - would reseal the export if it were read unguarded.
	if s.fheEnabled() {
		savedPublicKey = ""
	}

	recordPhase := record.Phase
	if recordPhase == 0 {
		recordPhase = currentPhase
	}

	s.Logs.Add(LogInfo, "export", "收到导出请求: requestId=%s, taskId=%s, hash=%s, resultDir=%s, recordPhase=%d, currentPhase=%d",
		req.RequestID, req.TaskID, record.Hash, record.ResultDir, recordPhase, currentPhase)

	maxBytes := s.Security.GetMaxFileBytes()
	// The leakage check itself runs right after training finishes and its verdict is
	// persisted on this record, so export never pays the scan again. A verdict that
	// says the result leaks always blocks. The two states without a usable verdict -
	// none recorded at all, or one recording that the check could not run - block only
	// under fail-closed: llm.failClosed=false turns those two into a warning and lets
	// the export through.
	if s.Security.ResultCheck {
		verdict := record.ResultCheck
		failClosed := s.Security.LLM.FailClosed
		switch {
		case verdict == nil:
			if failClosed {
				s.Logs.Add(LogError, "export", "结果安全检查裁决缺失，拒绝导出（fail-closed）: resultDir=%s", record.ResultDir)
				writeErr(w, http.StatusInternalServerError, pkgerrors.New(pkgerrors.CodeInternal, "结果安全检查裁决缺失，拒绝导出（fail-closed）"))
				return
			}
			s.Logs.Add(LogWarn, "export", "结果安全检查裁决缺失，llm.failClosed=false，按配置放行: resultDir=%s", record.ResultDir)
		case verdict.Error != "":
			if failClosed {
				s.Logs.Add(LogError, "export", "结果安全检查执行失败，拒绝导出: %s", verdict.Error)
				writeErr(w, http.StatusInternalServerError, pkgerrors.Errorf(pkgerrors.CodeInternal, "结果安全检查执行失败，拒绝导出: %s", verdict.Error))
				return
			}
			s.Logs.Add(LogWarn, "export", "结果安全检查执行失败，llm.failClosed=false，按配置放行: %s", verdict.Error)
		case !verdict.Passed:
			msg := fmt.Sprintf("导出结果安全检查未通过，存在高危数据泄露隐患: %s", strings.Join(verdict.Details, "; "))
			s.Logs.Add(LogError, "export", "%s", msg)
			writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, msg))
			return
		default:
			s.Logs.Add(LogInfo, "export", "结果安全检查通过 (checkedAt=%s)", verdict.CheckedAt)
		}
	}

	// ── 确定公钥和是否加密 ──
	// The export key is optional on every phase: the first non-empty candidate
	// wins, and with no candidate at all the artifacts go out in plaintext.
	// Phase 3 prefers the key saved at model import and falls back to the one
	// carried by this request; phases 1/2 only ever use the request's. On an fhe
	// instance both candidates resolve empty, which is what puts this export in
	// the plaintext branch below.
	reqPubKey := s.exportPublicKeyForRequest(req.PublicKey)

	var pubKeyPEM, keySource string
	switch recordPhase {
	case 1, 2:
		pubKeyPEM, keySource = reqPubKey, "请求中的 publicKey"
	case 3:
		pubKeyPEM, keySource = savedPublicKey, "阶段1保存的 ExportPublicKey"
		if pubKeyPEM == "" {
			pubKeyPEM, keySource = reqPubKey, "请求中的 publicKey"
		}
	default:
		s.Logs.Add(LogError, "export", "不支持的阶段: %d", recordPhase)
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, fmt.Sprintf("当前阶段 %d 不支持导出", recordPhase)))
		return
	}

	if pubKeyPEM == "" {
		s.Logs.Add(LogInfo, "export", "阶段%d: 无可用 publicKey，返回明文", recordPhase)
	} else {
		s.Logs.Add(LogInfo, "export", "阶段%d: 使用 %s 加密 (长度=%d)", recordPhase, keySource, len(pubKeyPEM))
	}

	// The report is TAA's own metadata and carries table previews (dataset rows) by
	// design, so it is packed out of the export rather than shipped with it. It is
	// also the one file the leakage check skips, for the same reason.
	//
	// An FHE result already arrives as an archive: executeFHETask stores the
	// service's output.zip byte-for-byte. Re-zipping the result directory would
	// wrap that archive in a second one and make the platform unpack twice, so the
	// stored bytes are exported as they are and only the response filename changes.
	var resultData []byte
	if s.fheEnabled() {
		resultData, err = os.ReadFile(filepath.Join(record.ResultDir, fheResultArchiveName))
		if err != nil {
			s.Logs.Add(LogError, "export", "读取 FHE 结果包失败: %v", err)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("读取 FHE 结果包失败: %v", err))
			return
		}
	} else {
		resultData, err = compressDirToZip(record.ResultDir, trainingReportFileName)
		if err != nil {
			s.Logs.Add(LogError, "export", "压缩结果目录失败: %v", err)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("压缩结果目录失败: %v", err))
			return
		}
	}

	if int64(len(resultData)) > maxBytes {
		s.Logs.Add(LogError, "export", "导出产物大小超限: %d bytes > %d bytes", len(resultData), maxBytes)
		writeErr(w, http.StatusBadRequest, pkgerrors.Errorf(pkgerrors.CodeInvalidArgument, "导出产物大小超过限制: %d bytes, 上限 %d bytes", len(resultData), maxBytes))
		return
	}

	filename := filepath.Base(record.ResultDir) + ".zip"

	if pubKeyPEM != "" {
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
		if int64(len(sealed)) > maxBytes {
			s.Logs.Add(LogError, "export", "导出加密产物大小超限: %d bytes > %d bytes", len(sealed), maxBytes)
			writeErr(w, http.StatusBadRequest, pkgerrors.Errorf(pkgerrors.CodeInvalidArgument, "导出加密产物大小超过限制: %d bytes, 上限 %d bytes", len(sealed), maxBytes))
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
