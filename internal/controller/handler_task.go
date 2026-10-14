package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"taa/internal/resource"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

// importRequest is the body shared by /v1/taa/import and /v1/taa/importModel.
//
// The early combined flow routed on a "type" field (1=model, 2=debug data,
// 3=training data). That field is ignored: there is no field for it here, so
// decoding drops it and a client that still sends one changes nothing. Which
// resource a request carries is decided by the endpoint alone.
type importRequest struct {
	ResourceURL   string  `json:"resourceUrl"`
	RequestID     string  `json:"requestId"`
	TaskID        string  `json:"taskId"`
	PublicKey     *string `json:"publicKey,omitempty"`
	RuntimeConfig string  `json:"runtimeConfig,omitempty"`
}

func (r *importRequest) UnmarshalJSON(data []byte) error {
	type Alias importRequest
	aux := &struct {
		RuntimeConfig any `json:"runtimeConfig"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	switch v := aux.RuntimeConfig.(type) {
	case string:
		r.RuntimeConfig = v
	case nil:
		r.RuntimeConfig = ""
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		r.RuntimeConfig = string(b)
	}
	return nil
}

// ── Handler: /v1/taa/stopTraining ────────────────────────

func (s *TAAState) stopTrainingHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	control := s.trainingControl
	isTraining := s.TrainingRunning && s.activeTask != nil && s.activeTask.Type == "training"
	s.mu.RUnlock()

	if control == nil || !isTraining {
		writeEnvelope(w, http.StatusOK, "不存在训练任务", nil, 0)
		return
	}

	cmd := control.requestStop()
	if cmd != nil {
		if err := KillProcessGroup(cmd); err != nil {
			s.Logs.Add(LogWarn, "stopTraining", "中止训练进程组警告: %v", err)
		}
	}

	select {
	case <-control.done:
		writeEnvelope(w, http.StatusOK, "训练任务已中止", nil, 0)
	case <-time.After(5 * time.Second):
		s.Logs.Add(LogError, "stopTraining", "等待训练任务中止超时 (5s)")
		writeError(w, http.StatusInternalServerError, "中止训练任务超时")
	}
}

// ── Handler: /v1/taa/import ──────────────────────────────

func (s *TAAState) importHandler(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}
	req.ResourceURL = strings.TrimSpace(req.ResourceURL)
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.TaskID = strings.TrimSpace(req.TaskID)
	if req.ResourceURL == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "resourceUrl 不能为空"))
		return
	}
	if req.RequestID == "" && req.TaskID == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "requestId 和 taskId 不能同时为空"))
		return
	}

	// Encrypted data resources use the shape "envelope in the URL, ciphertext
	// downloaded on its own": resourceUrl looks like
	// <download link>?dataKeyCipher=<hex C1C3C2>.
	// The envelope is unwrapped before the download, so a malformed value or a key
	// mismatch surfaces without first pulling the whole ciphertext.
	downloadURL, dataKeyCipherHex, hasDataKeyCipher, err := resource.SplitDataKeyCipher(req.ResourceURL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
	}
	var dataKey []byte
	if hasDataKeyCipher {
		wrapped, err := teecrypto.ParseWrappedDataKeyHex(dataKeyCipherHex)
		if err != nil {
			writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
			return
		}
		dataKey, err = teecrypto.UnwrapKeySM2(s.SM2PrivateKey, wrapped)
		if err != nil {
			writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument,
				fmt.Sprintf("dataKeyCipher 解封失败: %v", err), err))
			return
		}
	}

	release, err := s.tryAcquireTask(req.TaskID, req.RequestID, "downloading", false)
	if err != nil {
		s.Logs.Add(LogWarn, "import", "拒绝并发任务请求: %v", err)
		writeErr(w, http.StatusConflict, err)
		return
	}

	store, err := s.importIndexStore()
	if err != nil {
		release()
		writeErr(w, http.StatusInternalServerError, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("加载导入索引失败: %v", err), err))
		return
	}
	if err := store.Reserve(req.RequestID, req.TaskID); err != nil {
		release()
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
	}

	s.mu.RLock()
	phase := s.CurrentPhase
	s.mu.RUnlock()

	s.Logs.Add(LogInfo, "import", "收到数据 import 请求: taskId=%s, requestId=%s, phase=%d",
		req.TaskID, req.RequestID, phase)

	if strings.TrimSpace(req.RuntimeConfig) != "" {
		s.mu.Lock()
		s.RuntimeConfig = req.RuntimeConfig
		// Sealed exactly like the model import path. Left in memory only, the
		// overwrite would survive until the next restart and then silently revert
		// this run to the previous configuration.
		if err := s.sealStateLocked(); err != nil {
			s.Logs.Add(LogError, "state", "持久化 runtimeConfig 失败: %v", err)
		}
		s.mu.Unlock()
		s.Logs.Add(LogInfo, "import", "已保存 runtimeConfig (长度=%d)", len(req.RuntimeConfig))
	}

	msg := "资源已接收，下载处理中"
	s.setCurrentOp("downloading")
	s.Logs.Add(LogInfo, "import", "开始下载资源: %s", downloadURL)
	ciphertextPath, size, err := s.downloadToTempFile(downloadURL)
	if err != nil {
		store.Rollback(req.RequestID, req.TaskID)
		release()
		s.Logs.Add(LogError, "import", "下载资源失败: %v", err)
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.Logs.Add(LogInfo, "import", "下载完成 (%d bytes) -> %s", size, ciphertextPath)

	msg = "数据已接收，训练结果将通过 reportRes 上报"
	writeEnvelope(w, http.StatusOK, msg, nil, 0)

	s.runAsyncSafe("processImportedResource", release, func() {
		s.processImportedResource(req, phase, false, ciphertextPath, dataKey)
	})
}

// ── Handler: /v1/taa/importModel ─────────────────────────

func (s *TAAState) modelImportHandler(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}
	req.ResourceURL = strings.TrimSpace(req.ResourceURL)
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.TaskID = strings.TrimSpace(req.TaskID)
	if req.RequestID == "" && req.TaskID == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "requestId 和 taskId 不能同时为空"))
		return
	}

	hasSavedModel := s.hasSavedModel()

	if req.ResourceURL == "" {
		if !hasSavedModel {
			writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "resourceUrl 不能为空: 之前未传输过且请求中为空"))
			return
		}
	}

	s.mu.RLock()
	phase := s.CurrentPhase
	s.mu.RUnlock()

	var publicKey string
	hasPublicKeyInput := req.PublicKey != nil && strings.TrimSpace(*req.PublicKey) != ""
	savedPublicKey := s.getExportPublicKey()

	if phase == 1 && hasPublicKeyInput {
		cleanKey := strings.TrimSpace(*req.PublicKey)
		if _, err := teecrypto.ParseSM2PublicKeyPEM([]byte(cleanKey)); err != nil {
			writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("publicKey 解析失败: %v", err), err))
			return
		}
		publicKey = *req.PublicKey
		s.mu.Lock()
		if s.ExportPublicKey == "" {
			s.ExportPublicKey = publicKey
			_ = s.sealStateLocked()
			s.Logs.Add(LogInfo, "importModel", "阶段1: 已保存 ExportPublicKey 用于后续阶段3导出 (长度=%d)\n%s", len(publicKey), publicKey)
		} else {
			s.Logs.Add(LogInfo, "importModel", "阶段1: ExportPublicKey 已存在，保留首次公钥，跳过保存 (已有长度=%d, 新长度=%d)", len(s.ExportPublicKey), len(publicKey))
		}
		s.mu.Unlock()
	} else if phase == 1 {
		// publicKey is optional on this endpoint: a platform that sends none is
		// not doing anything wrong, it just leaves no key saved for the export.
		if savedPublicKey == "" {
			s.Logs.Add(LogInfo, "importModel", "阶段1: 未提供 publicKey 且此前未保存过，本次不保存导出公钥")
		} else {
			s.Logs.Add(LogInfo, "importModel", "阶段1: 请求未提供 publicKey，复用已保存的 ExportPublicKey (长度=%d)", len(savedPublicKey))
		}
	}

	s.Logs.Add(LogInfo, "importModel", "收到模型 import 请求: taskId=%s, requestId=%s, phase=%d, resourceUrlEmpty=%v",
		req.TaskID, req.RequestID, phase, req.ResourceURL == "")

	if strings.TrimSpace(req.RuntimeConfig) != "" {
		s.mu.Lock()
		s.RuntimeConfig = req.RuntimeConfig
		_ = s.sealStateLocked()
		s.mu.Unlock()
		s.Logs.Add(LogInfo, "importModel", "已保存 runtimeConfig (长度=%d)", len(req.RuntimeConfig))
	}

	// 若 resourceUrl 为空且已有保存的模型，仅更新 runtimeConfig，绝不触发训练任务
	if req.ResourceURL == "" {
		s.mu.RLock()
		isBusy := s.isTrainingBusyLocked()
		task, op := s.activeTaskInfoLocked()
		runtimeConfigToUse := s.RuntimeConfig
		s.mu.RUnlock()
		if isBusy {
			writeErr(w, http.StatusConflict, pkgerrors.New(pkgerrors.CodeConflict,
				fmt.Sprintf("当前已有训练任务正在执行中 (taskId: %s, op: %s)，请等待完成后再提交", task, op)))
			return
		}
		if strings.TrimSpace(runtimeConfigToUse) == "" {
			writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "runtimeConfig 不能为空"))
			return
		}
		cfg, _, err := parseRuntimeConfig(runtimeConfigToUse)
		if err != nil {
			writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("runtimeConfig 解析失败: %v", err), err))
			return
		}
		if len(cfg.Commands) == 0 {
			writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "runtimeConfig.commands 不能为空"))
			return
		}

		s.mu.Lock()
		s.ModelImported = true
		_ = s.sealStateLocked()
		s.mu.Unlock()

		s.Logs.Add(LogInfo, "importModel", "阶段%d: 模型运行配置已更新(ModelImported=true)，等待数据下发以触发训练任务: taskId=%s, requestId=%s",
			phase, req.TaskID, req.RequestID)
		msg := "模型参数命令已导入，等待数据重新导入后执行训练"
		writeEnvelope(w, http.StatusOK, msg, nil, 0)
		return
	}

	release, err := s.tryAcquireTask(req.TaskID, req.RequestID, "downloading", true)
	if err != nil {
		s.Logs.Add(LogWarn, "importModel", "拒绝并发任务请求: %v", err)
		writeErr(w, http.StatusConflict, err)
		return
	}

	s.mu.Lock()
	s.ModelImported = true
	_ = s.sealStateLocked()
	s.mu.Unlock()

	s.setSavedModelResourceURL(req.ResourceURL)
	if strings.TrimSpace(req.RuntimeConfig) == "" {
		s.Logs.Add(LogWarn, "importModel", "runtimeConfig 为空，后续训练将失败")
	}

	s.Logs.Add(LogInfo, "importModel", "开始下载资源: %s", req.ResourceURL)
	ciphertextPath, size, err := s.downloadToTempFile(req.ResourceURL)
	if err != nil {
		// ModelImported was sealed before the download, so a failure here has to
		// undo it explicitly. Relying on release() alone left the flag set with no
		// model on disk and no audit ever launched — and release() clears
		// activeTask, the one thing crash recovery keys on, so nothing downstream
		// would have corrected it either. The other failure paths in
		// processImportedResource all go through reportImportFailure for the same
		// reason.
		s.clearImportedState(true, phase)
		release()
		s.Logs.Add(LogError, "importModel", "下载资源失败: %v", err)
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.Logs.Add(LogInfo, "importModel", "下载完成 (%d bytes) -> %s", size, ciphertextPath)

	msg := "模型已接收，训练结果将通过 reportRes 上报"
	writeEnvelope(w, http.StatusOK, msg, nil, 0)

	s.runAsyncSafe("processImportedResource", release, func() {
		s.processImportedResource(req, phase, true, ciphertextPath, nil)
	})
}
