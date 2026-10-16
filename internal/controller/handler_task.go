package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

// importRequest is the body shared by /v1/taa/import and /v1/taa/importModel.
//
// PublicKey and RuntimeConfig are read by /v1/taa/importModel alone: the export
// public key is saved when the model is delivered in phase 1, and training runs
// the runtimeConfig saved there. A data import (/v1/taa/import) that carries
// either field is accepted and the field is ignored, so the two endpoints cannot
// disagree about the key an export uses or the commands a run executes.
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

	// EvalKeyURL and EvalKeyFileHash are the FHE contract's additions.
	//
	// Which branch a request takes is decided by the instance type alone
	// (TAAState.fheEnabled), never by these fields: on an fhe instance both are
	// mandatory and on a tee instance both are refused. EvalKeyURL is where the
	// eval key is fetched from when it is not already cached. EvalKeyFileHash is
	// the SM3 digest of that key; it names the cache entry and is the FHE-side
	// user id.
	//
	// The hash is required even on a cache hit: it declares which user the task
	// belongs to, which the URL alone cannot say.
	EvalKeyURL      string `json:"evalKeyUrl,omitempty"`
	EvalKeyFileHash string `json:"evalKeyFileHash,omitempty"`
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

	// The eval key fields are checked before anything is reserved or downloaded,
	// so a request that cannot be served is refused without touching state. On a
	// tee instance both fields must be absent, which leaves every existing request
	// unchanged.
	req.EvalKeyURL = strings.TrimSpace(req.EvalKeyURL)
	req.EvalKeyFileHash = strings.TrimSpace(req.EvalKeyFileHash)
	if err := s.validateFHEFields(req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
	}

	// Encrypted data resources use the shape "envelope in the URL, ciphertext
	// downloaded on its own": resourceUrl looks like
	// <download link>?dataKeyCipher=<hex C1C3C2>.
	// The envelope is unwrapped before the download, so a malformed value or a key
	// mismatch surfaces without first pulling the whole ciphertext.
	downloadURL, dataKey, err := s.unwrapDataKeyCipherFromURL(req.ResourceURL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
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

	// publicKey and runtimeConfig belong to /v1/taa/importModel: the export key is
	// saved when the model is delivered in phase 1, and training runs the
	// runtimeConfig saved there. A data import that carries either one is not an
	// error, but it changes nothing here — the alternative was two sources for the
	// same setting, and a run that executes the configuration of whichever
	// endpoint spoke last. Logged rather than dropped in silence, because a
	// platform that still sends them expects them to apply.
	if strings.TrimSpace(req.RuntimeConfig) != "" || (req.PublicKey != nil && strings.TrimSpace(*req.PublicKey) != "") {
		s.Logs.Add(LogWarn, "import", "数据下发携带 publicKey/runtimeConfig: 本接口不读取这两个字段，已忽略; 训练执行的是 /v1/taa/importModel 保存的 runtimeConfig")
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

	// evalKeyUrl and evalKeyFileHash belong to /v1/taa/import: the eval key is
	// delivered with the data package it is used for, while this endpoint stages the
	// model package. They are not rejected here the way validateFHEFields rejects
	// them on the data endpoint - importModel is how a model reaches an fhe instance,
	// so refusing the request would close the only path that stages one - but a
	// platform that sends them here expects them to apply, and they do not. Logged
	// rather than dropped in silence, like the mirror-image case on importHandler,
	// where the data endpoint names the endpoint that does read what it ignores.
	req.EvalKeyURL = strings.TrimSpace(req.EvalKeyURL)
	req.EvalKeyFileHash = strings.TrimSpace(req.EvalKeyFileHash)
	if req.EvalKeyURL != "" || req.EvalKeyFileHash != "" {
		s.Logs.Add(LogWarn, "importModel", "模型下发携带 evalKeyUrl/evalKeyFileHash: 本接口不读取这两个字段，已忽略; eval key 随 /v1/taa/import 的数据下发提交")
	}

	// Models are delivered exactly like data: an encrypted model either arrives as a
	// whole-file envelope, or its key envelope travels in the URL
	// (<download link>?dataKeyCipher=<hex C1C3C2>) while the file itself is bare
	// ciphertext.
	//
	// The parse sits here, before any state is written (the phase-1 export key,
	// ModelImported, the saved model URL) and before the download, so a rejected
	// request leaves nothing behind and no bandwidth is spent on a payload whose key
	// is already known to be unusable.
	resourceURL, dataKey, err := s.unwrapDataKeyCipherFromURL(req.ResourceURL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
	}
	// From here on req.ResourceURL is the stripped URL, and every later reader wants
	// it that way: the download, the log line, the legacy resolver, and
	// beginModelImportAndAudit, which re-records the URL as the model's delivery
	// record once the import succeeds in the async stage. Rewriting the local copy
	// keeps those writers from disagreeing, and leaves the wrapped key in exactly one
	// place -- the dataKey above.
	req.ResourceURL = resourceURL

	// A URL that consisted of nothing but the enveloped key ("?dataKeyCipher=<hex>")
	// strips down to "". That is not the "runtimeConfig only" request handled below:
	// the caller did send a resource URL and a key, it just never named a download
	// address. Reading it as runtimeConfig-only would answer 200 and drop the key.
	if req.ResourceURL == "" && dataKey != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument,
			"resourceUrl 缺少下载地址: 剥离 dataKeyCipher 后为空"))
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
		s.processImportedResource(req, phase, true, ciphertextPath, dataKey)
	})
}
