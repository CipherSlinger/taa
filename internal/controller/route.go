package controller

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"taa/internal/attestation"
	"taa/internal/codeaudit"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
	"taa/pkg/utils"
)

// maxDownloadBytes 限制单次资源下载的最大字节数，防止 OOM。
const maxDownloadBytes = 512 << 20 // 512 MB

// ── 公共返回格式 ──────────────────────────────────────────

type apiResponse struct {
	Msg    string `json:"msg"`
	Result any    `json:"result"`
	Error  int    `json:"error"`
}

// ── TAA 全局状态 ──────────────────────────────────────────

// SecurityConfig holds immutable security settings configured at startup.
// Separated from TAAState so it doesn't need the phase mutex and can't be
// accidentally left at zero values.
type SecurityConfig struct {
	ScanEnabled    bool                // 是否在 import type=1 时执行源码安全扫描
	ModelDir       string              // 模型代码存放目录（扫描目标，type=1）
	DataDir        string              // 数据目录（type=2 测试数据，type=3 训练数据，用于数据指纹比对）
	ResultCheck    bool                // 是否在 export 时检查明文数据泄露
	ResultDir      string              // 训练结果目录（导出前检查）
	ModelInputDir  string              // 模型数据输入目录（缺省 /opt/taa/input）
	ModelOutputDir string              // 模型结果输出目录（缺省 /opt/taa/output）
	LLM            codeaudit.LLMConfig // 本地 LLM 语义验证配置
}

const (
	DefaultModelInputDir  = "/opt/taa/input"
	DefaultModelOutputDir = "/opt/taa/output"
)

func (sec SecurityConfig) GetModelInputDir() string {
	dir := DefaultModelInputDir
	if strings.TrimSpace(sec.ModelInputDir) != "" {
		dir = sec.ModelInputDir
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}

func (sec SecurityConfig) GetModelOutputDir() string {
	dir := DefaultModelOutputDir
	if strings.TrimSpace(sec.ModelOutputDir) != "" {
		dir = sec.ModelOutputDir
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}

type TAAState struct {
	mu                    sync.RWMutex
	attestMu              sync.Mutex
	importIndexOnce       sync.Once
	CurrentPhase          int
	ModelImported         bool
	TrainingRunning       bool
	AttestationFile       string
	PlatformIP            string
	DockerID              string
	SM2PrivateKey         *teecrypto.SM2PrivateKey // TAA 启动时生成的 SM2 私钥，用于解密资源信封
	UserData              []byte                   // TAA 启动时生成的 64 字节 USERDATA，用于重新生成远程证明报告
	ExportPublicKey       string                   // phase1 import 时保存的公钥，phase3 export 时使用
	SavedModelResourceURL string                   // phase1 / importModel 保存的模型资源 URL，允许后续下发模型时为空复用
	RuntimeConfig         string                   // importModel 保存的运行配置，训练时按该配置执行命令
	Security              SecurityConfig           // immutable after startup — no mutex needed
	Logs                  *LogStore                // 结构化日志存储
	LastAudit             *codeaudit.AuditReport   // 最近一次模型代码审计结果，用于训练报告输出
	CurrentDataRecord     ImportIndexRecord        // 当前绑定的数据导入记录
	LatestDataRecord      ImportIndexRecord        // 下发数据接口始终记录的最新数据索引
	ModelChecksum         map[string]any           // 模型压缩包校验和 (size, algorithm, value)
	DataChecksum          map[string]any           // 数据压缩包校验和 (size, algorithm, value)
	CurrentOp             string                   // 当前操作: idle/downloading/decrypting/extracting/debugging/training/auditing/reporting
	ActiveTaskID          string                   // 当前独占执行的任务 ID
	ActiveRequestID       string                   // 当前独占执行的请求 ID
	activeToken           int64                    // 当前独占令牌
	activeTask            *ActiveTaskSnapshot      // 当前在飞任务快照
	stateStore            *StateStore              // 持久化密封存储
	importIndex           *ImportIndexStore
	importIndexErr        error
}

// SetStateStore 注入密封状态存储引擎
func (s *TAAState) SetStateStore(store *StateStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateStore = store
}

// GetStateStore 获取当前绑定的密封状态存储引擎
func (s *TAAState) GetStateStore() *StateStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stateStore
}

// GetActiveTask 获取当前在飞任务快照副本
func (s *TAAState) GetActiveTask() *ActiveTaskSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeTask == nil {
		return nil
	}
	cloned := *s.activeTask
	return &cloned
}

// ResetActiveTask 重置在飞任务状态并密封落盘
func (s *TAAState) ResetActiveTask() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeTask = nil
	s.ActiveTaskID = ""
	s.ActiveRequestID = ""
	s.activeToken = 0
	s.CurrentOp = "idle"
	s.TrainingRunning = false
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "ResetActiveTask 持久化密封失败: %v", err)
	}
}

// RestoreFromPersistentState 从已解密验证的受保护持久化状态还原运行时内存
func (s *TAAState) RestoreFromPersistentState(p *PersistentState) {
	if p == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.CurrentPhase >= 1 && p.CurrentPhase <= 4 {
		s.CurrentPhase = p.CurrentPhase
	}
	s.ModelImported = p.ModelImported
	s.TrainingRunning = p.TrainingRunning
	s.ExportPublicKey = p.ExportPublicKey
	s.SavedModelResourceURL = p.SavedModelResourceURL
	s.RuntimeConfig = p.RuntimeConfig

	if p.ModelChecksum != nil {
		s.ModelChecksum = make(map[string]any, len(p.ModelChecksum))
		for k, v := range p.ModelChecksum {
			s.ModelChecksum[k] = v
		}
	}
	if p.DataChecksum != nil {
		s.DataChecksum = make(map[string]any, len(p.DataChecksum))
		for k, v := range p.DataChecksum {
			s.DataChecksum[k] = v
		}
	}
	if p.ActiveTask != nil {
		taskCopy := *p.ActiveTask
		s.activeTask = &taskCopy
		s.ActiveTaskID = p.ActiveTask.TaskID
		s.ActiveRequestID = p.ActiveTask.RequestID
		s.CurrentOp = p.ActiveTask.Status
	} else {
		s.activeTask = nil
		s.ActiveTaskID = ""
		s.ActiveRequestID = ""
		s.CurrentOp = "idle"
	}
}

// sealStateLocked 在持有 s.mu 锁的情况下同步密封受保护状态到磁盘。
// 若未配置 stateStore，则安全返回 nil。
func (s *TAAState) sealStateLocked() error {
	if s.stateStore == nil {
		return nil
	}

	var state PersistentState
	if base := s.stateStore.GetState(); base != nil {
		state = *base
	} else {
		state = *newCleanPersistentState()
	}

	state.CurrentPhase = s.CurrentPhase
	state.ModelImported = s.ModelImported
	state.TrainingRunning = s.TrainingRunning
	state.ExportPublicKey = s.ExportPublicKey
	state.SavedModelResourceURL = s.SavedModelResourceURL
	state.RuntimeConfig = s.RuntimeConfig

	if s.ModelChecksum != nil {
		state.ModelChecksum = make(map[string]any, len(s.ModelChecksum))
		for k, v := range s.ModelChecksum {
			state.ModelChecksum[k] = v
		}
	} else {
		state.ModelChecksum = nil
	}

	if s.DataChecksum != nil {
		state.DataChecksum = make(map[string]any, len(s.DataChecksum))
		for k, v := range s.DataChecksum {
			state.DataChecksum[k] = v
		}
	} else {
		state.DataChecksum = nil
	}

	if s.activeTask != nil {
		taskCopy := *s.activeTask
		state.ActiveTask = &taskCopy
	} else {
		state.ActiveTask = nil
	}

	return s.stateStore.SealState(&state)
}

func (s *TAAState) saveModelSuccess(resourceURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ModelImported = true
	s.SavedModelResourceURL = resourceURL
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化模型导入成功状态失败: %v", err)
	}
}

// SaveModelSuccess 导出供调用的模型导入成功状态更新方法
func (s *TAAState) SaveModelSuccess(resourceURL string) {
	s.saveModelSuccess(resourceURL)
}

func (s *TAAState) saveDataSuccess(record ImportIndexRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LatestDataRecord = record
	s.CurrentDataRecord = record
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化数据导入成功状态失败: %v", err)
	}
}

// SaveDataSuccess 导出供调用的数据导入成功状态更新方法
func (s *TAAState) SaveDataSuccess(record ImportIndexRecord) {
	s.saveDataSuccess(record)
}

func (s *TAAState) updateImportState(isModel bool, imported bool, phase int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isModel {
		s.ModelImported = imported
		if !imported {
			s.SavedModelResourceURL = ""
			s.RuntimeConfig = ""
		}
	} else if !imported {
		s.CurrentDataRecord = ImportIndexRecord{}
	}
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化导入状态更新失败: %v", err)
	}
}

// UpdateImportState 导出供调用的导入状态更新方法
func (s *TAAState) UpdateImportState(isModel bool, imported bool, phase int) {
	s.updateImportState(isModel, imported, phase)
}

func (s *TAAState) setModelChecksum(checksum map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ModelChecksum = checksum
}

func (s *TAAState) getModelChecksum() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ModelChecksum == nil {
		return nil
	}
	out := make(map[string]any, len(s.ModelChecksum))
	for k, v := range s.ModelChecksum {
		out[k] = v
	}
	return out
}

// GetModelChecksum 获取当前模型压缩包校验和快照
func (s *TAAState) GetModelChecksum() map[string]any {
	return s.getModelChecksum()
}

func (s *TAAState) setDataChecksum(checksum map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DataChecksum = checksum
}

func (s *TAAState) getDataChecksum() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.DataChecksum == nil {
		return nil
	}
	out := make(map[string]any, len(s.DataChecksum))
	for k, v := range s.DataChecksum {
		out[k] = v
	}
	return out
}

// GetDataChecksum 获取当前数据压缩包校验和快照
func (s *TAAState) GetDataChecksum() map[string]any {
	return s.getDataChecksum()
}

func (s *TAAState) setSavedModelResourceURL(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SavedModelResourceURL = url
}

func (s *TAAState) getSavedModelResourceURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.SavedModelResourceURL
}

func (s *TAAState) hasSavedModel() bool {
	s.mu.RLock()
	savedURL := s.SavedModelResourceURL
	modelImported := s.ModelImported
	modelDir := s.Security.ModelDir
	s.mu.RUnlock()

	if savedURL != "" || modelImported {
		return true
	}
	if modelDir != "" {
		if entries, err := os.ReadDir(modelDir); err == nil && len(entries) > 0 {
			return true
		}
	}
	return false
}

func (s *TAAState) getExportPublicKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ExportPublicKey
}

func (s *TAAState) setLatestDataRecord(record ImportIndexRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LatestDataRecord = record
	s.CurrentDataRecord = record
}

func (s *TAAState) getLatestDataRecord() (ImportIndexRecord, bool) {
	s.mu.RLock()
	record := s.LatestDataRecord
	s.mu.RUnlock()
	if record.RequestID != "" || record.TaskID != "" || record.DataDir != "" || record.Hash != "" {
		return record, true
	}
	store, err := s.importIndexStore()
	if err == nil {
		if rec, ok := store.Latest(); ok {
			s.mu.Lock()
			s.LatestDataRecord = rec
			s.CurrentDataRecord = rec
			s.mu.Unlock()
			return rec, true
		}
	}
	return ImportIndexRecord{}, false
}

func (s *TAAState) getTAAPublicKeyPEM() string {
	s.mu.RLock()
	priv := s.SM2PrivateKey
	s.mu.RUnlock()
	if priv == nil {
		return ""
	}
	pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return ""
	}
	return string(pubPEM)
}

func NewTAAState(attestationFile, platformIP, dockerID string, sm2Key *teecrypto.SM2PrivateKey, userData []byte, sec SecurityConfig) *TAAState {
	return &TAAState{
		CurrentPhase:    1,
		AttestationFile: attestationFile,
		PlatformIP:      platformIP,
		DockerID:        dockerID,
		SM2PrivateKey:   sm2Key,
		UserData:        userData,
		Security:        sec,
		Logs:            NewLogStore(1000),
		CurrentOp:       "idle",
	}
}

// ── 请求结构体 ────────────────────────────────────────────

type switchRequest struct {
	Phase int `json:"phase"`
}

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

type runtimeConfig struct {
	Commands []string `json:"commands"`
	Env      string   `json:"env"`
}

type exportRequest struct {
	PublicKey *string `json:"publicKey"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
}

type getAttestationRequest struct {
	RequestID string `json:"requestId"`
}

type resourceInfoRequest struct {
	ResourceURL string `json:"resourceUrl"`
}

type reportResPlatformRequest struct {
	RequestID string  `json:"requestId"`
	Code      int     `json:"code"`
	Msg       *string `json:"msg"`
}

type logsRequest struct {
	Since *string `json:"since"` // optional ISO8601 timestamp
}

// ── 路由注册 ─────────────────────────────────────────────

func RegisterRoutes(mux *http.ServeMux, state *TAAState) {
	taaRoutes := []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/v1/taa/health", state.healthHandler},
		// {"/v1/taa/reportRes", state.reportResHandler}, // /v1/taa/reportRes 为 TAA -> 平台上报接口，TAA 服务端不再接收该路径。
		{"/v1/taa/import", state.importHandler},
		{"/v1/taa/importModel", state.modelImportHandler},
		{"/v1/taa/getResourceInfo", state.resourceInfoHandler},
		{"/v1/taa/switch", state.switchHandler},
		{"/v1/taa/export", state.exportHandler},
		{"/v1/taa/getAttestation", state.getAttestationHandler},
		{"/v1/taa/logs", state.logsHandler},
		{"/v1/taa/status", state.statusHandler},
	}

	for _, route := range taaRoutes {
		mux.HandleFunc(route.path, postOnly(route.handler))
	}
}

func postOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, Content-Length, X-TAA-Task-Id, X-TAA-Encrypted")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{
				Msg:    "仅支持 POST 方法",
				Result: nil,
				Error:  http.StatusMethodNotAllowed,
			})
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, resp apiResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeEnvelope(w http.ResponseWriter, status int, msg string, result any, errorCode int) {
	writeJSON(w, status, apiResponse{Msg: msg, Result: result, Error: errorCode})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeEnvelope(w, status, msg, nil, status)
}

// writeErr 根据 error 对象的类型写入统一 API 错误响应。
// 若 err 为 pkg/errors.Error，自动使用其内置 Code 作为 HTTP 状态码与业务错误码，
// 否则使用 defaultStatus。
func writeErr(w http.ResponseWriter, defaultStatus int, err error) {
	if err == nil {
		return
	}
	code := pkgerrors.CodeOf(err, defaultStatus)
	var appErr *pkgerrors.Error
	msg := err.Error()
	if pkgerrors.As(err, &appErr) {
		msg = appErr.Message()
	}
	writeEnvelope(w, code, msg, nil, code)
}

func phaseName(phase int) string {
	switch phase {
	case 1:
		return "调试"
	case 2:
		return "测试"
	case 3:
		return "正式训练"
	case 4:
		return "推理"
	default:
		return fmt.Sprintf("未知(%d)", phase)
	}
}

// ── Handler: /v1/taa/health ──────────────────────────────

func (s *TAAState) healthHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	phase := s.CurrentPhase
	modelImported := s.ModelImported
	trainingRunning := s.TrainingRunning
	currentOp := s.CurrentOp
	s.mu.RUnlock()

	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"phase":           phase,
		"phaseName":       phaseName(phase),
		"modelImported":   modelImported,
		"trainingRunning": trainingRunning,
		"currentOp":       currentOp,
	}, 0)
}

// ── Handler: /v1/taa/logs ────────────────────────────────

func (s *TAAState) logsHandler(w http.ResponseWriter, r *http.Request) {
	var req logsRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // ignore decode error — body may be empty

	var entries []LogEntry
	if req.Since != nil && *req.Since != "" {
		t, err := time.Parse(time.RFC3339, *req.Since)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("since 时间格式错误: %v", err))
			return
		}
		entries = s.Logs.Since(t)
	} else {
		entries = s.Logs.Drain()
	}

	s.mu.RLock()
	currentOp := s.CurrentOp
	s.mu.RUnlock()

	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"logs":      entries,
		"currentOp": currentOp,
		"total":     len(entries),
	}, 0)
}

// ── Handler: /v1/taa/status ──────────────────────────────

func (s *TAAState) statusHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	phase := s.CurrentPhase
	modelImported := s.ModelImported
	trainingRunning := s.TrainingRunning
	currentOp := s.CurrentOp
	s.mu.RUnlock()

	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"phase":           phase,
		"phaseName":       phaseName(phase),
		"modelImported":   modelImported,
		"trainingRunning": trainingRunning,
		"currentOp":       currentOp,
		"logCount":        s.Logs.Count(),
	}, 0)
}

// setCurrentOp is a helper to update the current operation.
func (s *TAAState) setCurrentOp(op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentOp = op
}

// isTrainingBusyLocked 检查是否处于正在训练/执行阶段（调用方需持有 s.mu 读锁或写锁）。
func (s *TAAState) isTrainingBusyLocked() bool {
	return s.TrainingRunning || s.CurrentOp == "staging" || s.CurrentOp == "training" || s.CurrentOp == "reporting"
}

// activeTaskInfoLocked 获取当前占用任务的信息描述（调用方需持有 s.mu 读锁或写锁）。
func (s *TAAState) activeTaskInfoLocked() (string, string) {
	task := s.ActiveTaskID
	if task == "" {
		task = s.ActiveRequestID
	}
	if task == "" {
		task = "unknown"
	}
	op := s.CurrentOp
	if op == "" {
		op = "busy"
	}
	return task, op
}

// tryAcquireTask 尝试原子抢占训练/导入任务执行权（单任务互斥）。
// isModel: true 表示模型导入流程，false 表示数据导入/训练流程
// initialOp: 初始操作标识（如 "downloading" 或 "staging"）
func (s *TAAState) tryAcquireTask(taskID, requestID, initialOp string, isModel bool) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. 若当前处于训练执行阶段，全局绝对互斥，禁止任何新任务下发
	if s.isTrainingBusyLocked() {
		task, op := s.activeTaskInfoLocked()
		return nil, pkgerrors.New(pkgerrors.CodeConflict,
			fmt.Sprintf("当前已有训练任务正在执行中 (taskId: %s, op: %s)，请等待完成后再提交", task, op))
	}

	// 2. 检查是否有其他任务正在处理（如正在下载、解密、审计等）
	if s.ActiveTaskID != "" || (s.CurrentOp != "" && s.CurrentOp != "idle") {
		isSameTaskPair := false
		if taskID != "" && s.ActiveTaskID == taskID {
			if s.activeTask != nil {
				currentIsModel := (s.activeTask.Type == "model_import")
				if currentIsModel != isModel {
					isSameTaskPair = true
				}
			}
		}

		if !isSameTaskPair {
			task, op := s.activeTaskInfoLocked()
			return nil, pkgerrors.New(pkgerrors.CodeConflict,
				fmt.Sprintf("当前已有任务正在执行中 (taskId: %s, op: %s)，请等待完成后再提交", task, op))
		}
	}

	token := time.Now().UnixNano()
	s.activeToken = token
	s.ActiveTaskID = taskID
	s.ActiveRequestID = requestID
	s.CurrentOp = initialOp

	taskType := "data_import"
	if isModel {
		taskType = "model_import"
	} else if initialOp == "staging" || initialOp == "training" {
		taskType = "training"
		s.TrainingRunning = true
	}

	s.activeTask = &ActiveTaskSnapshot{
		RequestID:        requestID,
		TaskID:           taskID,
		Type:             taskType,
		Phase:            s.CurrentPhase,
		Status:           "RUNNING",
		ResultDir:        resultDirForRequestTask(s.Security.ResultDir, requestID, taskID),
		StartedAt:        time.Now().UTC(),
		RecoveryAttempts: 0,
	}
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "task", "持久化在飞任务快照失败: %v", err)
	}

	var once sync.Once
	release := func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.activeToken == token {
				s.activeToken = 0
				s.ActiveTaskID = ""
				s.ActiveRequestID = ""
				s.CurrentOp = "idle"
				s.activeTask = nil
				s.TrainingRunning = false
				if err := s.sealStateLocked(); err != nil {
					s.Logs.Add(LogError, "task", "清除在飞任务快照持久化失败: %v", err)
				}
			}
		})
	}

	return release, nil
}

// promoteCurrentTaskToTraining 将当前处于飞行的导入任务状态提升为独占训练状态
func (s *TAAState) promoteCurrentTaskToTraining() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.TrainingRunning {
		return pkgerrors.New(pkgerrors.CodeConflict, "��前已有训练任务正在执行中，请等待完成后再提交")
	}
	s.TrainingRunning = true
	s.CurrentOp = "training"
	if s.activeTask != nil {
		s.activeTask.Type = "training"
	}
	return s.sealStateLocked()
}

// runAsyncSafe 在独立 goroutine 中安全执行异步处理逻辑，统一管理锁释放与 panic 恢复。
func (s *TAAState) runAsyncSafe(name string, release func(), fn func()) {
	go func() {
		if release != nil {
			defer release()
		}
		defer func() {
			if r := recover(); r != nil {
				s.handleAsyncPanic(name, r)
			}
		}()
		fn()
	}()
}

// handleAsyncPanic 实现规约 11（Async Goroutine Panic Recovery & Compensation）
func (s *TAAState) handleAsyncPanic(name string, r any) {
	panicMsg := fmt.Sprintf("%v", r)
	s.Logs.Add(LogError, "panic", "%s 发生异常恢复: %v", name, r)
	log.Printf("[PANIC RECOVERY] %s recovered from panic: %v", name, r)

	// 1. 读取当前在飞任务信息并清空内存在飞任务，落盘密封存储
	s.mu.Lock()
	snapshot := s.activeTask
	taskID := s.ActiveTaskID
	requestID := s.ActiveRequestID
	startedAt := time.Now().UTC()
	taskType := ""
	resultDir := ""

	if snapshot != nil {
		if snapshot.TaskID != "" {
			taskID = snapshot.TaskID
		}
		if snapshot.RequestID != "" {
			requestID = snapshot.RequestID
		}
		if !snapshot.StartedAt.IsZero() {
			startedAt = snapshot.StartedAt
		}
		taskType = snapshot.Type
		resultDir = snapshot.ResultDir
	}
	if taskType == "" {
		if strings.Contains(strings.ToLower(name), "model") {
			taskType = "model_import"
		} else {
			taskType = "data_import"
		}
	}
	if resultDir == "" && (requestID != "" || taskID != "") {
		resultDir = resultDirForRequestTask(s.Security.ResultDir, requestID, taskID)
	}

	modelChecksum := s.ModelChecksum
	dataChecksum := s.DataChecksum
	platformIP := s.PlatformIP
	dockerID := s.DockerID

	s.activeTask = nil
	s.ActiveTaskID = ""
	s.ActiveRequestID = ""
	s.activeToken = 0
	s.CurrentOp = "idle"
	s.TrainingRunning = false
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "panic", "清除在飞任务并持久化状态失败: %v", err)
	}
	s.mu.Unlock()

	// 2. 构建规约 11 标准崩溃失败报告 (exit_code: 137, status: "failed")
	finishedAt := time.Now().UTC()
	failureReason := fmt.Sprintf("%s 发生异常 panic: %s", name, panicMsg)
	reportMap, err := BuildCrashFailureReport(taskID, startedAt, finishedAt, failureReason, modelChecksum, dataChecksum)
	var reportJSON string
	if err == nil {
		if b, mErr := json.Marshal(reportMap); mErr == nil {
			reportJSON = string(b)
		}
	}
	if reportJSON == "" {
		reportJSON = fmt.Sprintf(`{"status":"failed","exit_code":137,"failure_reason":%q}`, failureReason)
	}

	if resultDir != "" && reportMap != nil {
		_ = writeJSONFile(filepath.Join(resultDir, "training_report.json"), reportMap)
	}

	// 3. Fail-Closed: 主动向管控平台发送失败通知（通过 ReportTaskOutcome 自动分流）
	if platformIP != "" && dockerID != "" && (requestID != "" || taskID != "") {
		log.Printf("[PANIC RECOVERY] notifying platform of %s failure: requestId=%s, taskId=%s", taskType, requestID, taskID)
		if repErr := ReportTaskOutcome(context.Background(), platformIP, dockerID, requestID, taskID, taskType, 1, failureReason, reportJSON); repErr != nil {
			log.Printf("[PANIC RECOVERY] ReportTaskOutcome failed: %v", repErr)
		}
	}
}

// ── Handler: /v1/taa/switch ──────────────────────────────

func (s *TAAState) switchHandler(w http.ResponseWriter, r *http.Request) {
	var req switchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}

	if req.Phase < 1 || req.Phase > 4 {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, fmt.Sprintf("无效的阶段值: %d，有效范围 1-4", req.Phase)))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isTrainingBusyLocked() || s.ActiveTaskID != "" || (s.CurrentOp != "" && s.CurrentOp != "idle") {
		task, op := s.activeTaskInfoLocked()
		writeErr(w, http.StatusConflict, pkgerrors.New(pkgerrors.CodeConflict,
			fmt.Sprintf("当前已有任务正在执行中 (taskId: %s, op: %s)，严禁切换运行阶段", task, op)))
		return
	}

	current := s.CurrentPhase
	s.CurrentPhase = req.Phase
	s.activeToken = 0
	s.ActiveTaskID = ""
	s.ActiveRequestID = ""
	s.activeTask = nil
	s.Logs.Add(LogInfo, "phase", "阶段切换: %d(%s) -> %d(%s)", current, phaseName(current), req.Phase, phaseName(req.Phase))

	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "phase", "持久化阶段切换状态失败: %v", err)
	}

	writeEnvelope(w, http.StatusOK, "阶段切换成功", nil, 0)
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
		s.mu.Unlock()
		s.Logs.Add(LogInfo, "import", "已保存 runtimeConfig (长度=%d)", len(req.RuntimeConfig))
	}

	msg := "资源已接收，下载处理中"
	s.setCurrentOp("downloading")
	s.Logs.Add(LogInfo, "import", "开始下载资源: %s", req.ResourceURL)
	ciphertextPath, size, err := downloadToTempFile(req.ResourceURL)
	if err != nil {
		store.Rollback(req.RequestID, req.TaskID)
		release()
		s.Logs.Add(LogError, "import", "下载资源失败: %v", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("下载资源失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "import", "下载完成 (%d bytes) -> %s", size, ciphertextPath)

	msg = "数据已接收，训练结果将通过 reportRes 上报"
	writeEnvelope(w, http.StatusOK, msg, nil, 0)

	s.runAsyncSafe("processImportedResource", release, func() {
		s.processImportedResource(req, phase, false, ciphertextPath)
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
		if savedPublicKey == "" {
			s.Logs.Add(LogWarn, "importModel", "阶段1: 未提供 publicKey，后续阶段3导出可能失败")
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
	ciphertextPath, size, err := downloadToTempFile(req.ResourceURL)
	if err != nil {
		release()
		s.Logs.Add(LogError, "importModel", "下载资源失败: %v", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("下载资源失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "importModel", "下载完成 (%d bytes) -> %s", size, ciphertextPath)

	msg := "模型已接收，训练结果将通过 reportRes 上报"
	writeEnvelope(w, http.StatusOK, msg, nil, 0)

	s.runAsyncSafe("processImportedResource", release, func() {
		s.processImportedResource(req, phase, true, ciphertextPath)
	})
}

// downloadToTempFile 将资源从 URL 流式写入临时文件，避免将整个文件加载到内存。
// 返回临时文件路径，调用方负责删除。
func downloadToTempFile(resourceURL string) (string, int64, error) {
	resp, err := http.Get(resourceURL)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxDownloadBytes {
		return "", 0, fmt.Errorf("资源过大: %d bytes, 上限 %d bytes", resp.ContentLength, maxDownloadBytes)
	}

	f, err := os.CreateTemp("", "taa-download-*")
	if err != nil {
		return "", 0, fmt.Errorf("创建临时文件失败: %w", err)
	}
	path := f.Name()

	reader := io.LimitReader(resp.Body, maxDownloadBytes+1)
	n, err := io.Copy(f, reader)
	f.Close()
	if err != nil {
		os.Remove(path)
		return "", 0, fmt.Errorf("下载写入失败: %w", err)
	}
	if n > maxDownloadBytes {
		os.Remove(path)
		return "", 0, fmt.Errorf("资源超过大小上限: %d bytes > %d bytes", n, maxDownloadBytes)
	}
	return path, n, nil
}

// decryptResourceToTempFile 从磁盘密文文件中读取 SM2+SM4-GCM 封装密文，
// 用 TAA SM2 私钥解密，将明文写入临时文件。返回明文文件路径，调用方负责删除。
// 资源格式：WrappedKey(SM2WrappedKeySize 字节) || Ciphertext(剩余字节)
func (s *TAAState) decryptResourceToTempFile(ciphertextPath string) (string, error) {
	f, err := os.Open(ciphertextPath)
	if err != nil {
		return "", fmt.Errorf("打开密文文件: %w", err)
	}
	defer f.Close()

	// 读取完整密文到内存，交给一步式接口拆包并解密。
	sealed, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("读取密文: %w", err)
	}

	log.Printf("decrypt debug: sealed=%d bytes (first 16: %x)",
		len(sealed), sealed[:min(16, len(sealed))])

	if s.SM2PrivateKey != nil {
		if pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&s.SM2PrivateKey.PublicKey); err != nil {
			log.Printf("decrypt debug: marshal TAA public key failed: %v", err)
			s.Logs.Add(LogError, "decrypt", "打印 TAA 公钥失败: %v", err)
		} else {
			log.Printf("decrypt debug: TAA public key:\n%s", pubPEM)
			s.Logs.Add(LogInfo, "decrypt", "TAA 公钥:\n%s", pubPEM)
		}
	}

	// 用 TAA SM2 私钥直接解密 SM2+SM4-GCM 密文。
	plaintext, err := teecrypto.OpenSM2SM4GCM(s.SM2PrivateKey, sealed)
	sealed = nil // 释放密文内存
	if err != nil {
		return "", err
	}

	// 明文写入临时文件后立即释放明文内存。
	out, err := os.CreateTemp("", "taa-plaintext-*")
	if err != nil {
		plaintext = nil
		return "", fmt.Errorf("创建明文临时文件: %w", err)
	}
	plainPath := out.Name()
	if _, err := out.Write(plaintext); err != nil {
		out.Close()
		os.Remove(plainPath)
		plaintext = nil
		return "", err
	}
	out.Close()
	plaintext = nil

	return plainPath, nil
}

func (s *TAAState) reportTrainingAsync(requestID, taskID string, code int, msg, report string) {
	requestID = strings.TrimSpace(requestID)
	taskID = strings.TrimSpace(taskID)
	if taskID == "" && requestID != "" {
		taskID = requestID
	}
	if requestID == "" && taskID != "" {
		requestID = taskID
	}

	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()
	log.Printf("reportTrainingAsync: scheduling report upload, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, reportLen=%d",
		platformIP, dockerID, requestID, taskID, code, len(report))
	go func() {
		log.Printf("reportTrainingAsync: calling ReportRes, requestID=%s, taskID=%s", requestID, taskID)
		if err := ReportRes(nil, platformIP, dockerID, requestID, taskID, code, msg, report); err != nil {
			log.Printf("reportTrainingAsync: report training result failed: requestID=%s, taskID=%s, err=%v", requestID, taskID, err)
		} else {
			log.Printf("reportTrainingAsync: report upload succeeded: requestID=%s, taskID=%s", requestID, taskID)
		}
	}()
}

// ── Handler: /v1/taa/export ──────────────────────────────

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

	resultData, err := compressDirToZip(record.ResultDir)
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

// compressDirToZip 将目录压缩为 zip 格式的字节切片，并对软链接进行越界安全校验。
func compressDirToZip(srcDir string) ([]byte, error) {
	srcDir = filepath.Clean(srcDir)
	log.Printf("compressDirToZip: 开始压缩目录: %s", srcDir)
	info, err := os.Stat(srcDir)
	if err != nil {
		log.Printf("compressDirToZip: 目录不存在: %v", err)
		return nil, fmt.Errorf("目录不存在: %w", err)
	}
	if !info.IsDir() {
		log.Printf("compressDirToZip: 路径不是目录: %s", srcDir)
		return nil, fmt.Errorf("路径不是目录: %s", srcDir)
	}

	evalSrcDir, err := filepath.EvalSymlinks(srcDir)
	if err != nil {
		evalSrcDir = srcDir
	}
	cleanSrcDir := filepath.Clean(evalSrcDir)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	baseDir := filepath.Dir(srcDir)
	fileCount := 0
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("访问文件失败 %s: %w", path, err)
		}

		relPath, err := filepath.Rel(baseDir, path)
		if err != nil {
			return fmt.Errorf("计算相对路径失败 %s: %w", path, err)
		}
		// 统一使用 / 分隔符，兼容跨平台
		relPath = filepath.ToSlash(relPath)

		if info.Mode()&os.ModeSymlink != 0 {
			evalPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("解析物理路径失败 %s: %w", path, err)
			}
			cleanEval := filepath.Clean(evalPath)
			if cleanEval != cleanSrcDir && !strings.HasPrefix(cleanEval, cleanSrcDir+string(filepath.Separator)) {
				return fmt.Errorf("检测到非法越界软链接: %s -> %s", path, evalPath)
			}

			linkTarget, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("读取软链接目标失败 %s: %w", path, err)
			}
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return fmt.Errorf("创建软链接 header 失败 %s: %w", path, err)
			}
			header.Name = relPath
			header.Method = zip.Store
			w, err := zw.CreateHeader(header)
			if err != nil {
				return fmt.Errorf("写入软链接 header 失败 %s: %w", path, err)
			}
			if _, err := io.WriteString(w, linkTarget); err != nil {
				return fmt.Errorf("写入软链接内容失败 %s: %w", path, err)
			}
			fileCount++
			log.Printf("compressDirToZip:   [软链接] %s -> %s", relPath, linkTarget)
			return nil
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("创建 header 失败 %s: %w", path, err)
		}

		if info.IsDir() {
			header.Name = strings.TrimSuffix(relPath, "/") + "/"
			header.Method = zip.Store
			if _, err := zw.CreateHeader(header); err != nil {
				return fmt.Errorf("写入目录 header 失败 %s: %w", path, err)
			}
			log.Printf("compressDirToZip:   [目录] %s", header.Name)
			return nil
		}

		header.Name = relPath
		header.Method = zip.Deflate

		w, err := zw.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("写入文件 header 失败 %s: %w", path, err)
		}

		fileCount++
		log.Printf("compressDirToZip:   [文件] %s (%d bytes)", relPath, info.Size())

		if err := func() error {
			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("打开文件失败 %s: %w", path, err)
			}
			defer f.Close()

			if _, err := io.Copy(w, f); err != nil {
				return fmt.Errorf("复制文件内容失败 %s: %w", path, err)
			}
			return nil
		}(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Printf("compressDirToZip: 遍历目录失败: %v", err)
		return nil, err
	}

	log.Printf("compressDirToZip: 共压缩 %d 个文件", fileCount)

	if err := zw.Close(); err != nil {
		return nil, err
	}
	result := buf.Bytes()
	log.Printf("compressDirToZip: 压缩完成，最终大小=%d bytes", len(result))
	return result, nil
}

func safeFilenamePart(value string) string {
	res := utils.SafeFilename(value)
	if res == "default" {
		return "request"
	}
	return res
}

// writeFileStream 直接返回二进制文件流：成功时写入 octet-stream 附件头并从 body 复制内容。
// encrypted 决定 X-TAA-Encrypted 头，errLabel 用于写入失败时的日志。
func writeFileStream(w http.ResponseWriter, taskID, filename string, encrypted bool, size int64, body io.Reader, errLabel string) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	w.Header().Set("X-TAA-Task-Id", taskID)
	w.Header().Set("X-TAA-Encrypted", fmt.Sprintf("%t", encrypted))
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, body); err != nil {
		log.Printf("%s: %v", errLabel, err)
	}
}

// ── Handler: /v1/taa/getAttestation ──────────────────────

func (s *TAAState) buildAttestationResult(ctx context.Context, attestationFile string, userData []byte) ([]byte, string, bool, string) {
	generateCtx, generateCancel := context.WithTimeout(ctx, 30*time.Second)
	defer generateCancel()

	if err := attestation.Generate(generateCtx, attestation.Config{
		OutputPath: attestationFile,
		UserData:   userData,
	}); err != nil {
		log.Printf("get attestation failed: generate report: %v", err)
		return nil, "", false, "获取报告失败: " + err.Error()
	}

	reportData, err := os.ReadFile(attestationFile)
	if err != nil {
		log.Printf("get attestation failed: read report: %v", err)
		return nil, "", false, "获取报告失败: " + err.Error()
	}

	reportValues, err := attestation.ExtractReportValues(attestationFile)
	if err != nil {
		log.Printf("get attestation failed: extract report values: %v", err)
		return nil, "", false, "获取报告失败: " + err.Error()
	}

	formattedValues, err := formatAttestationValuesUserDataPEM(reportValues, userData)
	if err != nil {
		log.Printf("get attestation failed: format userdata as PEM: %v", err)
		return nil, "", false, "获取报告失败: " + err.Error()
	}

	return reportData, formattedValues, true, "success"
}

func (s *TAAState) getAttestationHandler(w http.ResponseWriter, r *http.Request) {
	var req getAttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}

	if req.RequestID == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "requestId 不能为空"))
		return
	}

	s.mu.RLock()
	attestationFile := s.AttestationFile
	userData := s.UserData
	s.mu.RUnlock()

	// 同一时刻只允许一个 attestation 重新生成
	s.attestMu.Lock()
	defer s.attestMu.Unlock()

	reportData, reportValues, verifiedPass, msg := s.buildAttestationResult(r.Context(), attestationFile, userData)
	attestationBase64 := ""
	if len(reportData) > 0 {
		attestationBase64 = base64.StdEncoding.EncodeToString(reportData)
	}

	if verifiedPass {
		log.Printf("attestation report regenerated: requestId=%s report=%d bytes", req.RequestID, len(reportData))
	} else {
		log.Printf("attestation report downgraded: requestId=%s report=%d bytes msg=%s", req.RequestID, len(reportData), msg)
	}

	writeEnvelope(w, http.StatusOK, msg, map[string]any{
		"requestId":         req.RequestID,
		"verifiedPass":      verifiedPass,
		"attestation":       attestationBase64,
		"attestationValues": reportValues,
	}, 0)
}

func (s *TAAState) resourceInfoHandler(w http.ResponseWriter, r *http.Request) {
	var req resourceInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}
	if req.ResourceURL == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "resourceUrl 不能为空"))
		return
	}

	s.Logs.Add(LogInfo, "getResourceInfo", "收到资源信息获取请求: resourceUrl=%s", req.ResourceURL)

	s.setCurrentOp("downloading")
	s.Logs.Add(LogInfo, "getResourceInfo", "开始下载资源: %s", req.ResourceURL)
	ciphertextPath, size, err := downloadToTempFile(req.ResourceURL)
	if err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "下载资源失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("资源下载失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "getResourceInfo", "下载完成 (%d bytes) -> %s", size, ciphertextPath)
	defer os.Remove(ciphertextPath)

	s.setCurrentOp("decrypting")
	plaintextPath, isDecrypted, err := s.resolvePlaintextResource(req.ResourceURL, ciphertextPath, "getResourceInfo")
	if err != nil {
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if isDecrypted {
		defer os.Remove(plaintextPath)
	}

	s.setCurrentOp("analyzing")
	_, hash, err := teecrypto.HashFileSM3(plaintextPath)
	if err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "计算资源压缩包哈希失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("计算资源哈希失败: %v", err))
		return
	}

	dataDir := dataDirForHash(s.Security.DataDir, hash)
	extracted, err := ensureArchiveExtractedIntoDir(dataDir, plaintextPath)
	if err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "展开 hash 数据目录失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("解压资源失败: %v", err))
		return
	}
	if extracted {
		s.Logs.Add(LogInfo, "getResourceInfo", "hash 数据目录保存完成: %s (hash=%s)", dataDir, hash)
	} else {
		s.Logs.Add(LogInfo, "getResourceInfo", "hash 数据目录已存在，复用: %s (hash=%s)", dataDir, hash)
	}

	output, err := buildResourceInfoJSON(dataDir, plaintextPath)
	if err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "生成资源树失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("生成资源信息失败: %v", err))
		return
	}

	s.setCurrentOp("idle")
	s.Logs.Add(LogInfo, "getResourceInfo", "资源树分析完成，数据已持久化备份至 %s", dataDir)
	writeEnvelope(w, http.StatusOK, "ok", string(output), 0)
}

// ── Handler: /v1/taa/reportRes (平台 → TAA) ─────────────
//
// /v1/taa/reportRes 在接口文档中定义为 TAA -> 平台的训练结果上报接口，
// TAA 服务端不再注册或接收该路径。保留以下历史实现注释，便于必要时追溯。
//
// func (s *TAAState) reportResHandler(w http.ResponseWriter, r *http.Request) {
// 	var req reportResPlatformRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		writeError(w, http.StatusBadRequest, fmt.Sprintf("请求解析失败: %v", err))
// 		return
// 	}
//
// 	if req.RequestID == "" {
// 		writeError(w, http.StatusBadRequest, "requestId 不能为空")
// 		return
// 	}
//
// 	s.mu.Lock()
// 	if req.Code == 0 {
// 		// 结果接收逻辑已由平台上报链路处理。
// 	}
// 	s.mu.Unlock()
//
// 	log.Printf("report result received: requestId=%s code=%d", req.RequestID, req.Code)
//
// 	writeEnvelope(w, http.StatusOK, "结果已接收", nil, 0)
// }

// ── Script helpers ──────────────────────────────────────

// runPythonScript executes a Python script via python3 with the given output path and optional extra args.
// Does not depend on bash or any shell shebang.
func runPythonScript(script, outputDir string, env map[string]string, args ...string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	cmdArgs := append([]string{script}, args...)
	cmdArgs = append(cmdArgs, "--output", outputDir)
	cmd := exec.Command("python3", cmdArgs...)
	cmd.Dir = filepath.Dir(script)
	if len(env) > 0 {
		cmd.Env = os.Environ()
		for key, value := range env {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s exited with error: %w", filepath.Base(script), err)
	}
	return string(output), nil
}

// runScript executes a Python script via python3 with --output argument.
func runScript(script, outputDir string) (string, error) {
	return runPythonScript(script, outputDir, nil)
}

func parseRuntimeConfig(raw string) (runtimeConfig, map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return runtimeConfig{}, nil, fmt.Errorf("runtimeConfig 不能为空")
	}

	var cfg runtimeConfig
	var env map[string]string
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		if strings.Contains(err.Error(), "cannot unmarshal object into Go struct field runtimeConfig.env of type string") {
			var objCfg struct {
				Commands []string       `json:"commands"`
				Env      map[string]any `json:"env"`
			}
			if errObj := json.Unmarshal([]byte(raw), &objCfg); errObj != nil {
				return runtimeConfig{}, nil, fmt.Errorf("解析 runtimeConfig 失败: %w", errObj)
			}
			cfg.Commands = objCfg.Commands
			if objCfg.Env != nil {
				env = make(map[string]string, len(objCfg.Env))
				for k, v := range objCfg.Env {
					switch val := v.(type) {
					case string:
						env[k] = val
					default:
						b, err := json.Marshal(val)
						if err == nil && !bytes.Equal(b, []byte("null")) {
							env[k] = string(b)
						} else {
							env[k] = fmt.Sprintf("%v", val)
						}
					}
				}
				if envBytes, err := json.Marshal(env); err == nil {
					cfg.Env = string(envBytes)
				}
			}
		} else {
			return runtimeConfig{}, nil, fmt.Errorf("解析 runtimeConfig 失败: %w", err)
		}
	}
	if len(cfg.Commands) == 0 {
		return runtimeConfig{}, nil, fmt.Errorf("runtimeConfig.commands 不能为空")
	}
	for i, command := range cfg.Commands {
		if strings.TrimSpace(command) == "" {
			return runtimeConfig{}, nil, fmt.Errorf("runtimeConfig.commands[%d] 不能为空", i)
		}
	}

	if env == nil {
		env = map[string]string{}
		if strings.TrimSpace(cfg.Env) != "" {
			if err := json.Unmarshal([]byte(cfg.Env), &env); err != nil {
				return runtimeConfig{}, nil, fmt.Errorf("解析 runtimeConfig.env 失败: %w", err)
			}
		}
	}
	return cfg, env, nil
}

func newInOutReplacer(dataDir, outputDir string) *strings.Replacer {
	return strings.NewReplacer(
		DefaultModelInputDir, dataDir,
		DefaultModelOutputDir, outputDir,
		"<input>", dataDir,
		"<output>", outputDir,
		"<INPUT>", dataDir,
		"<OUTPUT>", outputDir,
		"<in>", dataDir,
		"<out>", outputDir,
		"<IN>", dataDir,
		"<OUT>", outputDir,
	)
}

func resolveRuntimeCommands(commands []string, dataDir, outputDir string) []string {
	replacer := newInOutReplacer(dataDir, outputDir)
	resolved := make([]string, len(commands))
	for i, cmd := range commands {
		resolved[i] = replacer.Replace(cmd)
	}
	return resolved
}

func resolveRuntimeEnv(env map[string]string, dataDir, outputDir string) map[string]string {
	if len(env) == 0 {
		return env
	}
	replacer := newInOutReplacer(dataDir, outputDir)
	resolved := make(map[string]string, len(env))
	for k, v := range env {
		resolved[k] = replacer.Replace(v)
	}
	return resolved
}

func runRuntimeConfig(cfg runtimeConfig, env map[string]string, modelDir, dataDir, outputDir, taskID, startedAt string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	resolvedCommands := resolveRuntimeCommands(cfg.Commands, dataDir, outputDir)
	commandLine := strings.Join(resolvedCommands, " && ")

	cmd := exec.Command("/bin/sh", "-c", commandLine)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Dir = modelDir
	cmd.Env = mergedRuntimeEnv(resolveRuntimeEnv(env, dataDir, outputDir), map[string]string{
		"TAA_TASK_ID":          taskID,
		"TAA_STARTED_AT":       startedAt,
		"TAA_DATA_DIR":         dataDir,
		"TAA_INPUT_DIR":        dataDir,
		"TAA_MODEL_INPUT_DIR":  dataDir,
		"TAA_MODEL_OUTPUT_DIR": outputDir,
		"TAA_OUTPUT_DIR":       outputDir,
	})

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("runtimeConfig command exited with error: %w", err)
	}
	return string(output), nil
}

// KillProcessGroup 级联清理进程及其所属的整个进程组。
func KillProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func mergedRuntimeEnv(userEnv, systemEnv map[string]string) []string {
	merged := map[string]string{}
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			merged[key] = value
		}
	}
	for key, value := range userEnv {
		merged[key] = value
	}
	for key, value := range systemEnv {
		merged[key] = value
	}

	keys := envKeys(merged)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+merged[key])
	}
	return out
}

func envKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
