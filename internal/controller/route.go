package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"taa/internal/codeaudit"
	"taa/internal/config"
	"taa/internal/fhe"
	"taa/internal/runtime"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

// ── TAA 全局状态 ──────────────────────────────────────────

// SecurityConfig holds immutable security settings configured at startup.
// Separated from TAAState so it doesn't need the phase mutex and can't be
// accidentally left at zero values.
//
// Binary is the exception that proves that rule: its zero value is a working
// configuration rather than an obviously broken one. BinaryConfig.Enabled has no
// normalizer default - Go cannot tell an explicit false from the zero value - so
// a SecurityConfig built without this field runs the audit with no binary pass
// at all, silently: no error, no log line, and a report indistinguishable from
// one where the operator turned the channel off. buildSecurityConfig is the only
// production constructor and always sets it; a second caller must as well.
type SecurityConfig struct {
	ScanEnabled      bool                   // 是否在 import type=1 时执行源码安全扫描
	Engine           codeaudit.StaticEngine // Tier 1 静态扫描引擎（启动时由 codeAudit.codeScan.engine 配置解析）
	Binary           codeaudit.BinaryConfig // 二进制审计通道配置（与 Tier 1 引擎无关，两种引擎部署都生效）
	ModelDir         string                 // 模型代码存放目录（扫描目标，type=1）
	DataDir          string                 // 数据目录（type=2 测试数据，type=3 训练数据，用于数据指纹比对）
	ResultCheck      bool                   // 是否在 export 时检查明文数据泄露
	ResultDir        string                 // 训练结果目录（导出前检查）
	ModelInputDir    string                 // 模型数据输入目录（缺省 /opt/taa/input）
	ModelOutputDir   string                 // 模型结果输出目录（缺省 /opt/taa/output/result）
	ModelLogDir      string                 // Model log file or directory path (default /opt/taa/output/log)
	ModelProgressDir string                 // Model progress file or directory path (default /opt/taa/output/progress/progress.json)
	LLM              codeaudit.LLMConfig    // 本地 LLM 语义验证配置
	// ServerType is the startup config's server.type. It is read only to select
	// the data-anaylsis import path; FHE still keys on the runner being non-nil.
	ServerType string
}

const (
	DefaultModelInputDir    = "/opt/taa/input"
	DefaultModelOutputDir   = "/opt/taa/output/result"
	DefaultModelLogDir      = "/opt/taa/output/log"
	DefaultModelProgressDir = "/opt/taa/output/progress/progress.json"
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

func (sec SecurityConfig) GetModelLogDir() string {
	dir := DefaultModelLogDir
	if strings.TrimSpace(sec.ModelLogDir) != "" {
		dir = sec.ModelLogDir
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}

func (sec SecurityConfig) GetModelProgressDir() string {
	dir := DefaultModelProgressDir
	if strings.TrimSpace(sec.ModelProgressDir) != "" {
		dir = sec.ModelProgressDir
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
	HRKCertPath           string
	HSKCekCertPath        string
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
	CurrentOp             string                   // Current operation: idle/downloading/decrypting/extracting/debugging/training/reporting
	ActiveTaskID          string                   // Current active task ID for data/model transfer and training
	ActiveRequestID       string                   // Current active request ID
	activeToken           int64                    // Current active token
	activeTask            *ActiveTaskSnapshot      // Snapshot of currently active task
	CurrentAuditOp        string                   // Current audit operation: idle/auditing
	AuditRunning          bool                     // Whether model code audit is actively running
	ActiveAuditTaskID     string                   // Current active audit task ID
	ActiveAuditRequestID  string                   // Current active audit request ID

	// auditGen identifies the audit that currently owns the audit fields above.
	// Every audit goroutine carries the generation it started with; writes and
	// reports are dropped once the field no longer matches, so an aborted or
	// superseded audit cannot clear or overwrite its successor's state. It is
	// in-memory only and deliberately not persisted.
	auditGen    uint64
	auditCancel context.CancelFunc
	auditDone   chan struct{}

	// pendingAudit is the durable counterpart of the audit fields above: it is
	// what makes an audit that never concluded visible after a restart, so the
	// startup path can report it to the platform as an interrupted audit. It is
	// held separately rather than derived from AuditRunning/CurrentAuditOp on
	// restore: no goroutine survives the restart to clear those fields, so
	// restoring them would leave the status stuck at "auditing" with no
	// goroutine left to clear it, and isAuditBusyLocked() would keep rejecting
	// phase switches.
	pendingAudit    *AuditPendingSnapshot
	trainingControl *trainingControl // 当前训练任务的中止控制对象
	stateStore      *StateStore      // 持久化密封存储
	importIndex     *ImportIndexStore
	importIndexErr  error

	// FHE is nil unless this instance runs as server.type=fhe. A nil runner is
	// the single switch every FHE branch keys on, so a tee instance cannot
	// accidentally enter an FHE path.
	FHE *fhe.Runner
	// fheActiveTaskID is the FHE task currently in flight, so stopTraining can be
	// mapped onto the service's cancel endpoint. It is empty when no FHE task runs.
	fheActiveTaskID string
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
	control := s.trainingControl
	s.trainingControl = nil
	s.activeTask = nil
	s.ActiveTaskID = ""
	s.ActiveRequestID = ""
	s.activeToken = 0
	s.CurrentOp = "idle"
	s.TrainingRunning = false
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "ResetActiveTask 持久化密封失败: %v", err)
	}
	s.mu.Unlock()
	if control != nil {
		control.finish()
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

	// A pending audit is restored as a marker only. The goroutine that was
	// running it did not survive the restart, so the in-flight audit fields stay
	// idle: reporting the audit as still running would make isAuditBusyLocked()
	// true forever, and no goroutine remains to ever clear it. Consuming the
	// marker is the startup path's job (see app's abandoned-audit reconciliation).
	if p.AuditPending != nil {
		pendingCopy := *p.AuditPending
		s.pendingAudit = &pendingCopy
	} else {
		s.pendingAudit = nil
	}
	s.AuditRunning = false
	s.CurrentAuditOp = "idle"
	s.ActiveAuditTaskID = ""
	s.ActiveAuditRequestID = ""
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

	// Deep-copied for the same reason ActiveTask is: StateStore keeps the pointer
	// it is handed as its live cache, so sealing the in-memory snapshot itself
	// would let a later mutation of s.pendingAudit show up in the "sealed" state
	// without ever going through SealState.
	if s.pendingAudit != nil {
		pendingCopy := *s.pendingAudit
		state.AuditPending = &pendingCopy
	} else {
		state.AuditPending = nil
	}

	return s.stateStore.SealState(&state)
}

func (s *TAAState) saveModelSuccess(resourceURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveModelSuccessLocked(resourceURL)
}

// saveModelSuccessLocked records the model as imported and seals (caller must
// hold s.mu Lock).
func (s *TAAState) saveModelSuccessLocked(resourceURL string) {
	s.ModelImported = true
	s.SavedModelResourceURL = resourceURL
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化模型导入成功状态失败: %v", err)
	}
}

// beginModelImportAndAudit records the imported model together with the audit
// owed for it in one locked, sealed write.
//
// The two facts have to become durable in the same seal. Recorded apart, a crash
// between them leaves either a model that no audit is owed for on disk (so an
// interrupted audit goes unreported) or a pending audit for a model not yet
// marked imported (so startup reports an interruption for an import that never
// happened).
func (s *TAAState) beginModelImportAndAudit(req importRequest, phase int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Supersede any audit goroutine still unwinding: its generation-gated defers
	// must not clear the marker written below. abortModelAudit cannot cover this
	// window, because it returns early once the old audit has already cleared its
	// busy flags.
	s.auditGen++
	s.markModelAuditPendingLocked(req, phase)
	s.saveModelSuccessLocked(req.ResourceURL)
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
			// Dropping the model import drops whatever audit was outstanding for it:
			// the verdict can no longer refer to anything, so keeping the marker
			// would have startup report an interrupted audit for an import that is gone.
			s.pendingAudit = nil
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

func NewTAAState(attestationFile, platformIP, dockerID, hrkCertPath, hskCekCertPath string, sm2Key *teecrypto.SM2PrivateKey, userData []byte, sec SecurityConfig) *TAAState {
	return &TAAState{
		CurrentPhase:    1,
		AttestationFile: attestationFile,
		PlatformIP:      platformIP,
		DockerID:        dockerID,
		HRKCertPath:     hrkCertPath,
		HSKCekCertPath:  hskCekCertPath,
		SM2PrivateKey:   sm2Key,
		UserData:        userData,
		Security:        sec,
		Logs:            NewLogStore(1000),
		CurrentOp:       "idle",
		CurrentAuditOp:  "idle",
	}
}

type runtimeConfig = runtime.RuntimeConfig

// setCurrentOp is a helper to update the current operation.
func (s *TAAState) setCurrentOp(op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentOp = op
}

// SetFHERunner installs the FHE runner. It is called once at boot on a
// server.type=fhe instance, before the HTTP server starts.
func (s *TAAState) SetFHERunner(r *fhe.Runner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FHE = r
}

// fheEnabled reports whether this instance orchestrates the FHE service.
func (s *TAAState) fheEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.FHE != nil
}

// dataAnalysisEnabled reports whether this instance runs the data-anaylsis
// import path. Security is immutable after construction, so no lock is needed.
func (s *TAAState) dataAnalysisEnabled() bool {
	return s.Security.ServerType == config.ServerTypeDataAnalysis
}

// fheRunner returns the FHE runner, or nil on a tee instance.
func (s *TAAState) fheRunner() *fhe.Runner {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.FHE
}

func (s *TAAState) setFHEActiveTask(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fheActiveTaskID = taskID
}

func (s *TAAState) clearFHEActiveTask(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fheActiveTaskID == taskID {
		s.fheActiveTaskID = ""
	}
}

func (s *TAAState) fheActiveTask() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fheActiveTaskID
}

// setCurrentAuditOp is a helper to update the audit operation status. It is
// generation-gated so a superseded audit cannot leave its operation behind.
func (s *TAAState) setCurrentAuditOp(gen uint64, op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auditGen != gen {
		return
	}
	s.CurrentAuditOp = op
	s.AuditRunning = (op != "idle" && op != "")
}

// isCurrentAuditGen reports whether gen still owns the audit state.
func (s *TAAState) isCurrentAuditGen(gen uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auditGen == gen
}

// finishAudit releases one audit goroutine's registration. The busy fields and
// the pending marker are cleared only when the generation still owns them; a
// stale goroutine must not erase the state of the audit that replaced it.
func (s *TAAState) finishAudit(gen uint64, done chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.auditDone == done {
		s.auditDone = nil
		if s.auditCancel != nil {
			s.auditCancel()
		}
		s.auditCancel = nil
	}
	if s.auditGen != gen {
		return
	}
	s.resetAuditStateLocked()
	if s.pendingAudit != nil {
		s.clearAuditPendingLocked()
		if err := s.sealStateLocked(); err != nil {
			s.Logs.Add(LogError, "state", "持久化审计结论状态失败: %v", err)
		}
	}
}

// abortModelAudit cancels the running model audit, if any. It is silent: no
// platform callback is sent. The durable marker is dropped so a restart does
// not report an audit that was deliberately abandoned.
//
// The generation is incremented before the cancel, so every later write from
// the old goroutine (state, last audit, platform report) fails its ownership
// check even if it was already past the context check.
func (s *TAAState) abortModelAudit() {
	s.mu.Lock()
	if !s.isAuditBusyLocked() {
		s.mu.Unlock()
		return
	}
	oldTask := s.ActiveAuditTaskID
	oldRequest := s.ActiveAuditRequestID
	s.auditGen++
	s.resetAuditStateLocked()
	s.clearAuditPendingLocked()
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化审计中止状态失败: %v", err)
	}
	cancel := s.auditCancel
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	s.Logs.Add(LogInfo, "audit", "模型代码审计已中止: 收到新的模型下发; 旧 taskId=%s, requestId=%s", oldTask, oldRequest)
}

// auditAbortWaitTimeout bounds how long an import waits for the aborted audit to
// leave the model directory before overwriting it.
const auditAbortWaitTimeout = 30 * time.Second

// waitAuditStopped waits for the audit goroutine to exit before ModelDir is
// replaced. A superseded audit's result is discarded either way, so a timeout
// only logs: blocking the import forever on a scan that refuses to die would
// defeat the point of aborting it.
func (s *TAAState) waitAuditStopped() {
	s.mu.RLock()
	done := s.auditDone
	s.mu.RUnlock()
	if done == nil {
		return
	}

	timer := time.NewTimer(auditAbortWaitTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		s.Logs.Add(LogWarn, "audit",
			"旧模型审计未在 %s 内退出，继续覆盖模型目录；其结论已被代际号作废", auditAbortWaitTimeout)
	}
}

// isAuditBusyLocked checks if model code audit is currently running (caller must hold s.mu RLock or Lock).
func (s *TAAState) isAuditBusyLocked() bool {
	return s.AuditRunning || s.CurrentAuditOp == "auditing"
}

// resetAuditStateLocked resets model audit fields to idle state (caller must hold s.mu Lock).
func (s *TAAState) resetAuditStateLocked() {
	s.ActiveAuditTaskID = ""
	s.ActiveAuditRequestID = ""
	s.CurrentAuditOp = "idle"
	s.AuditRunning = false
}

// markModelAuditPendingLocked records that an audit is about to run for the model
// being imported (caller must hold s.mu Lock). It marks the in-memory audit
// fields busy and, when scanning is enabled, leaves the durable pending marker;
// the very next seal carries both to disk in one write.
//
// It is split from launching the goroutine so that "model is imported" and "an
// audit is owed for it" become durable together. Launched first, the audit could
// fail and clear the imported marker before saveModelSuccess re-sealed it as imported.
//
// Scanning disabled means no audit is owed: auditAndReportModelImport returns
// immediately, so writing the marker would leave a window in which a crash makes
// startup report an audit that never ran.
func (s *TAAState) markModelAuditPendingLocked(req importRequest, phase int) {
	s.ActiveAuditTaskID = req.TaskID
	s.ActiveAuditRequestID = req.RequestID
	s.CurrentAuditOp = "auditing"
	s.AuditRunning = true

	if !s.Security.ScanEnabled {
		s.pendingAudit = nil
		return
	}
	s.pendingAudit = &AuditPendingSnapshot{
		RequestID: req.RequestID,
		TaskID:    req.TaskID,
		Phase:     phase,
		StartedAt: time.Now().UTC(),
	}
}

// clearAuditPendingLocked drops the durable pending marker (caller must hold
// s.mu Lock). Idempotent: abortModelAudit, finishAudit, concludeAuditPending and
// ConcludeAuditPending all call it when an audit concludes or is abandoned.
func (s *TAAState) clearAuditPendingLocked() {
	s.pendingAudit = nil
}

// concludeAuditPending clears the durable pending marker and seals, so that an
// audit which reached a verdict is not mistaken for an abandoned one after a
// restart. Called when the verdict is known rather than when the goroutine
// unwinds: the unwind happens after the platform report, and a crash in between
// would otherwise have startup report an audit that had in fact concluded.
//
// It is generation-gated: an audit that no longer owns the state must not clear
// the marker its successor is relying on.
func (s *TAAState) concludeAuditPending(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auditGen != gen || s.pendingAudit == nil {
		return
	}
	s.clearAuditPendingLocked()
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化审计结论状态失败: %v", err)
	}
}

// ConcludeAuditPending 导出供调用的待决审计标记清除方法，供启动期对账使用：
// 被遗弃的审计补报平台后调用，避免同一次中断审计在下次启动被重复上报。
func (s *TAAState) ConcludeAuditPending() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingAudit == nil {
		return
	}
	s.clearAuditPendingLocked()
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化审计结论状态失败: %v", err)
	}
}

// PendingAudit reports the audit that was in flight when the process last sealed
// its state, or nil if there was none. The startup path consumes it to reconcile
// an audit whose goroutine did not survive the restart.
func (s *TAAState) PendingAudit() *AuditPendingSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pendingAudit == nil {
		return nil
	}
	snapshot := *s.pendingAudit
	return &snapshot
}

// effectiveOpLocked returns the user-facing operational status (caller must hold s.mu RLock or Lock).
func (s *TAAState) effectiveOpLocked() string {
	if (s.CurrentOp == "" || s.CurrentOp == "idle") && s.isAuditBusyLocked() {
		return "auditing"
	}
	if s.CurrentOp != "" {
		return s.CurrentOp
	}
	return "idle"
}

// isTrainingBusyLocked 检查是否处于正在训练/执行阶段（调用方需持有 s.mu 读锁或写锁）。
func (s *TAAState) isTrainingBusyLocked() bool {
	return s.TrainingRunning || s.CurrentOp == "staging" || s.CurrentOp == "training" || s.CurrentOp == "reporting"
}

// activeTaskInfoLocked 获取当前占用任务的信息描述（调用方需持有 s.mu 读锁或写锁）。
func (s *TAAState) activeTaskInfoLocked() (string, string) {
	if s.ActiveTaskID != "" {
		return s.ActiveTaskID, s.CurrentOp
	}
	if s.activeTask != nil {
		return s.activeTask.TaskID, s.CurrentOp
	}
	if s.isAuditBusyLocked() {
		task := s.ActiveAuditTaskID
		if task == "" {
			task = "model_audit"
		}
		return task, "auditing"
	}
	task := s.ActiveRequestID
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

	// 2. 检查是否有其他任务正在处理（如正在下载、解密等）
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
			var control *trainingControl
			if s.activeToken == token {
				control = s.trainingControl
				s.activeToken = 0
				s.ActiveTaskID = ""
				s.ActiveRequestID = ""
				s.CurrentOp = "idle"
				s.activeTask = nil
				s.TrainingRunning = false
				s.trainingControl = nil
				if err := s.sealStateLocked(); err != nil {
					s.Logs.Add(LogError, "task", "清除在飞任务快照持久化失败: %v", err)
				}
			}
			s.mu.Unlock()
			if control != nil {
				control.finish()
			}
		})
	}

	return release, nil
}

// promoteCurrentTaskToTraining 将当前处于飞行的导入任务状态提升为独占训练状态
func (s *TAAState) promoteCurrentTaskToTraining() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.TrainingRunning || s.trainingControl != nil {
		return pkgerrors.New(pkgerrors.CodeConflict, "当前已有训练任务正在执行中，请等待完成后再提交")
	}
	s.TrainingRunning = true
	s.CurrentOp = "training"
	if s.activeTask != nil {
		s.activeTask.Type = "training"
	}
	s.trainingControl = newTrainingControl()
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

	// 1. 读取当前在飞任务信息并清空内存中飞任务，落盘密封存储
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
	reportMap, err := BuildCrashFailureReport(taskID, startedAt, finishedAt, failureReason, modelChecksum, dataChecksum, resultDir)
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
		_ = writeJSONFile(filepath.Join(resultDir, trainingReportFileName), reportMap)
	}

	// 3. Fail-Closed: 主动向管控平台发送失败通知（通过 ReportTaskOutcome 自动分流）
	if platformIP != "" && dockerID != "" && (requestID != "" || taskID != "") {
		log.Printf("[PANIC RECOVERY] notifying platform of %s failure: requestId=%s, taskId=%s", taskType, requestID, taskID)
		if repErr := ReportTaskOutcome(context.Background(), platformIP, dockerID, requestID, taskID, taskType, 1, failureReason, reportJSON); repErr != nil {
			log.Printf("[PANIC RECOVERY] ReportTaskOutcome failed: %v", repErr)
		}
	}
}

// handleAuditPanic is the model audit's panic recovery. A panic in a superseded
// audit is not reported: the audit that replaced it owns the task ids now.
//
// The audit contract is that it never writes to, deletes, or modifies the
// package it reads, and a panic is not an exception to it: the extracted model
// directory and its dependency libraries are left exactly as they were.
func (s *TAAState) handleAuditPanic(gen uint64, req importRequest, r any) {
	panicMsg := fmt.Sprintf("%v", r)
	s.Logs.Add(LogError, "panic", "modelAudit 发生异常恢复: %v", r)
	log.Printf("[PANIC RECOVERY] modelAudit recovered from panic: %v", r)

	s.mu.Lock()
	if s.auditGen != gen {
		s.mu.Unlock()
		return
	}
	taskID := s.ActiveAuditTaskID
	requestID := s.ActiveAuditRequestID
	if taskID == "" {
		taskID = req.TaskID
	}
	if requestID == "" {
		requestID = req.RequestID
	}
	platformIP := s.PlatformIP
	dockerID := s.DockerID
	s.auditGen++
	s.resetAuditStateLocked()
	s.clearAuditPendingLocked()
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "panic", "持久化审计中断状态失败: %v", err)
	}
	s.mu.Unlock()

	if platformIP != "" && dockerID != "" && (taskID != "" || requestID != "") {
		s.reportAuditAsync(requestID, taskID, 2, fmt.Sprintf("model audit panic: %s", panicMsg), "")
	}
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

// decryptCiphertextWithDataKey decrypts a ciphertext-only resource file with an
// SM4 data key supplied from outside.
//
// Unlike decryptResourceToTempFile there is no SM2 key envelope prefix inside the
// file: the envelope came from the dataKeyCipher parameter of the delivery URL and
// was already unwrapped into dataKey upstream. The plaintext is written to a temp
// file whose path is returned; the caller removes it.
func (s *TAAState) decryptCiphertextWithDataKey(dataKey []byte, ciphertextPath string) (string, error) {
	f, err := os.Open(ciphertextPath)
	if err != nil {
		return "", fmt.Errorf("打开密文文件: %w", err)
	}
	defer f.Close()

	ciphertext, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("读取密文: %w", err)
	}
	if len(ciphertext) == 0 {
		return "", errors.New("密文为空")
	}

	plaintext, err := teecrypto.Decrypt(dataKey, ciphertext)
	if err != nil && ciphertext[0] == teecrypto.SM4FileVersion {
		// The platform's own SM4 files carry a one-byte format version in front of the
		// nonce -- [version][nonce][ciphertext][tag] -- while TAA writes the bare
		// [nonce][ciphertext][tag]. Reading a versioned file as the bare layout takes
		// that byte into the nonce and every tag check fails with the message above.
		//
		// The first byte alone cannot settle the layout (a random nonce starts with 0x01
		// one time in 256), so the bare layout is tried first and the versioned one only
		// after it fails: the GCM tag then decides, and only one layout can ever verify.
		//
		// The version is checked rather than skipped so an unknown one is refused instead
		// of being decrypted with whatever key happens to be at hand -- the producer's
		// rule for that byte is that it identifies the key space.
		plaintext, err = teecrypto.Decrypt(dataKey, ciphertext[1:])
	}
	ciphertext = nil // release the ciphertext buffer early
	if err != nil {
		return "", err
	}

	out, err := os.CreateTemp("", "taa-plaintext-*")
	if err != nil {
		plaintext = nil
		return "", fmt.Errorf("创建明文临时文件: %w", err)
	}
	plainPath := out.Name()
	if _, err := out.Write(plaintext); err != nil {
		_ = out.Close()
		_ = os.Remove(plainPath)
		plaintext = nil
		return "", fmt.Errorf("写入明文临时文件: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(plainPath)
		return "", fmt.Errorf("关闭明文临时文件: %w", err)
	}
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
	return runtime.ParseRuntimeConfig(raw)
}

func resolveRuntimeString(s string, dataDir, outputDir string) string {
	return runtime.ResolveRuntimeString(s, dataDir, outputDir)
}

func resolveRuntimeCommands(commands []string, dataDir, outputDir string) []string {
	return runtime.ResolveRuntimeCommands(commands, dataDir, outputDir)
}

func resolveRuntimeEnv(env map[string]string, dataDir, outputDir string) map[string]string {
	return runtime.ResolveRuntimeEnv(env, dataDir, outputDir)
}

func runRuntimeConfig(cfg runtimeConfig, env map[string]string, modelDir, dataDir, outputDir, taskID, startedAt string) (string, error) {
	return runtime.RunRuntimeConfig(cfg, env, modelDir, dataDir, outputDir, taskID, startedAt)
}

func runRuntimeConfigWithControl(control *trainingControl, cfg runtimeConfig, env map[string]string, modelDir, dataDir, outputDir, taskID, startedAt string) (string, error) {
	return runtime.RunRuntimeConfigWithControl(control, cfg, env, modelDir, dataDir, outputDir, taskID, startedAt)
}

// KillProcessGroup 级联清理进程及其所属的整个进程组。
func KillProcessGroup(cmd *exec.Cmd) error {
	return runtime.KillProcessGroup(cmd)
}

func mergedRuntimeEnv(userEnv, systemEnv map[string]string) []string {
	return runtime.MergedRuntimeEnv(userEnv, systemEnv)
}

func envKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
