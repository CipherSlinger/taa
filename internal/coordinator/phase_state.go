package coordinator

import (
	"fmt"
	"sync"

	"taa/internal/codeaudit"
	"taa/internal/resource"
	"taa/internal/store"
	pkgerrors "taa/pkg/errors"
)

// PhaseState 维护运行时业务阶段、模型就绪状态及与底层密封存储的同步
type PhaseState struct {
	mu                sync.RWMutex
	store             *store.StateStore
	currentPhase      int
	modelImported     bool
	exportPublicKey   string
	savedModelURL     string
	runtimeConfig     string
	currentOp         string
	currentDataRecord resource.ImportIndexRecord
	latestDataRecord  resource.ImportIndexRecord
	modelChecksum     map[string]any
	dataChecksum      map[string]any
	lastAudit         *codeaudit.AuditReport
}

// NewPhaseState 创建阶段状态管理器
func NewPhaseState(st *store.StateStore) *PhaseState {
	ps := &PhaseState{
		store:        st,
		currentPhase: 1,
		currentOp:    "idle",
	}
	if st != nil {
		_ = ps.RestoreFromStore()
	}
	return ps
}

// CurrentPhase 返回当前阶段号 (1-4)
func (s *PhaseState) CurrentPhase() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentPhase
}

// SetPhase 校验并切换当前阶段号，并同步密封持久化
func (s *PhaseState) SetPhase(phase int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if phase < 1 || phase > 4 {
		return pkgerrors.New(pkgerrors.CodeInvalidArgument, fmt.Sprintf("无效的阶段值: %d，有效范围 1-4", phase))
	}
	s.currentPhase = phase
	return s.sealLocked(nil)
}

// IsModelImported 检查模型是否已就绪
func (s *PhaseState) IsModelImported() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.modelImported
}

// SetModelImported 设置模型就绪标志与资源 URL
func (s *PhaseState) SetModelImported(imported bool, url string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.modelImported = imported
	if url != "" {
		s.savedModelURL = url
	}
	_ = s.sealLocked(nil)
}

// SavedModelURL 返回已缓存的模型资源 URL
func (s *PhaseState) SavedModelURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.savedModelURL
}

// ExportPublicKey 获取用于加密阶段 3 结果的阶段 1 导出公钥
func (s *PhaseState) ExportPublicKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exportPublicKey
}

// SetExportPublicKey 保存阶段 1 传入的导出公钥
func (s *PhaseState) SetExportPublicKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exportPublicKey = key
	_ = s.sealLocked(nil)
}

// RuntimeConfig 获取当前持久化的运行配置
func (s *PhaseState) RuntimeConfig() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runtimeConfig
}

// SetRuntimeConfig 更新运行配置并密封落盘
func (s *PhaseState) SetRuntimeConfig(cfg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runtimeConfig = cfg
	_ = s.sealLocked(nil)
}

// CurrentOp 返回当前执行的子操���
func (s *PhaseState) CurrentOp() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentOp
}

// SetCurrentOp 更新当前操作状态
func (s *PhaseState) SetCurrentOp(op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentOp = op
}

// ModelChecksum 获取模型校验和信息
func (s *PhaseState) ModelChecksum() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.modelChecksum == nil {
		return nil
	}
	out := make(map[string]any, len(s.modelChecksum))
	for k, v := range s.modelChecksum {
		out[k] = v
	}
	return out
}

// SetModelChecksum 更新模型校验和信息
func (s *PhaseState) SetModelChecksum(c map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.modelChecksum = c
	_ = s.sealLocked(nil)
}

// DataChecksum 获取数据校验和信息
func (s *PhaseState) DataChecksum() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.dataChecksum == nil {
		return nil
	}
	out := make(map[string]any, len(s.dataChecksum))
	for k, v := range s.dataChecksum {
		out[k] = v
	}
	return out
}

// SetDataChecksum 更新数据校验和信息
func (s *PhaseState) SetDataChecksum(c map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dataChecksum = c
	_ = s.sealLocked(nil)
}

// LastAudit 获取最近一次代码审计报告
func (s *PhaseState) LastAudit() *codeaudit.AuditReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastAudit
}

// SetLastAudit 记录最近一次代码审计报告
func (s *PhaseState) SetLastAudit(report *codeaudit.AuditReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAudit = report
}

// CurrentDataRecord 获取当前绑定的数据索引记录
func (s *PhaseState) CurrentDataRecord() resource.ImportIndexRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentDataRecord
}

// LatestDataRecord 获取最新导入的数据索引记录
func (s *PhaseState) LatestDataRecord() resource.ImportIndexRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latestDataRecord
}

// SetDataRecords 更新数据索引记录并密封落盘
func (s *PhaseState) SetDataRecords(current, latest resource.ImportIndexRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentDataRecord = current
	s.latestDataRecord = latest
	_ = s.sealLocked(nil)
}

// SealState 手动执行状态持久化落盘
func (s *PhaseState) SealState(activeTask *store.ActiveTaskSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sealLocked(activeTask)
}

func (s *PhaseState) sealLocked(activeTask *store.ActiveTaskSnapshot) error {
	if s.store == nil {
		return nil
	}
	persistent := &store.PersistentState{
		CurrentPhase:          s.currentPhase,
		ModelImported:         s.modelImported,
		ExportPublicKey:       s.exportPublicKey,
		SavedModelResourceURL: s.savedModelURL,
		RuntimeConfig:         s.runtimeConfig,
		ModelChecksum:         s.modelChecksum,
		DataChecksum:          s.dataChecksum,
		ActiveTask:            activeTask,
	}
	return s.store.SealState(persistent)
}

// RestoreFromStore 从持久化密封存储中恢复状态
func (s *PhaseState) RestoreFromStore() error {
	if s.store == nil {
		return nil
	}
	state, err := s.store.UnsealState()
	if err != nil {
		return err
	}
	if state == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.currentPhase = state.CurrentPhase
	if s.currentPhase == 0 {
		s.currentPhase = 1
	}
	s.modelImported = state.ModelImported
	s.exportPublicKey = state.ExportPublicKey
	s.savedModelURL = state.SavedModelResourceURL
	s.runtimeConfig = state.RuntimeConfig
	s.modelChecksum = state.ModelChecksum
	s.dataChecksum = state.DataChecksum
	return nil
}
