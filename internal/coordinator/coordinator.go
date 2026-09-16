package coordinator

import (
	"context"
	"path/filepath"
	"sync"

	"taa/internal/platform"
	"taa/internal/resource"
	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

// CoordinatorParams 初始化 Coordinator 的依赖参数
type CoordinatorParams struct {
	StateStore      *store.StateStore
	PhaseState      *PhaseState
	TaskManager     *TaskManager
	PlatformClient  *platform.Client
	IndexStore      *resource.ImportIndexStore
	Security        SecurityConfig
	SM2PrivateKey   *teecrypto.SM2PrivateKey
	UserData        []byte
	AttestationFile string
	PlatformIP      string
	DockerID        string
}

// Coordinator 作为业务编排核心，组合各领域服务并驱动端到端工作流
type Coordinator struct {
	mu              sync.RWMutex
	stateStore      *store.StateStore
	phaseState      *PhaseState
	taskManager     *TaskManager
	platformClient  *platform.Client
	indexStore      *resource.ImportIndexStore
	security        SecurityConfig
	sm2PrivateKey   *teecrypto.SM2PrivateKey
	userData        []byte
	attestationFile string
	platformIP      string
	dockerID        string
}

// NewCoordinator 创建 Coordinator 实例
func NewCoordinator(params CoordinatorParams) *Coordinator {
	ps := params.PhaseState
	if ps == nil {
		ps = NewPhaseState(params.StateStore)
	}
	tm := params.TaskManager
	if tm == nil {
		tm = NewTaskManager()
	}

	c := &Coordinator{
		stateStore:      params.StateStore,
		phaseState:      ps,
		taskManager:     tm,
		platformClient:  params.PlatformClient,
		indexStore:      params.IndexStore,
		security:        params.Security,
		sm2PrivateKey:   params.SM2PrivateKey,
		userData:        params.UserData,
		attestationFile: params.AttestationFile,
		platformIP:      params.PlatformIP,
		dockerID:        params.DockerID,
	}

	// 初始化索引引擎
	if c.indexStore == nil && c.security.DataDir != "" {
		indexPath := filepath.Join(c.security.DataDir, "import_index.json")
		if idx, err := resource.LoadImportIndexStore(indexPath); err == nil {
			c.indexStore = idx
		}
	}

	return c
}

// StateStore 返回状态存储引擎
func (c *Coordinator) StateStore() *store.StateStore {
	return c.stateStore
}

// PhaseState 返回阶段状态管理器
func (c *Coordinator) PhaseState() *PhaseState {
	return c.phaseState
}

// TaskManager 返回任务排他锁管理器
func (c *Coordinator) TaskManager() *TaskManager {
	return c.taskManager
}

// PlatformClient 返回平台通信客户端
func (c *Coordinator) PlatformClient() *platform.Client {
	return c.platformClient
}

// IndexStore 返回导入索引引擎
func (c *Coordinator) IndexStore() *resource.ImportIndexStore {
	return c.indexStore
}

// Security 返回固化的安全配置
func (c *Coordinator) Security() SecurityConfig {
	return c.security
}

// SM2PrivateKey 返回 TAA 私钥
func (c *Coordinator) SM2PrivateKey() *teecrypto.SM2PrivateKey {
	return c.sm2PrivateKey
}

// UserData 返回 64 字节 USERDATA
func (c *Coordinator) UserData() []byte {
	return c.userData
}

// ImportModel 发起模型导入任务
func (c *Coordinator) ImportModel(ctx context.Context, params ModelImportParams) (int64, error) {
	token, err := c.taskManager.AcquireTaskLock(params.RequestID, params.TaskID, "model_import", params.Phase)
	if err != nil {
		return 0, err
	}

	_ = c.phaseState.SealState(c.taskManager.GetActiveTask())

	c.taskManager.RunAsyncSafe(token, func() {
		_ = c.ExecuteModelImportFlow(context.Background(), params)
	})
	return token, nil
}

// ImportTraining 发起数据导入与模型训练任务
func (c *Coordinator) ImportTraining(ctx context.Context, params TrainingImportParams) (int64, error) {
	token, err := c.taskManager.AcquireTaskLock(params.RequestID, params.TaskID, "data_import", params.Phase)
	if err != nil {
		return 0, err
	}

	_ = c.phaseState.SealState(c.taskManager.GetActiveTask())

	c.taskManager.RunAsyncSafe(token, func() {
		_ = c.ExecuteTrainingImportFlow(context.Background(), params)
	})
	return token, nil
}

// Export 执行产物信封加密导出
func (c *Coordinator) Export(params ExportParams) ([]byte, error) {
	if c.taskManager.IsBusy() {
		return nil, pkgerrors.New(pkgerrors.CodeConflict, "当前有任务正在执行，无法导出产物")
	}
	return c.ExecuteExportFlow(params)
}

// StopTraining 中止当前训练任务
func (c *Coordinator) StopTraining() bool {
	return c.taskManager.StopTraining()
}

// SetStateStore 动态注入密封存储
func (c *Coordinator) SetStateStore(st *store.StateStore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateStore = st
	if c.phaseState != nil {
		_ = c.phaseState.RestoreFromStore()
	}
}
