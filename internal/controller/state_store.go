package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	teecrypto "taa/pkg/crypto"
	"taa/pkg/utils"
)

const (
	// DefaultStateVersion 默认状态存储格式版本号
	DefaultStateVersion = "1.4"
)

// PersistentState 定义 TAA 核心受保护运行状态
type PersistentState struct {
	Version               string              `json:"version"`               // 固定 "1.4"
	StateSeq              uint64              `json:"stateSeq"`              // 单调递增版本序列号
	IncarnationID         string              `json:"incarnationId"`         // 冷启动纪元 UUID
	CurrentPhase          int                 `json:"currentPhase"`          // 当前阶段 1~4
	ModelImported         bool                `json:"modelImported"`         // 模型已解密且通过审计
	TrainingRunning       bool                `json:"trainingRunning"`       // 是否存在正在执行的训练任务
	ExportPublicKey       string              `json:"exportPublicKey"`       // Phase 1 保存的公钥 PEM
	SavedModelResourceURL string              `json:"savedModelResourceURL"` // 密态存储
	RuntimeConfig         string              `json:"runtimeConfig"`         // 密态存储
	ModelChecksum         map[string]any      `json:"modelChecksum"`
	DataChecksum          map[string]any      `json:"dataChecksum"`
	ActiveTask            *ActiveTaskSnapshot `json:"activeTask,omitempty"` // 在飞任务快照
	UpdatedAt             time.Time           `json:"updatedAt"`
}

// ActiveTaskSnapshot 在飞任务快照
type ActiveTaskSnapshot struct {
	RequestID        string    `json:"requestId"`
	TaskID           string    `json:"taskId"`
	Type             string    `json:"type"` // "model_import" | "data_import" | "training"
	Phase            int       `json:"phase"`
	Status           string    `json:"status"` // "RUNNING"
	ResultDir        string    `json:"resultDir"`
	StartedAt        time.Time `json:"startedAt"`
	RecoveryAttempts int       `json:"recoveryAttempts"`
}

// DeriveSealingKey 利用私钥标量 D（填充为 32 字节大端）：
// SM3(privKey.D || "TAA-STATE-SEALING-V1" || 0x00000001)[:16]
// 派生 16 字节 SM4-128 密钥。复用 pkg/crypto.DeriveSealingKey 底层实现。
func DeriveSealingKey(privKey *teecrypto.SM2PrivateKey) []byte {
	return teecrypto.DeriveSealingKey(privKey)
}

// StateStore 管理持久化状态文件的密封存储与内存缓存
type StateStore struct {
	mu         sync.RWMutex
	path       string
	sealingKey []byte
	state      *PersistentState
}

// NewStateStore 构造密封状态存储引擎
func NewStateStore(path string, sealingKey []byte) (*StateStore, error) {
	if len(sealingKey) != 16 {
		return nil, fmt.Errorf("invalid sealing key size: expected 16 bytes, got %d", len(sealingKey))
	}
	return &StateStore{
		path:       path,
		sealingKey: append([]byte(nil), sealingKey...),
	}, nil
}

// GetState 获取当前内存中的状态快照
func (s *StateStore) GetState() *PersistentState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil
	}
	cloned := *s.state
	return &cloned
}

// SealState 序列化状态，通过 SM4-GCM 加密并执行全链路 Fsync 原子落盘
func (s *StateStore) SealState(state *PersistentState) error {
	if state == nil {
		return errors.New("state cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.sealStateLocked(state)
}

func (s *StateStore) sealStateLocked(state *PersistentState) error {
	state.StateSeq++
	if state.Version == "" {
		state.Version = DefaultStateVersion
	}
	state.UpdatedAt = time.Now().UTC()

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	ciphertext, err := teecrypto.Encrypt(s.sealingKey, data)
	if err != nil {
		return fmt.Errorf("encrypt state: %w", err)
	}

	if err := utils.AtomicWriteFile(s.path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("atomic write state file: %w", err)
	}

	s.state = state
	return nil
}

// UnsealState 读取磁盘密文，使用 SM4-GCM 解密并校验完整性，反序列化为状态结构体
func (s *StateStore) UnsealState() (*PersistentState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.unsealStateLocked()
}

func (s *StateStore) unsealStateLocked() (*PersistentState, error) {
	ciphertext, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}

	plaintext, err := teecrypto.Decrypt(s.sealingKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt state: %w", err)
	}

	var state PersistentState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}

	s.state = &state
	return &state, nil
}

// DetectAndHandleKeyDrift 探测密钥漂移并进行处理：
// 若 UnsealState() 认证失败且 isNewKey == true，将损坏旧文件重命名为 .orphaned.<timestamp>，并干净初始化；
// 若 isNewKey == false（老私钥但解密失败），按 Fail-Closed 原则返回错误拒绝加载。
func (s *StateStore) DetectAndHandleKeyDrift(isNewKey bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.unsealStateLocked()
	if err == nil {
		s.state = state
		return false, nil
	}

	// 若文件不存在，属于初次启动，直接初始化干净状态
	if os.IsNotExist(err) {
		cleanState := newCleanPersistentState()
		if err := s.sealStateLocked(cleanState); err != nil {
			return false, fmt.Errorf("initialize clean state: %w", err)
		}
		return false, nil
	}

	// 文件存在但解密认证失败
	if isNewKey {
		timestamp := time.Now().Unix()
		parentDir := filepath.Dir(s.path)
		orphanedPath := filepath.Join(parentDir, fmt.Sprintf(".orphaned.%d", timestamp))
		if renameErr := os.Rename(s.path, orphanedPath); renameErr != nil && !os.IsNotExist(renameErr) {
			return false, fmt.Errorf("archive orphaned state file failed: %w", renameErr)
		}

		cleanState := newCleanPersistentState()
		if err := s.sealStateLocked(cleanState); err != nil {
			return false, fmt.Errorf("seal clean state after key drift: %w", err)
		}
		return true, nil
	}

	// 老私钥但解密失败：Fail-Closed 拒绝启动
	return false, fmt.Errorf("state integrity verification failed (fail-closed): %w", err)
}

func newCleanPersistentState() *PersistentState {
	return &PersistentState{
		Version:       DefaultStateVersion,
		StateSeq:      0,
		IncarnationID: utils.NewUUID(),
		CurrentPhase:  1,
		ModelChecksum: make(map[string]any),
		DataChecksum:  make(map[string]any),
		UpdatedAt:     time.Now().UTC(),
	}
}
