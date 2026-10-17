package controller

import (
	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
)

const (
	// DefaultStateVersion 默认状态存储格式版本号
	DefaultStateVersion = store.DefaultStateVersion
)

// PersistentState 定义 TAA 核心受保护运行状态
type PersistentState = store.PersistentState

// ActiveTaskSnapshot 在飞任务快照
type ActiveTaskSnapshot = store.ActiveTaskSnapshot

// AuditPendingSnapshot 在飞安全审计快照，用于跨重启识别被遗弃的审计
type AuditPendingSnapshot = store.AuditPendingSnapshot

// StateStore 管理持久化状态文件的密封存储与内存缓存
type StateStore = store.StateStore

// KeySource identifies where the state sealing key came from.
type KeySource = store.KeySource

const (
	// KeySourceSM2 is a sealing key derived from the SM2 private scalar.
	KeySourceSM2 = store.KeySourceSM2
	// KeySourceCSVHW is the Hygon CSV hardware sealing key.
	KeySourceCSVHW = store.KeySourceCSVHW
)

// DeriveSealingKey 利用私钥标量 D 派生 16 字节 SM4-128 密钥。
func DeriveSealingKey(privKey *teecrypto.SM2PrivateKey) []byte {
	return store.DeriveSealingKey(privKey)
}

// NewStateStore 构造密封状态存储引擎
func NewStateStore(path string, sealingKey []byte, source KeySource) (*StateStore, error) {
	return store.NewStateStore(path, sealingKey, source)
}

func newCleanPersistentState() *PersistentState {
	return store.NewCleanPersistentState()
}
