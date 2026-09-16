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

// StateStore 管理持久化状态文件的密封存储与内存缓存
type StateStore = store.StateStore

// DeriveSealingKey 利用私钥标量 D 派生 16 字节 SM4-128 密钥。
func DeriveSealingKey(privKey *teecrypto.SM2PrivateKey) []byte {
	return store.DeriveSealingKey(privKey)
}

// NewStateStore 构造密封状态存储引擎
func NewStateStore(path string, sealingKey []byte) (*StateStore, error) {
	return store.NewStateStore(path, sealingKey)
}

func newCleanPersistentState() *PersistentState {
	return store.NewCleanPersistentState()
}
