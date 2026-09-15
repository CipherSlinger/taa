package controller

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	teecrypto "taa/pkg/crypto"
)

func TestStateStore_DeriveSealingKey(t *testing.T) {
	// 1. 正常派生与确定性校验
	privKey1, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key pair failed: %v", err)
	}

	key1 := DeriveSealingKey(privKey1)
	if len(key1) != 16 {
		t.Fatalf("expected 16-byte sealing key, got %d bytes", len(key1))
	}

	key1Repeat := DeriveSealingKey(privKey1)
	if string(key1) != string(key1Repeat) {
		t.Fatalf("key derivation is not deterministic")
	}

	// 2. 差异性：不同私钥派生出的密钥必然不同
	privKey2, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate second SM2 key pair failed: %v", err)
	}
	key2 := DeriveSealingKey(privKey2)
	if string(key1) == string(key2) {
		t.Fatalf("different private keys produced identical sealing keys")
	}

	// 3. 异常边界：nil 输入
	if key := DeriveSealingKey(nil); key != nil {
		t.Fatalf("expected nil for nil private key, got %v", key)
	}
	if key := DeriveSealingKey(&teecrypto.SM2PrivateKey{}); key != nil {
		t.Fatalf("expected nil for empty private key, got %v", key)
	}

	// 4. 大端填充验证（小标量 D）
	smallPriv := &teecrypto.SM2PrivateKey{
		D: big.NewInt(42),
	}
	smallKey := DeriveSealingKey(smallPriv)
	if len(smallKey) != 16 {
		t.Fatalf("expected 16-byte sealing key for small D, got %d bytes", len(smallKey))
	}
}

func TestPersistentStateJSONUsesTrainingRunning(t *testing.T) {
	state := PersistentState{
		Version:         DefaultStateVersion,
		ModelImported:   true,
		TrainingRunning: true,
	}

	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal persistent state failed: %v", err)
	}

	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshal persistent state JSON failed: %v", err)
	}
	for _, removed := range []string{"dataImported", "trainingDataImported", "trainingDone"} {
		if _, ok := fields[removed]; ok {
			t.Fatalf("persistent state JSON contains removed field %q: %s", removed, data)
		}
	}
	if got, ok := fields["trainingRunning"].(bool); !ok || !got {
		t.Fatalf("persistent state JSON trainingRunning = %#v, want true", fields["trainingRunning"])
	}
}

func TestStateStore_SealAndUnseal(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.bin")

	privKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key failed: %v", err)
	}
	sealingKey := DeriveSealingKey(privKey)

	store, err := NewStateStore(statePath, sealingKey)
	if err != nil {
		t.Fatalf("new state store failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	initialState := &PersistentState{
		Version:               DefaultStateVersion,
		StateSeq:              0,
		IncarnationID:         "epoch-uuid-12345",
		CurrentPhase:          2,
		ModelImported:         true,
		TrainingRunning:       true,
		ExportPublicKey:       "-----BEGIN PUBLIC KEY-----\nMIIB...PEM\n-----END PUBLIC KEY-----",
		SavedModelResourceURL: "oss://model-bucket/encrypted/model.tar.gz",
		RuntimeConfig:         `{"batch_size":32,"lr":0.001}`,
		ModelChecksum: map[string]any{
			"algorithm": "sm3",
			"hash":      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		DataChecksum: map[string]any{
			"algorithm": "sm3",
			"hash":      "d41d8cd98f00b204e9800998ecf8427e",
		},
		ActiveTask: &ActiveTaskSnapshot{
			RequestID:        "req-001",
			TaskID:           "task-001",
			Type:             "training",
			Phase:            2,
			Status:           "RUNNING",
			ResultDir:        "/opt/taa/results/req-001-task-001",
			StartedAt:        now,
			RecoveryAttempts: 1,
		},
	}

	// 1. 密封落盘
	if err := store.SealState(initialState); err != nil {
		t.Fatalf("seal state failed: %v", err)
	}

	// 验证 StateSeq 自增为 1
	if initialState.StateSeq != 1 {
		t.Fatalf("expected stateSeq 1, got %d", initialState.StateSeq)
	}

	// 检查磁盘文件权限为 0600
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat state file failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected file perm 0600, got %o", perm)
	}

	// 检查落盘文件内容不是明文 JSON
	rawBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state file failed: %v", err)
	}
	var probe map[string]any
	if json.Unmarshal(rawBytes, &probe) == nil {
		t.Fatalf("state file was stored in plaintext JSON, expected ciphertext")
	}

	// 2. 解密加载
	loadedState, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state failed: %v", err)
	}

	if loadedState.Version != DefaultStateVersion {
		t.Fatalf("expected version %s, got %s", DefaultStateVersion, loadedState.Version)
	}
	if loadedState.StateSeq != 1 {
		t.Fatalf("expected stateSeq 1, got %d", loadedState.StateSeq)
	}
	if loadedState.IncarnationID != initialState.IncarnationID {
		t.Fatalf("expected incarnationID %s, got %s", initialState.IncarnationID, loadedState.IncarnationID)
	}
	if loadedState.CurrentPhase != 2 {
		t.Fatalf("expected currentPhase 2, got %d", loadedState.CurrentPhase)
	}
	if !loadedState.ModelImported || !loadedState.TrainingRunning {
		t.Fatalf("expected modelImported and trainingRunning to be true")
	}
	if loadedState.ExportPublicKey != initialState.ExportPublicKey {
		t.Fatalf("exportPublicKey mismatch")
	}
	if loadedState.SavedModelResourceURL != initialState.SavedModelResourceURL {
		t.Fatalf("savedModelResourceURL mismatch")
	}
	if loadedState.RuntimeConfig != initialState.RuntimeConfig {
		t.Fatalf("runtimeConfig mismatch")
	}
	if loadedState.ActiveTask == nil || loadedState.ActiveTask.TaskID != "task-001" {
		t.Fatalf("activeTask mismatch: %+v", loadedState.ActiveTask)
	}

	// 3. 二次保存，StateSeq 递增
	if err := store.SealState(loadedState); err != nil {
		t.Fatalf("second seal state failed: %v", err)
	}
	if loadedState.StateSeq != 2 {
		t.Fatalf("expected stateSeq 2, got %d", loadedState.StateSeq)
	}

	// 内存状态获取
	cached := store.GetState()
	if cached == nil || cached.StateSeq != 2 {
		t.Fatalf("expected cached stateSeq 2, got %+v", cached)
	}
}

func TestStateStore_Unseal_TamperedOrCorrupted(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.bin")

	privKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key failed: %v", err)
	}
	sealingKey := DeriveSealingKey(privKey)

	store, err := NewStateStore(statePath, sealingKey)
	if err != nil {
		t.Fatalf("new state store failed: %v", err)
	}

	state := &PersistentState{
		Version:       DefaultStateVersion,
		IncarnationID: "test-epoch",
		CurrentPhase:  1,
	}
	if err := store.SealState(state); err != nil {
		t.Fatalf("seal state failed: %v", err)
	}

	// 1. 篡改密文内容
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state failed: %v", err)
	}
	if len(raw) > 20 {
		raw[len(raw)-5] ^= 0xff // 破坏末尾 tag
	}
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatalf("write tampered state failed: %v", err)
	}

	// 验证解密失败
	if _, err := store.UnsealState(); err == nil {
		t.Fatalf("expected error when unsealing tampered ciphertext, got nil")
	}

	// 2. 使用不同的私钥解密
	otherPrivKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate other SM2 key failed: %v", err)
	}
	wrongStore, err := NewStateStore(statePath, DeriveSealingKey(otherPrivKey))
	if err != nil {
		t.Fatalf("new wrong store failed: %v", err)
	}
	if _, err := wrongStore.UnsealState(); err == nil {
		t.Fatalf("expected error when unsealing with wrong sealing key, got nil")
	}
}

func TestStateStore_DetectAndHandleKeyDrift_NewKey(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.bin")

	// 1. 使用旧私钥密封落盘状态
	oldPrivKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate old key failed: %v", err)
	}
	oldStore, err := NewStateStore(statePath, DeriveSealingKey(oldPrivKey))
	if err != nil {
		t.Fatalf("new old store failed: %v", err)
	}

	oldState := &PersistentState{
		Version:       DefaultStateVersion,
		IncarnationID: "old-epoch-uuid",
		CurrentPhase:  3,
	}
	if err := oldStore.SealState(oldState); err != nil {
		t.Fatalf("seal old state failed: %v", err)
	}

	// 2. 模拟新私钥（isNewKey == true）启动
	newPrivKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate new key failed: %v", err)
	}
	newStore, err := NewStateStore(statePath, DeriveSealingKey(newPrivKey))
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}

	drifted, err := newStore.DetectAndHandleKeyDrift(true)
	if err != nil {
		t.Fatalf("expected successful drift handling, got error: %v", err)
	}
	if !drifted {
		t.Fatalf("expected drifted to be true")
	}

	// 验证旧文件被重命名为 .orphaned.<timestamp>
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("read tempDir failed: %v", err)
	}
	foundOrphaned := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".orphaned.") {
			foundOrphaned = true
			break
		}
	}
	if !foundOrphaned {
		t.Fatalf("expected orphaned file prefixed with .orphaned., entries found: %v", entries)
	}

	// 验证新状态已干净初始化，可成功解密
	reloaded, err := newStore.UnsealState()
	if err != nil {
		t.Fatalf("unseal after drift handling failed: %v", err)
	}
	if reloaded.CurrentPhase != 1 {
		t.Fatalf("expected clean state phase 1, got %d", reloaded.CurrentPhase)
	}
	if reloaded.IncarnationID == "old-epoch-uuid" {
		t.Fatalf("expected new incarnationID, got old one")
	}
}

func TestStateStore_DetectAndHandleKeyDrift_OldKeyFailClosed(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.bin")

	privKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}
	store, err := NewStateStore(statePath, DeriveSealingKey(privKey))
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}

	// 写入损坏的非密文数据
	if err := os.WriteFile(statePath, []byte("garbage corrupted data"), 0o600); err != nil {
		t.Fatalf("write garbage failed: %v", err)
	}

	// isNewKey == false（老私钥但解密失败），必须 Fail-Closed
	drifted, err := store.DetectAndHandleKeyDrift(false)
	if err == nil {
		t.Fatalf("expected fail-closed error, got nil (drifted=%v)", drifted)
	}
	if !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("expected error mentioning fail-closed, got: %v", err)
	}
}

func TestStateStore_DetectAndHandleKeyDrift_CleanStart(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.bin")

	privKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}
	store, err := NewStateStore(statePath, DeriveSealingKey(privKey))
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}

	// 状态文件原本不存在
	drifted, err := store.DetectAndHandleKeyDrift(false)
	if err != nil {
		t.Fatalf("clean start failed: %v", err)
	}
	if drifted {
		t.Fatalf("expected drifted to be false on clean start")
	}

	// 文件应已初始化
	state, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal initialized state failed: %v", err)
	}
	if state.Version != DefaultStateVersion || state.CurrentPhase != 1 {
		t.Fatalf("unexpected state after clean start: %+v", state)
	}
}
