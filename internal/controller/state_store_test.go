package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	teecrypto "taa/pkg/crypto"
)

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
