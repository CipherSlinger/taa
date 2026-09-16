package resource

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportIndexStoreBasic(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "import-index.json")

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("LoadImportIndexStore failed: %v", err)
	}

	// 1. 预留
	if err := store.Reserve("req-1", "task-1"); err != nil {
		t.Fatalf("Reserve failed: %v", err)
	}

	// 重复预留应失败
	if err := store.Reserve("req-1", "task-2"); err == nil {
		t.Fatal("expected reserve error on duplicate reqID, got nil")
	}

	// 2. 提交
	rec := ImportIndexRecord{
		RequestID: "req-1",
		TaskID:    "task-1",
		Hash:      "hash-123456",
		DataDir:   filepath.Join(tmpDir, "data"),
		ResultDir: filepath.Join(tmpDir, "result"),
		Phase:     1,
	}
	if err := store.Commit(rec); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// 3. 查找
	found, ok := store.LookupByRequestID("req-1")
	if !ok || found.Hash != "hash-123456" {
		t.Fatalf("LookupByRequestID failed: ok=%v, found=%+v", ok, found)
	}

	foundTask, ok := store.LookupByTaskID("task-1")
	if !ok || foundTask.Hash != "hash-123456" {
		t.Fatalf("LookupByTaskID failed: ok=%v, found=%+v", ok, foundTask)
	}

	latest, ok := store.Latest()
	if !ok || latest.RequestID != "req-1" {
		t.Fatalf("Latest failed: ok=%v, latest=%+v", ok, latest)
	}

	// 4. 从磁盘重载验证持久化
	store2, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("reload LoadImportIndexStore failed: %v", err)
	}
	if latest2, ok := store2.Latest(); !ok || latest2.RequestID != "req-1" {
		t.Fatalf("reloaded Latest mismatch: ok=%v, latest=%+v", ok, latest2)
	}
}

func TestImportIndexStoreRollback(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "import-index.json")

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("LoadImportIndexStore failed: %v", err)
	}

	if err := store.Reserve("req-rb", "task-rb"); err != nil {
		t.Fatalf("Reserve failed: %v", err)
	}
	store.Rollback("req-rb", "task-rb")

	// Rollback 后应该可以重新预留
	if err := store.Reserve("req-rb", "task-rb"); err != nil {
		t.Fatalf("Reserve after Rollback failed: %v", err)
	}
}

func TestImportIndexStoreRecoveryFromBak(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "import-index.json")
	bakPath := indexPath + ".bak"

	// 写入合法的 bak 文件
	validJSON := `{
		"records": [
			{
				"requestId": "req-bak",
				"taskId": "task-bak",
				"hash": "hash-bak-123",
				"dataDir": "/tmp/data",
				"resultDir": "/tmp/res",
				"phase": 1
			}
		]
	}`
	if err := os.WriteFile(bakPath, []byte(validJSON), 0o644); err != nil {
		t.Fatalf("write bak file: %v", err)
	}

	// 写入损坏的 index 文件
	if err := os.WriteFile(indexPath, []byte("{corrupted json"), 0o644); err != nil {
		t.Fatalf("write corrupted index file: %v", err)
	}

	// 加载时应自动从 .bak 恢复
	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("LoadImportIndexStore failed to recover from bak: %v", err)
	}

	rec, ok := store.LookupByRequestID("req-bak")
	if !ok || rec.Hash != "hash-bak-123" {
		t.Fatalf("record recovered from bak mismatch: ok=%v, rec=%+v", ok, rec)
	}
}
