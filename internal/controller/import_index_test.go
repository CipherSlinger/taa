package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportIndex_PhaseField(t *testing.T) {
	tempDir := t.TempDir()
	indexPath := filepath.Join(tempDir, "import-index.json")

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("load store failed: %v", err)
	}

	rec := ImportIndexRecord{
		RequestID: "req-phase-test",
		TaskID:    "task-phase-test",
		Hash:      "hash-12345",
		DataDir:   "/data/test",
		ResultDir: "/result/test",
		Phase:     2,
	}

	if err := store.Reserve(rec.RequestID, rec.TaskID); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}
	if err := store.Commit(rec); err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	// 重新从磁盘加载并验证 Phase
	reloaded, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("reload store failed: %v", err)
	}

	found, ok := reloaded.LookupByRequestID(rec.RequestID)
	if !ok {
		t.Fatalf("lookup failed")
	}
	if found.Phase != 2 {
		t.Fatalf("expected phase 2, got %d", found.Phase)
	}

	// 检查磁盘 JSON 中包含 "phase": 2
	data, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read index file failed: %v", err)
	}
	if !strings.Contains(string(data), `"phase": 2`) {
		t.Fatalf("JSON did not contain \"phase\": 2, got: %s", string(data))
	}
}

func TestImportIndex_FsyncAtomicSaveAndBak(t *testing.T) {
	tempDir := t.TempDir()
	indexPath := filepath.Join(tempDir, "import-index.json")
	bakPath := indexPath + ".bak"

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("load store failed: %v", err)
	}

	rec := ImportIndexRecord{
		RequestID: "req-1",
		TaskID:    "task-1",
		Hash:      "hash-1",
		DataDir:   "/data/1",
		ResultDir: "/result/1",
		Phase:     1,
	}
	if err := store.Reserve(rec.RequestID, rec.TaskID); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}
	if err := store.Commit(rec); err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	// 验证 .bak 文件已自动生成
	if _, err := os.Stat(bakPath); err != nil {
		t.Fatalf("expected .bak file to exist: %v", err)
	}

	mainBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read main file failed: %v", err)
	}
	bakBytes, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("read bak file failed: %v", err)
	}

	if string(mainBytes) != string(bakBytes) {
		t.Fatalf("main file and bak file contents mismatch")
	}
}

func TestImportIndex_CorruptionRecoveryFromBak(t *testing.T) {
	tempDir := t.TempDir()
	indexPath := filepath.Join(tempDir, "import-index.json")
	bakPath := indexPath + ".bak"

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("load store failed: %v", err)
	}

	rec := ImportIndexRecord{
		RequestID: "req-recover",
		TaskID:    "task-recover",
		Hash:      "hash-recover",
		Phase:     3,
	}
	if err := store.Reserve(rec.RequestID, rec.TaskID); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}
	if err := store.Commit(rec); err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	// 确认 .bak 文件存在
	if _, err := os.Stat(bakPath); err != nil {
		t.Fatalf("expected bak file %s to exist: %v", bakPath, err)
	}

	// 人为损坏主文件
	if err := os.WriteFile(indexPath, []byte("{ corrupted json syntax !!!"), 0o644); err != nil {
		t.Fatalf("corrupt main file failed: %v", err)
	}

	// 验证从 .bak 恢复成功
	recoveredStore, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("load store with corrupted main file failed: %v", err)
	}

	found, ok := recoveredStore.LookupByRequestID("req-recover")
	if !ok {
		t.Fatalf("failed to recover record from .bak")
	}
	if found.Phase != 3 {
		t.Fatalf("expected phase 3, got %d", found.Phase)
	}

	// 验证主文件已被自动修复为合法 JSON
	mainBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read repaired main file failed: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(mainBytes, &probe); err != nil {
		t.Fatalf("repaired main file is not valid JSON: %v", err)
	}
}

func TestImportIndex_CorruptionNoBakArchive(t *testing.T) {
	tempDir := t.TempDir()
	indexPath := filepath.Join(tempDir, "import-index.json")

	// 仅写入损坏的主文件，无任何 .bak
	if err := os.WriteFile(indexPath, []byte("NOT_JSON_DATA_AT_ALL"), 0o644); err != nil {
		t.Fatalf("write corrupted file failed: %v", err)
	}

	// 加载时应自动归档损坏文件并初始化干净索引
	cleanStore, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("expected clean init without error, got: %v", err)
	}

	if _, ok := cleanStore.Latest(); ok {
		t.Fatalf("expected empty store")
	}

	// 验证损坏文件被重命名为 <path>.corrupted.<timestamp>
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("read dir failed: %v", err)
	}
	foundCorrupted := false
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".corrupted.") {
			foundCorrupted = true
			break
		}
	}
	if !foundCorrupted {
		t.Fatalf("expected corrupted archive file in %s, found: %v", tempDir, entries)
	}

	// 验证干净索引可继续正常写入
	rec := ImportIndexRecord{
		RequestID: "req-after-corrupt",
		TaskID:    "task-after-corrupt",
		Hash:      "hash-new",
		Phase:     1,
	}
	if err := cleanStore.Reserve(rec.RequestID, rec.TaskID); err != nil {
		t.Fatalf("reserve on clean store failed: %v", err)
	}
	if err := cleanStore.Commit(rec); err != nil {
		t.Fatalf("commit on clean store failed: %v", err)
	}
}

func TestImportIndex_Purge(t *testing.T) {
	tempDir := t.TempDir()
	indexPath := filepath.Join(tempDir, "import-index.json")
	resultsRoot := filepath.Join(tempDir, "results")
	if err := os.MkdirAll(resultsRoot, 0o755); err != nil {
		t.Fatalf("create results root failed: %v", err)
	}

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("load store failed: %v", err)
	}

	// 创建两个任务的真实 ResultDir
	resultDir1 := filepath.Join(resultsRoot, "req-1-task-1")
	if err := os.MkdirAll(resultDir1, 0o755); err != nil {
		t.Fatalf("create resultDir1 failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultDir1, "report.json"), []byte(`{"status":"ok1"}`), 0o644); err != nil {
		t.Fatalf("write report1 failed: %v", err)
	}

	resultDir2 := filepath.Join(resultsRoot, "req-2-task-2")
	if err := os.MkdirAll(resultDir2, 0o755); err != nil {
		t.Fatalf("create resultDir2 failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultDir2, "report.json"), []byte(`{"status":"ok2"}`), 0o644); err != nil {
		t.Fatalf("write report2 failed: %v", err)
	}

	rec1 := ImportIndexRecord{
		RequestID: "req-1",
		TaskID:    "task-1",
		Hash:      "hash-1",
		ResultDir: resultDir1,
		Phase:     1,
	}
	rec2 := ImportIndexRecord{
		RequestID: "req-2",
		TaskID:    "task-2",
		Hash:      "hash-2",
		ResultDir: resultDir2,
		Phase:     2,
	}

	_ = store.Reserve(rec1.RequestID, rec1.TaskID)
	_ = store.Commit(rec1)
	_ = store.Reserve(rec2.RequestID, rec2.TaskID)
	_ = store.Commit(rec2)

	// latest 应当是 rec2
	latest, ok := store.Latest()
	if !ok || latest.TaskID != "task-2" {
		t.Fatalf("expected latest to be task-2, got %+v", latest)
	}

	// 1. 执行 Purge rec2 (即当前 latest)
	if err := store.Purge("req-2", "task-2"); err != nil {
		t.Fatalf("purge failed: %v", err)
	}

	// 验证 records, byRequestID, byTaskID 已被清理
	if _, ok := store.LookupByRequestID("req-2"); ok {
		t.Fatalf("expected req-2 to be purged")
	}
	if _, ok := store.LookupByTaskID("task-2"); ok {
		t.Fatalf("expected task-2 to be purged")
	}

	// 验证 latestRecord 回退到 rec1
	newLatest, ok := store.Latest()
	if !ok || newLatest.TaskID != "task-1" {
		t.Fatalf("expected latest to roll back to task-1, got %+v", newLatest)
	}

	// 验证 resultDir2 被重命名为 .failed-task-2-<timestamp> 归档
	if _, err := os.Stat(resultDir2); !os.IsNotExist(err) {
		t.Fatalf("expected original resultDir2 to no longer exist: %s", resultDir2)
	}
	entries, err := os.ReadDir(resultsRoot)
	if err != nil {
		t.Fatalf("read results root failed: %v", err)
	}
	foundArchive := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".failed-task-2-") {
			foundArchive = true
			// 检查归档内文件是否完整
			archivedReport := filepath.Join(resultsRoot, entry.Name(), "report.json")
			content, err := os.ReadFile(archivedReport)
			if err != nil || !strings.Contains(string(content), "ok2") {
				t.Fatalf("archived report content missing or corrupted: %v", err)
			}
			break
		}
	}
	if !foundArchive {
		t.Fatalf("expected .failed-task-2-<timestamp> directory in %s, entries: %v", resultsRoot, entries)
	}

	// 2. 验证落盘持久化：重新加载 store，验证 rec2 已不在磁盘中
	reloadedStore, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("reload store after purge failed: %v", err)
	}
	if _, ok := reloadedStore.LookupByRequestID("req-2"); ok {
		t.Fatalf("purged record still present on disk")
	}
	latestOnDisk, ok := reloadedStore.Latest()
	if !ok || latestOnDisk.TaskID != "task-1" {
		t.Fatalf("disk latest record expected task-1, got %+v", latestOnDisk)
	}

	// 3. Purge rec1，验证 latestRecord 回退为 nil
	if err := store.Purge("req-1", "task-1"); err != nil {
		t.Fatalf("purge rec1 failed: %v", err)
	}
	if _, ok := store.Latest(); ok {
		t.Fatalf("expected latest to be nil when all records are purged")
	}

	// 4. 验证对不存在的记录 Purge 幂等不报错
	if err := store.Purge("non-existent-req", "non-existent-task"); err != nil {
		t.Fatalf("expected idempotent purge to succeed, got: %v", err)
	}
}
