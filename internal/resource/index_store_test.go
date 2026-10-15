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

func TestImportIndexStoreSetResultCheck(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "import-index.json")

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("LoadImportIndexStore failed: %v", err)
	}

	if err := store.Reserve("req-rc", "task-rc"); err != nil {
		t.Fatalf("Reserve failed: %v", err)
	}
	if err := store.Commit(ImportIndexRecord{
		RequestID: "req-rc",
		TaskID:    "task-rc",
		Hash:      "hash-rc",
		DataDir:   filepath.Join(tmpDir, "data"),
		ResultDir: filepath.Join(tmpDir, "result"),
		Phase:     3,
	}); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	verdict := &ResultCheckVerdict{
		Passed:    false,
		Details:   []string{"[plaintext] leak.csv"},
		CheckedAt: "2026-10-15T00:00:00Z",
	}
	if err := store.SetResultCheck("req-rc", "task-rc", verdict); err != nil {
		t.Fatalf("SetResultCheck failed: %v", err)
	}

	// Every holder has to see it: the requestId map, the taskId map and the
	// latest-record pointer are three separate copies of the same record.
	byReq, ok := store.LookupByRequestID("req-rc")
	if !ok || byReq.ResultCheck == nil || byReq.ResultCheck.Passed || len(byReq.ResultCheck.Details) != 1 {
		t.Fatalf("LookupByRequestID missing verdict: ok=%v, rec=%+v", ok, byReq)
	}
	byTask, ok := store.LookupByTaskID("task-rc")
	if !ok || byTask.ResultCheck == nil || byTask.ResultCheck.CheckedAt != "2026-10-15T00:00:00Z" {
		t.Fatalf("LookupByTaskID missing verdict: ok=%v, rec=%+v", ok, byTask)
	}
	latest, ok := store.Latest()
	if !ok || latest.ResultCheck == nil || latest.ResultCheck.Passed {
		t.Fatalf("Latest missing verdict: ok=%v, latest=%+v", ok, latest)
	}

	// Persistence: the verdict must survive a reload from disk.
	reloaded, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("reload LoadImportIndexStore failed: %v", err)
	}
	if rec, ok := reloaded.LookupByTaskID("task-rc"); !ok || rec.ResultCheck == nil || rec.ResultCheck.CheckedAt != "2026-10-15T00:00:00Z" {
		t.Fatalf("verdict did not survive reload: ok=%v, rec=%+v", ok, rec)
	}
	rec, err := reloaded.Lookup("req-rc", "task-rc")
	if err != nil {
		t.Fatalf("reloaded Lookup failed: %v", err)
	}
	if rec.ResultCheck == nil || rec.ResultCheck.Passed != false || rec.ResultCheck.CheckedAt != "2026-10-15T00:00:00Z" {
		t.Fatalf("reloaded verdict mismatch: %+v", rec.ResultCheck)
	}
	if reloadedLatest, ok := reloaded.Latest(); !ok || reloadedLatest.ResultCheck == nil {
		t.Fatalf("reloaded Latest missing verdict: ok=%v, latest=%+v", ok, reloadedLatest)
	}

	// A nil verdict clears it again (record stays, verdict goes).
	if err := store.SetResultCheck("req-rc", "", nil); err != nil {
		t.Fatalf("SetResultCheck(nil) failed: %v", err)
	}
	if rec, _ := store.Lookup("req-rc", "task-rc"); rec.ResultCheck != nil {
		t.Fatalf("nil verdict did not clear the field: %+v", rec.ResultCheck)
	}
}

func TestImportIndexStoreSetResultCheckErrors(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "import-index.json")

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("LoadImportIndexStore failed: %v", err)
	}

	if err := store.SetResultCheck("", "", &ResultCheckVerdict{}); err == nil {
		t.Fatal("expected error on empty requestId and taskId")
	}
	if err := store.SetResultCheck("missing", "", &ResultCheckVerdict{}); err == nil {
		t.Fatal("expected error on unknown record")
	}

	// requestId and taskId resolving to different records must be rejected, same
	// rule as Lookup.
	if err := store.Reserve("req-a", "task-a"); err != nil {
		t.Fatalf("Reserve req-a failed: %v", err)
	}
	if err := store.Commit(ImportIndexRecord{RequestID: "req-a", TaskID: "task-a", Hash: "hash-a", ResultDir: filepath.Join(tmpDir, "ra")}); err != nil {
		t.Fatalf("Commit req-a failed: %v", err)
	}
	if err := store.Reserve("req-b", "task-b"); err != nil {
		t.Fatalf("Reserve req-b failed: %v", err)
	}
	if err := store.Commit(ImportIndexRecord{RequestID: "req-b", TaskID: "task-b", Hash: "hash-b", ResultDir: filepath.Join(tmpDir, "rb")}); err != nil {
		t.Fatalf("Commit req-b failed: %v", err)
	}
	if err := store.SetResultCheck("req-a", "task-b", &ResultCheckVerdict{}); err == nil {
		t.Fatal("expected conflict error when requestId and taskId hit different records")
	}
	if rec, _ := store.LookupByRequestID("req-a"); rec.ResultCheck != nil {
		t.Fatalf("conflicting SetResultCheck mutated the record: %+v", rec.ResultCheck)
	}
}

func TestImportIndexStoreSetResultCheckRollback(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "import-index.json")

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("LoadImportIndexStore failed: %v", err)
	}
	if err := store.Reserve("req-rb2", "task-rb2"); err != nil {
		t.Fatalf("Reserve failed: %v", err)
	}
	if err := store.Commit(ImportIndexRecord{RequestID: "req-rb2", TaskID: "task-rb2", Hash: "hash-rb2", ResultDir: filepath.Join(tmpDir, "res")}); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Make the atomic replace impossible: the index path becomes a directory, so
	// the temp file cannot be renamed onto it.
	if err := os.Remove(indexPath); err != nil {
		t.Fatalf("remove index file: %v", err)
	}
	if err := os.Mkdir(indexPath, 0o755); err != nil {
		t.Fatalf("mkdir over index path: %v", err)
	}

	if err := store.SetResultCheck("req-rb2", "task-rb2", &ResultCheckVerdict{Passed: false}); err == nil {
		t.Fatal("expected SetResultCheck to fail when persistence fails")
	}

	if rec, _ := store.Lookup("req-rb2", "task-rb2"); rec.ResultCheck != nil {
		t.Fatalf("verdict survived a failed save: %+v", rec.ResultCheck)
	}
	if latest, _ := store.Latest(); latest.ResultCheck != nil {
		t.Fatalf("latestRecord was mutated despite failed save: %+v", latest.ResultCheck)
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
