package taa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"taa/internal/controller"
)

// snapshotTreeHashes 记录 dir 下每个文件的相对路径、大小与内容摘要（sha256），
// 用于断言恢复后模型包逐字节原样保留（路径 + 大小 + 内容哈希）。目录本身不记录：
// 目录不携带自身内容，能区分快照的是文件条目，记录目录不会带来额外信息。
func snapshotTreeHashes(t *testing.T, dir string) map[string]string {
	t.Helper()
	snap := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		snap[rel] = fmt.Sprintf("%d:%s", len(data), hex.EncodeToString(sum[:]))
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return snap
}

// setupTestRecoveryState 构造用于自愈测试的独立环境与状态实例
func setupTestRecoveryState(t *testing.T) (*controller.TAAState, *controller.StateStore, string) {
	t.Helper()
	tempDir := t.TempDir()

	keysDir := filepath.Join(tempDir, "keys")
	modelDir := filepath.Join(tempDir, "model")
	dataDir := filepath.Join(tempDir, "data")
	resultDir := filepath.Join(tempDir, "results")
	inputDir := filepath.Join(tempDir, "input")
	outputDir := filepath.Join(tempDir, "output")

	for _, d := range []string{keysDir, modelDir, dataDir, resultDir, inputDir, outputDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s failed: %v", d, err)
		}
	}

	keyPair, err := generateTAAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	sealingKey := controller.DeriveSealingKey(keyPair.PrivateKey)
	statePath := filepath.Join(keysDir, "state.sealed")
	store, err := controller.NewStateStore(statePath, sealingKey, controller.KeySourceSM2)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}

	sec := controller.SecurityConfig{
		ModelDir:       modelDir,
		DataDir:        dataDir,
		ResultDir:      resultDir,
		ModelInputDir:  inputDir,
		ModelOutputDir: outputDir,
	}

	userData, err := deriveUserData(&keyPair.PrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("derive user data: %v", err)
	}

	state := controller.NewTAAState(
		filepath.Join(tempDir, "attestation.report"),
		"127.0.0.1:65535",
		"docker-test-01",
		"",
		"",
		keyPair.PrivateKey,
		userData,
		sec,
	)
	state.SetStateStore(store)

	return state, store, tempDir
}

// TestRecovery_CircuitBreaker 校验自愈熔断保护机制（规约 3）：
// 连续自愈失败达 3 次（RecoveryAttempts >= 3）时，触发熔断：
// 转入死信隔离 .dead-letter-<taskId>.json，清除 ActiveTask，复位 CurrentOp = idle 并正常退出。
// 自愈未达 3 次时，RecoveryAttempts 计数递增并落盘。
func TestRecovery_CircuitBreaker(t *testing.T) {
	state, store, tempDir := setupTestRecoveryState(t)
	taskResultDir := filepath.Join(tempDir, "results", "task-cb-001")
	_ = os.MkdirAll(taskResultDir, 0o755)

	// 1. 验证未达阈值（attempts = 1）：执行后 attempts 递增为 2 并持久化
	initialTask := &controller.ActiveTaskSnapshot{
		RequestID:        "req-cb-01",
		TaskID:           "task-cb-001",
		Type:             "training",
		Phase:            1,
		Status:           "RUNNING",
		ResultDir:        taskResultDir,
		StartedAt:        time.Now().UTC().Add(-2 * time.Minute),
		RecoveryAttempts: 1,
	}

	pState := &controller.PersistentState{
		Version:       controller.DefaultStateVersion,
		StateSeq:      1,
		CurrentPhase:  1,
		ActiveTask:    initialTask,
		IncarnationID: "test-epoch-1",
		UpdatedAt:     time.Now().UTC(),
	}
	if err := store.SealState(pState); err != nil {
		t.Fatalf("seal initial state: %v", err)
	}
	state.RestoreFromPersistentState(pState)

	ctx := context.Background()
	if err := reconcileCrashRecovery(ctx, state, store, initialTask); err != nil {
		t.Fatalf("reconcileCrashRecovery failed: %v", err)
	}

	// 验证 attempts 递增并落盘
	if initialTask.RecoveryAttempts != 2 {
		t.Fatalf("expected RecoveryAttempts=2, got %d", initialTask.RecoveryAttempts)
	}

	// 2. 验证达到阈值（attempts = 3）：触发死信归档与熔断
	circuitTask := &controller.ActiveTaskSnapshot{
		RequestID:        "req-cb-02",
		TaskID:           "task-cb-002",
		Type:             "training",
		Phase:            1,
		Status:           "RUNNING",
		ResultDir:        taskResultDir,
		StartedAt:        time.Now().UTC().Add(-5 * time.Minute),
		RecoveryAttempts: 3,
	}
	pState.ActiveTask = circuitTask
	if err := store.SealState(pState); err != nil {
		t.Fatalf("seal circuit state: %v", err)
	}
	state.RestoreFromPersistentState(pState)

	if err := reconcileCrashRecovery(ctx, state, store, circuitTask); err != nil {
		t.Fatalf("reconcileCrashRecovery circuit breaker failed: %v", err)
	}

	// 验证死信文件存在
	deadLetterPath := filepath.Join(taskResultDir, ".dead-letter-task-cb-002.json")
	content, err := os.ReadFile(deadLetterPath)
	if err != nil {
		t.Fatalf("expected dead-letter file at %s: %v", deadLetterPath, err)
	}
	var deadLetterRecord map[string]any
	if err := json.Unmarshal(content, &deadLetterRecord); err != nil {
		t.Fatalf("unmarshal dead-letter json: %v", err)
	}
	if deadLetterRecord["reason"] == "" {
		t.Fatalf("expected reason in dead-letter record, got %+v", deadLetterRecord)
	}

	// 验证持久化存储中 ActiveTask 已被清空
	persisted := store.GetState()
	if persisted.ActiveTask != nil {
		t.Fatalf("expected persisted.ActiveTask to be nil, got %+v", persisted.ActiveTask)
	}

	// 验证内存状态已复位为 idle
	if state.GetActiveTask() != nil {
		t.Fatalf("expected activeTask to be nil in state")
	}
}

// TestRecovery_ModelImportQuarantine 校验未审计模型代码安全隔离机制（规约 1）：
// 若崩溃任务属于 model_import，仅复位 ModelImported = false；隔离只在状态层面发生，
// modelDir 中的模型代码与依赖库保持上传原样，不得被删除或改动。
func TestRecovery_ModelImportQuarantine(t *testing.T) {
	state, store, _ := setupTestRecoveryState(t)

	// 在 modelDir 中放入未审计的高危残留代码
	unAuditedFile := filepath.Join(state.Security.ModelDir, "backdoor.py")
	if err := os.WriteFile(unAuditedFile, []byte("import os; os.system('malicious')"), 0o644); err != nil {
		t.Fatalf("write un-audited file: %v", err)
	}
	nestedDir := filepath.Join(state.Security.ModelDir, "subpkg")
	_ = os.MkdirAll(nestedDir, 0o755)
	_ = os.WriteFile(filepath.Join(nestedDir, "leak.sh"), []byte("#!/bin/sh\n"), 0o755)

	// 恢复前对 modelDir 做逐字节快照
	before := snapshotTreeHashes(t, state.Security.ModelDir)

	// 模拟之前已被置位为 ModelImported
	state.SaveModelSuccess("https://test.s3.com/model.tar.gz")

	task := &controller.ActiveTaskSnapshot{
		RequestID:        "req-model-crash-01",
		TaskID:           "task-model-crash-01",
		Type:             "model_import",
		Phase:            1,
		Status:           "RUNNING",
		ResultDir:        filepath.Join(state.Security.ResultDir, "task-model-crash-01"),
		StartedAt:        time.Now().UTC(),
		RecoveryAttempts: 0,
	}

	pState := &controller.PersistentState{
		Version:       controller.DefaultStateVersion,
		StateSeq:      1,
		ModelImported: true,
		ActiveTask:    task,
		IncarnationID: "test-epoch-model",
		UpdatedAt:     time.Now().UTC(),
	}
	if err := store.SealState(pState); err != nil {
		t.Fatalf("seal state: %v", err)
	}
	state.RestoreFromPersistentState(pState)

	ctx := context.Background()
	if err := reconcileCrashRecovery(ctx, state, store, task); err != nil {
		t.Fatalf("reconcileCrashRecovery model_import failed: %v", err)
	}

	// 隔离是状态层面的：modelDir 必须逐字节原样保留，不得被删除或改动
	after := snapshotTreeHashes(t, state.Security.ModelDir)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("quarantine changed the model package on disk: before=%v after=%v", before, after)
	}
	if _, err := os.Stat(unAuditedFile); err != nil {
		t.Fatalf("recovery deleted the un-audited model code it must leave untouched: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nestedDir, "leak.sh")); err != nil {
		t.Fatalf("recovery deleted a nested package file it must leave untouched: %v", err)
	}

	// 验证 ModelImported 已被强制重置为 false
	persisted := store.GetState()
	if persisted.ModelImported {
		t.Fatalf("expected persisted.ModelImported=false after model_import recovery")
	}
}

// TestRecovery_TempCleanAndOrphanReclamation 校验脏环境清理与孤儿进程回收机制（规约 6 与规约 9）：
// 清空 inputDir/outputDir，清除 /tmp 临时下载碎片，并安全探测杀灭残留孤儿训练子进程。
func TestRecovery_TempCleanAndOrphanReclamation(t *testing.T) {
	state, store, _ := setupTestRecoveryState(t)

	// 1. 制造 input 和 output 脏文件
	dirtyInput := filepath.Join(state.Security.GetModelInputDir(), "dirty-input.dat")
	dirtyOutput := filepath.Join(state.Security.GetModelOutputDir(), "dirty-output.dat")
	_ = os.WriteFile(dirtyInput, []byte("dirty-data"), 0o644)
	_ = os.WriteFile(dirtyOutput, []byte("dirty-output"), 0o644)

	// 2. 制造 /tmp 碎片文件
	fragment1 := fmt.Sprintf("/tmp/taa-download-test-%d.tmp", time.Now().UnixNano())
	fragment2 := fmt.Sprintf("/tmp/test.extract-%d.part", time.Now().UnixNano())
	_ = os.WriteFile(fragment1, []byte("fragment1"), 0o644)
	_ = os.WriteFile(fragment2, []byte("fragment2"), 0o644)

	// 3. 拉起一个伪装的训练子进程
	cmd := exec.Command("sh", "-c", "sleep 30")
	if err := cmd.Start(); err == nil {
		defer func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}()
	}

	task := &controller.ActiveTaskSnapshot{
		RequestID:        "req-clean-01",
		TaskID:           "task-clean-01",
		Type:             "training",
		Phase:            1,
		Status:           "RUNNING",
		ResultDir:        filepath.Join(state.Security.ResultDir, "task-clean-01"),
		StartedAt:        time.Now().UTC(),
		RecoveryAttempts: 0,
	}

	ctx := context.Background()
	if err := reconcileCrashRecovery(ctx, state, store, task); err != nil {
		t.Fatalf("reconcileCrashRecovery cleanup failed: %v", err)
	}

	// 验证 input 与 output 目录已被清空
	inputEntries, err := os.ReadDir(state.Security.GetModelInputDir())
	if err != nil || len(inputEntries) != 0 {
		t.Fatalf("expected inputDir empty, got %d entries", len(inputEntries))
	}
	outputEntries, err := os.ReadDir(state.Security.GetModelOutputDir())
	if err != nil || len(outputEntries) != 0 {
		t.Fatalf("expected outputDir empty, got %d entries", len(outputEntries))
	}

	// 验证 /tmp 碎片已被清除
	if _, err := os.Stat(fragment1); !os.IsNotExist(err) {
		t.Fatalf("expected fragment1 removed: %s", fragment1)
	}
	if _, err := os.Stat(fragment2); !os.IsNotExist(err) {
		t.Fatalf("expected fragment2 removed: %s", fragment2)
	}
}

// TestRecovery_ImportIndexPurgeAndBlackboxArchival 校验索引清洗与黑匣子归档（规约 4）：
// 通过 ImportIndexStore.Purge 清洗中断任务条目，并将产物目录重命名为 .failed-<taskId>-<timestamp> 归档。
func TestRecovery_ImportIndexPurgeAndBlackboxArchival(t *testing.T) {
	state, store, tempDir := setupTestRecoveryState(t)

	indexStore, err := state.ImportIndexStore()
	if err != nil {
		t.Fatalf("load import index store: %v", err)
	}

	reqID := "req-purge-01"
	taskID := "task-purge-01"
	taskResultDir := filepath.Join(tempDir, "results", taskID)
	_ = os.MkdirAll(taskResultDir, 0o755)
	outputFile := filepath.Join(taskResultDir, "model.bin")
	_ = os.WriteFile(outputFile, []byte("partial output before crash"), 0o644)

	record := controller.ImportIndexRecord{
		RequestID: reqID,
		TaskID:    taskID,
		Hash:      "hash-123",
		DataDir:   filepath.Join(tempDir, "data", "hash-123"),
		ResultDir: taskResultDir,
		Phase:     1,
	}
	_ = indexStore.Reserve(reqID, taskID)
	if err := indexStore.Commit(record); err != nil {
		t.Fatalf("commit record to index: %v", err)
	}

	// 确认在 Purge 前可查到该记录
	if _, found := indexStore.LookupByTaskID(taskID); !found {
		t.Fatalf("record should exist before purge")
	}

	task := &controller.ActiveTaskSnapshot{
		RequestID:        reqID,
		TaskID:           taskID,
		Type:             "training",
		Phase:            1,
		Status:           "RUNNING",
		ResultDir:        taskResultDir,
		StartedAt:        time.Now().UTC(),
		RecoveryAttempts: 0,
	}

	ctx := context.Background()
	if err := reconcileCrashRecovery(ctx, state, store, task); err != nil {
		t.Fatalf("reconcileCrashRecovery purge failed: %v", err)
	}

	// 验证索引已被 Purge
	if _, found := indexStore.LookupByTaskID(taskID); found {
		t.Fatalf("record should be purged from index store")
	}

	// 验证原产物目录已被重命名为黑匣子 .failed-<taskId>-* 归档目录
	if _, err := os.Stat(taskResultDir); !os.IsNotExist(err) {
		t.Fatalf("expected original resultDir %s to be renamed", taskResultDir)
	}

	parentDir := filepath.Dir(taskResultDir)
	matches, err := filepath.Glob(filepath.Join(parentDir, fmt.Sprintf(".failed-%s-*", taskID)))
	if err != nil || len(matches) == 0 {
		t.Fatalf("expected blackbox archive matching .failed-%s-*, got matches=%v", taskID, matches)
	}

	blackboxDir := matches[0]
	// 验证黑匣子目录中包含原有中断产物
	if _, err := os.Stat(filepath.Join(blackboxDir, "model.bin")); err != nil {
		t.Fatalf("expected model.bin in blackbox dir: %v", err)
	}
}

// TestRecovery_StandardSchemaReport 校验崩溃占位报告生成机制（规约 5）：
// 生成符合 Schema 1.0 的 training_report.json，包含标准 training_task (exit_code=137, status="failed") 与 dataset.checksum。
func TestRecovery_StandardSchemaReport(t *testing.T) {
	state, store, tempDir := setupTestRecoveryState(t)

	taskResultDir := filepath.Join(tempDir, "results", "task-schema-001")
	_ = os.MkdirAll(taskResultDir, 0o755)

	task := &controller.ActiveTaskSnapshot{
		RequestID:        "req-schema-001",
		TaskID:           "task-schema-001",
		Type:             "training",
		Phase:            1,
		Status:           "RUNNING",
		ResultDir:        taskResultDir,
		StartedAt:        time.Now().UTC().Add(-10 * time.Second),
		RecoveryAttempts: 0,
	}

	ctx := context.Background()
	if err := reconcileCrashRecovery(ctx, state, store, task); err != nil {
		t.Fatalf("reconcileCrashRecovery schema report failed: %v", err)
	}

	// 定位生成的 training_report.json（可能在归档的 .failed 目录或 resultDir 下）
	matches, _ := filepath.Glob(filepath.Join(tempDir, "results", fmt.Sprintf(".failed-%s-*", task.TaskID)))
	reportPath := filepath.Join(taskResultDir, "training_report.json")
	if len(matches) > 0 {
		reportPath = filepath.Join(matches[0], "training_report.json")
	}

	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read training_report.json failed at %s: %v", reportPath, err)
	}

	var report map[string]any
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		t.Fatalf("unmarshal training_report.json: %v", err)
	}

	if report["schema_version"] != "1.0" {
		t.Fatalf("expected schema_version=1.0, got %v", report["schema_version"])
	}

	trainingTask, ok := report["training_task"].(map[string]any)
	if !ok {
		t.Fatalf("training_task is not object: %+v", report["training_task"])
	}
	if trainingTask["status"] != "failed" {
		t.Fatalf("expected status=failed, got %v", trainingTask["status"])
	}
	if trainingTask["exit_code"] != float64(137) {
		t.Fatalf("expected exit_code=137, got %v", trainingTask["exit_code"])
	}
	if trainingTask["task_id"] != "task-schema-001" {
		t.Fatalf("expected task_id=task-schema-001, got %v", trainingTask["task_id"])
	}

	dataset, ok := report["dataset"].(map[string]any)
	if !ok {
		t.Fatalf("dataset is not object: %+v", report["dataset"])
	}
	checksum, ok := dataset["checksum"].(map[string]any)
	if !ok || checksum["algorithm"] == "" {
		t.Fatalf("expected dataset.checksum, got %+v", dataset)
	}
}

// TestRecovery_DualTrackDrain 校验双轨补偿投递（规约 7）：
// 1. 极速探测成功：平台在线时，2秒硬超时内同步成功完成上报；
// 2. 平台离线转后台重试：平台离线或超时后，自愈流水线不阻塞，启动流程瞬间完成，后台 Detached Worker 继续重试。
func TestRecovery_DualTrackDrain(t *testing.T) {
	// ── 场景 1: 前置同步极速通道成功 ──
	t.Run("FastSyncSuccess", func(t *testing.T) {
		state, store, tempDir := setupTestRecoveryState(t)

		reported := make(chan struct{}, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/taa/reportRes" {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body["taskId"] == "task-fast-001" && body["code"] == float64(1) {
					select {
					case reported <- struct{}{}:
					default:
					}
				}
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		state.PlatformIP = server.Listener.Addr().String()
		state.DockerID = "docker-fast-001"

		task := &controller.ActiveTaskSnapshot{
			RequestID:        "req-fast-001",
			TaskID:           "task-fast-001",
			Type:             "training",
			Phase:            1,
			Status:           "RUNNING",
			ResultDir:        filepath.Join(tempDir, "results", "task-fast-001"),
			StartedAt:        time.Now().UTC(),
			RecoveryAttempts: 0,
		}

		start := time.Now()
		if err := reconcileCrashRecovery(context.Background(), state, store, task); err != nil {
			t.Fatalf("reconcileCrashRecovery failed: %v", err)
		}
		duration := time.Since(start)

		if duration > 2*time.Second {
			t.Fatalf("fast-sync took too long: %v", duration)
		}

		select {
		case <-reported:
		case <-time.After(1 * time.Second):
			t.Fatalf("expected fast-sync report received by platform server")
		}

		// 验证任务已完全解封复位
		persisted := store.GetState()
		if persisted.ActiveTask != nil {
			t.Fatalf("expected ActiveTask to be nil in store")
		}
		if state.CurrentOp != "idle" {
			t.Fatalf("expected state.CurrentOp=idle, got %s", state.CurrentOp)
		}
	})

	// ── 场景 2: 平台离线转后台重试，不阻塞启动 ──
	t.Run("DetachedAsyncNonBlocking", func(t *testing.T) {
		state, store, tempDir := setupTestRecoveryState(t)

		// 指向一个不可达或超时的地址
		state.PlatformIP = "127.0.0.1:65534"
		state.DockerID = "docker-detached-001"

		task := &controller.ActiveTaskSnapshot{
			RequestID:        "req-async-001",
			TaskID:           "task-async-001",
			Type:             "training",
			Phase:            1,
			Status:           "RUNNING",
			ResultDir:        filepath.Join(tempDir, "results", "task-async-001"),
			StartedAt:        time.Now().UTC(),
			RecoveryAttempts: 0,
		}

		start := time.Now()
		// reconcileCrashRecovery 在前置同步 2 秒硬超时后，应立即转后台并返回，绝对不等待 60 秒
		if err := reconcileCrashRecovery(context.Background(), state, store, task); err != nil {
			t.Fatalf("reconcileCrashRecovery failed: %v", err)
		}
		duration := time.Since(start)

		if duration > 3*time.Second {
			t.Fatalf("recovery took %v, should not block longer than fast-sync timeout (2s)", duration)
		}

		// 验证即使上报未成功，任务快照依然被安全解封，允许服务开放探针
		persisted := store.GetState()
		if persisted.ActiveTask != nil {
			t.Fatalf("expected ActiveTask cleared even when platform offline")
		}
		if state.CurrentOp != "idle" {
			t.Fatalf("expected state.CurrentOp=idle, got %s", state.CurrentOp)
		}
	})
}

// TestRecovery_AbandonedAuditReportsOnly covers the crash that
// reconcileCrashRecovery cannot see.
//
// An audit runs in a goroutine that outlives the import task, so a crash
// mid-audit leaves ActiveTask nil while ModelImported stays true and the model's
// code sits on disk without a verdict. Nothing else the daemon persists records
// that an audit was owed — AuditPending is that record, and this is the startup
// path that consumes it.
//
// All the recovery does is report. The verdict is advisory, so an interrupted
// audit says nothing about the import: the model stays imported with its resource
// URL intact, and the package is left exactly as it was uploaded, byte for byte.
// The marker is dropped after reporting so the next restart does not send the
// same report again.
//
// It is the activeTask==nil half of TestRecovery_ModelImportQuarantine.
func TestRecovery_AbandonedAuditReportsOnly(t *testing.T) {
	state, store, _ := setupTestRecoveryState(t)

	unAudited := filepath.Join(state.Security.ModelDir, "backdoor.py")
	if err := os.WriteFile(unAudited, []byte("import os; os.system('malicious')"), 0o644); err != nil {
		t.Fatalf("write un-adjudicated model file: %v", err)
	}

	// 恢复前对 modelDir 做逐字节快照
	before := snapshotTreeHashes(t, state.Security.ModelDir)

	reports := make(chan map[string]any, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/taa/reportAudit" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			reports <- body
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	state.PlatformIP = server.Listener.Addr().String()
	state.DockerID = "docker-audit-crash-01"

	pState := &controller.PersistentState{
		Version:               controller.DefaultStateVersion,
		StateSeq:              1,
		ModelImported:         true,
		SavedModelResourceURL: "https://test.s3.com/model.tar.gz",
		AuditPending: &controller.AuditPendingSnapshot{
			RequestID: "req-audit-crash-01",
			TaskID:    "task-audit-crash-01",
			Phase:     1,
			StartedAt: time.Now().UTC(),
		},
		IncarnationID: "test-epoch-audit",
		UpdatedAt:     time.Now().UTC(),
	}
	if err := store.SealState(pState); err != nil {
		t.Fatalf("seal state: %v", err)
	}
	state.RestoreFromPersistentState(pState)

	// Precondition: the fixture must not route through reconcileCrashRecovery.
	if state.GetActiveTask() != nil {
		t.Fatalf("fixture is wrong: an active task would take the other recovery path")
	}
	pending := state.PendingAudit()
	if pending == nil {
		t.Fatalf("restoring the sealed state lost the pending audit marker")
	}

	if err := reconcileAbandonedAudit(context.Background(), state, pending); err != nil {
		t.Fatalf("reconcileAbandonedAudit failed: %v", err)
	}

	// The recovery only reports: the audit never deletes or modifies the package
	// it was reading, so the un-adjudicated code has to be left byte-identical.
	after := snapshotTreeHashes(t, state.Security.ModelDir)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("the abandoned-audit recovery changed the package on disk: before=%v after=%v", before, after)
	}
	if _, err := os.Stat(unAudited); err != nil {
		t.Errorf("the abandoned-audit recovery deleted the model code it must leave untouched: %v", err)
	}

	persisted, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if !persisted.ModelImported {
		t.Error("the model came back as not imported; an interrupted audit must not roll back the import")
	}
	if persisted.SavedModelResourceURL != "https://test.s3.com/model.tar.gz" {
		t.Errorf("the resource URL of the model was cleared: %q", persisted.SavedModelResourceURL)
	}
	if persisted.AuditPending != nil {
		t.Errorf("the pending marker survived reconciliation, so every restart would report the same interruption again: %+v",
			persisted.AuditPending)
	}

	var first map[string]any
	select {
	case first = <-reports:
	case <-time.After(2 * time.Second):
		t.Fatal("no audit report reached the platform for the abandoned audit")
	}
	if first["code"] != float64(2) {
		t.Errorf("audit report code = %v, want 2", first["code"])
	}
	if first["taskId"] != "task-audit-crash-01" {
		t.Errorf("the report did not carry the persisted audit task id: %v", first["taskId"])
	}
	select {
	case extra := <-reports:
		t.Errorf("more than one audit report was sent: %+v", extra)
	default:
	}
}

// TestRecovery_NoPendingAudit_LeavesModelUntouched guards the other direction:
// a model with no audit outstanding must survive startup completely intact.
//
// Deployments that do not scan seal ModelImported=true and never write a marker,
// as do deployments whose audit has already concluded. Were the reconciliation
// keyed on ModelImported instead of on the marker, every restart would quarantine
// a perfectly good model — clear its imported marker and report an audit that
// never happened — even though the package on disk is untouched.
func TestRecovery_NoPendingAudit_LeavesModelUntouched(t *testing.T) {
	state, store, _ := setupTestRecoveryState(t)

	modelFile := filepath.Join(state.Security.ModelDir, "train.py")
	if err := os.WriteFile(modelFile, []byte("import torch\nmodel = torch.nn.Linear(2, 2)\n"), 0o644); err != nil {
		t.Fatalf("write model file: %v", err)
	}

	reports := make(chan map[string]any, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/taa/reportAudit" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			reports <- body
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	state.PlatformIP = server.Listener.Addr().String()
	state.DockerID = "docker-audit-none-01"

	pState := &controller.PersistentState{
		Version:               controller.DefaultStateVersion,
		StateSeq:              1,
		ModelImported:         true,
		SavedModelResourceURL: "https://test.s3.com/model.tar.gz",
		AuditPending:          nil,
		IncarnationID:         "test-epoch-no-audit",
		UpdatedAt:             time.Now().UTC(),
	}
	if err := store.SealState(pState); err != nil {
		t.Fatalf("seal state: %v", err)
	}
	state.RestoreFromPersistentState(pState)

	if err := reconcileAbandonedAudit(context.Background(), state, state.PendingAudit()); err != nil {
		t.Fatalf("reconcileAbandonedAudit with no pending audit failed: %v", err)
	}

	if _, err := os.Stat(modelFile); err != nil {
		t.Errorf("the model was disturbed although no audit was outstanding: %v", err)
	}

	persisted, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if !persisted.ModelImported {
		t.Error("a model with no audit outstanding was marked not imported")
	}
	if persisted.SavedModelResourceURL == "" {
		t.Error("a model with no audit outstanding lost its resource URL")
	}

	select {
	case body := <-reports:
		t.Errorf("an audit was reported although none was outstanding: %+v", body)
	default:
	}
}
