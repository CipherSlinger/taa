package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	teecrypto "taa/pkg/crypto"
)

func createTestStateStore(t *testing.T) (*StateStore, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "taa_state.bin")
	privKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key failed: %v", err)
	}
	sealingKey := DeriveSealingKey(privKey)
	store, err := NewStateStore(statePath, sealingKey)
	if err != nil {
		t.Fatalf("new state store failed: %v", err)
	}
	_, err = store.DetectAndHandleKeyDrift(false)
	if err != nil {
		t.Fatalf("init state store failed: %v", err)
	}
	return store, statePath
}

// ── 1. StateStore Getter / Setter 与 ImportIndexStore 测试 ──

func TestTAAState_StateStoreAndIndexStore(t *testing.T) {
	state, _ := setupTestServer(t)
	if state.GetStateStore() != nil {
		t.Fatal("expected initial StateStore to be nil")
	}

	store, _ := createTestStateStore(t)
	state.SetStateStore(store)
	if state.GetStateStore() != store {
		t.Fatal("expected GetStateStore to return injected store")
	}

	// 测试导出的 ImportIndexStore() 与未导出的 importIndexStore()
	idx1, err1 := state.ImportIndexStore()
	if err1 != nil {
		t.Fatalf("ImportIndexStore() failed: %v", err1)
	}
	idx2, err2 := state.importIndexStore()
	if err2 != nil {
		t.Fatalf("importIndexStore() failed: %v", err2)
	}
	if idx1 != idx2 {
		t.Fatalf("expected ImportIndexStore and importIndexStore to return same instance")
	}
}

// ── 2. switchHandler 与 sealStateLocked 联动测试 ──

func TestTAAState_SwitchPhase_SealingIntegration(t *testing.T) {
	state, server := setupTestServer(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)

	baseState := store.GetState()
	if baseState == nil || baseState.CurrentPhase != 1 {
		t.Fatalf("unexpected base state: %+v", baseState)
	}
	initSeq := baseState.StateSeq

	// 切换到 Phase 2
	body, _ := json.Marshal(switchRequest{Phase: 2})
	resp, err := http.Post(server.URL+"/v1/taa/switch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post switch failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// 验证磁盘上的持久化状态已同步
	diskState, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state failed: %v", err)
	}
	if diskState.CurrentPhase != 2 {
		t.Fatalf("expected disk phase 2, got %d", diskState.CurrentPhase)
	}
	if diskState.StateSeq <= initSeq {
		t.Fatalf("expected StateSeq > %d, got %d", initSeq, diskState.StateSeq)
	}
}

// ── 3. tryAcquireTask / release 与 ActiveTaskSnapshot 联动测试 ──

func TestTAAState_TryAcquireAndRelease_ActiveTaskSealing(t *testing.T) {
	state, _ := setupTestServer(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)

	// 1. tryAcquireTask 获取任务
	taskID := "task-seal-001"
	reqID := "req-seal-001"
	release, err := state.tryAcquireTask(taskID, reqID, "downloading", true)
	if err != nil {
		t.Fatalf("tryAcquireTask failed: %v", err)
	}

	// 内存与���盘都应有 ActiveTask
	activeSnap := state.GetActiveTask()
	if activeSnap == nil || activeSnap.TaskID != taskID || activeSnap.Type != "model_import" {
		t.Fatalf("unexpected active task in memory: %+v", activeSnap)
	}

	diskState, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state failed: %v", err)
	}
	if diskState.ActiveTask == nil || diskState.ActiveTask.TaskID != taskID {
		t.Fatalf("expected disk activeTask to have taskId %s, got %+v", taskID, diskState.ActiveTask)
	}
	if diskState.ActiveTask.Status != "RUNNING" {
		t.Fatalf("expected RUNNING status, got %s", diskState.ActiveTask.Status)
	}

	// 2. release 释放任务
	release()

	if state.GetActiveTask() != nil {
		t.Fatal("expected memory activeTask to be nil after release")
	}

	diskStateAfter, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state after release failed: %v", err)
	}
	if diskStateAfter.ActiveTask != nil {
		t.Fatalf("expected disk activeTask to be nil after release, got %+v", diskStateAfter.ActiveTask)
	}
}

// ── 4. saveModelSuccess / saveDataSuccess / updateImportState 联动测试 ──

func TestTAAState_ImportSuccessMethods_Sealing(t *testing.T) {
	state, _ := setupTestServer(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)

	// 测试 saveModelSuccess
	modelURL := "http://example.com/model.enc"
	state.SaveModelSuccess(modelURL)

	diskState, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state failed: %v", err)
	}
	if !diskState.ModelImported || diskState.SavedModelResourceURL != modelURL {
		t.Fatalf("expected ModelImported=true and URL saved, got %+v", diskState)
	}

	// 测试 saveDataSuccess
	rec := ImportIndexRecord{
		RequestID: "req-data-1",
		TaskID:    "task-data-1",
		Hash:      "hash-abc",
		DataDir:   "/tmp/data",
		Phase:     1,
	}
	state.SaveDataSuccess(rec)

	diskState2, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state failed: %v", err)
	}
	if !diskState2.DataImported {
		t.Fatal("expected DataImported=true in disk state")
	}

	// 测试 updateImportState 清除
	state.UpdateImportState(true, false, 1)
	diskState3, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state failed: %v", err)
	}
	if diskState3.ModelImported {
		t.Fatal("expected ModelImported=false after updateImportState")
	}
}

// ── 5. ResetActiveTask 与 RestoreFromPersistentState 测试 ──

func TestTAAState_ResetActiveTaskAndRestore(t *testing.T) {
	state, _ := setupTestServer(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)

	// 手动构造一个被中断的状态
	p := &PersistentState{
		Version:               DefaultStateVersion,
		StateSeq:              10,
		IncarnationID:         "test-incarnation",
		CurrentPhase:          3,
		ModelImported:         true,
		DataImported:          true,
		TrainingDataImported:  true,
		ExportPublicKey:       "test-pubkey",
		SavedModelResourceURL: "test-url",
		RuntimeConfig:         `{"commands":["python test.py"]}`,
		ModelChecksum:         map[string]any{"algorithm": "sm3", "value": "model-123"},
		DataChecksum:          map[string]any{"algorithm": "sm3", "value": "data-456"},
		ActiveTask: &ActiveTaskSnapshot{
			RequestID: "req-crash-001",
			TaskID:    "task-crash-001",
			Type:      "training",
			Phase:     3,
			Status:    "RUNNING",
			ResultDir: "/tmp/results",
			StartedAt: time.Now().UTC().Add(-1 * time.Minute),
		},
		UpdatedAt: time.Now().UTC(),
	}

	// 还原状态到内存
	state.RestoreFromPersistentState(p)

	state.mu.RLock()
	if state.CurrentPhase != 3 || !state.ModelImported || !state.TrainingDataImported {
		state.mu.RUnlock()
		t.Fatalf("RestoreFromPersistentState failed to restore flags: phase=%d, model=%v, trainData=%v",
			state.CurrentPhase, state.ModelImported, state.TrainingDataImported)
	}
	if state.ActiveTaskID != "task-crash-001" || state.ActiveRequestID != "req-crash-001" {
		state.mu.RUnlock()
		t.Fatalf("RestoreFromPersistentState failed to restore ActiveTaskID: %s", state.ActiveTaskID)
	}
	state.mu.RUnlock()

	activeSnap := state.GetActiveTask()
	if activeSnap == nil || activeSnap.TaskID != "task-crash-001" {
		t.Fatalf("expected activeTask snapshot restored, got %+v", activeSnap)
	}

	// 测试 ResetActiveTask
	state.ResetActiveTask()

	if state.GetActiveTask() != nil {
		t.Fatal("expected GetActiveTask to be nil after ResetActiveTask")
	}
	state.mu.RLock()
	if state.ActiveTaskID != "" || state.ActiveRequestID != "" || state.CurrentOp != "idle" {
		state.mu.RUnlock()
		t.Fatalf("active task identifiers not cleared: task=%s, req=%s, op=%s",
			state.ActiveTaskID, state.ActiveRequestID, state.CurrentOp)
	}
	state.mu.RUnlock()

	// 验证磁盘上的 ActiveTask 同样被清除
	diskState, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state failed: %v", err)
	}
	if diskState.ActiveTask != nil {
		t.Fatalf("expected disk activeTask to be nil after ResetActiveTask, got %+v", diskState.ActiveTask)
	}
}

// ── 6. 规约 11 异常 Panic 恢复、失败报告与平台补偿通知测试 ──

func TestTAAState_RunAsyncSafe_PanicRecoveryAndCompensation(t *testing.T) {
	// 搭建 mock 管控平台服务器，捕获 ReportRes 或 ReportModelImport 上报
	type reportPayload struct {
		DockerID  string  `json:"dockerId"`
		RequestID string  `json:"requestId"`
		TaskID    string  `json:"taskId"`
		Code      int     `json:"code"`
		Msg       *string `json:"msg"`
		Report    string  `json:"report"`
	}

	var reportMu sync.Mutex
	var receivedReport *reportPayload
	var receivedPath string
	reportNotifyChan := make(chan struct{}, 1)

	mockPlatform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p reportPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err == nil {
			reportMu.Lock()
			receivedReport = &p
			receivedPath = r.URL.Path
			reportMu.Unlock()
			select {
			case reportNotifyChan <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockPlatform.Close()

	state, _ := setupTestServer(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)
	state.PlatformIP = mockPlatform.URL
	state.DockerID = "docker-panic-test"
	state.setModelChecksum(map[string]any{"algorithm": "sm3", "value": "model-hash-123"})
	state.setDataChecksum(map[string]any{"algorithm": "sm3", "value": "data-hash-456"})

	taskID := "task-panic-001"
	reqID := "req-panic-001"

	release, err := state.tryAcquireTask(taskID, reqID, "training", false)
	if err != nil {
		t.Fatalf("tryAcquireTask failed: %v", err)
	}

	// 确认当前在飞任务已落盘
	diskState, err := store.UnsealState()
	if err != nil || diskState.ActiveTask == nil || diskState.ActiveTask.TaskID != taskID {
		t.Fatalf("precondition check: active task not persisted properly: %+v", diskState)
	}

	// 执行会在异步内部发生 panic 的任务
	state.runAsyncSafe("trainingPanicProcess", release, func() {
		panic("simulated fatal runtime panic in async goroutine")
	})

	// 等待平台通知到达或超时
	select {
	case <-reportNotifyChan:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for platform failure notification after async panic")
	}

	reportMu.Lock()
	p := receivedReport
	path := receivedPath
	reportMu.Unlock()

	if p == nil {
		t.Fatal("expected platform report to be received")
	}
	if path != reportResEndpoint {
		t.Fatalf("expected report endpoint %s, got %s", reportResEndpoint, path)
	}
	if p.TaskID != taskID || p.RequestID != reqID {
		t.Fatalf("expected taskId=%s, reqId=%s, got taskId=%s, reqId=%s", taskID, reqID, p.TaskID, p.RequestID)
	}
	if p.Code != 1 {
		t.Fatalf("expected failure code 1, got %d", p.Code)
	}
	if p.Msg == nil || !bytes.Contains([]byte(*p.Msg), []byte("simulated fatal runtime panic")) {
		t.Fatalf("expected panic message in failure reason, got %#v", p.Msg)
	}

	// 解析结构化失败报告
	var crashReport map[string]any
	if err := json.Unmarshal([]byte(p.Report), &crashReport); err != nil {
		t.Fatalf("unmarshal crash report failed: %v, report: %s", err, p.Report)
	}
	if crashReport["schema_version"] != "1.0" {
		t.Fatalf("expected schema_version 1.0, got %v", crashReport["schema_version"])
	}
	taskMap, ok := crashReport["training_task"].(map[string]any)
	if !ok {
		t.Fatalf("training_task field missing in crash report: %+v", crashReport)
	}
	if taskMap["status"] != "failed" {
		t.Fatalf("expected status failed, got %v", taskMap["status"])
	}
	// exit_code 137
	if exitCode, ok := taskMap["exit_code"].(float64); !ok || int(exitCode) != 137 {
		t.Fatalf("expected exit_code 137, got %v", taskMap["exit_code"])
	}

	// 校验内存在飞任务已被清除
	if state.GetActiveTask() != nil {
		t.Fatal("expected in-memory activeTask to be cleared after panic")
	}

	// 校验磁盘持久化状态中的在飞任务已被清除
	diskStateAfter, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state after panic failed: %v", err)
	}
	if diskStateAfter.ActiveTask != nil {
		t.Fatalf("expected disk activeTask to be cleared after panic, got %+v", diskStateAfter.ActiveTask)
	}
}

// ── 7. BuildCrashFailureReport 字段完整性规范测试 ──

func TestBuildCrashFailureReport_Schema(t *testing.T) {
	startedAt := time.Now().UTC().Add(-10 * time.Second)
	finishedAt := time.Now().UTC()
	taskID := "task-schema-test"
	reason := "OOM killed or panic crash"
	modelChecksum := map[string]any{"algorithm": "sm3", "value": "model-val", "size": 1024}
	dataChecksum := map[string]any{"algorithm": "sm3", "value": "data-val", "size": 2048}

	report, err := BuildCrashFailureReport(taskID, startedAt, finishedAt, reason, modelChecksum, dataChecksum)
	if err != nil {
		t.Fatalf("BuildCrashFailureReport failed: %v", err)
	}

	if report["schema_version"] != "1.0" {
		t.Fatalf("expected schema_version 1.0, got %v", report["schema_version"])
	}
	if report["report_id"] == nil || report["report_id"] == "" {
		t.Fatal("expected non-empty report_id")
	}

	trainingTask, ok := report["training_task"].(map[string]any)
	if !ok {
		t.Fatalf("training_task missing: %+v", report)
	}
	if trainingTask["task_id"] != taskID {
		t.Fatalf("expected task_id %s, got %v", taskID, trainingTask["task_id"])
	}
	if trainingTask["status"] != "failed" {
		t.Fatalf("expected status failed, got %v", trainingTask["status"])
	}
	if trainingTask["exit_code"] != 137 {
		t.Fatalf("expected exit_code 137, got %v", trainingTask["exit_code"])
	}
	if trainingTask["failure_reason"] != reason {
		t.Fatalf("expected failure_reason %s, got %v", reason, trainingTask["failure_reason"])
	}
	if trainingTask["model_checksum"] == nil {
		t.Fatal("expected model_checksum to be present")
	}

	dataset, ok := report["dataset"].(map[string]any)
	if !ok {
		t.Fatalf("dataset missing: %+v", report)
	}
	if dataset["checksum"] == nil {
		t.Fatal("expected dataset checksum to be present")
	}
}

// ── 8. 规约 11 模型导入阶段发生 Panic 时上报 ReportModelImport 测试 ──

func TestTAAState_RunAsyncSafe_ModelImportPanicRecovery(t *testing.T) {
	type reportPayload struct {
		DockerID  string  `json:"dockerId"`
		RequestID string  `json:"requestId"`
		TaskID    string  `json:"taskId"`
		Code      int     `json:"code"`
		Msg       *string `json:"msg"`
		Report    string  `json:"report"`
	}

	var reportMu sync.Mutex
	var receivedReport *reportPayload
	var receivedPath string
	reportNotifyChan := make(chan struct{}, 1)

	mockPlatform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p reportPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err == nil {
			reportMu.Lock()
			receivedReport = &p
			receivedPath = r.URL.Path
			reportMu.Unlock()
			select {
			case reportNotifyChan <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockPlatform.Close()

	state, _ := setupTestServer(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)
	state.PlatformIP = mockPlatform.URL
	state.DockerID = "docker-panic-model"

	taskID := "task-panic-model-001"
	reqID := "req-panic-model-001"

	// isModel = true
	release, err := state.tryAcquireTask(taskID, reqID, "downloading", true)
	if err != nil {
		t.Fatalf("tryAcquireTask failed: %v", err)
	}

	state.runAsyncSafe("processImportedResourceModel", release, func() {
		panic("model parsing crash panic")
	})

	select {
	case <-reportNotifyChan:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for platform model import failure notification")
	}

	reportMu.Lock()
	p := receivedReport
	path := receivedPath
	reportMu.Unlock()

	if p == nil {
		t.Fatal("expected platform report to be received")
	}
	if path != reportModelImportEndpoint {
		t.Fatalf("expected report endpoint %s, got %s", reportModelImportEndpoint, path)
	}
	if p.TaskID != taskID || p.RequestID != reqID {
		t.Fatalf("expected taskId=%s, reqId=%s, got taskId=%s, reqId=%s", taskID, reqID, p.TaskID, p.RequestID)
	}
	if p.Code != 1 {
		t.Fatalf("expected code 1, got %d", p.Code)
	}
}
