package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTrainingControlCancellationAndFinish(t *testing.T) {
	control := newTrainingControl()
	if control.isCancelled() {
		t.Fatal("new control is cancelled")
	}

	control.requestStop()
	if !control.isCancelled() {
		t.Fatal("requestStop did not mark control cancelled")
	}

	control.finish()
	control.finish()
	select {
	case <-control.done:
	default:
		t.Fatal("done was not closed")
	}
}

func TestTrainingControlStartCommandAfterCancellation(t *testing.T) {
	control := newTrainingControl()
	control.requestStop()

	if err := control.startCommand(exec.Command("true")); !errors.Is(err, context.Canceled) {
		t.Fatalf("startCommand error = %v, want context.Canceled", err)
	}
}

func TestTrainingControlCommandRegistrationAndCleanup(t *testing.T) {
	control := newTrainingControl()
	cmd := exec.Command("sleep", "30")
	if err := control.startCommand(cmd); err != nil {
		t.Fatalf("startCommand() error = %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	if got := control.requestStop(); got != cmd {
		t.Fatalf("requestStop() command = %p, want %p", got, cmd)
	}

	control.clearCommand(cmd)
	if got := control.requestStop(); got != nil {
		t.Fatalf("requestStop() command after cleanup = %p, want nil", got)
	}
}

func TestTrainingControlStartCommandFailureCleansUp(t *testing.T) {
	control := newTrainingControl()
	cmd := exec.Command("/definitely/missing/training-command")
	if err := control.startCommand(cmd); err == nil {
		t.Fatal("startCommand() error = nil, want an error")
	}
	if got := control.requestStop(); got != nil {
		t.Fatalf("requestStop() command after start failure = %p, want nil", got)
	}
}

func TestStopTrainingWithoutActiveTaskIsIdempotent(t *testing.T) {
	_, server := setupTestServer(t)
	defer server.Close()

	resp := postEmptyJSON(t, server.URL+"/v1/taa/stopTraining")
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 || api.Msg != "不存在训练任务" {
		t.Fatalf("status=%d error=%d msg=%q, want 200, error=0, msg='不存在训练任务'", resp.StatusCode, api.Error, api.Msg)
	}
}

func TestStopTrainingRejectsNonPost(t *testing.T) {
	_, server := setupTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/v1/taa/stopTraining")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestRunRuntimeConfigCanBeCancelled(t *testing.T) {
	control := newTrainingControl()
	cfg := runtimeConfig{
		Commands: []string{"sleep 30"},
	}
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	outputDir := filepath.Join(tmpDir, "output")
	_ = os.MkdirAll(dataDir, 0o755)
	_ = os.MkdirAll(outputDir, 0o755)

	errCh := make(chan error, 1)
	go func() {
		_, err := runRuntimeConfigWithControl(control, cfg, nil, tmpDir, dataDir, outputDir, "task-cancel-test", "2026-09-15T00:00:00Z")
		errCh <- err
	}()

	// 等待 cmd 在 control 中登记并启动
	var cmd *exec.Cmd
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		control.mu.Lock()
		cmd = control.cmd
		control.mu.Unlock()
		if cmd != nil && cmd.Process != nil && cmd.Process.Pid > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		t.Fatal("runtime command was not registered/started in time")
	}

	stoppedCmd := control.requestStop()
	if stoppedCmd != cmd {
		t.Fatalf("requestStop() returned %p, want %p", stoppedCmd, cmd)
	}

	if err := KillProcessGroup(stoppedCmd); err != nil {
		t.Fatalf("KillProcessGroup() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runRuntimeConfigWithControl error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runRuntimeConfigWithControl did not return in time after process group kill")
	}
}

func TestStopTrainingDuringRuntimeConfig(t *testing.T) {
	state, server := setupTestServer(t)
	defer server.Close()

	trainDone := make(chan struct{})
	req := importRequest{
		TaskID:    "task-stop-runtime",
		RequestID: "req-stop-runtime",
	}
	record := ImportIndexRecord{
		TaskID:    req.TaskID,
		RequestID: req.RequestID,
		DataDir:   t.TempDir(),
		ResultDir: t.TempDir(),
	}
	cfg := runtimeConfig{
		Commands: []string{"sleep 30"},
	}

	go func() {
		defer close(trainDone)
		state.executeTraining(req, 1, record, cfg, nil, time.Now().UTC())
	}()

	// 等待进入 training 状态并且 control 已分配
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		state.mu.RLock()
		op := state.CurrentOp
		ctrl := state.trainingControl
		state.mu.RUnlock()
		if op == "training" && ctrl != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp := postEmptyJSON(t, server.URL+"/v1/taa/stopTraining")
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 || api.Msg != "训练任务已中止" {
		t.Fatalf("status=%d error=%d msg=%q, want 200/0/'训练任务已中止'", resp.StatusCode, api.Error, api.Msg)
	}

	select {
	case <-trainDone:
	case <-time.After(3 * time.Second):
		t.Fatal("executeTraining did not exit in time after stop")
	}

	state.mu.RLock()
	currentOp := state.CurrentOp
	ctrl := state.trainingControl
	trainingRunning := state.TrainingRunning
	state.mu.RUnlock()

	if currentOp != "idle" {
		t.Fatalf("currentOp = %q, want 'idle'", currentOp)
	}
	if ctrl != nil {
		t.Fatal("trainingControl was not cleared after task completed")
	}
	if trainingRunning {
		t.Fatal("TrainingRunning should be false for cancelled task")
	}
}

func TestStopTrainingDuringStaging(t *testing.T) {
	state, server := setupTestServer(t)
	defer server.Close()

	trainDone := make(chan struct{})
	req := importRequest{
		TaskID:    "task-stop-staging",
		RequestID: "req-stop-staging",
	}
	record := ImportIndexRecord{
		TaskID:    req.TaskID,
		RequestID: req.RequestID,
		DataDir:   t.TempDir(),
		ResultDir: t.TempDir(),
	}
	cfg := runtimeConfig{
		Commands: []string{"echo done"},
	}

	// 提前创建并取消 control，模拟在 staging 阶段前/中收到取消信号
	control := newTrainingControl()
	control.requestStop()

	state.mu.Lock()
	state.trainingControl = control
	state.mu.Unlock()

	go func() {
		defer close(trainDone)
		state.executeTraining(req, 1, record, cfg, nil, time.Now().UTC())
	}()

	resp := postEmptyJSON(t, server.URL+"/v1/taa/stopTraining")
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("status=%d error=%d msg=%q", resp.StatusCode, api.Error, api.Msg)
	}

	select {
	case <-trainDone:
	case <-time.After(3 * time.Second):
		t.Fatal("executeTraining did not return in time")
	}

	state.mu.RLock()
	currentOp := state.CurrentOp
	trainingRunning := state.TrainingRunning
	state.mu.RUnlock()

	if currentOp != "idle" {
		t.Fatalf("currentOp = %q, want 'idle'", currentOp)
	}
	if trainingRunning {
		t.Fatal("TrainingRunning should be false")
	}
}

func TestStopTrainingDoesNotReportResult(t *testing.T) {
	state, server := setupTestServer(t)
	defer server.Close()

	reportCh := make(chan importedReportPayload, 1)
	modelLogCh := make(chan struct{}, 1)
	progressCh := make(chan struct{}, 1)
	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case reportResEndpoint:
			var payload importedReportPayload
			_ = json.NewDecoder(r.Body).Decode(&payload)
			reportCh <- payload
		case modelLogEndpoint:
			modelLogCh <- struct{}{}
		case reportProgressEndpoint:
			progressCh <- struct{}{}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"msg":"success","result":{"received":true},"error":0}`))
	}))
	defer platformServer.Close()

	state.mu.Lock()
	state.PlatformIP = platformServer.URL
	state.DockerID = "docker-stop-test"
	state.mu.Unlock()

	trainDone := make(chan struct{})
	req := importRequest{
		TaskID:    "task-no-report",
		RequestID: "req-no-report",
	}
	record := ImportIndexRecord{
		TaskID:    req.TaskID,
		RequestID: req.RequestID,
		DataDir:   t.TempDir(),
		ResultDir: t.TempDir(),
	}
	logPath := filepath.Join(state.Security.GetModelLogDir(), "train.jsonl")
	progressPath := filepath.Join(state.Security.GetModelProgressDir(), "progress.json")
	cfg := runtimeConfig{
		Commands: []string{
			fmt.Sprintf("printf '%%s\\n' %q > %q", "{\\\"message\\\":\\\"epoch=1\\\"}", logPath),
			fmt.Sprintf("printf '%%s\\n' %q > %q", "{\\\"percent\\\":25,\\\"timestamp\\\":\\\"2026-09-15T00:00:00Z\\\"}", progressPath),
			"sleep 30",
		},
	}

	go func() {
		defer close(trainDone)
		state.executeTraining(req, 1, record, cfg, nil, time.Now().UTC())
	}()

	// 等待进入 training
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		state.mu.RLock()
		op := state.CurrentOp
		ctrl := state.trainingControl
		state.mu.RUnlock()
		if op == "training" && ctrl != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp := postEmptyJSON(t, server.URL+"/v1/taa/stopTraining")
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 || api.Msg != "训练任务已中止" {
		t.Fatalf("status=%d error=%d msg=%q, want 200/0/'训练任务已中止'", resp.StatusCode, api.Error, api.Msg)
	}

	select {
	case <-trainDone:
	case <-time.After(3 * time.Second):
		t.Fatal("executeTraining did not finish in time")
	}

	// 确认未向平台发送任何训练结果、日志或进度上报请求
	select {
	case payload := <-reportCh:
		t.Fatalf("unexpected reportRes sent to platform: %+v", payload)
	case <-modelLogCh:
		t.Fatal("unexpected modelLog sent to platform")
	case <-progressCh:
		t.Fatal("unexpected reportProgress sent to platform")
	case <-time.After(300 * time.Millisecond):
		// 正常：没有上报
	}
}

func TestStopTrainingConcurrentRequests(t *testing.T) {
	state, server := setupTestServer(t)
	defer server.Close()

	trainDone := make(chan struct{})
	req := importRequest{
		TaskID:    "task-stop-concurrent",
		RequestID: "req-stop-concurrent",
	}
	record := ImportIndexRecord{
		TaskID:    req.TaskID,
		RequestID: req.RequestID,
		DataDir:   t.TempDir(),
		ResultDir: t.TempDir(),
	}
	cfg := runtimeConfig{
		Commands: []string{"sleep 30"},
	}

	go func() {
		defer close(trainDone)
		state.executeTraining(req, 1, record, cfg, nil, time.Now().UTC())
	}()

	// 等待进入 training
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		state.mu.RLock()
		op := state.CurrentOp
		ctrl := state.trainingControl
		state.mu.RUnlock()
		if op == "training" && ctrl != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	const concurrentCount = 2
	var wg sync.WaitGroup
	type stopResult struct {
		statusCode int
		api        apiResponse
	}
	results := make([]stopResult, concurrentCount)

	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resp := postEmptyJSON(t, server.URL+"/v1/taa/stopTraining")
			api := decodeResponse(t, resp)
			results[idx] = stopResult{statusCode: resp.StatusCode, api: api}
		}(i)
	}

	wg.Wait()

	select {
	case <-trainDone:
	case <-time.After(3 * time.Second):
		t.Fatal("executeTraining did not return in time")
	}

	// 两个请求都必须返回 HTTP 200, error=0, 且 msg 为 "训练任务已中止" 或 "不存在训练任务"
	for i, r := range results {
		if r.statusCode != http.StatusOK || r.api.Error != 0 {
			t.Fatalf("request %d: status=%d error=%d msg=%q", i, r.statusCode, r.api.Error, r.api.Msg)
		}
		if r.api.Msg != "训练任务已中止" && r.api.Msg != "不存在训练任务" {
			t.Fatalf("request %d: unexpected msg=%q", i, r.api.Msg)
		}
	}

	state.mu.RLock()
	currentOp := state.CurrentOp
	ctrl := state.trainingControl
	state.mu.RUnlock()

	if currentOp != "idle" {
		t.Fatalf("currentOp = %q, want 'idle'", currentOp)
	}
	if ctrl != nil {
		t.Fatal("trainingControl was not cleared")
	}
}

func TestStopTrainingThenRestart(t *testing.T) {
	state, server := setupTestServer(t)
	defer server.Close()

	// 1. 启动第一个被中止的任务
	trainDone1 := make(chan struct{})
	req1 := importRequest{
		TaskID:    "task-stop-restart-1",
		RequestID: "req-stop-restart-1",
	}
	record1 := ImportIndexRecord{
		TaskID:    req1.TaskID,
		RequestID: req1.RequestID,
		DataDir:   t.TempDir(),
		ResultDir: t.TempDir(),
	}
	cfg1 := runtimeConfig{
		Commands: []string{"sleep 30"},
	}

	go func() {
		defer close(trainDone1)
		state.executeTraining(req1, 1, record1, cfg1, nil, time.Now().UTC())
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		state.mu.RLock()
		op := state.CurrentOp
		ctrl := state.trainingControl
		state.mu.RUnlock()
		if op == "training" && ctrl != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp := postEmptyJSON(t, server.URL+"/v1/taa/stopTraining")
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 || api.Msg != "训练任务已中止" {
		t.Fatalf("status=%d error=%d msg=%q", resp.StatusCode, api.Error, api.Msg)
	}

	select {
	case <-trainDone1:
	case <-time.After(3 * time.Second):
		t.Fatal("first executeTraining did not finish in time")
	}

	// 2. 启动第二个正常任务，验证状态未受第一个任务影响且能正常执行
	trainDone2 := make(chan struct{})
	req2 := importRequest{
		TaskID:    "task-stop-restart-2",
		RequestID: "req-stop-restart-2",
	}
	record2 := ImportIndexRecord{
		TaskID:    req2.TaskID,
		RequestID: req2.RequestID,
		DataDir:   t.TempDir(),
		ResultDir: t.TempDir(),
	}
	cfg2 := runtimeConfig{
		Commands: []string{"echo second_task_done"},
	}

	go func() {
		defer close(trainDone2)
		state.executeTraining(req2, 1, record2, cfg2, nil, time.Now().UTC())
	}()

	select {
	case <-trainDone2:
	case <-time.After(60 * time.Second):
		t.Fatal("second executeTraining did not finish in time")
	}

	state.mu.RLock()
	currentOp := state.CurrentOp
	ctrl := state.trainingControl
	trainingRunning := state.TrainingRunning
	state.mu.RUnlock()

	if currentOp != "idle" {
		t.Fatalf("currentOp = %q, want 'idle'", currentOp)
	}
	if ctrl != nil {
		t.Fatal("trainingControl was not cleared for task 2")
	}
	if trainingRunning {
		t.Fatal("TrainingRunning should be false after task 2 completes")
	}
}
