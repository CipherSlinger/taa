package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgerrors "taa/pkg/errors"
)

// TestConcurrency_ImportRejectedWhenTrainingBusy 验证当处于训练执行阶段时，
// 任何下发的 import 请求都会被拦截并返回 409 Conflict。
func TestConcurrency_ImportRejectedWhenTrainingBusy(t *testing.T) {
	state, server := setupTestServer(t)

	// 模拟当前正在训练中
	state.mu.Lock()
	state.ActiveTaskID = "task-training-01"
	state.ActiveRequestID = "req-training-01"
	state.CurrentOp = "training"
	state.mu.Unlock()

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": "http://127.0.0.1:9999/data.tar.gz",
		"requestId":   "req-data-concurrent",
		"taskId":      "task-data-concurrent",
	})
	api := decodeResponse(t, resp)

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected status 409 Conflict, got %d", resp.StatusCode)
	}
	if api.Error != http.StatusConflict {
		t.Fatalf("expected api.Error = 409, got %d", api.Error)
	}
	if !strings.Contains(api.Msg, "当前已有训练任务正在执行中") || !strings.Contains(api.Msg, "task-training-01") {
		t.Fatalf("unexpected error msg: %s", api.Msg)
	}
}

// TestConcurrency_ModelImportRejectedWhenTrainingBusy 验证当处于训练执行阶段时，
// 任何下发的 importModel 请求都会被拦截并返回 409 Conflict。
func TestConcurrency_ModelImportRejectedWhenTrainingBusy(t *testing.T) {
	state, server := setupTestServer(t)

	// 模拟处于 staging 阶段
	state.mu.Lock()
	state.ActiveTaskID = "task-staging-01"
	state.ActiveRequestID = "req-staging-01"
	state.CurrentOp = "staging"
	state.mu.Unlock()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl": "http://127.0.0.1:9999/model.tar.gz",
		"requestId":   "req-model-concurrent",
		"taskId":      "task-model-concurrent",
	})
	api := decodeResponse(t, resp)

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected status 409 Conflict, got %d", resp.StatusCode)
	}
	if api.Error != http.StatusConflict {
		t.Fatalf("expected api.Error = 409, got %d", api.Error)
	}
	if !strings.Contains(api.Msg, "当前已有训练任务正在执行中") || !strings.Contains(api.Msg, "task-staging-01") {
		t.Fatalf("unexpected error msg: %s", api.Msg)
	}
}

// TestConcurrency_EmptyURLModelReuseRejectedWhenTrainingBusy 验证在模型复用场景（空 resourceUrl）下，
// 若有训练正在执行，也会被互斥拦截返回 409 Conflict。
func TestConcurrency_EmptyURLModelReuseRejectedWhenTrainingBusy(t *testing.T) {
	state, server := setupTestServer(t)

	state.mu.Lock()
	state.SavedModelResourceURL = "http://127.0.0.1:9999/saved-model.tar.gz"
	state.RuntimeConfig = `{"commands":["echo 1"]}`
	state.ActiveTaskID = "task-running-01"
	state.CurrentOp = "training"
	state.mu.Unlock()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl": "",
		"requestId":   "req-reuse-concurrent",
		"taskId":      "task-reuse-concurrent",
	})
	api := decodeResponse(t, resp)

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected status 409 Conflict, got %d", resp.StatusCode)
	}
	if api.Error != http.StatusConflict {
		t.Fatalf("expected api.Error = 409, got %d", api.Error)
	}
	if !strings.Contains(api.Msg, "当前已有训练任务正在执行中") {
		t.Fatalf("unexpected error msg: %s", api.Msg)
	}
}

// TestConcurrency_DuplicateImportRejectedWhileDownloading 验证当同一或不同任务正在下载/处理资源时，
// 并发请求会被拦截返回 409 Conflict。
func TestConcurrency_DuplicateImportRejectedWhileDownloading(t *testing.T) {
	state, server := setupTestServer(t)

	state.mu.Lock()
	state.CurrentPhase = 2 // 阶段 2
	state.ActiveTaskID = "task-download-01"
	state.ActiveRequestID = "req-download-01"
	state.CurrentOp = "downloading"
	state.mu.Unlock()

	// 尝试并发提交相同的任务
	respSame := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": "http://127.0.0.1:9999/data.tar.gz",
		"requestId":   "req-download-01-dup",
		"taskId":      "task-download-01",
	})
	apiSame := decodeResponse(t, respSame)

	if respSame.StatusCode != http.StatusConflict || apiSame.Error != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate task download, got status=%d error=%d msg=%s",
			respSame.StatusCode, apiSame.Error, apiSame.Msg)
	}
	if !strings.Contains(apiSame.Msg, "当前已有任务正在执行中") {
		t.Fatalf("expected busy message, got: %s", apiSame.Msg)
	}

	// 尝试并发提交不同的任务
	respDiff := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": "http://127.0.0.1:9999/data.tar.gz",
		"requestId":   "req-other",
		"taskId":      "task-other",
	})
	apiDiff := decodeResponse(t, respDiff)

	if respDiff.StatusCode != http.StatusConflict || apiDiff.Error != http.StatusConflict {
		t.Fatalf("expected 409 for concurrent task download, got status=%d error=%d msg=%s",
			respDiff.StatusCode, apiDiff.Error, apiDiff.Msg)
	}
}

// TestConcurrency_SequentialExecutionAfterRelease 验证任务互斥锁获取与释放逻辑：
// 任务执行期间互斥，释放后下一个任务可顺利获取执行权。
func TestConcurrency_SequentialExecutionAfterRelease(t *testing.T) {
	state, _ := setupTestServer(t)

	// 1. 任务 1 抢占执行权
	release1, err := state.tryAcquireTask("task-seq-01", "req-seq-01", "downloading", false)
	if err != nil {
		t.Fatalf("task 1 tryAcquireTask failed: %v", err)
	}
	if release1 == nil {
		t.Fatal("release1 function should not be nil")
	}

	// 验证状态已更新
	state.mu.RLock()
	if state.ActiveTaskID != "task-seq-01" || state.CurrentOp != "downloading" {
		t.Fatalf("unexpected state: activeTask=%s, currentOp=%s", state.ActiveTaskID, state.CurrentOp)
	}
	state.mu.RUnlock()

	// 2. 在任务 1 未释放前，任务 2 尝试获取执行权，必须被拦截 (409)
	release2, err := state.tryAcquireTask("task-seq-02", "req-seq-02", "downloading", false)
	if err == nil {
		t.Fatal("expected conflict error for concurrent task 2, but got nil")
	}
	if release2 != nil {
		t.Fatal("release2 should be nil on error")
	}
	code := pkgerrors.CodeOf(err, 0)
	if code != http.StatusConflict {
		t.Fatalf("expected error code 409, got %d", code)
	}

	// 3. 释放任务 1
	release1()

	// 验证状态已恢复 idle
	state.mu.RLock()
	if state.ActiveTaskID != "" || state.CurrentOp != "idle" {
		t.Fatalf("state not reset to idle: activeTask=%s, currentOp=%s", state.ActiveTaskID, state.CurrentOp)
	}
	state.mu.RUnlock()

	// 4. 重复释放 release1 应具备幂等性，不产生副作用
	release1()

	// 5. 任务 2 此时应能顺利获取执行权
	release2, err = state.tryAcquireTask("task-seq-02", "req-seq-02", "downloading", false)
	if err != nil {
		t.Fatalf("task 2 tryAcquireTask after release failed: %v", err)
	}
	if release2 == nil {
		t.Fatal("release2 should not be nil")
	}

	state.mu.RLock()
	if state.ActiveTaskID != "task-seq-02" || state.CurrentOp != "downloading" {
		t.Fatalf("unexpected state after task 2 acquire: activeTask=%s, currentOp=%s", state.ActiveTaskID, state.CurrentOp)
	}
	state.mu.RUnlock()

	// 释放任务 2
	release2()
	state.mu.RLock()
	if state.ActiveTaskID != "" || state.CurrentOp != "idle" {
		t.Fatalf("state not reset after task 2 release: activeTask=%s, currentOp=%s", state.ActiveTaskID, state.CurrentOp)
	}
	state.mu.RUnlock()
}

// TestConcurrency_ReleaseIdempotenceAndTokenProtection 验证不同任务生成的令牌保护：
// 旧任务的 release 函数不会误清理新任务的锁。
func TestConcurrency_ReleaseIdempotenceAndTokenProtection(t *testing.T) {
	state, _ := setupTestServer(t)

	// 任务 1 抢占
	release1, err := state.tryAcquireTask("task-token-01", "req-01", "staging", false)
	if err != nil {
		t.Fatalf("tryAcquireTask task 1 failed: %v", err)
	}

	// 模拟底层状态意外变更或者强行切换
	state.mu.Lock()
	state.activeToken = 999999999
	state.ActiveTaskID = "task-token-02"
	state.CurrentOp = "training"
	state.mu.Unlock()

	// 调用旧的 release1，因为 token 不匹配，不应清空当前任务 2 的锁
	release1()

	state.mu.RLock()
	if state.ActiveTaskID != "task-token-02" || state.CurrentOp != "training" {
		t.Fatalf("release1 should not have cleared task 2's active state: activeTask=%s, currentOp=%s",
			state.ActiveTaskID, state.CurrentOp)
	}
	state.mu.RUnlock()
}

// TestConcurrency_RealHTTPConcurrentRequests 模拟真实的并发 HTTP POST 请求，
// 验证在高并发下只有一个请求能成功启动任务，其他请求均返回 409 Conflict。
func TestConcurrency_RealHTTPConcurrentRequests(t *testing.T) {
	state, server := setupTestServer(t)

	// 创建一个延迟响应的模拟资源服务器，确保任务执行持续一段时间
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write([]byte("mock-data-archive"))
	}))
	defer slowServer.Close()

	concurrency := 5
	errCh := make(chan error, concurrency)
	statusCh := make(chan int, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			taskID := fmt.Sprintf("task-concurrent-%d", idx)
			reqID := fmt.Sprintf("req-concurrent-%d", idx)
			resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
				"resourceUrl": slowServer.URL + "/data.tar.gz",
				"requestId":   reqID,
				"taskId":      taskID,
			})
			statusCh <- resp.StatusCode
			errCh <- nil
		}(i)
	}

	statusCount := make(map[int]int)
	for i := 0; i < concurrency; i++ {
		<-errCh
		status := <-statusCh
		statusCount[status]++
	}

	// 预期有且仅有 1 个请求能进入处理，其他 4 个请求必须返回 409 Conflict（或因下载 mock 数据非法返回 500）
	// 最关键的是：绝不能有两个请求同时返回 200！
	successCount := statusCount[http.StatusOK]
	conflictCount := statusCount[http.StatusConflict]
	if successCount > 1 {
		t.Fatalf("expected at most 1 successful request (200 OK), got %d; status counts: %+v", successCount, statusCount)
	}
	if conflictCount == 0 {
		t.Fatalf("expected at least one 409 Conflict under concurrency, got none; status counts: %+v", statusCount)
	}

	waitForIdle(t, state)
}
