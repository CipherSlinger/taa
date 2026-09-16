# Platform Mock 五大接口调整与对接支持实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `platform-mock`（`internal/app/mock/`）及 Web 控制台（`index.html`）中完整支持 5 个调整或新增接口（`reportModelImport`、`reportAudit`、`modelLog`、`reportProgress`、`stopTraining`）的规约对齐、去重存储、时序控制、代理转发及可视化测试。

**Architecture:** 
- 后端采用各模块独立的线程安全 Store（内存缓存 + JSON 文件持久化），遵循标准公共返回格式 `{msg, result, error}`；
- `reportModelImport` 与 `reportAudit` 补充严格字段校验与结构化字段（`checksum`、`statistics: {high, medium, low}`）暴露；
- `reportProgress` 基于 RFC3339 时间戳防止逆序回退；`modelLog` 基于 `dockerId + requestId + seq` 严格去重并采用环形缓冲存储；
- `stopTraining` 通过 Mock 代理向真实 TAA 服务透传控制指令并在 `requestLogs` 中捕获全量请求体；
- 前端 Web 控制台在“训练结果”区域集成进度条与中止按钮，页面底部新增现代终端样式的“模型终端日志”实时面板。

**Tech Stack:** Go (Standard Library `net/http`, `sync`, `json`), HTML5/CSS3/Vanilla JavaScript, Go test.

---

### Task 1: 强化 `reportModelImport` 与 `reportAudit` 规约校验与结果字段提取

**Files:**
- Modify: `internal/app/mock/server.go`
- Test: `internal/app/mock/server_test.go`

- [ ] **Step 1: 编写测试用例验证校验与结果暴露**

在 `internal/app/mock/server_test.go` 中新增测试用例：
```go
func TestReportModelImportStrictValidationAndChecksum(t *testing.T) {
	stateDir := t.TempDir()
	store := newReportStateStore(stateDir, "reportModelImport-state.json")
	handler := reportModelImportHandler(store)

	// 1. 缺少 requestId 报错 400
	{
		body := `{"dockerId":"docker-1","code":0,"checksum":{"size":100,"algorithm":"sm3","value":"abcd"}}`
		req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportModelImport", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when requestId missing, got %d", w.Code)
		}
	}

	// 2. code=0 但缺少 checksum 报错 400
	{
		body := `{"dockerId":"docker-1","requestId":"req-1","code":0}`
		req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportModelImport", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when checksum missing on success, got %d", w.Code)
		}
	}

	// 3. 正确上报，状态包含 checksum
	{
		body := `{"dockerId":"docker-1","requestId":"req-1","code":0,"msg":"模型导入成功","checksum":{"size":581632,"algorithm":"sm3","value":"a1b2c3d4"}}`
		req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportModelImport", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		res := reportStateResult(store.get())
		checksum, ok := res["checksum"].(map[string]any)
		if !ok || checksum["algorithm"] != "sm3" {
			t.Fatalf("expected checksum in result, got %#v", res["checksum"])
		}
	}
}

func TestReportAuditStatisticsParsing(t *testing.T) {
	stateDir := t.TempDir()
	store := newReportStateStore(stateDir, "reportAudit-state.json")
	handler := reportAuditHandler(store)

	body := `{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"code": 0,
		"msg": "通过",
		"report": "{\"conclusion\":{\"passed\":true,\"risk_level\":\"LOW\",\"summary\":\"ok\",\"statistics\":{\"high\":0,\"medium\":1,\"low\":2}}}"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportAudit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	res := reportStateResult(store.get())
	stats, ok := res["statistics"].(map[string]any)
	if !ok || stats["medium"] != float64(1) || stats["low"] != float64(2) {
		t.Fatalf("expected parsed statistics in result, got %#v", res["statistics"])
	}
	if res["riskLevel"] != "LOW" {
		t.Fatalf("expected riskLevel LOW, got %v", res["riskLevel"])
	}
}
```

- [ ] **Step 2: 运行测试确认其因未实现而失败**

运行：`/snap/bin/go test -v -run "TestReportModelImportStrictValidationAndChecksum|TestReportAuditStatisticsParsing" ./internal/app/mock`
预期：FAIL

- [ ] **Step 3: 修改 `server.go` 实现校验与解析**

1. 修改 `reportStateResult`：
```go
func reportStateResult(state reportState) map[string]any {
	res := map[string]any{
		"received":    state.Received,
		"accepted":    state.Accepted,
		"receivedAt":  state.ReceivedAt,
		"dockerId":    state.DockerID,
		"requestId":   state.RequestID,
		"taskId":      state.TaskID,
		"code":        state.Code,
		"msg":         state.Msg,
		"report":      state.Report,
		"checksum":    state.Checksum,
		"contentType": state.ContentType,
		"statusCode":  state.StatusCode,
		"message":     state.Message,
		"rawBody":     state.RawBody,
	}
	if state.Report != "" {
		var parsed struct {
			Conclusion struct {
				Passed     bool           `json:"passed"`
				RiskLevel  string         `json:"risk_level"`
				Statistics map[string]any `json:"statistics"`
			} `json:"conclusion"`
		}
		if err := json.Unmarshal([]byte(state.Report), &parsed); err == nil {
			if parsed.Conclusion.RiskLevel != "" {
				res["riskLevel"] = parsed.Conclusion.RiskLevel
			}
			if parsed.Conclusion.Statistics != nil {
				res["statistics"] = parsed.Conclusion.Statistics
			}
		}
	}
	return res
}
```

2. 强化 `reportModelImportHandler` 校验逻辑：
- `strings.TrimSpace(state.DockerID) == ""` -> 返回 400 "缺少 dockerId"
- `strings.TrimSpace(state.RequestID) == ""` -> 返回 400 "缺少 requestId"
- `state.Code == 0` 时检查 `state.Checksum`，若为空或缺少 `size` / `algorithm` / `value` -> 返回 400 "导入成功时 checksum 不能为空且必须包含 size、algorithm 与 value"

3. 强化 `reportAuditHandler` 校验逻辑：
- `strings.TrimSpace(state.DockerID) == ""` -> 返回 400 "缺少 dockerId"
- `strings.TrimSpace(state.RequestID) == ""` -> 返回 400 "缺少 requestId"
- 校验 `state.Code` 必须为 0, 1, 或 2，否则返回 400 "code 必须为 0(通过)、1(未通过) 或 2(LLM不可用)"

- [ ] **Step 4: 重新运行测试验证通过**

运行：`/snap/bin/go test -v -run "TestReportModelImportStrictValidationAndChecksum|TestReportAuditStatisticsParsing" ./internal/app/mock`
预期：PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/app/mock/server.go internal/app/mock/server_test.go
git commit -m "feat(mock): 强化模型导入与代码审计结果上报的规约校验与字段解析"
```

---

### Task 2: 实现 `reportProgress`（训练进度上报）后端存储与接口

**Files:**
- Modify: `internal/app/mock/server.go`
- Test: `internal/app/mock/server_test.go`

- [ ] **Step 1: 编写测试用例验证进度上报与时间戳防逆序机制**

在 `internal/app/mock/server_test.go` 中新增测试用例：
```go
func TestReportProgressHandlingAndTimestampOrdering(t *testing.T) {
	stateDir := t.TempDir()
	store := newProgressStateStore(stateDir)
	handler := reportProgressHandler(store)

	// 1. 正常上报 35.5% 进度
	body1 := `{"dockerId":"docker-1","requestId":"req-1","taskId":"task-1","percent":35.5,"timestamp":"2026-09-15T09:30:00Z"}`
	req1 := httptest.NewRequest(http.MethodPost, "/v1/taa/reportProgress", strings.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	handler(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w1.Code)
	}
	if store.get().Percent != 35.5 {
		t.Fatalf("expected percent 35.5, got %v", store.get().Percent)
	}

	// 2. 乱序较早的时间戳到达，返回 200 但不回退已有进度
	bodyOlder := `{"dockerId":"docker-1","requestId":"req-1","taskId":"task-1","percent":20.0,"timestamp":"2026-09-15T09:20:00Z"}`
	req2 := httptest.NewRequest(http.MethodPost, "/v1/taa/reportProgress", strings.NewReader(bodyOlder))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}
	if store.get().Percent != 35.5 {
		t.Fatalf("percent should remain 35.5, got %v", store.get().Percent)
	}

	// 3. 更高进度与更新时间戳到达，成功更新
	bodyNewer := `{"dockerId":"docker-1","requestId":"req-1","taskId":"task-1","percent":80.0,"timestamp":"2026-09-15T09:40:00Z"}`
	req3 := httptest.NewRequest(http.MethodPost, "/v1/taa/reportProgress", strings.NewReader(bodyNewer))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	handler(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w3.Code)
	}
	if store.get().Percent != 80.0 {
		t.Fatalf("percent should update to 80.0, got %v", store.get().Percent)
	}
}
```

- [ ] **Step 2: 运行测试确认其失败**

运行：`/snap/bin/go test -v -run "TestReportProgressHandlingAndTimestampOrdering" ./internal/app/mock`
预期：FAIL（编译错误，函数未定义）

- [ ] **Step 3: 实现 `progressStateStore`、`reportProgressHandler` 以及 status/reset 端点**

在 `internal/app/mock/server.go` 中实现：
1. `progressState` 结构体及 `progressStateStore`（落盘至 `reportProgress-state.json`）。
2. `reportProgressHandler(store *progressStateStore) http.HandlerFunc`：
   - 校验 POST 方法与 Content-Type；
   - 反序列化 `reportProgressRequest`；
   - 校验 `dockerId`、`requestId` 必填，`percent` 必须在 0 到 100 之间，`timestamp` 符合 RFC3339；
   - 若校验失败，写入错误状态并返回 HTTP 400；
   - 比较 RFC3339 时间戳：若新时间戳早于当前已保存的时间戳，仍接受并返回 HTTP 200 `{"msg":"success","result":{"received":true},"error":0}`，但不覆盖已有的最新进度；
   - 若时间戳更新，则更新当前记录并持久化。
3. `progressStatusHandler(store *progressStateStore)` 与 `progressResetHandler(store *progressStateStore)`。
4. 在 `NewServer` 中注册：
   ```go
   mux.HandleFunc("/v1/taa/reportProgress", reportProgressHandler(progressStore))
   mux.HandleFunc("/api/reportProgress/status", progressStatusHandler(progressStore))
   mux.HandleFunc("/api/reportProgress/reset", progressResetHandler(progressStore))
   ```

- [ ] **Step 4: 重新运行测试验证通过**

运行：`/snap/bin/go test -v -run "TestReportProgressHandlingAndTimestampOrdering" ./internal/app/mock`
预期：PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/app/mock/server.go internal/app/mock/server_test.go
git commit -m "feat(mock): 实现训练进度上报 reportProgress 接口及防逆序状态存储"
```

---

### Task 3: 实现 `modelLog`（任务终端日志）后端存储、去重与接口

**Files:**
- Modify: `internal/app/mock/server.go`
- Test: `internal/app/mock/server_test.go`

- [ ] **Step 1: 编写测试用例验证终端日志接收、去重与排序**

在 `internal/app/mock/server_test.go` 中新增测试用例：
```go
func TestModelLogDeduplicationAndRingBuffer(t *testing.T) {
	stateDir := t.TempDir()
	store := newModelLogStore(stateDir, 100) // 容量 100
	handler := modelLogHandler(store)

	// 1. 发送一批日志 seq 1..2
	body1 := `{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"seqStart": 1,
		"entries": [
			{"seq": 1, "message": "starting task"},
			{"seq": 2, "message": "epoch=1 loss=0.5"}
		]
	}`
	req1 := httptest.NewRequest(http.MethodPost, "/v1/taa/modelLog", strings.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	handler(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w1.Code)
	}

	state := store.get()
	if len(state.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(state.Entries))
	}
	if state.Entries[0].Seq != 1 || state.Entries[1].Seq != 2 {
		t.Fatalf("unexpected entries order: %#v", state.Entries)
	}

	// 2. 发送重复日志 seq 2，并带有新日志 seq 3（模拟重传）
	body2 := `{
		"dockerId": "docker-1",
		"requestId": "req-1",
		"seqStart": 2,
		"entries": [
			{"seq": 2, "message": "epoch=1 loss=0.5"},
			{"seq": 3, "message": "epoch=1 acc=0.9"}
		]
	}`
	req2 := httptest.NewRequest(http.MethodPost, "/v1/taa/modelLog", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}

	stateAfter := store.get()
	if len(stateAfter.Entries) != 3 {
		t.Fatalf("expected 3 entries after deduplication, got %d", len(stateAfter.Entries))
	}
	if stateAfter.Entries[2].Seq != 3 {
		t.Fatalf("entry 3 seq mismatch: %#v", stateAfter.Entries[2])
	}
}
```

- [ ] **Step 2: 运行测试确认其失败**

运行：`/snap/bin/go test -v -run "TestModelLogDeduplicationAndRingBuffer" ./internal/app/mock`
预期：FAIL

- [ ] **Step 3: 实现 `modelLogStore`、`modelLogHandler` 及 status/reset 端点**

在 `internal/app/mock/server.go` 中实现：
1. `modelLogEntry` 与 `modelLogState` 结构体：
   ```go
   type modelLogEntry struct {
       Seq       uint64 `json:"seq"`
       Message   string `json:"message"`
       Timestamp string `json:"timestamp"`
   }
   type modelLogState struct {
       DockerID   string          `json:"dockerId"`
       RequestID  string          `json:"requestId"`
       TaskID     string          `json:"taskId"`
       TotalCount int             `json:"totalCount"`
       LastSeq    uint64          `json:"lastSeq"`
       Entries    []modelLogEntry `json:"entries"`
   }
   ```
2. `modelLogStore`：
   - 互斥锁并发安全；
   - 内存维护 `seen map[string]struct{}`（key 格式 `dockerId:requestId:seq`）；
   - 按 seq 递增顺序插入切片；
   - 最大缓冲容量（默认 2000 条，测试可自定义）；
   - 变更时异步或同步写入 `stateDir/modelLog-state.json`。
3. `modelLogHandler(store *modelLogStore) http.HandlerFunc`：
   - 校验 POST 方法与 Content-Type；
   - 校验 `dockerId`、`requestId` 必填，`entries` 不能为空；
   - 批量排重添加条目，返回 HTTP 200 `{"msg":"success","result":{"received":true},"error":0}`。
4. `modelLogStatusHandler(store *modelLogStore)` 与 `modelLogResetHandler(store *modelLogStore)`。
5. 在 `NewServer` 中注册：
   ```go
   mux.HandleFunc("/v1/taa/modelLog", modelLogHandler(modelLogStore))
   mux.HandleFunc("/api/modelLog/status", modelLogStatusHandler(modelLogStore))
   mux.HandleFunc("/api/modelLog/reset", modelLogResetHandler(modelLogStore))
   ```

- [ ] **Step 4: 重新运行测试验证通过**

运行：`/snap/bin/go test -v -run "TestModelLogDeduplicationAndRingBuffer" ./internal/app/mock`
预期：PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/app/mock/server.go internal/app/mock/server_test.go
git commit -m "feat(mock): 实现任务终端日志 modelLog 接口、去重存储与状态查询"
```

---

### Task 4: 实现 `stopTraining` 代理调用与请求体日志记录

**Files:**
- Modify: `internal/app/mock/server.go`
- Test: `internal/app/mock/server_test.go`

- [ ] **Step 1: 编写测试用例验证 `stopTraining` 代理转发与日志记录**

在 `internal/app/mock/server_test.go` 中新增测试用例：
```go
func TestTAAStopTrainingProxyAndLogging(t *testing.T) {
	// 启动模拟真实 TAA 服务的后端 server
	called := false
	taaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/taa/stopTraining" && r.Method == http.MethodPost {
			called = true
			writeEnvelope(w, http.StatusOK, "训练任务已中止", nil, 0)
			return
		}
		http.NotFound(w, r)
	}))
	defer taaServer.Close()

	requestLogs.reset()
	handler := taaStopTrainingHandler(taaServer.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/taa/stopTraining", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("expected TAA /v1/taa/stopTraining to be called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var res apiResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response error: %v", err)
	}
	if res.Msg != "训练任务已中止" {
		t.Fatalf("expected msg 训练任务已中止, got %q", res.Msg)
	}

	// 验证请求体日志中已记录此请求
	logs := requestLogs.list()
	found := false
	for _, l := range logs {
		if l.Path == "/v1/taa/stopTraining" && l.Component == "taa-stopTraining" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected requestLogs to contain /v1/taa/stopTraining")
	}
}
```

- [ ] **Step 2: 运行测试确认其失败**

运行：`/snap/bin/go test -v -run "TestTAAStopTrainingProxyAndLogging" ./internal/app/mock`
预期：FAIL

- [ ] **Step 3: 实现 `taaStopTrainingHandler` 并更新 `requestComponentFromPath`**

1. 修改 `requestComponentFromPath`：
```go
case strings.HasPrefix(path, "/v1/taa/stopTraining") || strings.HasPrefix(path, "/api/taa/stopTraining"):
	return "taa-stopTraining"
case strings.HasPrefix(path, "/v1/taa/modelLog") || strings.HasPrefix(path, "/api/modelLog"):
	return "modelLog"
case strings.HasPrefix(path, "/v1/taa/reportProgress") || strings.HasPrefix(path, "/api/reportProgress"):
	return "reportProgress"
```

2. 实现 `taaStopTrainingHandler(taaAddr string) http.HandlerFunc`：
```go
func taaStopTrainingHandler(taaAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method != http.MethodPost {
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}
		if taaAddr == "" {
			writeEnvelope(w, http.StatusBadGateway, "未配置 TAA 目标地址（-taa-target 或 TAA_POD）", nil, http.StatusBadGateway)
			return
		}
		reqID := fmt.Sprintf("req-stop-%d", time.Now().UnixNano())
		targetURL := fmt.Sprintf("%s/v1/taa/stopTraining", strings.TrimRight(taaAddr, "/"))
		
		logRequestWithID(requestLogs, reqID, "out", "taa-stopTraining", http.MethodPost, "/v1/taa/stopTraining", http.StatusOK, "", []byte("{}"))

		httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader([]byte("{}")))
		if err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "创建请求失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}
		httpReq.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			logRequestWithID(requestLogs, reqID, "in", "taa-stopTraining", http.MethodPost, "/v1/taa/stopTraining", http.StatusBadGateway, "TAA 请求失败: "+err.Error(), nil)
			writeEnvelope(w, http.StatusBadGateway, "TAA 请求失败: "+err.Error(), nil, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		logRequestWithID(requestLogs, reqID, "in", "taa-stopTraining", http.MethodPost, "/v1/taa/stopTraining", resp.StatusCode, string(respBody), respBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
	}
}
```

3. 在 `NewServer` 中注册：
```go
mux.HandleFunc("/api/taa/stopTraining", taaStopTrainingHandler(taaAddr))
```

- [ ] **Step 4: 重新运行测试验证通过**

运行：`/snap/bin/go test -v -run "TestTAAStopTrainingProxyAndLogging" ./internal/app/mock`
预期：PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/app/mock/server.go internal/app/mock/server_test.go
git commit -m "feat(mock): 实现中止训练接口代理 taaStopTraining 及请求日志捕获"
```

---

### Task 5: 前端 Web 控制台（`index.html`）界面整合与交互实现

**Files:**
- Modify: `internal/app/mock/index.html`
- Test: `internal/app/mock/server_test.go`

- [ ] **Step 1: 在 `server_test.go` 中扩充前端 DOM 节点与关键函数断言**

在 `TestIndexShowsTrainingReportAndResourceInfoModules` 中补充断言：
```go
for _, want := range []string{
	"reportProgressBar", "reportProgressPercent", "reportProgressStatusText", "resetProgressBtn",
	"stopTrainingBtn", "testStopTraining", "stopTrainingStatusBox", "stopTrainingStatusText",
	"card-modelLog", "modelLogOutput", "modelLogCount", "modelLogLastSeq", "clearModelLogs", "fetchModelLogs",
	"/v1/taa/stopTraining", "/v1/taa/modelLog", "/v1/taa/reportProgress",
} {
	if !strings.Contains(indexHTML, want) {
		t.Fatalf("index.html missing expected element/function: %q", want)
	}
}
```

- [ ] **Step 2: 运行测试确认其失败**

运行：`/snap/bin/go test -v -run "TestIndexShowsTrainingReportAndResourceInfoModules" ./internal/app/mock`
预期：FAIL

- [ ] **Step 3: 更新 `index.html` 视图与交互逻辑**

1. **训练与控制卡片**：
   - 在卡片 `card-reportRes` 头部加入：
     - 中止训练按钮：`<button id="stopTrainingBtn" class="danger" onclick="testStopTraining()">🛑 中止训练</button>`；
     - 中止结果回显状态：`stopTrainingStatusBox`；
   - 插入动态进度条区块：
     - `<div class="progress-track"><div id="reportProgressBar" class="progress-fill" style="width:0%"></div></div>`
     - `<span id="reportProgressPercent">0%</span>`、`<span id="reportProgressStatusText">等待进度上报...</span>`、重置按钮。
2. **模型导入与审计弹窗展示升级**：
   - `buildReportModelImportBodyPreview`：若有 `checksum`，高亮展示 `checksum` 概要；
   - `buildReportAuditBodyPreview`：若有 `statistics` 与 `risk_level`，提取并在弹窗顶部渲染高中低三级风险指标徽章。
3. **新增模型终端日志面板**：
   - 结构采用终端样式：标题“模型终端日志（/v1/taa/modelLog）”，包含自动刷新、暂停、清空操作；
   - 条目按 seq 升序展示，支持自动滚屏。
4. **请求体过滤下拉框**：
   - 补充 `<option value="/v1/taa/stopTraining">/v1/taa/stopTraining（中止任务）</option>`。
5. **轮询机制**：
   - 定时刷新进度与模型日志（每 2 秒），与现有定时器集成。

- [ ] **Step 4: 重新运行测试验证通过**

运行：`/snap/bin/go test -v -run "TestIndexShowsTrainingReportAndResourceInfoModules" ./internal/app/mock`
预期：PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/app/mock/index.html internal/app/mock/server_test.go
git commit -m "feat(mock): Web控制台增加训练进度条、中止训练控制及模型终端日志视窗"
```

---

### Task 6: 全面回归测试与端到端联调验证

**Files:**
- Test: `internal/app/mock/server_test.go`

- [ ] **Step 1: 运行 mock 包所有单元测试**

运行：`/snap/bin/go test -v ./internal/app/mock/...`
预期：全部 PASS，代码覆盖率与预期行为一致。

- [ ] **Step 2: 运行整个项目的相关测试**

运行：`/snap/bin/go test -v ./internal/controller/...`
预期：原有 controller 路由测试正常通过无回归缺陷。

- [ ] **Step 3: 启动 mock 服务进行真实 HTTP 连通与界面渲染联调**

在后台启动 mock 服务，使用 curl 发送 mock 模拟请求：
1. 发送 `POST /v1/taa/reportProgress` 验证控制台进度百分比变更；
2. 发送 `POST /v1/taa/modelLog` 验证控制台模型日志终端实时渲染与去重；
3. 发送 `POST /v1/taa/reportModelImport` 验证 checksum 正常展示；
4. 发送 `POST /v1/taa/reportAudit` 验证 statistics 三级风险归类正常展示；
5. 调用 `POST /api/taa/stopTraining` 验证请求被记入请求体日志。

- [ ] **Step 4: 提交最终功能代码与测试记录**

```bash
git add internal/app/mock/
git commit -m "test(mock): 完善五大接口的端到端联调与单元测试覆盖"
```
