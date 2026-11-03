# platform-mock 控制台 TEE-LLM 面板实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 platform-mock 内嵌控制台新增一张 TEE-LLM 实例卡片，展示注册、自检、心跳、报告大小、最近来源与运行日志，并让重置真正清空全部 LLM 状态。

**Architecture:** 后端在 `llmState` 里增加一份最近来源列表（最多 5 个 `dockerId`），由 register / heartbeat / log 三个入口在写入主状态时顺带更新；`/api/llm/status` 多返回一个 `sources` 字段，`/api/llm/reset` 改为同时清空日志 store。前端新增独立的 `static/js/llm.js` 承载全部渲染逻辑，卡片挂在 `PollingManager` 的中速轮询上，复用现有卡片、状态灯、抽屉与 toast，不改 CSS。

**Tech Stack:** Go 1.22 标准库（`net/http`、`encoding/json`、`sort`、`time`）、原生 JavaScript（无构建步骤，`embed.FS` 直接托管）、`httptest`。

**Spec:** `.claude/specs/2026-11-03-platform-mock-llm-panel-design.md`

---

## 文件结构

| 文件 | 职责 |
| --- | --- |
| `tools/platform-mock/internal/llm_state.go` | `llmSource` 类型、来源列表的更新/排序/淘汰、可注入时钟、重置语义 |
| `tools/platform-mock/internal/llm_state_test.go`（新增） | 来源去重、计数、上限、排序、重置 |
| `tools/platform-mock/internal/handlers_llm.go` | 三个入口 touch 来源；status 返回 `sources`；reset 同时清日志 |
| `tools/platform-mock/internal/handlers_llm_test.go` | 上述行为的 handler 级测试 |
| `tools/platform-mock/internal/server.go` | 调整 handler 调用签名 |
| `tools/platform-mock/internal/static/index.html` | 新卡片 `#card-llm`、公钥弹窗、`llm.js` 脚本标签 |
| `tools/platform-mock/internal/static/js/llm.js`（新增） | 状态灯、来源列表、日志渲染、刷新/重置/弹窗 |
| `tools/platform-mock/internal/static/js/api.js` | 中速轮询里调用 `refreshLLMStatus()` |
| `tools/platform-mock/internal/static/js/app.js` | 启动时初始化面板并拉一次状态 |
| `tools/platform-mock/README.md`、`CHANGELOG.md` | 文档 |

---

### Task 1: 后端来源列表

**Files:**
- Modify: `tools/platform-mock/internal/llm_state.go`
- Create: `tools/platform-mock/internal/llm_state_test.go`

- [ ] **Step 1: 写失败测试**

创建 `tools/platform-mock/internal/llm_state_test.go`：

```go
package mock

import (
	"fmt"
	"testing"
	"time"
)

func TestLLMSourcesTrackDistinctDockerIDs(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	store.setRegister(llmRegisterState{Received: true, DockerID: "taa-teellm", ReceivedAt: time.Now().Format(time.RFC3339)})
	store.recordHeartbeat(llmHeartbeatState{DockerID: "taa-teellm", Count: 1})
	store.touchLog("taa-teellm")

	sources := store.get().Sources
	if len(sources) != 1 {
		t.Fatalf("len(sources) = %d, want 1: %+v", len(sources), sources)
	}
	src := sources[0]
	if src.DockerID != "taa-teellm" {
		t.Errorf("dockerId = %q", src.DockerID)
	}
	if src.Registers != 1 || src.Heartbeats != 1 || src.Logs != 1 {
		t.Errorf("counters = %+v", src)
	}
	if src.LastEvent != llmEventLog {
		t.Errorf("lastEvent = %q, want %q", src.LastEvent, llmEventLog)
	}
}

func TestLLMSourcesCapAtFiveAndDropOldest(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	base := time.Unix(1700000000, 0)
	for i := 0; i < 7; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		store.now = func() time.Time { return at }
		store.recordHeartbeat(llmHeartbeatState{DockerID: fmt.Sprintf("llm-%d", i), Count: 1})
	}

	sources := store.get().Sources
	if len(sources) != maxLLMSources {
		t.Fatalf("len(sources) = %d, want %d", len(sources), maxLLMSources)
	}
	if sources[0].DockerID != "llm-6" {
		t.Errorf("newest = %q, want llm-6", sources[0].DockerID)
	}
	for _, src := range sources {
		if src.DockerID == "llm-0" || src.DockerID == "llm-1" {
			t.Errorf("evicted source %q is still present", src.DockerID)
		}
	}
}

func TestLLMResetClearsSources(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	store.recordHeartbeat(llmHeartbeatState{DockerID: "taa-teellm", Count: 1})
	store.reset()
	if got := store.get().Sources; len(got) != 0 {
		t.Fatalf("sources after reset = %+v, want empty", got)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./tools/platform-mock/internal/ -run 'TestLLMSources|TestLLMResetClearsSources' -count=1`
Expected: 编译失败，`undefined: llmEventLog`、`undefined: maxLLMSources`、`store.touchLog undefined`、`store.now undefined`。

- [ ] **Step 3: 实现来源列表**

在 `tools/platform-mock/internal/llm_state.go` 中：

导入增加 `sort` 与 `time`：

```go
import (
	"log"
	"os"
	"sort"
	"sync"
	"time"
)
```

在 `llmState` 之前加入类型与常量：

```go
// maxLLMSources bounds the recent-source list. Five is enough to see which
// instances have been talking without turning the panel into an audit log.
const maxLLMSources = 5

// LastEvent values recorded in llmSource.
const (
	llmEventRegister  = "register"
	llmEventHeartbeat = "heartbeat"
	llmEventLog       = "log"
)

// llmSource records that a dockerId has reported to this mock. It exists only
// for observability: the registration state itself stays single-instance, so a
// second dockerId overwrites the panel while leaving a trace here.
type llmSource struct {
	DockerID   string `json:"dockerId"`
	FirstSeen  string `json:"firstSeen"`
	LastSeen   string `json:"lastSeen"`
	LastEvent  string `json:"lastEvent"`
	Registers  uint64 `json:"registers"`
	Heartbeats uint64 `json:"heartbeats"`
	Logs       uint64 `json:"logs"`
}
```

`llmState` 增加字段：

```go
type llmState struct {
	Register  llmRegisterState  `json:"register"`
	Heartbeat llmHeartbeatState `json:"heartbeat"`
	Sources   []llmSource       `json:"sources"`
}
```

`llmStateStore` 增加可注入时钟：

```go
type llmStateStore struct {
	mu    sync.RWMutex
	path  string
	now   func() time.Time
	state llmState
}

func newLLMStateStore(stateDir string) *llmStateStore {
	store := &llmStateStore{
		path: defaultStateFile(stateDir, "llm-state.json"),
		now:  time.Now,
	}
	store.load()
	return store
}
```

`get()` 保证 `Sources` 非 nil：

```go
func (s *llmStateStore) get() llmState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cpy := s.state
	if cpy.Sources == nil {
		cpy.Sources = []llmSource{}
	} else {
		cpy.Sources = append([]llmSource(nil), cpy.Sources...)
	}
	return cpy
}
```

`setRegister` / `recordHeartbeat` 在同一把锁里 touch 来源：

```go
func (s *llmStateStore) setRegister(state llmRegisterState) {
	s.mu.Lock()
	s.state.Register = state
	s.touchSourceLocked(state.DockerID, llmEventRegister)
	snapshot := s.state
	s.mu.Unlock()
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

func (s *llmStateStore) recordHeartbeat(state llmHeartbeatState) {
	s.mu.Lock()
	s.state.Heartbeat = state
	s.touchSourceLocked(state.DockerID, llmEventHeartbeat)
	snapshot := s.state
	s.mu.Unlock()
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

// touchLog records that a log batch arrived. Logs live in their own store, so
// this only keeps the recent-source list current.
func (s *llmStateStore) touchLog(dockerID string) {
	s.mu.Lock()
	s.touchSourceLocked(dockerID, llmEventLog)
	snapshot := s.state
	s.mu.Unlock()
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

// touchSourceLocked upserts one dockerId and re-sorts newest-first. Empty ids
// are rejected by the handlers already, but guarding here keeps a malformed
// state file from producing a nameless row.
func (s *llmStateStore) touchSourceLocked(dockerID, event string) {
	if dockerID == "" {
		return
	}
	now := s.now().Format(time.RFC3339)
	for i := range s.state.Sources {
		src := &s.state.Sources[i]
		if src.DockerID != dockerID {
			continue
		}
		src.LastSeen = now
		src.LastEvent = event
		switch event {
		case llmEventRegister:
			src.Registers++
		case llmEventHeartbeat:
			src.Heartbeats++
		case llmEventLog:
			src.Logs++
		}
		s.sortSourcesLocked()
		return
	}
	src := llmSource{
		DockerID:  dockerID,
		FirstSeen: now,
		LastSeen:  now,
		LastEvent: event,
	}
	switch event {
	case llmEventRegister:
		src.Registers = 1
	case llmEventHeartbeat:
		src.Heartbeats = 1
	case llmEventLog:
		src.Logs = 1
	}
	s.state.Sources = append(s.state.Sources, src)
	s.sortSourcesLocked()
	if len(s.state.Sources) > maxLLMSources {
		s.state.Sources = s.state.Sources[:maxLLMSources]
	}
}

// sortSourcesLocked orders newest first. The dockerId is the tie-break so an
// equal timestamp cannot reshuffle the list between request and render.
func (s *llmStateStore) sortSourcesLocked() {
	sort.SliceStable(s.state.Sources, func(i, j int) bool {
		ti, tj := s.state.Sources[i], s.state.Sources[j]
		if ti.LastSeen != tj.LastSeen {
			return ti.LastSeen > tj.LastSeen
		}
		return ti.DockerID < tj.DockerID
	})
}
```

`reset()` 清空来源：

```go
func (s *llmStateStore) reset() {
	s.mu.Lock()
	s.state = llmState{Sources: []llmSource{}}
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, llmState{Sources: []llmSource{}}); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./tools/platform-mock/internal/ -run 'TestLLMSources|TestLLMResetClearsSources' -count=1`
Expected: `ok  taa/tools/platform-mock/internal`

- [ ] **Step 5: 提交**

```bash
git add tools/platform-mock/internal/llm_state.go tools/platform-mock/internal/llm_state_test.go
git commit -m "feat(platform-mock): track the recent dockerIds reporting to the LLM endpoints"
```

---

### Task 2: handler 接线与重置语义

**Files:**
- Modify: `tools/platform-mock/internal/handlers_llm.go`
- Modify: `tools/platform-mock/internal/handlers_llm_test.go`
- Modify: `tools/platform-mock/internal/server.go`

- [ ] **Step 1: 写失败测试**

在 `tools/platform-mock/internal/handlers_llm_test.go` 末尾追加：

```go
func TestLLMEndpointsRecordSources(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	logs := newTaaLogStoreAt(t.TempDir()+"/llm-log-state.json", 2000)

	register := llmRegisterHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/v1/llm/register",
		strings.NewReader(`{"dockerId":"taa-teellm","attestation":"AQID"}`))
	rec := httptest.NewRecorder()
	register(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
	}

	heartbeat := llmHeartbeatHandler(store)
	req = httptest.NewRequest(http.MethodPost, "/v1/llm/heartbeat",
		strings.NewReader(`{"dockerId":"taa-teellm","timestamp":"1730000030"}`))
	rec = httptest.NewRecorder()
	heartbeat(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, body = %s", rec.Code, rec.Body.String())
	}

	logHandler := llmLogHandler(logs, store)
	body := `{"dockerId":"taa-teellm","requestId":"system","entries":[{"seq":1,"message":"ready"}]}`
	req = httptest.NewRequest(http.MethodPost, "/v1/llm/log", strings.NewReader(body))
	rec = httptest.NewRecorder()
	logHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("log status = %d, body = %s", rec.Code, rec.Body.String())
	}

	sources := store.get().Sources
	if len(sources) != 1 {
		t.Fatalf("sources = %+v, want one entry", sources)
	}
	if sources[0].Registers != 1 || sources[0].Heartbeats != 1 || sources[0].Logs != 1 {
		t.Fatalf("source counters = %+v", sources[0])
	}
	if sources[0].LastEvent != llmEventLog {
		t.Errorf("lastEvent = %q, want %q", sources[0].LastEvent, llmEventLog)
	}
}

func TestLLMStatusReportsSources(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	logs := newTaaLogStoreAt(t.TempDir()+"/llm-log-state.json", 2000)
	store.recordHeartbeat(llmHeartbeatState{DockerID: "taa-teellm", Count: 1})

	req := httptest.NewRequest(http.MethodGet, "/api/llm/status", nil)
	rec := httptest.NewRecorder()
	llmStatusHandler(store, logs)(rec, req)

	var resp struct {
		Result struct {
			Sources []llmSource `json:"sources"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v, body = %s", err, rec.Body.String())
	}
	if len(resp.Result.Sources) != 1 || resp.Result.Sources[0].DockerID != "taa-teellm" {
		t.Fatalf("sources = %+v", resp.Result.Sources)
	}
}

func TestLLMResetClearsLogsAndSources(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	logs := newTaaLogStoreAt(t.TempDir()+"/llm-log-state.json", 2000)
	logs.addEntries("taa-teellm", "system", "", []taaLogEntry{{Seq: 1, Message: "ready"}})
	store.setRegister(llmRegisterState{Received: true, DockerID: "taa-teellm"})

	req := httptest.NewRequest(http.MethodPost, "/api/llm/reset", nil)
	rec := httptest.NewRecorder()
	llmResetHandler(store, logs)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if state := store.get(); state.Register.Received || len(state.Sources) != 0 {
		t.Fatalf("state after reset = %+v", state)
	}
	if got := logs.get().TotalCount; got != 0 {
		t.Fatalf("log totalCount after reset = %d, want 0", got)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./tools/platform-mock/internal/ -run 'TestLLMEndpointsRecordSources|TestLLMStatusReportsSources|TestLLMResetClearsLogsAndSources' -count=1`
Expected: 编译失败 —— `not enough arguments in call to llmLogHandler`（以及 `llmResetHandler`）。

- [ ] **Step 3: 实现 handler 改动**

`handlers_llm.go` 中 `llmLogHandler` 增加状态参数并在写入日志后更新来源：

```go
func llmLogHandler(store *taaLogStore, state *llmStateStore) http.HandlerFunc {
```

在其 `store.addEntries(...)` 之后加一行：

```go
		store.addEntries(req.DockerID, req.RequestID, req.TaskID, req.Entries)
		state.touchLog(req.DockerID)
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"received": true}, 0)
```

`llmStatusHandler` 返回 `sources`：

```go
// llmStatusHandler exposes what the LLM instance last reported.
func llmStatusHandler(state *llmStateStore, logs *taaLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		snapshot := state.get()
		writeJSON(w, http.StatusOK, map[string]any{
			"register":  snapshot.Register,
			"heartbeat": snapshot.Heartbeat,
			"logs":      logs.get(),
			"sources":   snapshot.Sources,
		})
	}
}
```

`llmResetHandler` 同时清日志：

```go
// llmResetHandler clears the record so a test can start from a clean panel.
// The log store is part of what the panel shows, so leaving it behind would
// contradict the button's meaning.
func llmResetHandler(state *llmStateStore, logs *taaLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeLLMResponse(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}
		state.reset()
		logs.reset()
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"reset": true}, 0)
	}
}
```

`server.go` 调整两处调用：

```go
	mux.HandleFunc("/v1/llm/log", llmLogHandler(llmLogStore, llmState))
	mux.HandleFunc("/api/llm/status", llmStatusHandler(llmState, llmLogStore))
	mux.HandleFunc("/api/llm/reset", llmResetHandler(llmState, llmLogStore))
```

既有测试 `TestLLMLogAcceptsPlaintextEntries`（`handlers_llm_test.go:54`）也使用了旧签名，一并改：

```go
func TestLLMLogAcceptsPlaintextEntries(t *testing.T) {
	logStore := newTaaLogStoreAt(t.TempDir()+"/llm-log-state.json", 2000)
	stateStore := newLLMStateStore(t.TempDir())
	handler := llmLogHandler(logStore, stateStore)
```

- [ ] **Step 4: 运行全部 platform-mock 测试**

Run: `go test ./tools/platform-mock/... -count=1`
Expected: 全部 `ok`。

- [ ] **Step 5: 提交**

```bash
git add tools/platform-mock/internal/handlers_llm.go tools/platform-mock/internal/server.go tools/platform-mock/internal/handlers_llm_test.go
git commit -m "feat(platform-mock): expose LLM recent sources and reset its log store"
```

---

### Task 3: 控制台卡片与弹窗

**Files:**
- Modify: `tools/platform-mock/internal/static/index.html`

- [ ] **Step 1: 插入卡片**

在「平台注册」卡片结束标签 `</section>`（`id="card-attestation"` 那张，约第 138 行）之后、
`<!-- ─── 训练流程（平台 → TAA）接口测试 ─── -->` 注释之前插入：

```html
  <!-- TEE-LLM: a separate instance kind. It reports in plaintext on /v1/llm/*
       and keeps its own state, so this panel is independent of the TAA
       instance selector. TEE only: the FHE path runs no code audit. -->
  <section class="card" id="card-llm" data-console="tee" style="display:flex; flex-direction:column; margin-bottom:24px;">
    <div class="card-head" style="margin-bottom:12px; padding-bottom:10px; flex-wrap:wrap; gap:12px;">
      <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
        <h2 style="margin:0;">TEE-LLM 实例</h2>
        <div id="llmStatusPill" class="status-pill pending" style="font-size:13px;">
          <span id="llmStatusDot" class="dot pill-dot pending"></span>
          <span id="llmStatusText">等待 TEE-LLM 注册</span>
        </div>
        <span id="llmHeartbeatText" class="muted" style="font-size:12.5px;"></span>
      </div>
      <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
        <button type="button" id="llmPublicKeyBtn" class="secondary" onclick="openLLMPublicKeyModal()" disabled>公钥</button>
        <button type="button" id="llmRegisterBodyBtn" class="secondary" onclick="openLLMRegisterBody()" disabled>注册报文</button>
        <button type="button" class="secondary" onclick="refreshLLMStatus()">刷新</button>
        <button type="button" class="secondary" onclick="resetLLMStatus()">重置</button>
      </div>
    </div>

    <div style="display:flex; align-items:center; gap:18px; flex-wrap:wrap; font-size:13px; margin-bottom:10px;">
      <span>dockerId: <code id="llmDockerId">—</code></span>
      <span>自检: <span id="llmVerified">—</span></span>
      <span>报告: <span id="llmAttestationSize">—</span></span>
      <span>注册于: <span id="llmRegisteredAt">—</span></span>
    </div>

    <details id="llmSourcesBox" style="display:none; margin-bottom:10px;">
      <summary style="cursor:pointer; font-size:13px; font-weight:650;">最近来源 (<span id="llmSourcesCount">0</span>)</summary>
      <div id="llmSourcesList" style="margin-top:8px; display:flex; flex-direction:column; gap:4px; font-size:12.5px;"></div>
    </details>

    <details id="llmLogBox">
      <summary style="cursor:pointer; font-size:13px; font-weight:650;">运行日志</summary>
      <div style="display:flex; align-items:center; justify-content:space-between; gap:8px; margin:8px 0 6px;">
        <span id="llmLogCount" class="muted" style="font-size:12.5px;">0 条日志</span>
        <button type="button" id="llmLogPauseBtn" class="secondary" style="padding:2px 10px; font-size:12px;" onclick="toggleLLMLogPause()">暂停</button>
      </div>
      <div id="llmLogOutput" style="max-height:240px; overflow:auto; background:var(--panel-sub); border:1px solid var(--line); border-radius:8px; padding:8px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px;"></div>
    </details>
  </section>
```

- [ ] **Step 2: 插入公钥弹窗**

在 `#taaPublicKeyModal` 结束标签之后（`<div id="resourceInfoModal"` 之前）插入：

```html
<div id="llmPublicKeyModal" class="modal-overlay" aria-hidden="true" onclick="if (event.target === this) closeLLMPublicKeyModal();">
  <div class="modal" style="width:min(680px, 94%); display:flex; flex-direction:column;" role="dialog" aria-modal="true" aria-labelledby="llmPublicKeyModalTitle">
    <div class="modal-head">
      <h3 id="llmPublicKeyModalTitle" style="margin:0;">TEE-LLM 注册公钥</h3>
      <div class="modal-actions">
        <button type="button" class="secondary" onclick="closeLLMPublicKeyModal()">关闭</button>
      </div>
    </div>
    <div style="padding:14px 16px; overflow:auto;">
      <textarea id="llmPublicKeyText" readonly style="min-height:140px; font-size:12px; font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; line-height:1.45; cursor:text; background:rgba(37,99,235,.04); border-radius:8px; margin:0;" onclick="this.select();"></textarea>
    </div>
  </div>
</div>
```

- [ ] **Step 3: 引入脚本**

在 `<script src="/static/js/logs.js"></script>` 之后、`<script src="/static/js/app.js"></script>` 之前加：

```html
<script src="/static/js/llm.js"></script>
```

- [ ] **Step 4: 确认页面结构合法**

Run: `grep -c 'id="card-llm"' tools/platform-mock/internal/static/index.html && grep -c 'js/llm.js' tools/platform-mock/internal/static/index.html`
Expected: 输出 `1` 和 `1`。

- [ ] **Step 5: 提交**

```bash
git add tools/platform-mock/internal/static/index.html
git commit -m "feat(platform-mock): add the TEE-LLM instance card to the console"
```

---

### Task 4: 前端渲染逻辑

**Files:**
- Create: `tools/platform-mock/internal/static/js/llm.js`

- [ ] **Step 1: 创建 `llm.js`**

```javascript
// ── TEE-LLM instance panel ──
//
// The LLM is a separate instance kind: it reports in plaintext on /v1/llm/* and
// keeps its own state, so nothing here uses the ?dockerId= selection.

// Three missed heartbeats (30s each) mark the instance offline, matching the
// platform-side rule the LLM spec documents.
const LLM_OFFLINE_AFTER_MS = 90 * 1000;

let llmLogPaused = false;
let llmLogAutoScroll = true;
let lastLLMState = null;

function llmRelativeTime(iso) {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const diff = Date.now() - t;
  if (diff < 1000) return '刚刚';
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s 前`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m 前`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h 前`;
  return `${Math.floor(h / 24)}d 前`;
}

function llmTimeOfDay(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '—';
  return new Date(t).toLocaleTimeString('zh-CN', { hour12: false });
}

function renderLLMStatus(payload) {
  lastLLMState = payload || null;
  const reg = (payload && payload.register) || {};
  const hb = (payload && payload.heartbeat) || {};

  let cls = 'pending';
  let label = '等待 TEE-LLM 注册';
  if (reg.received) {
    const lastHeartbeat = hb.receivedAt ? Date.parse(hb.receivedAt) : NaN;
    if (Number.isNaN(lastHeartbeat)) {
      label = '已注册，等待心跳';
    } else if (Date.now() - lastHeartbeat <= LLM_OFFLINE_AFTER_MS) {
      cls = 'ok';
      label = '在线';
    } else {
      cls = 'bad';
      label = '离线';
    }
  }

  const dot = document.getElementById('llmStatusDot');
  if (dot) dot.className = `dot pill-dot ${cls}`;
  const pill = document.getElementById('llmStatusPill');
  if (pill) pill.className = `status-pill ${cls}`;
  const statusText = document.getElementById('llmStatusText');
  if (statusText) statusText.textContent = label;

  const hbText = document.getElementById('llmHeartbeatText');
  if (hbText) {
    hbText.textContent = hb.receivedAt
      ? `心跳 ${hb.count || 0} 次 · ${llmRelativeTime(hb.receivedAt)}`
      : '';
  }

  const setText = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };
  setText('llmDockerId', reg.dockerId || '—');
  setText('llmVerified', reg.received ? (reg.verifiedPass ? '✓' : '✗') : '—');
  setText('llmAttestationSize', reg.received ? `${reg.attestationSize || 0} B` : '—');
  setText('llmRegisteredAt', reg.received ? llmTimeOfDay(reg.receivedAt) : '—');

  const pubKeyBtn = document.getElementById('llmPublicKeyBtn');
  if (pubKeyBtn) pubKeyBtn.disabled = !(reg.received && reg.taaPublicKey);
  const bodyBtn = document.getElementById('llmRegisterBodyBtn');
  if (bodyBtn) bodyBtn.disabled = !reg.received;

  renderLLMSources(payload && payload.sources, reg);
  renderLLMLogs(payload && payload.logs);
}

function renderLLMSources(sources, reg) {
  const box = document.getElementById('llmSourcesBox');
  const list = document.getElementById('llmSourcesList');
  const count = document.getElementById('llmSourcesCount');
  const items = Array.isArray(sources) ? sources : [];
  if (box) box.style.display = items.length ? '' : 'none';
  if (count) count.textContent = String(items.length);
  if (!list) return;

  const eventLabels = { register: '注册', heartbeat: '心跳', log: '日志' };
  const currentId = reg && reg.received ? reg.dockerId : '';
  list.innerHTML = items.map((src) => {
    const isCurrent = src.dockerId && src.dockerId === currentId;
    const tag = isCurrent
      ? '<span class="status-pill ok" style="font-size:11px; padding:1px 6px;">当前</span>'
      : '';
    const event = eventLabels[src.lastEvent] || src.lastEvent || '—';
    return `<div style="display:flex; align-items:center; gap:10px; padding:4px 8px; background:var(--panel-sub); border-radius:6px; flex-wrap:wrap;">
      <code style="min-width:160px;">${escapeHtml(src.dockerId || '')}</code>
      ${tag}
      <span class="muted">${escapeHtml(event)} · ${escapeHtml(llmRelativeTime(src.lastSeen))}</span>
    </div>`;
  }).join('');
}

function renderLLMLogEntry(entry) {
  const msg = escapeHtml(entry.message || '');
  return `<div class="log-row" data-seq="${entry.seq}"><span class="log-seq" style="color:#60a5fa; font-weight:600; margin-right:6px;">[seq=${entry.seq}]</span><span class="log-msg">${msg}</span></div>`;
}

function renderLLMLogs(logs) {
  const out = document.getElementById('llmLogOutput');
  const countEl = document.getElementById('llmLogCount');
  if (!out) return;

  const entries = logs && Array.isArray(logs.entries) ? logs.entries : [];
  const total = logs && logs.totalCount != null ? logs.totalCount : entries.length;
  if (countEl) countEl.textContent = `${total} 条日志`;

  if (llmLogPaused) return;

  out.innerHTML = entries.length
    ? entries.map(renderLLMLogEntry).join('')
    : '<div style="color:#6b7280; text-align:center; padding:16px 0;">暂无日志。(/v1/llm/log)</div>';

  if (llmLogAutoScroll) out.scrollTop = out.scrollHeight;
}

function toggleLLMLogPause() {
  llmLogPaused = !llmLogPaused;
  const btn = document.getElementById('llmLogPauseBtn');
  if (btn) {
    btn.textContent = llmLogPaused ? '继续' : '暂停';
    btn.className = llmLogPaused ? 'success' : 'secondary';
  }
}

function initLLMPanel() {
  const out = document.getElementById('llmLogOutput');
  if (!out) return;
  out.addEventListener('scroll', () => {
    llmLogAutoScroll = out.scrollHeight - out.scrollTop - out.clientHeight <= 40;
  });
}

async function refreshLLMStatus() {
  try {
    const res = await fetch('/api/llm/status', { cache: 'no-store' });
    const data = await res.json();
    renderLLMStatus(responseResult(data));
  } catch (_) {
    // Background poll: a transient failure leaves the last render in place.
  }
}

async function resetLLMStatus() {
  try {
    await fetch('/api/llm/reset', { method: 'POST' });
  } catch (_) {}
  if (typeof showToast === 'function') {
    showToast({ type: 'success', title: '已重置', message: 'TEE-LLM 注册、心跳、来源与日志已清空' });
  }
  refreshLLMStatus();
}

function openLLMRegisterBody() {
  if (!lastLLMState || !lastLLMState.register || !lastLLMState.register.received) {
    if (typeof showToast === 'function') {
      showToast({ type: 'warning', title: '提示', message: '暂无 TEE-LLM 注册报文' });
    }
    return;
  }
  recordInteraction('llmRegister', {
    title: 'TEE-LLM 平台注册详情',
    primaryLabel: '上报内容 (TEE-LLM 请求体)',
    secondaryLabel: '平台应答',
    primaryContent: lastLLMState.register,
    secondaryContent: { code: 0, msg: 'ok', result: { received: true } },
    endpoint: '/v1/llm/register',
  });
  openInteractionDrawer('llmRegister', 'primary');
}

function openLLMPublicKeyModal() {
  const modal = document.getElementById('llmPublicKeyModal');
  const field = document.getElementById('llmPublicKeyText');
  const key = lastLLMState && lastLLMState.register ? lastLLMState.register.taaPublicKey : '';
  if (!modal || !field || !key) {
    if (typeof showToast === 'function') {
      showToast({ type: 'warning', title: '提示', message: '暂无 TEE-LLM 注册公钥' });
    }
    return;
  }
  field.value = key;
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
}

function closeLLMPublicKeyModal() {
  const modal = document.getElementById('llmPublicKeyModal');
  if (!modal) return;
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
}
```

- [ ] **Step 2: 语法检查**

Run: `node --check tools/platform-mock/internal/static/js/llm.js`
Expected: 无输出、退出码 0。

若本机没有 `node`，改为 `grep -c 'function refreshLLMStatus' tools/platform-mock/internal/static/js/llm.js`，Expected: `1`。

- [ ] **Step 3: 提交**

```bash
git add tools/platform-mock/internal/static/js/llm.js
git commit -m "feat(platform-mock): render the TEE-LLM panel from the LLM status endpoint"
```

---

### Task 5: 轮询与启动接线

**Files:**
- Modify: `tools/platform-mock/internal/static/js/api.js`
- Modify: `tools/platform-mock/internal/static/js/app.js`

- [ ] **Step 1: 挂到中速轮询**

`api.js` 的 `pollMediumTier()` 中，在 `fetchTaaLogs` 之后加：

```js
  async pollMediumTier() {
    if (this.isPaused) return;
    try {
      if (typeof refreshReportResStatus === 'function') {
        refreshReportResStatus();
      }
      if (typeof fetchModelLogs === 'function') {
        fetchModelLogs();
      }
      if (typeof fetchTaaLogs === 'function') {
        fetchTaaLogs();
      }
      if (typeof refreshLLMStatus === 'function') {
        refreshLLMStatus();
      }
    } catch (_) {}
  }
```

- [ ] **Step 2: 启动时初始化**

`app.js` 的 `DOMContentLoaded` 回调中，在 `fetchTaaLogs();` 之后、`PollingManager.start();` 之前加：

```js
  initLLMPanel();
  refreshLLMStatus();
```

- [ ] **Step 3: 语法检查**

Run: `node --check tools/platform-mock/internal/static/js/api.js && node --check tools/platform-mock/internal/static/js/app.js`
Expected: 无输出、退出码 0（无 `node` 时用 `grep -c 'refreshLLMStatus' tools/platform-mock/internal/static/js/api.js` 与 `grep -c 'initLLMPanel' tools/platform-mock/internal/static/js/app.js`，各得到 `1`）。

- [ ] **Step 4: 提交**

```bash
git add tools/platform-mock/internal/static/js/api.js tools/platform-mock/internal/static/js/app.js
git commit -m "feat(platform-mock): poll the LLM panel with the medium polling tier"
```

---

### Task 6: 文档与端到端验证

**Files:**
- Modify: `tools/platform-mock/README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: 更新 README**

在 `tools/platform-mock/README.md` 的 `## Web Console` 列表中加入一条：

```markdown
- **TEE-LLM Instance**: the LLM reports on its own plaintext `/v1/llm/*` routes, so the console
  gives it a dedicated card (TEE mode only): registration, self-check, heartbeat liveness, a
  collapsible recent-source list of the `dockerId`s that have reported, and the batched run logs
  from `/v1/llm/log`. Reset clears the registration, the sources and the LLM log store.
```

- [ ] **Step 2: 更新 CHANGELOG**

在 `CHANGELOG.md` 的 `### Added` 段落末尾追加一条：

```markdown
- **TEE-LLM Instance Panel In The platform-mock Console**: the mock has accepted `/v1/llm/register`, `/v1/llm/heartbeat` and `/v1/llm/log` since the LLM platform integration, but nothing in the console showed them — the only way to see an LLM instance was `curl /api/llm/status`. The TEE console now carries a dedicated card: a liveness pill (green within 90 seconds of the last heartbeat, yellow after registration with no heartbeat, red past three missed 30-second periods), the `dockerId`, the self-check verdict, report size and registration time, the public key in a modal, the raw registration body in the existing drawer, a collapsible run-log viewer with pause, and a collapsible "recent sources" list. `llmState` gains a `sources` list capped at five entries — upserted by all three inbound routes, ordered newest-first, evicted oldest-first — so a second `dockerId` overwriting the single-instance registration state still leaves a visible trace instead of silently replacing the panel. `POST /api/llm/reset` now also clears the LLM log store, which it previously left behind even though the panel shows those logs.
```

- [ ] **Step 3: 端到端验证**

```bash
./deploy-platform-mock.sh local restart
curl -s http://127.0.0.1:18080/api/llm/status | head -c 300
curl -s -X POST http://127.0.0.1:18080/v1/llm/register \
  -H 'Content-Type: application/json' \
  -d '{"dockerId":"taa-teellm","taaPublicKey":"-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n","attestation":"AQID","attestationValues":"{}","timestamp":"1730000000","verifiedPass":true}'
curl -s -X POST http://127.0.0.1:18080/v1/llm/heartbeat \
  -H 'Content-Type: application/json' -d '{"dockerId":"taa-teellm","timestamp":"1730000030"}'
curl -s -X POST http://127.0.0.1:18080/v1/llm/log \
  -H 'Content-Type: application/json' \
  -d '{"dockerId":"taa-teellm","requestId":"system","entries":[{"seq":1,"message":"[2026-11-03 10:00:00] [INFO] [teellm] ready"}]}'
curl -s http://127.0.0.1:18080/api/llm/status
```

Expected：最后一次输出里 `register.received=true`、`heartbeat.count=1`、`logs.totalCount=1`、`sources` 只有一条且 `lastEvent="log"`。

浏览器打开 `http://127.0.0.1:18080`（TEE 模式）确认：卡片状态灯为绿色「在线」、显示 `taa-teellm`、「最近来源 (1)」展开后有当前标记、运行日志展开后能看到 `ready` 一行、暂停按钮可切换、重置后卡片回到「等待 TEE-LLM 注册」且日志为空。

- [ ] **Step 4: 提交**

```bash
git add tools/platform-mock/README.md CHANGELOG.md
git commit -m "docs(platform-mock): document the TEE-LLM console panel"
```

---

## 自检

- **规格覆盖**：数据模型 → Task 1；重置语义与 API → Task 1/2；卡片位置、可见性、状态灯、元素、来源列表、日志、轮询 → Task 3/4/5；测试 → Task 1/2/6；兼容性 → Task 1 的 nil 切片处理与 Task 2 的只增字段。
- **占位符**：无 TBD/TODO，每个代码步骤都给出完整代码。
- **类型一致**：`llmSource`、`maxLLMSources`、`llmEvent*`、`touchLog`、`store.now` 在 Task 1 定义，Task 2 与测试复用同名；前端 `refreshLLMStatus` / `initLLMPanel` / `renderLLMStatus` 在 Task 4 定义，Task 5 调用。
