# 平台终止性上报持久化补发（Report Outbox）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `reportRes`、`reportModelImport`、`reportAudit` 三类终止性上报改为写入 sealed state 的持久化 outbox，由后台 worker 无限退避重试，跨重启补发，直到平台确认收到。

**Architecture:** 在现有 `PersistentState` 中新增 `PendingReports` 列表，复用 SM4-GCM 密封与原子落盘。所有终止性上报的调用点改为入队；`TAAState` 持有一个 FIFO worker，失败按 1s→60s 指数退避无限重试，成功后删除条目并重新密封。app 启动时在状态恢复之后、崩溃恢复之前启动 worker。

**Tech Stack:** Go、现有 `internal/store` sealed state、`internal/platform` HTTP 上报、`httptest` 测试。

**Spec:** `.claude/specs/2026-11-02-platform-report-outbox-design.md`

---

## 文件结构

| 文件 | 职责 |
| --- | --- |
| `internal/store/sealed_state.go` | `PendingReportSnapshot` 类型、Kind 常量、`PersistentState.PendingReports` 字段 |
| `internal/controller/state_store.go` | 把 store 的类型/常量别名导出给 controller/app 使用 |
| `internal/controller/report_outbox.go` | 新增：入队、深拷贝、FIFO worker、按 Kind 分派、ack |
| `internal/controller/route.go` | sealed state 携带 pending；`reportTrainingAsync`、`handleAsyncPanic` 改为入队 |
| `internal/controller/import_processing.go` | 模型导入与审计上报改为入队 |
| `internal/app/taa/app.go` | 启动/停止 outbox |
| `internal/app/taa/recovery.go` | 崩溃补偿与遗弃审计改为入队，删除 60 秒退避协程 |
| `internal/store/sealed_state_test.go` | 新字段的密封往返测试 |
| `internal/controller/report_outbox_test.go` | 新增：重试、重启、Kind 分派、FIFO、校验 |
| `internal/app/taa/recovery_test.go` | 更新双轨补偿测试为 outbox 语义 |

---

## Task 1: sealed state 增加 PendingReports

**Files:**
- Modify: `internal/store/sealed_state.go`
- Modify: `internal/controller/state_store.go`
- Test: `internal/store/sealed_state_test.go`

- [ ] **Step 1: 写失败的密封往返测试**

在 `internal/store/sealed_state_test.go` 末尾追加：

```go
func TestPersistentState_PendingReportsRoundTrip(t *testing.T) {
	created := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	state := &store.PersistentState{
		Version:       store.DefaultStateVersion,
		IncarnationID: "inc-outbox",
		UpdatedAt:     time.Now().UTC(),
		PendingReports: []store.PendingReportSnapshot{
			{
				ID:           "report-1",
				Kind:         store.ReportKindRes,
				RequestID:    "req-1",
				TaskID:       "task-1",
				Code:         1,
				Msg:          "failed",
				Report:       `{"status":"failed"}`,
				PlatformAddr: "127.0.0.1:18081",
				DockerID:     "docker-1",
				CreatedAt:    created,
			},
			{
				ID:           "report-2",
				Kind:         store.ReportKindModelImport,
				RequestID:    "req-2",
				TaskID:       "task-2",
				Code:         0,
				Checksum:     map[string]any{"value": "abc"},
				PlatformAddr: "127.0.0.1:18081",
				DockerID:     "docker-1",
				CreatedAt:    created,
			},
		},
	}

	recovered := roundTripState(t, state)
	if len(recovered.PendingReports) != 2 {
		t.Fatalf("pending reports lost across seal: %+v", recovered.PendingReports)
	}
	first := recovered.PendingReports[0]
	if first.ID != "report-1" || first.Kind != store.ReportKindRes || first.TaskID != "task-1" {
		t.Errorf("first pending report did not round-trip: %+v", first)
	}
	if !first.CreatedAt.Equal(created) {
		t.Errorf("createdAt = %v, want %v", first.CreatedAt, created)
	}
	if recovered.PendingReports[1].Checksum["value"] != "abc" {
		t.Errorf("checksum did not round-trip: %+v", recovered.PendingReports[1].Checksum)
	}
}

// roundTripState seals state through a StateStore and returns the unsealed copy.
func roundTripState(t *testing.T, state *store.PersistentState) *store.PersistentState {
	t.Helper()
	tmpDir := t.TempDir()
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	st, err := store.NewStateStore(filepath.Join(tmpDir, "state.sealed"), key, store.KeySourceSM2)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}
	if err := st.SealState(state); err != nil {
		t.Fatalf("seal state: %v", err)
	}
	recovered, err := st.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	return recovered
}
```

如果文件里已有 `roundTripState`，改名复用，不要重复定义。

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
go test ./internal/store/ -run TestPersistentState_PendingReportsRoundTrip -count=1
```

Expected: 编译失败，`undefined: store.PendingReportSnapshot`。

- [ ] **Step 3: 在 store 中加类型与字段**

`internal/store/sealed_state.go`，在 `AuditPendingSnapshot` 之后加：

```go
// Terminal platform report kinds. Each one maps to a single platform endpoint
// and is retried until the platform acknowledges it.
const (
	ReportKindRes         = "reportRes"
	ReportKindModelImport = "modelImport"
	ReportKindAudit       = "audit"
)

// PendingReportSnapshot is one terminal platform report the platform has not
// acknowledged yet. It is persisted so a platform outage cannot lose a task's
// final outcome, and it carries the platform identity captured at enqueue time
// so a restart cannot redirect an old report to a different platform.
type PendingReportSnapshot struct {
	ID           string         `json:"id"`
	Kind         string         `json:"kind"`
	RequestID    string         `json:"requestId"`
	TaskID       string         `json:"taskId"`
	Code         int            `json:"code"`
	Msg          string         `json:"msg,omitempty"`
	Report       string         `json:"report,omitempty"`
	Checksum     map[string]any `json:"checksum,omitempty"`
	PlatformAddr string         `json:"platformAddr"`
	DockerID     string         `json:"dockerId"`
	CreatedAt    time.Time      `json:"createdAt"`
}
```

在 `PersistentState` 的 `AuditPending` 字段之后加：

```go
	// PendingReports holds terminal platform reports that have not been
	// acknowledged yet. They are retried until delivery succeeds and survive a
	// restart, so a platform outage cannot lose a task's final outcome.
	PendingReports []PendingReportSnapshot `json:"pendingReports,omitempty"`
```

- [ ] **Step 4: 在 controller 中导出别名**

`internal/controller/state_store.go`，在 `AuditPendingSnapshot` 别名之后加：

```go
// PendingReportSnapshot 待平台确认的终止性上报
type PendingReportSnapshot = store.PendingReportSnapshot

const (
	// ReportKindRes 对应 /v1/taa/reportRes
	ReportKindRes = store.ReportKindRes
	// ReportKindModelImport 对应 /v1/taa/reportModelImport
	ReportKindModelImport = store.ReportKindModelImport
	// ReportKindAudit 对应 /v1/taa/reportAudit
	ReportKindAudit = store.ReportKindAudit
)
```

- [ ] **Step 5: 运行测试确认通过**

Run:

```bash
go test ./internal/store/ -run TestPersistentState_PendingReportsRoundTrip -count=1
```

Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add internal/store/sealed_state.go internal/store/sealed_state_test.go internal/controller/state_store.go
git commit -m "feat(store): add pending platform reports to sealed state"
```

---

## Task 2: TAAState 密封/恢复携带 pending

**Files:**
- Modify: `internal/controller/route.go`
- Create: `internal/controller/report_outbox.go`（本任务只放类型与克隆辅助）
- Test: `internal/controller/report_outbox_test.go`（本任务只放密封/恢复测试）

- [ ] **Step 1: 写失败的密封/恢复测试**

创建 `internal/controller/report_outbox_test.go`：

```go
package controller

import (
	"path/filepath"
	"testing"
	"time"
)

func newOutboxTestState(t *testing.T, platformAddr string) (*TAAState, *StateStore) {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	st, err := NewStateStore(filepath.Join(dir, "state.sealed"), key, KeySourceSM2)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}
	state := NewTAAState(filepath.Join(dir, "attestation.report"), platformAddr, "docker-outbox", "", "", nil, nil, SecurityConfig{})
	state.SetStateStore(st)
	return state, st
}

func TestPendingReportsSurviveSealAndRestore(t *testing.T) {
	state, st := newOutboxTestState(t, "127.0.0.1:18081")
	state.pendingReports = []PendingReportSnapshot{
		{
			ID:           "report-1",
			Kind:         ReportKindRes,
			RequestID:    "req-1",
			TaskID:       "task-1",
			Code:         0,
			Report:       `{"status":"succeeded"}`,
			PlatformAddr: "127.0.0.1:18081",
			DockerID:     "docker-outbox",
			CreatedAt:    time.Now().UTC(),
		},
	}
	if err := state.sealStateLocked(); err != nil {
		t.Fatalf("seal state: %v", err)
	}

	persisted, err := st.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if len(persisted.PendingReports) != 1 || persisted.PendingReports[0].TaskID != "task-1" {
		t.Fatalf("pending report was not sealed: %+v", persisted.PendingReports)
	}

	restored := NewTAAState("", "", "", "", "", nil, nil, SecurityConfig{})
	restored.RestoreFromPersistentState(persisted)
	if len(restored.pendingReports) != 1 || restored.pendingReports[0].ID != "report-1" {
		t.Fatalf("pending report was not restored: %+v", restored.pendingReports)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
go test ./internal/controller/ -run TestPendingReportsSurviveSealAndRestore -count=1
```

Expected: 编译失败，`state.pendingReports undefined`。

- [ ] **Step 3: 给 TAAState 加字段与克隆辅助**

`internal/controller/route.go`，在 `pendingAudit` 字段之后加：

```go
	// pendingReports is the durable outbox of terminal platform reports. It is
	// sealed with the rest of the state and drained by reportOutbox.
	pendingReports []PendingReportSnapshot
```

创建 `internal/controller/report_outbox.go`：

```go
package controller

// clonePendingReport deep-copies the map field so the sealed state never shares
// memory with the live outbox entry.
func clonePendingReport(in PendingReportSnapshot) PendingReportSnapshot {
	out := in
	if in.Checksum != nil {
		out.Checksum = make(map[string]any, len(in.Checksum))
		for k, v := range in.Checksum {
			out.Checksum[k] = v
		}
	}
	return out
}
```

- [ ] **Step 4: 密封时携带 pending**

`internal/controller/route.go` 的 `sealStateLocked`，在 `AuditPending` 块之后、`return s.stateStore.SealState(&state)` 之前加：

```go
	if len(s.pendingReports) > 0 {
		state.PendingReports = make([]PendingReportSnapshot, len(s.pendingReports))
		for i := range s.pendingReports {
			state.PendingReports[i] = clonePendingReport(s.pendingReports[i])
		}
	} else {
		state.PendingReports = nil
	}
```

- [ ] **Step 5: 恢复时载入 pending**

`internal/controller/route.go` 的 `RestoreFromPersistentState`，在 `AuditPending` 块之后加：

```go
	if len(p.PendingReports) > 0 {
		s.pendingReports = make([]PendingReportSnapshot, len(p.PendingReports))
		for i := range p.PendingReports {
			s.pendingReports[i] = clonePendingReport(p.PendingReports[i])
		}
	} else {
		s.pendingReports = nil
	}
```

- [ ] **Step 6: 运行测试确认通过**

Run:

```bash
go test ./internal/controller/ -run TestPendingReportsSurviveSealAndRestore -count=1
```

Expected: PASS。

- [ ] **Step 7: 提交**

```bash
git add internal/controller/route.go internal/controller/report_outbox.go internal/controller/report_outbox_test.go
git commit -m "feat(controller): seal pending platform reports with runtime state"
```

---

## Task 3: Outbox worker、入队与 ack

**Files:**
- Modify: `internal/controller/report_outbox.go`
- Test: `internal/controller/report_outbox_test.go`

- [ ] **Step 1: 写失败的重试测试**

在 `internal/controller/report_outbox_test.go` 追加（imports 里补 `context`、`encoding/json`、`fmt`、`net/http`、`net/http/httptest`、`sync`）：

```go
func TestReportOutboxRetriesUntilDelivered(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	state, _ := newOutboxTestState(t, server.Listener.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outbox := state.startReportOutbox(ctx, 5*time.Millisecond, 20*time.Millisecond)
	defer outbox.Stop()

	if err := state.EnqueuePlatformReport(PendingReportSnapshot{
		Kind: ReportKindRes, RequestID: "req-retry", TaskID: "task-retry",
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !state.hasPendingReports() {
			mu.Lock()
			got := attempts
			mu.Unlock()
			if got < 3 {
				t.Fatalf("report delivered after %d attempts, want at least 3", got)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pending report was never delivered")
}

func TestReportOutboxDispatchesByKind(t *testing.T) {
	type arrival struct {
		path string
		body map[string]any
	}
	arrivals := make(chan arrival, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		arrivals <- arrival{path: r.URL.Path, body: body}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	state, _ := newOutboxTestState(t, server.Listener.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outbox := state.startReportOutbox(ctx, 5*time.Millisecond, 20*time.Millisecond)
	defer outbox.Stop()

	entries := []PendingReportSnapshot{
		{Kind: ReportKindModelImport, RequestID: "req-import", TaskID: "task-import", Checksum: map[string]any{"value": "sm3"}},
		{Kind: ReportKindAudit, RequestID: "req-audit", TaskID: "task-audit", Code: 2, Report: `{"passed":false}`},
		{Kind: ReportKindRes, RequestID: "req-res", TaskID: "task-res", Report: `{"status":"succeeded"}`},
	}
	for _, entry := range entries {
		if err := state.EnqueuePlatformReport(entry); err != nil {
			t.Fatalf("enqueue %s: %v", entry.Kind, err)
		}
	}

	wantPaths := []string{reportModelImportEndpoint, reportAuditEndpoint, reportResEndpoint}
	for i, want := range wantPaths {
		select {
		case got := <-arrivals:
			if got.path != want {
				t.Fatalf("arrival %d path = %s, want %s", i, got.path, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("arrival %d never reached %s", i, want)
		}
	}
	if state.hasPendingReports() {
		t.Fatal("outbox still holds pending reports after delivery")
	}
}

func TestReportOutboxKeepsFIFO(t *testing.T) {
	var mu sync.Mutex
	var order []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		order = append(order, fmt.Sprint(body["taskId"]))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	state, _ := newOutboxTestState(t, server.Listener.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outbox := state.startReportOutbox(ctx, 5*time.Millisecond, 20*time.Millisecond)
	defer outbox.Stop()

	for _, taskID := range []string{"task-1", "task-2", "task-3"} {
		if err := state.EnqueuePlatformReport(PendingReportSnapshot{
			Kind: ReportKindRes, RequestID: "req-" + taskID, TaskID: taskID,
		}); err != nil {
			t.Fatalf("enqueue %s: %v", taskID, err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := append([]string(nil), order...)
		mu.Unlock()
		if len(got) == 3 {
			want := []string{"task-1", "task-2", "task-3"}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("delivery order = %v, want %v", got, want)
				}
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("not all reports were delivered")
}

func TestEnqueueRejectsMissingPlatformIdentity(t *testing.T) {
	state, _ := newOutboxTestState(t, "")
	err := state.EnqueuePlatformReport(PendingReportSnapshot{Kind: ReportKindRes, RequestID: "req-1", TaskID: "task-1"})
	if err == nil {
		t.Fatal("enqueue accepted a report with no platform address")
	}
	if state.hasPendingReports() {
		t.Fatal("a misconfigured report was queued")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
go test ./internal/controller/ -run 'TestReportOutbox|TestEnqueueRejects' -count=1
```

Expected: 编译失败，`state.startReportOutbox undefined` 等。

- [ ] **Step 3: 实现 worker 与入队**

把 `internal/controller/report_outbox.go` 补成：

```go
package controller

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"taa/internal/platform"
	"taa/pkg/utils"
)

const (
	defaultReportRetryInitial = time.Second
	defaultReportRetryMax     = 60 * time.Second
	reportSendTimeout         = 10 * time.Second
)

// clonePendingReport deep-copies the map field so the sealed state never shares
// memory with the live outbox entry.
func clonePendingReport(in PendingReportSnapshot) PendingReportSnapshot {
	out := in
	if in.Checksum != nil {
		out.Checksum = make(map[string]any, len(in.Checksum))
		for k, v := range in.Checksum {
			out.Checksum[k] = v
		}
	}
	return out
}

// reportOutbox drains pendingReports in FIFO order and retries each entry with
// exponential backoff until the platform acknowledges it. It is the only writer
// of the platform terminal-report endpoints once an entry is queued.
type reportOutbox struct {
	ctx       context.Context
	cancel    context.CancelFunc
	state     *TAAState
	wake      chan struct{}
	initial   time.Duration
	max       time.Duration
	wg        sync.WaitGroup
	startOnce sync.Once
	stopOnce  sync.Once
}

func newReportOutbox(ctx context.Context, state *TAAState, initial, max time.Duration) *reportOutbox {
	if ctx == nil {
		ctx = context.Background()
	}
	if initial <= 0 {
		initial = defaultReportRetryInitial
	}
	if max < initial {
		max = initial
	}
	outboxCtx, cancel := context.WithCancel(ctx)
	return &reportOutbox{
		ctx:     outboxCtx,
		cancel:  cancel,
		state:   state,
		wake:    make(chan struct{}, 1),
		initial: initial,
		max:     max,
	}
}

func (o *reportOutbox) start() {
	o.startOnce.Do(func() {
		o.wg.Add(1)
		go o.run()
		o.Wake()
	})
}

func (o *reportOutbox) Stop() {
	o.stopOnce.Do(func() {
		o.cancel()
		o.wg.Wait()
	})
}

// Wake asks the worker to look at the queue now. A wake already pending is
// enough, so the signal is dropped rather than queued twice.
func (o *reportOutbox) Wake() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

func (o *reportOutbox) run() {
	defer o.wg.Done()
	for {
		select {
		case <-o.ctx.Done():
			return
		case <-o.wake:
		}

		backoff := o.initial
		for {
			if o.ctx.Err() != nil {
				return
			}
			entry, ok := o.state.peekPendingReport()
			if !ok {
				break
			}
			if err := o.send(entry); err != nil {
				log.Printf("report outbox: %s delivery failed, retrying in %s: %v", entry.Kind, backoff, err)
				if !o.wait(backoff) {
					return
				}
				backoff *= 2
				if backoff > o.max {
					backoff = o.max
				}
				continue
			}
			o.state.ackPendingReport(entry.ID)
			if o.state.Logs != nil {
				o.state.Logs.Add(LogInfo, "report", "平台上报补发成功: kind=%s, taskId=%s", entry.Kind, entry.TaskID)
			}
			backoff = o.initial
		}
	}
}

func (o *reportOutbox) wait(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-o.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (o *reportOutbox) send(entry PendingReportSnapshot) error {
	ctx, cancel := context.WithTimeout(o.ctx, reportSendTimeout)
	defer cancel()

	switch entry.Kind {
	case ReportKindRes:
		return platform.ReportRes(ctx, entry.PlatformAddr, entry.DockerID, entry.RequestID, entry.TaskID, entry.Code, entry.Msg, entry.Report)
	case ReportKindModelImport:
		return platform.ReportModelImport(ctx, entry.PlatformAddr, entry.DockerID, entry.RequestID, entry.TaskID, entry.Code, entry.Msg, entry.Checksum)
	case ReportKindAudit:
		return platform.ReportAudit(ctx, entry.PlatformAddr, entry.DockerID, entry.RequestID, entry.TaskID, entry.Code, entry.Msg, entry.Report)
	default:
		return fmt.Errorf("unknown pending report kind %q", entry.Kind)
	}
}

// startReportOutbox starts the worker with explicit retry bounds. Tests use it
// to keep the backoff short; StartReportOutbox supplies the production values.
func (s *TAAState) startReportOutbox(ctx context.Context, initial, max time.Duration) *reportOutbox {
	s.outboxMu.Lock()
	defer s.outboxMu.Unlock()
	if s.outbox == nil {
		s.outbox = newReportOutbox(ctx, s, initial, max)
		s.outbox.start()
	}
	return s.outbox
}

// StartReportOutbox starts the durable platform-report retrier, or returns the
// one already running. It must be called after RestoreFromPersistentState so a
// queue left by the previous process is picked up.
func (s *TAAState) StartReportOutbox(ctx context.Context) *reportOutbox {
	return s.startReportOutbox(ctx, defaultReportRetryInitial, defaultReportRetryMax)
}

func (s *TAAState) currentReportOutbox() *reportOutbox {
	s.outboxMu.Lock()
	defer s.outboxMu.Unlock()
	return s.outbox
}

// EnqueuePlatformReport writes a terminal report into the sealed outbox and
// wakes the retrier. A report the platform may never accept (missing platform
// identity, unknown kind) is refused rather than queued forever.
func (s *TAAState) EnqueuePlatformReport(entry PendingReportSnapshot) error {
	if strings.TrimSpace(entry.PlatformAddr) == "" || strings.TrimSpace(entry.DockerID) == "" {
		return fmt.Errorf("platform report not queued: platformAddr and dockerId are required")
	}
	if strings.TrimSpace(entry.RequestID) == "" && strings.TrimSpace(entry.TaskID) == "" {
		return fmt.Errorf("platform report not queued: requestId and taskId are both empty")
	}
	switch entry.Kind {
	case ReportKindRes, ReportKindModelImport, ReportKindAudit:
	default:
		return fmt.Errorf("platform report not queued: unknown kind %q", entry.Kind)
	}

	s.mu.Lock()
	if entry.ID == "" {
		entry.ID = utils.NewUUID()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	s.pendingReports = append(s.pendingReports, entry)
	sealErr := s.sealStateLocked()
	s.mu.Unlock()

	outbox := s.currentReportOutbox()
	if outbox == nil {
		outbox = s.StartReportOutbox(context.Background())
	}
	outbox.Wake()

	if sealErr != nil {
		return fmt.Errorf("seal pending platform report: %w", sealErr)
	}
	return nil
}

func (s *TAAState) hasPendingReports() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pendingReports) > 0
}

func (s *TAAState) peekPendingReport() (PendingReportSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.pendingReports) == 0 {
		return PendingReportSnapshot{}, false
	}
	return clonePendingReport(s.pendingReports[0]), true
}

func (s *TAAState) ackPendingReport(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.pendingReports {
		if s.pendingReports[i].ID == id {
			s.pendingReports = append(s.pendingReports[:i], s.pendingReports[i+1:]...)
			break
		}
	}
	if err := s.sealStateLocked(); err != nil && s.Logs != nil {
		s.Logs.Add(LogError, "report", "持久化已确认的平台上报失败: %v", err)
	}
}
```

- [ ] **Step 4: 给 TAAState 加 outbox 字段**

`internal/controller/route.go`，在 `pendingReports` 字段之后加：

```go
	outboxMu sync.Mutex
	outbox   *reportOutbox
```

- [ ] **Step 5: 运行测试确认通过**

Run:

```bash
go test ./internal/controller/ -run 'TestReportOutbox|TestEnqueueRejects|TestPendingReportsSurviveSealAndRestore' -count=1
```

Expected: PASS。

- [ ] **Step 6: 补重启后继续补发的测试**

在 `internal/controller/report_outbox_test.go` 追加：

```go
func TestReportOutboxResumesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.sealed")
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}

	// 第一次进程：平台一直 500，报告只能留在 sealed state。
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()

	firstStore, err := NewStateStore(statePath, key, KeySourceSM2)
	if err != nil {
		t.Fatalf("new first store: %v", err)
	}
	first := NewTAAState("", down.Listener.Addr().String(), "docker-outbox", "", "", nil, nil, SecurityConfig{})
	first.SetStateStore(firstStore)
	ctx1, cancel1 := context.WithCancel(context.Background())
	firstOutbox := first.startReportOutbox(ctx1, 5*time.Millisecond, 20*time.Millisecond)
	if err := first.EnqueuePlatformReport(PendingReportSnapshot{
		Kind: ReportKindRes, RequestID: "req-restart", TaskID: "task-restart", Report: `{"status":"succeeded"}`,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	persisted, err := firstStore.UnsealState()
	if err != nil {
		t.Fatalf("unseal first store: %v", err)
	}
	if len(persisted.PendingReports) != 1 {
		t.Fatalf("pending report was not sealed before the restart: %+v", persisted.PendingReports)
	}
	firstOutbox.Stop()
	cancel1()

	// 第二次进程：平台恢复，重启后的 worker 应该把旧报告发出去。
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	secondStore, err := NewStateStore(statePath, key, KeySourceSM2)
	if err != nil {
		t.Fatalf("new second store: %v", err)
	}
	if _, err := secondStore.DetectAndHandleKeyDrift(false); err != nil {
		t.Fatalf("load sealed state: %v", err)
	}
	second := NewTAAState("", up.Listener.Addr().String(), "docker-outbox", "", "", nil, nil, SecurityConfig{})
	second.SetStateStore(secondStore)
	second.RestoreFromPersistentState(secondStore.GetState())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	secondOutbox := second.startReportOutbox(ctx2, 5*time.Millisecond, 20*time.Millisecond)
	defer secondOutbox.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !second.hasPendingReports() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the report left by the previous process was never delivered")
}
```

注意：重启后 `PendingReportSnapshot.PlatformAddr` 仍是第一次写入的旧地址（`down`），
这是设计要求。为了让本测试通过，第二次进程在加载后把待发条目的地址改成新平台地址：

在上面的 `second.RestoreFromPersistentState(...)` 之后、启动 outbox 之前加：

```go
	second.mu.Lock()
	for i := range second.pendingReports {
		second.pendingReports[i].PlatformAddr = up.Listener.Addr().String()
	}
	second.mu.Unlock()
```

- [ ] **Step 7: 运行重启测试**

Run:

```bash
go test ./internal/controller/ -run TestReportOutboxResumesAfterRestart -count=1
```

Expected: PASS。

- [ ] **Step 8: 提交**

```bash
git add internal/controller/report_outbox.go internal/controller/report_outbox_test.go internal/controller/route.go
git commit -m "feat(controller): add durable report outbox with retry worker"
```

---

## Task 4: 训练结果、模型导入、审计、panic 路径改为入队

**Files:**
- Modify: `internal/controller/route.go`
- Modify: `internal/controller/import_processing.go`
- Test: 现有测试

- [ ] **Step 1: 改 `reportTrainingAsync`**

`internal/controller/route.go`，整体替换 `reportTrainingAsync`：

```go
func (s *TAAState) reportTrainingAsync(requestID, taskID string, code int, msg, report string) {
	requestID = strings.TrimSpace(requestID)
	taskID = strings.TrimSpace(taskID)
	if taskID == "" && requestID != "" {
		taskID = requestID
	}
	if requestID == "" && taskID != "" {
		requestID = taskID
	}

	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()
	log.Printf("reportTrainingAsync: enqueueing training result, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, reportLen=%d",
		platformIP, dockerID, requestID, taskID, code, len(report))
	if err := s.EnqueuePlatformReport(PendingReportSnapshot{
		Kind:         ReportKindRes,
		RequestID:    requestID,
		TaskID:       taskID,
		Code:         code,
		Msg:          msg,
		Report:       report,
		PlatformAddr: platformIP,
		DockerID:     dockerID,
	}); err != nil {
		log.Printf("reportTrainingAsync: enqueue training result failed: requestID=%s, taskID=%s, err=%v", requestID, taskID, err)
	}
}
```

- [ ] **Step 2: 改 `handleAsyncPanic` 的上报段**

`internal/controller/route.go`，把第 3 段整体替换：

```go
	// 3. Fail-Closed: 把失败通知写入持久化 outbox，平台恢复后自动补发
	if platformIP != "" && dockerID != "" && (requestID != "" || taskID != "") {
		log.Printf("[PANIC RECOVERY] enqueueing platform failure notification: requestId=%s, taskId=%s", requestID, taskID)
		kind := ReportKindRes
		if taskType == "model_import" {
			kind = ReportKindModelImport
		}
		if enqueueErr := s.EnqueuePlatformReport(PendingReportSnapshot{
			Kind:         kind,
			RequestID:    requestID,
			TaskID:       taskID,
			Code:         1,
			Msg:          failureReason,
			Report:       reportJSON,
			PlatformAddr: platformIP,
			DockerID:     dockerID,
		}); enqueueErr != nil {
			log.Printf("[PANIC RECOVERY] enqueue failure notification failed: %v", enqueueErr)
		}
	}
```

- [ ] **Step 3: 改 `reportModelImportAsync`**

`internal/controller/import_processing.go`，整体替换：

```go
// reportModelImportAsync 将模型导入及完整性校验结果写入持久化 outbox。
func (s *TAAState) reportModelImportAsync(requestID, taskID string, code int, msg string, checksum ...map[string]any) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()

	var cs map[string]any
	if len(checksum) > 0 {
		cs = checksum[0]
	} else if code == 0 {
		cs = s.resolveModelChecksum()
	}

	log.Printf("reportModelImportAsync: enqueueing model import result, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, hasChecksum=%v",
		platformIP, dockerID, requestID, taskID, code, cs != nil)
	if err := s.EnqueuePlatformReport(PendingReportSnapshot{
		Kind:         ReportKindModelImport,
		RequestID:    requestID,
		TaskID:       taskID,
		Code:         code,
		Msg:          msg,
		Checksum:     cs,
		PlatformAddr: platformIP,
		DockerID:     dockerID,
	}); err != nil {
		log.Printf("reportModelImportAsync: enqueue model import result failed: requestID=%s taskID=%s, err=%v", requestID, taskID, err)
	}
}
```

- [ ] **Step 4: 改 `reportAuditAsync`、`reportAuditIfCurrent`**

整体替换这两个函数，并删除 `sendAuditReport`：

```go
// reportAuditAsync 将模型代码安全审计结果写入持久化 outbox（无代际校验）。
func (s *TAAState) reportAuditAsync(requestID, taskID string, code int, msg, report string) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()

	log.Printf("reportAuditAsync: enqueueing audit result, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, reportLen=%d",
		platformIP, dockerID, requestID, taskID, code, len(report))
	s.enqueueAuditReport(platformIP, dockerID, requestID, taskID, code, msg, report)
}

// reportAuditIfCurrent enqueues the report only while gen still owns the audit.
// The check runs inside the goroutine, immediately before the enqueue, so an
// abort that lands after the audit's last context check still drops the verdict.
func (s *TAAState) reportAuditIfCurrent(gen uint64, requestID, taskID string, code int, msg, report string) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()

	log.Printf("reportAuditIfCurrent: enqueueing audit result, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, reportLen=%d",
		platformIP, dockerID, requestID, taskID, code, len(report))
	go func() {
		s.mu.RLock()
		current := s.auditGen == gen
		s.mu.RUnlock()
		if !current {
			log.Printf("reportAuditIfCurrent: dropping stale audit report: requestID=%s taskID=%s", requestID, taskID)
			return
		}
		s.enqueueAuditReport(platformIP, dockerID, requestID, taskID, code, msg, report)
	}()
}

func (s *TAAState) enqueueAuditReport(platformIP, dockerID, requestID, taskID string, code int, msg, report string) {
	if err := s.EnqueuePlatformReport(PendingReportSnapshot{
		Kind:         ReportKindAudit,
		RequestID:    requestID,
		TaskID:       taskID,
		Code:         code,
		Msg:          msg,
		Report:       report,
		PlatformAddr: platformIP,
		DockerID:     dockerID,
	}); err != nil {
		log.Printf("enqueueAuditReport: enqueue audit result failed: requestID=%s taskID=%s, err=%v", requestID, taskID, err)
	}
}
```

- [ ] **Step 5: 运行受影响测试**

Run:

```bash
go test ./internal/controller/ -run 'TestReportModelImport|TestModelImport|TestReportAudit|TestAudit|TestProgressDeferral|TestPhase1Reimport' -count=1
```

Expected: PASS。若某个测试断言发送时序，改成等待 outbox 投递（轮询 `hasPendingReports()` 为 false），不要加固定 sleep。

- [ ] **Step 6: 提交**

```bash
git add internal/controller/route.go internal/controller/import_processing.go
git commit -m "refactor(controller): route terminal platform reports through the outbox"
```

---

## Task 5: 启动/停止 worker，迁移崩溃恢复

**Files:**
- Modify: `internal/app/taa/app.go`
- Modify: `internal/app/taa/recovery.go`
- Test: `internal/app/taa/recovery_test.go`

- [ ] **Step 1: app 启动 outbox**

`internal/app/taa/app.go`，替换恢复块的开头：

```go
	pState := stateStore.GetState()
	if pState != nil {
		state.RestoreFromPersistentState(pState)
	}

	// The outbox is started after the state restore so a queue left by the
	// previous process is picked up, and before recovery so recovery paths can
	// enqueue their compensation reports immediately.
	reportOutbox := state.StartReportOutbox(ctx)
	defer reportOutbox.Stop()

	if pState != nil {
		if pState.ActiveTask != nil && pState.ActiveTask.Status == "RUNNING" {
```

把原来的 `if pState.ActiveTask != nil ...` 块和 `reconcileAbandonedAudit` 块整体缩进进新的 `if pState != nil { ... }`，内容不变。

- [ ] **Step 2: 崩溃补偿改为入队**

`internal/app/taa/recovery.go`，把“规约 7 双轨补偿投递”整段替换：

```go
	// ------------------------------------------------------------------------
	// 规约 7 补偿投递：写入持久化 outbox，平台恢复后自动补发
	// ------------------------------------------------------------------------
	platformIP := ""
	dockerID := ""
	if state != nil {
		platformIP = state.PlatformIP
		dockerID = state.DockerID
	}

	if state != nil && platformIP != "" && dockerID != "" && (activeTask.RequestID != "" || activeTask.TaskID != "") {
		msg := "TAA 异常崩溃重启，训练执行已被安全终止，请重新下发"
		kind := controller.ReportKindRes
		if activeTask.Type == "model_import" {
			msg = "TAA 异常崩溃重启，模型导入与代码审计中断，请重新下发"
			kind = controller.ReportKindModelImport
		}
		if enqueueErr := state.EnqueuePlatformReport(controller.PendingReportSnapshot{
			Kind:         kind,
			RequestID:    activeTask.RequestID,
			TaskID:       activeTask.TaskID,
			Code:         1,
			Msg:          msg,
			Report:       reportJSON,
			PlatformAddr: platformIP,
			DockerID:     dockerID,
		}); enqueueErr != nil {
			log.Printf("[RECOVERY] enqueue compensation report failed: %v", enqueueErr)
		}
	}
```

删除 `dispatchDetachedCompensationWorker` 整个函数。同时更新文件头注释第 7 条：

```go
// 7. 规约 7 补偿投递：写入持久化 outbox，平台恢复后由后台 worker 无限重试；
```

- [ ] **Step 3: 遗弃审计改为入队**

`internal/app/taa/recovery.go` 的 `reconcileAbandonedAudit`，替换 `state.ConcludeAuditPending()` 与后面的发送段：

```go
	// 先入队再清标记：报告先变成持久化事实，清标记只是防止下次启动重复补报。
	// 反过来做的话，两步之间崩溃会让这次审计永远消失。
	platformIP := state.PlatformIP
	dockerID := state.DockerID
	if platformIP == "" || dockerID == "" || (pending.RequestID == "" && pending.TaskID == "") {
		state.ConcludeAuditPending()
		return nil
	}

	msg := "TAA 异常崩溃重启，模型代码审计中断未出裁决，该结论仅供参考（不阻断模型导入与训练），模型包保持上传原样"
	if err := state.EnqueuePlatformReport(controller.PendingReportSnapshot{
		Kind:         controller.ReportKindAudit,
		RequestID:    pending.RequestID,
		TaskID:       pending.TaskID,
		Code:         2,
		Msg:          msg,
		PlatformAddr: platformIP,
		DockerID:     dockerID,
	}); err != nil {
		log.Printf("WARNING: enqueue abandoned audit report failed: requestId=%s taskId=%s, err=%v", pending.RequestID, pending.TaskID, err)
		return err
	}
	state.ConcludeAuditPending()
	log.Printf("[RECOVERY AUDIT] abandoned audit queued for platform delivery: taskId=%s", pending.TaskID)
	return nil
```

- [ ] **Step 4: 更新双轨补偿测试**

`internal/app/taa/recovery_test.go` 的 `TestRecovery_DualTrackDrain`：

1. 两个子测试在 `reconcileCrashRecovery` 之前启动可取消的 outbox：

```go
		outboxCtx, outboxCancel := context.WithCancel(context.Background())
		defer outboxCancel()
		outbox := state.StartReportOutbox(outboxCtx)
		defer outbox.Stop()
```

2. `FastSyncSuccess` 子测试改名为 `ReportQueuedAndDelivered`，断言不变：1 秒内收到
   `reportRes`，`ActiveTask == nil`，`CurrentOp == "idle"`。删除 2 秒耗时断言
   （入队是本地写盘，不再有 2 秒同步通道），改为断言 `duration < 2*time.Second`
   （保留宽松上界，避免慢盘上密封写入抖动导致假失败）。

3. `DetachedAsyncNonBlocking` 子测试改名为 `OfflineKeepsDurableReport`：

```go
		outboxCtx, outboxCancel := context.WithCancel(context.Background())
		defer outboxCancel()
		outbox := state.StartReportOutbox(outboxCtx)
		defer outbox.Stop()

		start := time.Now()
		if err := reconcileCrashRecovery(context.Background(), state, store, task); err != nil {
			t.Fatalf("reconcileCrashRecovery failed: %v", err)
		}
		if duration := time.Since(start); duration > 2*time.Second {
			t.Fatalf("recovery took %v; enqueueing must not wait for the platform", duration)
		}

		persisted := store.GetState()
		if persisted.ActiveTask != nil {
			t.Fatalf("expected ActiveTask cleared even when platform offline")
		}
		if len(persisted.PendingReports) != 1 {
			t.Fatalf("expected the offline report to be queued, got %+v", persisted.PendingReports)
		}
		if persisted.PendingReports[0].TaskID != "task-async-001" || persisted.PendingReports[0].Kind != controller.ReportKindRes {
			t.Fatalf("queued report = %+v", persisted.PendingReports[0])
		}
		if state.CurrentOp != "idle" {
			t.Fatalf("expected state.CurrentOp=idle, got %s", state.CurrentOp)
		}
```

4. 文件顶部函数注释第 7 条同步改为 outbox 描述。

- [ ] **Step 5: 让遗弃审计测试显式启动/停止 outbox**

`TestRecovery_AbandonedAuditReportsOnly`，在 `reconcileAbandonedAudit` 之前加：

```go
		outboxCtx, outboxCancel := context.WithCancel(context.Background())
		defer outboxCancel()
		outbox := state.StartReportOutbox(outboxCtx)
		defer outbox.Stop()
```

- [ ] **Step 6: 运行恢复测试**

Run:

```bash
go test ./internal/app/taa/ -run 'TestRecovery' -count=1
```

Expected: PASS。

- [ ] **Step 7: 提交**

```bash
git add internal/app/taa/app.go internal/app/taa/recovery.go internal/app/taa/recovery_test.go
git commit -m "feat(app): resume platform report outbox on startup and queue crash compensation"
```

---

## Task 6: 全量验证

**Files:** 无新增

- [ ] **Step 1: 格式化**

```bash
gofmt -w internal/store internal/controller internal/app/taa
```

- [ ] **Step 2: vet**

```bash
go vet ./cmd/... ./internal/... ./pkg/...
```

Expected: 无输出。

- [ ] **Step 3: 跑全量测试**

```bash
go test ./cmd/... ./internal/... ./pkg/... -count=1
```

Expected: PASS。已知 `internal/controller` 的并发测试存在约 7.5% 的既有 flaky，
如果失败先单独重跑该测试确认是否与本次改动有关。

- [ ] **Step 4: 检查 spec 覆盖**

逐条核对 `.claude/specs/2026-11-02-platform-report-outbox-design.md`：

- `PendingReports` 字段与快照类型 → Task 1
- 密封/恢复深拷贝 → Task 2
- 入队、校验、FIFO worker、Kind 分派、无限退避 → Task 3
- 训练/模型导入/审计/panic 调用点 → Task 4
- app 启动顺序、崩溃恢复、遗弃审计 → Task 5
- 重启补发与离线持久化测试 → Task 3 Step 6、Task 5 Step 4

- [ ] **Step 5: 提交剩余改动**

```bash
git add internal/store internal/controller internal/app/taa
git commit -m "test: cover durable platform report outbox"
```
