# 平台终止性上报的持久化补发（Report Outbox）设计

- 日期：2026-11-02
- 状态：已确认
- 范围：`reportRes`、`reportModelImport`、`reportAudit` 三类终止性上报

## 1. 背景与问题

TAA 的所有平台上报都是单次尝试：

- `reportTrainingAsync`（`internal/controller/route.go`）起一个 goroutine，调用
  `platform.ReportRes` 一次，失败只写本地日志。
- `reportModelImportAsync`、`reportAuditAsync` / `sendAuditReport`
  （`internal/controller/import_processing.go`）同样只发一次。
- 崩溃恢复路径（`internal/app/taa/recovery.go`）有一次 2 秒快速同步加最多 60 秒的
  指数退避补偿，超时即放弃。

平台长时间不可达时，任务正常结束但平台永远收不到终态：任务状态停留在“进行中”，
结果只能靠事后人工用 `/v1/taa/export`、`/v1/taa/getResourceInfo` 拉取。TAA 重启也不会
补发，因为任务正常结束后 `activeTask` 已被清空，恢复逻辑只处理 `RUNNING` 的任务。

## 2. 目标与非目标

### 目标

- 三类终止性上报在平台不可达时持久化排队，平台恢复后自动补发。
- 补发状态跨 TAA 重启存活。
- 无限重试直到平台确认收到，不设过期时间。
- 上报失败不阻塞训练、导入、审计或任务状态清理。

### 非目标

- 模型日志（`/v1/taa/modelLog`）、训练进度（`/v1/taa/reportProgress`）、
  TAA 自身日志（`/v1/taa/taaLog`）不纳入 outbox。这些是流式、可丢弃的上报，
  语义与终止性结果不同。
- 不改变平台侧接口，不改变报告体的 JSON 结构。
- 不实现平台侧的幂等逻辑；本设计只记录 at-least-once 的投递契约。

## 3. 方案选择

采用**并入现有 sealed state**：

- 复用 `PersistentState` 已有的 SM4-GCM 密封、原子落盘、`StateSeq` 单调序列和启动
  解密校验，崩溃一致性免费获得。
- 不新增密钥派生或第二个密封文件。

未采用的方案：

- 独立 sealed outbox 文件：能把大报告体与核心状态分开，但需要复制一套密封/加载
  逻辑并维护两个文件的一致性，代码量更大。
- 仅进程内重试：实现最简单，但进程重启即丢失，不满足“确保送达”。

## 4. 数据模型

`internal/store/sealed_state.go` 的 `PersistentState` 新增可选字段：

```go
// PendingReports holds terminal platform reports the platform has not
// acknowledged yet. They are retried until delivery succeeds and survive a
// restart, so a platform outage cannot lose a task's final outcome.
PendingReports []PendingReportSnapshot `json:"pendingReports,omitempty"`
```

```go
type PendingReportSnapshot struct {
	ID           string         `json:"id"`
	Kind         string         `json:"kind"` // "reportRes" | "modelImport" | "audit"
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

要点：

- `ID` 为随机十六进制串，用于确认成功后精确删除。不能用 `requestId + taskId`
  作键，因为同一任务理论上可能产生多条不同类型的报告。
- `PlatformAddr` / `DockerID` 随条目落盘，避免重启后环境变量或配置变化把旧报告
  发到另一个平台。
- `Checksum` 仅 `modelImport` 使用，保持 `map[string]any` 原样。
- 格式版本保持 `1.4`：新增字段为可选，旧状态解密后为 `nil`，旧代码读取新状态会
  忽略未知字段，无需迁移。
- `sealStateLocked` 与 `RestoreFromPersistentState` 必须同步携带该字段。落盘时对
  `Checksum` 做深拷贝，理由与 `AuditPending` 相同：`StateStore` 持有传入指针作为
  活缓存，浅拷贝会让后续内存修改绕过 `SealState`。

## 5. 入队

新增 `TAAState.EnqueuePlatformReport(entry PendingReportSnapshot)`：

1. 在 `s.mu` 下补全 `ID`（若空）与 `CreatedAt`（若零值），append 到
   `s.pendingReports`，调用 `sealStateLocked`。
2. 非阻塞唤醒 outbox worker（buffered channel，容量 1）。
3. 密封失败只记 `LogError`，条目仍留在内存，worker 照常尝试发送；下次状态密封会
   顺带补上。

配置校验：身份（addr / dockerId / requestId 或 taskId）为空属于部署配置错误，
不是暂时断连。校验直接复用 `platform.ValidateAndNormalizePlatformParams`，它同时
做 trim 与 requestId/taskId 的互相回填；失败则记错误日志并**不入队**，否则会永久
堆积且永远无法送达。

调用点只提供报告内容，统一经 `TAAState.QueueReport(kind, requestID, taskID, code,
msg, report, checksum)` 入队：平台身份从 `TAAState` 自动回填，失败日志只有一处，
新增上报路径时不会再各写一套。

### 改为入队的调用点

| 位置 | 原行为 | 新行为 |
| --- | --- | --- |
| `internal/controller/route.go` `reportTrainingAsync` | goroutine 单发 `ReportRes` | `QueueReport(ReportKindRes, ...)` |
| `internal/controller/import_processing.go` `reportModelImportAsync` | goroutine 单发 `ReportModelImport` | `QueueReport(ReportKindModelImport, ...)`；`resolveModelChecksum` 仍在入队前同步完成 |
| `internal/controller/import_processing.go` `reportAuditAsync` / `reportAuditIfCurrent` | goroutine 单发 `ReportAudit` | 代际检查通过后 `QueueReport(ReportKindAudit, ...)` |
| `internal/controller/route.go` `handleAsyncPanic` | 直接调用 `ReportTaskOutcome` | `QueueReport(ReportKindForTaskType(taskType), ...)` |
| `internal/app/taa/recovery.go` `reconcileCrashRecovery` | 2 秒快速同步 + 60 秒退避补偿 | 直接入队；删除 `dispatchDetachedCompensationWorker` |
| `internal/app/taa/recovery.go` `reconcileAbandonedAudit` | 直接调用 `ReportAudit` | 入队 `audit` |

taskType → `Kind` 的映射收敛到 `ReportKindForTaskType`，`handleAsyncPanic` 与崩溃
恢复共用；worker 不再需要 `taskType`。审计的旧包装
`controller.ReportTaskOutcome` 因此没有生产调用者，已删除——留着它就是一条绕过
outbox、丢掉持久化保证的后门。`reportAuditIfCurrent` 的代际检查改为同步执行：
调用方本来就在异步路径上，额外一层 goroutine 只是让窗口看起来被关上了。

## 6. 补发 worker

新文件 `internal/controller/report_outbox.go`。

```go
type reportOutbox struct {
	ctx     context.Context
	cancel  context.CancelFunc
	state   *TAAState
	wake    chan struct{}
	initial time.Duration // 默认 1s
	max     time.Duration // 默认 60s
	retry   map[string]retryState // per-entry backoff, in memory only
}
```

### 生命周期

- `TAAState.StartReportOutbox(ctx)`：幂等启动，`outboxMu` 下判空即可，无需额外的
  `sync.Once`。
- `internal/app/taa/app.go` 的启动顺序：
  `RestoreFromPersistentState` → `StartReportOutbox(ctx)` → 崩溃/审计恢复（入队）
  → `startServer`。先启动 worker，恢复路径入队时就能立刻投递，且 worker 跟随
  服务 ctx 退出。
- 未显式启动时，`EnqueuePlatformReport` 惰性以 `context.Background()` 启动。
  这样测试里直接构造的 `TAAState` 也能正常投递，不要求每个测试辅助函数都改。
  生产路径始终先调用 `StartReportOutbox`，所以惰性分支不会在 app 中触发。
- `defer outbox.Stop()`：停止 goroutine，不 flush；未送达条目留在 sealed state，
  下次启动继续。

### 循环

```text
启动时若 pending 非空，先唤醒一次
loop:
  wait for wake / ctx.Done / 下一个到期时刻
  entries := 队列快照（按入队顺序）
  acked := []
  next := 最早到期时刻
  对每个 entry:
     if 有退避记录且未到期:
        next = min(next, 到期时刻); continue
     err := send(entry)
     if err == nil:
        acked = append(acked, entry.ID); continue
     log.Printf 失败与退避时间
     retry[entry.ID] = {wait: min(wait*2, max), due: now + wait}
     next = min(next, wait)
  if len(acked) > 0:
     ackPendingReports(acked...)   // 一次删除
     continue                      // 队列变短了，立刻重新评估
  if next > 0: wait(next); continue
  return
```

- **逐条目调度，而非严格队首阻塞**：就绪条目仍按入队顺序送达，因此
  `modelImport → audit → reportRes` 的自然顺序不变；但一条失败不会堵住后面的条目。
  严格 FIFO 下，一条指向已失效地址的报告会永久饿死整条队列——FHE 测试正是这样
  暴露了问题（一条指向不可达平台的 `modelImport` 让后续所有报告都卡住）。
- 退避状态只存在内存（`retry map[string]retryState`），重启后全部立即重试。
- 一轮里确认成功的条目合并成**一次** `ackPendingReports`，因为密封会重写整个状态
  文件（marshal + 加密 + fsync + rename）：一轮送达 N 条不应付出 N 次 fsync。
- 等待期间同时监听 `wake`，新入队的报告不必等满别人的退避计时。
- `send` 按 `Kind` 分派到现有的 `platform.ReportRes` / `platform.ReportModelImport` /
  `platform.ReportAudit`，每次请求使用与 `platform.DefaultTimeout` 相同的超时。
- 重试失败只写 `log.Printf`（stderr），不写 `s.Logs`，避免重试日志反过来进入
  `taaLog` 上报通道形成噪声。成功补发时写一条 `LogInfo`。

## 7. 语义与代价

- **at-least-once**：平台返回 200 之后、`ack` 密封之前进程崩溃，重启后会重复投递。
  平台需要按 `(dockerId, requestId, taskId, 接口)` 幂等。本设计不引入去重表。
- 上报完全不阻塞任何流程；任务结束仍按原逻辑清理 `activeTask` 并密封。
- pending 列表无上限、无过期，符合“确保送达”的要求。任务流水线本身串行，
  离线期间条目数实际增长有限；代价是离线期间每完成一个任务，sealed state 会变大，
  每次密封需要重写全部待发报告。
- 报告体包含 `result_files` 的目录树与预览，本身已受现有密封保护，不新增明文落盘。

## 8. 测试

新增 `internal/controller/report_outbox_test.go`：

1. 平台返回 500：条目留在 `PersistentState.PendingReports`；平台恢复后自动补发，
   pending 清空。
2. 重启恢复：密封状态后用新的 `StateStore` 加载并 `RestoreFromPersistentState`，
   启动 outbox 后继续补发。
3. 三种 `Kind` 分别打到 `/v1/taa/reportRes`、`/v1/taa/reportModelImport`、
   `/v1/taa/reportAudit`，请求体字段完整。
4. FIFO：同一时刻多条待发报告按入队顺序到达平台（逐条目调度不改变就绪条目的顺序）。
5. 立即成功路径不留 pending。
6. 配置为空（`PlatformAddr` 或 `DockerID`）时拒绝入队并记错误日志。

现有测试保持通过，重点确认：

- `progress_deferral_test.go` 的 `waitForResult` 仍能等到 `reportRes`。
- 模型导入、审计相关测试中对 httptest 服务器的断言不受异步入队影响。
- 崩溃恢复测试改为断言“条目入队”，不再断言 60 秒退避协程。

## 9. 涉及文件

- `internal/store/sealed_state.go`：新增字段与快照类型。
- `internal/controller/route.go`：密封/恢复携带 pending；`reportTrainingAsync`
  与 panic 路径改为入队。
- `internal/controller/report_outbox.go`：新增 worker、入队、ack。
- `internal/controller/import_processing.go`：模型导入与审计上报改为入队。
- `internal/app/taa/app.go`：启动/停止 outbox。
- `internal/app/taa/recovery.go`：崩溃与审计补偿改为入队，删除旧的退避协程。
- 对应测试文件。
