# 审计进行中重新下发模型：中止旧审计并重建审计链

- **Date**: 2026-10-22
- **Specification Path**: `.claude/specs/2026-10-22-model-reimport-aborts-audit-design.md`
- **Scope**: 模型导入并发语义、模型代码审计的可取消执行与代际隔离
- **Lifecycle Status**: Target Architecture Specification
- **Affected Modules**: `internal/controller`, `internal/codeaudit`, `docs/api-design.md`

---

## 1. 背景与现状

模型导入完成后，代码审计在后台 goroutine 中异步执行（`import_processing.go:659`），不阻塞后续数据下发与训练。当审计仍在运行时再次调用 `/v1/taa/importModel`，当前实现会拒绝请求：

- `tryAcquireTask` 中 `isModel && isAuditBusyLocked()` 直接返回 409（`route.go:778`）。
- 拒绝理由是避免两轮导入争用同一个 `Security.ModelDir`（`docs/api-design.md:1084`）。

该行为的问题是：平台无法用新模型替换正在审计的旧模型，只能等待审计结束，而审计耗时可能是分钟级（semgrep 全量扫描 + CPU 推理逐 finding 验证）。

本设计将语义改为：**审计进行中收到新的模型下发时，中止旧审计，下载并覆盖模型，然后对新模型重新发起审计。**

已确认的产品决策：

1. 旧审计**静默中止，不向平台回调** `reportAudit`。
2. 旧审计在**收到请求即中止**（下载开始之前），而不是等新模型就绪后。
3. 采用**上下文贯通**实现真中止，而不是逻辑作废。

---

## 2. 目标与非目标

### 2.1 目标

- 审计运行中 `importModel` 不再返回 409，而是正常受理。
- 旧审计被取消后，semgrep 子进程被杀死，LLM 请求被取消，扫描循环尽快退出，CPU/内存立即释放。
- 旧审计 goroutine 在模型目录被覆盖前退出（有界等待），避免 `RemoveAll` + `Rename` 与扫描并发读。
- 新模型的审计以新代际号启动，旧 goroutine 的收尾不得清除新审计的内存状态或持久化待决标记。
- 中止不上报、不补报；重启后不把被中止的审计当作“遗留审计”再次上报。

### 2.2 非目标

- 不改变数据下发与审计并行的既有语义。
- 不改变“训练进行中拒绝模型导入”的互斥规则。
- 不改变审计裁决的含义、风险分级或 fail-closed 策略。
- 不改变 `resourceUrl` 为空时“仅更新 runtimeConfig”的请求路径。
- 不实现下载失败后自动重启旧模型审计。

---

## 3. 总体流程

```
平台 ──importModel(B)──▶ TAA
                          │
                          ├─ tryAcquireTask(B)：审计不再阻断（仍受训练/在飞导入互斥）
                          │
                          ├─ abortModelAudit()：
                          │    cancel(A 的 ctx)
                          │    清除 pendingAudit 并 seal（静默，不回调）
                          │
                          ├─ 下载 B
                          └─ 200「模型已接收」
                               │（异步）
                               ├─ 解密 B、SM3
                               ├─ waitAuditStopped()：等待 A 的 goroutine 退出（≤ 上限）
                               ├─ extractArchiveToDir(ModelDir, B)
                               │    （临时目录解压 → RemoveAll(ModelDir) → Rename）
                               ├─ reportModelImport(B, 0)
                               ├─ beginModelImportAndAudit(B)
                               │    （ModelImported=true 与新的 pendingAudit 同一次 seal）
                               └─ launchModelAudit(B)：auditGen++
```

---

## 4. codeaudit 层：让扫描可取消

### 4.1 引擎接口

`StaticEngine`（`internal/codeaudit/engine.go:27`）增加一个方法：

```go
// ScanDirectoryWithLinesContext is ScanDirectoryWithLines with cancellation.
// ctx 取消时尽快返回 ctx.Err()，且不产出可用于裁决的报告。
ScanDirectoryWithLinesContext(ctx context.Context, dir string) (*Report, map[string]int, error)
```

- 现有 `ScanDirectory` / `ScanDirectoryWithLines` 保持不变，语义等同于传入 `context.Background()`；这样现有调用点和测试无需机械改写。
- `regexEngine` 与 `semgrepEngine` 实现新方法。
- 测试桩 `namedEngine` 内嵌 `codeaudit.StaticEngine`，自动获得新方法，无需改动。

### 4.2 Semgrep 引擎

- `semgrepEngine.scan` 增加 `ctx` 参数；`context.WithTimeout(ctx, e.timeout)` 合并调用方取消与自身超时。
- `runSemgrepCLI` 已使用 `exec.CommandContext`（`semgrep_engine.go:603`），父 ctx 取消即向子进程发信号并返回。
- `walkSourceFiles` / `countLines` / 结果组装循环在每 N 个文件或每次迭代检查 `ctx.Err()`。
- CPG 富化（`enrichFindingsWithCPG`，`semgrep_engine.go:246`）是有界步骤（节点上限 50000），只在进入前和返回后检查 ctx；不改造 cpg 包内部。

### 4.3 二进制通道

- `BinaryScanner` 新增 `ScanDirectoryContext(ctx, dir)`；原 `ScanDirectory` 委托 `context.Background()`。
- `filepath.Walk` 回调开头检查 `ctx.Err()`：取消时返回该错误终止遍历。
- 逐文件分类/证据提取循环同样检查。
- `runBinaryChannel` 改为接收 ctx（`verifier.go:485`）。

### 4.4 LLM 与健康探测

- `GenerateAuditReport` 已接收 ctx，`VerifyReport` 与 `analyzeFileWithLLM` 均把 ctx 传给推理客户端；`teellm.Client` 使用 `http.NewRequestWithContext`（`teellm/client.go:152`），取消即中断请求。
- `isLLMServiceAvailable` 改为接收 ctx，其内部超时从该 ctx 派生（`context.WithTimeout(ctx, auditLLMHealthCheckTimeout)`）。
- `auditAndReportModelImport` 在健康探测、扫描、LLM 各阶段之间检查 `ctx.Err()`，取消后立即返回。

### 4.5 取消的可观测结果

- 取消导致 `GenerateAuditReport` 返回 `context.Canceled`；调用方区分“取消”与“审计失败”，取消分支只记日志、不产生裁决、不调用 `reportAuditAsync`。

---

## 5. controller 层：中止、等待与重建

### 5.1 新增内存状态（不持久化）

`TAAState`（`route.go:106`）新增：

```go
auditCancel context.CancelFunc // 当前审计的取消函数
auditGen    uint64             // 审计代际号，每次 launch 递增
auditDone   chan struct{}      // 当前审计 goroutine 的退出信号
```

三者只在内存中，`restoreState` 后保持零值。代际号不参与密封状态，不改变持久化 schema。

### 5.2 审计的启动与收尾

`launchModelAudit`（`import_processing.go:659`）改为：

1. `ctx, cancel := context.WithCancel(context.Background())`。
2. 加锁：`auditGen++`，记录 `gen`、`auditCancel = cancel`、`auditDone = make(chan struct{})`。
3. 启动 goroutine，`defer close(done)`；结束时调用 `finishAudit(gen, done)`：
   - 若 `s.auditDone == done`，清空 `auditDone` / `auditCancel`（按通道身份判断，不依赖代际）；
   - 仅当 `s.auditGen == gen` 时复位 `AuditRunning` / `CurrentAuditOp` / `ActiveAudit*`、清 `pendingAudit` 并 seal；
   - 代际不匹配说明已被中止或取代，只做通道清理，不触碰审计状态与待决标记。

`auditAndReportModelImport` 增加 `ctx` 与 `gen` 参数：

- 所有状态写入（`setLastAudit`、`setCurrentAuditOp`、`concludeAuditPending`）都做代际校验；不匹配时跳过。
- `ctx.Err() != nil` 时视为中止：记 Info 日志「本次审计已被新的模型下发中止」，返回，不上报。
- 已算出裁决但尚未上报时同样检查 ctx；取消优先于上报。
- `reportAuditAsync` 增加 `gen` 参数：异步发送前再次校验 `s.auditGen == gen`，不匹配则丢弃。该检查紧邻 HTTP 请求，用于把「裁决已算出、abort 恰好发生在检查之后」的窗口压到最小。

`concludeAuditPending` 改为接收 `gen`；当前无参版本由 `recovery` 使用的导出方法 `ConcludeAuditPending()` 保持不变（恢复路径没有并发审计）。

### 5.3 中止入口

新增：

```go
// abortModelAudit cancels the running model audit, if any. Silent: no platform
// callback is sent. Clears the durable pending marker so a restart does not
// report an audit that was deliberately abandoned.
func (s *TAAState) abortModelAudit()
```

- 加锁：若 `!isAuditBusyLocked()`，直接返回；否则记录被中止的 requestId/taskId。
- `auditGen++` 使当前代际立即失效——此后旧 goroutine 的任何状态写入与上报校验都会失败。
- 复位 `AuditRunning` / `CurrentAuditOp` / `ActiveAudit*`，清 `pendingAudit`，seal。保留 `auditDone` 供覆盖前等待，保留 `auditCancel` 由 finish 清理。
- 解锁后调用 `cancel()`（不等待）。
- 记日志（`audit` 组件）：`模型代码审计已中止: 收到新的模型下发, 旧 taskId=..., 新 taskId=...`。

立即复位内存状态而不是等 goroutine 退出，是为了避免「中止后新导入失败、旧 goroutine 因代际不匹配不再收尾」导致 `AuditRunning` 永久为 true。

### 5.4 导入请求路径

`modelImportHandler`（`handler_task.go:284`）：

- 删除 `tryAcquireTask` 中针对审计的 409 分支（`route.go:778-786`）。审计不再阻止模型导入；训练中/在飞导入的互斥保持不变。
- `tryAcquireTask` 成功后、`downloadToTempFile` 之前调用 `s.abortModelAudit()`。
- `resourceUrl` 为空的“仅更新 runtimeConfig”分支不调用中止（不覆盖模型目录，无需中止）。
- 响应保持现有 200 文案，不新增字段。

### 5.5 覆盖前的有界等待

`processImportedResource` 模型分支（`import_processing.go:93` 前）：

- 在 `extractArchiveToDir` 之前调用 `waitAuditStopped()`：
  - 取 `auditDone`；为 nil 直接返回；
  - 等待关闭或 `auditAbortWaitTimeout`（常量，30s）到期；
  - 超时记 Warn：旧审计未在期限内退出，仍继续覆盖；其结果已被代际号作废，不会上报，也不会清除新状态。
- 等待发生在解密与哈希之后、真正删除/替换 `ModelDir` 之前，确保 `RemoveAll` 时不与旧扫描并发。

选择 30s 的理由：semgrep 取消是进程级立即生效，LLM 请求随 ctx 中断，剩余最坏情况是 CPG 构建；30s 是安全上限而非预期耗时。

### 5.6 与已有闸门的关系

- `isAuditBusyLocked()` 继续用于状态展示与 `handler_system.go:91`，语义不变。
- `tryAcquireTask` 的检查顺序保持：训练互斥 → 在飞任务互斥。删除审计互斥后，审计期间 `ActiveTaskID` 为空、`CurrentOp=idle`，模型导入可正常获得任务权。
- 数据下发与训练路径完全不动。

---

## 6. 竞态与代际规则

| 场景 | 结果 |
| --- | --- |
| 旧审计 goroutine 在新审计启动后才退出 | `finishAudit(oldGen)` 代际不匹配，不清新状态、不清新 pending 标记；只清理自己登记的 done/cancel 通道 |
| 旧审计在 abort 前已自然完成 | `abortModelAudit` 看到非 busy，直接返回；不影响已完成结论 |
| abort 与裁决上报并发 | `reportAuditAsync(gen)` 在发送前校验代际，abort 已递增代际则丢弃该次上报 |
| abort 后、新导入解压前进程崩溃 | pending 已被清，重启不补报；`ModelImported` 仍指向旧模型，与静默中止语义一致 |
| 覆盖超时，旧审计仍在读 ModelDir | 读到的内容可能已被替换，但其报告因 ctx 取消/代际不匹配被丢弃；不产生平台回调 |
| 新导入下载失败 | 旧模型保留、保持已导入，但无审计结论；不自动重发旧审计 |
| 新导入解压失败 | 走现有 `reportImportFailure` → `clearImportedState`；不触发旧审计恢复 |
| 两次模型导入连续到达 | 第二次在第一次任务在飞时仍被 `tryAcquireTask` 拒绝；审计互斥删除不会放开导入互斥 |

---

## 7. 持久化与重启语义

- `pendingAudit` 继续承担“审计欠账”的唯一持久记录（`route.go:158`）。
- 中止时清除该标记并 seal：被中止的审计**不欠平台结论**。
- 新模型导入时 `beginModelImportAndAudit` 用新 requestId/taskId 写入新标记，与 `ModelImported` 同一次 seal。
- 启动期 `reconcileAbandonedAudit` 逻辑不变：只补报真正因崩溃中断的审计。

---

## 8. API 与文档变化

- `/v1/taa/importModel`：审计进行中不再返回 409；返回既有 200 受理文案。
- 删除 409 场景「当前已有模型代码审计正在执行中」，保留「当前已有任务正在执行中」与训练互斥的 409。
- 更新 `docs/api-design.md:1084` 的并发说明：审计不阻止新的模型下发；新模型会使旧审计中止（不回调），模型目录被覆盖后重新审计。

---

## 9. 测试策略

### 9.1 controller

1. **替换** `TestConcurrency_ModelImportRejectedWhileAuditing`（`concurrency_test.go:353`）：
   - 审计运行中 POST `/v1/taa/importModel` 返回 200；
   - 旧审计 goroutine 在覆盖前退出；
   - `extractArchiveToDir` 执行时旧扫描不再运行（用阻塞到 ctx 取消的假引擎断言顺序）；
   - 新审计启动，`ActiveAuditTaskID` / `pendingAudit` 为新请求的 ID。
2. **静默中止**：旧审计不产生 `reportAudit` 请求（httptest 平台记录）。
3. **代际隔离**：旧 goroutine 在新审计登记后收尾，新审计的 `AuditRunning`、`CurrentAuditTaskID`、`pendingAudit` 保持不变。
4. **中止清标记**：`abortModelAudit` 后 seal 状态中 `AuditPending == nil`。
5. **下载失败**：中止已发生，`ModelImported` 被回滚，无审计上报，无崩溃。
6. `go test -race ./internal/controller/...` 通过。

### 9.2 codeaudit

1. semgrep：`execFn` 假实现阻塞在 ctx 上，取消后返回 `context.Canceled`（`semgrep_engine.go:105` 已有注入点）。
2. 二进制扫描：`ScanDirectoryContext` 在取消后返回错误并停止遍历。
3. 正则引擎：大目录取消后尽快返回。
4. 现有非取消路径的扫描结果与非 ctx 版本逐字段一致（回归保证）。

### 9.3 全量

- `go test ./...` 全绿。
- 现有审计报告、恢复、并发测试不回归。

---

## 10. 验收标准

1. 审计运行中下发新模型：HTTP 200，不再 409。
2. 旧审计在收到请求后被取消；semgrep 子进程被终止；不产生 `reportAudit` 回调。
3. 覆盖 `ModelDir` 前旧审计 goroutine 已退出（或 30s 上限到期后记 Warn 并继续）。
4. 新模型导入完成后自动启动新审计，待决标记属于新请求。
5. 旧 goroutine 无法清除新审计的内存状态与持久标记。
6. 重启不会补报被中止的审计。
7. 文档与测试同步更新。

---

## 11. 已决策事项

| 问题 | 决策 |
| --- | --- |
| 旧审计是否回调平台 | 不回调（静默中止） |
| 中止时机 | 收到新模型请求即中止，早于下载 |
| 实现方式 | context 贯通，真取消（含 semgrep 进程与 LLM 请求） |
| 下载失败后是否重发旧审计 | 不重发 |
| 等待上限 | 30s，超时继续覆盖并记 Warn |
