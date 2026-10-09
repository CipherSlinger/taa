# 修复 C1：模型"已导入"标记先于审计落盘，异常路径不回滚

**日期**：2026-10-09
**范围**：`internal/controller`、`internal/store`、`internal/app/taa`（+ 测试）。不改平台载荷契约。

## Context

平台把模型交给 TAA 后，代码路径是：

```
解密解压 → 【写盘 ModelImported=true，字段注释声称"已解密且通过审计"】 → 才启动后台审计
```

`saveModelSuccess`（`import_processing.go:77` → `route.go:299-307`）在审计**开始之前**就把 `ModelImported=true` 连同 `SavedModelResourceURL` 一起 `sealStateLocked()` 落盘；`startModelAuditAsync` 在 `import_processing.go:81` 才启动审计。

正常审计失败会回滚（`import_processing.go:597-602`：`clearImportedState` + `stopActiveTraining`），但两条异常路径不会：

1. **panic**：`runAsyncSafe`（`route.go:689-701`）recover 后只调 `handleAsyncPanic`，不重跑 `fn`，故 `fn` 里的回滚永不执行；而 `handleAsyncPanic` 的 `modelAudit` 分支（`route.go:710-722`）只 `resetAuditStateLocked()` + 上报 code 2 就 `return`——不 `clearImportedState`、不 `cleanDirContents`、不 `stopActiveTraining`。该分支注释自陈原因是"隔离以免清掉在飞训练任务"。
2. **崩溃**：`PersistentState`（`sealed_state.go:20-35`）**没有任何审计字段**，"审计在飞"从不落盘；`app.go:164-170` 只在 `pState.ActiveTask != nil && Status=="RUNNING"` 时调自愈，而后台审计运行时模型导入任务早已 release（`activeTask == nil`），`recovery.go:34-36` 也首行 `return nil` → 自愈根本不触发。

**后果**：`ModelImported=true` 永久留下，模型代码未出裁决。而数据导入路径（`import_processing.go:148-159`）正是以 `ModelImported` 决定是否触发 `executeTraining`——未审计的模型代码会被真的执行（C2 是有意设计，但那是"审计在飞、稍后出结论且能事后追停"；C1 是"审计永不结束、无人追停"）。

**本次要建立的不变式**：**一次永远不会得出结论的审计，不得让模型停留在 `ModelImported=true`。**

### 核验中额外发现的同类泄漏（同一不变式的另一触发点）

`handler_task.go:267-269` 在**下载之前**就置 `ModelImported=true` 并 seal，而下载失败分支（`:275-281`）只调 `release()`，**不调 `clearImportedState`**（对比 `import_processing.go:36-66` 的解密/哈希/解压失败都调了 `reportImportFailure`）。结果：`ModelImported=true` + `SavedModelResourceURL` 已写、盘上无模型、从未启动审计、`release()` 又把 `activeTask` 清掉 → 自愈同样找不到它。这是同一条不变式的另一个违反点，1 行可补，一并纳入。

（已核实**不是**缺陷的相邻路径：`handler_task.go:245-248` 的空 URL 重导入分支置 `ModelImported=true` 且不审计，那是"只更新运行配置、无新模型内容"的有意语义，不动。）

## 决定

| 项 | 决定 |
| :--- | :--- |
| 遗弃审计的处置 | **回滚 + 物理清除**，与现有失败路径和规约 1 一致（用户已选） |
| 崩溃恢复是否补报平台 | **补报 code 2**，用持久化的审计 task/request id（用户已选） |
| pending 标记是否按 `ScanEnabled` 门控 | **是**。`ScanEnabled=false` 时审计立即返回 passed（`import_processing.go:608-611`），没有可"遗弃"的审计；不门控则"写标记→清标记"之间的崩溃会误隔离一个好模型 |
| panic 分支是否 `stopActiveTraining` | **是**，与正常失败路径（`:600`）对齐。该调用在解锁后执行 |
| 是否复用 `ActiveTask` 机制 | **否**。`ActiveTask` 是数据导入的单任务互斥量，`reconcileCrashRecovery` 会为它生成训练崩溃报告并归档；审计需要独立的嵌套快照 |
| `PersistentState.Version` | **不动**（`"1.4"` 无校验逻辑），新字段用 `omitempty` 指针保持旧文件可读 |
| 不上报路径外的可见性 | 不在本次范围（平台载荷契约有测试钉住，见 C1 清单"后续项"） |

## 关键机制

**顺序必须是「置内存字段 → 一次 seal → 再启动协程」**，不能反过来：若先启协程，审计失败会先把 `ModelImported` 清成 false，`saveModelSuccess` 随后又 seam 回 true，把 bug 反向复活。

```
processImportedResource:
  s.markModelAuditPending(req, phase)   // 仅内存：置 ActiveAudit*、CurrentAuditOp="auditing"、
                                        // AuditRunning=true、(仅当 ScanEnabled) pendingAudit=&{...}；不 seal
  s.saveModelSuccess(req.ResourceURL)   // 单次 seal：ModelImported=true + SavedModelResourceURL + AuditPending
  s.launchModelAudit(req, phase)        // runAsyncSafe("modelAudit", s.clearAuditState, fn)
```

即把现有 `startModelAuditAsync` 拆成 `markModelAuditPending`（置位）与 `launchModelAudit`（起协程）两半。

**清除 pending 的时机放在出结论时，而不是 release**：在 `auditAndReportModelImport` 顶部 `defer s.concludeAuditPending()`。理由：`release` 在整个 `fn` 之后才跑；若审计**通过**后在 `reportAuditAsync` 与 `release` 之间崩溃，只靠 release 清除会留下一个 pending 标记，而该模型其实已通过 → 重启时会误隔离。`clearAuditState` 里保留一次幂等清除作兜底。

**panic 回滚的锁序**（`stopActiveTraining` 取 `s.mu.RLock()`，`updateImportState` 取 `s.mu.Lock()`，`sync.RWMutex` 不可重入 → 持锁调用必死锁）：

```
s.mu.Lock()
  capture taskID, requestID, platformIP, dockerID        // 供解锁后上报
  s.resetAuditStateLocked()
  s.ModelImported = false
  s.SavedModelResourceURL = ""
  s.RuntimeConfig = ""
  s.pendingAudit = nil
  _ = s.sealStateLocked()                                  // 一次 seal：回滚 + 清 pending 同时落盘
s.mu.Unlock()
// 解锁之后：
cleanDirContents(s.Security.ModelDir)                      // 与 handleAsyncPanic 同包，可直接调
s.stopActiveTraining("模型安全审计 panic 未通过")
s.reportAuditAsync(requestID, taskID, 2, ..., "")
```

之后 `release`→`clearAuditState` 会再 seal 一次；因为 `sealStateLocked` 总是从内存 `s` 重建固定字段集，回滚结果不会被覆盖。

`runAsyncSafe` 的 defer 是 LIFO：recover-defer 先跑（`handleAsyncPanic`），`defer release()` 后跑。`clearAuditState`/`resetAuditStateLocked` 只碰 `ActiveAudit*`、`CurrentAuditOp`、`AuditRunning`，不碰 `ModelImported`，故回滚得以幸存。

## 改动

### `internal/store/sealed_state.go`
- 新增 `type AuditPendingSnapshot struct { RequestID, TaskID string; Phase int; StartedAt time.Time }`。
- `PersistentState` 在 `ActiveTask` 之后加 `AuditPending *AuditPendingSnapshot \`json:"auditPending,omitempty"\``。
- 更正 `:27` 的注释（现写"已解密且通过审计"，强于写入点），指向 `AuditPending`。

### `internal/controller/route.go`
- `TAAState` 加 `pendingAudit *AuditPendingSnapshot`（**不**从 `AuditRunning`/`CurrentAuditOp` 派生——否则恢复出的标记会让 `isAuditBusyLocked()` 恒真，经 `tryAcquireTask:588` 永久挡住所有模型导入）。
- `RestoreFromPersistentState`：**深拷贝** `p.AuditPending` 到 `s.pendingAudit`；显式保持 `AuditRunning=false`、`CurrentAuditOp="idle"`、`ActiveAuditTaskID/RequestID=""`。
- `sealStateLocked`：在 `ActiveTask` 块之后加 `state.AuditPending`，同样**深拷贝**（`StateStore` 把你交给它的 `*PersistentState` 当作活缓存，别名会让后续内存修改绕过 seal）。
- `updateImportState`：`isModel && !imported` 时一并 `s.pendingAudit = nil`（这让 `clearImportedState(true, …)` 同时满足失败路径与恢复路径的清理，且随其已有的 seal 落盘）。
- 新增 `markModelAuditPending(req, phase)`（置位，不 seal）、`launchModelAudit(req, phase)`、`concludeAuditPending()`（持锁；非 nil 则清 + seal；幂等）、导出 `PendingAudit() *AuditPendingSnapshot`。
- `handleAsyncPanic` 的 `modelAudit` 分支：按上面"锁序"重写。
- `clearAuditState`：seal 前顺带清 `pendingAudit` 作兜底（保持幂等）。

### `internal/controller/import_processing.go`
- `processImportedResource`（70-84）：改为 `markModelAuditPending` → `saveModelSuccess` → `launchModelAudit`。
- `startModelAuditAsync`（585-603）：拆成上述两半。
- `auditAndReportModelImport`（607）：顶部加 `defer s.concludeAuditPending()`。
- 正常失败分支（597-602）不变——`clearImportedState` 现在顺带清 pending。

### `internal/controller/handler_task.go`
- 下载失败分支（`:275-281`）：`release()` 之前加 `s.clearImportedState(true, phase)`。

### `internal/app/taa/recovery.go`
- 新增 `reconcileAbandonedAudit(ctx, state, store, pending)`：日志 → `utils.CleanDir(state.Security.ModelDir)`（沿用 `recovery.go:95` 的既有工具，非导出的 `cleanDirContents` 跨包不可用）→ `state.UpdateImportState(true, false, pending.Phase)`（清 `ModelImported`/`SavedModelResourceURL`/`RuntimeConfig`/`pendingAudit` 并 seal）→ `controller.ReportAudit(ctx, platformIP, dockerID, reqID, taskID, 2, msg, "")`。不调 `stopActiveTraining`（`startServer` 之前不可能有在飞训练）。

### `internal/app/taa/app.go`
- 在既有 `pState.ActiveTask` 恢复块（161-171）之后：`if p := state.PendingAudit(); p != nil { reconcileAbandonedAudit(ctx, state, stateStore, p) }`。读**当前内存值**而非 `pState`，这样"model_import 崩溃"已由 `reconcileCrashRecovery` 走 `UpdateImportState(true,false)` 清掉 pending 的情况不会重复上报。

## 测试（TDD：先写 → 逐条确认按预期原因失败 → 再实现）

| # | 测试 | 断言要点 |
| :-- | :--- | :--- |
| 1 | `TestModelImportSealsPendingWithModelImported` | 走 `markModelAuditPending` + `SaveModelSuccess`；`UnsealState()` 必须同时看到 `ModelImported==true` **与** `AuditPending != nil`（钉住"单次 seal"） |
| 2 | `TestScanDisabledSealsNoPending` | `ScanEnabled=false` 导入后 `AuditPending==nil`（钉住门控，防好模型被误隔离） |
| 3 | `TestAuditPanicRollsBackModelImport` | 置 `ModelImported`/`SavedModelResourceURL`/`pendingAudit` + ModelDir 放文件 + mock 平台；`handleAsyncPanic("modelAudit", …)` 后内存与盘上均 `ModelImported==false`、`pendingAudit==nil`、ModelDir 空、收到 code 2。**该用例同时守死锁：持锁误调 `stopActiveTraining` 会挂住** |
| 4 | 扩展现有 `TestConcurrency_AuditPanicDoesNotClearTrainingTask`（`concurrency_test.go:400-439`） | 保持"训练任务不被破坏"断言，另加"`ModelImported` 已回滚"；并设非 nil `trainingControl` 断言收到了 `requestStop` |
| 5 | `TestAuditVerdictClearsPending` | 通过/失败两路都断言盘上 `AuditPending==nil`；失败路另断言 `ModelImported==false` 且 ModelDir 空 |
| 6 | `TestModelImportDownloadFailureClearsModelImported` | 下载失败后 `ModelImported==false`（同类泄漏回归） |
| 7 | `TestRecovery_AbandonedAuditQuarantine`（app 包） | `PersistentState{ModelImported:true, AuditPending:{…}}` + `ActiveTask==nil` + ModelDir 有文件 → ModelDir 空、盘上 `ModelImported==false`、`AuditPending==nil`、收到且仅收到一条 code 2。这是 `TestRecovery_ModelImportQuarantine`（`recovery_test.go:165-215`）缺的 `activeTask==nil` 那一半 |
| 8 | `TestRecovery_NoPendingAudit_LeavesModelUntouched`（app 包） | `ModelImported==true` + `AuditPending==nil` + ModelDir 有文件 → 一切不变（守 `ScanEnabled=false` 与已正常完成审计的部署，防误隔离） |
| 9 | `TestPersistentState_AuditPendingRoundTrip`（store 包） | seal/unseal JSON 往返；nil 时 `omitempty` 不出字段（守旧文件兼容） |

## 验证

本仓 `go test ./...` 不可用（`models/audit/holdout-sources/` 有伪装成 `.go` 的 semgrep YAML），一律按包、`-p 1`：

```
go build -o bin/taa ./cmd/taa && go build -o bin/platform-mock ./tools/platform-mock/cmd/platform-mock
go vet ./cmd/... ./internal/... ./pkg/... ./tools/...
go test -p 1 -timeout 120s ./internal/store/...
go test -p 1 -timeout 180s ./internal/controller/...   # 注意既有 flake: TestConcurrency_DataImportAllowedWhileAuditing，约 7.5%
go test -p 1 -timeout 180s ./internal/app/taa/...
go test -p 1 ./internal/config/...
```

`-timeout` 显式给出：测试 3/4 若把 `stopActiveTraining` 误放进锁内会**挂死**而非报错，靠超时暴露。

## 不在本次范围（仅记录）

1. **C2 不动**：训练与审计解耦、以 `ModelImported` 触发，是有意设计且有 `TestConcurrency_DataImportAllowedWhileAuditing` 钉死。C1 修完后，"审计在飞"与"审计被遗弃"首次可区分，是否进一步收紧 C2 应单独决定。
2. **`AuditPending` 不上报平台**：与 C1 清单后续项 1 同源（`projectCodeAuditSection` 只发 `{conclusion, file_reports}`，有契约测试钉住），需先动载荷契约。
3. **空 URL 重导入分支**（`handler_task.go:245-248`）不审计即置位，是有意语义；本次只保证它的 seal 会正确带上在飞的 pending。
