# 模型代码审计改为"仅供参考"（2026-10-13）

## 1. 触发

对 `/v1/taa/importModel` 的规格与实现做对照复核后，确认审计在实现里承担了**闸门**角色：审计失败会清
`ModelImported` 并中止在飞训练。平台方裁定该角色不成立——

> **审核不通过的模型不阻塞训练，该审核结果只作为参考结果。**

崩溃/panic 导致审计没跑出结论时，同样**只作参考、不拒绝导入**（与裁决失败同等对待）。

## 2. 改前语义（被替换的契约）

| 触发点 | 改前行为 | 位置 |
| :--- | :--- | :--- |
| 审计判 `passed=false` | `clearImportedState`（`ModelImported=false`、清 `SavedModelResourceURL`）+ `stopActiveTraining` | `import_processing.go` 审计回调 |
| LLM 不可用（fail-closed） | 同上，`reportAudit` code=2 | 同上 |
| 审计 goroutine panic | `handleAsyncPanic` 的 `modelAudit` 分支：复位审计态 + 回滚导入 + 中止训练 + code=2 | `route.go` |
| 进程崩溃在审计途中 | 启动期 `reconcileAbandonedAudit`：回滚 `ModelImported` + 清 URL + 补报 code=2 | `internal/app/taa/recovery.go` |
| 审计总结文本 | 「建议阻断导入」「禁止导入」「准予导入」 | `internal/codeaudit/audit.go` |

配套契约见 `2026-10-09-abandoned-model-audit-rollback.md`（那份计划是当时的设计记录，**不重写**；
本文件是它的替代契约）。

## 3. 新语义

**不变式：审计裁决（通过 / 未通过 / 无结论）不改变任何导入与训练相关的状态。**

只读、只报：审计读模型目录、出结论、经 `/v1/taa/reportAudit` 上报，此外不动任何东西。

| 触发点 | 改后行为 |
| :--- | :--- |
| 审计判 `passed=false` | 仅上报 code=1 + 记一条 WARN 日志；模型保持已导入、可复用；在飞训练继续跑 |
| LLM 不可用（fail-closed） | 仅上报 code=2；同上 |
| 审计 goroutine panic | 复位审计态（`AuditRunning`/`CurrentAuditOp`/`ActiveAudit*`）+ 清待决标记并落盘 + 上报 code=2；**不回滚导入、不中止训练** |
| 进程崩溃在审计途中 | 启动期清待决标记并落盘 + 补报 code=2；**不回滚导入** |
| 审计总结文本 | 「建议拒绝该模型」「审计结论为未通过」「未发现阻断级风险」——描述裁决本身，不再宣称 TAA 执行了阻断 |

模型包与依赖库在任何路径下都保持上传原样：这是审计自身的契约（审计从不写、不删、不改它读的东西），
新语义只是把这条契约从前置闸门扩展到全部路径。

### 保留：并发闸门与裁决无关

审计进行中仍拒绝**新的模型下发**（409「当前已有模型代码审计正在执行中」），理由不是裁决，而是两轮导入
会争用同一个模型目录。数据下发与训练在审计进行中照常放行。训练任务在飞时的 409 同样保留。

### 保留：待决标记机制

`AuditPending` 继续落盘。它的作用从"崩溃后回滚的依据"变成"崩溃后知道欠平台一次补报的依据"——审计
goroutine 比导入任务活得久，崩溃时 `activeTask` 已释放，没有这个标记就没有任何东西记录过"这里欠一次
审计结论"。删掉它会让崩溃的审计静默消失。

## 4. 影响面

- **状态面**：`ModelImported` / `SavedModelResourceURL` 不再被审计路径改写。
- **启动对账**：`reconcileAbandonedAudit` 变为 report-only；`reconcileCrashRecovery` 的 `model_import`
  回滚**不动**——那条路径针对的是"导入任务本身没跑完"（此时盘上可能只有半个模型），与审计裁决无关。
- **可观测**：审计失败从"静默改状态"变成一条显式 WARN 日志 + `reportAudit` code=1/2。
- **平台侧**：结论仅供参考，采取行动（是否采用该模型）是平台的判断。

## 5. 残留边界（不在本次范围内）

- 审计结论的说服力仍受 `2026-10-08-llm-timeout-layering-design.md` 描述的降级路径约束：LLM 不可用时
  结论可能是"未得出结论"而非"代码有问题"。改为仅供参考后，这条降级不再有阻断性后果，但它对结论质量的
  影响依旧存在。
- 空 `resourceUrl` 复用路径的 `hasSavedModel()` 目录回退（`route.go`）本可"复活"被审计拒绝的模型——审计
  不再回滚后该场景自然消失，故未改动。
