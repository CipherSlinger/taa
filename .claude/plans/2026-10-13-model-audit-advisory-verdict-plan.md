# 实施：模型代码审计改为"仅供参考" + 规格同步

**日期**：2026-10-13
**设计**：`.claude/specs/2026-10-13-model-audit-advisory-verdict-design.md`
**范围**：`internal/controller`、`internal/app/taa`、`internal/store`、`internal/codeaudit`、`docs/`、`api/`、
`README.md`、`CHANGELOG.md`、`tools/platform-mock`。不新增接口、不改平台载荷结构。

## A. 逻辑（问题 1）

1. `internal/controller/import_processing.go`
   - 删除 `stopActiveTraining`（两个调用点都去掉后已无调用者）。
   - `launchModelAudit`：回调只记 WARN，不回滚；文档注释写明"仅供参考"。
   - `auditAndReportModelImport`：注释改为"只读、只判、只报；裁决仅供参考，调用方仅记日志"。
2. `internal/controller/route.go`
   - `handleAsyncPanic` 的 `modelAudit` 分支：去掉回滚导入与中止训练，保留审计态复位、清待决标记并落盘、
     上报 code=2。
   - 新增导出包装 `ConcludeAuditPending()`，供启动期对账在补报后清标记。
   - `pendingAudit` / `beginModelImportAndAudit` / `updateImportState` / `markModelAuditPendingLocked` /
     `concludeAuditPending` 注释按新语义更新。
3. `internal/app/taa/recovery.go`
   - `reconcileAbandonedAudit` 改为 report-only：调 `ConcludeAuditPending()`（放在 platformIP 空返回之前，
     保证标记一定被清），`reportAudit` code=2，文案点明"不阻断模型导入与训练"。删除
     `state.UpdateImportState(true, false, pending.Phase)`。
4. `internal/store/sealed_state.go`
   - `AuditPending` 字段注释：启动期"补报参考结论"，不再改变模型是否可用。
5. `internal/codeaudit/audit.go`
   - 总结文本去掉对 TAA 动作的宣称：`禁止导入` → `建议拒绝该模型`；`准予导入` → `未发现阻断级风险`；
     `建议阻断导入` → `建议拒绝该模型`；`fail-closed 阻断策略，禁止导入` →
     `fail-closed 阻断策略，审计结论为未通过`（保留 `fail-closed 阻断策略` 字样，现有断言依赖它）。

## B. 测试

| 文件 | 变更 |
| :--- | :--- |
| `internal/controller/model_audit_pending_test.go` | `TestAuditPanicRollsBackModelImport` → `TestAuditPanicLeavesModelImported`；`TestAuditFailureClearsPending` 改为断言 `ModelImported` 保持 |
| `internal/controller/concurrency_test.go` | `TestConcurrency_AuditPanicRollsBackModelButKeepsTrainingTask` → `TestConcurrency_AuditPanicKeepsModelAndTrainingTask`：断言模型保持、训练**未**被取消 |
| `internal/controller/import_flow_new_test.go` | `TestPhase1ModelAuditFailureAbortsTraining` → `TestPhase1ModelAuditFailureDoesNotBlockTraining`：仍断言 `reportAudit` code 1/2 与目录原样，改为断言数据下发后训练照常执行并上报 `reportRes` |
| `internal/app/taa/recovery_test.go` | `TestRecovery_AbandonedAuditQuarantine` → `TestRecovery_AbandonedAuditReportsOnly`：只报不改（URL 保留、标记清除、目录逐字节一致） |
| `internal/controller/security_hardening_test.go` | `TestAuditFailureAbortsWithoutClearingDir` → `TestAuditFailureLeavesModelDirIntact`（仅名称与注释） |

## C. 文档同步（问题 2–5）

| 问题 | 处置 |
| :--- | :--- |
| 2 规格过期：空 `resourceUrl` 被写成"直接对最新数据训练" | `docs/api-design.md` §4.3 参数表 + 执行规则条目改为"只更新运行配置、不触发训练"；`api/openapi.yaml` `ImportModelRequest.resourceUrl` 描述同步 |
| 3 openapi 200 契约错误 | 200 描述改为"请求已受理，`result` 恒为 `null`，结果走 `reportModelImport`/`reportAudit`"，删掉 `auditPassed` 假字段；`runtimeConfig` 示例改为合法 JSON 对象串 |
| 4 响应面不全 | §4.3 与 openapi 补齐 400 各场景、409（三种忙碌文案）、500；补空 `resourceUrl` 成功消息，并注明非空 URL 的"训练结果将通过 reportRes 上报"是历史遗留文案 |
| 5 架构文档安全声明与代码不符 | `docs/architecture-design.md` 总述、"审计后执行"表项、时序图 `reportRes (上报审计通过或阻断)`、§5.2 流程图、§6.1 补"结论仅供参考"说明；`README.md` mermaid 门禁标签、能力清单第 4 条、审计章节、二进制通道的 "blocks the import" 系列措辞、`llm.policy`/`temperature` 配置说明 |
| 附带 | `api/proto/taa.proto` `ImportModelRequest` 补 `public_key = 5` 与 `ReportAuditRequest.code` 注释；`tools/platform-mock` 裁决 pill 与 stepper 不再把未通过画成流水线中断；`docs/model-file-io-guide.html` 去掉"导入阶段即被阻断"与失效文档引用；`CHANGELOG.md` `[Unreleased] → Changed` 增条目 |

历史记录（`CHANGELOG.md` 已发布段、`.claude/specs|plans` 中 2026-10-09 的两份文档）**不重写**，它们是
当时契约的存档。

## D. 验证

- `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`
- `go vet ./internal/controller/... ./internal/app/taa/... ./internal/store/...`
- `go test ./internal/controller/... ./internal/app/taa/... ./internal/store/... ./internal/codeaudit/...`
- `go test ./...`
- `python3 -c "import yaml; yaml.safe_load(open('api/openapi.yaml'))"`
