# 结果目录查出原始数据时：上报 code=2，报告不带 result_files

## Context

训练结束时那次明文泄露检查（`bytes.Contains`）的裁决此前被折成报告里的 `result_files.contains_dataset`
布尔值上报。平台侧的要求变了：**查出结果目录含原始数据时不要只给一个标记位，而是直接把这次训练上报为失败**，
并且**连结果目录清单与预览都不给**——预览本身就是数据行，正是要拒的东西。

定稿行为（用户确认）：

- 移除 `report.result_files.contains_dataset`。
- 裁决指认泄露时：`/v1/taa/reportRes` 的 `code` 用 **2**（与 1 区分：1 是训练自己失败，2 是训练跑完了但产物被拒），
  `msg` 给出原因；报告体内 `training_task.status` 改为 `failed`、`failure_reason` 填同一原因，**`exit_code` 仍为 0**；
  报告**整段不带 `result_files`**。
- 只有"查出原始数据"才这样。检查自己没跑起来（裁决里 `error` 非空 / 没有裁决 / 开关关着）不算被拒，照常上报。
- `/v1/taa/export` 的闸门不变，泄露裁决照样 400。

## 实现

### `internal/controller/result_files.go`

- 新增 `reportCodeResultLeak = 2` 常量。
- 新增 `resultLeakDetected(v)`：`v != nil && v.Error == "" && !v.Passed`。其余情况（无裁决、检查执行失败）不算。
- 新增 `resultLeakText(base, v)`：把 `Details`（高危项 `[check] detail`）接在固定文案后面，供 `msg` 与 `failure_reason` 共用；
  两段固定文案分列 `resultLeakBaseReason` / `resultLeakBaseMsg`。
- `AttachResultFiles`：`resultLeakDetected` 为真时**直接返回**，连目录树都不扫。
- 删除 `verdictContainsDataset` 与 `contains_dataset` 写入；`buildResultFilesTree` 去掉 `resultCheck` 参数。

### `internal/controller/import_processing.go`（训练成功路径，约 :572）

原来的固定 `"succeeded", 0, ""` 与 `reportTrainingAsync(..., 0, "", ...)` 改成由裁决算出的 `status/exitCode/failureReason/code/msg`：

```go
status, exitCode, failureReason, code, msg := "succeeded", 0, "", 0, ""
if resultLeakDetected(trainResultCheck) {
    status = "failed"
    failureReason = resultLeakText(resultLeakBaseReason, trainResultCheck)
    code = reportCodeResultLeak
    msg = resultLeakText(resultLeakBaseMsg, trainResultCheck)
    s.Logs.Add(LogError, "report", "训练结果被拒: %s", failureReason)
}
```

`code=0` 的日志一并改成 `code=%d`。**失败路径（:966）与两条崩溃路径（`route.go` / `recovery.go`）不动**：
它们传 `nil` 裁决，本来就是 `code=1` + 完整报告。

## 测试

- `internal/controller/import_flow_new_test.go`：`phase1FlowCase` 增 `wantReportCode` / `wantReportStatus`；
  `runPhase1FlowCase` 按用例断言 code 与 `training_task.status`（顺带断言 `exit_code` 恒为 0）；
  `assertFlowResultCheck` 改成：泄露用例断言**没有 `result_files`** 且 `msg` 含"原始训练数据"，
  其余断言 `result_files` 照常在且**不再有 `contains_dataset`**。泄露用例填 `wantReportCode: reportCodeResultLeak`、`wantReportStatus: "failed"`。
- `internal/controller/import_processing_report_test.go`：`TestBuildAndSaveTrainingReportCarriesContainsDataset`
  改为 `TestBuildAndSaveTrainingReportWithholdsResultFilesOnLeak`，四个子测：泄露 → 内存报告与落盘的
  `training_report.json` 都没有 `result_files`；通过 / 无裁决 / 检查执行失败 → 都照常带树、且树里没有 `contains_dataset`。

## 文档

- `docs/api-design.md`：3.4 `code` 参数表补 `2`；两处示例去掉 `contains_dataset`；"关于 `result_files`" 第二条改为
  "检查指认泄露时整段不出现"，并新增"关于结果被拒（`code=2`）"小节；4.1 `preview` 出口的注解补例外。
- `README.md`：`security.resultCheck.enabled` 行末尾改为描述新的上报行为。
- `CHANGELOG.md`：删掉 `result_files.contains_dataset` 那条 Added，`Changed` 里新增本次行为（含 code 2、不带 tree、
  与 1 的区别），并把两处"失败检查只记日志、照常上报"的旧描述改成"训练进程不失败，但这次运行被上报为被拒"。

## 验证

1. `go test ./internal/controller/ -run 'ResultCheck|Report|Export' -count=1`
2. `go test ./...`（同一检出里不并发跑测试）
3. `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`
4. 端到端（可选，需 178）：训练命令往 `$TAA_OUTPUT_DIR` 写一个含 `id,label,image` 的 csv，
   平台侧应收到 `code=2`、`msg` 带"原始训练数据"、`report` 无 `result_files`、`status=failed`；随后导出 400。
