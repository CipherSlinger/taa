# 训练 100% 进度推迟到结果检查之后再上报

## Context

`executeTraining`（`internal/controller/import_processing.go:314`）里，`reportWatcher` 每 500ms 从模型进度目录读一次最新进度上报（`internal/controller/model_reporting.go:278`），训练命令退出时 `watcher.Stop()` 再刷一次。模型代码在训练收尾时会写 `{"percent":100}`，于是**平台在 TAA 还在拷贝产物、还在跑结果明文泄露检查时就看到了 100%**——而那次检查实测可跑到 80 秒（见 `.claude/plans/2026-10-15-result-check-at-training-end-plan.md`）。平台据此认为任务已结束。

用户要求：拿到 100% 或训练结束时先不上报 100%，直接进结果检查，检查结束后再补报 100%。

## 决策（已与用户确认）

1. **只延后真实的 100%**：模型写过 100% 才延后补发；模型从头到尾没写过 100%（例如只写到 97% 就正常退出）就不补，平台停在最后一个真实进度。不合成数据。
2. **被拒时照发**：检查判定结果目录里有明文泄露（`reportRes` code=2、`result_files` 整段省略）时，这 100% 照样补发——任务执行确实走完了，被拒这件事由 `reportRes` 告知平台。

## 方案

### 1. `reportWatcher` 扣住 100% 不发（`internal/controller/model_reporting.go`）

- 新增常量 `progressHoldPercent = 100.0`；
- `reportWatcher` 新增 `deferredProgress progressSnapshot` + `hasDeferredProgress bool`；
- `flushWithContext`：读到 `percent >= progressHoldPercent` 时**不调 `ReportProgress`**，把快照存进 `deferredProgress`、置位标记、记一条 info 日志，然后照旧更新 `lastProgressKey`（否则下一个 tick 会重复扣同一个快照）；
- 新增 `reportDeferredProgress(ctx)`：补发存下的快照，成功与否都清空标记（一次性，没有下个 tick 可重试）；没存过则空操作——这是「模型从没写过 100%」那条路径。

### 2. 检查结束后补发（`internal/controller/import_processing.go`）

在结果明文泄露检查那一整块之后、`StepSeparator("Build & Upload Report")` 之前调用：

```go
if !checkCancelled() {
    watcher.reportDeferredProgress(context.Background())
}
```

- 位置就是用户说的「结果检查结束后」；
- `ResultCheck` 关掉时检查块整段跳过，补发点因此落在产物拷贝之后——100% 仍不会早于产物归集；
- **失败与取消路径不补发**：训练命令报错、拷贝产物失败、检查中途被 stopTraining，都在补发点之前 return，扣住的 100% 随 watcher 一起丢掉。100% 的含义收窄为「TAA 把这次训练任务走完了」。

### 3. 不动的东西

不改 `reportProgress` 报文与字段、不改报告 schema、不改 `reportRes` 的 code，也不改 FHE 那条独立的上报路径（`fhe_processing.go` 自己算进度）。

## 测试

- watcher 单测：100% 不立即上报、`reportDeferredProgress` 后恰好上报一次；非 100% 立即上报（回归）；没扣过任何东西时 `reportDeferredProgress` 不发请求。
- `executeTraining` 端到端：训练命令写 100% + 开启 `ResultCheck`，断言平台收到 100% 时检查裁决**已经**落在导入索引记录上（顺序断言，而不是靠时间差）。
