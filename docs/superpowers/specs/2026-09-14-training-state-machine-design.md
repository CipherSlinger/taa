# TAA 训练状态与导入触发逻辑重构设计规范

- **日期**：2026-09-14
- **状态**：待用户复核
- **适用范围**：`internal/controller` 的模型/数据导入、训练触发、阶段切换、状态持久化与状态接口

---

## 1. 背景与目标

当前控制器使用 `DataImported`、`TrainingDone` 和 `Phase1TrainingStarted` 等字段协同判断阶段 1 的训练触发。这种设计将训练流程绑定到阶段与“数据是否导入”的历史标志，导致：

1. 数据导入必须等待 `DataImported` 与 `ModelImported` 同时为真；
2. 阶段 1 训练完成后，`Phase1TrainingStarted` 会阻止同阶段再次训练；
3. `TrainingDone` 表示最近一次训练结果，而不是当前训练是否运行，容易与实时状态混淆；
4. 阶段切换到阶段 1 会重置模型标志，不符合模型在 TAA 生命周期内持续复用的要求。

本次重构目标：

- 彻底删除 `DataImported` 的运行时字段、持久化字段和 API 返回字段；
- 保留 `TrainingDataImported` 作为阶段 3 的兼容状态字段，但不参与训练触发；
- 彻底删除 `TrainingDone` 和 `Phase1TrainingStarted`；
- 新增唯一实时训练状态 `TrainingRunning`；
- 数据导入完成后以 `ModelImported` 作为训练触发前置条件；
- 任意阶段都允许重复执行训练，但同一时刻只能有一个真实训练任务；
- 阶段切换不再重置 `ModelImported`。

---

## 2. 状态模型

### 2.1 TAAState 字段调整

保留：

```go
ModelImported        bool
TrainingDataImported bool
TrainingRunning      bool
```

删除：

```go
DataImported         bool
TrainingDone         bool
Phase1TrainingStarted bool
```

字段语义：

| 字段 | 语义 | 设置时机 | 清除时机 |
| :--- | :--- | :--- | :--- |
| `ModelImported` | 当前已有可复用模型状态/模型请求已被接受 | 模型请求完成基础参数校验、携带非空 URL 且成功取得任务执行权后立即置为 `true` | 模型下载、解密、解压或审计失败时回滚为 `false`；阶段切换不清除 |
| `TrainingDataImported` | 阶段 3 数据导入兼容状态 | 阶段 3 数据成功保存后置为 `true` | 阶段 3 数据处理失败时清除 |
| `TrainingRunning` | 当前是否存在真实训练执行任务 | 训练任务获得独占执行权、开始进入训练流程前置为 `true` | 训练成功、失败、报告生成失败、panic 或崩溃恢复完成后置为 `false` |

`TrainingRunning` 不表示最近一次结果，也不依赖 `CurrentPhase`。

### 2.2 PersistentState 调整

从密封持久化结构中删除：

```go
DataImported
TrainingDone
```

新增：

```go
TrainingRunning bool `json:"trainingRunning"`
```

`TrainingDataImported` 暂时保留并继续持久化，以保持阶段 3 兼容性。由于旧版本密封 JSON 中包含已删除字段，Go JSON 反序列化会忽略未知字段；保存新版本时不再写回这些字段。`DefaultStateVersion` 递增到 `1.4`，用于明确标识新状态结构。

### 2.3 状态接口

`/v1/taa/health` 与 `/v1/taa/status`：

- 删除 `dataImported`；
- 删除 `trainingDone`；
- 保留 `trainingDataImported`；
- 新增 `trainingRunning`。

状态查询只反映当前内存和密封状态，不通过历史报告推断训练是否完成。

---

## 3. 导入与训练数据流

### 3.1 模型请求

模型请求完成基础 JSON、标识和并发校验后：

1. 若 `resourceUrl` 非空，立即将 `ModelImported` 置为 `true` 并密封保存；
2. 异步执行下载、解密、解压和审计；
3. 若任一步失败，执行 fail-closed 清理并将 `ModelImported` 回滚为 `false`；
4. 若 URL 为空，继续表示复用当前模型，不改变 `ModelImported`；
5. 阶段切换只更新 `CurrentPhase`，不重置 `ModelImported`。

“立即置位”仅针对通过基础校验并成功取得任务执行权的非空 URL 请求；被并发拒绝的请求不得改变模型状态。失败回滚是为了避免失败模型请求被误认为可训练模型。

### 3.2 数据请求

数据请求不再读写 `DataImported`。数据处理顺序为：

```text
数据请求
  → 下载
  → 解密
  → 计算哈希
  → 保存/复用 hash 数据目录
  → 写入导入索引
  → 更新 LatestDataRecord / CurrentDataRecord
  → 检查 ModelImported
```

- `ModelImported == false`：数据保存成功后结束本次导入，等待后续模型请求；
- `ModelImported == true`：直接尝试启动训练，不再等待数据标志或阶段 1 专用标志。

模型先到、数据后到时，数据流程直接使用最新数据启动训练。数据先到、模型后到时，模型流程在模型处理成功后复用 `LatestDataRecord` 启动训练。上述行为适用于所有阶段。

阶段 3 数据成功仍可设置 `TrainingDataImported = true`，但该字段不参与训练触发。

---

## 4. 训练并发与生命周期

### 4.1 独占条件

训练并发检测必须依据 `TrainingRunning`，不得依据阶段或 `Phase1TrainingStarted`：

```text
收到会触发训练的请求
  → 加锁
  → TrainingRunning == true？
      是：返回 409 Conflict
      否：设置 TrainingRunning=true，记录 ActiveTask
  → 解锁
  → 执行训练
```

该规则对阶段 1、2、3、4 完全一致。训练完成后，下一次请求可以重新启动训练，不要求切换阶段。

模型/数据下载和导入仍可使用 `ActiveTask` 记录生命周期；现有阶段 1 “模型/数据配对”特殊放行逻辑必须删除，避免并发判断重新依赖阶段。

### 4.2 真实训练状态边界

`TrainingRunning` 应在训练流程正式获得执行权后设置为 `true`，并在所有出口统一清除：

- 模型输入/输出目录准备失败；
- runtimeConfig 执行失败；
- 训练产物拷贝失败；
- 训练报告生成失败；
- 训练报告上报成功或失败后的正常收尾；
- 异步 goroutine panic；
- 启动时发现密封状态为 `RUNNING` 并完成崩溃恢复。

统一收尾应保证：

```go
TrainingRunning = false
ActiveTask = nil
ActiveTaskID = ""
ActiveRequestID = ""
CurrentOp = "idle"
```

状态清除必须通过受保护的状态更新函数完成，并同步密封持久化。

### 4.3 训练报告

训练成功或失败报告继续通过现有报告生成和上报流程处理；报告结果不再写入 `TrainingDone`。报告中的 `status` 是单次任务结果，`TrainingRunning` 是实时控制状态，两者职责分离。

---

## 5. 异常处理与恢复

1. 模型请求在异步处理前置位，但下载/解密/解压/审计失败时必须回滚 `ModelImported`，并清理模型目录；
2. 数据导入失败不再清除不存在的 `DataImported`，但需保留导入索引回滚、当前数据记录清理和失败报告逻辑；
3. 训练异常由统一 defer/释放函数清除 `TrainingRunning`；
4. panic 恢复需要清除 `TrainingRunning`，保留现有失败报告、平台补偿上报和活动任务清理；
5. 冷启动恢复读取 `TrainingRunning` 与 `ActiveTask`，若发现任务状态为 RUNNING，按现有 crash recovery 处理并在完成后将其置为 `false`；
6. 阶段切换期间若 `TrainingRunning == true`，继续返回 409；训练状态为 `false` 时允许切换，且不重置 `ModelImported`。

---

## 6. 测试设计

### 6.1 状态结构与 API

- 编译级检查：`TAAState` 不再包含 `DataImported`、`TrainingDone`、`Phase1TrainingStarted`；
- 密封 JSON 不包含 `dataImported`、`trainingDone`；
- 密封 JSON 包含 `trainingRunning`；
- 旧状态加载后可忽略已删除字段，并按 1.4 结构重新保存；
- `/health` 和 `/status` 不返回 `dataImported`、`trainingDone`，返回 `trainingRunning`；
- `TrainingDataImported` 仍按阶段 3 兼容规则工作。

### 6.2 导入触发

- 非空模型 URL 通过基础校验并取得执行权后立即将 `ModelImported` 置为 `true`；
- 模型请求失败时回滚 `ModelImported`；
- 阶段 1 → 2、2 → 3、3 → 4、4 → 1 均不重置 `ModelImported`；
- 模型先到、数据后到时自动训练；
- 数据先到、模型后到时模型成功后自动训练；
- 四个阶段都不依赖 `DataImported` 或 `Phase1TrainingStarted`。

### 6.3 训练并发

- `TrainingRunning == true` 时，任意阶段的第二个训练请求均返回 409；
- 第一次训练正常结束后 `TrainingRunning == false`；
- 训练失败、报告生成失败、panic 和 crash recovery 后 `TrainingRunning == false`；
- 训练结束后不切换阶段即可再次训练；
- 阶段切换只要训练未运行即可执行，且不影响 `ModelImported`。

### 6.4 验证命令

```bash
/usr/local/go/bin/go test ./...
git diff --check
```

---

## 7. 非目标

- 不重构导入索引的数据目录结构；
- 不修改模型审计策略和报告 Schema；
- 不删除 `TrainingDataImported`，其后续清理另行评估；
- 不改变模型或数据请求的外部 API 路径和 HTTP 方法。
