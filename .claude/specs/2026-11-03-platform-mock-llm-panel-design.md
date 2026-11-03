# platform-mock 控制台 TEE-LLM 实例面板设计

**日期:** 2026-11-03
**状态:** 已确认，待实现

## 目标

让 platform-mock 内嵌控制台能看见 TEE-LLM 实例的接入情况：注册是否到达、自检验证结果、
心跳是否还在、运行日志内容，以及最近有哪些 `dockerId` 在向它上报。后端已经接收这些数据
（`/v1/llm/register`、`/v1/llm/heartbeat`、`/v1/llm/log`，状态由 `/api/llm/status` 暴露），
但控制台没有任何对应的视图，只能 curl。

## 非目标

- **不把 teellm 改成按 `dockerId` 的多实例模型。** 注册/心跳主状态仍是全进程单份，
  后注册覆盖先注册；多实例只以「最近来源」只读列表的形式呈现。
- 不改 `/v1/llm/*` 协议，不改 teellm 侧代码。
- 不改造底部「TAA 运行日志」卡片，不把 LLM 日志混进去。
- 不重做控制台视觉，新卡片复用既有卡片、状态灯、抽屉和 toast 组件。

## 数据模型

### 最近来源

`llmState` 增加 `sources` 列表，记录最近向 mock 上报的不同 `dockerId`：

```go
type llmSource struct {
    DockerID   string `json:"dockerId"`
    FirstSeen  string `json:"firstSeen"`  // RFC3339，首次出现
    LastSeen   string `json:"lastSeen"`   // RFC3339，最后一次活动
    LastEvent  string `json:"lastEvent"`  // register | heartbeat | log
    Registers  uint64 `json:"registers"`
    Heartbeats uint64 `json:"heartbeats"`
    Logs       uint64 `json:"logs"`
}
```

规则：

- 三个入口（register、heartbeat、log）在写入主状态的同时调用一次 `touchSource(dockerId, event)`。
- 同一个 `dockerId` 只保留一条，更新 `LastSeen` / `LastEvent` 并递增对应计数。
- 上限 **5** 条；超出时淘汰 `LastSeen` 最早的一条。
- 返回与持久化时按 `LastSeen` 倒序。
- `dockerId` 为空的请求在 handler 已被拒绝，不会进入列表。

主状态与来源列表互不影响：第二个不同的 `dockerId` 注册时，`register`/`heartbeat` 被覆盖，
列表里两条都在，控制台因此能看出「换过实例」。

### 重置语义

`POST /api/llm/reset` 现在只清 `register` 和 `heartbeat`，日志仍然留着。面板上按「重置」却
还看到旧日志会造成误解，因此重置改为同时清空：

- `register` → 空
- `heartbeat` → 零值
- `sources` → 空列表
- LLM 日志 store（`llm-log-state.json`）→ 空，复用 `taaLogStore.reset()`

### API

`GET /api/llm/status` 的响应增加 `sources`：

```json
{
  "register": { "...": "..." },
  "heartbeat": { "...": "..." },
  "logs": { "...": "..." },
  "sources": [
    { "dockerId": "taa-teellm", "firstSeen": "...", "lastSeen": "...",
      "lastEvent": "heartbeat", "registers": 1, "heartbeats": 42, "logs": 18 }
  ]
}
```

其余字段保持现状。该端点与改造前一样直接返回顶层 JSON 对象（不走 `/v1/taa/*` 那套
`{msg, result, error}` 信封），因此新增 `sources` 对既有调用方无影响。

## 前端

### 卡片位置与可见性

新增卡片 `#card-llm`，`data-console="tee"`，位于「平台注册」卡片之后、「训练流程」之前。
只在 TEE 控制台模式下显示：LLM 服务于 TEE 侧的代码审计，FHE 模式没有这条链路。

```
┌─ TEE-LLM 实例 ────────────────────┐
│ ● 在线   心跳 12 次 · 8s 前        │
│ dockerId: taa-teellm               │
│ 自检 ✓   报告 512 B   注册于 14:52 │
│ [公钥] [注册报文] [刷新] [重置]     │
│ ▸ 最近来源 (3)                     │
│ ▾ 运行日志  [暂停]                 │
│   14:52:03 INFO  [teellm] ollama…  │
└────────────────────────────────────┘
```

### 状态灯

三种已接入状态，外加未接入：

| 条件 | 显示 |
| --- | --- |
| `register.received == false` | 灰：等待 TEE-LLM 注册 |
| 已注册，无心跳 | 黄：已注册，等待心跳 |
| 最后一次心跳在 90 秒内 | 绿：在线 |
| 最后一次心跳超过 90 秒 | 红：离线（超过 3 个心跳周期） |

90 秒阈值取 spec 5.2 的「连续 3 个周期（90 秒）未收到判离线」，以 mock 侧
`heartbeat.receivedAt` 为准，不信任实例上报的 `timestamp`。

### 卡片元素

- **状态行**：状态灯、心跳次数、距上次心跳的相对时间（`8s 前` / `2m 前`）。
- **dockerId**：`register.dockerId`；为空时显示 `—`。
- **自检**：`register.verifiedPass` → `✓` / `✗`；`false` 时给 toast 风格提示色，
  但仍算正常接入（与 TAA 的降级语义一致，自检失败不拒绝注册）。
- **报告大小**：`register.attestationSize` 字节。
- **注册时间**：`register.receivedAt` 的时分秒。
- **公钥**：打开弹窗显示 `register.taaPublicKey`（PEM），复用现有公钥弹窗样式。
- **注册报文**：通过既有的 `recordInteraction('llmRegister', …)` 抽屉展示完整
  `register` 对象，不新造视图。
- **刷新**：立即拉一次 `/api/llm/status`。
- **重置**：调用 `/api/llm/reset`，成功后刷新并 toast 提示。

### 最近来源列表

默认折叠，标题显示条数（`最近来源 (3)`）。展开后每行：

```
taa-teellm        当前   心跳 · 8s 前
taa-teellm-old           注册 · 2h 前
```

- 当前生效的条目（`register.received && dockerId == register.dockerId`）标「当前」。
- 其余列 `dockerId`、最近事件中文标签（注册 / 心跳 / 日志）、最后活动相对时间。
- 最多 5 行，与后端上限一致；列表为空时整块隐藏。

### 运行日志

默认折叠。展开后：

- 渲染 `logs.entries` 的 `message` 字段（格式已是 `[时间] [级别] [组件] 正文`），
  等宽字体、限高 240px、自动滚到底。
- 「暂停」按钮冻结自动滚动与重绘，再次点击恢复并跳到底部；与底部 TAA 日志卡的暂停
  行为一致，但状态独立，互不影响。
- 无日志时显示「暂无日志」。

### 轮询

挂到 `PollingManager.mediumTier`（2 秒一次），复用其页面隐藏时暂停的机制；不新增
`setInterval`。`/api/llm/status` 是全局端点，不携带 `?dockerId=`。

## 测试

- `llm_state_test.go`：
  - 同一 `dockerId` 重复上报只保留一条，计数递增；
  - 超过 5 个 `dockerId` 时淘汰 `LastSeen` 最早的一条；
  - 返回顺序按 `LastSeen` 倒序；
  - 重置后 `sources` 为空。
- `handlers_llm_test.go`：
  - register、heartbeat、log 各自写入来源并更新 `lastEvent`；
  - `/api/llm/status` 返回 `sources`；
  - `/api/llm/reset` 同时清空注册、心跳、来源和日志。
- 前端无测试框架，靠手动验证：启动 mock → 用 curl 模拟 register/heartbeat/log →
  打开控制台确认状态灯、来源列表、日志展开与暂停、重置清空。

## 兼容性

- `llm-state.json` 旧文件没有 `sources` 字段，反序列化为空列表，无需迁移。
- `/api/llm/status` 只增加字段，既有调用方不受影响。
- 控制台在 FHE 模式下看不到新卡片，与改造前一致。
