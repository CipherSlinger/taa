# Platform Mock 调整与接口对接测试支持设计方案

## 1. 背景与目标

根据 `docs/taa接口设计文档.md` 规约，针对近期调整及新增的 5 个接口，调整 `platform-mock` 服务（位于 `internal/app/mock/`）及其嵌入式 Web 控制台（`index.html`），以全面支持本地开发、CI 测试及真实联调验证：

1. **/v1/taa/reportModelImport（TAA → 平台，模型导入与校验结果）**：规约对齐（必填字段 `requestId`、`code` 校验；`code=0` 时强制校验 `checksum: {size, algorithm, value}`；状态回显包含 checksum）。
2. **/v1/taa/reportAudit（TAA → 平台，代码安全审计结果）**：规约对齐（`code: 0/1/2` 校验；解析并展示重构后的 `statistics: {high, medium, low}` 三级风险归类统计）。
3. **/v1/taa/modelLog（TAA → 平台，任务终端日志）**：新增接收处理接口、`dockerId + requestId + seq` 去重及环形缓冲区，控制台终端日志流展示与查询。
4. **/v1/taa/reportProgress（TAA → 平台，训练进度上报）**：新增接收处理接口、时间戳防逆序机制，控制台动态进度条展示与查询。
5. **/v1/taa/stopTraining（平台 → TAA，中止任务）**：新增控制台调用中转与代理支持、流量捕获、控制台一键触发与结果回显。

---

## 2. 后端架构与接口设计

### 2.1 状态存储与数据结构

在 `internal/app/mock/server.go` 中维护各模块独立的状态存储：

#### 2.1.1 模型导入状态拓展（`reportModelImport`）
- 在现有 `reportState` 中确保 `Checksum map[string]any` 正确反序列化并保存。
- `reportStateResult(state)` 中新增输出 `"checksum": state.Checksum`。
- 校验规则：
  - `dockerId` 非空字符串；
  - `requestId` 非空字符串；
  - `code` 为整数（0 表示成功，非 0 表示失败）；
  - 当 `code == 0` 时，请求必须包含非空 `checksum`，且 `checksum["size"] > 0`、`checksum["algorithm"] != ""`、`checksum["value"] != ""`；不满足时返回 HTTP 400。

#### 2.1.2 代码审计状态拓展（`reportAudit`）
- 校验规则：
  - `dockerId` 非空字符串；
  - `requestId` 非空字符串；
  - `code` 为 0（通过）、1（未通过/高危）、2（LLM 不可用）；
- 状态结构中自动解析 `report` JSON 字符串中的 `conclusion.risk_level` 与 `conclusion.statistics`（含 `high`, `medium`, `low` 计数值），并在 `reportStateResult` 中透出，供控制台直观呈现。

#### 2.1.3 训练进度状态（`reportProgress`）
- 数据结构：
  ```go
  type progressState struct {
      Received    bool    `json:"received"`
      Accepted    bool    `json:"accepted"`
      ReceivedAt  string  `json:"receivedAt"`
      DockerID    string  `json:"dockerId"`
      RequestID   string  `json:"requestId"`
      TaskID      string  `json:"taskId"`
      Percent     float64 `json:"percent"`
      Timestamp   string  `json:"timestamp"`
      StatusCode  int     `json:"statusCode"`
      Message     string  `json:"message"`
      RawBody     string  `json:"rawBody"`
  }
  ```
- 校验与时序规则：
  - `dockerId`、`requestId` 必填；
  - `percent` 必须满足 `0.0 <= percent <= 100.0`；
  - 解析 `timestamp`（RFC3339 格式）：若新进时间戳早于当前记录的时间戳，仍正常返回 HTTP 200 `{"received": true}`，但不覆盖已有的较新进度快照。
- 持久化至 `stateDir/reportProgress-state.json`。

#### 2.1.4 任务终端日志状态（`modelLog`）
- 数据结构：
  ```go
  type modelLogEntry struct {
      Seq       uint64 `json:"seq"`
      Message   string `json:"message"`
      Timestamp string `json:"timestamp"`
  }
  type modelLogState struct {
      DockerID   string          `json:"dockerId"`
      RequestID  string          `json:"requestId"`
      TaskID     string          `json:"taskId"`
      TotalCount int             `json:"totalCount"`
      LastSeq    uint64          `json:"lastSeq"`
      Entries    []modelLogEntry `json:"entries"`
  }
  ```
- 去重与容量规则：
  - 校验 `dockerId`、`requestId` 必填；
  - `entries` 数组非空，每项包含 `seq` 及非空 `message`；
  - 使用 `dockerId:requestId:seq` 进行唯一性判定，已存在项幂等跳过；
  - 有序插入环形切片，最多保留最近 2000 条条目；
  - 持久化至 `stateDir/modelLog-state.json`。

---

### 2.2 HTTP 路由设计

```
# TAA 回调接口（TAA → Mock）
POST /v1/taa/reportModelImport  — 接收模型导入结果
POST /v1/taa/reportAudit        — 接收代码审计结果
POST /v1/taa/reportProgress     — 接收训练进度快照
POST /v1/taa/modelLog           — 接收终端日志流

# 控制台查询与重置接口（Console → Mock）
GET,POST /api/reportProgress/status — 获取当前任务进度
POST     /api/reportProgress/reset  — 重置任务进度
GET,POST /api/modelLog/status       — 获取终端日志列表与最新状态
POST     /api/modelLog/reset        — 清空终端日志缓存

# 控制台代理控制接口（Console → Mock → TAA）
POST     /api/taa/stopTraining      — 向 TAA 发送中止训练请求
```

- **统一公共返回格式**：所有接口遵循 `{ "msg": "...", "result": ..., "error": 0 }`。
- **流量监控拦截**：
  - `requestComponentFromPath` 新增组件标记：`/v1/taa/modelLog` → `modelLog`、`/v1/taa/reportProgress` → `reportProgress`、`/v1/taa/stopTraining` → `taa-stopTraining`。
  - 控制台发起 `/api/taa/stopTraining` 时，记录出站请求与返回体至 `requestLogs`。

---

## 3. Web 控制台前端交互设计（`index.html`）

### 3.1 训练进度与控制栏
- 布局位置：位于卡片 `card-reportRes`（训练相关卡片）顶部。
- **实时进度条**：
  - 0% ~ 100% 动态高亮进度条；
  - 显示进度百分比（如 `45.5%`）、最新更新时间、`requestId` 与 `taskId` 标识；
  - 提供“重置进度”快捷操作。
- **中止训练控制**：
  - 放置“🛑 中止训练”红色控制按钮；
  - 点击向 `/api/taa/stopTraining` 发起请求，按钮置为 loading；
  - 返回后显示执行结果（如 `✅ 训练任务已中止` 或 `ℹ️ 不存在训练任务`）。

### 3.2 模型导入与审计卡片增强
- **`reportModelImport` 弹窗**：格式化呈现响应体，并在顶部明显块高亮展示 `checksum`（`size`, `algorithm`, `value`）。
- **`reportAudit` 状态与弹窗**：
  - 状态栏显示风险结论与徽标（如 `PASS [NONE]` 或 `FAIL [HIGH]`）；
  - 弹窗顶部显式展示三级风险归类统计：`高危(high): X` | `中危(medium): Y` | `低危(low): Z`。

### 3.3 模型终端日志面板
- 布局位置：位于页面底部“TAA 实时日志”旁边或下方，采用黑底现代终端样式窗口。
- 窗口元素：
  - 标题及窗口装饰按钮（红/黄/绿点）；
  - 当前条数指示与最新 seq 序号徽标；
  - 操作工具栏：自动刷新间隔选择器（1s/3s/5s）、暂停/继续按钮、清空日志按钮；
  - 内容区：条目按 seq 升序排列展示 `[seq=N] <message>`，默认自动滚动至底端。

### 3.4 流量监控下拉过滤项
- 接口过滤下拉列表中补充 `/v1/taa/stopTraining（中止任务）`。

---

## 4. 验证与测���策略

1. **单元测试与集成测试（`internal/app/mock/server_test.go`）**：
   - `TestReportModelImportValidationAndChecksum`：验证必填字段校验、`code=0` 时缺少 `checksum` 报错（400），正常上报时 status 能取到 checksum。
   - `TestReportAuditStatisticsParsing`：验证 `reportAudit` 请求接收及对 `statistics: {high, medium, low}` 的解析。
   - `TestReportProgressHandlingAndTimestampOrdering`：验证进度更新及乱序逆序时间戳不覆盖最新进度的机制。
   - `TestModelLogDeduplicationAndRingBuffer`：验证相同 `dockerId + requestId + seq` 去重及乱序日志按 seq 排序。
   - `TestTAAStopTrainingProxyAndLogging`：验证 `/api/taa/stopTraining` 对 TAA 的代理转发与在 `requestLogs` 中的记录。
   - `TestIndexHTMLComponentsPresence`：验证前端 HTML 中包含新增进度条、中止按钮、日志终端面板等必要 DOM 节点与事件绑定。
2. **端到端功能验证**：
   - 启动平台 mock 服务，通过 HTTP client 模拟发送 5 类请求，验证控制台实时更新与状态一致性。
