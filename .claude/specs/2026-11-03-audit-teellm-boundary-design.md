# 审计逻辑下沉 TAA、teellm 收敛为纯推理服务 设计

- 日期：2026-11-03
- 状态：已确认（边界由用户拍板）
- 范围：`teellm/` 子模块（服务端 + 其内置的 TAA 客户端）与 TAA `internal/codeaudit`、`internal/llmclient`（新增）

## 1. 背景与问题

当前审计语义散落在两侧：

- TAA（`internal/codeaudit`）负责扫描、分类、统计与放行判定；
- teellm 服务端的 `OllamaBackend.HandleVerifyFinding` 里还留着**审计语义**：提示词模板
  （`findingAnalysisPromptTemplate`）、`rawDecision`、verdict 解析，以及被强制为 0 的 temperature。
- TAA 编译进自己二进制的客户端（`teellm/client.go`、`retry.go`、`circuit_breaker.go`、
  `validator.go`）也放在 teellm 模块里，导致 TAA 依赖远端服务的协议类型。

用户要求：**远端 LLM 服务只需要"大模型功能"**，审计逻辑全部归 TAA，便于以后把审计整理成
独立仓库；teellm 仓库保持干净。

## 2. 目标与非目标

### 目标

- teellm 对外只提供：通用推理、健康检查、远程证明、平台上报。
- TAA 侧承接全部审计语义：提示词、verdict 解析、fail-closed、统计与结论。
- TAA 不再 import `github.com/CipherSlinger/teellm`。
- teellm 不再存在 `FindingPayload`、`DecisionResult`、`verdict` 等审计概念。

### 非目标

- 不改平台上报（注册/心跳/日志）与 `getAttestation`。
- 不保留 `/v1/llm/verify` 旧路径（TAA 与 teellm 同版本升级）。
- 不改 `teetls`。
- 不引入流式返回、不引入新的鉴权。
- 不改变审计的判定语义与 fail-closed 行为。

## 3. 边界定义

### 3.1 teellm 保留（通用推理网关）

| 路径 | 作用 |
|---|---|
| `POST /v1/llm/generate` | 通用推理：给提示词，返回模型文本 |
| `GET /v1/llm/healthz` | 就绪检查（含一次真实推理探针，行为不变） |
| `POST /v1/llm/getAttestation` | 平台索取 CSV 远程证明 |

服务端保留：Ollama 后端、模型目录、重试（仅服务端到 Ollama 需要的部分，实际无）、
TEE-TLS、平台上报器、日志缓冲。

服务端**不再**：拼审计提示词、解析 verdict、强制 temperature、认识任何审计字段。

### 3.2 TAA 承接

| 新增/修改 | 职责 |
|---|---|
| `internal/llmclient/`（新包） | 传输层：TEE-TLS、endpoint 校验、重试、熔断、`/v1/llm/generate` 与 `/v1/llm/healthz` 客户端、协议类型 |
| `internal/codeaudit/prompt.go`（新文件） | 审计提示词模板与 `BuildFindingPrompt` |
| `internal/codeaudit/verifier.go` | 调 `Generate`，用 `parseDecision` 解析返回文本 |
| `internal/codeaudit/llm.go` | 本地 `LLMClient` 接口与客户端构造 |

`internal/llmclient` 不含任何审计词汇，只认识 "prompt 进、text 出"。

## 4. 线协议

### 4.1 请求

```json
{
  "protocolVersion": "teellm-protocol/v1",
  "requestId": "verify-1730000000000000000",
  "model": "qwen2.5-coder:3b",
  "prompt": "...",
  "options": { "temperature": 0 }
}
```

- `model` 省略时用服务端默认模型。
- `options` 原样透传给 Ollama；服务端先合并模型目录里的 profile options，再用请求里的
  `options` 覆盖。

### 4.2 响应

```json
{
  "protocolVersion": "teellm-protocol/v1",
  "requestId": "verify-1730000000000000000",
  "status": "SUCCESS",
  "model": "qwen2.5-coder:3b",
  "text": "..."
}
```

- 失败时 `status` 取 `INVALID_REQUEST` / `MODEL_NOT_FOUND` / `INTERNAL_ERROR` /
  `SERVICE_UNAVAILABLE`，并带 `errorMessage`。
- 不做 verdict 字段、不做 JSON 抽取，`text` 是模型原始输出。

## 5. 关键决策

1. **审计提示词与解析全部在 TAA。** teellm 只转发。提示词模板从
   `teellm/ollama_backend.go` 原样搬到 `internal/codeaudit/prompt.go`，逐字保留（包含前置评分
   标准与尾部重述），避免改变判定行为。
2. **temperature 由 TAA 显式发送。** 服务端不再钉 0。`LLMConfig.Temperature` 为 nil 时 TAA
   发 0，保持既有"确定性裁决"语义；非 nil 时按配置发送。
3. **TAA 侧客户端搬进 `internal/llmclient`。** 父模块 `go.mod` 移除
   `github.com/CipherSlinger/teellm` 依赖，TAA 与远端服务之间只靠线协议耦合。
4. **不保留旧接口。** `/v1/llm/verify` 直接删除。TAA 与 teellm 镜像必须同版本部署，否则审计
   会整体失败（fail-closed 下表现为导入被拒）。
5. **`num_predict` 默认值留在服务端模型目录**，请求里的 `options` 覆盖它。TAA 目前只发送
   `temperature`，不新增 `maxCompletionTokens` 配置；覆盖能力只为将来保留。

## 6. 代码落点

### 6.1 teellm（删除/收敛）

| 文件 | 处理 |
|---|---|
| `types.go` | 重写为 `GenerateRequest` / `GenerateResponse` + 状态常量；删除 `FindingPayload`、`DecisionResult`、`PolicyOptions`、`RequestEnvelope` 等 |
| `server.go` | `/v1/llm/verify` → `/v1/llm/generate`；`Backend` 接口改为 `Generate` + `HandleHealthCheck` |
| `ollama_backend.go` | 删除提示词模板、`rawDecision`、`parseDecisionJSON`；新增通用 `Generate` |
| `client.go`、`retry.go`、`circuit_breaker.go`、`validator.go` | 整体删除（迁到 `internal/llmclient`） |
| `attestation.go`、`platformagent/`、`model_catalog.go` | 不变 |
| 测试 | 删除客户端/审计协议测试；新增 generate 的服务端测试 |

### 6.2 TAA（新增/修改）

| 文件 | 处理 |
|---|---|
| `internal/llmclient/types.go` | 协议类型与错误常量 |
| `internal/llmclient/client.go` | 从 `teellm/client.go` 移植，方法改名 `Generate`，路径 `/v1/llm/generate` |
| `internal/llmclient/retry.go`、`circuit_breaker.go`、`validator.go` | 原样移植 |
| `internal/codeaudit/prompt.go` | 模板 + `BuildFindingPrompt` |
| `internal/codeaudit/llm.go` | 本地 `LLMClient` 接口；`NewInferenceClient` 构造 `llmclient.Client` |
| `internal/codeaudit/verifier.go` | 拼 prompt、调 `Generate`、`parseDecision(resp.Text)` |
| `internal/app/taa/app.go`、`internal/controller/import_processing.go` | `teellm.DefaultHealthCheckTimeout` → `llmclient.DefaultHealthCheckTimeout` |

## 7. 失败语义（保持不变）

| 情况 | 结果 |
|---|---|
| 请求构造/传输失败、熔断开、HTTP 非 200 | 该 finding `UNCERTAIN` + `SERVICE_UNAVAILABLE: ...`，`LLMDegraded=true` |
| 模型返回无法解析 | `UNCERTAIN` + `unable to parse model output`（由 `parseDecision` 决定） |
| `FailClosed` 打开且存在 HIGH/MEDIUM 非 BENIGN | 报告 `Passed=false` |
| `FailClosed` 关闭 | 回退静态严重度判定 |

## 8. 部署与兼容

- 一次部署必须同时更新 TAA 镜像/二进制与 teellm 镜像；单独升级任一侧，审计会全部落到
  `SERVICE_UNAVAILABLE`（fail-closed 下导入被拒）。
- 平台侧不受影响：平台不调用 `/v1/llm/verify`，只调用 `getAttestation`。
- 部署脚本无需改动：`deploy-llm.sh` / `deploy.sh` 不涉及该路径。

## 9. 验证方式

1. `internal/llmclient` 单测：熔断、重试、endpoint 校验、健康检查超时（从 teellm 移植）。
2. `internal/codeaudit`：prompt 构造逐字断言；verdict 解析；fail-closed / gate 语义测试改为
   新客户端。
3. teellm 服务端：生成请求的 options 合并顺序、缺 prompt / 缺 requestId / 超限返回码。
4. 端到端：用 `-mock-attestation` 起 teellm-service，用 TAA 的客户端跑一次 `Generate`
   （测试内以明文或 TEE-TLS 均可），再跑 `go test ./cmd/... ./internal/... ./pkg/... ./teellm/...`。
5. `gofmt -l` 对改动文件无输出；`go vet` 通过。

## 10. 已知取舍

- **提示词模板逐字搬迁**：模板内含针对 EMB_*/DYN_* 的豁免与"良性优先"提醒，逐字保留是为了
  不改变现网判定；重构后模板在 TAA 内演进。
- **`FileAnalyzer` 路径维持现状**：生产客户端不实现它，只有测试 mock 实现；本次只把它的
  `AnalyzeFile` 调用改为基于 `Generate` 的 mock 实现，不改变生产行为。
- **父模块 `go.mod` 仍需 `teetls`**：TAA 直接使用 `teetls` 做 TEE-TLS，这是传输层，不含审计。
