# TAA 与 Qwen 推理引擎完全独立解耦与标准化安全通信协议设计规范

## 1. 背景与解耦目标

### 1.1 现状与安全隐患
在现有 TAA (Trusted Application Agent) 架构中，TAA 守护进程与本地推理子进程（Ollama / Qwen）存在强耦合关系，具体表现如下：
1. **进程生命周期杂糅与特权风险**：
   - TAA 主程序在启动流程（`internal/app/taa/app.go:ensureQwenAvailable`）中，使用 `sh -c` 拼接包含配置参数的命令行后台拉起 `start-ollama.sh`。
   - 配置项（`llm.dir`, `llm.endpoint`）若存在非预期字符易引发命令注入；启动脚本日志直接重定向至固定路径 `/tmp/ollama.log`，存在符号链接劫持风险。
   - TAA 退出时无法有效管控和清理推理引擎子进程树，极易产生孤儿僵尸进程。
2. **计算资源配额与故障传导**：
   - TAA 与 Ollama 运行在同一容器或宿主上下文中（共享 host network 与 PID/IPC namespace）。当大模型推理出现 GPU 显存溢出 (OOM)、死锁或内存泄漏时，将直接拖垮 TAA 核心证明与任务协调守护进程。
3. **通信契约私有化与缺乏认证**：
   - TAA 直接依赖 Ollama 私有的 `/api/generate` 接口，入参仅为未结构化的自然语言 Prompt，缺失协议版本、请求 ID、代码切片哈希、时间戳等元数据。
   - 通信未设置服务身份鉴权、消息防重放与完整性校验。当 Endpoint 被配置为非回环地址时，存在服务端请求伪造 (SSRF) 与代码审计数据明文泄露风险。
4. **容错机制与 Fail-Closed 语义不一致**：
   - 现存实现缺乏统一的超时分层、熔断器 (Circuit Breaker) 与指数退避重试；
   - 在启动探测、导入预检、单条 Finding 仲裁等不同阶段，对 `failClosed` 策略的处理存在歧义（部分路径静默降级为 `UNCERTAIN`，未能严格执行阻断）。

### 1.2 解耦与协议设计目标
1. **彻底解耦计算边界 (Process & Container Decoupling)**：
   - TAA 守护进程彻底剥离推理引擎进程管理逻辑，不再负责拉起、监控或强杀推理子进程。
   - 推理引擎（Ollama / Qwen / vLLM）作为独立的计算单元或专属容器（Sidecar 或独立 Microservice）运行，配置专属 CPU/GPU 配额。
2. **制定平台无关的标准化安全通信协议 (Inference Security Protocol, ISP)**：
   - 定义统一的请求信封与结构化判定响应模型，解耦底层具体推理引擎后端；
   - 支持跨容器 HTTP/REST (含 mTLS/Token 认证)、本地高效 UDS (Unix Domain Socket) 与高性能 gRPC 三种传输通道；
   - 引入请求随机数 (Nonce)、时间戳 (Timestamp)、租户与任务标识、代码切片内容摘要 (SHA-256/SM3)，杜绝伪造与重放攻击。
3. **安全加固与 SSRF 防护**：
   - 实施严格的端点白名单校验（默认仅允许回环地址 `127.0.0.1`、受限私有网络或 UDS 路径），阻断恶意外部端点注入。
4. **弹性容错、自愈与确定性 Fail-Closed 决策状态机**：
   - 实现轻量级健康心跳探测，区分连接故障与业务错误；
   - 引入熔断状态机（Closed -> Open -> Half-Open）与带有 Jitter 的指数退避重试；
   - 统一定义 `assist`（辅助审计/降级通行）与 `gate`（严格门禁/阻断）模式下推理不可用时的行为规范，确保安全闭环。

---

## 2. 总体架构与服务边界

解耦后系统划分为 **TAA 宿主进程** 与 **推理服务守护单元**，两者通过标准化协议通信：

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ TAA Enclave / Container (TEE 业务编排与证明边界)                            │
│                                                                             │
│  ┌───────────────────────┐         ┌────────────��────────────────────────┐  │
│  │ internal/coordinator  │         │ internal/codeaudit                  │  │
│  │ (FlowModelImport)     │────────►│ - Verifier                          │  │
│  └───────────────────────┘         │ - BatchPromptAggregator             │  │
│                                    └──────────────────┬──────────────────┘  │
│                                                       │                     │
│                                                       ▼                     │
│                            ┌─────────────────────────────────────────────┐  │
│                            │ internal/inference (新解耦通信客户端模块)   │  │
│                            │  - EndpointValidator (SSRF/Whitelist)       │  │
│                            │  - SecurityAuth (mTLS / HMAC Token / Peer)  │  │
│                            │  - CircuitBreaker & RetryEngine             │  │
│                            │  - ProtocolSerializer & HashVerifier        │  │
│                            └──────────────────┬──────────────────────────┘  │
└───────────────────────────────────────────────┼─────────────────────────────┘
                                                │ 
                                ┌───────────────┴───────────────┐
                                │ Standardized Security Channel │
                                │ (UDS / HTTP REST / gRPC)      │
                                └───────────────┬───────────────┘
                                                │
┌───────────────────────────────────────────────▼─────────────────────────────┐
│ Inference Service (独立容器 / 独立系统单元，拥有专属 GPU/CPU 配额)          │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Inference Security Protocol Gateway / Adapter (或原生兼容端点)        │  │
│  │  - Auth Verification (Token / Peer Credentials / Cert)                │  │
│  │  - Health & Readiness Probes (/v1/healthz)                            │  │
│  │  - Request Schema Parser & Context Budget Guard                       │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Core Inference Engine (Ollama / Qwen2.5-Coder / vLLM)                 │  │
│  │  - Model Weights & KV Cache                                           │  │
│  │  - Structured Output / Reasoning Chain (<think>)                      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 部署拓扑支持
| 拓扑模式 | 传输通道 | 身份认证与通道安全 | 适用场景 |
|---|---|---|---|
| **模式 A：同 Pod / 同机隔离 (默认推荐)** | **Unix Domain Socket (UDS)** | 文件系统权限 (0660) + `SO_PEERCRED` UID/GID 校验 | 本地最高性能，零网络栈开销，免疫外部网络探测 |
| **模式 B：独立容器 / 内部网络** | **HTTP/1.1 or HTTP/2 (REST)** | Pre-shared HMAC Token / Bearer Token + Loopback 绑定 | 容器编排解耦、开发测试环境、标准容器间通信 |
| **模式 C：跨主机微服务 / 高性能集群** | **gRPC over mTLS** | 双向 TLS (SM2 或 ECDSA 证书绑定) | 多租户共享推理节点、分布式异构计算集群 |

---

## 3. 标准化通信协议规范 (ISP Specification)

协议统一使用版本号 `taa-isp/v1`。

### 3.1 统一请求信封 (Request Envelope)

```json
{
  "protocolVersion": "taa-isp/v1",
  "requestId": "req-7b3f1c24-a128-4d56-b072-96b5a329df01",
  "taskId": "task-train-20260917-001",
  "timestamp": 1789728000,
  "nonce": "c8e1a90f842345d2e7b16521",
  "deadlineMs": 60000,
  "auth": {
    "authType": "token",
    "token": "isp-secret-token-value"
  },
  "modelRef": {
    "name": "qwen2.5-coder",
    "tag": "3b",
    "minContextTokens": 8192
  },
  "action": "VERIFY_FINDING",
  "findingPayload": {
    "ruleId": "TAA-SEC-001",
    "category": "command_injection",
    "severity": "HIGH",
    "description": "Potential remote command execution via system call",
    "target": {
      "filePath": "dataset.py",
      "line": 42,
      "codeSnippet": "os.system('sh ' + user_script)",
      "contextBefore": "def execute_custom_script(user_script):\n    logger.info('executing')",
      "contextAfter": "    return True",
      "contentSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  },
  "policy": {
    "mode": "gate",
    "enableReasoningChain": false,
    "temperature": 0.1,
    "maxCompletionTokens": 1024
  }
}
```

### 3.2 统一响应信封 (Response Envelope)

```json
{
  "protocolVersion": "taa-isp/v1",
  "requestId": "req-7b3f1c24-a128-4d56-b072-96b5a329df01",
  "status": "SUCCESS",
  "decision": {
    "verdict": "MALICIOUS",
    "confidence": 0.95,
    "riskLevel": "HIGH",
    "reasonCode": "CONFIRMED_UNCHECKED_INPUT_EXECUTION",
    "explanation": "The code directly interpolates user input into os.system without validation or sanitization, allowing arbitrary command execution.",
    "suggestedRemediation": "Replace os.system with subprocess.run and pass argument list without shell=True.",
    "reasoningChain": ""
  },
  "metrics": {
    "latencyMs": 342,
    "promptTokens": 512,
    "completionTokens": 128
  },
  "engineInfo": {
    "backend": "ollama",
    "modelLoaded": "qwen2.5-coder:3b",
    "modelDigest": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
  }
}
```

### 3.3 状态码与判定枚举映射

#### Verdict 状态
- `MALICIOUS`：高危利用链明确，具备确切攻击路径。
- `SUSPICIOUS`：包含危险函数或反模式，需人工重点关注。
- `BENIGN`：误报排查，确认为正常业务逻辑或防御性编程。
- `UNCERTAIN`：上下文不足或模型生成无法解析。

#### Status 响应状态
- `SUCCESS`：正常推理完成，包含确定性 decision。
- `INVALID_REQUEST`：参数校验未通过（行号超出、缺少必填项、超限等）。
- `UNAUTHORIZED`：身份认证失败（Token 错误或 UDS Peer 凭证不匹配）。
- `SERVICE_OVERLOADED`：推理服务并发排队满或显存受限（可重试）。
- `MODEL_NOT_FOUND`：请求指定的模型未在引擎中加载或哈希不匹配。
- `INTERNAL_ERROR`：推理引擎内部异常。

---

## 4. 安全防护与认证机制

### 4.1 SSRF 与网络边界防御
针对 HTTP REST 模式，客户端实施严格的端点安全验证：
1. **协议校验**：仅支持 `http://`、`https://` 或 `unix://` 协议头。
2. **目标主机安全校验**：
   - 解析目标 Host IP；
   - 严禁请求 Cloud Metadata 端点（如 `169.254.169.254`）；
   - 严禁 `0.0.0.0`、组播地址（`224.0.0.0/4`）与 IPv6 环路/特殊范围（`::`, `fe80::/10`）；
   - 生产环境中，若配置使用网络通信，强制限定在预设受信任子网或固定名称（如 `inference-service:11434`），禁止任意出向连接。

### 4.2 UDS 安全隔离 (模式 A)
- Socket 文件建立在专用受保护目录 `/run/taa/ipc/`；
- 文件权限掩码严格设置为 `0660`，仅允许同组用户访问；
- 建立连接时，TAA 与推理网关均可通过 `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ...)` 获取对端 UID/GID，确保非特权未授权进程无法连接。

### 4.3 防重放与输入完整性
- **Nonce 缓存**：接收端/发送端维护有效期为 60s 的 LRU Nonce 缓存，拒绝相同 Nonce 重复请求；
- **时间戳偏斜校验**：请求时间戳与当前系统时间差值超过 30s 则拒绝处理；
- **代码切片摘要**：请求携带 `contentSha256`，校验上下文代码片段完整性，避免传输损坏。

---

## 5. 弹性容错与熔断降级状态机 (Resilience Architecture)

```
             ┌──────────────────────────────────────────────────────────┐
             │                                                          │
             ▼                                                          │
      ┌──────────────┐   连续失败 >= 3 次 (超时/5xx)    ┌─────────────┐   │ 成功探测 1 次
      │    CLOSED    │─────────────────────────────────►│    OPEN     │   │
      │ (正常服务中) │                                  │ (熔断开启)  │   │
      └──────────────┘                                  └──────┬──────┘   │
             ▲                                                 │          │
             │                                   冷却 30s 过去 │          │
             │                                                 ▼          │
             │              探针失败                     ┌────────────┐   │
             └───────────────────────────────────────────┤ HALF-OPEN  │───┘
                                                         │ (半开试探) │
                                                         └────────────┘
```

### 5.1 熔断策略参数
- **失败阈值**：连续 3 次超时（单次请求 > 10s 未响应）或返回 `5xx` / `SERVICE_OVERLOADED`；
- **冷却时间**：30 秒。在冷却期内，所有审计请求直接快速失败，不发起实际网络/IPC 交互；
- **半开状态**：30 秒后进入 Half-Open 状态，仅允许单条心跳/轻量探针请求通过。探测成功则重置为 Closed，失败则重新退回 Open。

### 5.2 重试与退避算法
仅针对可重试故障进行自动重试：
- **可重试故障**：连接断开（Connection Refused）、网络超时、HTTP 429、HTTP 502/503/504；
- **不可重试故障**：HTTP 400（参数错误）、HTTP 401/403（认证失败）、HTTP 404（模型不存在）；
- **退避公式**：采用指数退避伴随全抖动 (Full Jitter)：
  $$Backoff = \min(MaxDelay, BaseDelay \times 2^{attempt}) \times Random(0.8, 1.2)$$
  默认参数：$BaseDelay = 500\text{ms}$，$MaxDelay = 3000\text{ms}$，最大重试次数 $N = 2$。

### 5.3 故障降级与 Fail-Closed 决策矩阵

当推理引擎彻底不可用（熔断中、重试耗尽或未就绪）时，系统严格执行配置策略：

| 策略模式 (`policy`) | 静态规则存在 HIGH | 静态规则仅存在 MEDIUM | 静态规则为 0 / Passed | 系统最终决策 | 平台报告字段标记 |
|---|---|---|---|---|---|
| **`gate` (严格门禁)** | 命中 | 任意 | 任意 | **BLOCK (直接拒绝导入)** | `audit_status="failed"`, `llm_error="SERVICE_UNAVAILABLE"` |
| **`gate` (严格门禁)** | 0 | 命中 | 任意 | **BLOCK (直接拒绝导入)** | `audit_status="failed"`, `llm_error="SERVICE_UNAVAILABLE"` |
| **`gate` (严格门禁)** | 0 | 0 | 通过 | **ALLOW (允许导入)** | `audit_status="passed"`, `llm_skipped=true` |
| **`assist` (辅助模式)** | 命中 | 任意 | 任意 | **BLOCK (基于静态高危阻断)** | `audit_status="failed"`, `llm_degraded=true` |
| **`assist` (辅助模式)** | 0 | 任意 | 任意 | **ALLOW (降级放行并告警)** | `audit_status="passed"`, `llm_degraded=true` |

> **关键原则**：在 `gate` 模式下，绝不允许因推理服务宕机而导致潜在高危代码静默放行；任何因服务故障导致的非确定性必须显式阻断并向管控平台告警。

---

## 6. 配置项演进与兼容性规划

在 `internal/config/config.go` 中扩展 `llm` 配置段，实现向前兼容：

```json
{
  "llm": {
    "enabled": true,
    "transport": "uds",
    "udsPath": "/run/taa/ipc/inference.sock",
    "endpoint": "http://127.0.0.1:11434",
    "model": "qwen2.5-coder:3b",
    "policy": "gate",
    "failClosed": true,
    "auth": {
      "type": "token",
      "token": "${INFERENCE_AUTH_TOKEN}"
    },
    "networkSecurity": {
      "allowedHosts": ["127.0.0.1", "localhost", "inference-service"],
      "blockPrivateIPs": false
    },
    "resilience": {
      "requestTimeoutMs": 15000,
      "maxRetries": 2,
      "circuitBreakerThreshold": 3,
      "circuitBreakerCooldownSec": 30
    }
  }
}
```

- 若 `transport` 未配置，但 `endpoint` 为 `http://...`，自动降级为兼容历史配置的 HTTP 传输适配器；
- 若配置了 `udsPath` 且可用，优先采用高安全、零网络暴露的 UDS 通道。

---

## 7. 模块解耦重构实施方案

### 7.1 新增模块与包划分
1. **`internal/inference`（核心接口与传输层）**：
   - `client.go`：定义 `InferenceClient` 统一接口；
   - `types.go`：标准化请求/响应信封结构体；
   - `adapter_http.go`：HTTP REST (兼容 Ollama / 原生 ISP 网关) 传输实现；
   - `adapter_uds.go`：Unix Domain Socket 传输实现；
   - `circuit_breaker.go`：熔断状态机与并发限流；
   - `validator.go`：SSRF 防护与端点白名单校验。
2. **`internal/codeaudit`（业务消费方重构）**：
   - 彻底移除对 `OllamaClient` 的私有依赖，全面对接 `inference.InferenceClient`；
   - 升级 `Verifier`，利用标准化响应填充审计结论。
3. **`internal/app/taa` 与 `cmd/taa`（生命周期剥离）**：
   - 彻底删除 `app.go:ensureQwenAvailable`、`start-ollama.sh` 进程启动与日志重定向代码；
   - 启动流程仅执行快速探针（`inference.Ping()`），若不可用则根据 `policy` 决定日志报警或退出。
4. **`deploy.sh`（运维部署解耦）**：
   - 移除容器内强绑定的 Ollama 后台拉起逻辑；
   - 在 Docker Compose / K8s Pod 模板中将 Ollama/Qwen 编排为独立 Sidecar 容器，分配独立资源 limits。

---

## 8. 验证方案与质量基线

1. **协议序列化与反序列化单测**：
   - 覆盖标准 JSON 请求/响应与各字段边界校验；
   - 覆盖恶意 Hostname/IP 的 SSRF 拦截测试。
2. **断网与抖动模拟测试 (Fault Injection)**：
   - Mock 故障服务端（模拟 500ms 延迟、503 过载、随机超时）；
   - 验证连续 3 次失败触发熔断进入 Open 状态；
   - 验证 30s 后探针恢复进入 Closed 状态。
3. **Fail-Closed 闭环验证**：
   - 构造服务彻底宕机场景，验证在 `gate` 模式下 `reportAudit` 准确上报 `SERVICE_UNAVAILABLE` 并阻断模型导入；
   - 验证在 `assist` 模式下准确标记 `llm_degraded: true` 并完成静态兜底。
4. **性能对比压测**：
   - 对比 UDS 与 HTTP 在 50 并发下的 CPU 开销与传输延迟，确保无性能回退。
