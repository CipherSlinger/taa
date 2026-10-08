# TEE-LLM 请求超时的分层与取值（2026-10-08）

## 1. 触发

`taskId=task-model-muyziwnw-xbko` 的导入被阻断，报告自相矛盾：

- `conclusion.risk_level = "LOW"`、`statistics = {high:0, medium:0, low:5}`
- `conclusion.passed = false`，`code = 1`，msg「大模型服务降级，按规则评估。触发 fail-closed 阻断策略，禁止导入」
- 5 条 `file_report` 的 `llm_verdict` 全为 `UNCERTAIN`，`llm_reason` 为
  `SERVICE_UNAVAILABLE: retryable error: Post "https://127.0.0.1:8443/v1/verify": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`
  与 `SERVICE_UNAVAILABLE: circuit breaker open`

低危与不通过并不矛盾：`risk_level` 由 `ClassifyFindingRisk` **分级后**的统计得出（EMB_003/DYN_001 基线 MEDIUM，落在 `test_*.py` 内且 verdict 为 UNCERTAIN 时降级为 LOW），而 `passed = stats.High == 0 && ScanPassed`，其中 `ScanPassed` 被 `verifier.go` 的 assist + failClosed 分支因 `allFailed`（全部 verdict 为空或 UNCERTAIN）强制置为 false。**阻断导入的是「审查没跑完」，不是「代码有恶意」。**

## 2. 实测事实（本机，容器 `taa-env-slim-v2`）

| 项 | 值 | 出处 |
| :--- | :--- | :--- |
| 单次 verify 实际耗时 | 19.2–24.6s | 容器 `/tmp/ollama.log`，我复核该项目的 5 条命中 |
| 其中 prompt eval | ~17.4s / 890 token @ 51 tok/s | 同上，ollama 计时行 |
| 其中生成 | ~4.6s / 57 token @ 12.2 tok/s | 同上 |
| 失败运行中的请求 | 4 次，各在**正好 30.00s** 处 500 | `03:37:26 / 03:37:56 / 03:38:26 / 03:38:57` |
| TAA→teellm 预算 | 30s（`llm.requestTimeoutMs` 默认 30000，容器配置无此键） | `internal/config/config.go:312` |
| teellm→ollama 预算 | 60s（`backend.timeoutSeconds`） | 容器 `teellm-docker.json` |
| 重试 | `MaxRetries` 默认 **3**（TAA 未传）→ 每条 finding 最多 4 次尝试 | `teellm/client.go:82-83` |
| 熔断 | 阈值 3、冷却 30s | `internal/codeaudit/llm.go:48`、`teellm/circuit_breaker.go:115` |
| 重试前不复查熔断 | `AllowRequest()` 只在 `VerifyFinding` 入口调用一次 | `teellm/client.go:138` |

## 3. 因果链

1. 30s 是 `http.Client.Timeout`（客户端内部超时），外层 ctx 无 deadline → `ctx.Err()` 为 nil → 走 `RecordFailure()` + `ErrRetryable` → **重试**（`client.go:156-163`）。
2. 一条需要 >30s 的调用把 4 次尝试全部烧在 30s 上；其中**第 3 次失败即达到熔断阈值**，而第 4 次因入口已过检查仍会发出——这正好解释了日志里「只有 4 次请求、恰好相隔 30s」与报告里「1 条超时 + 4 条熔断」。
3. 其余 4 条 finding 在入口被 `ErrCircuitOpen` 直接拒绝，从未发请求 → 5 条全 UNCERTAIN → `allFailed` → `report.Passed = false` → `ScanPassed=false` → `passed=false`，同时 fail-closed 阻断导入。

**一条慢调用 → 整轮阻断。** 放大倍率来自「重试 3 次 × 熔断阈值 3」这对参数的乘积，不是单次超时本身。

## 4. 取值与分层（本次改动）

```
TAA ──(120s, llm.requestTimeoutMs)──> teellm ──(100s, backend.timeoutSeconds)──> ollama
                                        teellm server read/write = 120s
```

| 层 | 旧 | 新 | 理由 |
| :--- | ---: | ---: | :--- |
| TAA → teellm | 30s（缺省） | **120s** | 冷加载 ~15s + 推理 19–25s，实测失败点在 30–35s，120s 约 5× 余量 |
| teellm → ollama | 60s | **100s** | 须能容纳一次慢推理 |
| teellm server | 60s | **120s** | 须大于上一行，否则响应写不完就被截断 |

**内层必须严格小于外层**，这不是随意取整：

- 若内层 ≥ 外层，外层 deadline 先到 → TAA 取消请求 → `ctx.Err() != nil` → client 走 `ResetProbe()`，**不计失败**（`teellm/client.go:197-199`）→ 熔断永不打开 → 每条 finding 各烧 4×120s，5 条约 40 分钟后仍以失败收场（且全程挂住）。
- 内层 100s < 外层 120s 时，后端真挂会在 100s 处以 transparent 503 返回，被计为一次失败，熔断按既有语义在 3 次后打开，约 7 分钟得出结论。

120s 这个数不是新发明的量级：`internal/app/taa/app.go:575-578` 在 LLM 超时缺省时的兜底值就是 120s。

## 5. 落点与生效路径

- `configs/taa-docker.json` → `llm.requestTimeoutMs: 120000`
- `teellm/configs/teellm-docker.json` → `backend.timeoutSeconds: 100`、`server.read/writeTimeoutSeconds: 120`
- `internal/config/config_test.go` 新增 `wantLLMTimeoutMs` 断言，防止模板取值静默回退
- 生效需重新部署：模板由 `deploy.sh` 的 `write_taa_config` 逐字写入容器（`teellm/deploy.sh docker --config teellm/configs/teellm-docker.json` 写 teellm 侧）

## 6. 本次未处理（保留，未擅自改动）

1. **`MaxRetries`(3) ≥ 熔断阈值(3)**：单条 finding 自己即可跳闸，重试策略与熔断策略在数值上互相冲突。建议 `MaxRetries < CircuitBreakerThreshold`。
2. **超时重试对预算问题无效**：需要 35s 的调用重试 4 次仍是 35s，只是多烧 3 倍时间。可考虑对超时类错误不重试。
3. **模型驻留**：teellm 的 `/api/generate` 未带 `keep_alive`，用 daemon 默认 5m；部署预热设的 30m 会过期，空闲 >5 分钟后的首次审查要付 ~15s 冷加载。120s 预算已覆盖它，但这是本可省掉的开销。
4. `configs/taa-production.json` / `teellm/configs/teellm-production.json` 仍是 60s/60s，未同步（生产是否同一套 CPU-only 推理待定）。
