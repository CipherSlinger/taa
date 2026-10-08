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

## 7. 验证结果与一个比超时更重要的发现（2026-10-08 补）

### 7.1 干净环境下端到端通过

容器 `taa-env-slim-v2`，样本 `models/examples/Retina-DKD/Retina-DKD`（494 文件、打包 214MB），配置为本次改动后生效值：

| 项 | 读数 |
| :--- | :--- |
| 推理调用 | 6 次：探针 6.48s（吃掉冷加载），5 次验证 22.92 / 21.71 / 22.88 / 18.84 / 22.44s |
| 状态码 | 全部 200，无 500 |
| 5 条命中 verdict | 全 `BENIGN`（EMB_003 ×4、DYN_001 ×1） |
| 结论 | `passed=true`、`code=0`、msg「发现 5 处低危/良性提示项（大模型确认为正常）。代码符合安全规范，准予导入」 |

即：**改动生效、审查不再被 fail-closed 拦住。** 但请注意这批调用的实测耗时是 18.8–22.9s，都**没到**旧的 30s——所以这一轮证明的是「没坏」，不是「旧的 30s 会坏」。

### 7.2 施加 CPU 负载后：仍然 fail-closed，而且不是超时能修的

用 16 个 CPU 竞争者（宿主 `while :; do :; done`）复现，结果与 7.1 相反：

- 审计 04:06:51 开始、**04:13:58** 结束，历时 **427s**，`passed=false`，msg「大模型服务降级，按规则评估」。
- ollama 侧访问日志：**1 次 200（20.28s）+ 4 次 500，每次恰好 `1m40s`**，间隔 100s = `MaxRetries` 的四次尝试。
- `1m40s` = **100s = 本次新设的 `backend.timeoutSeconds`**：内层先到，外层 120s 根本没轮到——分层按设计工作了（快速失败而非挂满 40 分钟），但**这次阻断没有任何超时值能避免**。

### 7.3 归因：是 llama.cpp 的线程超订，不是 CPU 不够、不是内存、不是限流

同一台机器、同一个暖机模型、同一条 86 token 请求：

| 条件 | 耗时 | 说明 |
| :--- | ---: | :--- |
| 无竞争者 | 0.64 / 0.79s | A/B/A/B 的两次 A |
| **1 个竞争者** | **24.96 / 25.79s** | 两次 B，可复现 |
| 1 / 2 / 4 / 8 个竞争者 | 25.3 / 26.6 / 26.4 / 32.7s | 与竞争者数量几乎无关 |

排除项：

- **不是 CPU 饥饿**：容器内纯单线程计算 0.56 / 0.56 / 0.57s（有、无竞争者一致）；慢调用期间 llama-server 每 2s 消耗约 **29 核·秒**（正常约 13–15），即它占了机器却在空转。吞吐从 9.37 tok/s 掉到 **0.25 tok/s**（约 36×）。
- **不是内存**：测试期间容器 `memory.current` 5.01→5.04 GiB，`pswpout` 零增长。
- **不是限流**：cgroup `cpu.max = max`、`nr_throttled = 0`、`throttled_usec = 0`。
- **不是空闲自旋**：llama-server 空闲时实测 0 核，基线可信。

机制：llama-server 有 **35 个线程而只有 16 vCPU**（已超订），ggml 线程池在屏障处自旋；一旦别的进程抢走某个线程的时间片，整批线程按屏障逐个空转。压线程可去掉这种敏感性：`num_thread=8` → 有竞争者 9.89s；`num_thread=4` → 有竞争者 12.70s vs 空闲 12.85s（对竞争不敏感），但绝对速度比无竞争时的默认配置差。

### 7.4 结论与建议

1. **30s→120s 是有效的**，它覆盖冷加载（~35s 那个场景）与温和抖动；对 7.2 那种崩塌无效，任何按请求的超时都无效。
2. **用户那次 `task-model-muyziwnw-xbko` 的阻断与 7.2 同形**（同样 4 次尝试、同样各自卡在客户端预算上）。最可能的原因是审查期间有别的进程在抢 CPU，而不是预算少了 90 秒。
3. 真正要防的是**「LLM 验证与其他吃 CPU 的活并行」**：Semgrep、另一次审计、宿主上的作业。D4 拓扑里 semgrep 与 LLM 同容器，虽然当前是分阶段串行，但任何一次并行都会命中这条崩塌。
4. 若必须共享 CPU，按请求压 `num_thread`（`teellm/configs/models.json` 的 per-model options）可去掉对竞争的敏感性，代价是绝对吞吐下降——需按机器核数选值，不宜照搬本机的 4/8。
5. 复现脚本（临时目录，未入库）：`/tmp/verify-timeout/run.sh`（端到端）、`infer-bench.sh`（曲线）、`ab.sh`（A/B/A/B + 瞬时 CPU）、`threads.sh`（线程数）。**注**：`run.sh` 最初版本的时长解析只认 `<float><unit>`，会把 Go 的 `1m40s` 静默丢弃，使「全部 200」在残缺列表上通过——已修。这类验证工具「静默丢弃 = 假装通过」的失败模式值得单独记住。

