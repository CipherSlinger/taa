# TAA 启动期 teellm 连通性日志 + platform-mock 显示真实 IP（2026-10-10）

- **状态**：已实现并实测通过
- **日期**：2026-10-10
- **宿主**：`ubuntu2404`（`172.16.10.116`）
- **相关文件**：`internal/app/taa/app.go`、`deploy.sh`、`tools/platform-mock/internal/static/js/app.js`
- **前置**：`.claude/specs/2026-10-10-teellm-separate-container-design.md`（其中的 §7.1 直接导致了本文件 §1）

---

## 1. platform-mock 右上角的 TAA 代理地址不再显示 `127.0.0.1`

### 1.1 链路

badge 的文本就是 `-taa-target` 的原样回显：

```
deploy.sh:1400  -taa-target "$LOCAL_TAA_URL"
  → /api/taa-target  {"taaTarget": "<LOCAL_TAA_URL>"}
    → app.js:1554  badge.textContent = 'TAA 代理: ' + payload.taaTarget
```

而 `LOCAL_TAA_URL` 原本默认 `http://127.0.0.1:6001`。这个值对**从别的机器打开这个页面的人毫无意义**——
页面本身绑在 `0.0.0.0:18080` 上，本来就是给局域网看的。

### 1.2 改法

`deploy.sh` 新增 `detect_local_host_ip()`，`LOCAL_TAA_URL` 默认值改为宿主机可路由地址：

| 优先级 | 取值 |
| :--- | :--- |
| 1 | 显式设置的 `LOCAL_TAA_URL` |
| 2 | 显式设置的 `LOCAL_HOST_IP` |
| 3 | `ip route get 1.1.1.1` 报出的 `src`（内核视角的出行源地址） |
| 4 | `hostname -I` 里第一个非 `127.` 的地址 |
| 5 | `127.0.0.1` |

选 `ip route get` 而不是 `hostname -I` 打头，是因为**`hostname -I` 会一并列出 docker 网桥**
（本机实测输出 `172.16.10.116 10.144.122.102 10.183.106.107 100.103.193.56 10.0.0.1 172.17.0.1`
——最后两个是 docker0 和默认 bridge 的网关）。`ip route get` 天然避开它们。

两处细节都是为了不在 `set -euo pipefail` 下翻车：每条命令都带 `|| true`，
且用**单个 awk** 取 `hostname -I` 的字段，不写 `grep | head`（后者 `head` 提前退出会让
`grep` 吃 SIGPIPE，配 `pipefail` 会直接把赋值判失败）。

`LOCAL_TAA_URL` 同时被就绪等待与摘要打印使用，两者都跟着变成真实 IP。这没有副作用——
TAA 容器是 `--network host`，监听 `:6001`（`TAA_CONTAINER_ADDR` 的默认值），宿主机上哪个地址都通。

### 1.3 顺带：`app.js` 里的兜底地址

`detectTAAProxy()` 探测失败时会把输入框填成硬编码的 `http://127.0.0.1:6001`，是同一类缺陷
（同样是"页面被远程打开时指向读者的本机"）。改为 `location.hostname`，取不到才回落 `127.0.0.1`。
**注意这只影响"未检测到 TAA"时的输入框默认值，不影响 badge。**

### 1.4 证据

| # | 验证项 | 结果 |
| :--- | :--- | :--- |
| 1 | `bash -x ./deploy.sh __nonexistent__ \| grep LOCAL_` | `LOCAL_HOST_IP=172.16.10.116`、`LOCAL_TAA_URL=http://172.16.10.116:6001` |
| 2 | TAA 在该地址上确实应答 | `curl -X POST http://172.16.10.116:6001/v1/taa/health` → **200** |
| 3 | **badge 的数据源** | `/api/taa-target` → `{"taaTarget":"http://172.16.10.116:6001"}` |
| 4 | 反代仍可用 | `POST http://127.0.0.1:18099/taa/v1/taa/health` → **200** |
| 5 | 内嵌静态资源已更新 | `/static/js/app.js` 第 1546/1562/1573 行出现 `fallbackAddr` |
| 6 | **真实部署** | `./deploy.sh docker start taa` → `✓ taa ready: http://172.16.10.116:6001/v1/taa/health` |

第 3–5 条是把 platform-mock 二进制单独起在 `127.0.0.1:18099` 上验的，
**没有重启用户正在用的那个实例**。

---

## 2. TAA 启动时打印 teellm 连通性结论

### 2.1 改前的三个盲区

原实现整个探测只打两行：

```
probing inference service readiness (transport=…, endpoint=…, attestMode=…)
inference service probe succeeded
```

- **没有耗时**。而 `/healthz` 要等后端模型加载完才应答（冷启动实测 17.5s），
  "网关冷" 和 "网关不通" 的失败长得一模一样，只能靠猜。
- **失败时没有独立日志**。fail-closed 下进程直接退出，最后一行是 `[TAA-FATAL] …`，
  既没有耗时也没有排查方向。
- **LLM 关闭时一行都不打**。于是"日志里没有探测结论"有两种可能：探测过了且成功、
  或者根本没探测——两者无法区分。

### 2.2 改法（`internal/app/taa/app.go`）

| 位置 | 变化 |
| :--- | :--- |
| `RunWithConfig` 的 `else` 分支 | LLM 关闭时打印 `LLM code audit disabled; skipping inference service connectivity probe` |
| `probeInferenceService` 开头 | `probeTimeout` 的计算**上移**到建 client 之前，然后打印 `inference service connectivity probe: endpoint=… transport=… attestMode=… mutualAttest=… timeout=…`。放在建 client 之前，是为了让"端点非法 / 不在 AllowedHosts"这类配置失败也有端点上下文 |
| 探测调用处 | 用 `time.Now()` 计时；失败打 `ERROR: … failed after <耗时>: <err>` 加一行 `hint:`，成功打 `… succeeded (took <耗时>)` |

hint 的内容直接对应本项目真实踩过的两种失败：`transient status 503` = **网关活着但模型没加载完**
（见 `[[teellm-healthz-requires-warm-model]]`），dial/connect 错误 = **没人监听**。

失败日志在探测内部和调用点各说一次，是刻意的：fail-closed 时调用点那行由 `main` 打成
`[TAA-FATAL]` 且**不带 hint**；非 fail-closed 时调用点只有 `WARNING: … (non-fatal)`，
**同样不带耗时和 hint**。

### 2.3 证据

三条路径都在容器 `taa-env-slim-v2` 里真跑过。

**成功**（真实部署，`./deploy.sh docker start taa` 之后的 `taa.log`）：

```
2026/10/10 07:22:20 inference service connectivity probe: endpoint=https://10.0.0.2:8443 transport=teetls attestMode=permissive mutualAttest=false timeout=2m0s
2026/10/10 07:22:38 inference service connectivity probe succeeded (took 17.549s)
```

`timeout=2m0s` 不是那个 `5s` 兜底值：`requestTimeoutMs: 120000` 让 `probeTimeout = timeout = 120s`。
**这个数字暴露了一件事**——探测的上限是 2 分钟而不是 5 秒，与"按冷加载定时限"的记忆一致；
17.5s 就是一次真实的冷加载。

**失败**（临时配置指向 `https://127.0.0.1:9`）：

```
… inference service connectivity probe: endpoint=https://127.0.0.1:9 … timeout=5s
… ERROR: inference service connectivity probe failed after 812ms: retryable error: Get "https://127.0.0.1:9/healthz": teetls: dial 127.0.0.1:9: dial tcp 127.0.0.1:9: connect: connection refused
… hint: check the tee-llm gateway at https://127.0.0.1:9 -- "transient status 503" means it is running but its model is not loaded yet, a dial/connect error means nothing is listening there
… [TAA-FATAL] probe inference service (fail-closed): health check failed: retryable error: …
```

**LLM 关闭**（临时配置 `llm.enabled=false`）：

```
2026/10/10 07:22:54 LLM code audit disabled; skipping inference service connectivity probe
```

后两条用的临时配置与 keys 目录都建在容器 `/tmp` 下，**跑完已删除**；
两处都改了 `server.addr`/`storage`，没有碰正在运行的 TAA 的任何状态。

---

## 3. 未决

1. **探测只在启动时做一次。** 运行期网关掉线不会被感知，只会在真实审计请求上暴露。
   若需要，可挂到 `/v1/taa/health` 上做按需复检，但会改变该接口的语义与耗时，不在本次范围。
2. **`LOCAL_HOST_IP` 没有参与平台注册地址。** `LOCAL_PLATFORM_IP`（默认 `127.0.0.1:18080`）
   仍是 TAA 注册到平台用的地址，本次**刻意不动**——那是功能值，不是显示值；
   远程部署路径下改错会让注册打到错误的主机。
