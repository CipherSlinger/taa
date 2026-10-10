# 把 teellm 拆到独立容器，TAA 跨容器访问网关（2026-10-10）

- **状态**：已实现并实测通过
- **日期**：2026-10-10
- **宿主**：`ubuntu2404`（`172.16.10.116`，本地开发机），**不是** `hygon-master`
- **相关文件**：`deploy.sh`、`teellm/deploy.sh`
- **提交**：父仓库 `5767bc3`、子模块 `teellm` `043ea6c`

---

## 1. 目标

teellm（TEE-TLS 推理网关）原本与 TAA **同容器部署**，两者共享网络命名空间，TAA 走回环
`https://127.0.0.1:8443` 访问网关。本次把网关拆到**独立容器**，让两个进程可以分别部署、
分别重启，TAA 改为按**容器 IP** 访问。

验收口径：两个容器之间 TAA ↔ teellm 通信正常。

---

## 2. 拓扑决策

### 2.1 实测的网络现状

| 项 | 值 |
| :--- | :--- |
| 容器 1（TAA） | `taa-env-slim-v2`，`--network host`，镜像 `taa-env:slim-v2` |
| 容器 2（teellm） | `taa-teellm`，`--network bridge`，`10.0.0.2`，同镜像 |
| 宿主 docker0 | `10.0.0.0/24`，网关 `10.0.0.1` |

### 2.2 为什么是「容器 2 上 bridge，容器 1 不动」

**Docker 的硬约束：一个 `--network host` 的容器无法再接入任何别的 bridge 网络。**
容器 1 已经在 host 网络里跑了 21 小时，且可写层里有 TAA 的配置、密钥、`ld.so.cache` 等状态。
把它重建到 bridge 上等于销毁这些状态，代价与收益完全不成比例。

于是取：

```
容器1 (host netns)  ──IP 10.0.0.2──▶  容器2 (bridge 10.0.0.2:8443)
        :6001                                    │
                                                 ▼
                                       ollama 127.0.0.1:11434
```

host netns 可以直接路由到 bridge 容器的 IP，所以这**仍然是真实的容器间 IP 通信**
（不是回环），且是唯一不必摧毁容器 1 的选项。

**这是让跨容器能成立的关键既有事实**：`teellm/deploy.sh:615` 写的是 `server.addr = ":${port}"`，
即绑定 `0.0.0.0` 而非 `127.0.0.1`。若当初写的是回环，本次改动就不止是改默认值这么简单。

### 2.3 端口

端口保持 `8443` 不变。**只有 IP 从回环变成容器 IP**，端口号没有理由改——改变它只会让
配置文件、健康检查、证明绑定三处都多一次不必要的漂移。

---

## 3. 改动

### 3.1 `teellm/deploy.sh`（子模块）

```diff
-LOCAL_DOCKER_CONTAINER="${LOCAL_DOCKER_CONTAINER:-taa-env-slim-v2}"
+LOCAL_DOCKER_CONTAINER="${LOCAL_DOCKER_CONTAINER:-taa-teellm}"
```

只改默认值。**这是"部署到哪个容器"的唯一开关**，其余逻辑（`ensure_local_docker_container`
找不到就报错、`CON_WORKDIR`、ollama 目录四项硬校验）逐条核过，都按容器名参数化，不需要改。

### 3.2 `deploy.sh`（父仓库）

端点从**三处硬编码**收敛为一个变量：

```diff
+TAA_LLM_ENDPOINT="${TAA_LLM_ENDPOINT:-https://127.0.0.1:8443}"
```

| 位置 | 用途 |
| :--- | :--- |
| `:479` | `save_local_docker_image` 里烘焙进镜像的生产配置 |
| `:1400` | `deploy_docker_taa` 里写本地容器配置 |
| `:1540` | 远端部署路径写配置 |

**默认值刻意保持回环**：同容器部署仍然合法且更简单，把默认改成容器 IP 会让那个场景静默失效。
跨容器时由调用方给出，例如：

```bash
TAA_LLM_ENDPOINT=https://10.0.0.2:8443 ./deploy.sh ...
```

**容器 IP 是运行期变量，不能写死进仓库。** 因此这里给的是"可配置"而不是"改成新 IP"——
写死一个 `10.0.0.2` 下次重建容器就过期了。

---

## 4. 本次暴露的真实缺陷：ollama bundle 缺 soname 符号链接

这是本次最有价值的发现，**独立于跨容器这个目标**。

### 4.1 现象与定位链

teellm 部署后自检报 503，且**持续 280s 不退**（排除了冷加载延迟）。逐层剥：

```
healthz 503
  └─ ollama POST /api/generate 返回 500
       └─ {"error":"llama-server process has terminated: exit status 127"}
            └─ ldd：libllama-common.so.0 => not found
```

**根因**：本地 bundle `teellm/models/ollama/lib/ollama/` 里**只有带版本号的文件**
（`libllama-common.so.0.1.2`、`libllama.so.0.1.2`、`libmtmd.so.0.1.2`、
`libggml.so.0.20.2`、`libggml-base.so.0.20.2`），**没有 soname 形式的符号链接**。
而 `llama-server` 的 `DT_NEEDED` 记的是 soname（`libllama-common.so.0`），且**没有 RUNPATH**，
所以动态加载器只能靠精确文件名或 `ld.so.cache` 命中。两者都没有 → 127。

### 4.2 容器 1 当初为什么"是好的"

**纯属巧合。** 容器 1 的 `ld.so.cache`（mtime Sep 21 01:56）指向的是**另一个目录**
`/root/taa/ollama-qwen/lib/ollama`，那个目录里恰好有符号链接。
**仓库里没有任何脚本会跑 `ldconfig`**，所以这份 cache 是历史遗物，不可复现。

### 4.3 处置

容器 2 内补齐 6 个符号链接 + 一条 `ld.so.conf.d` 条目 + `ldconfig`：

```sh
ln -sf libllama-common.so.0.1.2 libllama-common.so.0
ln -sf libllama.so.0.1.2        libllama.so.0
ln -sf libmtmd.so.0.1.2         libmtmd.so.0
ln -sf libggml.so.0.20.2        libggml.so.0
ln -sf libggml-base.so.0.20.2   libggml-base.so.0
ln -sf libgomp.so.1.0.0         libgomp.so.1
echo /root/taa/ollama/lib/ollama > /etc/ld.so.conf.d/ollama.conf && ldconfig
```

同时**在本地 bundle 源目录补了同样 6 个符号链接**，让后续全新部署不再踩这个坑。

> ⚠️ **但 bundle 的修复没有进 git**：`teellm/.gitignore:7` 忽略了 `models/ollama/lib/`。
> 也就是说**下一次全新克隆仍然会踩到 127**，需要 `teellm/deploy.sh` 自己补链接才能根治。
> 这一条记在 §6。

---

## 5. 验证证据

| # | 验证项 | 结果 |
| :--- | :--- | :--- |
| 1 | 容器 2 存在且在 bridge 上 | `taa-teellm`，`Up`，`ip=10.0.0.2`，`net=bridge` |
| 2 | teellm 监听 | `/proc/net/tcp6` local `…:20FB`(=8443) state `0A`(LISTEN)；日志 `listening on [::]:8443 via RFC 8998 TEE-TLS 1.3` |
| 3 | teellm 自检 | `teellm-service -probe https://127.0.0.1:8443` → `OK` |
| 4 | **TAA 启动期跨容器探测** | 日志 **3 次** `probing inference service readiness (… endpoint=https://10.0.0.2:8443 …)` → `inference service probe succeeded` |
| 5 | TAA 载入远端端点 | `LLM verifier enabled: model=qwen2.5-coder:7b transport=teetls endpoint=https://10.0.0.2:8443 attestMode=permissive policy=assist fail-closed=true` |
| 6 | TAA 服务本身在听 | `taa service listening on :6001`，无 bind 错误；`/proc/net/tcp6` `:1771` state `0A`；`curl /` → 404（HTTP 服务在答） |
| 7 | **容器 1 侧独立复测** | 在容器 1 的 netns 里跑 `teellm-service -probe https://10.0.0.2:8443` → `OK` |

第 4 条是承重证据：TAA 的 readiness 探测走的是一条完整的 **RFC 8998 TEE-TLS 1.3 握手 +
healthz**，而 healthz 内部会真发一次 `POST /api/generate`（`num_predict: 1`）。
所以 `probe succeeded` 意味着 **容器 1 的 TAA → 容器 2 的 teellm → ollama** 整条链通了，
不是只有一个 TCP 连接建立。

### 5.1 说明：teellm 侧没有请求日志

`/root/taa/teellm-service.log` 在三次探测前后 **mtime 与行数都没变**（停在 06:49:46 的启动行）。
**这是 teellm 只记启动、不记请求的特性，不是"请求没到"。** 因此本次不拿 teellm 侧日志做证据，
改用 TAA 侧的 `probe succeeded` 与 §5 第 7 条的独立复测。

### 5.2 意料之中的降级：证明是 mock

容器 2 日志有 `warning: /dev/csv-guest not found; falling back to mock attestation provider`。
本地开发机没有 CSV2 设备，这是预期的；与 TAA 侧 `attestationMode: permissive` 一致。
**这轮通的是通信路径，不是证明的真实性**——后者的验收在 initrd 那条线上（见
`.claude/specs/2026-10-10-taa-in-csv2-initrd-design.md` §5 第 5 条）。

---

## 6. 非目标与未决

**非目标**

- 不重建容器 1 的可写层（不动它的运行时、镜像、历史状态）。
- 不碰 DCU。本轮全程未涉及那张卡。
- 不改 teellm 的证明/后端逻辑，只改部署位置。
- 不把 `:6001` / `:8443` 暴露到宿主之外。

**未决**

1. **`models/ollama/lib/` 被 gitignore，soname 链接不在版本控制里**（§4.3）。
   根治应当由 `teellm/deploy.sh` 在部署后自动补链接 + `ldconfig`，而不是靠手工或靠 bundle——
   否则下一个全新环境必然重演 127。**这是本次唯一有复发风险的遗留。**
2. **`TAA_LLM_ENDPOINT` 需要在调用 `deploy.sh` 时显式给出**，仓库里没有持久化
   `10.0.0.2`。这是有意的（容器 IP 是运行期变量），但意味着文档/编排层要负责传递它。
3. **本轮未做真实审计请求的端到端**（TAA 收到扫描任务 → 调 LLM verifier → 返回）。
   启动探测已覆盖同一条链路且成本极低，真实审计需要走平台协议的加密信封，
   留给后续按需补做。
4. **容器 1 里那份 teellm 已被停掉**（网关现在只在容器 2）。若日后需要回退到同容器部署，
   `teellm/deploy.sh` 的默认值改回 `taa-env-slim-v2`、`TAA_LLM_ENDPOINT` 留默认回环即可，
   两条改动都是可逆的。
