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
而 `llama-server` 的 `DT_NEEDED` 记的是 soname（`libllama-common.so.0`），
它带的 `RUNPATH` 是 **`$ORIGIN`**，即加载器会去**二进制自己所在的目录**找这些名字——
目录里没有 → 未命中。

> ⚠️ **勘误**：本节初稿写的是「没有 RUNPATH」，那是错的。在容器里跑 `readelf` 失败（镜像内无此工具）
> 被 `|| echo` 吞成了「无 RUNPATH」。用宿主的 `readelf` 复核，`llama-server` 确实有
> `RUNPATH = $ORIGIN`。**这改变了修复方式**：不必动 `ld.so.cache`，只要在二进制旁边补出
> soname 名字即可。

### 4.2 容器 1 当初为什么"是好的"

**纯属巧合，而且是双重侥幸。** 容器 1 跑 ollama 时 `OLLAMA_LIBRARY_PATH` 指向
`/root/taa/ollama/lib/ollama`（**没有**链接），所以 `$ORIGIN` 那一跳必然未命中；
但加载器随后落到 `ld.so.cache`，而那份 cache（mtime Sep 21 01:56）指向的是**另一个目录**
`/root/taa/ollama-qwen/lib/ollama`，那里的链接是同一时刻手工建的。
**仓库里没有任何脚本会跑 `ldconfig`**，所以这份 cache 是历史遗物，不可复现——
两个目录、一次手工 `ln -s`，缺任何一个容器 1 都跑不起来。

### 4.3 处置：`teellm/deploy.sh` 自己补链接

**只补符号链接就够，不需要 `ldconfig`。** 实测：容器 2 撤掉 `/etc/ld.so.conf.d/ollama.conf`
并重跑 `ldconfig` 后，`ld.so.cache` 里 libllama 条目数为 **0**，仅靠 6 个符号链接，
`$ORIGIN` 那一跳即命中，healthz 返回 `OK`。（`ldconfig` 那条路一开始也做了，事后证明多余。）

已实现为 `teellm/deploy.sh` 里的 `ollama_soname_fix_script()`，在**本地容器路径**
（`deploy_docker`）与**远端 pod 路径**（`deploy_remote`）各调用一次，位置都在 ollama 文件落地
之后、守护进程启动之前。要点：

| 设计 | 理由 |
| :--- | :--- |
| **按版本号推导**，不写死 `0.1.2` | 从目录里实际存在的 `libNAME.so.X.Y.Z` 推出 `libNAME.so.X`。写死版本号会在 bundle 升级后变成悬空链接 |
| 只处理 `lib*.so.*` | `libllama-server-impl.so` / `libggml-cpu-*.so` 这类本就无版本号的文件天然不匹配 |
| 已是 soname 的文件跳过 | `libbaz.so.7` 这类不会被再包一层 |
| 幂等 | 已存在的链接不动，第二次运行报告 `0` |
| 报告新建条数 | 正常运行静默；只有真的补了才打印，便于发现 bundle 又退化了 |

**验证**（在容器 2 上真做了一遍复现—修复—幂等）：

| 步 | 动作 | 结果 |
| :--- | :--- | :--- |
| 1 | 删 6 个链接 + 撤 `ld.so.conf.d` 条目 + `ldconfig` | cache 里 libllama **0** 条 |
| 2 | 探测 | **`503`**（缺陷复现） |
| 3 | 跑脚本里的真实函数 | 报告 **6** |
| 4 | 探测 | **`OK`** |
| 5 | 再跑一次 | 报告 **0**（幂等） |

远端路径的字符串拼接另用本地 stub 验过：`libfoo.so.1.2.3 → libfoo.so.1`、
`libbar.so.4.5.6 → libbar.so.4`、已是 soname 的 `libbaz.so.7` 被跳过、报告 `2`。

本地 bundle 源目录 `teellm/models/ollama/lib/ollama/` 也补了同样 6 个链接，
但**那份在 gitignore 里**（`teellm/.gitignore:7` 忽略 `models/ollama/lib/`），所以
**真正承重的是脚本里的自动补齐，不是 bundle**——这正是要把它做进 `deploy.sh` 的理由。

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

1. ~~**`models/ollama/lib/` 被 gitignore，soname 链接不在版本控制里**~~
   **已解决**：改由 `teellm/deploy.sh` 的 `ollama_soname_fix_script()` 在部署时自动补齐
   （§4.3），bundle 是否带链接、是否被 gitignore 都不再重要。**复发风险已消除。**
2. ~~**`TAA_LLM_ENDPOINT` 需要在调用 `deploy.sh` 时显式给出**~~
   **已解决**：`deploy.sh` 的 `resolve_llm_endpoint()` 改成**自动探测**——显式变量优先，
   否则取 `taa-teellm` 容器的 IP，都取不到才回落回环（host 网络的 teellm 报不出 IP，
   正好也落回环）。远端路径**不做探测**（`docker inspect` 在本地跑，会把本地容器 IP 写进
   远端配置），那里仍是「显式变量或回环」。见 §7。
3. **本轮未做真实审计请求的端到端**（TAA 收到扫描任务 → 调 LLM verifier → 返回）。
   启动探测已覆盖同一条链路且成本极低，真实审计需要走平台协议的加密信封，
   留给后续按需补做。
4. **容器 1 里那份 teellm 已被停掉**（网关现在只在容器 2）。若日后需要回退到同容器部署，
   `teellm/deploy.sh` 的默认值改回 `taa-env-slim-v2`、`TAA_LLM_ENDPOINT` 留默认回环即可，
   两条改动都是可逆的。

---

## 7. 顺带修掉的两个部署脚本缺陷

这两个都不是容器拆分引入的，而是在用 `./deploy.sh docker` 走一遍时暴露出来的。

### 7.1 端点默认值：写死回环 → 自动探测

**这是本文件 §3.2 那个默认值的直接后果。** 拆容器之后 `./deploy.sh docker` 不再带
`TAA_LLM_ENDPOINT`，于是配置被写回 `https://127.0.0.1:8443`，而网关在 `taa-teellm`
（`10.0.0.2`）——`fail-closed: true` 让 TAA 每 10s 崩溃重启，部署在 120s 就绪等待上超时：

```
[TAA-FATAL] probe inference service (fail-closed): health check failed:
  Get "https://127.0.0.1:8443/healthz": dial tcp 127.0.0.1:8443: connect: connection refused
```

**改法**：`TAA_LLM_ENDPOINT` 默认改为空，新增 `resolve_llm_endpoint()`：

| 优先级 | 取值 |
| :--- | :--- |
| 1 | 显式设置的 `TAA_LLM_ENDPOINT` |
| 2 | `taa-teellm` 容器（可用 `TAA_TEELLM_CONTAINER` 改名）的 IP |
| 3 | `https://127.0.0.1:<TAA_TEELLM_PORT>`（默认 8443） |

只在**本地 docker** 两处调用（`save_local_docker_image`、`deploy_docker_taa`），
并在部署时打印 `✓ taa llm endpoint: https://10.0.0.2:8443` 让它可见。

**远端那处刻意不探测**：那是要被 `scp` 到远端宿主机的配置，在本地跑 `docker inspect`
会把**本地**容器 IP 写进远端配置。远端维持「显式变量，否则回环」。

### 7.2 提示信息里 `\033[2m` 字面输出

`teellm/deploy.sh` 的日志函数把消息放在 `%s` 参数位：

```sh
info() { printf "   ${GREEN}✓${NC} %s\n" "$1"; }
...
info "$label ${DIM}(took ${total_elapsed}s)${NC}"   # ← 颜色码在参数里
```

`printf` **只解释格式串里的反斜杠转义**，参数里的 `\033` 原样输出，于是终端显示
`✓ compiling teellm-service binary \033[2m(took 1s)\033[0m`——绿色的 ✓ 正常，暗淡的耗时前后缀变成裸文本。

**改法**：`step/info/warn/err/detail` 的消息参数一律从 `%s` 改为 `%b`（`%b` 会解释参数里的转义），
一处改动覆盖全部调用点，也防止以后再犯。`banner()` 用 `echo -e`，本来就没问题。

⚠️ **这套 helper 在仓库里有三份拷贝**，只修一份会漏：

| 文件 | 触发点 | 状态 |
| :--- | :--- | :--- |
| `teellm/deploy.sh` | `:176`、`:1275`、`:1846`、`:2126` | 已修 |
| `deploy.sh` | `:297`、`:854`、`:1290` | 已修 |
| `deploy-docker.sh` | 当前无触发点，但 helper 同样是 `%s` | 已修（防患） |

**第一次只修了 `teellm/deploy.sh`，用户随即在 `./deploy.sh docker` 上再次撞到**——
所以这里明确记下"三份都要改"。

验证方式：颜色只在 `[[ -t 1 ]]` 为真时启用，管道里跑会因 `DIM=''` 而**看不出问题**。
必须用 `script -qec './deploy.sh docker' /dev/null` 分配 pty，再 `cat -v` 查
字面 `\033` 是否归零（实测 **0**）。

### 7.3 一处误导性注释

`deploy_remote` 里那对路径兼容软链接的注释写的是 **"Dynamic linker compatibility symlinks"**——
**错的**。它们与动态加载器无关（真正的加载器问题是 §4），只是把
`/taatest/ollama-qwen2.5-coder-0.5b` 与 `$CON_WORKDIR/ollama-qwen2.5-coder-0.5b`
这两个**旧路径**指向当前的 `CONTAINER_OLLAMA_DIR`。注释已改正，并点明与 §4 无关。

> **关于这对软链接的来历**（2026-10-10 追到了源头）：它们在子模块的第一个提交
> （`6a1d925`，2026-09-19）就存在，但**不是那时发明的**——父仓库 `e476172`
> （2026-09-10，"合并整合 qwen 模型目录为 ollama-qwen"）引入了它们，提交说明写的是
> "保留旧路径软链接向后兼容"，代码注释写得更具体：
>
> ```
> # The ollama binary expects /taatest/ollama-qwen2.5-coder-0.5b/lib/glibc/ld-linux-x86-64.so.2
> ```
>
> 即当时 bundle 里的 `ollama` 是通过**绝对路径**指向自带 glibc 加载器启动的，
> 目录一改名这条绝对路径就断，所以要在旧名字上留一个软链接。
>
> **这个理由今天已经不成立**，实测：
>
> | 检查 | 结果 |
> | :--- | :--- |
> | 当前 bundle 的 `start-ollama.sh` | 用 `$(dirname -- "$0")` 自解析，**无绝对路径** |
> | bundle 里的 `lib/glibc/` | **不存在**（那个加载器本身已不在包里） |
> | `ollama` 的 `PT_INTERP` | 系统的 `/lib64/ld-linux-x86-64.so.2` |
> | `llama-server` 的 `PT_INTERP` | 系统的 `/lib64/ld-linux-x86-64.so.2`（`RUNPATH=$ORIGIN`，见 §4） |
> | 两个二进制里 `taatest` 字符串 | **各 0 命中** |
> | 容器内 `/root /etc /usr/local /opt` 引用这两个路径的文件 | **0 命中** |
> | 仓库内 `taatest` | 只有 `Dockerfile.base` 建目录、`docs/architecture-design.md` §10.3、脚本自己 |
>
> 所以它**现在是纯路径别名**，没有加载器含义（§4 那个才是真加载器问题，两者无关）。
>
> **唯一还在真干活的地方是旧名字，不是软链接**：`copy_ollama_to_remote_pod`
> （`:1922-1928`）与 `sync_ollama_to_remote`（`:1873-1875`）把
> `ollama-qwen2.5-coder-0.5b` 当作**迁移来源**——远端 pod/宿主若还留着该名字的**真目录**，
> 就就地迁移或复用 `lib/`，省掉几 GB 传输。注意那里的判据是
> `test -d … && ! test -L …`，**本脚本自己建的软链接故意不算数**，不会被误当成旧安装。
>
> 结论：保留。它此刻是冗余的，但 **bundle 不在版本控制里**（`teellm/.gitignore:7`），
> 换一份 bundle 就可能重新需要它——用一个软链接买这个保险很便宜。删除属于待定项。
