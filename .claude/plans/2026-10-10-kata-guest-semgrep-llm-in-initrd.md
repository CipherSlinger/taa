# Kata guest 内启用 semgrep + LLM 审计（semgrep 进 initrd，LLM 指向 116 teellm）

## Context（为什么做这件事）

现状：kata CSV2 guest 里的 TAA 审计是 **regex-only**——`configs/taa-initrd.json` 里
`codeScanEngine: "regex"`、`llm.enabled: false`，所以 14:17:28→14:17:29 一秒跑完，5 处
LOW、无大模型复核。docker 臂（`taa-env-slim-v2`，`.local/run/docker-taa-config.json`）跑的是
`semgrep 1.177.0 + LLM(teetls → 10.0.0.2:8443, qwen2.5-coder:7b)`，同一个包耗时 ~2m49s。

目标（用户三条指令）：① initrd 配置 `llm.enabled=true`；② LLM 指向**本地 116 上 docker 部署的
teellm**；③ 把 semgrep 随 TAA 一起打进 initrd，并报告总大小。

## 实测事实（本次探到，直接决定方案）

| 事实 | 证据 |
|---|---|
| teellm 只在 docker bridge 上：容器 IP `10.0.0.2:8443`，宿主 **没有** 发布端口（`docker port` 空，`ss` 上无 8443） | `docker inspect taa-teellm` |
| teellm 容器不可重建：ollama 运行时 + 模型（约 4.7G）都在容器可写层，无挂载、无 restart 策略 | `docker inspect`（Mounts=[]，ENTRYPOINT=`tail -f /dev/null`） |
| guest rootfs = **Ubuntu 22.04 / glibc 2.35**，无 python3、无 semgrep | 解包 base initrd：`etc/os-release`、`usr/lib/x86_64-linux-gnu/libc.so.6` |
| `semgrep-core` 需 ≤ GLIBC_2.34 ✔；noble 的 `python3.12` 需 GLIBC_2.38 ✘ | `objdump -T`（psABI 版本） |
| semgrep 1.177.0 的 Linux wheel 标签是 **manylinux_2_34**（1.157.0 是最后一个 manylinux2014） | PyPI JSON API |
| TAA 用 PATH 找 `semgrep`（`exec.CommandContext(ctx, "semgrep", …)`），而 PID 1 继承内核默认 PATH（`/sbin:/usr/sbin:/bin:/usr/bin`）**不含 /usr/local/bin** | `internal/codeaudit/semgrep_engine.go:555`、`deploy/guest-build/taa-init.sh` |
| 配置键齐全，无需改 Go：`security.codeScanEngine` / `security.semgrepRulesPath` / `security.semgrepTimeoutSeconds`、`llm.{enabled,transport,endpoint,model,policy,failClosed,requestTimeoutMs,insecureSkipVerify,attestationMode}` | `internal/config/config.go:129-200, 400-404` |
| 镜像里没有 semgrep（`/opt/taa/semgrep` 是 `deploy-docker.sh` 运行时装进**容器**的），但仓库 tracked 了 rules | `docker exec taa-env-slim-v2`；`git ls-files models/audit/semgrep/rules` |

## 体积报告（实测）

| 组件 | 未压缩 | 进 initrd 后（gzip -9） |
|---|---|---|
| python3.10 运行时（`python3.10` + `lib-python3.10` 标准库） | 23 MiB | 6.8 MiB（实测 gzip） |
| semgrep 依赖闭包：66 个 cp310 wheel → `pylib/` | 310.3 MiB | ~81 MiB（按 wheel 自身 deflate 计） |
| ↳ 其中 `semgrep` wheel（含 `semgrep-core` 244.6 MiB） | 263.3 MiB | 62.5 MiB（实测 `semgrep-core` 单独 gzip） |
| ↳ 其余 65 个依赖（cryptography、pydantic_core、pygments、peewee…） | 47 MiB | ~19 MiB |
| rules（c/go/java/python/shell 5 份 yaml） | 60 KiB | ~0 |

- 今天的 initrd（regex 版）：**68,222,611 B ≈ 65.1 MiB**（`deploy/guest-build/out/…`）
- 预计加完后：**≈ 150–155 MiB（约 2.3×）**，构建后以实测为准
- guest 内存：initrd 就是 rootfs（`shared_fs=none`，无 virtio-fs），**rootfs 由 145 MiB 涨到 ~479 MiB，全部常驻 guest 内存（+334 MiB）**

## 实施

### 1. 新增载荷构建脚本 `deploy/guest-build/build-semgrep-payload.sh`（入库）

一键产出 `deploy/guest-build/semgrep-payload/`（**不入库**，加进 `deploy/guest-build/.gitignore`）：

```
semgrep-payload/
  host/{python3.10,lib-python3.10/}      # 来自 ubuntu:22.04（jammy，glibc 2.35 对齐）
  pylib/                                 # 66 个 wheel 解包后的 site-packages 树
  rules/{c,go,java,python,shell}/rules.yaml
  MANIFEST                               # engine/version/rules sha256/wheel 清单
  semgrep                                # wrapper（见下）
```

- python：`ubuntu:22.04` 里 `apt-get install --no-install-recommends python3.10-minimal libpython3.10-stdlib`，
  `cp -a` 出 `/usr/bin/python3.10` 与 `/usr/lib/python3.10`（**装到 guest 的 native 路径**，就不用 `PYTHONHOME`）。
  apt 源用镜像（tuna/aliyun，`APT_MIRROR` 可覆盖）——`archive.ubuntu.com` 在本机容器里实测会挂住。
- wheels：用 `taa-env:slim-v2`（有 pip）`pip download --only-binary=:all: --python-version 3.10 --abi cp310
  --platform manylinux_2_34_x86_64 --platform manylinux_2_28_x86_64 --platform manylinux2014_x86_64
  --platform manylinux_2_17_x86_64 -i $PIP_INDEX_URL semgrep==1.177.0`。
  版本对齐 docker 臂：把容器里的 `/opt/taa/semgrep/pip-freeze.txt` 当 constraints（去掉 `semgrep==…` 自身那行，
  否则 pip 报 ResolutionImpossible）；默认 index 用 `pypi.org`（tuna 上游只到 1.157.0）。
- 解包：直接 `unzip -q -o` 每个 wheel 到 `pylib/`（等于 pip 的安装动作，且不受宿主 python 版本限制）。
- wrapper（`/usr/local/bin/semgrep`，chmod 0755）：
  ```sh
  #!/bin/sh
  # The guest has no python3 on PATH and no distro semgrep: both are pinned here.
  PYTHONPATH=/opt/taa/semgrep/pylib
  export PYTHONPATH
  exec /usr/bin/python3.10 -c 'import sys; from semgrep.console_scripts.entrypoint import main; sys.argv[0]="semgrep"; sys.exit(main())' "$@"
  ```
  （`semgrep-core` 由包内 `semgrep/bin/semgrep-core` 提供，其自有依赖在 `semgrep/bin/libs/`，`RPATH` 已命中，
  只有 libc 取自 guest —— 已用 `ldd` 核过。）

### 2. `deploy/guest-build/build-initrd.sh` 注入载荷

- 新变量：`TAA_SEMGREP_PAYLOAD_DIR="${TAA_SEMGREP_PAYLOAD_DIR:-$ROOT_DIR/deploy/guest-build/semgrep-payload}"`。
- `check_build_inputs`：当 `$TAA_CONFIG_SRC` 里出现 `"codeScanEngine": "semgrep"` 时，校验
  payload 的 4 个入口（`host/python3.10`、`pylib/semgrep/bin/semgrep-core`、`rules/python/rules.yaml`、`semgrep`）
  存在，缺了就报「先跑 build-semgrep-payload.sh」——与 `ROOT_DIR` 那条「路径写错会报成缺输入」的教训保持一致。
- 新增 `stage_semgrep_payload()`：把 payload 按 guest 路径摆进 `$BUILD_WORK_DIR/extra/`：
  `usr/bin/python3.10`、`usr/lib/python3.10/`、`usr/local/bin/semgrep`、
  `opt/taa/semgrep/{pylib,rules,MANIFEST}`。（顺带补 guest 缺的 `libsqlite3`/`libreadline`/`libgdbm`，
  若 `ldd` 显示 `_sqlite3`/`readline` 需要；`libexpat/libffi/libbz2/liblzma/libncursesw/libtinfo/libuuid/libssl3` 已在内。）
- **追加清单改为枚举**：现在的 5 条硬编码 `for path in …` 改成
  `find "$BUILD_WORK_DIR/extra" -mindepth 1 | sed 's|^.*/extra/||' | LC_ALL=C sort`，
  父目录自然排在子项前；`etc/default/taa.env` 的按需写入仍然先于枚举即可。
  末尾「entry 数 = base + 追加数」的不变式保留不动（它正是防重复/静默丢失的那条）。
- 更新 `:352` 那段已过期的注释（“regex engine (no semgrep rules shipped in the initrd)”）。

### 3. `deploy/guest-build/taa-init.sh`：给 PID 1 的 PATH 加上 `/usr/local/bin`

在启动 TAA 之前加两行（带英文注释说明「内核给 PID 1 的 PATH 不含 /usr/local/bin，而 TAA 靠 PATH 找 semgrep」）。
之后跑 `deploy/guest-build/test-taa-init.sh`。

### 4. `configs/taa-initrd.json`：开 semgrep + LLM（对齐 docker 臂）

```json
"security": {
  "codeScan": true,
  "codeScanEngine": "semgrep",
  "semgrepRulesPath": "/opt/taa/semgrep/rules",
  "resultCheck": { "enabled": true, "maxFileBytes": 3221225472 }
},
"llm": {
  "enabled": true,
  "transport": "teetls",
  "endpoint": "https://172.16.10.116:8443",
  "model": "qwen2.5-coder:7b",
  "policy": "assist",
  "failClosed": true,
  "requestTimeoutMs": 120000,
  "insecureSkipVerify": true,
  "attestationMode": "permissive"
}
```
端点写死 116 是沿用仓库既有做法（`deploy-taa-vm.sh` 的 `TAA_PLATFORM_IP` 默认就指向 172.16.10.116）；
换环境用 `TAA_CONFIG_SRC` 覆盖整份配置。**不改任何 Go 代码**——引擎与 LLM 两条链路都已存在且有测试。

### 5. 116 上把 teellm 暴露到宿主（socat 边车，不碰 teellm 容器）

```sh
docker run --name teellm-socat-build alpine:latest sh -c 'apk add --no-cache socat'
docker commit teellm-socat-build teellm-socat:local && docker rm teellm-socat-build   # 固化，避免每次重启要联网
docker run -d --name teellm-portproxy --restart unless-stopped \
  -p 172.16.10.116:8443:8443 teellm-socat:local \
  socat TCP-LISTEN:8443,fork,reuseaddr TCP:10.0.0.2:8443
```
纯 L4 转发，TLS 端到端不变，teellm 与预热好的模型完全不动。

### 6. 入库与记忆

按 CLAUDE.md：本计划另存一份到 `.claude/plans/`（`.claude/` 被 ignore，需要 `git add -f`）；
提交信息英文、Conventional Commits、无任何 AI 署名。跑完后把结论写进 memory（新增「kata guest 内 semgrep+LLM 的载荷与开销」一条，并更新 `taa-initrd-guest-contents`）。

## 验证

1. **脚本静态**：`bash -n` 三个改动的脚本；`deploy/guest-build/test-taa-init.sh` 全绿。
2. **载荷能在 guest rootfs 里跑**（不需要真机）：把解包好的 base initrd 根fs `docker import` 成镜像，
   在**该 rootfs** 里跑 `/usr/local/bin/semgrep --version`，再对 `models/` 用 5 套 rules 真扫一遍，
   期望 exit 0、JSON 可解析、findings 与 docker 臂对同一目录的扫描结果逐字段一致。
3. **尺寸**：构建后 `ls -l deploy/guest-build/out/kata-containers-initrd-taa-csv.initrd` 报实测值。
4. **部署**：`TAA_PLATFORM_IP=172.16.10.178:18081 ./deploy-taa-vm.sh up`（exit 0、attestation 通过）；
   部署后确认 kata 配置里 `default_memory` 够（不够就调大，initrd 变大后要复核）。
5. **端到端**：`PLATFORM_PORT=18081 TARGET_NAMESPACE=default TARGET_POD=test-kata-csv2-taa ./deploy.sh remote platform-mock`
   （pod 重建后 mock 的 `-taa-target` 必须重启才生效）→ 上传同一模型包 → 看 `dockerId=kata-csv2-taa-test-0001`
   的 audit 日志变成 `engine=semgrep, llmEnabled=true`，且报告里出现大模型结论，耗时落在分钟级。
6. **连通性佐证**：guest 内探 `172.16.10.116:8443`（TAA 的 healthz 探针本身就会打这条），失败即 fail-closed 拒导入。
7. **Go 测试**：`go list -e ./... | grep -v /models/audit/` 逐包 `go test -p 1 -count=1`（本机 9G 内存，必须串行）。

## 风险与决策点（默认已选定，可否决）

- **initrd 2.3×、guest RAM +334 MiB**：kata `default_memory` 若只有 2GiB 需要调大（部署时读 178 上的
  `/etc/kata-containers/configuration-qemu-csv2-taa.toml` 确认）。
- **`failClosed: true`**：与 docker 臂一致；含义是 teellm 不可达时**拒绝导入**（不是降级）。
- **LLM 在 TEE 之外**：开启后 findings/代码片段会出 guest 到 116 的明文 docker（这是本次指令的既定选择，
  但它确实削弱了 kata 那条保密前提，值得在文档里写明）。
- **teellm 判定不确定**（已有 memory）：同一份良性代码可能被判 MALICIOUS，assist+failClosed 下会拒导入。
- **依赖闭包可裁剪**：`mcp`/`opentelemetry-*`/`uvicorn`/`starlette`/`pydantic` 这批是 semgrep 的 MCP 子命令带的，
  预计能省 ~20–30 MiB（压缩后）。默认**不裁**（与 docker 臂逐包保真，可复现同一次判定）；
  若要省，需实测裁剪后 `semgrep scan` 仍 exit 0。

---

## 实测结果（2026-10-10 完成）

### 尺寸（用户指令 3 要报的数）

| | 加 semgrep 前 | 加 semgrep 后 | 倍数 |
| :--- | ---: | ---: | ---: |
| initrd（gzip -9，落盘） | 68,222,611 B（65.1 MiB） | **160,071,959 B（152.7 MiB）** | 2.35× |
| 解包后（= guest rootfs，常驻 guest 内存） | 152,186,368 B（145.1 MiB） | **524,587,520 B（500.3 MiB）** | +355.1 MiB |

- 追加条目 4250（其中 semgrep 载荷 3329 条），cpio 条目 4682(base) + 4250 = 8932 ✓ 不变式通过。
- 载荷未压缩 346M / 4243 文件：python3.10 运行时 18M + pylib 319M（其中 `semgrep-core` 单文件 245M）
  + 补入 base 缺失的 8 个动态库（libstdc++/libcurl/libdw/libev/libnghttp2/libtree-sitter/libunwind）。
- 产物 sha256 前缀 `d412ee3586fb821c`；`.entries` 完整清单 4250 行。

### 实现期发现的两处设计更正（都已改在脚本里）

1. **不能用 `zipfile.extractall` 解 wheel**：semgrep 的 wheel 把整个 Python 包放在 scheme 目录
   `semgrep-1.177.0.data/purelib/` 下（要合并到安装根），而且 `semgrep-core` 的可执行位要靠 zip 条目的
   external attributes 恢复（pip 会做，`zipfile` 不会）。手写解包的结果是 pylib 看着非空、实际没有
   `semgrep` 包。改为在同一个 jammy 容器里 `python3.10 -m pip install --no-index --no-deps --no-compile
   --target` 装。
2. **PATH 上要放两个入口，不是一个**：`pylib/bin/semgrep` 会在 OCaml CLI 与 Python CLI 之间分派，OCaml CLI
   回退时按名字找 `pysemgrep`（`entrypoint.py` 为此把 `sysconfig` 的 scripts 目录追加进 PATH，本 rootfs 上
   就是 `/usr/local/bin`）。只放 `semgrep` 的报错是 `Unix_error: execvp pysemgrep`。
   故 `/usr/local/bin/{semgrep,pysemgrep}` 各一个 wrapper（都 pin `PYTHONPATH=/opt/taa/semgrep/pylib`）。

### 本机验证（不需要真机）

`deploy/guest-build/test-semgrep-payload.sh`（新增，入库）：把 base initrd 解包、叠加载荷、`docker import`
成镜像，在**该 rootfs 内**跑 `semgrep --version`（1.177.0）与一次真实扫描，再与运行中的 docker 臂
（`taa-env-slim-v2`）对同一份样本比较 findings。结果：**两臂 findings 完全一致（4 条，规则名+文件+行号）**。
说明：臂的 semgrep 只在容器可写层（`deploy-docker.sh` 运行时装的），所以对照必须走 `docker exec` 而不是
`docker run` 新容器。

注：容器化的 rootfs 里 `/dev` 由 docker 自己挂，故导入镜像前删掉 base 的 `dev/`；解包必须在 root 容器里做
（base 带 ~250 个设备节点，非 root cpio 建不出来且返回非零）。

### 第三处设计更正：LLM 启动探针必须只告警不致命（**一处 Go 改动**）

计划原本写「不改任何 Go 代码」，实际必须改一处。开 `llm.enabled=true` 后首次 `launch` 卡在
`ContainerCreating`：`Failed to create pod sandbox: … timed out connecting to vsock …`。
从 VM 的 `console.sock` 抓 guest 控制台，拿到的是决定性的证据：

```
taa-init: created /dev/csv-guest (10, 257)
taa-init: TAA exited immediately
ERROR: inference service connectivity probe failed after 738ms: … dial tcp
       172.16.10.116:8443: connect: network is unreachable
[TAA-FATAL] probe inference service (fail-closed): …
taa-init: TAA_REQUIRED=1; not starting kata-agent
```

即 `failClosed=true` 的**启动期**探针在 initrd 里结构上不可满足：guest 网卡由 kata-agent 配，
而 wrapper 只在 TAA 起来之后才 `exec /sbin/init`（§4.1 的启动顺序）。TAA 一退出，wrapper 按
`TAA_REQUIRED=1` 拒绝交出 PID 1，沙箱永远建不出来。这与 §7 第 4 条预测的注册失败是同一个根因，
只是注册那条只是 warning、这条是致命的。

处理（`internal/app/taa/app.go`）：启动探针改为**只告警**；`failClosed` 的承重位置不变，仍是
审计前的那次探测（`internal/controller/import_processing.go:633`，网络已就绪，不可用就拒导入）。
配套把 `TestRunWithConfig_LLMProbeFailClosed` 换成
`TestRunWithConfig_LLMProbeFailureDoesNotAbortStartup`（用「keys 目录指到一个普通文件」让后续步骤
确定性失败，从而证明探针之后控制流还在）。**不要**用 `llm.failClosed=false` 绕过——那会连审计期的
fail-closed 一起关掉。

### 第四处：initrd 里烘焙的注册身份必须与本次部署一致（驱动侧新增检查）

第二次 `launch` 后 pod Ready、attestation 通过，但平台始终收不到注册。原因：`build` 与 `deploy`
是两次独立调用，我这次 `build` 时没带 `TAA_PLATFORM_IP`，于是 initrd 里烘焙的是默认值
`PLATFORM_IP=172.16.10.116:18080`；deploy/launch 却按 `172.16.10.178:18081` 走。
guest 内的 TAA 只认 initrd 里那份，**本地完全无症状**（pod Ready、证明为真、只是注册去了别处）。

处理：`deploy-taa-vm.sh` 新增 `check_initrd_identity()`，在 deploy/launch 的 preflight 里解出
initrd 内的 `etc/default/taa.env`，与本次调用解析出的 `TAA_PLATFORM_IP`/`TAA_DOCKER_ID` 逐字比较，
不一致就带着「重新构建」的命令行直接失败（实测能拦住，且发生在任何上传之前）。
