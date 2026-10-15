# teellm 落进专用 Kata CSV2 Pod：让 TAA 收到真证明

日期：2026-10-15
状态：已实现并在 178 上实机验证（离线与实机结果见文末「验证状态」）

## 背景

TAA 的代码审计要调 TEE-LLM（`teellm`）。teellm 当时跑在 172.16.10.178 上一个**普通 docker 容器**
（`taa-env-slim-v2`，`172.17.0.2:8443`）里，而这个容器**没有 `/dev/csv-guest`**，于是
`teellm-service` 静默退回 **mock 证明提供者**（`teellm/cmd/teellm-service/main.go:191-202`）。
mock 的 HRK 是**每进程随机生成**的（`teellm/teetls/pkg/csvattest/mock.go:29-54`），而 TAA 客户端
拿的是真 Hygon HRK，握手必然死在：

```
teetls: verify server attestation: invalid or corrupted CSV attestation report: untrusted HRK certificate
```

→ `[ERROR] [audit] LLM 服务不可用，按 fail-closed 策略上报失败` → 审计 `code=2`。

`attestationMode: "permissive"` **救不了**：permissive 只放宽度量值不匹配，信任链失败在两种模式下
都是致命的（`teellm/teetls/verifier.go:118-172`）。

同一个故障现场还叠着一条网络问题：`dial tcp 172.17.0.2:8443: i/o timeout`。docker 28 重建
FORWARD 链后，`DOCKER` 链的 DROP 排在了 `deploy-llm.sh` 手工 ACCEPT 规则之前。该问题已就地修好，
但它属于 `allow_pod_access_to_container` 的既有缺陷（只查规则存在、不查规则位置），不在本设计范围内。

**目标**：让 teellm 跑在它自己的 Kata CSV2 Pod 里（同节点），那里 `/dev/csv-guest` 存在，teellm
出真报告，TAA 用真 HRK 验得过去——**不开 `llm.insecureSkipVerify`**。

## 现场事实（2026-10-15 实测，不要再假设）

- 在跑的 TAA Pod 都是 `runtimeClassName: kata-qemu-csv2`（宿主既有 handler）、`nodeName: hygon-master`、
  镜像 `172.16.10.178:31313/taa-env:slim-v2-20260916`，**容器里都有 `/dev/csv-guest`（`crw-rw-rw- 10,257`）**。
- **该设备不是 RuntimeClass 白送的（首次部署实测推翻，见下方「修正」）**：CSV2 guest 内核只**注册** misc 设备
  （容器里 `/proc/misc` 有 `257 csv-guest`、`/sys/class/misc/csv-guest/dev` = `10:257`），容器的 `/dev`
  是一块**全新 tmpfs**，节点要**容器侧**建。TAA 的 Deployment 清单里有一个 `lifecycle.postStart`
  钩子做这件事（等 sysfs → `mknod` → `chmod 666`），那个清单**不在本仓库**，所以在本仓库 grep
  `mknod` 找不到它。
- `deploy/guest-build/taa-init.sh:119` 的 `mknod` 是**guest 内** PID 1 自己用的（在 guest 的 /dev 里），
  并不会传进容器；容器看到的是另一块 tmpfs。
- guest 规格：**guest RAM = kata `default_memory` 23552M + `limits.memory`**；
  **vCPU = `default_vcpus` 1 + `limits.cpu`**。CSV2 加密内存**开机即 100% 实占**。
- 宿主：251GB / 64 核，可用 ~123GB。
- TAA Pod 里 `/root/taa/certs/hrk.cert` 与 `deploy/certs/hrk.cert` 同 md5 `d180de08…`（真 HRK），
  且 `internal/config/config.go:417-453` 把它作为**默认锚** → TAA 侧不需要改任何配置。
- `deploy-llm.sh` 的 `remote` 模式**已经是完整的 Pod 部署路径**（`deploy_remote()`：流式传 ollama、
  起 ollama、`kubectl cp` teellm-service + 配置 + 证书、起服务、`-probe` 探活），
  但它**从不创建 Pod**，Pod 路径上也**没有任何 `/dev/csv-guest` 检查**（那条只在 docker 路径上）。
- **8Gi 装不下一个 7B 模型（首次成功建 Pod 后再次实测，见下方「修正 2」）**：容器自己的 cgroup
  （`/sys/fs/cgroup/memory.max` = 8Gi）在 llama-server 加载 `qwen2.5-coder:7b` 时被打爆 ——
  `memory.events` 的 `oom_kill=128`、guest `dmesg` 里
  `Memory cgroup out of memory: Killed process … (llama-server) anon-rss:3690072kB`。
  模型 blob 的 page cache（4.4GB）加上张量缓冲（`load_tensors` 报 1483.70 + 2976.75 MiB）一起越顶，
  于是 teellm-service 一直回 503、部署在第 14 步超时退出。**默认内存因此从 8Gi 提到 16Gi。**
  TAA Pod 同样是 8Gi 却看不出问题，是因为它的 LLM 调用从来没越过握手、根本没让 ollama 加载过模型。

## 三个必须绕开的陷阱

1. **`-probe` 证明不了证明链**：`teellm/cmd/teellm-service/main.go:120-140` 的 probe 客户端写死
   `InsecureSkipAttestationVerify: true`。mock 与真硬件下 probe **同样通过**。它只能当就绪判据。
2. **打错 Pod 时 `/dev/csv-guest` 闸门会放行**：`TARGET_POD` 默认值就是**在跑的 TAA Pod**，
   而 TAA Pod 自己也有该设备。所以 `--create-pod` 必须**无条件**改写 `TARGET_POD`。
3. **`kubectl apply` 到已存在的 Pod 会失败或诱发重建**：`annotations`/`limits` 是不可变字段；
   「apply 失败就 delete 再 apply」正是**造出第二台 VM**（永久占宿主内存）的路径，
   而重建还会换 Pod IP，TAA 里烧死的 endpoint 就废了。

## 设计

```
deploy-llm.sh remote --create-pod start → 没有则建 taa-teellm；有且 Ready 则复用（绝不 apply）
TAA (kata-qemu-csv2, osr) --TEE-TLS--> https://<taa-teellm 的 PodIP>:8443   ← 真 /dev/csv-guest
```

- **不动** TAA 的 Go 代码、不动 `configs/*.json` 模板、不动宿主 RuntimeClass / containerd / kata 配置，
  也**不跑** `build-initrd.sh launch`。
- 不用 Service：Kata guest 解析不了集群 DNS，TAA 直接连 Pod IP。

### 新文件 `deploy/manifest/k8s/teellm-pod.yaml.tmpl`

**带注释的模板**，不是能直接 apply 的文件。占位符（模板头注释里逐条写明，且**不带双下划线**，
以免被自己的 `sed` 吃掉）：`__POD_NAME__ __NAMESPACE__ __NODE_NAME__ __IMAGE__ __RUNTIME_CLASS__
__CPU__ __MEMORY__ __CC_INIT_DATA__`。

关键字段（每条都在文件里写明理由）：

- `metadata.name`：**字面名**（默认 `taa-teellm`），**绝不用 `generateName`**——重跑不能生第二台 VM。
- `annotations`：**只放** `io.katacontainers.config.runtime.cc_init_data`（guest 内 CDH 拉镜像要 registry CA，
  缺了停 StartError）。**绝不能**照抄 `dcu-tee-pod.yaml` 里的 `io.containerd.cri.runtime-handler`
  （会劫持 runtime）和 `io.katacontainers.config.hypervisor.kernel_params`（空值会抹掉配置里的 `rdinit=`）。
  模板里以注释形式列出这两个禁抄键作为警示。
- `spec.runtimeClassName: kata-qemu-csv2`、`nodeName: hygon-master`、`restartPolicy: Always`
  （**不是 `Never`**：容器退出要能原地重启、保住 Pod IP）、`imagePullPolicy: IfNotPresent`。
- `command: ["/bin/sh","-c"]` / `args: ["while true; do sleep 3600; done"]`：容器活着以便
  `kubectl exec/cp`，同时**覆盖镜像 ENTRYPOINT**，不跑 TAA 自己的 `start.sh`。
- `resources.requests == limits`（Guaranteed，账要实）：默认 `cpu: 8` / `memory: 16Gi`
  → VM ≈ 23552 + 16384 = **39GiB 常驻**（16Gi 而非 8Gi 的理由见「现场事实」修正 2）。

### `deploy-llm.sh` 改动

1. **变量**：`TEELLM_POD_NAME=taa-teellm`、`TEELLM_POD_IMAGE`、`TEELLM_POD_NODE=hygon-master`、
   `TEELLM_POD_RUNTIME_CLASS=kata-qemu-csv2`、`TEELLM_POD_CPU=8`、`TEELLM_POD_MEMORY=16Gi`、
   `TEELLM_POD_READY_TIMEOUT=600`（guest 要从本地 registry 拉镜像）、`TEELLM_POD_TEMPLATE`、
   `TEELLM_POD_CC_INIT_DATA`、`TEELLM_POD_IP`、`CREATE_POD=false`、`TEMP_POD_MANIFEST=""`。
   并在 `TARGET_POD` 默认赋值**之前**捕获 `TARGET_POD_WAS_SET="${TARGET_POD+set}"`。
   - **与计划的一处偏差**：Pod 命名空间直接复用 `TARGET_NAMESPACE`（`K_NS`），因此不需要重建 `K_NS`。
2. **`derive_cc_init_data()`**：用 `kubectl ... jsonpath` 从任一在跑的 CoCo Pod 上取
   `io.katacontainers.config.runtime.cc_init_data`，去掉 CR/LF 返回**裸值**（引号交给模板），
   取不到就**致命退出**。`TEELLM_POD_CC_INIT_DATA` 可显式覆盖。
3. **`pod_up()`**：
   - 已存在且 `kubectl wait --for=condition=Ready --timeout=5s` 通过 → 打印 IP 返回，**绝不 apply**；
   - 已存在但不 Ready → dump `-o wide` + `describe` 后失败退出，**不自动删**；
   - 不存在 → `sed` 渲染模板 → `kubectl apply -f -`（stdin）→ `kubectl wait --timeout=$TEELLM_POD_READY_TIMEOUT`；
   - 最后 **硬闸门**：`kubectl exec … test -e /dev/csv-guest`，没有就报错并**保留 Pod 供查看**；
   - 取 `{.status.podIP}` 存入 `TEELLM_POD_IP`。
   **`pod_down()`**：`kubectl delete pod` 优雅删除（90s），仍在则 `--force --grace-period=0`，
   仍失败才报错。
4. **参数与动作**：`start` 上加 `--create-pod`；新增 `pod-down` 动作（照 `start/stop/probe` 的
   「cannot specify multiple actions」写法），处理块放在 stop 之后、start 前置检查**之前**
   （否则会被 ollama 包检查拦住）。归一化块：非 `remote` 模式用 `--create-pod`/`pod-down` 直接报错；
   `TARGET_POD_WAS_SET==set` 且与 `TEELLM_POD_NAME` 不同则报错；否则**无条件**
   `TARGET_POD="$TEELLM_POD_NAME"`。
5. **`deploy_remote()`**：在 `check_remote_connectivity` 与 `check_remote_pod` **之间**插入 `pod_up`，
   随后取一次 Pod IP。证书复制在 `CREATE_POD==true` 时从「有则拷、无则 warning」改成**致命**。
   probe 通过后再加**快检**：teellm-service 日志里必须出现硬件提供者那一行、
   **不得**出现 mock 回退行。
6. **收尾横幅**：打印可直接粘贴的 `TAA_LLM_ENDPOINT=https://<pod-ip>:8443`——remote 路径上这是
   **唯一**能改 TAA endpoint 的旋钮。
7. **`usage()`**：补 `pod-down`、`--create-pod`、全部 `TEELLM_POD_*` 环境变量、cc_init_data 的必要性
   与禁抄项，以及「Kata guest 解析不了集群 DNS，按 Pod IP 连」。

### TAA 侧

不改代码、不改模板。部署时显式给端点：

```
TAA_LLM_ENDPOINT=https://<taa-teellm 的 PodIP>:8443 TARGET_POD=<TAA pod> ./deploy.sh remote taa
```

（`write_taa_config` 在 remote 路径**总是**用 `${TAA_LLM_ENDPOINT:-https://127.0.0.1:8443}` 覆写
`llm.endpoint`，模板里的值不作数。）

## 新增测试 `tests/deploy_llm_remote_pod_test.sh`

沿用仓里既有约定（PATH 注入 `MOCK_BIN`、`ssh/scp` mock 把 `/root/taa` 重定向到临时根、
日志前缀 `SSH[...]`/`KUBECTL ...`）。测试从**一次性仓库根**运行 `deploy-llm.sh` 的副本，
里面放最小自洽的 teellm 模块与 ollama 包，因此不依赖 22G 的 submodule bundle，
也能构造出「证书缺失」这种在真检出里不可能出现的场景。断言：

- 首次运行**只 apply 一次**，落盘 YAML 含 `runtimeClassName: kata-qemu-csv2` / `name: taa-teellm` /
  `nodeName` / `restartPolicy: Always` / `cc_init_data` / 内存限额；
- 落盘 YAML 的 `io.` 注解键**恰好 1 个**且是 `cc_init_data`；
- **所有** `KUBECTL` 行的目标都是 `taa-teellm`，**没有一行**指向默认的 TAA Pod 名（陷阱 2 的护栏）；
- 第二次运行（Pod 已 Ready）**不再 apply**（陷阱 3 的护栏）；
- 没有 `/dev/csv-guest` 的 Pod 让脚本非零退出并给出明确信息（陷阱 1 的护栏）；
- `--create-pod` 与显式 `TARGET_POD=别的` 同时给 → 在**任何 kubectl 调用之前**被拒；
- 横幅里带 `TAA_LLM_ENDPOINT=https://<ip>:8443`；
- create 路径上证书缺失 → 部署失败（不是 warning）；
- `pod-down` 删掉 Pod，且从不指向默认 TAA Pod。

## 风险与边界

| 风险 | 处理 |
|---|---|
| 造出第二台 VM（永久吃宿主内存） | 字面 Pod 名；已存在绝不 apply、绝不 delete+recreate；测试断言第二次零 apply |
| 三台 100% 常驻 CSV2 VM 造成宿主 OOM | `requests == limits`；默认 **16Gi**（8Gi 实测被 cgroup OOM 打爆，见「现场事实」修正 2）；预检复核 `free -g`；`TEELLM_POD_MEMORY` 可调小 |
| `-probe` 在 mock 上照样通过 → 假成功 | 部署路径硬闸门 + 日志快检 + 实机反证（同锚换端点必须失败） |
| Pod 重建换 IP → TAA 里的 endpoint 废掉 | `restartPolicy: Always`；横幅打印 IP |
| guest 拉镜像超时 | `TEELLM_POD_READY_TIMEOUT=600`，超时先 dump events |
| Pod 里 teellm-service 死了没人拉起 | 已知限制：PID 1 是保活循环，恢复手段是重跑 `remote --create-pod start`（幂等）。**不复用** `teellm/deploy/start.sh` 当 PID 1——它优先读 `teellm-docker.json` 且不传 `-model`，会静默跑错配置 |
| Pod 重建后 ollama 包/模型丢失（可写层在 guest 内存里，`shared_fs=none`） | 重跑部署即可；这一点与 docker 容器形态的差别要在交付说明里点明 |

## 明确不做（本次范围外）

- `tools/teellm-attest-verify` 这类**独立校验小工具**：可选加固。TAA 自己的启动探针就是生产校验器
  （`InsecureSkipAttestationVerify` 默认 false），实机反证已构成真证明。
- `deploy-llm.sh` 里 `allow_pod_access_to_container` 的 DOCKER 链 bug：teellm 搬进 Pod 后
  TAA 直连 Pod IP，**这条路不再经过 docker0**，该 bug 不在关键路径上，另行处理。
- 178 上手工加的那条 DOCKER 链放行规则（搬完后可清掉）：截至本次交付**仍在**，且已确认**不在关键路径上**
  ——TAA 现在直连 `10.244.0.25:8443`，不经过 docker0。要清掉的话，规则原文是
  `-A DOCKER -s 10.244.0.0/16 -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp --dport 8443 -j ACCEPT`
  （`FORWARD` 链里还有一条同义规则），按整条 spec 删即可，别按行号删。

## 验证状态

- **离线（已完成）**：`bash -n` 全绿；模板渲染出合法 YAML 且注解键恰好 1 个；
  新测试 `tests/deploy_llm_remote_pod_test.sh` 通过，并对三处刻意变异（去掉无条件 `TARGET_POD` 覆盖、
  去掉 `/dev/csv-guest` 闸门、禁掉复用路径）分别给出预期失败；
  `tests/deploy_ollama_preflight_test.sh`、`tests/deploy_docker_transfer_test.sh`、
  `tests/deploy_scan_engine_test.sh` 回归通过；`CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa` 通过。
- **实机（2026-10-15 完成）**：
  - **建与部署**：`remote --create-pod start --model qwen2.5-coder:7b` → 第 02 步建 Pod，
    第 13 步报 `service is serving Hygon hardware evidence (/dev/csv-guest present)`，
    横幅给出 `TAA_LLM_ENDPOINT=https://10.244.0.25:8443`；teellm-service 日志里**没有** mock 回退行。
  - **反证 A（同锚换端点）**：用同一份真 HRK 做**校验型**探针（临时 `cmd/attest-probe`，
    `InsecureSkipAttestationVerify` 关着，未入库）—— 对 `https://10.244.0.25:8443` **通过**，
    对还活着的 docker 容器 `https://172.17.0.2:8443` **失败**在信任链
    （探针报文为 `CEK verification of PEK signature failed`；TAA 自己同期打的是
    `untrusted HRK certificate`，两者都是信任链失败，措辞不同而已）。
  - **端到端**：同一个自制包、同一个 TAA Pod，改端点前后两跑 ——
    改之前 `code=2, reportLen=0`（`LLM 服务不可用，按 fail-closed 策略上报失败`）；
    改之后 `审计完成: passed=false, riskLevel=CRITICAL, totalFindings=4`、`code=1, reportLen=4249`，
    且 `isLLMServiceAvailable` 失败行与 fail-closed 行都不再出现。这一跑（改之前）同时充当差分反证 B：
    包、TAA、HRK 都没换，只有端点不同。
  - **幂等**：重跑 `remote --create-pod start` → 走复用路径（`reusing the running TEE-LLM Pod
    (nothing applied)`），**零次 `kubectl apply`**；Pod 仍是 `10.244.0.25`、
    `creationTimestamp` 仍是 `2026-10-15T04:04:05Z`（VM 未重建）；宿主 kata qemu 进程数与
    `osr` 里的 Pod 数一一对应，仍为 3。
    —— 注意 `ps -eo args= | grep -F qemu` 还会捞到平台自带的两个 `qemu-kvm`
    （`ccs_cipher_app_service`、`mini_dev_app_service`，已运行 42 小时以上），
    所以该命令的原始计数是 5；比"VM 数"要用 `/opt/kata/bin/qemu-system-x86_64` 去数。
  - **未做**：178 上手工加的那条 DOCKER 链放行规则**仍在**（见「明确不做」）。
