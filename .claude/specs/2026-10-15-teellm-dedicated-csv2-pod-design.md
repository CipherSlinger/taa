# teellm 落进专用 Kata CSV2 Pod：让 TAA 收到真证明

日期：2026-10-15
状态：已实现（离线验证完成；178 上的实机验证见文末「验证状态」）

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
- 设备节点由 **guest init** 建（`deploy/guest-build/taa-init.sh:119` 的 `mknod`），不是容器建的；
  所以「含 `/dev/csv-guest` 的 Pod」= 本机上一个 CSV2 Pod，没有额外魔法。
- guest 规格：**guest RAM = kata `default_memory` 23552M + `limits.memory`**；
  **vCPU = `default_vcpus` 1 + `limits.cpu`**。CSV2 加密内存**开机即 100% 实占**。
- 宿主：251GB / 64 核，可用 ~123GB。
- TAA Pod 里 `/root/taa/certs/hrk.cert` 与 `deploy/certs/hrk.cert` 同 md5 `d180de08…`（真 HRK），
  且 `internal/config/config.go:417-453` 把它作为**默认锚** → TAA 侧不需要改任何配置。
- `deploy-llm.sh` 的 `remote` 模式**已经是完整的 Pod 部署路径**（`deploy_remote()`：流式传 ollama、
  起 ollama、`kubectl cp` teellm-service + 配置 + 证书、起服务、`-probe` 探活），
  但它**从不创建 Pod**，Pod 路径上也**没有任何 `/dev/csv-guest` 检查**（那条只在 docker 路径上）。

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
- `resources.requests == limits`（Guaranteed，账要实）：默认 `cpu: 8` / `memory: 8Gi`
  → VM ≈ 23552 + 8192 = **31.5GiB 常驻**。

### `deploy-llm.sh` 改动

1. **变量**：`TEELLM_POD_NAME=taa-teellm`、`TEELLM_POD_IMAGE`、`TEELLM_POD_NODE=hygon-master`、
   `TEELLM_POD_RUNTIME_CLASS=kata-qemu-csv2`、`TEELLM_POD_CPU=8`、`TEELLM_POD_MEMORY=8Gi`、
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
| 三台 100% 常驻 CSV2 VM 造成宿主 OOM | `requests == limits`；默认 8Gi 而非 16Gi；预检复核 `free -g`；`TEELLM_POD_MEMORY` 可调小 |
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
- 178 上手工加的那条 DOCKER 链放行规则：同上，搬完后可清掉。

## 验证状态

- **离线（已完成）**：`bash -n` 全绿；模板渲染出合法 YAML 且注解键恰好 1 个；
  新测试 `tests/deploy_llm_remote_pod_test.sh` 通过，并对三处刻意变异（去掉无条件 `TARGET_POD` 覆盖、
  去掉 `/dev/csv-guest` 闸门、禁掉复用路径）分别给出预期失败；
  `tests/deploy_ollama_preflight_test.sh`、`tests/deploy_docker_transfer_test.sh`、
  `tests/deploy_scan_engine_test.sh` 回归通过；`CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa` 通过。
- **实机（待做）**：`remote --create-pod start`、同锚反证（连还活着的 docker 容器必须失败在
  `untrusted HRK certificate`）、端到端审计 `code=2 → code≠2`、差分反证、幂等复核（不发第二次 apply、
  Pod IP 不变、宿主 qemu 进程数不变），以及清理 178 上手工加的那条 DOCKER 链规则。
