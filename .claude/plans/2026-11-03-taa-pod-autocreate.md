# TARGET_POD 未设置时由 deploy.sh 创建并接管 TAA Pod Implementation Plan

**Goal:** `deploy.sh` 远端模式在 `TARGET_POD` 未设置时，于远端创建一个专用 Kata CSV2 Pod 并部署进去；后续部署复用它，`stop` 顺带删除它。显式给出 `TARGET_POD` 时行为不变：只部署进该 Pod，不存在则失败，绝不创建或删除。

**约束:** 已存在的 Pod 不重建（Pod 规格不可变，且重建会丢掉 guest 可写层里的数据、密钥与模型，并多出一台常驻加密内存的机密 VM）。不新增 registry tag 解析：镜像由 `TAA_POD_IMAGE` 显式指定。

---

## File Structure

| 文件 | 责任 |
| --- | --- |
| `deploy.sh` | Pod 生命周期：`create_taa_pod` / `ensure_remote_pod` / `delete_taa_pod`、`stop` 分支、`TAA_POD_*` 变量与 usage |
| `deploy/manifest/k8s/taa-pod.yaml.tmpl`（新建） | Pod 清单模板，`__PLACEHOLDER__` 由 `sed` 替换 |
| `tests/deploy_taa_remote_pod_test.sh`（新建） | mock ssh/scp/kubectl 的端到端用例 |
| `README.md` / `deploy.md` / `CHANGELOG.md` | 记录新行为与调参项 |

## Design

- 变量：`TARGET_POD_WAS_SET` 在默认值之前捕获；`TARGET_POD` 推迟到参数解析之后解析——只部署 platform-mock 的运行必须继续用旧目标，不能被指向只有 TAA 部署才会创建的名字。
- Pod 规格：`kata-qemu-csv2`、`nodeName`、`requests == limits`（CSV2 加密内存按 limits 常驻）、ENV 传 `DOCKER_ID`/`PLATFORM_IP`/`CONTRACT_ID`（远端配置会剥掉 `platform` 块）。`TAA_LLM_ENDPOINT` 刻意不做 ENV：ENV 会活过每次部署并压过每次重写的 `taa-config.json`。
- 注解：只复制 `cc_init_data`；`io.containerd.cri.runtime-handler` 会让运行时绕过 `runtimeClassName`，`kernel_params` 必须非空否则会覆盖 `rdinit=`。
- 创建用 `kubectl create` 而非 `apply`：走到这里时已确认 Pod 不存在，`create` 把并发竞争变成明确错误，而不是静默改写不可变规格。
- 就绪后立刻 `touch manual` + 杀进程：镜像 ENTRYPOINT 的 supervisor 已经把旧 `taa` 起起来了，不能让它带着旧二进制跑完 semgrep provisioning 窗口。
- 复用路径对自有 Pod 做 30s Ready 等待，失败直接给 `describe`，而不是在替换完二进制之后才等出一个误导性的 readiness 超时。
- `stop`：先做 SSH 连通性检查；exec 失败（Pod Pending/卡死）只告警，自有 Pod 仍必须删除（其内存常驻宿主）；显式 Pod 只停进程。
- 渲染：`sed` 替换值统一转义 `\ & |`；命名空间为空时按远端 kubectl context 解析。

## Tasks

- [x] `deploy.sh`：变量、`ensure_remote_pod`/`create_taa_pod`/`delete_taa_pod`、`stop` 分支、usage。
- [x] 新增 `deploy/manifest/k8s/taa-pod.yaml.tmpl`。
- [x] 新增 `tests/deploy_taa_remote_pod_test.sh`（创建/复用/显式缺失/缺设备/stop 删除/显式不删除/exec 失败仍删除）。
- [x] 更新 `tests/deploy_scan_engine_test.sh` 的 `pgrep` mock：暂停步骤现在要求进程真的消失。
- [x] 文档：`README.md`、`deploy.md`、`CHANGELOG.md`。

## Verification

- `bash -n deploy.sh`、`bash -n tests/deploy_taa_remote_pod_test.sh`
- `bash tests/deploy_taa_remote_pod_test.sh`
- `bash tests/deploy_scan_engine_test.sh`
- 真机（须先确认，创建 Pod 的成本是一台常驻加密内存的机密 VM）：未设置 `TARGET_POD` 启动→创建；再跑→复用；`stop`→删除；显式 Pod→行为不变。
