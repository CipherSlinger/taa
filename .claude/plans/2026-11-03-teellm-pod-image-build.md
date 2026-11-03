# deploy-llm.sh：本地最新 teellm-service 打进镜像，并按参考脚本创建/删除 Pod

日期：2026-11-03
状态：已实现

## 背景

`deploy-llm.sh --create-pod start` 在 Pod 不存在时原本只做一件事：去 registry 里挑一个
**最新的日期 tag** 当镜像。Pod 里跑的是「上次有人推送的镜像」，不是当前工作树编出来的服务 ——
改了 `teellm/` 之后必须先手工跑 `build-teellm-image.sh --push`，忘了就静默跑旧代码。

`/home/wj/teellm-kata-pod/` 下的 `create-teellm-pod.sh` / `delete-teellm-pod.sh` 是已在本机
实测过的另一套做法。两边的差距不只是「有没有构建镜像」：

| 方面 | 参考脚本 | 改动前的 deploy-llm.sh |
|---|---|---|
| 镜像 | 用现成 tag | 用现成 tag（**不构建**） |
| 注解 | runtime-handler + kernel_params + cc_init_data | 只有 cc_init_data，另两条**刻意不加** |
| 调度 | `nodeSelector` | `nodeName` |
| 内存守卫 | 按镜像解包体积 + kata `default_memory` 算 overlay 上限，再核对宿主 `free -m` | 无 |
| 等就绪 | 自轮询 1800s，失败态提前退出 | `kubectl wait --timeout=600s` |
| 删除后 | 数三个数查沙箱残留 | 删掉即结束 |

## 决定

1. **镜像自构建只在创建路径上发生。** 已存在的 Pod 镜像不可变，在那里构建是无人消费的工作。
   构建时**先无条件重编二进制**（`build-teellm-image.sh` 只在二进制缺失时才编，见其第 98 行），
   再用 `LOCAL_BINARY_BUILT` 让同一次运行里后面那次 `build_local_binary` 变成空操作 ——
   装进 Pod 的文件和烤进镜像的文件必须是同一个。
2. **显式 `TEELLM_POD_IMAGE` 不被覆盖**，也不触发构建（操作者点名的镜像不猜）。
   `TEELLM_BUILD_POD_IMAGE=false` 回到「取 registry 最新 tag」的旧行为。
3. **构建出的 tag 是当天日期**，同一 tag 会被重建覆盖，因此该路径强制 `imagePullPolicy: Always`。
4. **三条注解全部保留**，撤回此前「刻意不加前两条」的决定：`runtime-handler` 与
   `runtimeClassName` 同值是平台在跑 Pod 的实际形态；`kernel_params` 的**空值**才会抹掉
   `rdinit=`，非空只是追加，而 guest 内 CDH 拉多 GB 镜像靠的正是这两个超时。
5. **创建前算内存**：`VM = kata default_memory + limits.memory`，`可见 = VM - 1500`，
   overlay 上限 = 可见的一半，`U = 镜像解包 × 1.04`，`NEED = U × 1.15 + 256`。
   `上限 < U` 直接拒绝；`上限 < NEED` 需要 `TEELLM_POD_FORCE_MEMORY=true`。随后核对宿主
   `free -m` 的 available：`VM > avail` 拒绝，`> 80%` 警告。
6. **等就绪用轮询而不是 `kubectl wait`**：后者不能提前退出，`ImagePullBackOff` /
   `CrashLoopBackOff` 已经判定失败还要空等满超时。超时默认 600 → 1800s。
7. **删除按参考脚本**：`--grace-period=30 --wait=false` → 轮询 180s → 强制删除 → 再轮询，
   然后数三个数（kata Pod / `/run/vc/sbs` / qemu-system）检查沙箱残留。Pod 已不存在时
   仍然做残留检查，这是手工清理孤儿之后唯一的复核入口。

## 不做的事

- 不动 `deploy.sh` 的 TAA Pod 路径（另一套清单、另一套创建逻辑）。
- 不改 `TEELLM_POD_CPU=8`：参考脚本给 2 是本机 CPU requests 已 91% 的运维建议，不是创建语义。
- 不引入 jq，不做 hostPort 映射（teellm 走 Pod IP:8443）。

## 验证

- `bash -n deploy-llm.sh`
- `tests/deploy_llm_remote_pod_test.sh`：新增镜像构建接线、三条注解、内存守卫两个负例、
  `pod-down` 的宽限期/轮询/残留检查断言；`TEELLM_POD_IMAGE` 与
  `TEELLM_BUILD_POD_IMAGE=false` 两条旁路各自成例。
- `tests/deploy_taa_remote_pod_test.sh`、`tests/deploy_scan_engine_test.sh` 无回归。
- 真机（172.16.10.178）验证留待单独确认执行：一次创建即一台宿主实占的机密 VM。
