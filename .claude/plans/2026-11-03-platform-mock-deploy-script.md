# platform-mock 独立部署脚本 Implementation Plan

**Goal:** 把散落在 `deploy.sh`（本地 docker / 远端 k8s）和 `deploy-fhe.sh`（远端 / `--local`）里的 platform-mock 构建、启停、pid 与就绪探针收敛到 `deploy-platform-mock.sh`，旧脚本改为调用它。

**约束:** 保持每个调用方现有行为不变，尤其是远端 `deploy.sh` 不传 `-state-dir` / `-upload-dir` / `-allow-empty-attestation`，而 `deploy-fhe.sh` 显式传目录、允许空证明、复用已有实例并清空注册状态。TAA 相关的 kubectl Pod IP 发现留在 `deploy.sh`。

---

## File Structure

| 文件 | 责任 |
| --- | --- |
| `deploy-platform-mock.sh`（新建） | 唯一的 platform-mock 生命周期脚本：`local\|remote` × `start\|stop\|restart\|status` |
| `deploy.sh` | 删除内联 mock 构建 / 启动 / 停止 / 状态检查，改为调用新脚本；保留 Pod IP 发现 |
| `deploy-fhe.sh` | 删除 mock 构建 / 上传 / `host_detach` / `wait_for_platform_mock`，改为调用新脚本 |
| `README.md` / `deploy.md` / `tools/platform-mock/README.md` | 记录新脚本与两者的委托关系 |
| `CHANGELOG.md` | 记录抽取、保留的差异与两处行为修正 |

## Design

- 目标与动作作为前两个位置参数：`deploy-platform-mock.sh <local|remote> <start|stop|restart|status>`。
- 构建：默认构建；远端自动 `CGO_ENABLED=0 GOOS=linux`，`--static` 让本地模式也静态构建（`deploy-fhe.sh` 使用）；`--skip-build` 复用现有二进制。
- 启动：先写 pidfile 再启动，`kill -0` 立即失败检测，随后轮询 `GET /api/register/status`；本地停止用 `pkill -x`（脚本自身 argv 含 `--binary PATH`，`pkill -f` 会误杀自己）。
- 参数透传：`--state-dir` / `--upload-dir` 为空时不传，保留二进制自身默认值；`--taa-target` 优先，否则透传 `--taa-pod/--taa-ns/--taa-port`。
- 兼容开关：`--reuse`（已有实例应答则不启动，先探测再决定）、`--reset-register`（就绪后 POST `/api/register/reset`）、`--dry-run`。

## Tasks

- [x] 新增 `deploy-platform-mock.sh`，实现 local/remote 的 start/stop/restart/status、构建、pid、就绪与注册重置。
- [x] `deploy.sh`：本地启动/停止、远端启动/停止全部委托；远端仍自行发现 Pod IP。
- [x] `deploy-fhe.sh`：mock 构建/上传/启动委托，保留 `--static`、state/upload、`--allow-empty-attestation`、`--reuse`、`--reset-register`。
- [x] 删除 `deploy-fhe.sh` 中不再使用的 `host_detach` 和 `wait_for_platform_mock`。
- [x] 文档与 CHANGELOG 更新。
- [x] 验证：`bash -n` 三个脚本；本地 start/status/restart/stop；`--skip-build` 与 `--reuse` 同 pid；
      `deploy-fhe.sh platform-mock -n --local` 与 local/remote `--dry-run`。
