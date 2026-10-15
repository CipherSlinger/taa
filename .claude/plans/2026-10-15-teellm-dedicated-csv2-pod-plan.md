# 计划：teellm 落进专用 Kata CSV2 Pod

对应设计：`.claude/specs/2026-10-15-teellm-dedicated-csv2-pod-design.md`

## 步骤

1. `deploy/manifest/k8s/teellm-pod.yaml.tmpl`：带注释模板，占位符
   `__POD_NAME__ __NAMESPACE__ __NODE_NAME__ __IMAGE__ __RUNTIME_CLASS__ __CPU__ __MEMORY__ __CC_INIT_DATA__`；
   字面 `name`、单一注解 `cc_init_data`、`runtimeClassName: kata-qemu-csv2`、`nodeName`、
   `restartPolicy: Always`、`requests == limits`、保活 `command/args` 覆盖 ENTRYPOINT。
2. `deploy-llm.sh` 变量：`TEELLM_POD_*` 一整套 + `CREATE_POD` + `TEMP_POD_MANIFEST`；
   在 `TARGET_POD` 默认赋值前捕获 `TARGET_POD_WAS_SET`。
3. `deploy-llm.sh` 函数：`derive_cc_init_data()`（取不到即致命）、`teellm_pod_ip()`、
   `pod_up()`（复用优先、绝不 apply、`/dev/csv-guest` 硬闸门）、`pod_down()`（优雅→force）。
4. `deploy-llm.sh` 参数与动作：`--create-pod`、`pod-down`；归一化块里拒绝非 remote 模式、
   拒绝与显式 `TARGET_POD` 冲突、否则无条件覆盖 `TARGET_POD`。
5. `deploy-llm.sh` `deploy_remote()`：`pod_up` 插在连通性检查与 `check_remote_pod` 之间；
   create 路径证书缺失改为致命；probe 通过后加快检（必须有硬件提供者日志、不得有 mock 回退日志）。
6. `deploy-llm.sh` 横幅 + `usage()`：打印 `TAA_LLM_ENDPOINT=https://<pod-ip>:8443`；
   补动作、选项、环境变量与 cc_init_data 说明。
7. `tests/deploy_llm_remote_pod_test.sh`：一次性仓库根 + mock ssh/scp/kubectl，六个场景（见设计文档）。
8. `CHANGELOG.md`：`## [Unreleased]` → `### Added` 加一条。
9. `.claude/specs/` 与 `.claude/plans/`：本设计/计划的持久副本，`git add -f`（`.claude/` 在 `.gitignore` 里）。
10. `bash -n` 全部脚本；跑新测试与三个既有部署测试；`go build` + 定向 `go test`。
11. 提交（Conventional Commits，英文，无 AI 署名）。

## 验证（离线，已完成）

- 三处刻意变异各自触发预期失败：去掉无条件 `TARGET_POD` 覆盖 / 去掉 `/dev/csv-guest` 闸门 /
  禁掉复用路径；脚本随后从备份还原并复验。
- `tests/deploy_ollama_preflight_test.sh`、`tests/deploy_docker_transfer_test.sh`、
  `tests/deploy_scan_engine_test.sh` 通过（最后一个需要在本 worktree 里补上 teellm 源码副本与 `go.work`）。
- `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa` 通过；
  `go test ./cmd/... ./internal/... ./pkg/... ./tools/...` 只有已知的 controller 并发 flake（重跑通过）。

## 验证（实机 178，待做）

1. 预检（只读）：`kubectl get runtimeclass`、`free -g`（加第三台 VM 后仍应余 ≥85GB）、
   cc_init_data 派生能得到非空值。
2. 模板渲染（离线）：渲染结果里 `runtime-handler`/`kernel_params` 出现次数必须为 **0**。
3. Pod 起来：`kubectl -n osr exec taa-teellm -- ls -l /dev/csv-guest` → `crw-rw-rw- 10,257`。
4. 部署：`./deploy-llm.sh remote --create-pod start --model ...`；日志里必须出现硬件提供者，
   **不得**出现 mock 回退。
5. 反证 A（同锚换端点）：用同一个 HRK 连**还活着的 docker 容器** `https://172.17.0.2:8443`
   —— **必须**失败在 `untrusted HRK certificate`。
6. 端到端：按横幅给的 `TAA_LLM_ENDPOINT` 重部署 TAA → 触发导入 → `taa.log` 里
   `untrusted HRK` / `LLM 服务不可用` 两行都不出现，`reportAudit` code ≠ 2。
7. 反证 B（差分）：把端点指回 `https://172.17.0.2:8443` 再跑同样的导入 → 必须回到 code=2。
8. 幂等：重跑 `remote --create-pod start` → 不许再发 `kubectl apply`、Pod IP 不变、
   宿主 `ps -eo args= | grep -F qemu` 计数不变。
9. 收尾：清掉 178 上手工加的那条 DOCKER 链放行规则。
