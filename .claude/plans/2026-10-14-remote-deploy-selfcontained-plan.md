# 计划：远程部署自洽化

对应设计：`.claude/specs/2026-10-14-remote-deploy-selfcontained-design.md`

## 步骤

1. `deploy.sh` 默认变量：`REMOTE_SEMGREP_BUNDLE`、`SEMGREP_BUNDLE`、`SEMGREP_RULES_SOURCE`。
2. `deploy.sh` 函数：
   - `taa_scan_engine_requirements <template>`：解析 `security.codeScanEngine` / `semgrepRulesPath`。
   - `provision_remote_scan_engine <template>`：探活 → 注入引擎/规则 → 验证。
3. `deploy.sh` 步骤插入点：`replacing remote taa, config, and certificates` 之后。
4. `deploy.sh` `usage()`：补 3 条环境变量说明。
5. `deploy-llm.sh`：`allow_pod_access_to_container`，在 remote-docker 容器就绪后调用。
6. `deploy/guest-build/build-semgrep-payload-container.sh`：容器形态 payload 构建配方。
7. `tests/deploy_scan_engine_test.sh`：mock ssh/sshpass/scp/kubectl 跑三个场景。
8. `bash -n` 全部脚本；跑新测试 + `tests/deploy_llm_remote_docker_test.sh` 回归。
9. 提交（Conventional Commits，英文，无 AI 署名）。

## 测试场景（tests/deploy_scan_engine_test.sh）

用 mock `kubectl` 维护「Pod 内状态」文件，探活回答随注入而改变，从而走完真实链路：

- **A 已就绪**：引擎与规则都在 → 不注入、不上传，输出 ready。
- **B 缺引擎和规则 + 宿主有 payload**：先流 payload（记录 stdin 字节数，必须 >0），再流规则，
  再验证通过。
- **C 缺引擎 + 宿主和本地都没有 payload**：快速失败（exit 1）、给出构建/分发解法，
  且**不能**走到「pausing old taa」（即失败发生在动旧进程之前）。
