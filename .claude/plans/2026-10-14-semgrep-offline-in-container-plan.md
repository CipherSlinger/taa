# 实施计划：Pod 内 semgrep 验证改为生产 argv + 离线有界

日期：2026-10-14
对应 spec：`.claude/specs/2026-10-14-semgrep-offline-in-container-design.md`

## 步骤

1. **`deploy.sh`：加入离线/有界常量**
   - `SEMGREP_OFFLINE_TIMEOUT`（默认 90）
   - `SEMGREP_OFFLINE_PREAMBLE`：远程侧定义 `bounded()`（有 `timeout` 就用，没有就不设界），并导出
     `SEMGREP_SEND_METRICS=off`、`SEMGREP_ENABLE_VERSION_CHECK=0`
   - `SEMGREP_VERIFY_MAX_MEMORY`（默认 1024，与 `DefaultSemgrepMaxMemoryMB` 同步）
   - `SEMGREP_VERIFY_BODY`：验证脚本正文（单引号常量，避免 `sh -lc '...'` 里再套引号）

2. **探测段**：`semgrep --version` 改为 `bounded semgrep --version --disable-version-check`，
   并加离线环境变量。老写法在已装引擎的 Pod 里会永久挂住（实测）。

3. **验证段**：`--validate` 换成生产 argv 扫探针文件，输出用 python3 解析 JSON 判定
   （退出码 0 / `errors` 空 / 文件被读 / 至少 1 个 finding），整段 bounded；失败时打印 semgrep
   自己的输出，并给出已验证的 argv 与「离线 + 有界」的说明后 `exit 1`。

4. **重构控制流**：把「已就绪就 `return 0`」改成「已就绪只跳过注入」，验证每次部署都执行。

5. **`deploy/guest-build/build-semgrep-payload-container.sh`**：wrapper 里写入
   `SEMGREP_SEND_METRICS=off` 与 `SEMGREP_ENABLE_VERSION_CHECK=0` 并 export。

6. **测试 `tests/deploy_scan_engine_test.sh`**：
   - kubectl mock 的判定从 `semgrep --validate` 改为 `semgrep scan`，成功时回
     `OK findings=1 scanned=1 version=1.177.0`，失败时回带 semgrep 原文的 `FAIL … version=unknown`
   - 场景 A 增加断言：已就绪的 Pod **仍然**跑验证
   - 新增场景 D：payload 装得上但引擎跑不起来 → 部署必须非 0 退出、打印 semgrep 的原文与
     「offline and bounded」说明、且**不能**已经替换掉正在运行的 taa

7. **文档**：spec + plan 落在 `.claude/`（`.claude/` 在 .gitignore 里，入库要 `git add -f`）。

8. **提交**：Conventional Commits，英文，不带任何 AI 署名。

## 验收

- `bash -n deploy.sh` 语法通过。
- `bash tests/deploy_scan_engine_test.sh` → PASS（4 个场景）。
- 真实环境已单独实测（Pod 内）：生产 argv rc=0/4s；`--validate` 带全部开关仍卡死；验证脚本原文在
  Pod 内返回 `OK findings=1 scanned=1 version=1.177.0`，耗时 6.5s。
- 未跑完整 `./deploy.sh remote taa`（会替换并重启在跑的 taa），由用户确认后执行。
