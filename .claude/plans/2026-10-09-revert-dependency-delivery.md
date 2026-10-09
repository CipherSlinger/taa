# 撤销依赖下发能力与合并代码审计

**日期**：2026-10-09
**触发**：`/v1/taa/importDeps` 不再需要。

## 1. 决定（本次改动的事实）

| 项 | 决定 |
| :--- | :--- |
| 撤销范围 | **整套依赖下发能力全删**：路由、handler、流水线、依赖状态、`/status` 字段、训练环境 `PYTHONPATH` 注入、wheelhouse 校验、离线安装器、配置项、文档、测试。训练环境恢复为完全不注入依赖，不留死代码 |
| 合并审计 | **回退到单根模型审计**：仅审计 `Security.ModelDir`，撤销多根扫描、分根结论与两个触发路径的改接 |
| 撤销方式 | **前向删除新提交**，保留完整历史。不用 `git revert`：特性的 126 个提交与无关工作（`aa6ec0a` 温度、`7ddd6e6` 全量校验 finding、`18fca70` 部署、两个 teellm submodule bump、`ee95877`/`8f88284` csv2-vm）交织，revert 会连带撤销它们 |
| `scope` 字段 | **删除**。`reportAudit` 不再携带 scope，`ReportAuditScoped` 合并回 `ReportAudit`；platform-mock 同步丢弃校验与拒绝文案。已接受代价：若平台已解析 scope，需平台侧同步变更 |
| `depsImported` / `depsHash` | **删除**（状态响应、内部状态字段、密封 blob 键） |
| `DepsDir` / `GetDepsDir` | **删除配置项**（结构字段、`GetDepsDir()`、`validateDepsDirPlacement`、启动期 mkdir） |
| 分根结论 `roots` | **删除**。`report` 与训练报告的 `codeaudit` 恢复为 `{conclusion, file_reports}` |

## 2. 方法：用基线 diff 分类，而不是逐文件猜

基线取 `deb5b0b`（依赖特性 spec 之前的最后一个提交）。对 `git diff --name-only deb5b0b HEAD` 的每个文件，先判定区间内触及它的提交是否全部属于本次要删的两个特性；只有 `aa6ec0a` 与 `7ddd6e6` 两个无关提交落在其中。据此得到三类：

- **整体还原到 `deb5b0b`**（该文件在区间内只被本特性提交改过）——`git checkout deb5b0b -- <path>`，逐字节精确。
- **整体删除**（该文件在 `deb5b0b` 不存在）——含全部 `deps_*.go`、`combined_audit*.go`、`roots*.go`、`multiroot_test.go`、`resource/deps.go`、`runtime/deps.go`、`platform/reporter_test.go`。
- **外科手术**（同时被无关提交改过）：`internal/codeaudit/verifier.go`、`internal/config/config.go`、`internal/config/config_test.go`、`internal/app/taa/app.go`、`internal/app/taa/app_test.go`。

**排除项（一律不碰）**：`deploy-docker.sh`、`teellm`（子模块）、`tools/csv2-vm/csv2-vm.sh`、`.claude/specs/2026-10-08-llm-timeout-layering-design.md`（一份与本次无关的超时/CPU 争用调查，`grep` 确认零依赖相关词）、`internal/codeaudit/llm.go` 与 `llm_test.go`（只被 `aa6ec0a`/`7ddd6e6` 触及）。`README.md` 核验后只差 `llm.temperature` 一行，**无需改动**。

**特别约束**：`internal/codeaudit/verifier.go` 是本检出里唯一与另一并发会话真正重叠的文件（他们持 `aa6ec0a` 的温度改动）。该文件在区间内只被两个提交触及——`aa6ec0a`（保留）与 `401ab6c`（删除），因此按块切除而非整文件还原。完成后 `git diff deb5b0b -- verifier.go` 只剩 `Temperature: cfg.Temperature` 一行。

**顺序**：依赖特性先删（含 `combined_audit.go`），审计回退随后。反向顺序会要求先复活 `.taa_audit_ok` 标记机制再删掉它。因为跨包 API 移除无法拆成多个各自可编译的提交，代码部分是一个原子提交。

## 3. 验证

```
go build ./cmd/taa                  # OK
go build ./tools/platform-mock/cmd/platform-mock   # OK
go vet ./cmd/... ./internal/... ./pkg/... ./tools/...   # 无输出
```

（`go test ./...` 与本仓不可用：`models/audit/holdout-sources/` 有 248 个伪装成 `.go` 的 semgrep YAML 且无 `go.mod`。一律按包、`-p 1`。）

| 包 | 结果 |
| :--- | :--- |
| `internal/codeaudit`（含 `cpg`） | ok |
| `internal/config` | ok |
| `internal/app/taa` | ok |
| `internal/platform` | ok |
| `internal/runtime` | ok |
| `internal/resource` | ok |
| `internal/store` | ok |
| `internal/attestation` | ok |
| `internal/coordinator` | ok |
| `pkg/*`（crypto, csvattest, errors, filetree, logger, utils） | ok |
| `tools/platform-mock/internal` | ok |
| `internal/controller` | **1 个既有 flake**，见下 |

残留检查：对全部已删符号（`ReportAuditScoped`、`GenerateAuditReportForDirs`、`ScanDirectoriesWithLines`、`RootReport`、`ValidateWheelhouse`、`InstallWheelhouse`、`applyDepsEnv`、`GetDepsDir`、`ReportDeps`、`DepsDir`、`DepsChecksum`、`taa-importDeps` 等）在全树 `grep`，零命中；`configs/` 与 platform-mock 静态资源中零命中。

工作树 vs `deb5b0b` 的最终差值只剩有意保留项：温度特性（`app.go`、`app_test.go`、`config.go`、`config_test.go`、`verifier.go`、`llm.go`、`llm_test.go`、`README.md`）与无关工作（`deploy-docker.sh`、`csv2-vm.sh`、`teellm`、那份超时调查）。

### 3.1 `TestConcurrency_DataImportAllowedWhileAuditing` 是既有 flake，非本次引入

现象：`TempDir RemoveAll cleanup: directory not empty`——测试最后一步发起真实 HTTP POST 触发异步导入流水线，未等 goroutine 结束就返回，`t.TempDir()` 清理时目录仍在被写。**断言本身从未失败**。

用 `git archive deb5b0b` 导出基线树（`teellm` 以符号链接接入，不触碰共享 `.git`），两侧各用预编译测试二进制跑 40 次：

| 树 | 失败 |
| :--- | ---: |
| 基线 `deb5b0b` | 3/40 |
| 本次回滚后 | 3/40 |

且 `git diff deb5b0b -- internal/controller/` 为空——控制器包逐字节等同基线。**故与本次改动无关，未修**：修它会改变一个与本次范围无关的测试，且本次不引入它。

## 4. 留在原地、不做迁移的东西

- 已有设备上密封状态 blob 里的 `depsImported` / `depsHash` / `depsChecksum` 键：读取走普通 `json.Unmarshal`，容忍未知键，无需迁移。
- `/opt/taa/model-deps` 目录及其历史 `<sm3>` 子目录：无人读取，无害，不主动删除（删数据是不可逆动作，且不在本次要求内）。
- `.claude/specs/` 与 `.claude/plans/` 中被删的 5 份设计件：仍在 git 历史中可读。
- `internal/coordinator/flow_training.go` 一并还原到基线——这不是"顺手改死代码"，而是编译必需：`BuildTrainingReport` 的 deps 参数随 `internal/runtime/report.go` 一起消失，不改就编不过。
