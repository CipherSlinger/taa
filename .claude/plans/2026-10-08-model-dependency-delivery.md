# 模型依赖下发（TAA 侧）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 TAA 增加一条依赖包下发通道：平台通过 `POST /v1/taa/importDeps` 投递离线 wheelhouse，TAA 按 SM3 内容寻址落盘到 `depsDir/<hash>`、以非 root 方式 `pip --target` 安装、走与模型同策略的 fail-closed 审计，并在后续训练子进程中注入 `TAA_DEPS_DIR` 与前置 `PYTHONPATH`。

**Architecture:** 内容寻址落盘（与既有 `dataDirForHash` 同构）+ 全局单例状态位（与 `ModelImported` 同构）+ 复用既有下载/解密/审计/上报四条能力。依赖目录放在 `ModelDir` **同级**，从而规避 `ModelDir` 被审计扫描、被折进模型 SM3、被 `cleanDirContents` 清空、被 `ExtractArchiveToDir` 整体删除这四个冲突。依赖是**可选**的：未导入时不注入任何环境变量，既有流程逐字节不变。

**Tech Stack:** Go 1.x（标准库 `net/http`、`os/exec`、`crypto` 封装 `pkg/crypto`）、`pip3`（离线 `--no-index --target` 安装）、既有 `internal/codeaudit` 审计引擎、`go test`。

**依据 spec:** `.claude/specs/2026-10-08-model-dependency-delivery-design.md`

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

**已知遗留（不在本计划范围）**：
- `reportRes` 的 `deps_checksum` 在 `internal/coordinator/flow_training.go:219` 这条备用执行路径上传
  `nil`——该路径没有依赖概念。理由与影响记在 Task 10。
- spec §12 的**端到端测试**（经 platform-mock 上传 wheelhouse → `importDeps` → `importModel` →
  `import` → 训练进程 `import` 到目标包）依赖 spec §11 的第 2 阶段，归入第二份计划。
- spec §5 只要求 `current_op` 新增 `deps_importing`；本计划的流水线另外用了 `decrypting`（沿用模型
  导入的既有取值）与 `deps_installing`（安装阶段），使 `status` 在长耗时的安装期间可区分于下载。
  这是对 spec 的**增量**，不改变 `deps_importing` 的语义。

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
| `api/proto/taa.proto:31-59,74-81,224-231` | 补 `ImportDeps`/`ReportDeps` rpc 与消息、`ReportAuditRequest.scope`、`StatusData` 状态位 |
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

## Task 3: `tryAcquireTaskTyped` 与任务类型扩展

**Files:**
- Modify: `internal/controller/route.go:575-642`
- Test: `internal/controller/deps_import_test.go`（本任务只放并发测试）

- [ ] **Step 1: 写失败测试**

创建 `internal/controller/deps_import_test.go`（后续任务会继续追加）：

```go
package controller

import (
	"net/http"
	"testing"
)

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

var _ = http.StatusOK
```

最后一行 `var _ = http.StatusOK` 只为占位；一旦本文件后续任务用到 `net/http` 就删掉它。

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

// tryAcquireTaskTyped 是 tryAcquireTask 的类型化实现。
// taskType 取值：model_import / data_import / deps_import；
// initialOp 为 "staging" 或 "training" 时一律升级为 training 任务。
func (s *TAAState) tryAcquireTaskTyped(taskID, requestID, initialOp, taskType string) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. 若当前处于训练执行阶段，全局绝对互斥，禁止任何新任务下发
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

	// 3. 检查是否有其他任务正在处理（如正在下载、解密等）
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

- [ ] **Step 4: 运行测试确认通过**

```bash
go test ./internal/controller/ -run 'TestTryAcquireDepsTask|TestDepsImportStillAllowsDataImportPairingRules' -v
go test ./internal/controller/ -run 'TestConcurren|TestStateStore' -v
```

期望：新增测试 PASS，且**既有并发与状态存储测试全部保持 PASS**（这是本任务的关键回归点——
原签名的语义必须逐字保持）。

- [ ] **Step 5: 提交**

```bash
git add internal/controller/route.go internal/controller/deps_import_test.go
git commit -m "refactor(controller): add typed task acquisition for deps imports"
```

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
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
```

若 `internal/resource` 中已存在同名的 `writeFile` 测试辅助函数，复用既有的，不要重复定义。

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

// ValidateWheelhouse 校验解包后的依赖归档结构：必须含 requirements.txt，
// 且至少有一个 .whl。缺失即判定依赖包不合法——离线安装无法补全依赖闭包，
// 因此这里宁可早失败，也不要拖到训练阶段才以 ImportError 暴露。
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
	"os/exec"
	"path/filepath"
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

// TestInstallWheelhouseOfflineEndToEnd 只在 pip3 可用时运行：把 pip 自己下载的
// wheel 当作 wheelhouse 装进 target，验证 --no-index 路径真的能落地文件。
func TestInstallWheelhouseOfflineEndToEnd(t *testing.T) {
	if _, err := exec.LookPath(pipBinary); err != nil {
		t.Skipf("%s not available: %v", pipBinary, err)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	// Use a wheel that ships inside any Python install: download nothing, instead let pip
	// resolve from a wheelhouse we build with `pip download` from the local cache.
	// If the environment has no network and no cache this test skips rather than fails.
	wh := t.TempDir()
	if err := os.WriteFile(filepath.Join(wh, "requirements.txt"), []byte("wheel\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	dl := exec.Command(pipBinary, "download", "wheel", "--dest", wh, "--no-deps", "-q")
	if out, err := dl.CombinedOutput(); err != nil {
		t.Skipf("pip download unavailable (offline environment): %v: %s", err, out)
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := InstallWheelhouse(context.Background(), wh, target); err != nil {
		t.Fatalf("InstallWheelhouse: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "wheel")); err != nil {
		t.Fatalf("expected installed package 'wheel' in target: %v", err)
	}
}
```

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

// pipBinary is a variable so tests can substitute a stub without needing a real pip.
var pipBinary = "pip3"

// InstallWheelhouse 以非 root、零网络方式把离线 wheelhouse 安装到 target 目录。
//
// 使用 --target 而非手工解压 wheel 的原因：需要正确的 .dist-info 元数据（torch 系生态会
// 在运行期查询 importlib.metadata），并正确处理 wheel 的 *.data/ 布局。
// --no-index 强制零网络：依赖闭包不完整时立即失败，而不是拖到训练阶段。
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

// tailLines 截取输出末尾若干行：pip 的失败原因总在最后，而成功路径的输出可能很长。
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

期望：前两个用例 PASS，`OfflineEndToEnd` 在无网环境 SKIP（这是设计内的降级，不是失败）。

- [ ] **Step 9: 提交**

```bash
git add internal/resource/deps.go internal/resource/deps_test.go internal/runtime/deps.go internal/runtime/deps_test.go
git commit -m "feat(deps): add wheelhouse validation and offline pip install"
```

---

## Task 5: `importDeps` handler 与路由

**Files:**
- Create: `internal/controller/deps_import.go`（本任务只放请求体与 handler）
- Modify: `internal/controller/router.go:9-22`
- Test: `internal/controller/deps_import_test.go`（追加）

- [ ] **Step 1: 写失败测试**

追加到 `internal/controller/deps_import_test.go`：

```go
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

`postJSON` 若 `internal/controller` 测试中已有等价辅助函数（例如 `handler_test.go` 里的
同名函数），复用它，不要重复定义。

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/controller/ -run TestImportDeps -v
```

期望：前两个用例 404（路由未注册），第三个 200 而非 405。

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

// depsImportRequest 是 /v1/taa/importDeps 的请求体。
// 刻意不复用 importRequest：其 publicKey 与 runtimeConfig 对依赖包没有意义，
// 接受它们只会制造「传了但不生效」的歧义。
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

	// resourceUrl 必须显式给出：依赖是内容寻址的，允许为空复用会让「当前生效的是哪一套依赖」
	// 不可推断。
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
// processImportedDeps 的最小版本。完整流水线见 Task 6。
func (s *TAAState) processImportedDeps(req depsImportRequest, phase int, ciphertextPath string) {
	defer os.Remove(ciphertextPath)
	s.setCurrentOp("idle")
}
```

`deps_import.go` 的 import 块需含 `"os"`。

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
func TestProcessImportedDepsRejectsArchiveWithoutWheel(t *testing.T) {
	state, _ := setupTestState(t)

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
func TestProcessImportedDepsRejectsZipSlip(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })
	depsInstallFunc = func(wheelhouse, target string) error { return os.MkdirAll(target, 0o755) }

	outside := filepath.Join(t.TempDir(), "pwned")
	archive := buildTestArchive(t, map[string]string{
		"requirements.txt":                         "torch\n",
		"a-1.0-py3-none-any.whl":                   "x",
		"../../../../../../../../" + filepath.Base(outside): "pwned",
	})

	req := depsImportRequest{ResourceURL: "http://x/evil.tar.gz", RequestID: "req-z", TaskID: "task-z"}
	state.processImportedDeps(req, 1, archive)

	if state.DepsImported {
		t.Fatal("DepsImported = true for an archive with a path-traversal entry")
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("zip-slip escaped the wheelhouse: %s exists", outside)
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

`deps_import_test.go` 的 import 块需要补：`"archive/tar"`、`"compress/gzip"`、`"encoding/json"`、
`"os"`、`"path/filepath"`、`"sort"`。

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

	// 解包到临时 wheelhouse：外层归档的解包需要 zip-slip 防护，因此不能直接写进
	// 内容寻址目录；wheel 自身的展开交给 pip。
	wheelhouse, err := os.MkdirTemp("", "taa-deps-wh-*")
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
		_ = os.RemoveAll(depsDir)
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("安装依赖包失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "importDeps", "依赖包安装完成: %s", depsDir)

	if !s.auditAndReportDeps(req, depsDir) {
		_ = os.RemoveAll(depsDir)
		s.clearDepsState()
		s.setCurrentOp("idle")
		return
	}

	if err := writeAuditMarker(depsDir); err != nil {
		_ = os.RemoveAll(depsDir)
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
保护范围与预期不符。这正是 Step 4 用 `os.MkdirTemp` 而非 `depsDir` 的原因。

同文件新增三个小辅助：

```go
const depsAuditMarker = ".taa_audit_ok"

func auditMarkerExists(depsDir string) bool {
	info, err := os.Stat(filepath.Join(depsDir, depsAuditMarker))
	return err == nil && !info.IsDir()
}

func writeAuditMarker(depsDir string) error {
	return os.WriteFile(filepath.Join(depsDir, depsAuditMarker), []byte("audited\n"), 0o644)
}
```

`reportDepsSuccess` / `reportDepsFailure` 在本任务内先直接调用 Task 7 会实现的
`s.reportDepsAsync`：

```go
func (s *TAAState) reportDepsSuccess(req depsImportRequest, checksum map[string]any) {
	s.reportDepsAsync(req.RequestID, req.TaskID, 0, "依赖包导入成功", checksum)
}

func (s *TAAState) reportDepsFailure(req depsImportRequest, reason string) {
	s.Logs.Add(LogError, "importDeps", "依赖包导入失败: %s", reason)
	s.reportDepsAsync(req.RequestID, req.TaskID, 1, reason)
}
```

`auditAndReportDeps` 由 Task 8 实现；本任务先给出**最小可用版本**，使包可编译且
`Security.ScanEnabled=false` 时短路放行：

```go
// auditAndReportDeps 对安装后的依赖目录执行 fail-closed 审计（Task 8 补全上报与 scope）。
func (s *TAAState) auditAndReportDeps(req depsImportRequest, depsDir string) bool {
	if !s.Security.ScanEnabled {
		s.Logs.Add(LogInfo, "audit", "安全扫描未启用，跳过依赖包审计")
		return true
	}
	return s.runDepsAudit(req, depsDir)
}
```

`runDepsAudit` 由 Task 8 实现，本任务给一个返回 `true` 的最小版本。

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

## Task 7: `reportDeps` 平台回调

**Files:**
- Modify: `internal/platform/reporter.go:11-17`、`:46-53`、`:191+`
- Modify: `internal/controller/report.go`
- Modify: `internal/controller/deps_import.go`（`reportDepsAsync`）
- Test: `internal/platform/reporter_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `internal/platform/reporter_test.go`（若文件名不同，用该目录下既有的 reporter 测试文件）：

```go
func TestReportDepsPostsScopedPayload(t *testing.T) {
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

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/platform/ -run 'TestReportDeps|TestReportAuditScoped' -v
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

在 `internal/controller/deps_import.go` 中，仿照 `model_reporting.go` 的
`reportModelImportAsync` 形状实现（先起一个 `import_model_report` 风格的日志标签
`"importDeps"`）：

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
git add internal/platform/reporter.go internal/platform/reporter_test.go internal/controller/report.go internal/controller/deps_import.go
git commit -m "feat(deps): report dependency import results and scoped audits"
```

---

## Task 8: 依赖审计（fail-closed，scope=deps）

**Files:**
- Create: `internal/controller/deps_audit.go`
- Modify: `internal/controller/deps_import.go`（删掉 Task 6 的最小 `runDepsAudit`）
- Test: `internal/controller/deps_import_test.go`（追加）

- [ ] **Step 1: 写失败测试**

追加到 `internal/controller/deps_import_test.go`：

```go
// TestDepsAuditFailureRemovesDirAndClearsState 验证 fail-closed：审计未通过时不留下
// 任何依赖目录，且状态位被回滚。
func TestDepsAuditFailureRemovesDirAndClearsState(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true

	origAudit := depsAuditFunc
	t.Cleanup(func() { depsAuditFunc = origAudit })
	depsAuditFunc = func(dir string) (bool, string) { return false, "命中 HIGH 风险规则" }

	depsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(depsDir, "pkg.py"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if passed := state.runDepsAudit(depsImportRequest{RequestID: "r", TaskID: "t"}, depsDir); passed {
		t.Fatal("runDepsAudit returned true for a failing audit")
	}
	if _, err := os.Stat(depsDir); !os.IsNotExist(err) {
		t.Fatalf("deps dir still present after a failed audit: %v", err)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/controller/ -run TestDepsAuditFailureRemovesDirAndClearsState -v
```

期望：编译失败 `depsAuditFunc undefined`。

- [ ] **Step 3: 实现依赖审计**

创建 `internal/controller/deps_audit.go`：

```go
package controller

import (
	"context"
	"os"
)

// depsAuditFunc 是依赖审计的可替换钩子，签名返回 (passed, summary)。
// 生产路径指向真实引擎；单测替换它以避开 Semgrep / LLM 依赖。
var depsAuditFunc func(dir string) (bool, string)

// runDepsAudit 对安装后的依赖目录执行与模型代码同引擎、同策略的审计，并以
// scope="deps" 上报。审计未通过时物理清除依赖目录——fail-closed 语义下，
// 被拒的依赖不应留在磁盘上。
// 审计状态位的置位/清位沿用 startModelAuditAsync（import_processing.go:585）的既有写法：
// startModelAuditAsync 在锁内写四个字段，审计体在首尾用 setCurrentAuditOp 切换 current_op。
func (s *TAAState) runDepsAudit(req depsImportRequest, depsDir string) bool {
	// Test hook: when set it fully replaces the real engine, so unit tests never
	// invoke Semgrep or the LLM verifier.
	if depsAuditFunc != nil {
		passed, summary := depsAuditFunc(depsDir)
		code := 0
		if !passed {
			code = 1
			_ = os.RemoveAll(depsDir)
		}
		s.reportAuditScopedAsync(req.RequestID, req.TaskID, code, summary, "", "deps")
		return passed
	}

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

`depsAuditFunc` 只在单测中赋值，生产路径下为 `nil`，因此上面的判断在生产中恒不成立。
它存在的唯一理由是让 `TestDepsAuditFailureRemovesDirAndClearsState` 能在不引入 Semgrep 与
LLM 依赖的前提下验证 fail-closed 的清除行为。

**清理语义的差异（有意为之）**：模型审计失败时调用 `cleanDirContents(dir)`——只清空内容、
保留目录本身，因为 `ModelDir` 是长期存在的固定路径。依赖目录是**内容寻址**的
`depsDir/<sm3>`，整目录即该版本的完整身份，因此这里用 `os.RemoveAll(depsDir)` 整体删除，
与 spec §6「不留半成品目录」一致。

`internal/controller/import_processing.go` 中新增 `reportAuditScopedAsync`：把既有
`reportAuditAsync`（`:718`）的实现体抽出为带 scope 的版本，原函数委托：

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

`deps_import.go` 中 Task 6 添加的返回 `true` 的最小 `runDepsAudit` 必须删除，避免重复定义
导致编译失败。

- [ ] **Step 5: 运行测试确认通过**

```bash
go test ./internal/controller/ -run 'TestDepsAudit|TestProcessImportedDeps|TestAudit' -v
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
go test ./internal/controller/ -run 'TestApplyDepsEnv|TestTrainingEnvUnchangedWithoutDeps|TestExecuteTraining' -v
```

期望：全部 PASS。

- [ ] **Step 8: 提交**

```bash
git add internal/controller/deps_env.go internal/controller/deps_env_test.go internal/controller/import_processing.go
git commit -m "feat(deps): inject TAA_DEPS_DIR and prepend PYTHONPATH for training"
```

---

## Task 10: `deps_checksum` 进训练报告，`status` 暴露依赖状态

**Files:**
- Modify: `internal/runtime/report.go:42,46,81-88`
- Modify: `internal/controller/import_processing.go:1006-1012`
- Modify: `internal/controller/handler_system.go:57-73`
- Modify: `internal/coordinator/flow_training.go:219`
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

- `internal/coordinator/flow_training.go:219` 同步插入 `nil`：

```go
	report, _ := runtime.BuildTrainingReport(record.TaskID, startedAt, finishedAt, status, exitCode, failureReason, c.phaseState.ModelChecksum(), c.phaseState.DataChecksum(), nil, trainResult, auditSection)
```

该执行路径没有依赖概念，因此传 `nil`——其结果是该路径的报告不含 `deps_checksum`，
属于本计划内的已知遗留，已在文件头「已知遗留」一节记录。

- `internal/controller/import_processing.go:1011` 的委托函数 `buildTrainingReport`
  参数表同样插入 `depsChecksum map[string]any,` 并透传。

- [ ] **Step 4: 训练路径传入真实 checksum**

`internal/controller/import_processing.go` 的 `buildAndSaveTrainingReport`（`:952`）与
`reportTrainingFailureFromResult`（`:909`）调用 `buildTrainingReport` 时，在
`dataChecksum` 位置之后插入 `s.getDepsChecksum()`。

- [ ] **Step 5: 运行测试确认通过**

```bash
go build ./... && go test ./internal/runtime/ ./internal/controller/ ./internal/coordinator/ -count=1
```

期望：全部 PASS。

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
go build -o bin/taa ./cmd/taa && go build -o bin/platform-mock ./tools/platform-mock/cmd/platform-mock && go test ./... -count=1
```

期望：两个二进制构建成功，全部测试 PASS。

- [ ] **Step 11: 提交**

```bash
git add internal/runtime/report.go internal/runtime/report_test.go internal/coordinator/flow_training.go internal/controller/import_processing.go internal/controller/handler_system.go internal/controller/deps_import_test.go
git commit -m "feat(deps): expose deps checksum in training report and status"
```

---

## Task 11: 同步 `api/proto/taa.proto`（设计稿一致性）

**Files:**
- Modify: `api/proto/taa.proto:31-34`、`:56-59`、`:74-81`、`:224-231`

spec §8 末条要求 proto 设计稿与实际 HTTP 接口保持一致。该文件**没有 gRPC 实现**
（`cmd/` 下只有 `main.go`），因此本任务只改文档、不加代码、不加测试——它的价值是让
读 proto 的人不会以为依赖下发不存在。

- [ ] **Step 1: 新增两个 rpc**

`service TaaService` 中（`:34` 的 `ImportModel` 之后、`:56` 的 `ReportModelImport` 之后）各插一行：

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

`message ReportAuditRequest`（`:224-231`）末尾新增：

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
