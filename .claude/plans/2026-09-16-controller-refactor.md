# Controller 架构分层与功能域重构实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 `internal/controller` 巨石包按功能域与分层架构彻底解耦为 `store`, `platform`, `resource`, `runtime`, `coordinator`, `controller` 6 个职责单一、单向依赖且完全自解释的模块，消除上帝对象并保证既有测试 100% 通过。

**Architecture:** 系统解耦为四层：底层为独立的四项基础功能域（`internal/store` 状态密封持久化、`internal/platform` 管控通信客户端、`internal/resource` 密态资源与安全解压、`internal/runtime` 训练进程与观测）；中层为 `internal/coordinator` 负责业务全流程编排与任务互斥；上层为 `internal/controller` 纯 HTTP 控制层；顶层为 `internal/app/taa` 负责生命周期组装。模块间单向无环调用。

**Tech Stack:** Go 1.26, 国密 SM2/SM3/SM4 (teecrypto), Linux 进程树与命名空间控制, HTTP ServeMux, 标准库 context/sync/exec.

---

### Task 1: 提取独立状态密封持久化包 `internal/store`

**Files:**
- Create: `internal/store/sealed_state.go`
- Create: `internal/store/sealed_state_test.go`
- Modify: `internal/controller/state_store.go` (复用/桥接 `internal/store`)
- Test: `internal/store/sealed_state_test.go`

- [ ] **Step 1: 编写 `internal/store` 独立测试套件**

创建 `internal/store/sealed_state_test.go`：
```go
package store_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
)

func TestStateStore_SealAndUnseal(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.sealed")
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}

	st, err := store.NewStateStore(statePath, key)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}

	state := &store.PersistentState{
		Version:         store.DefaultStateVersion,
		StateSeq:        1,
		IncarnationID:   "inc-001",
		CurrentPhase:    1,
		ModelImported:   true,
		TrainingRunning: false,
		UpdatedAt:       time.Now().UTC(),
	}

	if err := st.SealState(state); err != nil {
		t.Fatalf("seal state: %v", err)
	}

	recovered, err := st.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if recovered.StateSeq != 1 || recovered.IncarnationID != "inc-001" {
		t.Fatalf("state mismatch: got %+v", recovered)
	}
}
```

- [ ] **Step 2: 运行测试验证其因包不存在而失败**

Run: `/usr/local/go/bin/go test ./internal/store/...`
Expected: FAIL (package not found or build failure)

- [ ] **Step 3: 实现 `internal/store/sealed_state.go`**

编写 `internal/store/sealed_state.go`，将 `PersistentState`、`ActiveTaskSnapshot`、`StateStore`、`DeriveSealingKey`、`DetectAndHandleKeyDrift` 等从 `internal/controller/state_store.go` 提取为独立包，并在 `internal/controller/state_store.go` 中保留类型别名（Type Alias）以保证现有 controller 与 app 无缝兼容。

- [ ] **Step 4: 运行 `internal/store` 与 `internal/controller` 测试验证通过**

Run: `/usr/local/go/bin/go test -v ./internal/store/... && /usr/local/go/bin/go test -run "TestStateStore" ./internal/controller/...`
Expected: PASS

- [ ] **Step 5: 提交修改**

```bash
git add internal/store internal/controller/state_store.go
git commit -m "refactor(store): 提取独立的状态密封持久化包 internal/store"
```

---

### Task 2: 提取统一管控平台通信客户端 `internal/platform`

**Files:**
- Create: `internal/platform/client.go`
- Create: `internal/platform/register.go`
- Create: `internal/platform/reporter.go`
- Create: `internal/platform/client_test.go`
- Modify: `internal/controller/platform_client.go`, `internal/controller/register.go`, `internal/controller/report.go`
- Test: `internal/platform/client_test.go`

- [ ] **Step 1: 编写 `internal/platform` 测试用例**

创建 `internal/platform/client_test.go`，测试统一 HTTP Client 的 POST 请求、注册通知 `NoticeRegister`、参数规整校验以及事件上报。

- [ ] **Step 2: 运行测试验证失败**

Run: `/usr/local/go/bin/go test ./internal/platform/...`
Expected: FAIL (package does not exist)

- [ ] **Step 3: 实现 `internal/platform` 核心代码**

- `client.go`: 统一网络连接池、URL 拼接与请求 Dump 日志。
- `register.go`: 实例注册向 `/v1/taa/register` 上报公钥与 TEE 报告。
- `reporter.go`: 封装 `/v1/taa/reportModelImport`、`/v1/taa/reportAudit`、`/v1/taa/reportRes`、`/v1/taa/modelLog`、`/v1/taa/reportProgress`。
- 在 `internal/controller` 中的旧文件桥接调用 `platform` 包，保持既有单测 100% 绿灯。

- [ ] **Step 4: 运行测试验证通过**

Run: `/usr/local/go/bin/go test -v ./internal/platform/... && /usr/local/go/bin/go test -run "TestPostRegister|TestReport" ./internal/controller/...`
Expected: PASS

- [ ] **Step 5: 提交修改**

```bash
git add internal/platform internal/controller/platform_client.go internal/controller/register.go internal/controller/report.go
git commit -m "refactor(platform): 统一管控平台网络通信客户端至 internal/platform"
```

---

### Task 3: 提取密态资源与安全解压包 `internal/resource`

**Files:**
- Create: `internal/resource/downloader.go`
- Create: `internal/resource/envelope.go`
- Create: `internal/resource/archive.go`
- Create: `internal/resource/checksum.go`
- Create: `internal/resource/index_store.go`
- Create: `internal/resource/archive_test.go`
- Create: `internal/resource/checksum_test.go`
- Create: `internal/resource/index_store_test.go`
- Modify: `internal/controller/import_index.go`, `internal/controller/import_helpers.go`
- Test: `internal/resource/...`

- [ ] **Step 1: 编写 `internal/resource` 测试用例**

在 `internal/resource/archive_test.go`、`checksum_test.go`、`index_store_test.go` 中编写针对流式下载配额、Zip-Slip 路径逃逸防御、Zip-Bomb 防御、SM3 文件哈希计算以及 `ImportIndexStore` 的 `.bak` 容灾与 `Purge` 逻辑测试。

- [ ] **Step 2: 运行测试验证失败**

Run: `/usr/local/go/bin/go test ./internal/resource/...`
Expected: FAIL

- [ ] **Step 3: 实现 `internal/resource` 各组件**

- `downloader.go`: 实现 `DownloadToTempFile(resourceURL string, maxSize int64) (path string, size int64, err error)`。
- `envelope.go`: 实现 SM2 解密密态资源信封与导出结果加密。
- `archive.go`: 移植并优化 `ExtractArchiveFile`, `ExtractZipArchive`, `ExtractTarStream`, 防御 Zip-Bomb 与 Zip-Slip。
- `checksum.go`: 移植 `HashFileSM3`, `BuildDirectoryChecksum`。
- `index_store.go`: 移植 `ImportIndexStore`（原 `import_index.go`）。
- `internal/controller` 桥接引用 `internal/resource`。

- [ ] **Step 4: 运行测试验证全部通过**

Run: `/usr/local/go/bin/go test -v ./internal/resource/... && /usr/local/go/bin/go test -run "TestImportIndex|TestIsArchive|TestBuildDirectoryChecksum" ./internal/controller/...`
Expected: PASS

- [ ] **Step 5: 提交修改**

```bash
git add internal/resource internal/controller/import_index.go internal/controller/import_helpers.go
git commit -m "refactor(resource): 提取密态资源处理、解包防御与索引引擎至 internal/resource"
```

---

### Task 4: 提取训练执行与观测层 `internal/runtime`

**Files:**
- Create: `internal/runtime/config.go`
- Create: `internal/runtime/process.go`
- Create: `internal/runtime/executor.go`
- Create: `internal/runtime/telemetry.go`
- Create: `internal/runtime/report.go`
- Create: `internal/runtime/config_test.go`
- Create: `internal/runtime/process_test.go`
- Create: `internal/runtime/telemetry_test.go`
- Create: `internal/runtime/report_test.go`
- Modify: `internal/controller/training_control.go`, `internal/controller/model_reporting.go`
- Test: `internal/runtime/...`

- [ ] **Step 1: 编写 `internal/runtime` 测试用例**

编写针对 `runtimeConfig` 宏解析与环境注入、进程组中止 `KillProcessGroup`、JSONL 日志增量解析 `JSONLLogReader`、进度快照读取 `ReadLatestProgress`、Schema 1.0 报告生成的测试。

- [ ] **Step 2: 运行测试验证失败**

Run: `/usr/local/go/bin/go test ./internal/runtime/...`
Expected: FAIL

- [ ] **Step 3: 实现 `internal/runtime` 核心逻辑**

- `config.go`: 解析 JSON 格式 `runtimeConfig`，进行 `{MODEL_DIR}`, `{INPUT_DIR}`, `{OUTPUT_DIR}` 宏替换。
- `process.go`: `TrainingControl` 与 `KillProcessGroup`。
- `executor.go`: 命令启动与进程组绑定。
- `telemetry.go`: 读取本地 `train.jsonl` 与 `progress.json`。
- `report.go`: `BuildTrainingReport`, `BuildCrashFailureReport`。
- `internal/controller` 桥接引用。

- [ ] **Step 4: 运行测试验证通过**

Run: `/usr/local/go/bin/go test -v ./internal/runtime/... && /usr/local/go/bin/go test -run "TestTrainingControl|TestResolveRuntime|TestBuildTrainingReport" ./internal/controller/...`
Expected: PASS

- [ ] **Step 5: 提交修改**

```bash
git add internal/runtime internal/controller/training_control.go internal/controller/model_reporting.go
git commit -m "refactor(runtime): 提取训练执行、进程组控制与遥测解析至 internal/runtime"
```

---

### Task 5: 构建业务编排层 `internal/coordinator`

**Files:**
- Create: `internal/coordinator/coordinator.go`
- Create: `internal/coordinator/task_manager.go`
- Create: `internal/coordinator/phase_state.go`
- Create: `internal/coordinator/flow_model.go`
- Create: `internal/coordinator/flow_training.go`
- Create: `internal/coordinator/flow_export.go`
- Create: `internal/coordinator/recovery.go`
- Create: `internal/coordinator/coordinator_test.go`
- Create: `internal/coordinator/flow_test.go`
- Test: `internal/coordinator/...`

- [ ] **Step 1: 编写 `internal/coordinator` 测试套件**

编写针对 `TaskManager` 任务互斥与并发抢占、阶段流转状态机、崩溃自愈流水线的测试。

- [ ] **Step 2: 运行测试验证失败**

Run: `/usr/local/go/bin/go test ./internal/coordinator/...`
Expected: FAIL

- [ ] **Step 3: 实现 `internal/coordinator` 各组件**

- 组装 `store`, `platform`, `resource`, `runtime`, `codeaudit`。
- `task_manager.go`: 独占排他锁、`RunAsyncSafe`、ActiveTask 快照管理。
- `phase_state.go`: Phase 1~4 阶段管理与持久化落盘同步。
- `flow_model.go`: 模型拉取、信封解密、流式安全解压、代码审计与上报。
- `flow_training.go`: 数据拉取、哈希索引、训练子进程运行、后台遥测推送、训练报告构建与上报。
- `flow_export.go`: 结果打包与信封加密。
- `recovery.go`: 完备的自愈流水线（规约 1~9：熔断、清理、孤儿进程回收、黑匣子归档、标准报告补齐、双轨补偿上报）。

- [ ] **Step 4: 运行测试验证通过**

Run: `/usr/local/go/bin/go test -v ./internal/coordinator/...`
Expected: PASS

- [ ] **Step 5: 提交修改**

```bash
git add internal/coordinator
git commit -m "feat(coordinator): 实现业务编排层 internal/coordinator 串联各功能域"
```

---

### Task 6: 重构传输层 `internal/controller` 并拆解巨石文件

**Files:**
- Create: `internal/controller/router.go`
- Create: `internal/controller/handler_task.go`
- Create: `internal/controller/handler_export.go`
- Create: `internal/controller/handler_system.go`
- Create: `internal/controller/response.go`
- Modify: `internal/controller/route.go` (转为轻量包装或过渡适配)
- Modify: `internal/controller/import_processing.go` (委托给 coordinator)
- Test: `internal/controller/...`

- [ ] **Step 1: 编写控制器与各 Handler 拆分**

- `router.go`: 路由映射与 CORS/POST-Only 中间件。
- `handler_task.go`: `/importModel`, `/import`, `/stopTraining` HTTP 处理。
- `handler_export.go`: `/export` HTTP 处理。
- `handler_system.go`: `/health`, `/status`, `/logs`, `/switch`, `/getAttestation`, `/getResourceInfo`。
- `response.go`: `writeJSON`, `writeEnvelope`, `writeError`, `writeErr`。
- `TAAState` 转为内部持有 `*coordinator.Coordinator`，各方法完全委托给 `coordinator`，实现向下完全兼容。

- [ ] **Step 2: 运行全部 controller 测试验证 100% 绿灯**

Run: `/usr/local/go/bin/go test -v ./internal/controller/...`
Expected: ALL PASS

- [ ] **Step 3: 提交修改**

```bash
git add internal/controller
git commit -m "refactor(controller): 将 route.go 与 import_processing.go 解耦拆分至 Handler 子模块"
```

---

### Task 7: 重构上层装配 `internal/app/taa` 与全系统集成回归

**Files:**
- Modify: `internal/app/taa/app.go`
- Modify: `internal/app/taa/server.go`
- Modify: `internal/app/taa/recovery.go` (简化并委托至 coordinator)
- Test: 全系统测试套件 `go test ./...`

- [ ] **Step 1: 简化 `internal/app/taa` 启动与自愈流程**

使用 `coordinator.NewCoordinator` 与 `controller.RegisterRoutes` 优雅组装服务，将 `reconcileCrashRecovery` 委托给 `coordinator.ReconcileCrashRecovery`，大幅精简 `app.go` 与 `recovery.go`。

- [ ] **Step 2: 运行全工程自动化测试套件**

Run: `/usr/local/go/bin/go test ./internal/...`
Expected: ALL PASS

- [ ] **Step 3: 运行完整编译与启动烟测**

Run: `/usr/local/go/bin/go build -o /tmp/taa ./cmd/taa`
Expected: 成功生成二进制无报错

- [ ] **Step 4: 提交修改**

```bash
git add internal/app/taa
git commit -m "refactor(taa): 基于新分层架构重构 TAA 启动组装与自愈调用"
```

---

### Task 8: 清理过渡代码与生成重构总结文档

**Files:**
- Remove/Clean: 清理已无引用的过渡冗余代码
- Check: 检查所有代码行数与规范约束
- Test: 全量 `go test -v ./...` 回归

- [ ] **Step 1: 代码整洁度扫描与格式化**

Run: `gofmt -w internal/`

- [ ] **Step 2: 全局测试终验**

Run: `/usr/local/go/bin/go test ./...`
Expected: 所有的单元测试、并发测试、集成测试无一遗漏全部 PASS

- [ ] **Step 3: 提交最终修改**

```bash
git commit -m "chore: 完成 internal/controller 架构分层重构并清理过渡代码"
```
