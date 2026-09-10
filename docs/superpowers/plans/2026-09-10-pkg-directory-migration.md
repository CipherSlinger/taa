# TAA 公共可复用库 (pkg/) 重构与迁移实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将项目中与具体业务逻辑解耦的“通用轮子”（数据目录树解析 `filetree`、国密加解密库 `crypto`、硬件度量驱动 `attestation/csv_go`，以及内部重复的文件/日志工具）按照 Standard Go Project Layout 规范系统性迁入 `pkg/` 目录，并在保障现有构建流程（`Makefile`、`deploy.sh`）、外部 SDK（`sdk/`）及测试套件 100% 兼容的前提下完成平滑演进。

**Architecture:**
- `pkg/errors`：强类型业务/系统错误定义与状态码映射（已就绪）。
- `pkg/logger`：有界内存环形日志缓冲池与 ANSI 终端输出（已就绪）。
- `pkg/utils`：通用安全文件名清洗、文件递归拷贝与时间/随机数工具（已就绪）。
- `pkg/filetree`：从根目录 `filetree/` 迁入，提供多模态数据集魔数检测与 Schema 解析。
- `pkg/crypto`：从根目录 `crypto/` 迁入，提供国密 SM2/SM3/SM4-GCM 与混合信封算法。
- `pkg/csvattest`：从 `attestation/csv_go/` 迁入，提供纯 Go 实现的海光 CSV 硬件 IOCTL 通信与证书链验签。

**Tech Stack:** Go 1.26, `github.com/tjfoc/gmsm` (国密库), `github.com/xuri/excelize/v2`, `github.com/fraugster/parquet-go`, `modernc.org/sqlite`.

---

## 全局约束与设计原则 (Global Constraints)

1. **业务零污染**：`pkg/` 下的代码严禁反向引用 `internal/`、`cmd/`、`configs/` 或任何特定业务状态结构体。
2. **依赖单向性**：依赖关系必须为 `cmd/` -> `internal/` -> `pkg/`。
3. **SDK 零破坏兼容**：`sdk/` 作为独立的 Go module（`module teecrypto`，通过 `replace taa => ..` 引用根目录），其编译构建、CLI 二进制（`teecrypto-cli`）与 Tauri GUI 必须保持 100% 兼容。
4. **渐进式平滑演进**：采用“先引入/迁移、内部替换验证、最后清理废弃旧路径”的分阶段策略，严禁一次性破坏性大爆炸改造。
5. **规范提交**：每次阶段任务完成后，使用中文 Conventional Commits 自动提交，严禁提及任何 co-author / Anthropic / AI 相关字眼。

---

## 阶段一：内部 Controller / Mock 业务改造，对齐已就绪的 `pkg/logger` 与 `pkg/utils`

### Task 1.1: 将 `internal/controller/` 与 `internal/app/mock/` 接入 `pkg/logger`
**目标**: 消除内部重复的内存日志池实现，复用 `pkg/logger.Store`。

**涉及文件**:
- Modify: `internal/controller/log_store.go`（适配或类型别名包装 `pkg/logger.Store`）
- Modify: `internal/app/mock/server.go`（将 `requestLogStore` 内部缓冲区对齐 `pkg/logger.Store`）
- Test: `internal/controller/log_store_test.go`
- Test: `internal/app/mock/server_test.go`

- [ ] **Step 1.1.1: 改造 `internal/controller/log_store.go`**
  将其底层存储委托给 `pkg/logger.Store`，保持 `LogLevel` 与已有公共方法（`Add`, `Drain`, `Since`, `All`, `Count`）签名不变，确保对外 API 零破坏。
- [ ] **Step 1.1.2: 运行测试验证**
  ```bash
  go test -v ./internal/controller -run TestLogStore
  go test -v ./internal/app/mock
  ```

### Task 1.2: 将文件/路径工具迁移至 `pkg/utils`
**目标**: 移除 `internal/controller/` 中冗余的 `copyDir`、`copyFile`、`cleanDirContents`、`safeFilenamePart` 实现。

**涉及文件**:
- Modify: `internal/controller/import_helpers.go`（调用 `utils.CopyDir`、`utils.CleanDir`）
- Modify: `internal/controller/import_processing.go`（调用 `utils.CopyDir`）
- Modify: `internal/controller/route.go`（调用 `utils.SafeFilename`）
- Test: `internal/controller/...`

- [ ] **Step 1.2.1: 替换调用并删除重复私有函数**
- [ ] **Step 1.2.2: 运行 controller 全部单元测试**
  ```bash
  go test -v ./internal/controller/...
  ```

---

## 阶段二：`filetree/` 迁入 `pkg/filetree`

### Task 2.1: 迁移 `filetree` 到 `pkg/filetree`
**目标**: 将独立的数据集目录树解析引擎归入公共库。

**涉及文件**:
- Move: `filetree/filetree.go` -> `pkg/filetree/filetree.go`
- Move: `filetree/filetree_test.go` -> `pkg/filetree/filetree_test.go`
- Modify: `internal/controller/import_processing.go`（更新 import: `taa/pkg/filetree`）
- Modify: `internal/controller/resource_info.go`（更新 import: `taa/pkg/filetree`）
- Delete: 原根目录 `filetree/`

- [ ] **Step 2.1.1: 创建 `pkg/filetree` 并迁移代码**
  ```bash
  mkdir -p pkg/filetree
  git mv filetree/filetree.go pkg/filetree/filetree.go
  git mv filetree/filetree_test.go pkg/filetree/filetree_test.go
  ```
- [ ] **Step 2.1.2: 更新业务代码 import 路径**
  将 `taa/filetree` 替换为 `taa/pkg/filetree`。
- [ ] **Step 2.1.3: 运行验证**
  ```bash
  go test -v ./pkg/filetree/...
  go test -v ./internal/controller -run "TestResourceInfo|TestImport"
  ```
- [ ] **Step 2.1.4: 清理空目录并提交**
  ```bash
  rm -rf filetree/
  git add . && git commit -m "refactor(filetree): 将数据集目录树解析引擎迁移至 pkg/filetree"
  ```

---

## 阶段三：`crypto/` 迁入 `pkg/crypto` 且兼容 `sdk/`

### Task 3.1: 迁移国密算法库至 `pkg/crypto` 并建立过渡层
**目标**: 根目录 `crypto/` 下沉到 `pkg/crypto`，同时在根目录保留向前兼容的别名或轻量透传，避免破坏 `sdk/` 独立编译。

**涉及文件**:
- Move: `crypto/*.go` -> `pkg/crypto/*.go`
- Create: `crypto/compat.go`（兼容垫片，对外重新导出或透传类型与核心函数，保证旧 import 不中断）
- Modify: 更新 `internal/`、`cmd/`、`attestation/csv_go/` 中的引用至 `taa/pkg/crypto`
- Modify: 更新 `sdk/` 内部代码引用为 `taa/pkg/crypto`
- Test: `pkg/crypto/...`, `sdk/...`, `internal/...`

- [ ] **Step 3.1.1: 迁移源码到 `pkg/crypto`**
  ```bash
  mkdir -p pkg/crypto
  git mv crypto/sm2.go pkg/crypto/sm2.go
  git mv crypto/sm3.go pkg/crypto/sm3.go
  git mv crypto/sm4.go pkg/crypto/sm4.go
  git mv crypto/seal.go pkg/crypto/seal.go
  git mv crypto/keys.go pkg/crypto/keys.go
  git mv crypto/archive.go pkg/crypto/archive.go
  git mv crypto/doc.go pkg/crypto/doc.go
  git mv crypto/crypto_test.go pkg/crypto/crypto_test.go
  git mv crypto/archive_test.go pkg/crypto/archive_test.go
  ```
- [ ] **Step 3.1.2: 批量更新工程内 import 路径**
  将全工程中的 `"taa/crypto"` 全量更新为 `"taa/pkg/crypto"`。
- [ ] **Step 3.1.3: 在根目录 `crypto/` 设立兼容包（可选/渐进过渡）**
  若需保留历史兼容，保留轻量导入转发；或直接清理根目录 `crypto/` 并同步修正 `sdk/CLAUDE.md` 与 `sdk/go.mod`。
- [ ] **Step 3.1.4: 双重验证测试**
  ```bash
  go test -v ./pkg/crypto/...
  go test -v ./internal/... ./cmd/...
  (cd sdk && go test -v ./...)
  ```
- [ ] **Step 3.1.5: 提交变更**
  ```bash
  git add . && git commit -m "refactor(crypto): 将国密密码学与密钥信封库迁移至 pkg/crypto"
  ```

---

## 阶段四：海光硬件证明纯 Go 驱动 `attestation/csv_go/` 迁入 `pkg/csvattest`

### Task 4.1: 将纯 Go CSV 驱动与证书验证标准化为 `pkg/csvattest`
**目标**: 将海光 CSV TEE 纯 Go 驱动独立封装，底层 C 代码与度量二进制仍驻留 `attestation/csv_c` 与 `attestation/bin`。

**涉及文件**:
- Move: `attestation/csv_go/*.go` -> `pkg/csvattest/*.go`
- Modify: 将包名从 `package csvgo` 规范为 `package csvattest`
- Modify: 更新其中的密码学依赖（使用 `taa/pkg/crypto`）
- Test: `pkg/csvattest/...`

- [ ] **Step 4.1.1: 迁移代码至 `pkg/csvattest`**
  ```bash
  mkdir -p pkg/csvattest
  git mv attestation/csv_go/*.go pkg/csvattest/
  ```
- [ ] **Step 4.1.2: 规范包名与引用路径**
  修正 `package csvattest`，调整内部测试与文档。
- [ ] **Step 4.1.3: 运行驱动单元测试**
  ```bash
  go test -v ./pkg/csvattest/...
  ```
- [ ] **Step 4.1.4: 清理空目录并提交**
  ```bash
  rm -rf attestation/csv_go/
  git add . && git commit -m "refactor(attestation): 将海光 CSV 证明纯 Go 驱动迁移至 pkg/csvattest"
  ```

---

## 阶段五：统一错误映射机制落地（`pkg/errors` 深度集成）

### Task 5.1: 在 Controller 与 API 返回包装中统一应用 `pkg/errors`
**目标**: 淘汰魔法数字与松散的错误字符串拼接，全面采用结构化 `errors.Wrap` / `errors.New`。

**涉及文件**:
- Modify: `internal/controller/route.go`（`writeError` 与参数校验错误）
- Modify: `internal/controller/import_processing.go`（解密、解包、哈希校验错误包裹）
- Test: `internal/controller/handler_test.go`

- [ ] **Step 5.1.1: 增强 `writeError` 支持提取 `errors.CodeOf(err)`**
- [ ] **Step 5.1.2: 运行全套控制器接口集成测试**
  ```bash
  go test -v ./internal/controller/...
  ```
- [ ] **Step 5.1.3: 提交变更**
  ```bash
  git add . && git commit -m "feat(controller): 全面接入 pkg/errors 统一接口错误码与链路追踪"
  ```

---

## 最终验证清单 (Verification Checklist)

- [ ] `go test ./pkg/...` 全部通过
- [ ] `go test ./internal/... ./cmd/...` 全部通过
- [ ] `(cd sdk && go test ./...)` 客户端 SDK 单元测试通过
- [ ] `make taa && make platform-mock-build` 二进制构建产物正常且无编译警告
- [ ] `git status` 无残留未追踪冗余文件
