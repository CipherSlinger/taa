# Controller 架构分层与功能域重构设计规范

## 1. 背景与重构目标

### 1.1 现状与痛点
目前 `internal/controller` 包承担了整个 TAA (Trusted Application Agent) 系统的全能中枢角色，包含 14 个源文件与 20 个测试文件，总代码量超过 13,000 行。现存系统存在以下结构性缺陷：
1. **上帝对象膨胀**：`TAAState` 包含 28 个跨越不同领域的字段，涵盖并发锁、网络通信、机密身份、持久化落盘、进程管理、内存日志等，所有模块直接读写此结构体，耦合严重。
2. **职责杂糅与倒置**：HTTP 控制层（`route.go` 超过 2000 行）侵入底层进程树强杀、宏替换；资源处理层（`import_processing.go` 超过 1300 行）将解密、解压防炸弹、代码审计、子进程调度全部混在一个文件中；遥测层既读本地文件又做网络推送。
3. **平台通信重复分散**：存在 4 处重复构建 HTTP POST、URL 拼接与请求转储的实现。
4. **单测膨胀且脆弱**：测试简单纯逻辑必须构造庞大且完整的 `TAAState` 上下文。

### 1.2 重构目标
1. **单一职责与分层解耦**：将系统解耦为 **传输层 (HTTP) -> 业务编排层 (Coordinator) -> 基础功能域 (Resource / Runtime / Platform / Store)**。
2. **绝对依赖单向流动**：严禁循环引用，基础功能域彼此平级独立，不依赖编排层与传输层。
3. **消除上帝对象**：将 `TAAState` 瘦身为纯粹的协调器 `Coordinator`，并将任务互斥、阶段状态、机密身份拆分为内聚的子组件。
4. **统一平台出向客户端**：将网络请求、重试与日志 Dump 统一收敛至 `platform.Client`。
5. **保证 100% 行为兼容**：重构后所有现有接口行为、报文格式、错误码及 8,700+ 行自动化测试全部无缝通过。

---

## 2. 总体分层架构与依赖规约

系统按功能域划分为 6 个主要模块：

```
                     ┌────────────────────────┐
                     │    cmd/taa/main.go     │
                     └───────────┬────────────┘
                                 │ 启动入口
                                 ▼
                     ┌────────────────────────┐
                     │    internal/app/taa    │ (系统装配根)
                     └───────────┬────────────┘
                                 │ 注册 HTTP 路由
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. internal/controller (纯 HTTP 传输层，负责协议转换、入参校验与响应封包)   │
│    - router.go          : HTTP 路由映射与中间件 (CORS, POST-Only)            │
│    - handler_task.go    : 任务下发接口 (/importModel, /import, /stopTraining)│
│    - handler_export.go  : 产物导出接口 (/export)                             │
│    - handler_system.go  : 诊断接口 (/health, /status, /logs, /switch 等)     │
│    - response.go        : 统一 API 响应信封 (writeJSON, writeError)          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ 调用
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. internal/coordinator (核心编排层：状态机、任务互斥与全流程编排)          │
│    - coordinator.go     : 全局业务协调器 (组合各基础功能域模块)              │
│    - task_manager.go    : 独占排他锁机制、在飞任务快照与 Panic 保护          │
│    - phase_state.go     : 阶段状态机 (Phase 1~4) 与密封状态同步              │
│    - flow_model.go      : 模型导入流水线 (下载 -> 解密 -> 解压 -> 审计 -> 上报)│
│    - flow_training.go   : 数据导入与训练流水线 (下载 -> 索引 -> 进程 -> 报告)  │
│    - flow_export.go     : 产物打包与加密流水线                               │
│    - recovery.go        : 启动崩溃自愈 (熔断、黑匣子归档、离线补偿)          │
└──────────┬───────────────────┬───────────────────┬───────────────────┬──────┘
           │ 调用              │ 调用              │ 调用              │ 调用
           ▼                   ▼                   ▼                   ▼
┌──────────────────┐┌──────────────────┐┌──────────────────┐┌──────────────────┐
│ 3. resource      ││ 4. runtime       ││ 5. platform      ││ 6. store         │
│ (密态资源与数据) ││ (训练执行与观测) ││ (统一管控通信客户端)││ (硬件绑定密封存储)│
├──────────────────┤├──────────────────┤├──────────────────┤├──────────────────┤
│ - downloader.go  ││ - executor.go    ││ - client.go      ││ - sealed_state.go│
│ - envelope.go    ││ - process.go     ││ - register.go    ││   (SM4-Sealing  │
│ - archive.go     ││ - config.go      ││ - reporter.go    ││    与防密钥漂移) │
│ - checksum.go    ││ - telemetry.go   ││   (统一 HTTP POST│                  │
│ - index_store.go ││ - report.go      ││    重试/Dump/认证)│                  │
└──────────────────┘└──────────────────┘└──────────────────┘└──────────────────┘
```

### 依赖规则表 (DAG 保证)
| 模块名 | 允许依赖的下层模块 | 禁止依赖的模块 | 职责定义 |
|---|---|---|---|
| `internal/controller` | `coordinator`, `pkg/*` | `resource`, `runtime`, `platform`, `store` | 纯 HTTP Handler 与参数解析 |
| `internal/coordinator` | `resource`, `runtime`, `platform`, `store`, `internal/codeaudit`, `pkg/*` | `controller`, `app/*` | 业务全流程编排与任务控制 |
| `internal/resource` | `pkg/crypto`, `pkg/utils`, `pkg/errors` | `controller`, `coordinator`, `runtime`, `platform` | 文件、加密、解压、去重索引 |
| `internal/runtime` | `pkg/utils`, `pkg/errors` | `controller`, `coordinator`, `resource`, `platform` | 子进程执行、日志解析、结果组装 |
| `internal/platform` | `pkg/crypto`, `pkg/utils` | `controller`, `coordinator`, `resource`, `runtime` | 纯网络 HTTP 请求发送与重试 |
| `internal/store` | `pkg/crypto`, `pkg/utils` | 其他所有 internal 业务包 | 纯本地状态加解密持久化 |

---

## 3. 详细功能域设计

### 3.1 ��输层 (`internal/controller`)
负责接收平台发送的 HTTP 请求，做最基本的鉴权、参数校验、反序列化，并委托 `coordinator` 处理，不包含耗时阻塞逻辑或业务处理。
- `router.go`：
  - `RegisterRoutes(mux *http.ServeMux, coord *coordinator.Coordinator)`：对外注册路由。
  - 中间件：`postOnly`（处理 OPTIONS、限制仅 POST、设置 CORS 响应头）。
- `handler_task.go`：
  - 处理 `/v1/taa/importModel`：参数反序列化为 `ModelImportRequest`，调用 `coord.ImportModelAsync`。
  - 处理 `/v1/taa/import`：参数反序列化为 `DataImportRequest`，调用 `coord.ImportDataAndTrainAsync`。
  - 处理 `/v1/taa/stopTraining`：调用 `coord.StopTraining`，返回中止状态。
- `handler_export.go`：
  - 处理 `/v1/taa/export`：校验 Phase 3，调用 `coord.ExportResult`，以流式写入 `http.ResponseWriter`。
- `handler_system.go`：
  - `/v1/taa/health`、`/v1/taa/status`：读取 Coordinator 的当前状态（状态码、操作状态、在飞任务）。
  - `/v1/taa/switch`：阶段切换（Phase 1 -> Phase 2 -> Phase 3 -> Phase 4）。
  - `/v1/taa/logs`：读取内存循环日志。
  - `/v1/taa/getAttestation`：调用 Coordinator 获取 TEE 远程证明报告。
  - `/v1/taa/getResourceInfo`：调用 Resource 模块探测数据文件树。
- `response.go`：
  - 提供 `writeJSON`, `writeEnvelope`, `writeError`, `writeErr` 统一响应规范。

### 3.2 业务编排层 (`internal/coordinator`)
作为整个 TAA 的大脑，协调任务状态流转，维护任务互斥性。
- `coordinator.go`：
  - 结构体 `Coordinator`，组合各子系统：
    ```go
    type Coordinator struct {
        tasks     *TaskManager
        phase     *PhaseState
        resource  *resource.Manager
        runtime   *runtime.Manager
        platform  *platform.Client
        store     *store.StateStore
        logs      *logger.Store
        secConfig SecurityConfig
    }
    ```
- `task_manager.go`：
  - 替代原有的零散互斥逻辑，提供原子锁操作：
    - `TryAcquireTask(taskID, reqID, op string, isModel bool) (releaseFn, error)`
    - `PromoteToTraining() error`
    - `RunAsyncSafe(name string, releaseFn, fn func())`：提供 panic 捕获、孤儿状态复位与错误自动上报。
- `phase_state.go`：
  - 管理 Phase 状态切换及合法性校验（Phase 1 必须导入模型与数据后方可推进 Phase 2）。
  - 同步更新内存状态并落盘密封到 `store.StateStore`。
- `flow_model.go`：
  - 模型导入异步任务流水线：
    1. 下载模型加密包；
    2. 使用 SM2 私钥解密信封；
    3. 流式解压至 `model_dir`；
    4. 调用 `internal/codeaudit` 进行静态扫描与 LLM 语义审计；
    5. 校验通过后记录 `ModelChecksum` 并向平台上报 `ReportModelImport` 与 `ReportAudit`。
- `flow_training.go`：
  - 数据导入与训练异步流水线：
    1. 下载数据加密包；
    2. 解密并解压至哈希索引目录；
    3. 解析 `runtimeConfig` 环境变量宏替换；
    4. 启动训练子进程组，绑定 `process_control`；
    5. 启动后台 Telemetry 监听协程，实时轮询推送日志与进度；
    6. 等待进程退出，收集产物，计算校验和；
    7. 生成 `training_report.json` 并调用 `platform.ReportTrainingResult`。
- `recovery.go`：
  - 启动崩溃自愈核心流水线（由 `internal/app/taa` 在初始化完成时调用）：
    - 检查是否存在 RUNNING 在飞任务；
    - 熔断保护（连续失败 >= 3 次归档死信队列并复位）；
    - 清理未审计代码目录与脏临时碎片；
    - 回收孤儿训练进程组；
    - 索引清洗与黑匣子归档；
    - 生成标准占位错误报告；
    - 双轨补偿投递（极速通道 2s + 离线后台退避 60s）；
    - 状态复位与重新密封。

### 3.3 密态资源与数据层 (`internal/resource`)
负责一切文件流、加解密、压缩解包与数据去重，纯纯的基础服务。
- `downloader.go`：
  - `DownloadToTempFile(resourceURL string, maxSize int64) (path string, size int64, err error)`
- `envelope.go`：
  - `DecryptEnvelope(privKey *teecrypto.SM2PrivateKey, cipherPath string) (plainPath string, err error)`
  - `EncryptDirectoryEnvelope(pubKeyPEM string, dir string) (cipherData []byte, err error)`
- `archive.go`：
  - `ExtractArchiveFile(dstDir, archivePath string) error`
  - 防 Zip-Slip 路径逃逸，限制解压总大小防 Zip-Bomb，自动设置可执行权限。
- `checksum.go`：
  - `HashFileSM3(filePath string) (string, error)`
  - `BuildDirectoryChecksum(dir, algorithm string) (map[string]any, error)`
- `index_store.go`：
  - `ImportIndexStore`：根据数据集 SM3 哈希进行去重索引，支持 `.bak` 容灾与原子落盘，支持 `Purge`。

### 3.4 训练执行与观测层 (`internal/runtime`)
负责底层操作系统进程交互、配置宏解析与日志度量解析，与网络无依赖。
- `config.go`：
  - `ParseRuntimeConfig(raw string) (cfg, env, error)`
  - `ResolvePlaceholders(str string, dataDir, outputDir string) string`
- `process.go`：
  - `TrainingControl`：封装 `sync.Mutex`、`context.Context`、`*exec.Cmd`。
  - `KillProcessGroup(cmd *exec.Cmd) error`：安全杀灭进程组（支持 Unix PGID 杀灭与 Windows 兼容）。
- `executor.go`：
  - `RunRuntimeConfig(control *TrainingControl, cfg, env, dirs...) error`
- `telemetry.go`：
  - `JSONLLogReader`：增量读取 `train.jsonl`，按行增量解码。
  - `ProgressReader`：读取 `progress.json` 进度快照。
- `report.go`：
  - `BuildTrainingReport(...)`、`BuildCrashFailureReport(...)`：生成 Schema 1.0 兼容的训练综合报告。

### 3.5 管控平台通信层 (`internal/platform`)
负责向上游管控平台发送 HTTP 上报，提供统一连接池与错误排查支持。
- `client.go`：
  - `Client`：持有 `http.Client`、`platformIP`、`dockerID`。
  - 提供统一的 `postJSON(ctx, endpoint, payload)`，负责 URL 规范化、超时重试、失败时自动转储全量 Request Dump 日志。
- `register.go`：
  - `NoticeRegister(ctx, attestationFile, taaPublicKey, timestamp) error`
- `reporter.go`：
  - `ReportModelImport(ctx, reqID, taskID, code, msg, checksum) error`
  - `ReportAudit(ctx, reqID, taskID, code, msg, report) error`
  - `ReportTrainingResult(ctx, reqID, taskID, code, msg, reportJSON) error`
  - `ReportModelLogs(ctx, reqID, taskID, seqStart, entries) error`
  - `ReportProgress(ctx, reqID, taskID, percent, timestamp) error`

### 3.6 密封状态存储层 (`internal/store`)
- `sealed_state.go`：
  - 纯粹的状态文件加密存储：
    - `DeriveSealingKey(privKey *teecrypto.SM2PrivateKey) []byte`
    - `NewStateStore(path string, sealingKey []byte) (*StateStore, error)`
    - `SealState(state *PersistentState) error`
    - `UnsealState() (*PersistentState, error)`
    - `DetectAndHandleKeyDrift(isNewKey bool) (bool, error)`

---

## 4. 迁移与重构演进计划

为确保系统稳定性，重构采用**渐进式落地**策略：

1. **第一阶段：创建下层基础设施包**
   - 创建 `internal/store`，迁移密封状态逻辑，保持单元测试全部通过。
   - 创建 `internal/platform`，统一客户端请求发送，保持上报测试通过。
   - 创建 `internal/resource`，迁移下载、信封加解密、安全解压与索引，测试通过。
   - 创建 `internal/runtime`，迁移执行器、中止控制、宏解析与报告生成，测试通过。
2. **第二阶段：建立 Coordinator 并重构 Controller**
   - 创建 `internal/coordinator`，组合各子包能力，承接原 `TAAState` 的业务流程。
   - 拆解 `internal/controller` 为纯 HTTP 路由与分发器（`handler_*.go`）。
3. **第三阶段：更新上层装配与回归测试**
   - 更新 `internal/app/taa/app.go`，使用新 Coordinator 组装系统。
   - 运行全部 20+ 个测试套件，验证 100% 测试通过。

---

## 5. 验收标准
1. `go build ./...` 编译无任何警告与错误。
2. `go test -v ./internal/...` 所有单元测试、并发测试与集成测试全部 PASS。
3. 没有任何循环导入（Import Cycle）。
4. 代码职责严格符合架构规范，单个源文件体积均控制在 400 行以内。
