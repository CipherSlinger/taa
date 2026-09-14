# TAA 状态持久化与崩溃自愈设计文档 (工业级完备版)

## 1. 概述与设计背景

### 1.1 背景与问题现状
TAA（Trusted Application Attestation）运行于 Hygon CSV TEE 物理隔离环境中，负责端到端密态资产的安全闭环：平台远程度量、密态资源解密、代码安全审计、隔离沙箱训练以及计算产物的 SM2 信封重加密导出。

在既有系统实现与历史缺陷排查中，TAA 面临以下深层次的系统性威胁与脆弱点：
1. **未审计代码残留与越权复用漏洞（Security Vulnerability）**：若 TAA 在模型导入（`importModel`）或代码审计中途因 OOM/崩溃中断，解压的高危源码已残留在 `<modelDir>` 中。因 `hasSavedModel()` 仅检测目录非空，重启后攻击者通过空 URL 下发即可绕过安全审计，直接拉起未审计的后门代码执行。
2. **运行中强切阶段导致并发踩踏（Race Condition）**：`switchHandler` 盲目清除 `ActiveTaskID`，若在训练执行途中接收到切换指令，将导致两组进程争抢 `/opt/taa/output` 目录，产物与哈希被当场污染。
3. **Phase 1 双步导入相互死锁（Deadlock）**：Phase 1 采用解耦的模型与数据两步导入流程（`importModel` -> `import`），若就绪标志被简单归为内存瞬态，重启后两端将陷入永久互相等待。
4. **TEE 机密性泄漏隐患（Unsealed Sensitive Data）**：`RuntimeConfig` 的环境变量 `env`（含数据库账密、S3 Token 等）若明文落盘，宿主机 Root 权限可随时透过虚拟磁盘镜像 dump 窃取，违背 TEE 密态计算原则。
5. **密钥漂移引发无限启动崩溃（Key Drift CrashLoop）**：若容器重新创建并生成了新 SM2 私钥，解封旧状态失败后若直接 `exit 1`，将导致 Kubernetes 陷入永久 `CrashLoopBackOff`。
6. **自愈二次崩溃与幽灵失败（Recovery Loop & Ghost Failure）**：磁盘写满（`ENOSPC`）会导致自愈写入失败报告再度崩溃；而异步补偿若跨越 HTTP 端口开放，会导致新调度的重试任务被旧补偿包误杀。

### 1.2 核心设计目标
- **零安全死角（Zero Un-audited Execution）**：未通过审计的模型在崩溃后必须被物理清除，绝对禁止任何未通过审计的代码被复用。
- **全状态生命周期强互斥**：运行中严格禁止任何阶段切换，彻底杜绝并发踩踏。
- **TEE 硬件级密封存储（Sealed Storage）**：高敏状态通过 SM4-GCM 密态落盘，具备防篡改与机密性保证。
- **自愈熔断与双轨投递（Circuit Breaker & Dual-Track Drain）**：前置极速同步补偿（< 2s） + 离线后台重试，解耦 K8s 存活探针，配备二次崩溃熔断保护。

---

## 2. 状态分类与 TEE 密封持久化（Sealing）设计

系统将状态严格划分为 **公共持久化状态**、**机密持久化状态（需 Sealing 保护）** 以及 **瞬态运行时状态**：

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TAA 运行时状态三层模型                          │
├───────────────────────────────────┬────────────────────────────────────┤
│ 🔒 TEE 密态持久化 (SM4-GCM 密封)   │ ⚡ 瞬态状态 (仅存内存 / 启动强制重置)│
│ (落盘至 <resultDir>/state.sealed) │                                    │
├───────────────────────────────────┼───────────────────────��────────────┤
│ • 运行阶段 (CurrentPhase: 1~4)     │ • 当前操作状态 (CurrentOp: 强置idle)│
│ • 阶段1就绪标志 (Model/DataImported)│ • 内存读写互斥锁 (mu, attestMu)    │
│ • 导出公钥 (ExportPublicKey)       │ • 内存环形日志缓冲池 (LogStore)    │
│ • [高敏] 环境变量 (RuntimeConfig)  │ • 临时解密文件句柄与网络连接       │
│ • [高敏] 模型下载凭证 (SavedModelURL│ • 操作系统训练子进程 (exec.Cmd)    │
│ • 在飞任务快照 (ActiveTaskSnapshot)│ • 阶段1并发执行锁 (TrainingStarted)│
│ • 实例纪元号 (IncarnationID)       │ • 动态操作上下文 (activeToken)     │
│ • 模型与数据压缩包哈希校验和       │                                    │
└───────────────────────────────────┴────────────────────────────────────┘
```

### 2.1 TEE 密封存储规范 (Sealing Mechanism)
- **存储路径**：`<resultDir>/taa-state.sealed`（默认 `/opt/taa/results/taa-state.sealed`）。
- **加密机制与 KDF 规范**：
  - **国密派生标准**：由 TAA 实例唯一的国密 SM2 私钥大整数标量 $D$（32 字节）通过国密 SM3 经 Domain Separation 派生专属 **State Sealing Key（SM4 128位密钥）**：
    $$\text{StateSealingKey} = \text{SM3}(\text{privKey.D} \parallel \text{"TAA-STATE-SEALING-V1"} \parallel 0x00000001)[:16]$$
  - **SM4-GCM 认证加密**：采用国密 SM4-GCM 认证加密模式，数据落盘格式为：
    $$[12\text{B Nonce}] \parallel [\text{Ciphertext}] \parallel [16\text{B GCM Tag}]$$
  - **单调防回滚机制（Anti-Rollback / Replay Guard）**：引入单调递增版本号 `StateSeq uint64`，每次状态写入原子自增；在平台会话恢复与状态恢复中校验时间戳与序列号单调性，防止宿主机恶意替换为历史合法旧快照。
  - **密文防篡改**：任何宿主机篡改、字节注入或位翻转均会导致 GCM 认证失败，严格以 Fail-Closed 原则拒绝载入。
- **全链路物理刷盘原子性（Full-Chain Fsync Atomicity）**：
  - 写入临时文件 `<resultDir>/.tmp-state-*` -> `file.Sync()` -> `file.Close()` -> 原子 `os.Rename` 覆盖 -> 打开父目录并执行 `dir.Sync()`。文件权限严格限定为 `0600`。

### 2.2 数据模型定义

```go
// PersistentState 定义被密封持久化的业务状态全集
type PersistentState struct {
    Version               string              `json:"version"`               // 架构版本，当前固定 "1.3"
    StateSeq              uint64              `json:"stateSeq"`              // 单调递增序列号，防重放与快照回滚
    IncarnationID         string              `json:"incarnationId"`         // 实例启动纪元 UUID，每次冷启动重新生成
    CurrentPhase          int                 `json:"currentPhase"`          // 当前阶段 1~4
    ModelImported         bool                `json:"modelImported"`         // 模型是否已完整解密并通过审计
    DataImported          bool                `json:"dataImported"`          // 阶段1/2数据是否已导入
    TrainingDataImported  bool                `json:"trainingDataImported"`  // 阶段3训练数据是否已导入
    ExportPublicKey       string              `json:"exportPublicKey"`       // Phase 1 保存的公钥 PEM
    SavedModelResourceURL string              `json:"savedModelResourceURL"` // 保存的模型下载 URL (密态存储)
    RuntimeConfig         string              `json:"runtimeConfig"`         // 包含 commands 和 env 的配置 JSON (密态存储)
    ModelChecksum         map[string]any      `json:"modelChecksum"`         // 模型包校验和
    DataChecksum          map[string]any      `json:"dataChecksum"`          // 数据包校验和
    ActiveTask            *ActiveTaskSnapshot `json:"activeTask,omitempty"`  // 当前正在异步执行的任务快照
    UpdatedAt             time.Time           `json:"updatedAt"`             // 状态更新时间戳
}

// ActiveTaskSnapshot 记录在飞任务元数据，用于中断感知与补偿
type ActiveTaskSnapshot struct {
    RequestID        string    `json:"requestId"`        // 平台请求 ID
    TaskID           string    `json:"taskId"`           // 训练任务 ID
    Type             string    `json:"type"`             // "model_import" | "data_import" | "training"
    Phase            int       `json:"phase"`            // 发起时的阶段 (1~4)
    Status           string    `json:"status"`           // 固定为 "RUNNING"
    ResultDir        string    `json:"resultDir"`        // 本地产物输出目录
    StartedAt        time.Time `json:"startedAt"`        // 任务启动 UTC 时间戳
    RecoveryAttempts int       `json:"recoveryAttempts"` // 自愈尝试次数（防死循环熔断）
}

// ImportIndexRecord 导入索引条目（扩展产物所属安全阶段）
type ImportIndexRecord struct {
    RequestID string `json:"requestId"`
    TaskID    string `json:"taskId"`
    Hash      string `json:"hash"`
    DataDir   string `json:"dataDir"`
    ResultDir string `json:"resultDir"`
    Phase     int    `json:"phase"`     // 关键：记录产物生成的安全等级阶段，决定导出的强制加密策略
}
```

---

## 3. 防御式边界与严格写入临界点（Point of Persistence）

### 3.1 资源下载防御（抗 Chunked 炸弹与超大包）
在 `downloadToTempFile` 中，杜绝因分块编码（`ContentLength == -1`）导致的无限写入打爆 `/tmp` 分区：
- **强制截断防护**：统一使用 `io.LimitReader(resp.Body, maxDownloadBytes + 1)`；
- 若读取字节数超过 `maxDownloadBytes`，立即中止流传输、清除已写入临时文件并返回 400 报错。

### 3.2 资源解压防御（抗解压炸弹与磁盘配额截断 Decompression Bomb Guard）
在 `extractTarStream` 与 `extractZipArchive` 中：
- **解压总量熔断配额**：全局维护 `maxExtractBytes` 累积计数器（默认 20GB 或磁盘安全阈值）；
- **逐字节限制写入**：在 `writeExtractedFile` 中，杜绝无限制 `io.Copy(out, src)`，改为包装 `io.LimitReader` 并在达到配额时立即中止解压；
- **防脏目录滞留**：触发超限时，立即递归清空目标解压目录并返回 `400 (解压超出安全配额限制)`，防止磁盘被填满（`ENOSPC`）诱发系统级级联崩溃。

### 3.3 训练子进程树隔离与孤儿进程防泄漏（Process Group & Orphan Guard）
在 `runRuntimeConfig` 中通过 `/bin/sh` 执行用户命令时：
- **进程组隔离（Process Group Isolation）**：显式注入 `cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}`，将 Python 训练脚本及其子进程（如 `torchrun`、多进程 worker 等）纳管至独立的进程组（PGID）；
- **级联终止机制**：若 TAA 收到停机信号或任务异常中断，通过 `syscall.Kill(-pgid, syscall.SIGKILL)` 级联杀灭整颗子进程树，杜绝子进程被 PID 1 收养为孤儿进程；
- **启动自愈进程探测**：在自愈流水线中，主动扫描并清理非 TAA 主进程的残留训练进程，彻底释放被锁定的 GPU 显存（CUDA OOM 根因）与端口文件句柄。

### 3.4 原子写入临界点定义
为杜绝“同步网络失败却误触发异步崩溃补偿”的契约混乱，`ActiveTaskSnapshot` 的写盘时机被严格限定：

```text
接收 HTTP 请求 (import / importModel)
  │
  ├─ 1. 同步参数校验 (非空检查、Phase合法性检查) ──[失败]──► 返回 400 Bad Request (无写盘)
  │
  ├─ 2. ImportIndexStore.Reserve 预留 ID ──────────[失败]──► 返回 400 正在处理中 (无写盘)
  │
  ├─ 3. 同步流式下载密文至临时文件 (防炸弹 LimitReader)
  │       │
  │       └──[网络超时/HTTP 404/500/超大]──────────[失败]──► 回滚 Reserve 内存锁，返回 500 (无写盘)
  │
  ├─ 4. ★★★ 原子写入临界点 (Point of Persistence) ★★★
  │       持久化写入 ActiveTaskSnapshot(status="RUNNING") 并执行 Sealing 落盘
  │
  ├─ 5. 同步返回 HTTP 200 OK 给平台 ("资源已接收，训练结果将通过 reportRes 上报")
  │
  └─ 6. 拉起后台 Goroutine 执行解密、审计、训练
```

### 3.5 全链路物理刷盘原子性与掉电防护（Full-Chain Fsync Atomicity）
针对 Linux ext4 延迟分配与宿主机断电掉电导致文件变成 0 字节损坏的隐患：
- **全链路 Fsync 规约**：针对 `state.sealed` 与 `import-index.json`，严格执行五步落盘：
  $$\text{OpenTemp} \longrightarrow \text{Write} \longrightarrow \text{file.Sync()} \longrightarrow \text{file.Close()} \longrightarrow \text{os.Rename()} \longrightarrow \text{dir.Sync()}$$
- **临时碎片清除**：自愈启动时自动扫描并清理历史遗留的 `*.tmp` 孤儿文件，防止悬挂碎片堆积。

### 3.6 导出打包软链接穿透越界防护（Symlink Escaping in Export Packaging）
在 `/v1/taa/export` 打包压缩目录（`compressDirToTarGz`）时，抵御模型训练脚本在 `/opt/taa/output` 构造软链接偷取宿主敏感文件的攻击：
- **符号链接物理路径解析**：遍历目录时对所有文件/链接调用 `filepath.EvalSymlinks(path)`；
- **沙箱越界阻断**：若链接指向的目标物理路径脱离了 `srcDir`（例如恶意软链接指向 `/opt/taa/keys/private.pem`、`/etc/shadow` 或 `/root/.ssh`），**坚决拒绝打包入流并记录严重安全报警**，从根源杜绝 TAA SM2 根私钥外泄。

---

## 4. 核心控制面防御设计

### 4.1 运行期阶段切换（Phase Switch）强互斥门禁
针对 `switchHandler` 盲目抹除活跃任务导致并发踩踏的重大缺陷，新增原子前置检查：

```go
func (s *TAAState) switchHandler(w http.ResponseWriter, r *http.Request) {
    ...
    s.mu.Lock()
    defer s.mu.Unlock()

    // 强互斥门禁：若当前有任何任务在执行（无论是下载、审计、训练、报告），严禁切换阶段
    if s.isTrainingBusyLocked() || s.ActiveTaskID != "" || (s.CurrentOp != "" && s.CurrentOp != "idle") {
        writeErr(w, http.StatusConflict, pkgerrors.New(pkgerrors.CodeConflict,
            fmt.Sprintf("当前已有任务正在执行中 (taskId: %s, op: %s)，严禁切换运行阶段", s.ActiveTaskID, s.CurrentOp)))
        return
    }
    // 允许切换阶段，并执行状态密封落盘...
}
```

### 4.2 Phase 1 调试模式双步导入防死锁设计
- `ModelImported` 与 `DataImported` 必须作为密封状态落盘；
- 若发生先导模型后崩塌的场景，启动时从 `state.sealed` 中无损还原 `ModelImported: true`；
- 当后续数据下发到达时，系统能立即识别“模型已就绪”，瞬间进入训练执行，彻底打破两端等待死锁。

### 4.3 产物阶段���和性绑定与越权明文导出阻断（Phase Affinity & Cross-Phase Export Guard）
针对系统级重大安全隐患：**攻击者通过切回低阶段导出高阶段敏感模型与数据**：
- **漏洞根因**：原 `exportHandler` 仅依据当前运行时状态 `s.CurrentPhase` 判定是否明文导出；若在 Phase 3（正式训练）产生敏感产物后，攻击者下发 `switch(phase=1)` 强切回调试阶段，再调用 `/v1/taa/export` 不传公钥，即可直接将 Phase 3 训练结果以**明文**带出！
- **防御机制**：
  1. `ImportIndexRecord` 严格持久化记录产物所属的 `Phase`；
  2. `exportHandler` 强制根据 `record.Phase`（产物生成时的法定安全等级）而非 `s.CurrentPhase` 执行加密断言；
  3. **强制加密铁律**：凡 `record.Phase == 3` 的产物，无论 TAA 当前被切换至何阶段，导出时**必须且只能使用 Phase 1 保存的 `ExportPublicKey` 执行 SM2+SM4-GCM 信封加密导出**，绝对禁止任何明文导出；若无公钥则拒绝导出返回 400。以此消除跨阶段权限降级漏洞。

---

## 5. 启动自愈（Fast-Fail）完备机制与二次崩溃熔断

```mermaid
flowchart TD
    Boot([TAA 启动: RunWithConfig]) --> LoadKey[1. 加载 SM2 私钥与派生 SealingKey]
    LoadKey --> UnsealCheck{Unseal state.sealed<br>解密成功?}
    
    UnsealCheck -- 失败且SM2为新生成 --> HandleDrift[实例密钥漂移: 归档旧状态为.orphaned, 干净初始化]
    UnsealCheck -- 失败且SM2为老私钥 --> FailClosed[Fail-Closed: 状态遭篡改, 拒绝启动]
    UnsealCheck -- 成功 --> CheckCrash{ActiveTask != nil<br>且状态为 RUNNING?}

    HandleDrift --> RegPlatform[2. POST /v1/taa/register 平台注册握手]
    FailClosed --> CrashExit([退出并报警 exit 1])

    CheckCrash -- 否 (静止期重启) --> RegPlatform
    CheckCrash -- 是 (任务执行中崩溃) --> RegPlatform

    RegPlatform --> ReconcileRecovery[3. reconcileCrashRecovery 启动自愈处理]

    ReconcileRecovery --> CheckCircuit{RecoveryAttempts >= 3?}

    CheckCircuit -- 是 (熔断触发) --> DeadLetter[转入死信隔离 .dead-letter, 记录严重报警, 清空ActiveTask]
    DeadLetter --> StartServer[4. 启动 HTTP API 监听对外提供服务]

    CheckCircuit -- 否 --> IncAttempts[RecoveryAttempts + 1]
    IncAttempts --> Step1[1. 安全隔离: 若为model_import崩溃, 强制抹除modelDir未审计代码]
    Step1 --> Step2[2. 脏环境清理: 清空 /opt/taa/input, output, 扫描清除 /tmp 碎片]
    Step2 --> Step3[3. 孤儿进程回收: 扫描清理残留训练孤儿进程树, 释放 GPU 显存与锁]
    Step3 --> Step4[4. 索引清洗与归档: ImportIndexStore.Purge 剔除孤儿条目, 归档黑匣子目录]
    Step4 --> Step5[5. 产物规范补齐: 按标准 Schema 生成规范占位 training_report.json]
    Step5 --> Step6[6. 双轨补偿上报: 极速同步探测(2s) + 失败离线后台重试]
    Step6 --> Step7[7. 任务解封: ActiveTask=nil, 更新落盘 state.sealed]
    Step7 --> ResetOp[8. 强制重置内存 CurrentOp = idle]
    ResetOp --> StartServer
```

### 5.1 关键自愈步骤技术规约

#### 规约 1：未审计代码的物理隔离自愈（堵塞后门）
- 若崩溃时处于 `ActiveTask.Type == "model_import"` 且尚未完成上报（说明未经完整安全审计或在审计中崩溃）：
  - **强制物理执行 `cleanDirContents(s.Security.ModelDir)`**；
  - 强制将 `ModelImported` 置为 `false`；
  - **安全收益**：根除任何攻击者利用空 URL 复用残留后门代码的可能性。

#### 规约 2：实例密钥漂移（Key Drift）自愈容错
- 检查 `state.sealed` 解封失败的原因：
  - 若检测到当前 SM2 私钥为本次冷启动**全新生成**（`loaded == false`），说明容器被销毁重建且未挂载持久密钥卷，原状态属于前朝废弃会话；
  - **处理策略**：将旧文件重命名为 `taa-state.sealed.orphaned.<timestamp>`，并初始化全新的空持久化状态，继续正常注册与启动；
  - **稳定性收益**：彻底消除 Kubernetes 滚动更新与重调度引发的 `CrashLoopBackOff` 死循环。

#### 规约 3：自愈熔断保护（Recovery Circuit Breaker）
- `ActiveTaskSnapshot.RecoveryAttempts` 记录自愈次数。
- 若因磁盘写满（`ENOSPC`）等硬性不可恢复故障导致连续自愈失败达 `3 次`：
  - 将当前中断任务转存为 `<resultDir>/.dead-letter-<taskId>.json`；
  - 将 `ActiveTask` 置为 `nil` 强制清空；
  - 记录严重 ERROR 告警，允许 TAA 正常启动开放 `/v1/taa/health` 端口，以便运维人员通过 `kubectl exec` 接入容器排障。

#### 规约 4：`ImportIndexStore.Purge` 索引物理清洗与黑匣子归档
- 在 `ImportIndexStore` 中提供 `Purge(requestID, taskID string) error`：
  - 从 `records` 列表、`byRequestID` 映射表及 `byTaskID` 映射表中物理移除该中断条目并原子重写 `import-index.json`；
  - 若 `latestRecord` 正好是该中断条目，平滑回退至列表中的上一条合法记录（或置为 `nil`）；
  - 将原中断产物目录重命名为 `<resultDir>/.failed-<taskId>-<timestamp>` 作为只读黑匣子留存，杜绝新任务下发时被静默踩踏覆盖；
  - **业务收益**：平台收到崩溃补偿后，允许携带原 `requestId` / `taskId` 重新发起重试下发，不会遭遇 `400 (requestId/taskId已存在)` 冲突。

#### 规约 5：失败占位报告 Schema 严格对齐（对齐标准规范）
直接复用 `buildTrainingReport` 的结构化标准，杜绝顶层扁平字段导致平台反序列化解析报错：
```json
{
  "report_id": "report-20260911-100500-recover",
  "generated_at": "2026-09-11T10:05:00Z",
  "schema_version": "1.0",
  "training_task": {
    "task_id": "task-train-1002",
    "status": "failed",
    "exit_code": 137,
    "failure_reason": "TAA 异常崩溃重启，执行已被安全终止 (Process Interrupted by Crash)",
    "started_at": "2026-09-11T10:00:00Z",
    "finished_at": "2026-09-11T10:05:00Z",
    "duration_seconds": 300
  },
  "dataset": {
    "checksum": {
      "algorithm": "sm3",
      "value": "N/A"
    }
  }
}
```
**业务收益**：产物结构 100% 契合平台端对 `training_task.status` 与 `schema_version` 的强类型断言，同时使平台调用 `/v1/taa/export` 归档错误日志时行为完全一致。

#### 规约 6：临时下载碎片与孤儿进程回收（清理无用资源）
- **清除临时下载碎片**：扫描并清理 `/tmp/taa-download-*` 以及 `/tmp/*.extract-*`，杜绝因下载中断残留大文件耗尽根分区；
- **清理孤儿训练子进程**：探测并级联清理残留的 Python/Shell 孤儿进程，彻底释放被锁定的 GPU 显存（预防后续任务拉起时发生 CUDA OOM）与共享内存（shm）。

#### 规约 7：双轨补偿投递（Fast-Sync + Detached-Async）
为避免平台离线导致 TAA 无法通过容器存活探针（Liveness Probe）：
1. **前置同步极速通道**：TAA 在启动阶段尝试向平台同步 POST 失败通知（带 `2 秒` 硬超时）；
2. **离线后台容错重试**：若平台在 2 秒内未响应（网络不通/平台正在拉起）：
   - 将该补偿请求转交后台 Detached Worker 执行（指数退避重试，最大持续 60 秒）；
   - **TAA 启动流程不再等待，立刻对外开放 HTTP 端口**；
   - 此时容器健康检查 `/v1/taa/health` 立即转为 200 OK，K8s 探针顺利通过，两端系统平滑协同。

#### 规约 8：导入索引损坏防御与自动降级（Index Corruption Recovery & Safe Re-init）
- 当 `import-index.json` 因断电或掉电导致反序列化失败（如残缺 JSON 语法）时：
  - 首先检测是否存在合法快照备份 `import-index.json.bak`，若存在则自动恢复；
  - 若无备份，自动将损坏文件安全归档为 `import-index.json.corrupted.<timestamp>`，并初始化全新干净的索引存储，避免单点坏块导致整个 TAA 实例所有导入导出接口永久瘫痪。

#### 规约 9：训练子进程树组隔离与级联回收（Process Group Lifecycle & Cascade Termination）
- `runRuntimeConfig` 启动脚本时显式赋予独立进程组（`cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}`）；
- 当 TAA 接收到 SIGTERM 优雅停机信号或在自愈流程清理孤儿时，通过负 PGID（`syscall.Kill(-pgid, syscall.SIGKILL)`）向整个进程树广播杀灭信号；
- 确保包含 PyTorch DDP / Torchrun 多卡分布式训练、Python multiprocessing 及 Shell 管道在内的所有后代孤儿进程被物理消灭，彻底回收 GPU 显存并释放显卡硬件锁。

#### 规约 10：模型代码审计失败即刻熔断与物理清除（Audit Failure Immediate Abort & Quarantine）
- 当 `auditAndReportModelImport` 检测到源码存在高危风险（`audit.Conclusion.Passed == false`）或在 `failClosed=true` 下 LLM 服务不可用时：
  - **立即物理清空 `<modelDir>`（`cleanDirContents`）**，销毁所有已解压代码；
  - 严禁将 `ModelImported` 置为 `true`；
  - **立即终止当前导入链路并返回**，绝对禁止在 Phase 1 或 Phase 2/3 中继续流转至训练执行。

#### 规约 11：异步协程 Panic 统一捕获与平台兜底补偿（Async Goroutine Panic Recovery & Compensation）
- 在 `runAsyncSafe` 捕获到未处理的 `recover()` 时：
  - 严禁仅将错误打印日志后静默退出；
  - 必须构建标准的结构化失败报告，主动调用 `reportTrainingAsync` 或 `reportModelImportAsync` 向平台发送失败通知（`exit_code: 128`，标记为非预期内部崩溃）；
  - 触发密封存储原子擦除 `ActiveTask`，防止管控平台任务状态无限期挂起等待。

#### 规约 12：分块传输超限熔断防护（Chunked Download Guard）
- 针对无 `Content-Length` 的分块传输编码（Chunked Transfer Encoding）攻击或异常流：
  - `downloadToTempFile` 强制全局包裹 `io.LimitReader(resp.Body, maxDownloadBytes + 1)`；
  - 凡超出 `512MB` 限额的流在达到限额时立即切断网络连接、删除临时文件并返回 400 错误，从源头杜绝宿主机磁盘被恶意流撑爆。

---

## 6. 管控平台协同报文规范（Platform Contract）

**模型审计中断补偿**：
`POST http://{PLATFORM_IP}/v1/taa/reportModelImport`
```json
{
  "dockerId": "taa-instance-001",
  "requestId": "req-model-2001",
  "taskId": "task-model-2001",
  "code": 1,
  "msg": "TAA 异常崩溃重启，模型导入与代码审计中断，请重新下发",
  "report": ""
}
```

**训练执行中断补偿**：
`POST http://{PLATFORM_IP}/v1/taa/reportRes`
```json
{
  "dockerId": "taa-instance-001",
  "requestId": "req-train-1002",
  "taskId": "task-train-1002",
  "code": 1,
  "msg": "TAA 异常崩溃重启，训练执行已被安全终止，请重新下发",
  "report": "{\"task_id\":\"task-train-1002\",\"status\":\"failed\",\"exit_code\":137,\"failure_reason\":\"TAA 异常崩溃重启...\"}"
}
```

---

## 7. 异常防御矩阵（Fail-Closed 原则）

| 异常场景 / 攻击向量 | 防御机制与表现 | 达成的安全性与稳定性目标 |
|:---|:---|:---|
| **恶意修改 `state.sealed` 注入伪造公钥** | SM4-GCM Tag 认证失败，若私钥未变则判定遭篡改，直接以 `exit 1` 拒绝启动并报警 | **Fail-Closed**：防止攻击者伪造 `ExportPublicKey` 窃取导出模型 |
| **宿主机快照回滚与重放攻击（Rollback Attack）** | 引入单调递增 `StateSeq uint64` 与冷启动 `IncarnationID`，单调校验状态时序 | **状态防回滚**：杜绝非信任宿主机通过还原旧虚拟磁盘快照重放会话 |
| **审计中途崩溃后利用空 URL 绕过检测** | 自愈逻辑强行清空 `<modelDir>`，`hasSavedModel()` 强校验持久化标记 | **代码安全兜底**：绝不允许任何未通过审计的代码被沙箱拉起执行 |
| **代码审计未通过仍被触发执行** | 审计失败（`Passed==false`）即刻阻断流程，清空代码目录，禁止置位 `ModelImported` | **带毒代码零执行**：杜绝高危漏洞/后门模型在后续数据到达时被拉起训练 |
| **任务执行途中下发强切 Phase 指令** | `switchHandler` 拦截并发状态，严格返回 `409 Conflict` | **状态单调性**：消灭双进程并发读写输出目录造成的产物污染 |
| **跨阶段权限降级明文导出漏洞** | `ImportIndexRecord` 持久化绑定 `Phase`，`exportHandler` 强制根据 `record.Phase` 断言加密 | **防产物降级外泄**：彻底消除 Phase 3 正式训练模型在切回 Phase 1 后被明文带出的漏洞 |
| **导出打包软链接穿透窃取宿主私钥** | 遍历产物时调用 `filepath.EvalSymlinks` 解析真实物理路径，脱离 `srcDir` 坚决拒绝打包 | **TEE 根凭证保护**：阻断恶意脚本通过软链接窃取 `/opt/taa/keys/private.pem` |
| **超大分块传输编码（Chunked Bomb）** | `downloadToTempFile` 全局包裹 `LimitReader` 强制在 `maxDownloadBytes` 处截断断开 | **资源边界保障**：保护容器 `/tmp` 磁盘空间绝不耗尽 |
| **压缩包解压炸弹（Decompression Bomb）** | `writeExtractedFile` 注入 `maxExtractBytes` 限额截断，超限熔断并清空目标目录 | **抗磁盘耗尽**：阻断超大包耗尽磁盘导致的全局 I/O 崩溃（ENOSPC） |
| **训练子进程多进程派生与孤儿残留** | 注入进程组隔离（`Setpgid: true`），自愈级联清理子进程树，释放显存与句柄 | **GPU/内存防护**：防止残留 worker 进程霸占 CUDA 显存引发下次任务 OOM |
| **全链路物理刷盘原子性与掉电损坏** | 状态与索引落盘严格遵循临时文件 -> `Sync` -> `Close` -> `Rename` -> `parentDir.Sync` | **断电数据完整性**：杜绝掉电造成的 0 字节文件与脏元数据损坏 |
| **导入索引 JSON 坏块导致全局瘫痪** | 自动探测并恢复 `.bak` 备份，无备份则安全隔离为 `.corrupted` 并干净重置 | **单点坏块隔离**：杜绝单一索引解析失败导致整个 TAA 所有接口报 500 |
| **持久卷写满导致自愈写报告失败** | 自愈熔断计数（上限 3 次），超限转入死信文件并降级开放只读排障 | **抗自愈死锁**：避免容器陷入无限重启，保留运维调试入口 |
| **异���处理协程遭遇非预期 Panic 崩溃** | `runAsyncSafe` 统一捕获 `recover()`，格式化错误上报平台（code=128）并擦除状态 | **防平台无限悬挂**：确保平台端即时感知内部崩溃，不陷入永久等待 |
| **崩溃任务占位报告 Schema 格式不兼容** | 统一复用 `buildTrainingReport`，对齐 `schema_version: "1.0"` 与 `training_task` | **契约一致性**：杜绝平台端反序列化崩溃与 `/v1/taa/export` 解析异常 |
| **多次下载中断导致临时碎片填满 /tmp** | 自愈流水线明确扫描并清除 `/tmp/taa-download-*` 与 `/tmp/*.extract-*` | **环境净化**：确保重启后临时卷具备完整可用存储空间 |
| **平台宕机或网络分区** | 双轨投递（2s 极速同步 + 离线后台重试），立刻开放探针端口 | **探针解耦**：防止容器存活探针连续失败被 K8s 强制杀死 |

---

## 8. 代码重构落地清单

1. **密封存储引擎 (`internal/controller/state_store.go`)**：
   - 封装 `StateStore`，基于 SM3-KDF 域隔离派生与 SM4-GCM 实现 `SealState` 与 `UnsealState`；
   - 纳入 `StateSeq uint64` 单调版本序列与冷启动 `IncarnationID`，防御宿主机快照回滚；
   - 封装 Key Drift 探测（新旧私钥比对与 `.orphaned` 自动迁移归档）。
2. **索引存储清理、防穿透与归档扩展 (`internal/controller/import_index.go`)**：
   - 扩展 `ImportIndexRecord` 增加 `Phase int` 字段，持久化绑定产物安全阶段；
   - 优化 `saveLocked` 遵循 `OpenTemp` -> `Write` -> `file.Sync()` -> `file.Close()` -> `os.Rename` -> `parentDir.Sync()` 全链路 Fsync 规约；
   - 增加索引反序列化坏块自动容错与 `.corrupted` 降级隔离机制；
   - 新增 `Purge(requestID, taskID string) error`，物理清理已提交的孤儿索引条目并平滑修正 `latestRecord`。
3. **控制层并发防御与安全导出阻断 (`internal/controller/route.go`)**：
   - `switchHandler` 增加 `isTrainingBusyLocked()` 409 拒绝门禁；
   - `exportHandler` 强制基于 `record.Phase`（而非瞬态 `s.CurrentPhase`）断言加密策略，Phase 3 产物无公钥坚决拒绝明文导出；
   - `compressDirToTarGz` 注入 `filepath.EvalSymlinks` 软链接越界检查，杜绝越界偷取 `/opt/taa/keys/private.pem`���
   - `downloadToTempFile` 全局无条件应用 `io.LimitReader` 阻断 Chunked 超限流；
   - `hasSavedModel()` 移除单纯探测物理目录非空的判定，严格以 `s.ModelImported == true` 为唯一法定依据；
   - `runAsyncSafe` 强化 Panic 兜底，自动向平台补偿投递致命错误上报。
4. **解压安全、审计熔断与进程树生命周期管控 (`internal/controller/import_processing.go`)**：
   - `extractTarStream` / `extractZipArchive` 注入 `maxExtractBytes` 解压配额限制；
   - `auditAndReportModelImport` 改造为带状态熔断，审计失败立即执行物理清库（`cleanDirContents`）并阻断后续执行；
   - `runRuntimeConfig` 显式设置独立进程组（`Setpgid: true`）并提供 `syscall.Kill(-pgid, syscall.SIGKILL)` 级联杀树机制。
5. **自愈与熔断流水线 (`internal/app/taa/app.go`)**：
   - 在 `startServer` 前组装 `reconcileCrashRecovery` 链；
   - 实现未审计代码清除、/tmp 碎片清理、孤儿进程探测杀灭、熔断计数器累加、规范占位报告生成与双轨补偿投递。
