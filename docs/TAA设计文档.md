# TAA 设计文档

## 1. 项目概述

TAA（Trusted Application Attestation）是一个运行在 Hygon CSV（可信安全虚拟化）TEE 环境中的可信应用代理服务。它负责：

- 通过远程证明（Remote Attestation）向平台注册自身身份
- 接收平台下发的加密资源（模型代码、测试数据、训练数据）
- 在 TEE 安全环境中解密、审计、执行训练任务
- 将训练结果加密导出给平台

## 2. 系统架构

### 2.1 整体数据流

```
  平台                     TAA 容器                    远程证明
  ────                    ────────                    ────────

  ┌──────┐              ┌──────────────┐           ┌──────────┐
  │      │── register ──▶│              │── vmmcall ─▶│          │
  │      │              │   TAA 服务    │           │ CSV 硬件  │
  │ 平台  │── import ───▶│   (:6001)    │◀─ report ──│          │
  │      │◀── reportRes ─│              │           └──────────┘
  │      │              │   ┌────────┐  │
  │      │── export ───▶│   │ Ollama │  │
  │      │◀── result ────│   │ (Qwen) │  │
  │      │              │   └────────┘  │
  └──────┘              └──────────────┘
```

### 2.2 核心组件

| 组件 | 位置 | 职责 |
|------|------|------|
| TAA 主服务 | `main.go` | 启动入口，密钥生成，注册，HTTP 服务 |
| 控制器 | `internal/controller/` | HTTP 路由、导入/导出/审计/阶段切换逻辑 |
| 远程证明 | `internal/attestation/` + `attestation/` | 调用 CSV 硬件生成远程证明报告 |
| 安全审计 | `internal/security/` | Python 代码静态扫描 + LLM 语义验证 |
| 加密工具 | `taa/crypto` | SM2 信封加密/解密，SM4-GCM |
| Ollama/Qwen | `ollama-qwen2.5-coder-0.5b/` | 本地 LLM 推理，用于代码审计的语义验证 |

## 3. 启动流程

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TAA 启动 (main.go)                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. 解析启动参数 (-debug, -addr, -security-scan 等)                  │
│  2. 生成 SM2 密钥对 (taaKeyPair)                                    │
│  3. 计算 USERDATA = SM3(publicKey + dockerId + platformIP + timestamp)│
│  4. 调用 attestation helper 生成远程证明报告 (report.cert)             │
│     └─ ATTESTATION_USERDATA 环境变量传入自定义 userdata                │
│  5. POST /v1/taa/register → 平台注册                                 │
│     └─ 携带: dockerId, attestation(base64), taaPublicKey,            │
│              attestationValues(JSON), timestamp, verifiedPass        │
│  6. 初始化 TAAState，启动 HTTP 服务 (默认 :6001)                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.1 启动参数

| 参数 | 环境变量 | 默认值 | 说明 |
|------|---------|--------|------|
| `-debug` | — | `false` | 调试模式：跳过训练，导出原始产物 |
| `-addr` | — | `:6001` | HTTP 监听地址 |
| `-security-scan` | `SECURITY_SCAN` | `true` | 启用代码安全扫描 |
| `-result-check` | `RESULT_CHECK` | `true` | 启用导出结果泄露检查 |
| `-security-llm-verify` | `SECURITY_LLM_VERIFY` | `true` | 启用 LLM 语义验证 |
| `-security-llm-endpoint` | `SECURITY_LLM_ENDPOINT` | `http://127.0.0.1:11434` | Ollama 端点 |
| `-security-llm-model` | `SECURITY_LLM_MODEL` | `qwen2.5-coder:0.5b` | LLM 模型名 |
| `-model-dir` | `MODEL_DIR` | `/opt/taa/models` | 模型代码目录 |
| `-data-dir` | `DATA_DIR` | `/opt/taa/data` | 数据目录 |
| `-result-dir` | `RESULT_DIR` | `/opt/taa/results` | 结果目录 |

## 4. API 接口

### 4.1 接口路由

| 接口 | 方法 | 说明 |
|------|------|------|
| `/v1/taa/switch` | POST | 切换阶段 (1→2→3) |
| `/v1/taa/import` | POST | 导入资源（模型/测试数据/训练数据） |
| `/v1/taa/export` | POST | 导出结果 |
| `/v1/taa/getAttestation` | POST | 重新获取远程证明报告 |
| `/v1/taa/reportRes` | POST | 平台向 TAA 上报结果状态 |
| `/v1/taa/health` | GET | 健康检查 |
| `/v1/taa/logs` | POST | 查询日志 |
| `/v1/taa/status` | GET | 查询状态 |

### 4.2 公共返回格式

```json
{
  "msg": "success",
  "result": { ... },
  "error": 0
}
```

## 5. 阶段流程

### 5.1 阶段切换

```
Phase 1 (调试)     Phase 2 (测试)     Phase 3 (正式训练)
┌──────────┐      ┌──────────┐      ┌──────────────┐
│ type=1   │  →   │ type=2   │  →   │ type=3       │
│ 模型+代码 │      │ 测试数据  │      │ 训练数据      │
│ debug.sh │      │ train.sh │      │ train.sh     │
│ +审计     │      │ +审计    │      │ 无审计        │
└──────────┘      └──────────┘      └──────────────┘
```

### 5.2 导入流程 (`/v1/taa/import`)

```
平台发送 import 请求 (resourceUrl, type, taskId, requestId)
                    │
                    ▼
          ┌─── 下载密文文件 ───┐
          │   HTTP GET URL     │
          │   → /tmp/taa-*     │
          └────────┬───────────┘
                   ▼
          ┌─── 解密 ───────────────────────────────────┐
          │  拆分: WrappedKey(129B) || AES-GCM密文      │
          │  SM2 私钥解包 → AES 数据密钥                 │
          │  AES-256-GCM 解密 → 明文归档包               │
          └────────┬───────────────────────────────────┘
                   ▼
          ┌─── 解压 ───────────────────────────────────┐
          │  自动检测格式: tar.gz / zip / tar            │
          │  type=1 → ModelDir  (/opt/taa/models)      │
          │  type=2,3 → DataDir (/opt/taa/data)        │
          │  .sh 文件自动 chmod +x                      │
          └────────┬───────────────────────────────────┘
                   ▼
         ┌─────────────────────────┐
         │  DebugMode == true ?    │
         └────┬─────────────┬─────┘
           YES│             │NO
              ▼             ▼
    ┌─────────────┐   ┌────────────────────────────────────┐
    │  调试模式     │   │           生产模式                   │
    ├─────────────┤   ├────────────────────────────────────┤
    │             │   │                                    │
    │ 保存调试产物  │   │  Phase 1 (type=1):                 │
    │ resultDir/  │   │    执行 debug.sh                    │
    │  debug/     │   │    代码安全审计                      │
    │  <taskId>/  │   │    生成报告 → 上报平台               │
    │  input.bin  │   │                                    │
    │  manifest   │   │  Phase 2 (type=2):                 │
    │             │   │    执行 train.sh                    │
    │ 生成模板报告  │   │    代码安全审计                      │
    │ debug_mode  │   │    生成报告 → 上报平台               │
    │  = true     │   │                                    │
    │             │   │  Phase 3 (type=3):                 │
    │ 上报平台     │   │    执行 train.sh                    │
    │ code=0      │   │    无审计                           │
    │             │   │    生成报告 → 上报平台               │
    └─────────────┘   └────────────────────────────────────┘
```

### 5.3 导出流程 (`/v1/taa/export`)

```
    平台发送 export 请求 (taskId, publicKey?)
                    │
                    ▼
          ┌─────────────────────┐
          │  DebugMode == true ? │
          └────┬──────────┬─────┘
            YES│          │NO
               ▼          ▼
    ┌──────────────┐  ┌──────────────────────────────┐
    │   调试模式    │  │        生产模式                │
    ├──────────────┤  ├──────────────────────────────┤
    │              │  │                              │
    │ 读取调试产物   │  │ 读取 result.bin              │
    │ debug/<tid>/ │  │                              │
    │ input.bin    │  │ 无 publicKey → 明文导出       │
    │              │  │ 有 publicKey → SM2 信封加密   │
    │ Phase 1/2:   │  │                              │
    │  无key→明文   │  └──────────────────────────────┘
    │  有key→加密   │
    │              │
    │ Phase 3:     │
    │  无key→400   │
    │  有key→加密   │
    └──────────────┘
```

### 5.4 上报流程 (TAA → 平台)

```
TAA 内部                           平台
────────                          ────

reportTrainingAsync()
     │
     ├─ POST /v1/taa/reportRes          (训练/调试结果报告)
     │
     └─ POST /v1/taa/reportResourceRes  (资源下载结果通知)
```

## 6. 代码安全审计

### 6.1 审计架构

```
    scanner.ScanDir(ModelDir)
            │
            ▼
    ┌─── 遍历 Python 文件 ───┐
    │  匹配 rules.go 中的规则  │
    │  - 网络外联 (NET_*)     │
    │  - 文件读写 (FILE_*)    │
    │  - 系统调用 (SYS_*)     │
    │  - 动态执行 (DYN_*)     │
    └────────┬───────────────┘
             ▼
      []Finding (可疑项)
             │
             ▼
    verifier.VerifyFindings()
             │
             ▼
    ┌─── LLM 语义验证 ───────┐
    │  llm.Client → Ollama   │
    │  http://127.0.0.1:11434│
    │  模型: qwen2.5-coder   │
    │                        │
    │  对每个 Finding 判断:    │
    │  - true_positive (确认) │
    │  - false_positive (误报)│
    │  - uncertain (不确定)   │
    └────────┬───────────────┘
             ▼
      AuditReport
      (passed/failed, risk_level, findings[])
```

### 6.2 源码文件

| 文件 | 行数 | 职责 |
|------|------|------|
| `internal/security/audit.go` | 434 | 审计入口，协调扫描+LLM验证，生成 `AuditReport` |
| `internal/security/scanner.go` | 314 | 静态扫描引擎，遍历 Python 文件匹配安全规则 |
| `internal/security/rules.go` | 227 | 安全规则定义，`Finding` 类型和严重级别 |
| `internal/security/llm.go` | 244 | Ollama/Qwen 客户端 |
| `internal/security/verifier.go` | 297 | LLM 语义验证，过滤误报 |
| `internal/security/result_checker.go` | 208 | 导出结果明文泄露检测 |

## 7. 远程证明

### 7.1 证明流程

1. TAA 启动时调用 `attestation/get-attestation` helper
2. Helper 通过 CSV 硬件（vmmcall 或 ioctl）获取远程证明报告
3. 报告包含 USERDATA（SM3 哈希）、MNONCE、DIGEST、CHIP_ID
4. 注册时报告以 Base64 编码发送给平台
5. `/v1/taa/getAttestation` 可重新生成报告（复用启动时的 USERDATA）

### 7.2 USERDATA 构成

```
USERDATA = SM3(taaPublicKey || dockerId || platformIP || timestamp)
```

- 64 字节（SM3 输出 32 字节，重复填充到 64 字节）
- 通过 `ATTESTATION_USERDATA` 环境变量传入 helper
- 绑定 TAA 公钥、容器、平台与 TEE 硬件

### 7.3 attestationValues 字段

```json
{
  "userdata": "098e3d33...",
  "mnonce": "dc4f8eb0...",
  "digest": "afb78b2e...",
  "chipId": "..."
}
```

## 8. 调试模式

### 8.1 启用方式

```sh
# 启动参数
./taa -debug -addr :6001

# 部署脚本
TAA_DEBUG_MODE=true ./deploy.sh taa
```

### 8.2 行为差异

| 行为 | 生产模式 | 调试模式 |
|------|---------|---------|
| 解密/解压 | ✅ 执行 | ✅ 执行 |
| debug.sh / train.sh | ✅ 执行 | ❌ 跳过 |
| 代码安全审计 | ✅ 执行 | ❌ 跳过 |
| 结果报告 | 真实训练报告 | 模板报告 (`debug_mode: true`) |
| 调试产物 | 无 | `resultDir/debug/<taskId>/input.bin` + `manifest.json` |
| 导出 Phase 1/2 无 key | result.bin 明文 | 原始输入包明文 |
| 导出 Phase 1/2 有 key | result.bin 加密 | 原始输入包加密 |
| 导出 Phase 3 无 key | result.bin 明文 | 400 错误 |
| 导出 Phase 3 有 key | result.bin 加密 | 原始输入包加密 |

## 9. 加密方案

### 9.1 SM2 信封加密

```
明文 → AES-256-GCM 加密 → 密文
              ↑
        随机 AES 数据密钥
              │
              └→ SM2 公钥加密 → WrappedKey (129 bytes)

输出格式: WrappedKey(129B) || Ciphertext(可变长)
```

### 9.2 密钥关系

- **TAA SM2 密钥对**：启动时随机生成，公钥注册到平台
- **AES 数据密钥**：每次加密随机生成，用 TAA SM2 公钥包装
- **平台 SM2 密钥对**：导出时由平台提供公钥，TAA 用于加密结果

## 10. 部署

### 10.1 部署脚本

```sh
# 全部部署
./deploy.sh

# 单独部署
./deploy.sh platform-mock   # 平台模拟器
./deploy.sh taa              # TAA 服务
./deploy.sh qwen             # Ollama/Qwen LLM
```

### 10.2 部署流程

```
本地构建 → scp 到远程宿主机 → kubectl cp 到容器 → 容器内启动
```

### 10.3 容器内目录结构

```
/taatest/
├── taa                          TAA 二进制
├── attestation.report           远程证明报告
├── attestation/
│   └── get-attestation          证明 helper
├── hrk.cert                     HRK 根证书
├── hsk_cek.cert                 HSK/CEK 证书
└── ollama-qwen2.5-coder-0.5b/  Ollama 离线包
    ├── ollama                   Ollama 二进制
    ├── start-ollama.sh          启动脚本
    ├── models/                  模型文件
    └── lib/                     运行时库
```

## 11. 项目目录结构

```
tee/
├── main.go                      启动入口
├── Makefile                     构建命令
├── deploy.sh                    部署脚本
├── go.mod                       Go 模块定义
├── internal/
│   ├── controller/              HTTP 路由和控制器
│   │   ├── route.go             路由注册、TAAState、handler
│   │   ├── import_processing.go 导入流程（解密、解压、训练）
│   │   ├── debug_mode.go        调试模式辅助函数
│   │   ├── report.go            上报平台逻辑
│   │   ├── register.go          注册逻辑
│   │   ├── platform_client.go   平台 HTTP 客户端
│   │   └── log_store.go         结构化日志存储
│   ├── attestation/             远程证明
│   │   ├── generate.go          调用 helper 生成报告
│   │   └── report.go            报告字段提取
│   ├── security/                代码安全审计
│   │   ├── audit.go             审计入口
│   │   ├── scanner.go           静态扫描引擎
│   │   ├── rules.go             安全规则定义
│   │   ├── llm.go               Ollama LLM 客户端
│   │   ├── verifier.go          LLM 语义验证
│   │   └── result_checker.go    导出结果泄露检测
│   ├── sm2/                     SM2 国密椭圆曲线实现
│   └── sm3/                     SM3 国密哈希算法实现
├── attestation/                 远程证明 C 工具链
│   ├── get-attestation          ioctl 模式 helper
│   ├── vmmcall-get-attestation  vmmcall 模式 helper
│   ├── csv_sdk/                 CSV SDK (C)
│   └── csv-guest.c              内核驱动
├── models/                      模型项目
│   ├── LogisticRegression/      逻辑回归模型
│   ├── TEE-test/                MNIST/CIFAR-10 测试
│   └── Retina-DKD/              视网膜疾病模型
├── ollama-qwen2.5-coder-0.5b/  Ollama 离线包
├── cmd/platform-mock/           平台模拟器
└── docs/                        文档
    ├── taa接口设计文档.md
    └── TAA设计文档.md            (本文件)
```
