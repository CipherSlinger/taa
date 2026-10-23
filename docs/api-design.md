# TAA 接口设计文档

## 目录

- [1. 前置要求](#1-前置要求)
- [2. 公共返回格式](#2-公共返回格式)
  - [2.1 接口一览](#21-接口一览)
    - [2.1.1 TAA → 平台（回调与上报接口）](#211-taa--平台回调与上报接口)
    - [2.1.2 平台 → TAA（业务与控制接口）](#212-平台--taa业务与控制接口)
    - [2.1.3 内部回调（FHE 服务 → TAA）](#213-内部回调fhe-服务--taa)
    - [2.1.4 调试接口（平台 → TAA）](#214-调试接口平台--taa)
- [3. TAA → 平台](#3-taa--平台)
  - [3.1 TAA 启动后生成远程证明报告并通知平台（/v1/taa/register）](#31-taa-启动后生成远程证明报告并通知平台v1taaregister)
  - [3.2 TAA 上报训练完成结果（/v1/taa/reportRes）](#32-taa-上报训练完成结果v1taareportres)
  - [3.3 TAA 上报模型导入结果（/v1/taa/reportModelImport）](#33-taa-上报模型导入结果v1taareportmodelimport)
  - [3.4 TAA 上报代码安全审计结果（/v1/taa/reportAudit）](#34-taa-上报代码安全审计结果v1taareportaudit)
  - [3.5 TAA 上报任务终端日志（/v1/taa/modelLog）](#35-taa-上报任务终端日志v1taamodellog)
  - [3.6 TAA 上报运行日志（/v1/taa/taaLog）](#36-taa-上报运行日志v1taataalog)
  - [3.7 TAA 上报任务进度（/v1/taa/reportProgress）](#37-taa-上报任务进度v1taareportprogress)
- [4. 平台 → TAA](#4-平台--taa)
  - [4.1 获取远程证明报告（/v1/taa/getAttestation）](#41-获取远程证明报告v1taagetattestation)
    - [4.1.1 远程证明报告二进制格式](#411-远程证明报告二进制格式)
  - [4.2 资源信息获取（/v1/taa/getResourceInfo）](#42-资源信息获取v1taagetresourceinfo)
  - [4.3 下发资源数据（/v1/taa/import）](#43-下发资源数据v1taaimport)
  - [4.4 下发模型资源（/v1/taa/importModel）](#44-下发模型资源v1taaimportmodel)
  - [4.5 中止当前训练任务（/v1/taa/stopTraining）](#45-中止当前训练任务v1taastoptraining)
  - [4.6 通知 TAA 阶段切换（/v1/taa/switch）](#46-通知-taa-阶段切换v1taaswitch)
  - [4.7 请求 TAA 导出结果（/v1/taa/export）](#47-请求-taa-导出结果v1taaexport)
- [5. 内部回调（FHE 服务 → TAA）](#5-内部回调fhe-服务--taa)
  - [5.1 FHE 服务终态回调（/v1/taa/fheCallback）](#51-fhe-服务终态回调v1taafhecallback)
- [6. 调试接口](#6-调试接口)
  - [6.1 连通性检查（/v1/taa/health）](#61-连通性检查v1taahealth)
  - [6.2 查询 TAA 完整状态（/v1/taa/status）](#62-查询-taa-完整状态v1taastatus)

---

## 1. 前置要求

TAA 所在 Pod 容器需提供以下运行参数：

```env
PLATFORM_IP={IP}:{PORT}
DOCKER_ID=xxxxxxxxx
CONTRACT_ID=合约ID（预留）
LLM_IP={IP}:{PORT}
```

```env
# 路径约定（默认模板；以配置文件为准）
/opt/taa/input/           # 输入目录（只读权限路径 READ_ONLY）
/opt/taa/output/result/   # 训练代码结果输出目录（写权限路径 READ_WRITE）
/opt/taa/output/log       # 模型终端日志目录（写权限路径 READ_WRITE）
/opt/taa/output/progress  # 训练进度目录（写权限路径 READ_WRITE）
```

**实例类型**（配置项 `server.type`）：同一份二进制按该值走不同链路，本文各接口都会标注类型差异。

| 取值 | 说明 |
| --- | --- |
| `tee`（默认） | CSV 客户机里的训练实例：导入模型与数据、代码审计、训练、加密导出 |
| `fhe` | GPU 宿主机上的 FHE 编排实例：数据下发即提交 FHE 任务，无训练、无审计，导出为明文结果包 |
| `data-anaylsis` | 数据落盘实例：只解密并保存数据（注意该字面值就是拼错的 `anaylsis`），不训练、不审计、不接受模型 |

## 2. 公共返回格式

Agent 公共请求返回参数如下：

```json
{
  "msg": "操作成功",
  "result": null,
  "error": 0
}
```

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `msg` | `string` | 返回信息 |
| `result` | `object/null` | 业务返回结果；无业务返回时为 `null` |
| `error` | `number` | 错误码，`0` 表示成功，非 `0` 表示失败；失败时与 HTTP 状态码一致（`400`/`404`/`405`/`409`/`500`） |

**方法与跨域**：TAA 对外暴露的每个路由都只接受 `POST`。

- 所有响应都带 `Access-Control-Allow-Origin: *`、`Access-Control-Allow-Methods: POST, OPTIONS`、`Access-Control-Allow-Headers: Content-Type`，
  以及 `Access-Control-Expose-Headers: Content-Disposition, Content-Length, X-TAA-Task-Id, X-TAA-Encrypted`（导出接口的响应头需要被浏览器读到）。
- `OPTIONS` 预检直接返回 `204 No Content`，不带响应体。
- 其他方法返回 `405`，带 `Allow: POST` 头：

```jsonc
{
  "msg": "仅支持 POST 方法",
  "result": null,
  "error": 405
}
```

### 2.1 接口一览

#### 2.1.1 TAA → 平台（回调与上报接口）

| 序号 | 接口 | 方法 | 功能说明 |
| --- | --- | --- | --- |
| 1 | `/v1/taa/register` | `POST` | TAA 启动后生成远程证明报告并通知平台 |
| 2 | `/v1/taa/reportRes` | `POST` | TAA 上报训练完成结果 |
| 3 | `/v1/taa/reportModelImport` | `POST` | TAA 上报模型导入与完整性校验结果 |
| 4 | `/v1/taa/reportAudit` | `POST` | TAA 上报模型代码安全审计结果 |
| 5 | `/v1/taa/modelLog` | `POST` | TAA 上报任务终端日志 |
| 6 | `/v1/taa/taaLog` | `POST` | TAA 上报内部运行日志 |
| 7 | `/v1/taa/reportProgress` | `POST` | TAA 上报任务数值进度 |

#### 2.1.2 平台 → TAA（业务与控制接口）

| 序号 | 接口 | 方法 | 功能说明 |
| --- | --- | --- | --- |
| 1 | `/v1/taa/getAttestation` | `POST` | 平台获取远程证明报告 |
| 2 | `/v1/taa/import` | `POST` | 平台下发数据资源（`tee`/`fhe` 触发训练或 FHE 任务，`data-anaylsis` 仅落盘） |
| 3 | `/v1/taa/importModel` | `POST` | 平台下发模型训练代码 |
| 4 | `/v1/taa/getResourceInfo` | `POST` | 平台传入 resourceUrl，TAA 下载、解密、分析后返回资源信息，按 SM3 哈希持久化保存目录与唯一标识备份 |
| 5 | `/v1/taa/switch` | `POST` | 平台通知 TAA 切换运行阶段 |
| 6 | `/v1/taa/export` | `POST` | 平台请求 TAA 导出任务结果目录压缩包，成功时直接返回文件流 |
| 7 | `/v1/taa/stopTraining` | `POST` | 平台同步请求 TAA 中止当前训练任务（`fhe` 实例上取消 FHE 任务） |

#### 2.1.3 内部回调（FHE 服务 → TAA）

| 序号 | 接口 | 方法 | 功能说明 |
| --- | --- | --- | --- |
| 1 | `/v1/taa/fheCallback` | `POST` | FHE 服务通知任务终态；仅接受本机环回地址，非 `fhe` 实例返回 404 |

#### 2.1.4 调试接口（平台 → TAA）

| 序号 | 接口 | 方法 | 功能说明 |
| --- | --- | --- | --- |
| 1 | `/v1/taa/health` | `POST` | 平台检查 TAA 连通性 |
| 2 | `/v1/taa/status` | `POST` | 查询 TAA 完整状态信息 |

---

## 3. TAA → 平台

### 3.1 TAA 启动后生成远程证明报告并通知平台（/v1/taa/register）

TAA 服务启动时先生成随机 SM2 公私钥对（若注入了环境变量 `TAASECRETKEY`，则从中恢复既有私钥），生成远程证明报告后，再调用平台注册接口。

**请求**：`POST http://{PLATFORM_IP}/v1/taa/register`

**请求内容类型**：`application/json`

**触发时机**：TAA 启动后主动调用平台接口；平台返回 HTTP `200` 即表示注册通知成功。请求失败或平台返回非 `200` 时，TAA 在后台退避重试：首次等待 `5s`，此后每次翻倍，上限 `30s`，整个重试窗口为 **5 分钟**；窗口耗尽后放弃并记录日志，不再重试。窗口按分钟计是刻意的——TAA 在 Kata CSV2 客户机里是第一个用户态进程，首次注册必然早于客户机拿到 IP，而重试日志落在客户机 tmpfs 上，无限重试会一直占用客户机内存。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | docker id |
| `attestation` | `string` | 是 | 远程证明报告文件，Base64 编码格式（原始 2548 字节 → 编码后约 3400 字符） |
| `taaPublicKey` | `string` | 是 | TAA 启动时生成（或从 `TAASECRETKEY` 恢复）的 SM2 公钥 PEM（国密标准） |
| `taaSecretKey` | `string` | 否 | 加密后的 TAA SM2 私钥，hex 小写编码（60 字节 → 120 字符）。仅在 CSV 环境下、且本次启动**未**从 `TAASECRETKEY` 恢复私钥时携带；恢复模式与非 CSV 实例省略该字段 |
| `attestationValues` | `string` | 是 | attestation report 核心字段提取的 JSON **字符串**，即 `{"userdata","mnonce","digest","chipId"}`：`userdata` 为 hex（报告里的 64 字节原值，**不转 PEM**），`mnonce`/`digest` 为 hex，`chipId` 为 ASCII 原文（去掉尾部 NUL）。字段含义见 [4.1 节](#41-获取远程证明报告v1taagetattestation) |
| `timestamp` | `string` | 是 | 生成 attestation 时的 Unix 时间戳（秒），随注册请求单独上报；不参与 USERDATA 构成 |
| `verifiedPass` | `bool` | 是 | TAA 验证远程证明报告结果，`true` 表示成功，`false` 表示失败 |
| `authInfo` | `object/null` | 否 | 当前固定传 `null` |

**Base64 编码说明**：
- 原始报告大小：`0x9F4` = 2548 字节
- Base64 编码后大小：约 3400 字符（计算公式：`ceil(2548 / 3) * 4 = 3400`）
- 编码会增加约 33% 的体积

**`taaSecretKey` 生成与恢复**：
- `sk = SM3(csv sealing key(32 字节) || CONTRACT_ID)[:16]`；`CONTRACT_ID` 按 UTF-8 原始字节拼接，无分隔符。
- `ct = SM4-128-GCM(sk, D)`，`D` 是 SM2 私钥的 32 字节大端裸标量（不是 PEM）。GCM nonce 随机生成并前置，因此密文固定 60 字节，hex 为 120 个小写字符。
- 平台保存该值；TAA 的 keys 目录丢失后，平台把它作为环境变量 `TAASECRETKEY` 注入。TAA 用同一 CSV sealing key 与 CONTRACT_ID 解密、重算 `Q = d·G`，并以**不含** `taaSecretKey` 的请求重新注册。
- 非 CSV 实例（`storage.stateSealingKeySource: "sm2"`，如 docker/FHE）既不生成该字段，也不接受 `TAASECRETKEY`。
- 同一私钥每次启动得到的 `taaSecretKey` 不同（随机 nonce），不能用作实例唯一标识；`CONTRACT_ID` 或宿主硬件 key 变化会让旧值解不开，启动 fail-closed。

**请求示例**：

```sh
# 先将报告文件 Base64 编码
ATTESTATION_BASE64=$(base64 -w 0 attestation.report)

curl -X POST "http://${PLATFORM_IP}/v1/taa/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"dockerId\": \"${DOCKER_ID}\",
    \"attestation\": \"${ATTESTATION_BASE64}\",
    \"taaPublicKey\": \"${TAA_PUBLIC_KEY}\",
    \"attestationValues\": \"${ATTESTATION_VALUES_JSON}\",
    \"timestamp\": \"${TIMESTAMP}\",
    \"verifiedPass\": true,
    \"authInfo\": null
  }"
```

**成功判定**：平台返回 HTTP `200`。

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `received` | `bool` | 平台是否成功接收注册请求 |
| `verifiedPass` | `bool` | 平台验证结果：`true` 表示验证通过，`false` 表示验证失败 |

**成功响应示例**（200 OK）

```jsonc
{
  "msg": "success",
  "result": {
    "received": true,
    "verifiedPass": true
  },
  "error": 0
}
```

### 3.2 TAA 上报训练完成结果（/v1/taa/reportRes）

**请求**：`POST /v1/taa/reportRes`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | 取值为容器启动参数 `DOCKER_ID` |
| `requestId` | `string` | 是 | 启动测试时对应的请求 ID |
| `taskId` | `string` | 否 | 训练任务 ID |
| `code` | `number` | 是 | `0` 成功；`1` 训练执行失败；`2` 训练执行完成但结果被拒（结果目录含原始训练数据，见下方说明）；`3` FHE 任务失败（仅 `fhe` 实例） |
| `msg` | `string` | 否 | 失败时为失败原因 |
| `report` | `string` | 否 | 训练结果报告字符串；`data-anaylsis` 实例上恒为空字符串 |

> **`code=3`（FHE 任务失败）**：`fhe` 实例上，FHE 服务执行失败或结果包取回落盘失败都按 `3` 上报，`msg` 为 `FHE 任务失败: <原因>` 或 `取回 FHE 结果失败: <原因>`。它刻意不复用 `1`：两种实例类型的失败原因不同，同一个码会让平台的日志无法区分。
>
> **`data-anaylsis` 实例**：该类型既无训练报告也无可审计的内容，落盘成功与失败都走本接口上报（`code` 为 `0` / `1`），`report` 恒为空字符串，`msg` 为 `数据导入成功` 或具体失败原因。

**示例**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "xx",
  "taskId": "task-001",
  "code": 0,
  "msg": null,
  "report": "{\"generated_at\":\"2026-09-02T10:03:43Z\",\"report_id\":\"train-report-20260902-100343-ae53fa14\",\"dataset\":{\"total_samples\":12500,\"splits\":{\"train\":10000,\"test\":1000},\"checksum\":{\"size\":540672,\"algorithm\":\"sm3\",\"value\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}},\"training_task\":{\"task_id\":\"task-20260825-001\",\"status\":\"succeeded\",\"exit_code\":0,\"failure_reason\":null,\"started_at\":\"2026-09-02T10:03:35Z\",\"finished_at\":\"2026-09-02T10:03:43Z\",\"duration_seconds\":8,\"model_checksum\":{\"size\":581632,\"algorithm\":\"sm3\",\"value\":\"a1b2c3d4e5f67890abcdef1234567890abcdefabcdefabcdefabcdefabcd\"},\"metrics\":{\"final_accuracy\":0.9087,\"final_loss\":0.2145,\"epochs\":[{\"epoch\":1,\"accuracy\":0.5231,\"loss\":1.2345},{\"epoch\":2,\"accuracy\":0.6789,\"loss\":0.9876}]}},\"result_files\":{\"total_files\":3,\"total_size\":541184,\"total_size_h\":\"528.5KB\",\"tree\":{\"name\":\"result\",\"type\":\"dir\",\"file_count\":3,\"children\":[{\"name\":\"metrics.csv\",\"type\":\"file\",\"fmt\":\"csv\",\"size\":428,\"rows\":2,\"fields\":[{\"name\":\"epoch\",\"type\":\"int\"},{\"name\":\"val_accuracy\",\"type\":\"float\"}],\"preview\":[[\"1\",\"0.5231\"],[\"2\",\"0.6789\"]]},{\"name\":\"model.pt\",\"type\":\"file\",\"fmt\":\"zip\",\"size\":540672}]}},\"codeaudit\":{\"conclusion\":{\"passed\":true,\"risk_level\":\"NONE\",\"summary\":\"\u672a\u53d1\u73b0\u5b89\u5168\u95ee\u9898\uff0c\u4ee3\u7801\u901a\u8fc7\u5ba1\u8ba1\",\"recommendation\":\"\u65e0\u9700\u4fee\u590d\",\"statistics\":{\"high\":0,\"medium\":0,\"low\":0}},\"duration_ms\":12345,\"file_reports\":null}}"
}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `received` | `bool` | 平台是否成功接收训练完成结果上报 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "success",
  "result": {
    "received": true
  },
  "error": 0
}
```

**`report` 字段内容示例**：

```jsonc
{
  "generated_at": "2026-09-02T10:03:43Z",                // 报告生成时间，ISO8601 UTC 格式
  "report_id": "train-report-20260902-100343-ae53fa14",  // 全局唯一报告 ID：train-report-YYYYMMDD-HHMMSS-<8位随机串>
  "dataset": {                                            // 数据集信息
    "total_samples": 12500,                               // 数据集总样本数
    "splits": {                                           // 数据集划分
      "train": 10000,                                     // 训练集样本数
      "test": 1000                                        // 测试集样本数
    },
    "checksum": {                                         // 数据集完整性校验
      "size": 540672,                                     // 数据集原始大小（字节）
      "algorithm": "sm3",                                // 哈希算法：当前实现固定为 sm3
      "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  // 哈希值
    }
  },
  "training_task": {                                      // 训练任务信息
    "task_id": "task-20260825-001",                       // 任务 ID，由平台分配
    "status": "succeeded",                                // 任务状态：succeeded / failed / cancelled / timeout
    "exit_code": 0,                                       // 训练进程退出码，0 表示正常
    "failure_reason": null,                               // 失败原因，成功时为 null
    "started_at": "2026-08-25T10:05:30Z",                 // 任务开始时间
    "finished_at": "2026-08-25T14:28:50Z",                // 任务完成时间
    "duration_seconds": 15800,                            // 总耗时（秒）
    "model_checksum": {                                   // 模型代码及权重压缩包完整性校验（与 /v1/taa/import 一致对明文压缩包计算 SM3）
      "size": 581632,                                     // 压缩包原始大小（字节）
      "algorithm": "sm3",                                // 哈希算法，固定为 sm3
      "value": "a1b2c3d4e5f67890abcdef1234567890abcdefabcdefabcdefabcdefabcd"  // 压缩包 SM3 哈希值
    },
    "metrics": {                                          // 训练指标（TAA 填写）
      "final_accuracy": 0.9087,                           // 最终验证集准确率
      "final_loss": 0.2145,                                // 最终验证集损失
      "epochs": [                                         // 逐 epoch 训练/验证指标（TAA 填写）
        {
          "epoch": 1,                                     // epoch 序号
          "accuracy": 0.5231,                             // 该 epoch 准确率
          "loss": 1.2345                                  // 该 epoch 损失
        }
      ]
    }
  },
  "result_files": {                                       // 导出目录的文件结构（TAA 扫描结果目录生成）
    "total_files": 3,                                     // 结果目录文件总数
    "total_size": 541184,                                 // 结果目录总字节数
    "total_size_h": "528.5KB",                            // 人类可读总大小
    "tree": {                                             // 目录树根节点，结构与 /v1/taa/getResourceInfo 的 tree 完全一致
      "name": "result",
      "type": "dir",
      "file_count": 3,
      "children": [
        {
          "name": "metrics.csv",                          // 表格类文件带 fmt / rows / fields，并带 preview 前 5 行
          "type": "file",
          "fmt": "csv",
          "size": 428,
          "rows": 2,
          "fields": [
            { "name": "epoch", "type": "int" },
            { "name": "val_accuracy", "type": "float" }
          ],
          "preview": [                                    // 前 5 行数据，与 fields 按位置对齐；不出现在导出包里
            [ "1", "0.5231" ],
            [ "2", "0.6789" ]
          ]
        },
        {
          "name": "model.pt",                             // 二进制产物不带解析信息
          "type": "file",
          "fmt": "zip",
          "size": 540672
        }
      ]
    }
  },
  "codeaudit": {                                          // 代码安全审计（TAA 填写）
    "conclusion": {                                       // 审计总体结论
      "passed": true,                                     // 是否通过：true 未发现阻断风险，false 存在高危/恶意
      "risk_level": "NONE",                               // 综合风险等级：NONE / LOW / MEDIUM / HIGH / CRITICAL
      "summary": "未发现安全问题，代码通过审计",           // 审计结论摘要
      "recommendation": "无需修复",                        // 处理建议
      "statistics": {                                     // 大模型 findings 归类统计
        "high": 0,                                        // 大模型归类为高危的数量
        "medium": 0,                                      // 大模型归类为中危的数量
        "low": 0                                          // 大模型归类为低危/良性的数量
      }
    },
    "duration_ms": 12345,                                  // 审计整体耗时（毫秒）：从静态扫描开始到 LLM 语义审查结束，不含审计前的 LLM 可用性探测
    "file_reports": null                                   // 按文件聚合的 findings 明细；null 表示无 findings，存在 findings 时为数组
  }
}
```

> 平台根据所处阶段处理结果报告 `report`：
> phase 1 调试阶段（明文结果返回模型提供方）
> phase 2 测试阶段（明文结果返回平台）
> phase 3 拒绝调用

**关于 `result_files`**：该字段是导出目录（`/v1/taa/export` 打包的那个目录）的文件结构树，节点结构与 [4.2 节](#42-资源信息获取v1taagetresourceinfo) `getResourceInfo` 返回的 `tree` 完全一致——**含表格类文件的 `preview` 前 5 行**，平台据此核对产物并看到样本行。两点差异：

- **不含报告自身**：扫描发生在 `training_report.json` 落盘之前，所以树里不会出现该文件。
- **检查指认泄露时整段不出现**：训练结束时若明文泄露检查（`bytes.Contains`）在结果目录里发现了原始训练数据，该字段**整个不出现**（`code` 为 `2`，原因见 `msg`，报告体内 `training_task.status` 为 `failed`）——目录树的预览就是那些数据行，正是要拒的东西，TAA 连扫都不扫。没有裁决（未开启检查、训练执行失败/崩溃路径）或裁决记着检查自身没跑起来时照常给出该字段：那是没有证据，不是有证据说泄露。

> 报告里的样本行不会外流：`training_report.json` 已被排除在导出清单之外（见 [4.7 节](#47-请求-taa-导出结果v1taaexport)），这份报告只经 `/v1/taa/reportRes` 上报给平台；导出目录中真正会被打包外发的文件照旧受明文泄露检查约束。

目录为空或扫描失败时省略该字段，报告其余部分照常生成。

**关于结果被拒（`code=2`）**：训练结束时若 `codeAudit.resultCheck.enabled` 为 `true` 且检查在结果目录里查出了原始训练数据，TAA 把这次运行按失败上报：

- `code` 为 `2`（区别于 `1`——训练进程本身跑完了，是产物被拒），`msg` 为 `结果目录包含原始训练数据，训练结果拒绝提供目录清单与预览: <高危明细>`；
- 报告体内 `training_task.status` 为 `failed`、`failure_reason` 为同样的原因、**`exit_code` 仍为 `0`**（训练进程正常退出），且不带 `result_files`；
- 随后 `/v1/taa/export` 对该任务一律返回 `400`（见 [4.7 节](#47-请求-taa-导出结果v1taaexport)）。

检查自身没跑起来（裁决里 `error` 非空）不算被拒：报告照常给出、`code` 仍为 `0`，只有导出闸门在 `codeAudit.llm.failClosed` 为 `true` 时会拦。

### 3.3 TAA 上报模型导入结果（/v1/taa/reportModelImport）

**请求**：`POST /v1/taa/reportModelImport`

**请求内容类型**：`application/json`

**触发时机**：TAA 接收 `/v1/taa/importModel` 请求后立即下载资源并异步处理。在资源解封、解密、计算原始压缩包 SM3 checksum 并解压到模型目录后，**立即调用此接口**向平台上报模型导入与完整性校验结果（无需等待代码安全审计完成）。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | 取值为容器启动参数 `DOCKER_ID` |
| `requestId` | `string` | 是 | 与 `/v1/taa/importModel` 请求中的 `requestId` 一致，用于绑定同一轮模型导入 |
| `taskId` | `string` | 否 | 任务 ID，与 `/v1/taa/importModel` 请求中的 `taskId` 一致 |
| `code` | `number` | 是 | `0` 表示模型下载、解密、解压和校验成功，`1` 表示资源下载/解密/解压等导入流程失败 |
| `msg` | `string` | 否 | 成功时固定为 `"模型导入成功"`，失败时为具体失败原因 |
| `checksum` | `object` | 否 | 模型压缩包完整性校验（逻辑与 `/v1/taa/reportRes` 的 `training_task.model_checksum` 完全一致，包含 `size`、`algorithm`、`value`，导入成功时必填） |

> **`fhe` 实例**：模型包按 SM3 解压到 FHE 共享模型目录并激活后，同样经本接口上报（`code=0`、`checksum` 与训练链路同格式）。FHE 模型是一组 FHE 层与参数、不是用户可执行代码，因此**没有对应的 `/v1/taa/reportAudit`**。

**请求示例（成功）**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "request-001",
  "taskId": "task-001",
  "code": 0,
  "msg": "模型导入成功",
  "checksum": {
    "size": 581632,
    "algorithm": "sm3",
    "value": "a1b2c3d4e5f67890abcdef1234567890abcdefabcdefabcdefabcdefabcd"
  }
}
```

**请求示例（失败）**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "request-001",
  "taskId": "task-001",
  "code": 1,
  "msg": "解密失败: SM2 私钥解封对称密钥错误",
  "checksum": null
}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `received` | `bool` | 平台是否成功接收模型导入结果上报 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "success",
  "result": {
    "received": true
  },
  "error": 0
}
```

### 3.4 TAA 上报代码安全审计结果（/v1/taa/reportAudit）

**请求**：`POST /v1/taa/reportAudit`

**请求内容类型**：`application/json`

**触发时机**：TAA 完成模型解压后，对模型代码执行安全审计（静态扫描规则分析 + LLM 语义审查）。审计流程完成后，调用此接口上报审计结论与明细报告。

> **审计结论仅供参考**：模型代码审计与训练流程解耦，审计在后台异步执行，`importModel` 接口不等待审计结论，也不由审计结论触发或阻止训练。无论 `code` 为 `0`、`1` 还是 `2`，模型均保持"已导入"状态，其后的数据下发都会照常触发训练；TAA 不因审计结论删除、回滚或拒绝已导入的模型包及其依赖库。平台如需按审计结论决定是否使用该模型，应在此接口回调中自行处置。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | 取值为容器启动参数 `DOCKER_ID` |
| `requestId` | `string` | 是 | 与 `/v1/taa/importModel` 请求中的 `requestId` 一致，用于绑定同一轮模型导入 |
| `taskId` | `string` | 否 | 任务 ID，与 `/v1/taa/importModel` 请求中的 `taskId` 一致 |
| `code` | `number` | 是 | 审计状态码：<br>• `0`：代码审计通过<br>• `1`：**代码审计未通过**（发现恶意/高危违规代码）<br>• `2`：**未得出结论**——LLM 服务不可用（模型探测失败或服务离线），或审计进程异常中断（含 TAA 崩溃重启后由启动期补报） |
| `msg` | `string` | 否 | 审计结论摘要或异常说明 |
| `report` | `string` | 否 | 代码审计报告 JSON 字符串，格式与训练结果报告中的 `codeaudit` 字段完全一致。当 LLM 服务不可用时可为空字符串 |

**请求示例（审计通过）**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "request-001",
  "taskId": "task-001",
  "code": 0,
  "msg": null,
  "report": "{\"conclusion\":{\"passed\":true,\"risk_level\":\"NONE\",\"summary\":\"未发现安全问题，代码通过审计\",\"recommendation\":\"无需修复\",\"statistics\":{\"high\":0,\"medium\":0,\"low\":0}},\"duration_ms\":12345,\"file_reports\":null}"
}
```

**请求示例（代码审计未通过：检出违规/后门代码）**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "request-001",
  "taskId": "task-001",
  "code": 1,
  "msg": "审计结论: 发现 1 处高危风险代码。存在数据泄露风险，建议拒绝该模型",
  "report": "{\"conclusion\":{\"passed\":false,\"risk_level\":\"CRITICAL\",\"summary\":\"审计结论: 发现 1 处高危风险代码。存在数据泄露风险，建议拒绝该模型\",\"recommendation\":\"建议修复: CMD_001: 移除子进程调用，使用安全的替代方案\",\"statistics\":{\"high\":1,\"medium\":0,\"low\":0}},\"duration_ms\":18342,\"file_reports\":[{\"file\":\"train.py\",\"findings_count\":1,\"high_count\":1,\"risk_level\":\"HIGH\",\"findings\":[{\"rule_id\":\"CMD_001\",\"line\":2,\"severity\":\"HIGH\",\"description\":\"shell 命令执行或危险外部命令\"}]}]}"
}
```

**请求示例（未得出结论：LLM 服务不可用）**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "request-001",
  "taskId": "task-001",
  "code": 2,
  "msg": "LLM 服务不可用，审计未出结论",
  "report": ""
}
```

**请求示例（审计中断：TAA 异常崩溃重启后补报）**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "request-001",
  "taskId": "task-001",
  "code": 2,
  "msg": "TAA 异常崩溃重启，模型代码审计中断未出裁决，该结论仅供参考（不阻断模型导入与训练），模型包保持上传原样",
  "report": ""
}
```

**`report` 字段内容格式**：与训练结果报告中的 `codeaudit` 字段完全一致，详见 [3.2 节 `report` 字段内容示例](#32-taa-上报训练完成结果v1taareportres) 中的 `codeaudit` 部分。其中 `duration_ms` 为本轮审计的整体耗时（毫秒）：从静态扫描开始，覆盖二进制审计通道与两轮 LLM 语义审查，但不含审计前的 LLM 可用性探测；`report` 为空字符串（LLM 服务不可用或审计中断）时该字段不存在。

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `received` | `bool` | 平台是否成功接收代码安全审计结果上报 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "success",
  "result": {
    "received": true
  },
  "error": 0
}
```

### 3.5 TAA 上报任务终端日志（/v1/taa/modelLog）

**请求**：`POST http://{PLATFORM_IP}/v1/taa/modelLog`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | 取值为容器启动参数 `DOCKER_ID` |
| `requestId` | `string` | 是 | 当前任务请求标识，用于关联同一任务的日志 |
| `taskId` | `string` | 否 | 平台任务 ID；单任务模式下可缺省 |
| `seqStart` | `uint64` | 是 | 本批日志的起始序号 |
| `entries` | `array` | 是 | 日志条目数组，不应为空 |

**`entries` 字段**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `seq` | `uint64` | 是 | 同一 `dockerId + requestId` 下递增的日志序号，用于排序和去重 |
| `message` | `string` | 是 | 日志内容；标准输出、标准错误和 TAA 系统日志统一通过该字段上报 |

**请求示例**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "req-001",
  "taskId": "task-001",
  "seqStart": 41,
  "entries": [
    {
      "seq": 41,
      "message": "epoch=1 loss=0.8234"
    },
    {
      "seq": 42,
      "message": "epoch=1 accuracy=0.9123"
    }
  ]
}
```

平台按 `dockerId + requestId + seq` 去重，允许 TAA 因网络失败重复发送同一日志。TAA 仅在平台返回 HTTP `200`、公共返回格式中的 `error=0` **且** `result.received=true` 时确认本批日志已接收；三者任一不满足即视为本批未送达，条目留在缓冲区里，在下一个 `500ms` 定时刷新时随下一批重发——按状态码区分重试与否、指数退避，本仓库都没有实现。

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `received` | `bool` | 平台是否成功接收本次日志上报 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "success",
  "result": {
    "received": true
  },
  "error": 0
}
```

### 3.6 TAA 上报运行日志（/v1/taa/taaLog）

**请求**：`POST http://{PLATFORM_IP}/v1/taa/taaLog`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | 取值为容器启动参数 `DOCKER_ID` |
| `requestId` | `string` | 是 | 当前任务请求标识，无活跃任务时缺省为 `"system"` |
| `taskId` | `string` | 否 | 平台任务 ID；无活跃任务或单任务模式下可缺省 |
| `seqStart` | `uint64` | 是 | 本批日志的起始序号 |
| `entries` | `array` | 是 | 日志条目数组，不应为空 |

**`entries` 字段**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `seq` | `uint64` | 是 | 同一 `dockerId + requestId` 下递增的日志序号，用于排序和去重 |
| `message` | `string` | 是 | 格式化后的 TAA 运行日志内容（格式为 `[timestamp] [LEVEL] [component] message`） |

**请求示例**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "system",
  "taskId": "",
  "seqStart": 1,
  "entries": [
    {
      "seq": 1,
      "message": "[2026-09-18 18:00:00] [INFO] [controller] TAA server starting on :6001"
    },
    {
      "seq": 2,
      "message": "[2026-09-18 18:00:01] [INFO] [register] register to platform completed"
    }
  ]
}
```

平台按 `dockerId + requestId + seq` 去重，允许 TAA 因网络失败重复发送同一日志。TAA 仅在平台返回 HTTP `200`、公共返回格式中的 `error=0` **且** `result.received=true` 时确认本批日志已接收；三者任一不满足即视为本批未送达，条目留在缓冲区里，在下一个 `500ms` 定时刷新时随下一批重发——按状态码区分重试与否、指数退避，本仓库都没有实现。

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `received` | `bool` | 平台是否成功接收本次日志上报 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "success",
  "result": {
    "received": true
  },
  "error": 0
}
```

### 3.7 TAA 上报任务进度（/v1/taa/reportProgress）

TAA 在任务执行过程中通过该接口向平台上报当前任务的数值进度。

**请求**：`POST http://{PLATFORM_IP}/v1/taa/reportProgress`

**请求内容类型**：`application/json`

**触发时机**：任务执行过程中，TAA 根据进度变化主动上报当前进度快照。**`percent` 为 `100` 的快照不在读到它时上报**：训练收尾后 TAA 还要归集产物、跑结果明文泄露检查，所以 `100%` 被推迟到那次检查出结论之后才补报（模型没写过 `100%` 就不补，平台停在最后一个真实进度；训练失败或任务被中止时也不补）。

`fhe` 实例的进度来自 FHE 服务自己的百分比回调（不读进度文件）：服务每推进一次就上报一次，任务失败时可能停在中间值；任务成功结束后，即使回调没报过 `100`，TAA 也会显式补报一次 `100`，所以 FHE 任务的成功进度一定收在 `100`。

平台按 `dockerId + requestId` 关联进度快照，并依据 `timestamp` 防止较早的进度覆盖较新的进度。同样按日志的确认规则：只有 HTTP `200`、`error=0` 且 `result.received=true` 才算送达。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | 取值为容器启动参数 `DOCKER_ID` |
| `requestId` | `string` | 是 | 当前任务请求标识，用于关联同一任务的进度 |
| `taskId` | `string` | 否 | 平台任务 ID；单任务模式下可缺省 |
| `percent` | `number` | 是 | 当前任务进度百分比，取值范围为 `0` ~ `100` |
| `timestamp` | `string` | 是 | 进度产生时间，RFC3339 格式 |

**请求示例**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "req-001",
  "taskId": "task-001",
  "percent": 35.5,
  "timestamp": "2026-09-15T09:31:00Z"
}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `received` | `bool` | 平台是否成功接收本次进度上报 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "success",
  "result": {
    "received": true
  },
  "error": 0
}
```

---

## 4. 平台 → TAA

### 4.1 获取远程证明报告（/v1/taa/getAttestation）

**请求**：`POST /v1/taa/getAttestation`

**请求内容类型**：`application/json`

**触发时机**：每次请求都会**重新生成**一份远程证明报告（不是返回启动时那份），并用部署时下发的 HRK 与 HSK-CEK 证书对报告做一次自检验证。重新生成带 `30s` 超时，且同一时刻只允许一个请求进入（进程内互斥）。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `requestId` | `string` | 是 | 随机值，用于防重放；为空返回 `400` |

**请求示例**：

```jsonc
{
  "requestId": "req-att-001"
}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `requestId` | `string` | 请求 ID，与请求中的 `requestId` 一致 |
| `verifiedPass` | `bool` | 本报告的自检验证结果：`true` 表示通过，`false` 表示失败 |
| `attestation` | `string` | 远程证明报告，Base64 编码后的二进制内容（`0x9F4` = 2548 字节原始数据）；生成失败时为空字符串 |
| `attestationValues` | `string` (JSON) | 从报告中提取的核心字段，JSON **字符串**（不是嵌套对象），字段见下表 |

**`attestationValues` 反序列化后的字段**：

| 字段 | 类型 | 编码 | 说明 |
| --- | --- | --- | --- |
| `userdata` | `string` | PEM | USERDATA 的 64 字节按 `X(32) ‖ Y(32)` 还原成 SM2 公钥后转成的 PEM，即 TAA 自己的 SM2 公钥 |
| `mnonce` | `string` | hex | 报告中的 `MNONCE`（16 字节） |
| `digest` | `string` | hex | 报告中的 `DIGEST`（32 字节） |
| `chipId` | `string` | **ASCII** | 报告中的 `CHIP_ID`，去掉尾部 `NUL` 填充后的原样字符串，**不是** hex |

> `/v1/taa/register` 上报的 `attestationValues` 与这里同源同格式，差异只有一处：注册路径不把 `userdata` 转成 PEM，保留报告里的 hex 原值。

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "success",
  "result": {
    "requestId": "req-att-001",
    "verifiedPass": true,
    "attestation": "base64-encoded-attestation-report...",
    "attestationValues": "{\"userdata\":\"-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\",\"mnonce\":\"0123...\",\"digest\":\"0123...\",\"chipId\":\"CSV-CHIP-0123456789\"}"
  },
  "error": 0
}
```

> 自检验证失败时 HTTP 仍为 `200`、`error` 仍为 `0`：`verifiedPass` 为 `false`，`msg` 为 `自检验证失败: <原因>`。只有报告本身生成/读取/解析失败时 `attestation` 为空、`msg` 为 `获取报告失败: <原因>`。平台应依据 `verifiedPass` 而不是 HTTP 状态码判断。

**错误响应示例**（400，`requestId` 为空）：

```jsonc
{
  "msg": "requestId 不能为空",
  "result": null,
  "error": 400
}
```

#### 4.1.1 远程证明报告二进制格式

`attestation` 为 Hygon CSV attestation report 二进制结构，总长度 `0x9F4` 字节。多字节整数按小端序解析。

| 偏移 | 长度 | 字段 | 说明 | ANONCE 异或还原 |
| --- | ---: | --- | --- | --- |
| `0x000` | 32 bytes | `PUBKEY_DIGEST` | DH 公钥的 SM3 摘要值，用于确认启动虚拟机的用户身份 | 否 |
| `0x020` | 16 bytes | `ID` | 虚拟机 ID，虚拟机用户自定义 | 否 |
| `0x030` | 16 bytes | `Version` | 虚拟机版本号，虚拟机用户自定义 | 否 |
| `0x040` | 64 bytes | `USERDATA` | 用户自定义数据 | 是 |
| `0x080` | 16 bytes | `MNONCE` | 一次性随机数，用于区别报告内容、防重放攻击，由请求方/虚拟机用户生成 | 是 |
| `0x090` | 32 bytes | `DIGEST` | 虚拟机启动摘要，通常为 initrd、OVMF.fd、内核镜像等启动参数的 SM3 摘要 | 是 |
| `0x0B0` | 4 bytes | `POLICY` | 虚拟机规则 | 是 |
| `0x0B4` | 4 bytes | `SIG_USAGE` | 签名密钥用途，PEK | 是 |
| `0x0B8` | 4 bytes | `SIG_ALGO` | 签名算法，SM2 | 是 |
| `0x0BC` | 4 bytes | `ANONCE` | CSV 固件产生的随机数，用于对报告部分字段做混淆处理，防止主机侧攻击 | 否 |
| `0x0C0` | 144 bytes | `Signature` | PEK 签名，按报告格式定义覆盖 `0x00` ~ `0xBF` | 否 |
| `0x150` | 2084 bytes | `PEK_CERT` | 平台 PEK 证书 | 是 |
| `0x974` | 64 bytes | `CHIP_ID` | 芯片 ID 字符串 | 是 |
| `0x9B4` | 32 bytes | `Reserved2` | 保留字段 | 否 |
| `0x9D4` | 32 bytes | `MAC` | 使用 `MNONCE` 对 `PEK_CERT + CHIP_ID + Reserved2` 生成的 SM3-HMAC | 否 |

---

### 4.2 资源信息获取（/v1/taa/getResourceInfo）

**请求**：`POST /v1/taa/getResourceInfo`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `resourceUrl` | `string` | 是 | 资源下载地址（支持 `.enc` 加密包或普通压缩包） |

**请求示例**：

```jsonc
{
  "resourceUrl": "https://example.com/data/sample.tar.gz.enc"
}
```
**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `result` | `string` | `filetree` 模块解析输出的 JSON 字符串，包含目录树结构、格式统计及资源包 SM3 校验和 |

**`result` 反序列化后的主要字段说明**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `version` | `string` | 工具版本号，如 `"1.0.0"` |
| `generated_at` | `string` | 生成时间戳（RFC3339 格式） |
| `total_files` | `int` | 数据集解压后的文件总数 |
| `total_size` | `int64` | 数据集总字节数 |
| `total_size_h` | `string` | 人类可读的总大小，如 `"528.0KB"` |
| `structured_files` | `int` | 成功解析出 schema / 行数的结构化文件数量 |
| `by_format` | `array` | 按格式汇总的统计列表（含 `format`、`count`、`size_sum`） |
| `checksum` | `object` | 资源包完整性校验信息（与 `/v1/taa/import` 一致对明文压缩包计算 SM3 哈希） |
| `checksum.algorithm` | `string` | 校验和算法，固定为 `"sm3"` |
| `checksum.value` | `string` | 64 位十六进制 SM3 哈希值 |
| `checksum.size` | `int64` | 压缩包原始字节大小 |
| `tree` | `object` | 目录树根节点对象，递归包含子目录和文件的 schema、行数等详细标注 |
| `tree.fields` | `array` | 表格类文件的列定义（`name`、`type`），按解析顺序排列 |
| `tree.preview` | `array` | 表格类文件的**前 5 行数据**，每行是一个数组，与 `tree.fields` **按位置对齐**（不重复列名）；单元格最长 128 字符，超出截断并追加 `…`。仅 CSV / JSONL / JSON 数组 / XLSX / SQLite 产生预览，其余格式不返回该字段 |
| `tree.tables` | `array` | 库类文件（如 SQLite）按表拆分的结构信息，每项含 `name`、`rows`、`columns`、`preview` |
| `tree.tables[].columns` | `array` | 该表的列定义，元素结构同 `fields`，用于解释 `preview` 的列位置 |
| `tree.tables[].preview` | `array` | 该表的前 5 行数据，与 `columns` 按位置对齐 |

> **`preview` 的两个出口**：`getResourceInfo` 是对资源包的一次性应答，平台需要看到样本数据本身；训练报告 `report.result_files` 的结构树与本接口完全一致，**同样带 `preview`**——这份报告只上报给平台，不会进导出包（`training_report.json` 已被排除在导出清单之外）。唯一的例外是泄露被查出的那次：报告干脆不带 `result_files`（见 [3.2 节](#32-taa-上报训练完成结果v1taareportres)），因为预览就是那些数据行。本接口不受此影响。

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "ok",
  "result": "{\n  \"version\": \"1.0.0\",\n  \"generated_at\": \"2026-09-08T10:00:00Z\",\n  \"total_files\": 2,\n  \"total_size\": 540672,\n  \"total_size_h\": \"528.0KB\",\n  \"structured_files\": 1,\n  \"by_format\": [\n    {\"format\": \"csv\", \"count\": 1, \"size_sum\": 340000},\n    {\"format\": \"txt\", \"count\": 1, \"size_sum\": 200672}\n  ],\n  \"checksum\": {\n    \"size\": 540672,\n    \"algorithm\": \"sm3\",\n    \"value\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n  },\n  \"tree\": {\n    \"name\": \"dataset\",\n    \"type\": \"dir\",\n    \"file_count\": 2,\n    \"children\": [\n      {\n        \"name\": \"users.csv\",\n        \"type\": \"file\",\n        \"fmt\": \"csv\",\n        \"size\": 340000,\n        \"rows\": 2000,\n        \"fields\": [\n          {\"name\": \"user_id\", \"type\": \"int\"},\n          {\"name\": \"name\", \"type\": \"str\"}\n        ],\n        \"preview\": [\n          [\"1\", \"alice\"],\n          [\"2\", \"bob\"]\n        ]\n      }\n    ]\n  }\n}",
  "error": 0
}
```

**错误响应示例**：

`resourceUrl` 为空（400）：

```jsonc
{
  "msg": "resourceUrl 不能为空",
  "result": null,
  "error": 400
}
```

下载失败（500）：

```jsonc
{
  "msg": "资源下载失败: ...",
  "result": null,
  "error": 500
}
```

### 4.3 下发资源数据（/v1/taa/import）

**请求**：`POST /v1/taa/import`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `resourceUrl` | `string` | 是 | 数据资源下载地址。密态资源可携带 `?dataKeyCipher=<hex>` 参数承载 SM2 数据密钥信封，见下方说明 |
| `requestId` | `string` | 否* | 随机值，与 `taskId` 不能同时为空；同一 `requestId` 不能重复导入 |
| `taskId` | `string` | 否* | 任务 ID，与 `requestId` 不能同时为空；同一 `taskId` 不能重复导入。`fhe` 实例上必填（见下方说明） |
| `evalKeyUrl` | `string` | 否* | 仅 `fhe` 实例：FHE 求值密钥（`eval_context.bin`）的下载地址。与 `evalKeyFileHash` 必须同时提供；密钥已缓存时不下载，但字段仍必须存在（它同时声明了任务类型与期望的 `userId`） |
| `evalKeyFileHash` | `string` | 否* | 仅 `fhe` 实例：求值密钥的 SM3 摘要，64 位小写十六进制。同时作为 FHE 侧的 `userId` 与密钥缓存目录名 |

> **`fhe` 实例的数据下发**：`server.type=fhe` 时本接口不走训练链路——数据包与求值密钥落盘后直接提交 FHE 任务，任务结果仍通过 `/v1/taa/reportRes` 上报。该类型下 `evalKeyUrl`、`evalKeyFileHash` 与 `taskId` 均为必填：FHE 服务以 `taskId` 命名任务、输入目录与结果目录。`tee` 实例不接受 FHE 字段，携带任一字段返回 400。

> **`data-anaylsis` 实例的数据下发**（`server.type` 的字面值就是 `data-anaylsis`）：该类型只做解密落盘，不训练、不审计、不写导入索引。它用的是另一套 URL 参数，三个都必填：
>
> | 参数 | 说明 |
> | --- | --- |
> | `dataKeyCipher` | SM2 数据密钥信封 hex，与 `fhe`/`tee` 同格式 |
> | `fileName` | 原始上传文件名，需 URL 编码；解码后必须是单个路径元素 |
> | `dataResourceCode` | 资源编号，需 URL 编码；决定落盘子目录 `<storage.data>/<dataResourceCode>/` |
>
> 三个参数都会从下载 URL 中剥离后再发起下载（签名链接因此保持有效）。`fileName`/`dataResourceCode` 解码后不能为空、不能为空白、不能是 `.`/`..`、不能含 `/`、`\`、`NUL`，也不能是绝对路径。资源包（按魔数判定）解压到该目录；Office/EPUB 这类本质是 zip 的文档容器按单文件保存。`evalKeyUrl`/`evalKeyFileHash` 在该类型下被忽略（记日志），不报错。落盘结果仍经 `/v1/taa/reportRes` 上报（成功 `code=0`，`msg` 为 `数据导入成功`）。

> **密态资源的两种形态**（**资源/数据下发与模型下发通用**：`/v1/taa/import` 与 `/v1/taa/importModel` 都接受这两种形态；仅 `/v1/taa/getResourceInfo` 不解析该参数，仍按整文件信封处理）：
> 1. **URL 密钥信封（当前协议）**：`resourceUrl` 形如 `<下载链接>?dataKeyCipher=<hex>`。
>    `dataKeyCipher` 是 SM2 数据密钥信封的 hex 编码（C1C3C2 布局，112 字节不带未压缩点前缀，
>    或 113 字节带 `0x04` 前缀，两者都接受）；**下载链接指向的响应体只含 SM4-GCM 密文**。
>    TAA 在下载前解析并剥离该参数，用 TAA 自身 SM2 私钥解出 16 字节数据密钥后再下载密文；
>    参数重复出现、值为空、hex 非法、长度非法或信封解不开，均在校验阶段返回 400，**不发起下载**。
>    下载体的 SM4 布局两种都接受：`nonce(12) ‖ 密文 ‖ tag(16)`（TAA 与 platform-mock 的口径），
>    或 `版本(1) ‖ nonce(12) ‖ 密文 ‖ tag(16)`（平台前端产出的 `.enc`/`.sm4`，首字节格式版本目前恒为 1）。
>    两者靠 GCM 认证标签区分，最多只有一种能通过校验。
>    其余 query 参数（含签名类参数）逐字节保留，不被重编码；被剥离的 `dataKeyCipher` 不进日志、
>    不进导入索引，因此也不会被转发到实际下载请求。
>    分隔符 `?` 与 `&` 都认：下载链接本身带 query 时（预签名链接都带），即使平台用朴素拼接
>    写成 `<链接>?X-Amz-Signature=<hex>?dataKeyCipher=<hex>`，参数仍能被剥离，剩下的 URL 与
>    「不带信封时应发的那个」逐字节相同，签名依旧有效。
> 2. **整文件信封（兼容形态）**：URL 不带 `dataKeyCipher` 时沿用原逻辑——
>    文件内容为 `WrappedKey(113B) ‖ Ciphertext`，或 `.enc` 后缀强制解密，
>    或按压缩包魔数判定为明文直通。
>
> 信封与密文之间没有显式绑定：SM4-GCM 认证标签是两者唯一的关联，而它只认数据密钥——换上的密文若不是用同一数据密钥加密的，校验必然失败。
>
> 仅 `/v1/taa/getResourceInfo` 不支持该参数：把带 `dataKeyCipher` 的 URL 交给它，该参数会被原样转发到下载请求（并在日志中出现），
> 随后因解不开整文件信封而失败。

**请求示例**：

```jsonc
{
  "resourceUrl": "xx",
  "requestId": "xx",
  "taskId": "xxx"
}
```

`fhe` 实例还须携带求值密钥字段（`taskId` 在该类型下必填）：

```jsonc
{
  "resourceUrl": "xx",
  "requestId": "xx",
  "taskId": "xxx",
  "evalKeyUrl": "xx",
  "evalKeyFileHash": "xx"
}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，该接口成功时 `result` 为 `null`。

**执行规则**：

1. 本接口是**触发训练的唯一入口**（`fhe` 实例上触发的是 FHE 任务，见上）。下载在响应返回前同步完成（下载失败即 500，不进入后续阶段）；此后的解密 → 解压入库 → 上报导入索引异步执行。
2. 数据入库完成后检查训练前置条件——模型已导入（`ModelImported=true`）、无模型导入在飞、无其他训练在飞、已保存的 `runtimeConfig`（模型下发时保存的那份）及其 `commands` 有效。全部满足才执行训练。
3. 条件不满足时的处理：
   - 模型尚未导入、模型仍在导入传输中、已有训练在飞：本次数据仅入库、不训练，TAA 只记日志，不另行上报；训练由后续数据下发重新触发。
   - 已保存的 `runtimeConfig` 为空、解析失败或 `commands` 为空：本次数据保留（索引记录已提交，`requestId`/`taskId` 视为已使用），通过 `/v1/taa/reportRes` 上报一条训练失败结果；平台如需重试，需使用新的 `requestId`/`taskId`。
4. 训练结果（成功或失败）统一通过 `/v1/taa/reportRes` 上报。

**成功响应示例**（200 OK，资源已下载完成，解密、解压与训练结果随后异步处理）：

```jsonc
{
  "msg": "数据已接收，训练结果将通过 reportRes 上报",
  "result": null,
  "error": 0
}
```

`data-anaylsis` 实例的 `msg` 不同：

```jsonc
{
  "msg": "数据已接收，处理中",
  "result": null,
  "error": 0
}
```

> 该响应在资源**下载完成后**才返回：下载失败会返回 500 而不是本响应，因此收到 200 时资源已在 TAA 本地。此后的解密、解压与训练结果是否产生均通过回调体现。

**验证失败响应示例**（400 Bad Request）：

```jsonc
{
  "msg": "resourceUrl 不能为空",
  "result": null,
  "error": 400
}
```

其余 400 场景：`requestId` 和 `taskId` 同时为空；`requestId` 或 `taskId` 已存在或正在处理中；`dataKeyCipher` 重复、为空、hex 非法、长度非法或信封解不开；`fhe` 实例缺少 `evalKeyUrl`/`evalKeyFileHash`/`taskId` 或 `evalKeyFileHash` 格式不符；`tee` 实例携带 `evalKeyUrl` 或 `evalKeyFileHash`；`data-anaylsis` 实例缺少 `dataKeyCipher`/`fileName`/`dataResourceCode`、剥离后无下载地址，或 `fileName`/`dataResourceCode` 不是合法的单个路径元素。

**并发冲突响应示例**（409 Conflict）：

```jsonc
{
  "msg": "当前已有训练任务正在执行中 (taskId: task-001, op: training)，请等待完成后再提交",
  "result": null,
  "error": 409
}
```

其余 409 场景：已有其他任务正在下载或解密（`当前已有任务正在执行中`）。模型代码审计与训练解耦，审计进行中**不阻止**数据下发。

**失败响应示例**（500 Internal Server Error）：

```jsonc
{
  "msg": "下载资源失败: HTTP 404",
  "result": null,
  "error": 500
}
```

其余 500 场景：加载导入索引失败。

### 4.4 下发模型资源（/v1/taa/importModel）

**请求**：`POST /v1/taa/importModel`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `resourceUrl` | `string` | 否* | 模型资源下载地址。密态资源可携带 `?dataKeyCipher=<hex>` 参数承载 SM2 数据密钥信封，见下方说明；为空时表示只更新 `runtimeConfig` 并复用已导入的模型，此时此前必须已导入过模型（**只有** `?dataKeyCipher=<hex>`、没有下载地址的 `resourceUrl` 不算「为空」，按 400 拒绝） |
| `requestId` | `string` | 否* | 随机值，与 `taskId` 不能同时为空 |
| `taskId` | `string` | 否* | 任务 ID，与 `requestId` 不能同时为空 |
| `publicKey` | `string` | 否 | 平台侧 SM2 公钥 PEM，**非必填**。仅 phase 1 且请求携带时校验并保存（已保存过则保留首个公钥）；为空时不校验、不保存、也不返回失败。资源解封使用 TAA 自身私钥，与此参数无关；阶段 3 导出时的公钥选择顺序见 [4.7](#47-请求-taa-导出结果v1taaexport) |
| `runtimeConfig` | `string` | 否 | 运行配置 JSON 字符串（`{"commands":[...]}`）；非空即覆盖已保存的配置，与 `resourceUrl` 是否为空无关 |

> **密态资源的两种形态**（机制与 [4.3 /v1/taa/import](#43-下发资源数据v1taaimport) 完全一致，模型下发同样支持）：
> 1. **URL 密钥信封（当前协议）**：`resourceUrl` 形如 `<下载链接>?dataKeyCipher=<hex>`，下载链接指向的响应体只含 SM4-GCM 密文。TAA 在下载前剥离该参数，用自身 SM2 私钥解出数据密钥后再下载密文；参数重复、值为空、hex 非法、长度非法或信封解不开均直接返回 400，**不发起下载**。被剥离的 `dataKeyCipher` 不进入下载请求，作为投递记录保存的 `resourceUrl` 也只保留剥离后的 URL。
> 2. **整文件信封（兼容形态）**：URL 不带 `dataKeyCipher` 时沿用原逻辑——文件内容为 `WrappedKey(113B) ‖ Ciphertext`，或 `.enc` 后缀强制解密，或按压缩包魔数判定为明文直通。
>
> 解封与下载都正常、但下载体解不开的失败发生在异步阶段，经 `/v1/taa/reportModelImport`（`code=1`，`msg` 含 `解密资源失败` 与 `taaPublicKey:`）上报。

> **实例类型差异**：
> - `data-anaylsis` 实例**直接拒绝本接口**：在解码请求体之前就返回 `400 data-anaylsis 实例不支持模型导入`——该类型没有模型、审计与训练链路，收下模型包只会留下没人读的状态。
> - `fhe` 实例不保存 `publicKey`（导出从不加密），携带时记警告后忽略；`resourceUrl` 为空时**不校验** `runtimeConfig`（FHE 模型由 FHE 运行时加载，训练命令不是它的输入）。`evalKeyUrl`/`evalKeyFileHash` 在本接口上一律忽略并记警告——求值密钥随数据下发提交。
> - 仅 `tee` 实例会解析并执行 `runtimeConfig`。

**请求示例**：

```jsonc
{
  "resourceUrl": "xx",
  "requestId": "xx",
  "taskId": "xxx",
  "publicKey": "xx",
  "runtimeConfig": "{\"commands\":[\"python3 train.py\"]}"
}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，该接口成功时 `result` 为 `null`；导入结果与审计结论分别通过 `/v1/taa/reportModelImport`、`/v1/taa/reportAudit` 异步上报，不在本响应中返回。

**执行规则**：

1. `resourceUrl` 非空：下载（**同步**，在响应返回前完成）→ 响应 200 → 异步：解密 → 计算原始压缩包 SM3 → 解压到模型目录 → **立即**上报 `/v1/taa/reportModelImport`（code=0，携带 SM3）→ 记录 `ModelImported` 与待决审计标记（同一次落盘）→ 后台异步启动代码安全审计。
2. `resourceUrl` 为空：仅更新 `runtimeConfig` 并置 `ModelImported=true`，不下载、不审计。
3. **本接口不触发训练**：训练由数据下发（`/v1/taa/import`）拉起，模型导入完成后等待数据下发。
4. 模型包与其依赖库始终保持上传原样：审计只读、只判、只报，任何结论都不删除、不改写模型目录。

> `ModelImported` 在通过并发检查后、**下载开始前**即置位并落盘，因此下载失败时会显式回滚；进程在下载或解密途中崩溃时，由启动期对账按在飞任务回滚（`reconcileCrashRecovery` 的 `model_import` 分支）。两种情况都不会留下"标记已导入但盘上无模型"的状态。

**成功响应示例**（200 OK，`resourceUrl` 非空：资源已下载完成，解密、解压与审计随后异步执行）：

```jsonc
{
  "msg": "模型已接收，训练结果将通过 reportRes 上报",
  "result": null,
  "error": 0
}
```

> 该消息为历史遗留文案。本接口不触发训练，训练由数据下发（`/v1/taa/import`）拉起，因此这里的 `reportRes` 指后续数据下发所触发的那一轮训练。

**成功响应示例**（200 OK，`resourceUrl` 为空：仅更新模型运行配置）：

```jsonc
{
  "msg": "模型参数命令已导入，等待数据重新导入后执行训练",
  "result": null,
  "error": 0
}
```

**验证失败响应示例**（400 Bad Request）：

```jsonc
{
  "msg": "resourceUrl 不能为空: 之前未传输过且请求中为空",
  "result": null,
  "error": 400
}
```

其余 400 场景：`requestId` 和 `taskId` 同时为空；`publicKey` 解析失败（仅 phase 1 且请求中携带 `publicKey` 时校验）；`resourceUrl` 为空时 `runtimeConfig` 为空、解析失败或 `commands` 为空数组；`dataKeyCipher` 重复、为空、hex 非法、长度非法或信封解不开；`resourceUrl` 剥离 `dataKeyCipher` 后为空（缺少下载地址）。

**并发冲突响应示例**（409 Conflict）：

```jsonc
{
  "msg": "当前已有训练任务正在执行中 (taskId: task-001, op: training)，请等待完成后再提交",
  "result": null,
  "error": 409
}
```

其余 409 场景：`resourceUrl` 非空时，已有其他任务在飞（`当前已有任务正在执行中`）。模型代码审计与训练并行：审计进行中**不阻止**新的模型下发——新模型会中止旧模型的审计（静默中止，不回调 `reportAudit`），下载并覆盖模型目录后，对新模型重新发起审计。训练任务进行中仍会拒绝模型下发。

**下载失败响应示例**（500 Internal Server Error）：

```jsonc
{
  "msg": "下载资源失败: HTTP 404",
  "result": null,
  "error": 500
}
```

> **加密格式说明**：与 `/v1/taa/import` 相同——支持 URL 密钥信封（`?dataKeyCipher=<hex>`）与整文件信封两种形态，解封与解密逻辑完全共用。格式非法或信封解不开在下载前返回 400；密文解不开的失败发生在异步阶段，经 `/v1/taa/reportModelImport`（`code=1`）上报。

### 4.5 中止当前训练任务（/v1/taa/stopTraining）

该接口用于平台请求 TAA 中止当前正在执行的训练任务。TAA 当前为单任务模式，请求不需要传入 `taskId` 或 `requestId`，接口始终针对当前训练任务处理。

**请求**：`POST /v1/taa/stopTraining`

**请求内容类型**：`application/json`

**请求示例**：

```jsonc
{}
```

**处理规则**：

- 接口采用同步处理方式，TAA 等待训练进程及其子进程退出，并完成训练任务状态清理后返回；明确等待上限为 `5s`，超时返回 `500`。
- 当前存在训练任务时，成功中止后返回 HTTP `200`，公共返回格式中的 `error=0`。
- 当前不存在训练任务时，仍返回 HTTP `200`，公共返回格式中的 `error=0`，仅通过 `msg` 提示不存在训练任务；该场景按幂等成功处理。
- 该接口不区分或处理其他非训练任务，也不调用 `modelLog`、`reportProgress` 或 `/v1/taa/reportRes`。

**`fhe` 实例**：FHE 任务没有本地进程组可杀，停止要通过 FHE 服务自己的取消接口，因此该分支排在训练分支之前：

| 场景 | HTTP | `msg` |
| --- | --- | --- |
| 有在飞 FHE 任务且取消成功 | `200` | `FHE 任务已取消` |
| 任务在停止请求到达前已到终态 | `200` | `FHE 任务已结束` |
| 取消失败 | `500` | `取消 FHE 任务失败: <原因>` |
| 当前无 FHE 任务 | `200` | `不存在训练任务` |

**成功响应示例（当前存在训练任务并已中止）**：

```jsonc
{
  "msg": "训练任务已中止",
  "result": null,
  "error": 0
}
```

**成功响应示例（当前不存在训练任务）**：

```jsonc
{
  "msg": "不存在训练任务",
  "result": null,
  "error": 0
}
```

**失败响应示例（500，等待中止超时）**：

```jsonc
{
  "msg": "中止训练任务超时",
  "result": null,
  "error": 500
}
```
```

### 4.6 通知 TAA 阶段切换（/v1/taa/switch）

**请求**：`POST /v1/taa/switch`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `phase` | `number` | 是 | 阶段：`1` 调试，`2` 测试，`3` 正式训练，`4` 推理（预留） |

**请求示例**：

```jsonc
{
  "phase": 1
}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，该接口成功时 `result` 为 `null`。

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "阶段切换成功",
  "result": null,
  "error": 0
}
```

**失败条件**：

- `phase` 不在 `1`–`4`（含缺省为 0）：`400 无效的阶段值: <n>，有效范围 1-4`
- 有任务在飞（训练、FHE、导入下载/解密，或代码审计在跑）：`409 当前已有任务正在执行中 (taskId: <id>, op: <op>)，严禁切换运行阶段`
- 请求体 JSON 解析失败：`400 请求解析失败: ...`

切换成功后会清空当前活跃任务与令牌，并把新阶段落盘（`sealState`）；落盘失败只记错误日志，不影响本次响应。

### 4.7 请求 TAA 导出结果（/v1/taa/export）

该接口用于导出某个任务的结果目录压缩包：目录取自导入索引（`{security.resultDir}/import-index.json`）中按 `requestId`/`taskId` 命中的那条记录。考虑到结果文件可能较大，成功时接口直接返回二进制文件流。

> **打包的是该任务自己的结果目录，文件名取自该目录名**：导出对象是记录里的 `{security.resultDir}/{requestId}-{taskId}`（`resultDir` 默认 `/opt/taa/results`），也就是这次训练执行时 `<out>` 指向的目录；压缩包文件名等于该目录名，即 `{requestId}-{taskId}.zip`，加密导出时追加 `.enc`。`requestId`/`taskId` 在拼进路径前会做文件名净化：非 `A-Za-z0-9-_.` 的字符替换为 `-`，净化后为空的片段落为 `request`（例如只给 `taskId=task-001` 时文件名是 `request-task-001.zip`）。接口不按阶段去挑 `debug`/`train` 子目录。

> **导出用哪把公钥由「记录阶段」决定**：记录的阶段来自该次数据下发（`/v1/taa/import`）落库时的当前阶段；记录里没有阶段（为 0）时回退到当前阶段。阶段只支持 1/2/3，落在其他值（例如 4 推理）时返回 400。

> **`fhe` 实例导出的是服务产出的原始结果包**：FHE 结果在落盘时就是 FHE 服务给的 `output.zip`，按字节原样保存。导出时直接返回这份字节，**不再二次压缩**（否则平台要解两层包），因此文件名是结果目录名加 `.zip`。这类实例**从不加密**：不保存导出公钥，请求里带的 `publicKey` 也会被忽略并记一条警告——调用方期望拿到信封时静默丢弃，只会让它读不出结果。

> 公钥为非必填：能取到公钥就加密导出，取不到就明文导出。阶段 3 的公钥选择顺序为「阶段 1 `/v1/taa/importModel` 保存的公钥 → 本请求的 `publicKey` → 明文」；阶段 1/2 为「本请求的 `publicKey` → 明文」。

> 注意：该接口与其他 TAA 接口不同，**成功响应不是公共 JSON 格式**；只有失败响应继续遵循 [2. 公共返回格式](#2-公共返回格式)。

> **结果泄露检查在训练结束时执行，导出只读结论**：`codeAudit.resultCheck.enabled` 打开时（默认打开），TAA 在训练产物收集完成之后、写 `training_report.json` 之前，对结果目录执行一次明文泄露检查，并把裁决（是否通过、高危项、执行时间）写进 `{RESULT_DIR}/import-index.json` 中该任务的记录。导出接口读取这份裁决、**不再扫描结果目录**，因此收到请求后立即开始传输字节。代价是 fail-closed：裁决不通过、检查自身执行失败、或该记录根本没有裁决（例如由引入该字段之前的版本提交），导出都会被拒绝，其中后两种状态由 `codeAudit.llm.failClosed` 控制——设为 `false` 时它们只记警告并放行，而"裁决不通过"不受该开关影响，始终 400。检查本身不阻断训练——不通过只记日志，训练报告照常上报给平台。

**请求**：`POST /v1/taa/export`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `requestId` | `string` | 否* | 随机值，与 `taskId` 不能同时为空；两者一起用于在导入索引中定位记录，并组成导出文件名 `{requestId}-{taskId}.zip` |
| `publicKey` | `string/null` | 否 | SM2 公钥 PEM。phase 1/2 中为空、缺省或 `null` 时明文导出，非空时使用该公钥做 SM2+SM4-GCM 信封加密；phase 3 中优先使用 phase 1 `/v1/taa/importModel` 保存的公钥，未保存时改用本请求的 `publicKey`，两者都为空时明文导出 |
| `taskId` | `string` | 否* | 任务 ID，与 `requestId` 不能同时为空；用于定位记录并参与文件名；缺省时响应头 `X-TAA-Task-Id` 为空 |

**请求示例（phase 1/2 明文导出）**：

```jsonc
{
  "requestId": "req-export-001",
  "publicKey": null,
  "taskId": "task-001"
}
```

**请求示例（phase 1/2 加密导出）**：

```jsonc
{
  "requestId": "req-export-002",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "taskId": "task-001"
}
```

**导出内容与文件名**：

| 记录阶段 | 明文导出内容 | 文件名 | 加密规则 |
| --- | --- | --- | --- |
| phase 1（调试） | 该任务结果目录压缩得到的 zip | `{requestId}-{taskId}.zip` | 请求 `publicKey` 非空时加密，文件名追加 `.enc` |
| phase 2（测试） | 该任务结果目录压缩得到的 zip | `{requestId}-{taskId}.zip` | 请求 `publicKey` 非空时加密，文件名追加 `.enc` |
| phase 3（正式训练） | 该任务结果目录压缩得到的 zip | `{requestId}-{taskId}.zip` | 优先使用 phase 1 `/v1/taa/importModel` 保存的公钥加密；未保存时使用请求 `publicKey`；两者均为空则明文导出。加密时文件名追加 `.enc` |
| 其他值（如 phase 4 推理） | 暂不支持 | - | 返回 400 |
| `fhe` 实例（任意阶段） | 服务产出的 `output.zip` 原样字节，不再压缩 | `{requestId}-{taskId}.zip` | 从不加密，`publicKey` 被忽略 |

**成功响应内容类型**：`application/octet-stream`

**成功响应头**：

| 响应头 | 说明 |
| --- | --- |
| `Content-Type` | 固定为 `application/octet-stream` |
| `Content-Disposition` | 附件下载文件名：`attachment; filename="{requestId}-{taskId}.zip"`；加密时追加 `.enc` |
| `Content-Length` | 文件大小，单位为字节；加密导出时为加密后的文件大小 |
| `X-TAA-Task-Id` | 任务 ID，与请求中的 `taskId` 一致；`taskId` 缺省时为空 |
| `X-TAA-Encrypted` | 是否加密，`true` 表示响应体为 SM2+SM4-GCM 信封加密结果，`false` 表示响应体为明文 zip 压缩包 |

**成功响应体**：结果文件二进制流。

- `X-TAA-Encrypted: false` 时，响应体为当前阶段结果目录压缩得到的 zip 文件。
- `X-TAA-Encrypted: true` 时，响应体为信封加密后的二进制内容，格式为 `WrappedKey(113B) || SM4-GCM Ciphertext`。

**成功响应示例（200 OK，phase 2 明文导出）**：

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="req-export-001-task-001.zip"
Content-Length: 10485760
X-TAA-Task-Id: task-001
X-TAA-Encrypted: false

<req-export-001-task-001.zip binary stream>
```

**成功响应示例（200 OK，phase 3 加密导出）**：

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="req-export-002-task-001.zip.enc"
Content-Length: 10485901
X-TAA-Task-Id: task-001
X-TAA-Encrypted: true

<WrappedKey(113B) || SM4-GCM Ciphertext>
```

**调用示例**：

```sh
curl -X POST "http://{TAA_ADDR}/v1/taa/export" \
  -H "Content-Type: application/json" \
  -d '{"requestId":"req-export-001","publicKey":null,"taskId":"task-001"}' \
  -o req-export-001-task-001.zip
```

**失败响应内容类型**：`application/json`

**失败响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)。

**失败响应示例**：

```jsonc
{
  "msg": "requestId 和 taskId 不能同时为空",
  "result": null,
  "error": 400
}
```

```jsonc
{
  "msg": "未找到对应记录: requestId=req-export-001 taskId=task-001",
  "result": null,
  "error": 400
}
```

```jsonc
{
  "msg": "结果文件不存在: /opt/taa/results/req-export-001-task-001/training_report.json",
  "result": null,
  "error": 404
}
```

```jsonc
{
  "msg": "当前阶段 4 不支持导出",
  "result": null,
  "error": 400
}
```

```jsonc
{
  "msg": "压缩结果目录失败: 目录不存在: stat /opt/taa/results/req-export-001-task-001: no such file or directory",
  "result": null,
  "error": 500
}
```

```jsonc
{
  "msg": "publicKey 解析失败: ...",
  "result": null,
  "error": 400
}
```

```jsonc
{
  "msg": "导出结果安全检查未通过，存在高危数据泄露隐患: [plaintext_section] 结果文件中检测到明文段: CSV header (training data)",
  "result": null,
  "error": 400
}
```

```jsonc
{
  "msg": "结果安全检查执行失败，拒绝导出: read result dir: permission denied",
  "result": null,
  "error": 500
}
```

```jsonc
{
  "msg": "结果安全检查裁决缺失，拒绝导出（fail-closed）",
  "result": null,
  "error": 500
}
```

> 上面两条 500 只在 `codeAudit.llm.failClosed` 为 `true` 时返回；设为 `false` 时这两种状态记警告后照常导出，只有第一条"未通过"的 400 与开关无关。

其余失败场景：请求体 JSON 解析失败、`requestId` 与 `taskId` 命中了不同记录（均为 400）；加载导入索引失败、检查结果文件失败（`training_report.json` 存在但无法 stat）、加密失败（均为 500）。结果目录不存在时不会走到压缩这一步——入口的文件检查会先返回 404。`fhe` 实例上还有一条 `500 读取 FHE 结果包失败: ...`：记录里没有 `output.zip`，或它读不出来。

---

## 5. 内部回调（FHE 服务 → TAA）

### 5.1 FHE 服务终态回调（/v1/taa/fheCallback）

只有 `server.type=fhe` 的实例提供该接口：FHE 服务用它通知某个任务的终态（成功/失败）。TAA 收到后据此结束等待、取回 `output.zip` 并通过 `/v1/taa/reportRes` 上报。平台不调用它。

**请求**：`POST /v1/taa/fheCallback`

**请求内容类型**：`application/json`

**访问控制**：

- 接口不鉴权，改为**只接受本机环回地址**（`127.0.0.0/8`、`::1`）的来源。TAA 交给 FHE 服务的回调地址就是 `127.0.0.1`，因此服务必然经环回访问；网络上的其他进程无法伪造某个任务的终态。
- 环回过滤区分不了同一台机器上的不同进程，这是为了去掉共享令牌而刻意接受的代价。
- 非 `fhe` 实例、或来源不是环回地址，一律返回 `404 {"msg":"not found"}`——而不是 `400`，这样该接口在不提供它的实例上不可见。

**幂等性**：FHE 服务对同一任务最多投递 4 次（退避 `0/1/4/16s`）。本接口按构造幂等：只有真正结束任务的那次投递起作用，其余投递不做任何事；**每次投递都返回 `200`**——返回非 2xx 只会让服务对着一个已经结束的任务继续重试。

**参数**（由 FHE 服务按其回调约定提交）：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `taskId` / `task_id` | `string` | 是 | 任务 ID，两种下划线/驼峰写法都接受；为空返回 400 |
| `status` | `string` | 是 | 任务终态，为空返回 400 |
| `resultZip` / `result_zip` | `string` | 否 | 结果包位置 |
| `cases` / `results` | `array` | 否 | 各用例的执行结果；`cases` 为空时读取 `results` |

> 请求体上限 `4 MiB`，超限返回 `400 回调请求体过大`。解析失败返回 `400`，`msg` 为解析错误本身（`decode fhe callback: ...`、`fhe callback has no task id`、`fhe callback for task <id> has no status` 等）。

**响应内容类型**：`application/json`

**响应结果字段**：`result` 恒为 `null`。

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "ok",
  "result": null,
  "error": 0
}
```

**失败响应示例**（400，请求体解析失败）：

```jsonc
{
  "msg": "decode fhe callback: unexpected end of JSON input",
  "result": null,
  "error": 400
}
```

---

## 6. 调试接口

### 6.1 连通性检查（/v1/taa/health）

**请求**：`POST /v1/taa/health`

**请求内容类型**：`application/json`

**功能说明**：轻量级接口，不调用 attestation helper，用于快速确认 TAA 服务是否可达和正常运行。

**参数**：无

**请求示例**：

```jsonc
{}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `phase` | `number` | 当前阶段：`1` 调试，`2` 测试，`3` 正式训练，`4` 推理 |
| `phaseName` | `string` | 阶段名称：`调试`、`测试`、`正式训练`、`推理`；未知值返回 `未知(<n>)` |
| `modelImported` | `bool` | 模型是否已导入 |
| `trainingRunning` | `bool` | 当前是否有训练在跑 |
| `currentOp` | `string` | 当前操作状态：`idle`、`downloading`、`decrypting`、`analyzing`、`saving`（`data-anaylsis` 落盘）、`staging`、`training`、`reporting`；审计在跑且没有其他操作时为 `auditing` |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "ok",
  "result": {
    "phase": 1,
    "phaseName": "调试",
    "modelImported": false,
    "trainingRunning": false,
    "currentOp": "idle"
  },
  "error": 0
}
```

**使用场景**：
- 在调用其他接口前，先确认 TAA 服务是否正常运行
- 检查 TAA 当前所处的阶段状态
- 查看模型导入与训练运行状态

### 6.2 查询 TAA 完整状态（/v1/taa/status）

该接口用于查询 TAA 的完整状态信息，比 `/v1/taa/health` 返回更多字段。

**请求**：`POST /v1/taa/status`

**请求内容类型**：`application/json`

**参数**：无

**请求示例**：

```jsonc
{}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `phase` | `number` | 当前阶段：`1` 调试，`2` 测试，`3` 正式训练，`4` 推理 |
| `phaseName` | `string` | 阶段名称：`调试`、`测试`、`正式训练`、`推理`；未知值返回 `未知(<n>)` |
| `modelImported` | `bool` | 模型是否已导入 |
| `trainingRunning` | `bool` | 当前是否有训练在跑（`fhe` 实例上恒为 `false`，FHE 任务在 `currentOp` 上体现） |
| `currentOp` | `string` | 当前操作状态：`idle`、`downloading`、`decrypting`、`analyzing`、`saving`（`data-anaylsis` 落盘）、`staging`、`training`、`reporting`；审计在跑且没有其他操作时为 `auditing` |
| `logCount` | `number` | 日志缓冲区中尚未被上报例程取走的条数 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "ok",
  "result": {
    "phase": 1,
    "phaseName": "调试",
    "modelImported": true,
    "trainingRunning": false,
    "currentOp": "idle",
    "logCount": 5
  },
  "error": 0
}
```
