# TAA 接口设计文档

## 目录

- [1. 前置要求](#1-前置要求)
- [2. 公共返回格式](#2-公共返回格式)
  - [2.1 接口一览](#21-接口一览)
    - [2.1.1 TAA → 平台（回调与上报接口）](#211-taa--平台回调与上报接口)
    - [2.1.2 平台 → TAA（业务与控制接口）](#212-平台--taa业务与控制接口)
    - [2.1.3 调试接口（平台 → TAA）](#213-调试接口平台--taa)
- [3. TAA → 平台](#3-taa--平台)
  - [3.1 TAA 启动后生成远程证明报告并通知平台（/v1/taa/register）](#31-taa-启动后生成远程证明报告并通知平台v1taaregister)
  - [3.2 获取远程证明报告（/v1/taa/getAttestation）](#32-获取远程证明报告v1taagetattestation)
    - [3.2.1 远程证明报告二进制格式](#321-远程证明报告二进制格式)
  - [3.4 TAA 上报训练完成结果（/v1/taa/reportRes）](#34-taa-上报训练完成结果v1taareportres)
  - [3.5 TAA 上报模型导入结果（/v1/taa/reportModelImport）](#35-taa-上报模型导入结果v1taareportmodelimport)
  - [3.6 TAA 上报代码安全审计结果（/v1/taa/reportAudit）](#36-taa-上报代码安全审计结果v1taareportaudit)
  - [3.7 TAA 上报任务终端日志（/v1/taa/modelLog）](#37-taa-上报任务终端日志v1taamodellog)
  - [3.8 TAA 上报运行日志（/v1/taa/taaLog）](#38-taa-上报运行日志v1taataalog)
  - [3.9 TAA 上报任务进度（/v1/taa/reportProgress）](#39-taa-上报任务进度v1taareportprogress)
- [4. 平台 → TAA](#4-平台--taa)
  - [4.1 资源信息获取（/v1/taa/getResourceInfo）](#41-资源信息获取v1taagetresourceinfo)
  - [4.2 下发资源数据（/v1/taa/import）](#42-下发资源数据v1taaimport)
  - [4.3 通知 TAA 阶段切换（/v1/taa/switch）](#43-通知-taa-阶段切换v1taaswitch)
  - [4.4 请求 TAA 导出结果（/v1/taa/export）](#44-请求-taa-导出结果v1taaexport)
  - [4.5 下发模型资源（/v1/taa/importModel）](#45-下发模型资源v1taaimportmodel)
  - [4.6 中止当前训练任务（/v1/taa/stopTraining）](#46-中止当前训练任务v1taastoptraining)
- [5. 调试接口](#5-调试接口)
  - [5.1 连通性检查（/v1/taa/health）](#51-连通性检查v1taahealth)
  - [5.2 查询 TAA 完整状态（/v1/taa/status）](#52-查询-taa-完整状态v1taastatus)

---

## 1. 前置要求

TAA 所在 Pod 容器需提供以下运行参数：

```env
PLATFORM_IP=192.168.3.102:8080
DOCKER_ID=xxxxxxxxx
CONTRACT=合约ID（预留）
```

```env
# 模型方路径约定（详细规约参见 docs/TAA模型提供方开发与接口对接规范.md）
/opt/taa/input          # 输入目录（只读权限路径 READ_ONLY）
/opt/taa/output/result  # 训练代码主输出目录（写权限路径 READ_WRITE）
/opt/taa/output/log     # 模型终端日志目录（写权限路径 READ_WRITE）
/opt/taa/output/progress # 训练进度目录（写权限路径 READ_WRITE）
```

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
| `error` | `number` | 错误码，`0` 表示成功，非 `0` 表示失败 |

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
| 2 | `/v1/taa/import` | `POST` | 平台下发数据资源 |
| 3 | `/v1/taa/importModel` | `POST` | 平台下发模型训练代码 |
| 4 | `/v1/taa/getResourceInfo` | `POST` | 平台传入 resourceUrl，TAA 下载、解密、分析后返回资源信息，按 SM3 哈希持久化保存目录与唯一标识备份 |
| 5 | `/v1/taa/switch` | `POST` | 平台通知 TAA 切换运行阶段 |
| 6 | `/v1/taa/export` | `POST` | 平台请求 TAA 导出当前阶段结果目录压缩包，成功时直接返回文件流 |
| 7 | `/v1/taa/stopTraining` | `POST` | 平台同步请求 TAA 中止当前训练任务 |

#### 2.1.3 调试接口（平台 → TAA）

| 序号 | 接口 | 方法 | 功能说明 |
| --- | --- | --- | --- |
| 1 | `/v1/taa/health` | `POST` | 平台检查 TAA 连通性 |
| 2 | `/v1/taa/status` | `POST` | 查询 TAA 完整状态信息 |

---

## 3. TAA → 平台

### 3.1 TAA 启动后生成远程证明报告并通知平台（/v1/taa/register）

TAA 服务启动时先生成随机 SM2 公私钥对，生成远程证明报告后，再调用平台注册接口。

**请求**：`POST http://{PLATFORM_IP}/v1/taa/register`

**请求内容类型**：`application/json`

**触发时机**：TAA 启动后主动调用平台接口；平台返回 HTTP `200` 即表示注册通知成功。若请求失败或平台返回非 `200`，TAA 持续重试。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | docker id |
| `attestation` | `string` | 是 | 远程证明报告文件，Base64 编码格式（原始 2548 字节 → 编码后约 3400 字符） |
| `taaPublicKey` | `string` | 是 | TAA 启动时生成的 SM2 公钥 PEM（国密标准） |
| `attestationValues` | `string` | 是 | attestation report 核心字段提取的 JSON 字符串，包含 USERDATA、MNONCE、DIGEST、CHIP_ID 等关键字段 |
| `timestamp` | `string` | 是 | 生成 attestation 时的 Unix 时间戳（秒），与 USERDATA 中的时间戳一致 |
| `verifiedPass` | `bool` | 是 | TAA 验证远程证明报告结果，`true` 表示成功，`false` 表示失败 |
| `authInfo` | `object/null` | 否 | 当前固定传 `null` |

**Base64 编码说明**：
- 原始报告大小：`0x9F4` = 2548 字节
- Base64 编码后大小：约 3400 字符（计算公式：`ceil(2548 / 3) * 4 = 3400`）
- 编码会增加约 33% 的体积

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

### 3.2 获取远程证明报告（/v1/taa/getAttestation）

**请求**：`POST /v1/taa/getAttestation`

**请求内容类型**：`application/json`

**请求格式**：与注册接口保持一致，使用 JSON 格式。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `requestId` | `string` | 是 | 随机值，用于防重放 |

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
| `verifiedPass` | `bool` | TAA 验证结果：`true` 表示验证通过，`false` 表示验证失败 |
| `attestation` | `string` | 远程证明报告，Base64 编码后的二进制内容（`0x9F4` = 2548 字节原始数据） |
| `attestationValues` | `string` (JSON) | attestation report 核心字段提取，JSON 字符串，包含 `userdata`（PEM 格式 SM2 公钥）、`mnonce`、`digest`、`chipId`，其中后3项为 hex 编码 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "success",
  "result": {
    "requestId": "req-att-001",
    "verifiedPass": true,
    "attestation": "base64-encoded-attestation-report...",
    "attestationValues": "{\"userdata\":\"-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\",\"mnonce\":\"0123...\",\"digest\":\"0123...\",\"chipId\":\"0123...\"}"
  },
  "error": 0
}
```

#### 3.2.1 远程证明报告二进制格式

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

### 3.4 TAA 上报训练完成结果（/v1/taa/reportRes）

**请求**：`POST /v1/taa/reportRes`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | 取值为容器启动参数 `DOCKER_ID` |
| `requestId` | `string` | 是 | 启动测试时对应的请求 ID |
| `taskId` | `string` | 否 | 训练任务 ID |
| `code` | `number` | 是 | `0` 表示成功，非 `0` 表示失败 |
| `msg` | `string` | 否 | 失败时为失败原因 |
| `report` | `string` | 否 | 训练结果报告字符串 |

**示例**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "xx",
  "taskId": "task-001",
  "code": 0,
  "msg": null,
  "report": "{\"generated_at\":\"2026-09-02T10:03:43Z\",\"report_id\":\"train-report-20260902-100343-ae53fa14\",\"dataset\":{\"total_samples\":12500,\"splits\":{\"train\":10000,\"test\":1000},\"checksum\":{\"size\":540672,\"algorithm\":\"sm3\",\"value\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}},\"training_task\":{\"task_id\":\"task-20260825-001\",\"status\":\"succeeded\",\"exit_code\":0,\"failure_reason\":null,\"started_at\":\"2026-09-02T10:03:35Z\",\"finished_at\":\"2026-09-02T10:03:43Z\",\"duration_seconds\":8,\"model_checksum\":{\"size\":581632,\"algorithm\":\"sm3\",\"value\":\"a1b2c3d4e5f67890abcdef1234567890abcdefabcdefabcdefabcdefabcd\"},\"metrics\":{\"final_accuracy\":0.9087,\"final_loss\":0.2145,\"epochs\":[{\"epoch\":1,\"accuracy\":0.5231,\"loss\":1.2345},{\"epoch\":2,\"accuracy\":0.6789,\"loss\":0.9876}]}},\"codeaudit\":{\"conclusion\":{\"passed\":true,\"risk_level\":\"NONE\",\"summary\":\"\u672a\u53d1\u73b0\u5b89\u5168\u95ee\u9898\uff0c\u4ee3\u7801\u901a\u8fc7\u5ba1\u8ba1\",\"recommendation\":\"\u65e0\u9700\u4fee\u590d\",\"statistics\":{\"high\":0,\"medium\":0,\"low\":0}},\"file_reports\":null}}"
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
      "algorithm": "sm3",                                // 哈希算法：sm3 / sha256 等
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
    "file_reports": null                                   // 按文件聚合的 findings 明细；null 表示无 findings，存在 findings 时为数组
  }
}
```

> 平台根据所处阶段处理结果报告 `report`：
> phase 1 调试阶段（明文结果返回模型提供方）
> phase 2 测试阶段（明文结果返回平台）
> phase 3 拒绝调用

### 3.5 TAA 上报模型导入结果（/v1/taa/reportModelImport）

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

### 3.6 TAA 上报代码安全审计结果（/v1/taa/reportAudit）

**请求**：`POST /v1/taa/reportAudit`

**请求内容类型**：`application/json`

**触发时机**：TAA 完成模型解压后，对模型代码执行安全审计（静态扫描规则分析 + LLM 语义审查）。审计流程完成后，调用此接口上报审计结论与明细报告。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | 取值为容器启动参数 `DOCKER_ID` |
| `requestId` | `string` | 是 | 与 `/v1/taa/importModel` 请求中的 `requestId` 一致，用于绑定同一轮模型导入 |
| `taskId` | `string` | 否 | 任务 ID，与 `/v1/taa/importModel` 请求中的 `taskId` 一致 |
| `code` | `number` | 是 | 审计状态码：<br>• `0`：代码审计通过<br>• `1`：**代码审计未通过**（发现恶意/高危违规代码）<br>• `2`：**LLM 服务不可用**（模型探测失败或服务离线，按 Fail-Closed 策略拦截） |
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
  "report": "{\"conclusion\":{\"passed\":true,\"risk_level\":\"NONE\",\"summary\":\"未发现安全问题，代码通过审计\",\"recommendation\":\"无需修复\",\"statistics\":{\"high\":0,\"medium\":0,\"low\":0}},\"file_reports\":null}"
}
```

**请求示例（代码审计未通过：检出违规/后门代码）**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "request-001",
  "taskId": "task-001",
  "code": 1,
  "msg": "代码安全审计未通过: 发现反弹 Shell 风险",
  "report": "{\"conclusion\":{\"passed\":false,\"risk_level\":\"CRITICAL\",\"summary\":\"发现高危后门代码\",\"recommendation\":\"请清理非法网络外联指令\",\"statistics\":{\"high\":1,\"medium\":0,\"low\":0}},\"file_reports\":[{\"filename\":\"train.py\",\"findings\":[{\"rule_id\":\"SEC-PY-003\",\"line\":42,\"severity\":\"HIGH\",\"description\":\"可疑网络反弹 Shell 代码\",\"llm_verdict\":\"MALICIOUS\"}]}]}"
}
```

**请求示例（LLM 服务不可用：Fail-Closed 拦截）**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "request-001",
  "taskId": "task-001",
  "code": 2,
  "msg": "LLM 服务不可用，按 Fail-Closed 策略拦截",
  "report": ""
}
```

**`report` 字段内容格式**：与训练结果报告中的 `codeaudit` 字段完全一致，详见 [3.4 节 `report` 字段内容示例](#34-taa-上报训练完成结果) 中的 `codeaudit` 部分。

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

### 3.7 TAA 上报任务终端日志（/v1/taa/modelLog）

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

平台按 `dockerId + requestId + seq` 去重，允许 TAA 因网络失败重复发送同一日志。TAA 仅在平台返回 HTTP `200` 且公共返回格式中的 `error=0` 时确认本批日志已接收；网络错误、HTTP `408`、`429` 或 `5xx` 可按指数退避重试，参数错误等其他 `4xx` 不应自动重试。

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

### 3.8 TAA 上报运行日志（/v1/taa/taaLog）

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

平台按 `dockerId + requestId + seq` 去重，允许 TAA 因网络失败重复发送同一日志。TAA 仅在平台返回 HTTP `200` 且公共返回格式中的 `error=0` 时确认本批日志已接收；网络错误、HTTP `408`、`429` 或 `5xx` 可按指数退避重试，参数错误等其他 `4xx` 不应自动重试。

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

### 3.9 TAA 上报任务进度（/v1/taa/reportProgress）

TAA 在任务执行过程中通过该接口向平台上报当前任务的数值进度。

**请求**：`POST http://{PLATFORM_IP}/v1/taa/reportProgress`

**请求内容类型**：`application/json`

**触发时机**：任务执行过程中，TAA 根据进度变化主动上报当前进度快照。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | 取值为容器启动参数 `DOCKER_ID` |
| `requestId` | `string` | 是 | 当前任务请求标识，用于关联同一任务的进度 |
| `taskId` | `string` | 否 | 平台任务 ID；单任务模式下可缺省 |
| `percent` | `number` | 是 | 当前任务进度百分比，取值范围为 `0` ~ `100` |
| `timestamp` | `string` | 是 | 进度产生时间，RFC3339 格式 |

平台按 `dockerId + requestId` 关联进度快照，并依据 `timestamp` 防止较早的进度覆盖较新的进度。

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

### 4.1 资源信息获取（/v1/taa/getResourceInfo）

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

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "ok",
  "result": "{\n  \"version\": \"1.0.0\",\n  \"generated_at\": \"2026-09-08T10:00:00Z\",\n  \"total_files\": 2,\n  \"total_size\": 540672,\n  \"total_size_h\": \"528.0KB\",\n  \"structured_files\": 1,\n  \"by_format\": [\n    {\"format\": \"csv\", \"count\": 1, \"size_sum\": 340000},\n    {\"format\": \"txt\", \"count\": 1, \"size_sum\": 200672}\n  ],\n  \"checksum\": {\n    \"size\": 540672,\n    \"algorithm\": \"sm3\",\n    \"value\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n  },\n  \"tree\": {\n    \"name\": \"dataset\",\n    \"type\": \"dir\",\n    \"file_count\": 2,\n    \"children\": [\n      {\n        \"name\": \"users.csv\",\n        \"type\": \"file\",\n        \"fmt\": \"csv\",\n        \"size\": 340000,\n        \"rows\": 2000,\n        \"fields\": [\n          {\"name\": \"user_id\", \"type\": \"int\"},\n          {\"name\": \"name\", \"type\": \"str\"}\n        ]\n      }\n    ]\n  }\n}",
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

### 4.2 下发资源数据（/v1/taa/import）

**请求**：`POST /v1/taa/import`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `resourceUrl` | `string` | 是 | 资源下载地址 |
| `requestId` | `string` | 否* | 随机值，与 `taskId` 不能同时为空 |
| `taskId` | `string` | 否* | 任务 ID，与 `requestId` 不能同时为空 |
| `publicKey` | `string` | 否 | SM2 公钥 PEM，用于资源解密和结果导出 |

**请求示例**：

```jsonc
{
  "resourceUrl": "xx",
  "requestId": "xx",
  "taskId": "xxx",
  "publicKey": "xx"
}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，该接口成功时 `result` 为 `null`。

**成功响应示例**（200 OK，仅资源接收，未触发训练模拟）：

```jsonc
{
  "msg": "资源已接收，下载处理中",
  "result": null,
  "error": 0
}
```

**成功响应示例**（200 OK，触发训练模拟并异步上报训练结果）：

> TAA 在资源接收后根据当前阶段执行相应操作，并将训练结果通过 `/v1/taa/reportRes` 异步上报平台。

```jsonc
{
  "msg": "数据已接收，训练结果将通过 reportRes 上报",
  "result": null,
  "error": 0
}
```

**验证失败响应示例**（400 Bad Request）：

```jsonc
{
  "msg": "resourceUrl 不能为空",
  "result": null,
  "error": 400
}
```

**下载失败响应示例**（500 Internal Server Error）：

```jsonc
{
  "msg": "下载资源失败: HTTP 404",
  "result": null,
  "error": 500
}
```


### 4.3 通知 TAA 阶段切换（/v1/taa/switch）

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

### 4.4 请求 TAA 导出结果（/v1/taa/export）

该接口用于请求导出 TAA 当前阶段产生的结果目录压缩包。考虑到结果文件可能较大，成功时接口直接返回二进制文件流。

> 注意：该接口与其他 TAA 接口不同，**成功响应不是公共 JSON 格式**；只有失败响应继续遵循 [2. 公共返回格式](#2-公共返回格式)。

**请求**：`POST /v1/taa/export`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `requestId` | `string` | 否* | 随机值，与 `taskId` 不能同时为空；TAA 会将其写入导出文件名 |
| `publicKey` | `string/null` | 否 | SM2 公钥 PEM。phase 1/2 中为空、缺省或 `null` 时明文导出，非空时使用该公钥做 SM2+SM4-GCM 信封加密；phase 3 中当前实现不使用请求中的 `publicKey`，固定使用 phase 1 导入模型时保存的公钥加密 |
| `taskId` | `string` | 否* | 任务 ID，与 `requestId` 不能同时为空；缺省时响应头 `X-TAA-Task-Id` 为空 |

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

**当前阶段导出内容**：

| 当前阶段 | 明文导出内容 | 明文文件名 | 加密规则 |
| --- | --- | --- | --- |
| phase 1（调试） | `RESULT_DIR/debug` 目录压缩得到的 zip 文件 | `result-debug-{requestId}.zip` | 请求 `publicKey` 非空时加密，文件名追加 `.enc` |
| phase 2（测试） | `RESULT_DIR/train` 目录压缩得到的 zip 文件 | `result-train-{requestId}.zip` | 请求 `publicKey` 非空时加密，文件名追加 `.enc` |
| phase 3（正式训练） | `RESULT_DIR/train` 目录压缩得到的 zip 文件 | `result-train-{requestId}.zip` | 固定使用 phase 1 `/v1/taa/importModel` 保存的公钥加密，文件名追加 `.enc`；未保存公钥时返回 400 |
| phase 4（推理） | 暂不支持 | - | 返回 400 |

**成功响应内容类型**：`application/octet-stream`

**成功响应头**：

| 响应头 | 说明 |
| --- | --- |
| `Content-Type` | 固定为 `application/octet-stream` |
| `Content-Disposition` | 附件下载文件名。明文时为 `result-debug-{requestId}.zip` 或 `result-train-{requestId}.zip`；加密时追加 `.enc` |
| `Content-Length` | 文件大小，单位为字节；加密导出时为加密后的文件大小 |
| `X-TAA-Task-Id` | 任务 ID，与请求中的 `taskId` 一致；`taskId` 缺省时为空 |
| `X-TAA-Encrypted` | 是否加密，`true` 表示响应体为 SM2+SM4-GCM 信封加密结果，`false` 表示响应体为明文 zip 压缩包 |

**成功响应体**：结果文件二进制流。

- `X-TAA-Encrypted: false` 时，响应体为当前阶段结果目录压缩得到的 zip 文件。
- `X-TAA-Encrypted: true` 时，响应体为信封加密后的二进制内容，格式为 `WrappedKey(129B) || SM4-GCM Ciphertext`。

**成功响应示例（200 OK，phase 2 明文导出）**：

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="result-train-req-export-001.zip"
Content-Length: 10485760
X-TAA-Task-Id: task-001
X-TAA-Encrypted: false

<result-train-req-export-001.zip binary stream>
```

**成功响应示例（200 OK，phase 3 加密导出）**：

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="result-train-req-export-002.zip.enc"
Content-Length: 10485918
X-TAA-Task-Id: task-001
X-TAA-Encrypted: true

<WrappedKey(129B) || SM4-GCM Ciphertext>
```

**调用示例**：

```sh
curl -X POST "http://{TAA_ADDR}/v1/taa/export" \
  -H "Content-Type: application/json" \
  -d '{"requestId":"req-export-001","publicKey":null,"taskId":"task-001"}' \
  -o result-train-req-export-001.zip
```

**失败响应内容类型**：`application/json`

**失败响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)。

**失败响应示例**：

```jsonc
{
  "msg": "requestId 不能为空",
  "result": null,
  "error": 400
}
```

```jsonc
{
  "msg": "压缩 train 目录失败: 目录不存在: stat /opt/taa/results/train: no such file or directory",
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
  "msg": "阶段 3 需要先通过阶段 1 导入公钥",
  "result": null,
  "error": 400
}
```

### 4.5 下发模型资源（/v1/taa/importModel）

该接口**专门用于平台向 TAA 下发模型资源**（模型代码 + 训练代码 + 数据），复用 `/v1/taa/import` 的资源接收与处理流程，区别在于：固定处理模型导入场景，**移除 `type` 字段**。

**请求**：`POST /v1/taa/importModel`

**请求内容类型**：`application/json`

**参数**：

 | 参数 | 类型 | 必填 | 说明 |
 | --- | --- | --- | --- |
 | `resourceUrl` | `string` | 否* | 资源下载地址。与 `publicKey` 规则一致：若之前未传输过且请求中为空，则报错（400）；若之前已传输并保存过，则允许为空。当为空时，直接复用已保存模型，使用 `runtimeConfig` 中的 `commands` 对最新数据索引对应的数据执行训练 |
 | `requestId` | `string` | 否* | 随机值，与 `taskId` 不能同时为空 |
 | `taskId` | `string` | 否* | 任务 ID，与 `requestId` 不能同时为空 |
 | `publicKey` | `string` | 否 | SM2 公钥 PEM。TAA 在 phase=1 时校验并保存该公��，用于后续 phase=3 结果加密导出 |
 | `runtimeConfig` | `string` | 否* | 运行配置 JSON 字符串。包含顺序执行的命令列表和环境变量。当 `resourceUrl` 为空时必填且 `commands` 不能为空；缺省时按默认训练流程执行 |

**`runtimeConfig` 字段格式**：

`runtimeConfig` 的值是一个 JSON 字符串，字符串解析后的内容结构如下：

| 子字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `commands` | `array[string]` | 否* | 按顺序执行的命令列表。数组顺序即执行顺序，任一命令失败则停止后续执行。当 `resourceUrl` 为空复用模型时必填且至少包含一条命令 |
| `env` | `string` | 否 | 运行时环境变量 JSON 字符串。字符串内容应为 JSON 对象，解析后得到键值对并注入到每条命令的执行环境中 |

**执行规则**：

- `commands` 按数组顺序执行。
- 前一条命令成功后，才执行下一条命令。
- 任一条命令失败时，立即停止后续执行，并将失败结果上报平台。
- `env` 为空、缺省或为空字符串时，不额外注入环境变量。
- `env` 字符串解析后的环境变量对该次导入模型的执行过程生效。
- `runtimeConfig` 为空、缺省或为空字符串时，TAA 按默认模型导入流程执行，不额外注入命令和环境变量。
- **resourceUrl 复用与最新数据训练**：当 `resourceUrl` 为空且之前已传输/保存过模型时，TAA 直接跳过模型下载与审计，从数据索引记录中获取最新导入的数据（Latest Data Record），根据 `runtimeConfig` 中的 `commands` 与环境变量对该数据直接执行训练。训练完成后通过 `/v1/taa/reportRes` 异步上报结果，并支持平台后续按 `taskId`/`requestId` 调用 `/v1/taa/export` 导出该轮训练产物。若之前未保存过模型或未找到已导入数据，则返回 400 错误。

**请求示例**：

```jsonc
{
  "resourceUrl": "xx",
  "requestId": "xx",
  "taskId": "xxx",
  "publicKey": "xx",
  "runtimeConfig": {
    "commands": [
      "python preprocess.py",
      "python train.py --epochs 20 --batch-size 64",
      "python export_model.py"
    ],
    "env": "{\"CUDA_VISIBLE_DEVICES\":\"0\",\"OMP_NUM_THREADS\":\"4\"}"
  }
}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，该接口成功时 `result` 为 `null`。

**成功响应示例**（200 OK，仅资源接收，未触发训练模拟）：

```jsonc
{
  "msg": "资源已接收，下载处理中",
  "result": null,
  "error": 0
}
```

**成功响应示例**（200 OK，触发训练模拟并异步上报训练结果）：

```jsonc
{
  "msg": "模型已接收，训练结果将通过 reportRes 上报",
  "result": null,
  "error": 0
}
```

**验证失败响应示例**（400 Bad Request，`resourceUrl` 为空）：

```jsonc
{
  "msg": "resourceUrl 不能为空",
  "result": null,
  "error": 400
}
```

**下载失败响应示例**（500 Internal Server Error）：

```jsonc
{
  "msg": "下载资源失败: HTTP 404",
  "result": null,
  "error": 500
}
```

> **加密格式说明**：与 `/v1/taa/import` 相同。

### 4.6 中止当前训练任务（/v1/taa/stopTraining）

该接口用于平台请求 TAA 中止当前正在执行的训练任务。TAA 当前为单任务模式，请求不需要传入 `taskId` 或 `requestId`，接口始终针对当前训练任务处理。

**请求**：`POST /v1/taa/stopTraining`

**请求内容类型**：`application/json`

**请求示例**：

```jsonc
{}
```

**处理规则**：

- 接口采用同步处理方式，TAA 等待训练进程及其子进程退出，并完成训练任务状态清理后返回。
- 当前存在训练任务时，成功中止后返回 HTTP `200`，公共返回格式中的 `error=0`。
- 当前不存在训练任务时，仍返回 HTTP `200`，公共返回格式中的 `error=0`，仅通过 `msg` 提示不存在训练任务；该场景按幂等成功处理。
- 该接口不区分或处理其他非训练任务，也不调用 `modelLog`、`reportProgress` 或 `/v1/taa/reportRes`。

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

---

## 5. 调试接口

### 5.1 连通性检查（/v1/taa/health）

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
| `phaseName` | `string` | 阶段名称 |
| `modelImported` | `bool` | 模型是否已导入 |
| `dataImported` | `bool` | 数据是否已导入 |
| `trainingDone` | `bool` | 训练是否已完成 |
| `currentOp` | `string` | 当前操作状态：`idle`、`downloading`、`decrypting`、`training` 等 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "ok",
  "result": {
    "phase": 1,
    "phaseName": "调试",
    "modelImported": false,
    "dataImported": false,
    "trainingDone": false,
    "currentOp": "idle"
  },
  "error": 0
}
```

**使用场景**：
- 在调用其他接口前，先确认 TAA 服务是否正常运行
- 检查 TAA 当前所处的阶段状态
- 查看资源导入和训练完成状态

### 5.2 查询 TAA 完整状态（/v1/taa/status）

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
| `phaseName` | `string` | 阶段名称 |
| `modelImported` | `bool` | 模型是否已导入 |
| `dataImported` | `bool` | 数据是否已导入 |
| `trainingDataImported` | `bool` | 训练数据是否已导入 |
| `trainingDone` | `bool` | 训练是否已完成 |
| `currentOp` | `string` | 当前操作状态 |
| `logCount` | `number` | 日志缓冲区中的日志数量 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "ok",
  "result": {
    "phase": 1,
    "phaseName": "调试",
    "modelImported": true,
    "dataImported": false,
    "trainingDataImported": false,
    "trainingDone": false,
    "currentOp": "idle",
    "logCount": 5
  },
  "error": 0
}
```
