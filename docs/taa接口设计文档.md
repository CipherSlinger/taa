# TAA 接口设计文档

## 1. 前置要求

TAA 所在 Pod 容器需提供以下运行参数：

```env
PLATFORM_IP=192.168.3.102:8080
DOCKER_ID=xxxxxxxxx
CONTRACT=合约ID（预留）
```

```env
# 模型方路径约定
/opt/taa/input          # 输入目录（唯一只读权限路径，未实现权限管理）
/opt/taa/output         # 输出目录（唯一写权限路径，未实现权限管理）
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

| 序号 | 方向 | 接口 | 方法 | 功能说明 |
| --- | --- | --- | --- | --- |
| 1 | TAA → 平台 | `/v1/taa/register` | `POST` | TAA 启动后生成远程证明报告并通知平台 |
| 2 | TAA → 平台 | `/v1/taa/reportRes` | `POST` | TAA 上报训练完成结果 |
| 3 | TAA → 平台 | `/v1/taa/reportModelImport` | `POST` | TAA 上报模型导入结果（含代码审计报告） |
| 4 | 平台 → TAA | `/v1/taa/getAttestation` | `POST` | 平台获取远程证明报告 |
| 5 | 平台 → TAA | `/v1/taa/health` | `POST` | 平台检查 TAA 连通性 |
| 6 | 平台 → TAA | `/v1/taa/import` | `POST` | 平台下发数据资源 |
| 7 | 平台 → TAA | `/v1/taa/importModel` | `POST` | 平台下发模型训练代码 |
| 8 | 平台 → TAA | `/v1/taa/getResourceInfo` | `POST` | 平台传入 resourceUrl，TAA 下载、解密、分析后返回资源信息，临时文件自动清理 |
| 9 | 平台 → TAA | `/v1/taa/switch` | `POST` | 平台通知 TAA 切换运行阶段 |
| 10 | 平台 → TAA | `/v1/taa/export` | `POST` | 平台请求 TAA 导出当前阶段结果目录压缩包，成功时直接返回文件流 |
| 11 | 平台 → TAA | `/v1/taa/logs` | `POST` | 查询 TAA 结构化日志 |
| 12 | 平台 → TAA | `/v1/taa/status` | `POST` | 查询 TAA 完整状态信息 |

---

## 3. TAA → 平台

### 3.1 TAA 启动后生成远程证明报告并通知平台

TAA 服务启动时先生成随机 SM2 公私钥对（国密标准椭圆曲线密码算法，GB/T 32918-2016），并先调用 attestation helper 生成远程证明报告，保存到 `attestation.report` 后，再调用平台注册接口。

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

### 3.2 获取远程证明报告

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

### 3.4 TAA 上报训练完成结果

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
  "report": "{\"generated_at\":\"2026-09-02T10:03:43Z\",\"report_id\":\"train-report-20260902-100343-ae53fa14\",\"dataset\":{\"total_samples\":12500,\"splits\":{\"train\":10000,\"test\":1000},\"checksum\":{\"size\":540672,\"algorithm\":\"sm3\",\"value\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}},\"training_task\":{\"task_id\":\"task-20260825-001\",\"status\":\"succeeded\",\"exit_code\":0,\"failure_reason\":null,\"started_at\":\"2026-09-02T10:03:35Z\",\"finished_at\":\"2026-09-02T10:03:43Z\",\"duration_seconds\":8,\"model_checksum\":{\"size\":581632,\"algorithm\":\"sm3\",\"value\":\"a1b2c3d4e5f67890abcdef1234567890abcdefabcdefabcdefabcdefabcd\"},\"metrics\":{\"final_accuracy\":0.9087,\"final_loss\":0.2145,\"epochs\":[{\"epoch\":1,\"accuracy\":0.5231,\"loss\":1.2345},{\"epoch\":2,\"accuracy\":0.6789,\"loss\":0.9876}]}},\"codeaudit\":{\"conclusion\":{\"passed\":true,\"risk_level\":\"NONE\",\"summary\":\"\u672a\u53d1\u73b0\u5b89\u5168\u95ee\u9898\uff0c\u4ee3\u7801\u901a\u8fc7\u5ba1\u8ba1\",\"recommendation\":\"\u65e0\u9700\u4fee\u590d\",\"statistics\":{\"total_findings\":0,\"high\":0,\"medium\":0,\"malicious\":0,\"suspicious\":0,\"benign\":0,\"uncertain\":0}},\"file_reports\":null}}"
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
      "statistics": {                                     // findings 统计
        "total_findings": 0,                              // findings 总数
        "high": 0,                                        // 严重度 HIGH 数量
        "medium": 0,                                      // 严重度 MEDIUM 数量
        "malicious": 0,                                   // LLM 判定 MALICIOUS 数量
        "suspicious": 0,                                  // LLM 判定 SUSPICIOUS 数量
        "benign": 0,                                      // LLM 判定 BENIGN 数量
        "uncertain": 0                                    // LLM 判定 UNCERTAIN 数量
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

### 3.5 TAA 上报模型导入结果

**请求**：`POST /v1/taa/reportModelImport`

**请求内容类型**：`application/json`

**触发时机**：TAA 接收 `/v1/taa/importModel` 请求后，立即下载资源并异步处理。模型下载完成后，TAA 使用 Qwen 对模型代码进行安全审计，审计完成后调用此接口上报结果。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `dockerId` | `string` | 是 | 取值为容器启动参数 `DOCKER_ID` |
| `requestId` | `string` | 是 | 与 `/v1/taa/importModel` 请求中的 `requestId` 一致，用于绑定同一轮模型导入 |
| `taskId` | `string` | 否 | 任务 ID，与 `/v1/taa/importModel` 请求中的 `taskId` 一致 |
| `code` | `number` | 是 | `0` 表示导入和审计成功，`1` 表示资源下载/导入失败，`2` 表示审计失败 |
| `msg` | `string` | 否 | 失败时为失败原因 |
| `report` | `string` | 否 | 代码审计报告 JSON 字符串，格式与训练结果报告中的 `codeaudit` 字段完全一致 |

**请求示例**：

```jsonc
{
  "dockerId": "DOCKER_ID",
  "requestId": "request-001",
  "taskId": "task-001",
  "code": 0,
  "msg": null,
  "report": "{\"conclusion\":{\"passed\":true,\"risk_level\":\"NONE\",\"summary\":\"未发现安全问题，代码通过审计\",\"recommendation\":\"无需修复\",\"statistics\":{\"total_findings\":0,\"high\":0,\"medium\":0,\"malicious\":0,\"suspicious\":0,\"benign\":0,\"uncertain\":0}},\"file_reports\":null}"
}
```

**`report` 字段内容格式**：与训练结果报告中的 `codeaudit` 字段完全一致，详见 [3.4 节 `report` 字段内容示例](#34-taa-上报训练完成结果) 中的 `codeaudit` 部分。

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

---

## 4. 平台 → TAA

### 4.1 连通性检查

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

### 4.1.1 资源信息获取

TAA 接收到 `resourceUrl` 后，下载资源文件（若为 `.enc` 结尾则使用实例 SM2 私钥进行信封解密），将解密后的明文归档压缩包解压到临时目录，调用 `filetree` 解析器分析多模态数据集的目录结构、魔数格式识别及结构化文件元信息（CSV / TSV / JSON / JSONL / XLSX / SQLite / Parquet 等的 schema 与数据量），同时计算资源压缩包的国密 SM3 校验和（与 `/v1/taa/import` 接口哈希逻辑保持一致），分析完成后自动清理临时文件。

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

### 4.2 下发资源数据

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


### 4.3 通知 TAA 阶段切换（`如何防止平台和模型提供方共谋直接进入正式训练阶段偷取数据？`）

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

> 当前实现仅校验 `phase` 取值范围为 `1` ~ `4`，目前允许在有效阶段之间直接切换。

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

### 4.4 请求 TAA 导出结果

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
| phase 1（调试） | `RESULT_DIR/debug` 目录压缩得到的 tar.gz 文件 | `result-debug-{requestId}.tar.gz` | 请求 `publicKey` 非空时加密，文件名追加 `.enc` |
| phase 2（测试） | `RESULT_DIR/train` 目录压缩得到的 tar.gz 文件 | `result-train-{requestId}.tar.gz` | 请求 `publicKey` 非空时加密，文件名追加 `.enc` |
| phase 3（正式训练） | `RESULT_DIR/train` 目录压缩得到的 tar.gz 文件 | `result-train-{requestId}.tar.gz` | 固定使用 phase 1 `/v1/taa/importModel` 保存的公钥加密，文件名追加 `.enc`；未保存公钥时返回 400 |
| phase 4（推理） | 暂不支持 | - | 返回 400 |

**成功响应内容类型**：`application/octet-stream`

**成功响应头**：

| 响应头 | 说明 |
| --- | --- |
| `Content-Type` | 固定为 `application/octet-stream` |
| `Content-Disposition` | 附件下载文件名。明文时为 `result-debug-{requestId}.tar.gz` 或 `result-train-{requestId}.tar.gz`；加密时追加 `.enc` |
| `Content-Length` | 文件大小，单位为字节；加密导出时为加密后的文件大小 |
| `X-TAA-Task-Id` | 任务 ID，与请求中的 `taskId` 一致；`taskId` 缺省时为空 |
| `X-TAA-Encrypted` | 是否加密，`true` 表示响应体为 SM2+SM4-GCM 信封加密结果，`false` 表示响应体为明文 tar.gz 压缩包 |

**成功响应体**：结果文件二进制流。

- `X-TAA-Encrypted: false` 时，响应体为当前阶段结果目录压缩得到的 tar.gz 文件。
- `X-TAA-Encrypted: true` 时，响应体为信封加密后的二进制内容，格式为 `WrappedKey(129B) || SM4-GCM Ciphertext`。

**成功响应示例（200 OK，phase 2 明文导出）**：

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="result-train-req-export-001.tar.gz"
Content-Length: 10485760
X-TAA-Task-Id: task-001
X-TAA-Encrypted: false

<result-train-req-export-001.tar.gz binary stream>
```

**成功响应示例（200 OK，phase 3 加密导出）**：

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="result-train-req-export-002.tar.gz.enc"
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
  -o result-train-req-export-001.tar.gz
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

### 4.5 下发模型资源（`/v1/taa/importModel`）

该接口**专门用于平台向 TAA 下发模型资源**（模型代码 + 训练代码 + 数据），复用 `/v1/taa/import` 的资源接收与处理流程，区别在于：固定处理模型导入场景，**移除 `type` 字段**。

**请求**：`POST /v1/taa/importModel`

**请求内容类型**：`application/json`

**参数**：

 | 参数 | 类型 | 必填 | 说明 |
 | --- | --- | --- | --- |
 | `resourceUrl` | `string` | 是 | 资源下载地址 |
 | `requestId` | `string` | 否* | 随机值，与 `taskId` 不能同时为空 |
 | `taskId` | `string` | 否* | 任务 ID，与 `requestId` 不能同时为空 |
 | `publicKey` | `string` | 否 | SM2 公钥 PEM。TAA 在 phase=1 时校验并保存该公钥，用于后续 phase=3 结果加密导出 |
 | `runtimeConfig` | `string` | 否 | 运行配置 JSON 字符串。字符串内容应为 JSON 对象，包含顺序执行的命令列表和环境变量；缺省时按默认训练流程执行 |

**`runtimeConfig` 字段格式**：

`runtimeConfig` 的值是一个 JSON 字符串，字符串解析后的内容结构如下：

| 子字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `commands` | `array[string]` | 否 | 按顺序执行的命令列表。数组顺序即执行顺序，任一命令失败则停止后续执行 |
| `env` | `string` | 否 | 运行时环境变量 JSON 字符串。字符串内容应为 JSON 对象，解析后得到键值对并注入到每条命令的执行环境中 |

**执行规则**：

- `commands` 按数组顺序执行。
- 前一条命令成功后，才执行下一条命令。
- 任一条命令失败时，立即停止后续执行，并将失败结果上报平台。
- `env` 为空、缺省或为空字符串时，不额外注入环境变量。
- `env` 字符串解析后的环境变量对该次导入模型的执行过程生效。
- `runtimeConfig` 为空、缺省或为空字符串时，TAA 按默认模型导入流程执行，不额外注入命令和环境变量。

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

### 4.6 查询 TAA 结构化日志（`/v1/taa/logs`）

该接口用于查询 TAA 运行过程中的结构化日志。

**请求**：`POST /v1/taa/logs`

**请求内容类型**：`application/json`

**参数**：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `since` | `string` | 否 | ISO8601 时间戳，仅返回该时间之后的日志。缺省时返回所有日志并清空日志缓冲区 |

**请求示例**：

```jsonc
{
  "since": "2026-09-03T10:00:00Z"
}
```

**响应内容类型**：`application/json`

**响应参数**：遵循 [2. 公共返回格式](#2-公共返回格式)，业务字段放在 `result` 中。

**响应结果字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `logs` | `array` | 日志条目数组 |
| `currentOp` | `string` | 当前操作状态 |
| `total` | `number` | 日志条目数量 |

**日志条目字段**：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `timestamp` | `string` | ISO8601 时间戳 |
| `level` | `string` | 日志级别：`info`、`warn`、`error` |
| `component` | `string` | 组件名称 |
| `message` | `string` | 日志消息 |

**成功响应示例**（200 OK）：

```jsonc
{
  "msg": "ok",
  "result": {
    "logs": [
      {
        "timestamp": "2026-09-03T10:00:01Z",
        "level": "info",
        "component": "register",
        "message": "platform register completed"
      },
      {
        "timestamp": "2026-09-03T10:00:02Z",
        "level": "info",
        "component": "server",
        "message": "taa service listening on :6001"
      }
    ],
    "currentOp": "idle",
    "total": 2
  },
  "error": 0
}
```

### 4.7 查询 TAA 完整状态（`/v1/taa/status`）

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
