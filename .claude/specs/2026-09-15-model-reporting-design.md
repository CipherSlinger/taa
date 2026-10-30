# 模型日志与训练进度上报设计

## 目标

在 TAA 训练执行期间读取模型方约定的输出目录，并主动向平台上报模型日志与训练进度；同时将训练代码输出从 `/opt/taa/output` 调整到 `/opt/taa/output/result/`，为日志和进度保留独立目录。

## 接口

### 模型日志上报

- 方向：TAA → 平台
- 路径：`POST /v1/taa/modelLog`
- 请求字段：`dockerId`、`requestId` 必填；`taskId` 可选；`seqStart` 和 `entries` 必填。
- `entries` 为 JSONL 增量解析得到的日志数组，每项包含 `seq` 和 `message`。
- 平台成功响应必须为 HTTP 200 且公共返回格式 `error=0`、`result.received=true`。
- 同一日志批次失败重试时保持序号；网络错误、408、429、5xx 使用有限重试，不阻塞训练主流程。

### 训练进度上报

- 方向：TAA → 平台
- 路径：`POST /v1/taa/reportProgress`
- 请求字段：`dockerId`、`requestId`、`percent`、`timestamp` 必填；`taskId` 可选。
- 从进度目录中读取最新 JSON 文件，校验 `percent` 范围为 0～100；缺失或非法文件只记录日志，不影响训练。
- 平台成功响应必须为 HTTP 200 且公共返回格式 `error=0`、`result.received=true`。

## 输出目录

默认目录固定为：

- `/opt/taa/output/result/`：训练命令的 `<output>` 宏和 `TAA_OUTPUT_DIR`，训练代码输出写入此处；训练结束后复制到任务结果目录。
- `/opt/taa/output/log/`：模型方追加写入的 JSONL 日志文件。
- `/opt/taa/output/progress/`：模型方写入的进度 JSON 文件，TAA 读取最新修改文件。

目录支持配置覆盖，默认值用于生产部署；启动时统一创建，训练开始前清理本次临时内容。

## 数据流与并发

训练任务启动后创建一个后台 watcher：按固定间隔增量扫描日志文件并读取最新进度文件，串行调用两个平台回调，避免同一任务产生并发上报。watcher 在训练命令返回后停止并执行一次最终 flush。上报网络故障仅影响上报，不改变训练命令退出结果。

日志序号由 TAA 对本次任务发现的日志行从 1 开始分配；同一文件通过读取 offset 避免重复发送。平台可能收到重复请求，调用方必须保持原序号重试。

## 错误处理

- 缺少平台地址、容器 ID 或 requestId：回调返回本地参数错误，不发送请求。
- 文件不存在、文件为空或单行 JSON 无法解析：记录 warning，跳过该条目。
- 平台非 2xx、公共响应 `error != 0` 或网络失败：记录 warning；不让 watcher 退出训练流程。
- 训练任务结束后，watcher 必须先停止扫描再执行最终 flush，避免 goroutine 泄漏。

## 测试

覆盖以下行为：

1. 模型日志和进度请求 JSON 序列化、路径和可选 `taskId`。
2. JSONL 日志增量读取、序号分配和重复扫描不重复发送。
3. 最新进度 JSON 读取、百分比校验和非法文件跳过。
4. 默认输出目录为 `result/log/progress` 三个子目录，训练命令使用 result 目录。
5. watcher 在训练执行期间上报，并在训练结束时停止且最终 flush。
6. 平台失败不导致训练命令失败。
