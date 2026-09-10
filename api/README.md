# API 接口协议定义

本目录遵循 [Standard Go Project Layout](https://github.com/golang-standards/project-layout/blob/master/README_zh.md) 架构规范，用于存放系统对外的接口协议定义文件，包括 OpenAPI/Swagger 规范、Protocol Buffers（.proto）或 Thrift 文件。

---

## 目录结构

```text
api/
├── openapi.yaml        # OpenAPI 3.0.3 规范定义（RESTful HTTP / JSON 接口）
├── proto/              # Protocol Buffers 接口定义文件
│   └── taa.proto       # TAA 守护进程与平台回调的 gRPC / Protobuf 协议
└── README.md           # 本说明文档
```

---

## 文件说明

### 1. `openapi.yaml` (OpenAPI 3.0.3)
定义了 TAA 守护进程对外暴露的所有 RESTful HTTP 接口，以及 TAA 向管控平台发起的异步回调与上报接口：

- **运维与监控**：
  - `POST /v1/taa/health`：健康检查
  - `POST /v1/taa/status`：运行时阶段与导入状态查询
  - `POST /v1/taa/logs`：结构化运行日志增量拉取
- **远程证明**：
  - `POST /v1/taa/getAttestation`：获取 Hygon CSV 远程证明报告及绑定的公钥
- **资源流转**：
  - `POST /v1/taa/import`：测试/训练数据下发与解封导入
  - `POST /v1/taa/importModel`：模型训练代码包下发与安全审计
  - `POST /v1/taa/getResourceInfo`：多模态数据集预分析与目录树 Schema 提取
- **任务执行与导出**：
  - `POST /v1/taa/switch`：运行阶段切换与任务拉起
  - `POST /v1/taa/export`：训练产物防泄露检查与国密信封重加密导出
- **平台回调（TAA → 平台）**：
  - `POST /v1/taa/register`：TAA 启动后向平台主动注册
  - `POST /v1/taa/reportRes`：训练任务执行完成与结果上报
  - `POST /v1/taa/reportModelImport`：模型导入与代码安全审计报告上报

### 2. `proto/taa.proto` (Protocol Buffers v3)
定义了基于 Protobuf/gRPC 的双向微服务接口与强类型数据结构：
- **`TAAService`**：平台作为客户端向 TAA 发起的控制指令 RPC。
- **`PlatformCallbackService`**：TAA 作为客户端向平台发起的事件上报与注册 RPC。
- 完整的请求载荷、响应包装（`ApiResponse`）、代码审计报告（`AuditReport`）以及远程证明数据结构。

---

## 使用与代码生成

### 1. 浏览与验证 OpenAPI 规范
可直接使用 Swagger Editor、VS Code 插件（如 OpenAPI Editor）或运行本地 Swagger UI 容器查看可视化交互文档：

```bash
# 使用 Docker 快速启动 Swagger UI 预览
docker run -p 8081:8080 -e SWAGGER_JSON=/spec/openapi.yaml -v $(pwd)/api:/spec swaggerapi/swagger-ui
```
启动后访问 `http://localhost:8081` 即可交互式浏览 API 文档。

### 2. 生成 gRPC / Go 代码
如需在项目中使用 gRPC 或生成 Go 结构体代码，可执行以下命令（需预先安装 `protoc` 及 `protoc-gen-go` / `protoc-gen-go-grpc`）：

```bash
# 生成 Go 代码至 api/v1 目录
mkdir -p api/v1
protoc --proto_path=api/proto \
       --go_out=api/v1 --go_opt=paths=source_relative \
       --go-grpc_out=api/v1 --go-grpc_opt=paths=source_relative \
       api/proto/taa.proto
```

### 3. 基于 OpenAPI 生成多语言客户端 SDK
可通过 `openapi-generator` 自动生成前端、Python 或 Java 的客户端交互代码：

```bash
# 示例：生成 Python 客户端 SDK
openapi-generator-cli generate -i api/openapi.yaml -g python -o sdk/python-client
```

---

## 协议版本管理规范

1. **向后兼容性**：新增接口或字段必须保持向后兼容；字段废弃需保留过渡周期，禁止随意修改已有枚举值编号或既定字段名。
2. **多端一致性**：`internal/controller/` 下的实际路由逻辑变更时，应同步更新本目录中的 `openapi.yaml` 与 `taa.proto`。
