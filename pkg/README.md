# PKG 公共可复用库 (Public Reusable Libraries)

本目录遵循 [Standard Go Project Layout](https://github.com/golang-standards/project-layout/blob/master/README_zh.md) 架构规范，用于存放**可以被外部项目或内部其他模块安全导入、与当前业务逻辑完全解耦的通用工具代码（“轮子”）**。

---

## 一、包设计原则

1. **业务无关（Business-Agnostic）**：严禁导入 `internal/`、业务配置或特定业务状态模型。
2. **安全可复用（Safe to Import）**：对外暴露稳定、简洁且向后兼容的公共 API。
3. **零/低外部依赖（Minimal Dependencies）**：优先使用 Go 标准库，避免引入重量级间接依赖。
4. **单向引用（Unidirectional Dependency）**：`internal/` 和 `cmd/` 可以引用 `pkg/`，但 `pkg/` 绝不能反向引用业务层代码。

---

## 二、当前已就绪的通用包

### 1. `pkg/errors` — 强类型业务/系统错误定义
- **核心能力**：
  - 带数值状态码（`Code`）的错误封装（`New`、`Errorf`、`Wrap`、`Wrapf`）。
  - 支持完整的 Cause 错误链追踪，与标准库 `errors.Is`、`errors.As` 和 Go 1.13+ `Unwrap` 原生兼容。
  - 提供 `CodeOf(err)` 工具函数，快速从未知错误中提取状态码或映射为默认兜底码。
- **适用场景**：HTTP 接口错误响应、RPC 返回值转换及各底层库的统一错误包裹。

### 2. `pkg/logger` — 轻量分级日志与有界内存日志池
- **核心能力**：
  - 提供 `Store` 有界环形内存日志缓冲区（Ring Buffer），固定容量，溢出自动淘汰最旧记录。
  - 支持 ANSI 终端彩色高亮输出（Debug 青色 / Info 绿色 / Warn 黄色 / Error 红色）。
  - 支持 `Since(time.Time)` 增量拉取、`All()` 快照拷贝、`Drain()` 排空消费以及并发安全读写保护。
  - 结构化 `Entry` 支持原生 JSON 序列化。
- **适用场景**：替代散落在 `internal/controller/log_store.go` 和 `mock/server.go` 中的重复内存日志实现，支持平台增量拉取容器内部执行日志。

### 3. `pkg/utils` — 通用工具箱
- **文件与路径处理 (`file.go`)**：
  - `SafeFilename(name)`：过滤非法字符与 `../` 等路径遍历风险，生成安全的落盘文件名片段。
  - `CopyDir(dst, src)`：递归复制目录树，完整保留软链接及原始文件权限（包含可执行位）。
  - `CopyFile(dst, src, perm)`：单个文件安全复制并执行文件同步落盘（`fsync`）。
  - `CleanDir(dir)`：清空目录下所有子文件与子目录，同时保留该目录自身。
  - `EnsureDir(dir, perm)`：幂等创建目录。
- **字符串与时间处理 (`string.go`)**：
  - `RandomHex(bytes)` / `RandomString(len)`：基于 `crypto/rand` 的密码学安全随机字符串与 Nonce 生成器。
  - `FormatBytes(bytes)`：将字节数转换为友好显示格式（如 `1.50 MB`, `120 KB`）。
  - `ParseISO8601(str)` / `FormatISO8601(time)`：统一的 UTC RFC3339/ISO8601 时间格式化与反序列化。

---

## 三、全项目现有实现检索与进入 `pkg/` 的梳理清单

经过对本项目全量代码库的系统性检索，以下现有实现属于与具体 TAA 业务解耦的“通用轮子”，具备迁入 `pkg/` 的高度价值：

| 原模块路径 | 功能描述 | 业务解耦度 | 建议迁移目标 | 梳理与建议理由 |
|---|---|:---:|---|---|
| `filetree/` | **多模态数据集目录树解析与 Schema 提取**<br>通过魔数识别 CSV/TSV/XLSX/JSON/SQLite/Parquet/图片/PDF/压缩包，防 Zip Bomb 与内存溢出。 | **100% 纯轮子** | `pkg/filetree` | 位于根目录，其实现完全与 TAA、TEE 业务无耦合。外部任何数据管理平台或 AI 数据预处理项目均可直接复用。 |
| `crypto/` | **国密 SM2/SM3/SM4-GCM 加密与安全信封**<br>实现了 SM4-GCM 对称加解密、SM2 密钥生成/加解密/PEM 解析、国密混合信封封装及防目录逃逸的归档解压。 | **100% 纯轮子** | `pkg/crypto` | 现位于根目录 `crypto/`，客户端 SDK（`sdk/`）已在复用它。作为成熟通用的国密计算库，符合 `pkg/` 标准定位。 |
| `internal/controller/log_store.go`<br>`internal/app/mock/server.go` (内嵌) | **有界结构化内存日志记录器**<br>支持增量获取、日志上限丢弃与 ANSI 彩色终端输出。 | **100% 纯轮子** | `pkg/logger`<br>*(本次已落地)* | 两处出现重复代码实现，逻辑完全一致。抽取至 `pkg/logger` 后可供控制台、控制器与各子应用统一引用。 |
| `internal/controller/import_helpers.go`<br>`internal/controller/route.go` | **文件目录操作与文件名清洗**<br>包含 `copyDir`、`copyFile`、`cleanDirContents`、`safeFilenamePart`。 | **100% 纯轮子** | `pkg/utils`<br>*(本次已落地)* | 当前散落在 Controller 内部，但在模型解包、数据准备、产物备份等多处被调用，属于通用基础文件工具。 |
| `attestation/csv_go/` | **海光 CSV TEE 纯 Go 底层通信与证书链验证**<br>封装 `/dev/csv-guest` IOCTL，解析 CSV 证明报告并验证 HRK→HSK→CEK→PEK 证书链。 | **硬件驱动级轮子** | `pkg/csvattest` 或独立 SDK | 与上层应用逻辑解耦，是纯粹的海光 CSV 硬件交互驱动与报告验证器，适合封装为通用硬件证明库供所有 CSV 机密计算应用导入。 |

---

## 四、外部引用示例

外部项目或内部模块引用方式：

```go
import (
    "taa/pkg/errors"
    "taa/pkg/logger"
    "taa/pkg/utils"
)

// 1. 使用通用错误封装
if err != nil {
    return errors.Wrap(errors.CodeInvalidArgument, "invalid parameter", err)
}

// 2. 使用有界日志池
logStore := logger.NewStore(1000)
logStore.Info("worker", "process batch %d complete", batchID)

// 3. 使用安全文件与文件名工具
safeName := utils.SafeFilename("../../malicious/path/data.zip") // 得到 "malicious-path-data.zip"
utils.CopyDir("/target/dir", "/source/dir")
randomToken := utils.RandomString(32)
```
