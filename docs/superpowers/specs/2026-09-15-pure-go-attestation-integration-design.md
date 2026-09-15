# 远程证明纯 Go 原生集成与预编译二进制解耦设计文档

## 1. 背景与目标

### 1.1 现状分析
当前 TAA 服务的远程证明生成流程严重依赖外部 C 语言预编译二进制文件：
- 运行时链路：`internal/app/taa/app.go` 固定配置了 `fixedAttestationHelper = "./attestation/get-attestation"`，通过 `internal/attestation/generate.go` 中的 `exec.CommandContext` 唤起外部子进程生成 `report.cert`。
- 构建与部署：根目录 `Makefile` 依赖外部 GmSSL 路径编译 C 助手，在缺乏特定源码树的机器上编译受阻；`deploy.sh` 则因此通过回退逻辑拷贝 `attestation/bin/get-attestation`（预编译文件约 25MB）到运行时环境。
- 底层储备：底层纯 Go 实现的海光 CSV 硬件交互模块 `pkg/csvattest`（基于 Linux AMD64 下的 `/dev/csv-guest` 设备 `SYS_IOCTL` 系统调用）及证书链验证库已经就绪且单测完备，但尚未与 TAA 主程序闭环集成。

### 1.2 重构目标
1. **纯 Go 原生集成**：将 `internal/attestation` 的报告生成底层重构为直接调用 `pkg/csvattest`，彻底移除通过 `exec.Command` 执行外部进程的模式。
2. **剔除无用参数**：全面清理 `internal/app` 与 `internal/controller` 中遗留的历史参数（`fixedAttestationHelper`、`fixedAttestationMode`、`helperPath` 等）。
3. **彻底移除预编译二进制**：从代码库中删除 `attestation/bin/` 下所有预编译可执行文件、动态库与静态库，为代码仓库瘦身约 25MB。
4. **精简构建与部署系统**：从 `Makefile`、`deploy.sh` 及 `build-initrd.sh` 中移除对证明二进制助手的编译、复制、容器注入与权限校验逻辑。
5. **健壮性与可测性保证**：保留开发测试环境（无海光 CSV 硬件设备）下的优雅降级机制，保持单元测试在任何架构与环境下 100% 稳定运行。

---

## 2. 详细系统设计

### 2.1 架构分层设计

```
+-------------------------------------------------------------------+
|                           TAA 业务层                               |
|   cmd/taa  <-->  internal/app/taa  <-->  internal/controller      |
+-------------------------------------------------------------------+
                                  │
                                  ▼
+-------------------------------------------------------------------+
|                     internal/attestation (业务门面)                |
|  - Generate(ctx, Config): 业务调度、参数校验、报告与 Nonce 落盘       |
|  - ExtractReportValues(reportPath): 解析 2548B 二进制提取业务 JSON  |
+-------------------------------------------------------------------+
                                  │
                                  ▼
+-------------------------------------------------------------------+
|                       pkg/csvattest (硬件驱动)                    |
|  - Client / PlatformOps: 管理 /dev/csv-guest 设备通信               |
|  - SYS_IOCTL: 分配对齐物理内存页，发送 IOCTL 指令                  |
|  - Session MAC & MNonce 校验，ZeroReserved2 格式化规范             |
|  - VerifyAttestationReport: HRK->HSK->CEK->PEK 证书链纯 Go 验签    |
+-------------------------------------------------------------------+
                                  │
                                  ▼
                     Linux 内核 /dev/csv-guest
```

### 2.2 核心接口与数据结构重构

#### `internal/attestation/generate.go`
废除子进程与外部路径探测字段，精简为纯数据结构：
```go
package attestation

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"taa/pkg/csvattest"
)

const UserDataSize = 64

type Config struct {
	OutputPath string // 证明报告输出文件路径（必填）
	DevicePath string // /dev/csv-guest 设备路径，为空时使用默认硬件路径
	UserData   []byte // 64 字节公钥哈希或公钥坐标（必填，必须正好 64 字节）
	Nonce      []byte // 可选 16 字节 nonce，为空时由驱动自动安全生成
}

// Generate 生成远程证明报告并落盘
func Generate(ctx context.Context, cfg Config) error
```

`Generate` 的处理逻辑：
1. 校验 `OutputPath` 是否非空，计算绝对路径，创建父目录。
2. 校验 `UserData` 长度是否为 64 字节。
3. 校验或生成 `nonce`（若传入且不为空，必须为 16 字节；若为空则生成 16 字节随机数，并可选在同级目录生成 `nonce.bin` 保持与外部工具的兼容）。
4. 构造 `csvattest.NewClient(...)`，传入设备路径与 `UserData`。
5. 分配 2548 字节切片 `reportBuf := make([]byte, csvattest.ReportSize)`。
6. 调用 `client.GetAttestationReportIOCTL(reportBuf, nonce)`。
7. 将生成的报告数据写入临时文件并原子替换到 `OutputPath`。

#### `internal/app/taa/app.go`
1. 移除常量 `fixedAttestationHelper` 与 `fixedAttestationMode`。
2. 启动生成证明报告时：
   ```go
   if err := attestation.Generate(ctx, attestation.Config{
       OutputPath: fixedAttestationFile,
       UserData:   userData,
   }); err != nil {
       log.Printf("WARNING: generating attestation report failed, continuing with empty report: %v", err)
       if writeErr := os.WriteFile(fixedAttestationFile, nil, 0o600); writeErr != nil {
           return fmt.Errorf("write empty attestation report: %w", writeErr)
       }
   }
   ```
3. 构造 `NewTAAState` 时不再传递 helper 路径和模式。

#### `internal/controller/route.go`
1. `NewTAAState` 签名重构：
   ```go
   func NewTAAState(attestationFile, platformIP, dockerID string, sm2Key *teecrypto.SM2PrivateKey, userData []byte, sec SecurityConfig) *TAAState
   ```
2. `buildAttestationResult` 签名与实现重构：
   移除未使用的 `helperPath`、`helperMode` 参数，直接调用 `attestation.Generate`。

### 2.3 异常处理与降级机制
1. **设备缺失/无权限**：
   在无硬件/无 root 权限或非 Linux AMD64 平台下，`csvattest` 返回明确错误（如 `open /dev/csv-guest: no such file or directory` 或 `ErrUnsupported`）。
2. **启动降级**：
   `app.go` 捕获该错误，输出 WARNING 级别日志，并落盘 0 字节占位文件，确保本地开发调试和服务容器能够正常启动。
3. **接口降级**：
   `/v1/attestation` 重新生成失败时，记录日志并返回空报告字符串，返回适当的状态描述，保证接口不崩溃。

### 2.4 测试与验证方案
1. **单元测试解耦**：
   在 `internal/attestation` 中提供可替换的底层执行器或复用 `csvattest` 内部的虚拟设备/测试夹具，覆盖：
   - 成功生成报告与落盘流程
   - 参数校验失败（缺少输出路径、UserData 长度不合法、Nonce 长度不合法等）
   - 设备不存在时的错误返回
2. **控制器回归测试**：
   更新 `internal/controller` 的 `handler_test.go` 和 `register_test.go`，确保 `NewTAAState` 签名对齐，全部单测通过。
3. **端到端编译与全量测试**：
   执行 `go test ./pkg/... ./internal/... ./cmd/...` 验证全量代码库无回归缺陷。

---

## 3. 清理清单 (Deprecation & Deletion)

### 3.1 仓库文件删除
从 git 追踪中移除：
- `attestation/bin/` 目录及其所有内容（`get-attestation`, `ioctl-get-attestation`, `vmmcall-get-attestation`, `verify-attestation`, `libcsv.so`, `libcsv.a`, `dcu_attestation_demo` 等约 25MB）
- 根目录构建临时产物（如 `bin/ioctl-get-attestation`、`bin/get-attestation`）

### 3.2 构建系统精简（`Makefile`）
- 移除 `attestation-ioctl` 和 `attestation-vmmcall` 目标。
- 精简 `run` 依赖为仅 `taa`。
- 精简 `clean` 目标。
- 更新 `help` 文档。

### 3.3 部署脚本精简（`deploy.sh` 与 `build-initrd.sh`）
- `deploy.sh`：
  - 移除变量 `ATT_HELPER_SOURCE`。
  - 移除函数 `build_attestation_helper`。
  - 移除编译构建阶段对 attestation helper 的构建和 `require_file` 检查。
  - 移除目标容器部署阶段对 `get-attestation` 文件的传输、拷贝与权限赋予（`chmod +x`）。
- `deploy/guest-build/build-initrd.sh`：
  - 移除变量 `ATTESTATION_HELPER_SRC`。
  - 移除向 initrd 注入 `attestation/get-attestation` 的逻辑及相关清单校验。
