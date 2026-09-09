# Go 标准可执行入口（cmd/）与应用编排层重构设计规范

- **日期**：2026-09-09
- **状态**：已评审确认（Ready for Implementation）
- **适用范围**：TAA（Trusted Application Agent）主工程与 Platform Mock 平台模拟器

---

## 1. 背景与目标

### 1.1 现状与问题
当前仓库的可执行程序入口分散在根目录和顶层子目录中：
1. 根目录 `main.go`（483 行）承担了 TAA 守护进程的完整生命周期，混杂了参数解析、硬件证明生成（CSV Attestation）、SM2 密钥初始化、UserData 派生、平台注册交互、内存日志缓冲区初始化以及 HTTP 服务启动等逻辑。
2. 平台模拟器位于根目录下的 `platform-mock/main.go`（550 行），直接在顶层包内实现 Mock 控制台 UI 嵌入、路由处理、任务派发与反向代理。
3. 根目录缺乏标准的 Go 可执行程序布局，违反了社区通用的 Go 标准目录规范（Standard Go Project Layout），且使得启动引导逻辑与业务领域逻辑紧密耦合，不利于自动化测试与多子应用扩展。

### 1.2 重构目标
1. **引入标准的 `cmd/` 可执行入口**：
   - 建立 `cmd/taa/` 和 `cmd/platform-mock/` 目录结构，每个子目录下仅包含 `package main`。
   - `cmd/` 中的 `main.go` 严格限制为“极薄入口”（Thin Entrypoint，约 20 行），只负责参数解析、信号捕获与调用 `internal/app/`，严格禁止编写业务逻辑。
2. **抽象应用编排层 `internal/app/`**：
   - 将 TAA 启动组装、硬件自检、依赖注入与优雅停机收拢至 `internal/app/taa/`。
   - 将平台模拟器的服务编排、嵌入式 UI、反向代理与回调收拢至 `internal/app/mock/`。
3. **构建与部署零破坏兼容**：
   - 构建产物路径与文件名保持不变（`bin/taa`、`bin/platform-mock`）。
   - `deploy.sh`（支持 local、local-docker、remote k8s 等全场景）与 `build-initrd.sh` 零改动平滑过渡。

---

## 2. 整体架构与目录结构

### 2.1 目录结构映射

```text
.
├── cmd/                                  # 可执行程序入口集合（仅做引导、参数分发与退出码管理）
│   ├── taa/
│   │   └── main.go                       # TAA 主服务入口（~20行）
│   └── platform-mock/
│       └── main.go                       # Platform Mock 入口（~20行）
│
├── internal/                             # 私有领域逻辑与应用组装层
│   ├── app/                              # 应用装配与运行生命周期层
│   │   ├── taa/                          # TAA 守护进程编排
│   │   │   ├── app.go                    # 配置合并、硬件证明检查、平台注册与生命周期 Run
│   │   │   └── server.go                 # 日志流转挂载、HTTP 路由注册、优雅停机
│   │   └── mock/                         # 平台模拟器编排
│   │       ├── server.go                 # Mock 路由、反向代理、任务回调实现
│   │       ├── index.html                # 嵌入式控制台网页（go:embed）
│   │       └── server_test.go            # 模拟器单元与路由白盒测试（原 main_test.go 迁移）
│   ├── attestation/                      # 既有硬件证明生成与解析
│   ├── config/                           # 既有配置定义与加载
│   ├── controller/                       # 既有核心控制器与执行管道
│   ├── crypto/                           # 既有 SM2/SM4 密码学实现
│   ├── audit/                            # 既有规则与 LLM 代码审计
│   └── ...                               # 其他既有内部包
│
├── Makefile                              # 编译配置（构建源更新至 ./cmd/..., 产物输出保持 bin/）
├── deploy/
│   └── manifest/docker/Dockerfile        # 容器镜像编译构建更新
└── sdk/                                  # 独立客户端 SDK 模块（保持独立体系不变）
```

### 2.2 各层级权责边界规范

| 层级 | 包路径 | 职责与规范 | 禁止项 |
| :--- | :--- | :--- | :--- |
| **入口引导层** | `cmd/<name>/main.go` | 1. 声明 `package main`<br>2. 解析基础命令行参数（`flag.Parse`）<br>3. 监听系统中断信号（`SIGINT`/`SIGTERM`）<br>4. 调用 `internal/app/<name>.Run(ctx, cfg)`<br>5. 捕获非空错误并执行 `os.Exit(1)` | 1. 包含具体业务判断与处理<br>2. 直接初始化深层控制器或密码学工具<br>3. 超过 30 行引导逻辑 |
| **应用编排层** | `internal/app/<name>/` | 1. 完整的配置加载与环境校验<br>2. 实例化硬件检查、平台注册、加解密上下文<br>3. 初始化日志缓冲与路由注册<br>4. 统一管理网络 Server 生命周期与优雅退出 | 1. 编写独立可执行的 `main` 函数<br>2. 相互跨应用直接依赖（如 `taa` 依赖 `mock` 或反之） |
| **领域核心层** | `internal/{controller,attestation,...}` | 1. 提供领域抽象、算法、数据结构与 HTTP Handler<br>2. 纯粹的领域逻辑单元测试 | 1. 反向依赖 `cmd/` 或 `internal/app/`<br>2. 硬编码与特定可执行文件绑定的参数解析 |

---

## 3. 详细设计与实现方案

### 3.1 TAA 守护进程重构

#### 3.1.1 入口文件：`cmd/taa/main.go`
```go
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"taa/internal/app/taa"
)

func main() {
	configFile := flag.String("config", "", "Path to taa-config.json (optional)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := taa.Run(ctx, *configFile); err != nil {
		log.Printf("[TAA-FATAL] %v", err)
		os.Exit(1)
	}
}
```

#### 3.1.2 编排生命周期：`internal/app/taa/app.go`
- **生命周期入口**：`Run(ctx context.Context, configPath string) error`。
- **启动编排步骤**：
  1. **配置装载**：调用 `config.LoadConfig(configPath)` 并按既有逻辑与 `StartupConfig` 合并。
  2. **硬件证明与运行时密钥初始化**：
     - 生成临时 SM2 运行时公私钥对；
     - 派生 64 字节 `UserData`（SHA256(PublicKey) + 时间戳）；
     - 检查并执行 `./attestation/get-attestation` 助手生成硬件度量报告；
     - 对比验证报告中包含的 `UserData`，确保硬件报告有效。
  3. **平台注册联动**：
     - 若配置了 `PlatformIP`，调用 `controller.RegisterToPlatform` 上报硬件报告与公钥；
     - 注册失败则依安全策略进行报错拦截或重试。
  4. **依赖注入与组装**：
     - 将配置、密钥、证明报告注入上下文。
  5. **服务托管**：
     - 转交 `startHTTPServer(ctx, cfg, report, privKey)`，等待上下文取消信号或致命错误。

#### 3.1.3 HTTP 服务与优雅退出：`internal/app/taa/server.go`
- 初始化内存日志管道：调用 `controller.InitMemoryLogBuffer`，设置日志多路复用（`io.MultiWriter(os.Stdout, buffer)`）。
- 路由挂载：调用 `controller.SetupRoutes`，注入审计控制器、加解密控制器与证明控制器。
- 优雅停机：
  ```go
  go func() {
      if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
          serverErrChan <- err
      }
  }()

  select {
  case <-ctx.Done():
      shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
      defer cancel()
      return httpServer.Shutdown(shutdownCtx)
  case err := <-serverErrChan:
      return err
  }
  ```

---

### 3.2 Platform Mock 重构

#### 3.2.1 入口文件：`cmd/platform-mock/main.go`
```go
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"taa/internal/app/mock"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:8080", "Platform mock listen address")
	taaAddr := flag.String("taa-addr", "127.0.0.1:6001", "Target TAA daemon address")
	uploadDir := flag.String("upload-dir", "./uploads", "Upload storage directory")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := mock.Config{
		Addr:      *addr,
		TAAAddr:   *taaAddr,
		UploadDir: *uploadDir,
	}

	if err := mock.Run(ctx, cfg); err != nil {
		log.Printf("[MOCK-FATAL] %v", err)
		os.Exit(1)
	}
}
```

#### 3.2.2 模拟器实现：`internal/app/mock/server.go`
- **静态 UI 嵌入**：
  将 `platform-mock/index.html` 移入 `internal/app/mock/index.html`：
  ```go
  //go:embed index.html
  var indexHTML []byte
  ```
- **核心组件**：
  - `Config` 结构体：监听地址、目标 TAA 地址、上传与静态资源目录。
  - `Server` 结构体：封装标准 `http.ServeMux` 与 `httputil.ReverseProxy`。
  - 路由挂载：
    - `/` 与 `/index.html`：直接吐出嵌入的 `indexHTML`；
    - `/v1/platform/register`：设备注册接收；
    - `/v1/platform/report`：审计与推理任务结果收集；
    - `/v1/platform/tasks`：下发测试任务与测试数据；
    - `/v1/platform/upload`：静态模型与数据集文件接收；
    - `/taa/*`：反向代理至配置的 `TAAAddr`。
- **测试用例平移**：
  原 `platform-mock/main_test.go` 平移为 `internal/app/mock/server_test.go`，包名更新为 `package mock`。

---

## 4. 构建与部署适配矩阵

### 4.1 Makefile 改造
保持原有构建目标名称与输出产物不变，仅调整源码入口：

```makefile
TAA_BINARY ?= bin/taa
MOCK_BINARY ?= bin/platform-mock

taa:
	@mkdir -p $(dir $(TAA_BINARY))
	@echo "[build] building taa daemon from ./cmd/taa..."
	@go build -o $(TAA_BINARY) ./cmd/taa

platform-mock:
	@go run ./cmd/platform-mock -addr 0.0.0.0:8080

platform-mock-build:
	@mkdir -p $(dir $(MOCK_BINARY))
	@echo "[build] building platform-mock from ./cmd/platform-mock..."
	@go build -o $(MOCK_BINARY) ./cmd/platform-mock
```

### 4.2 Dockerfile 改造
`deploy/manifest/docker/Dockerfile` 更新编译行：
```dockerfile
# 编译源代码定位到 ./cmd/taa
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/app ./cmd/taa
```
容器执行命令 `ENTRYPOINT ["/app"]` 保持不变。

### 4.3 自动化脚本兼容性确认
- **`deploy.sh`**：
  依赖 `make TAA_BINARY=... taa` 以及产物路径 `bin/taa` 和 `bin/platform-mock`。由于构建变量与产物位置完全保持一致，`deploy.sh` **零改动即可 100% 兼容运行**。
- **`deploy/guest-build/build-initrd.sh`**：
  读取打包路径 `$ROOT_DIR/bin/taa`，对源码重构**完全解耦，零改动**。

---

## 5. 迁移与清理步骤

1. **新建目标目录**：
   - `cmd/taa/`
   - `cmd/platform-mock/`
   - `internal/app/taa/`
   - `internal/app/mock/`
2. **实现与移动文件**：
   - 编写 `cmd/taa/main.go`，将原 `main.go` 的编排逻辑抽取入 `internal/app/taa/app.go` 与 `internal/app/taa/server.go`；
   - 编写 `cmd/platform-mock/main.go`，将原 `platform-mock/main.go` 抽取为 `internal/app/mock/server.go`；
   - 移动 `platform-mock/index.html` 至 `internal/app/mock/index.html`；
   - 移动 `platform-mock/main_test.go` 至 `internal/app/mock/server_test.go` 并修正包名。
3. **清理遗留文件与目录**：
   - 删除根目录 `main.go`；
   - 删除旧目录 `platform-mock/`（包含其中残留的二进制调试文件）；
   - 更新 `.gitignore` 确保不再误跟踪根目录临时可执行文件。
4. **更新配置文件与文档**：
   - 更新 `Makefile` 与 `deploy/manifest/docker/Dockerfile`；
   - 更新 `README.md` 与 `docs/TAA设计文档.md` 中的目录树与路径引用。

---

## 6. 测试与验证策略

1. **单元测试与回归测试**：
   - 运行 `go test ./internal/app/mock/...` 确保模拟器接口与测试 100% 通过；
   - 运行核心控制器的既有测试集（`go test ./internal/controller/...`）验证领域逻辑未受影响。
2. **全流程编译测试**：
   - 执行 `make taa`，校验 `bin/taa` 生成与 ELF 属性；
   - 执行 `make platform-mock-build`，校验 `bin/platform-mock` 成功嵌入 `index.html`。
3. **本地部署集成验证**：
   - 执行 `./deploy.sh local start`，验证本地开发模式下 platform-mock 与 taa 互联互通及 `/v1/taa/health` 探针检查；
   - 执行 `./deploy.sh local stop`，确认两进程均能响应信号正常停机。
