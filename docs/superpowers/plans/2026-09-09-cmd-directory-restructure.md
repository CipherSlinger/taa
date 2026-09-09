# Go 标准可执行入口（cmd/）与应用编排层重构实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 TAA 主服务和 Platform Mock 平台模拟器统一重构为标准 Go `cmd/<app>/main.go` 架构，将业务与生命周期编排抽离至 `internal/app/`，保持构建产物（`bin/taa`、`bin/platform-mock`）与部署流程（`deploy.sh`、initrd 打包）零破坏兼容。

**Architecture:** 按照 Standard Go Project Layout 规范，设立 `cmd/taa/` 和 `cmd/platform-mock/` 作为可执行入口，每个 `main.go` 仅包含 20 行左右的配置参数传递与错误捕获；原 `main.go` 与 `platform-mock/main.go` 核心编排分别下沉为 `internal/app/taa` 和 `internal/app/mock`；构建系统 `Makefile` 和 `Dockerfile` 调整构建源，外部部署脚本完全透明。

**Tech Stack:** Go 1.22+, standard library (`net/http`, `os/signal`, `embed`, `flag`), SM2/SM4 crypto (`taa/crypto`), CSV TEE hardware attestation (`taa/internal/attestation`).

**Spec:** `docs/superpowers/specs/2026-09-09-cmd-directory-restructure-design.md`

## Global Constraints

- 提交规范：严禁提及任何 co-author / Anthropic / AI 相关内容，提交信息必须使用严格规范的中文 Conventional Commits。
- 入口极简规范：`cmd/` 下的 `main.go` 代码行数控制在 30 行以内，严格禁止包含具体的加解密、硬件证明或 HTTP 业务处理逻辑。
- 依赖规范：`cmd/` 单向依赖 `internal/app/`，`internal/` 内部单向依赖，严禁循环引用。
- 构建兼容性：Makefile 产物目标必须保持为 `bin/taa` 和 `bin/platform-mock`，确保 `deploy.sh` 与 `build-initrd.sh` 无需修改。
- 测试通过率：现有所有核心控制器测试（`internal/controller/...`）和 mock 测试（`internal/app/mock/...`）必须 100% 通过。

---

### Task 1: 重构 Platform Mock 为 `internal/app/mock` 与 `cmd/platform-mock`

**Files:**
- Create: `internal/app/mock/server.go`
- Create: `internal/app/mock/index.html` (从 `platform-mock/index.html` 复制)
- Create: `internal/app/mock/server_test.go` (从 `platform-mock/main_test.go` 迁移)
- Create: `cmd/platform-mock/main.go`
- Test: `internal/app/mock/server_test.go`

**Interfaces:**
- Consumes: `taa/crypto` (SM2/SM4 密码学测试接口)
- Produces: `mock.Config`, `mock.Run(ctx context.Context, cfg Config) error`, `mock.NewServer(cfg Config) *Server`

- [ ] **Step 1: 创建 `internal/app/mock/` 目录并拷贝静态文件**

```bash
mkdir -p internal/app/mock cmd/platform-mock
cp platform-mock/index.html internal/app/mock/index.html
```

- [ ] **Step 2: 编写 `internal/app/mock/server.go` 编排服务**

实现原 `platform-mock/main.go` 的所有功能结构（`Config`、`Server`、`registerStateStore`、路由反向代理与回调），导出 `Run(ctx context.Context, cfg Config) error` 与 `NewServer(cfg Config) *Server`，包名为 `package mock`。支持嵌入 `index.html`：
```go
package mock

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"taa/crypto"
)

//go:embed index.html
var indexHTML string

type Config struct {
	Addr      string
	TAAAddr   string
	UploadDir string
}

func Run(ctx context.Context, cfg Config) error {
	srv := NewServer(cfg)
	return srv.Start(ctx)
}
```

- [ ] **Step 3: 迁移并调整单元测试 `internal/app/mock/server_test.go`**

将 `platform-mock/main_test.go` 复制为 `internal/app/mock/server_test.go`，包名调整为 `package mock`，针对 `indexHTML` 和路由进行测试。

- [ ] **Step 4: 运行单元测试验证通过**

Run: `go test -v ./internal/app/mock/...`
Expected: PASS 全部测试通过。

- [ ] **Step 5: 编写 `cmd/platform-mock/main.go` 极简可执行入口**

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

- [ ] **Step 6: 验证编译并提交**

Run: `go build -o bin/platform-mock ./cmd/platform-mock`
Expected: 编译成功生成 `bin/platform-mock`。
Commit:
```bash
git add internal/app/mock/ cmd/platform-mock/
git commit -m "feat(mock): 重构平台模拟器至 cmd/platform-mock 与 internal/app/mock"
```

---

### Task 2: 抽象 TAA 运行生命周期与服务编排至 `internal/app/taa`

**Files:**
- Create: `internal/app/taa/app.go`
- Create: `internal/app/taa/server.go`
- Create: `internal/app/taa/app_test.go`
- Test: `internal/app/taa/app_test.go`

**Interfaces:**
- Consumes: `taa/internal/config`, `taa/internal/attestation`, `taa/internal/controller`, `taa/internal/codeaudit`, `taa/crypto`
- Produces: `taa.Run(ctx context.Context, configPath string) error`, `taa.NewApp(cfg config.StartupConfig) (*App, error)`

- [ ] **Step 1: 创建 `internal/app/taa/` 目录**

```bash
mkdir -p internal/app/taa
```

- [ ] **Step 2: 编写 `internal/app/taa/app.go` 生命周期主逻辑**

将原根目录 `main.go` 中的 `run()`、`ensureQwenAvailable`、`generateTAAKeyPair`、`deriveUserData`、`prepareAttestationReport`、`registerPlatform`、`buildSecurityConfig`、`ensureSecurityDirectories` 等抽取至 `package taa`：
```go
package taa

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	teecrypto "taa/crypto"
	"taa/internal/attestation"
	"taa/internal/codeaudit"
	"taa/internal/config"
	"taa/internal/controller"
)

const (
	fixedAttestationFile   = "attestation.report"
	fixedAttestationHelper = "./attestation/get-attestation"
	fixedAttestationMode   = "auto"
)

func Run(ctx context.Context, configPath string) error {
	path := config.DefaultFileName
	if configPath != "" {
		path = configPath
	}
	cfg, err := config.LoadStartupConfig(path)
	if err != nil {
		return fmt.Errorf("load startup config: %w", err)
	}
	return RunWithConfig(ctx, cfg)
}
```

- [ ] **Step 3: 编写 `internal/app/taa/server.go` 服务托管与优雅停机**

实现 `newTAAServer` 以及基于 `ctx.Done()` 的停机控制：
```go
package taa

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"taa/internal/controller"
)

func startServer(ctx context.Context, addr string, state *controller.TAAState) error {
	server := newTAAServer(addr, state)
	errChan := make(chan error, 1)

	go func() {
		log.Printf("taa service listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Printf("taa service received shutdown signal, shutting down gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errChan:
		return err
	}
}
```

- [ ] **Step 4: 编写 `internal/app/taa/app_test.go` 编排层单元测试**

编写测试校验 SM2 密钥生成、UserData 派生（64字节）以及安全配置映射：
```go
package taa

import (
	"testing"

	"taa/internal/config"
)

func TestDeriveUserDataAndKeyPair(t *testing.T) {
	keyPair, err := generateTAAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair failed: %v", err)
	}
	userData, err := deriveUserData(&keyPair.PrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("derive user data failed: %v", err)
	}
	if len(userData) != 64 {
		t.Fatalf("expected 64 bytes userdata, got %d", len(userData))
	}
}
```

- [ ] **Step 5: 运行测试验证**

Run: `go test -v ./internal/app/taa/...`
Expected: PASS 全部测试通过。

- [ ] **Step 6: 提交生命周期编排层代码**

```bash
git add internal/app/taa/
git commit -m "feat(taa): 抽象 TAA 守护进程生命周期与编排层至 internal/app/taa"
```

---

### Task 3: 编写 `cmd/taa` 极简入口并清理根目录旧可执行文件

**Files:**
- Create: `cmd/taa/main.go`
- Delete: `main.go`
- Delete: `platform-mock/` 目录及其下遗留文件
- Test: `go build -o bin/taa ./cmd/taa`

- [ ] **Step 1: 编写 `cmd/taa/main.go`**

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

- [ ] **Step 2: 验证编译生成 `bin/taa`**

Run: `go build -o bin/taa ./cmd/taa`
Expected: 编译成功。

- [ ] **Step 3: 删除根目录旧 `main.go` 与旧 `platform-mock/` 目录**

```bash
git rm -f main.go
git rm -rf platform-mock
```

- [ ] **Step 4: 运行全量单元测试确认未破坏任何引用**

Run: `go test -v ./internal/controller/... ./internal/app/...`
Expected: PASS 全部通过。

- [ ] **Step 5: 提交更改**

```bash
git add cmd/taa/main.go
git commit -m "refactor(taa): 迁移 TAA 可执行入口至 cmd/taa 并清理根目录旧入口"
```

---

### Task 4: 更新构建系统、容器与文档适配

**Files:**
- Modify: `Makefile`
- Modify: `deploy/manifest/docker/Dockerfile`
- Modify: `README.md`
- Modify: `docs/TAA设计文档.md`

- [ ] **Step 1: 更新 `Makefile` 目标路径**

修改 `Makefile` 中的 `taa`、`platform-mock` 与 `platform-mock-build` 目标：
```makefile
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

- [ ] **Step 2: 更新 `deploy/manifest/docker/Dockerfile`**

将 `RUN CGO_ENABLED=0 GOOS=linux go build -o /out/app main.go` 修改为：
```dockerfile
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/app ./cmd/taa
```

- [ ] **Step 3: 更新 `README.md` 与 `docs/TAA设计文档.md` 目录树与文档引用**

更新文档中的目录树示意，说明 `cmd/` 作���可执行入口，`internal/app/` 作为启动编排层。

- [ ] **Step 4: 测试 Makefile 构建目标**

Run: `make taa && make platform-mock-build`
Expected:
```text
[build] building taa daemon from ./cmd/taa...
[build] building platform-mock from ./cmd/platform-mock...
```
产物 `bin/taa` 与 `bin/platform-mock` 均正常生成。

- [ ] **Step 5: 提交构建系统与文档调整**

```bash
git add Makefile deploy/manifest/docker/Dockerfile README.md docs/TAA设计文档.md
git commit -m "build: 适配 Makefile、Dockerfile 及架构文档至 cmd/ 目录结构"
```

---

### Task 5: 全流程回归验证与集成测试

**Files:**
- Test: 全库单元测试与本地部署全流程

- [ ] **Step 1: 运行全库 Go 单元测试**

Run: `go test ./internal/...`
Expected: 全部 internal 包（`controller`, `crypto`, `audit`, `attestation`, `app/...`）测试通过。

- [ ] **Step 2: 本地全流程部署启动测试 (`deploy.sh local`)**

执行本地部署启动命令验证 TAA 与 Platform Mock 连通：
```bash
./deploy.sh local start
```
验证：
- Platform Mock 启动并在 8080 端口提供 Web UI。
- TAA 启动在 6001 端口并向 Platform Mock 注册。
- `/v1/taa/health` 探针返回 HTTP 200。

- [ ] **Step 3: 本地部署停止与优雅退出测试**

```bash
./deploy.sh local stop
```
验证各进程均能正常响应信号优雅退出，无孤儿进程残留。

- [ ] **Step 4: 检查工作区状态并完成最终提交**

确认工作区无未跟踪垃圾文件，提交最终验证记录。
