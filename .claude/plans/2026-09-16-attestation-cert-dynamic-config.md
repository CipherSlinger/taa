# 远程证明证书动态配置化与加载自检实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 将海光 CSV 远程证明根证书与背书证书从遗留目录迁移至 `deploy/certs/`，支持配置文件显式配置证书路径，在 TAA 服务生命周期中集成基于配置证书的报告自检与动态 `verifiedPass` 判定，并完成 `deploy.sh` 自动化闭环与遗留 `attestation/` 目录清理。

**Architecture:** 采用分层解耦架构：
1. **基础设施与配置层**：将官方证书集中收敛到 `deploy/certs/`，在 `configs/taa-*.json` 与 `internal/config/config.go` 中提供嵌套 `attestation` 证书路径模型与智能默认值；
2. **底层驱动层 (`pkg/csvattest`)**：抽象导出 `LoadCertChainFromFiles` 与 `VerifyReportWithOptions`，支持显式绝对/相对文件路径入参，保留历史接口向下兼容；
3. **业务门面与运行时自检层 (`internal/attestation`, `internal/app/taa`, `internal/controller`)**：封装报告自检接口，在 TAA 启动生成报告与 `/v1/taa/getAttestation` 动态生成报告时触发真实证书链自检，根据自检结果动态赋予并上报 `verifiedPass`；
4. **运维部署层 (`deploy.sh`)**：证书源指向 `deploy/certs/`，目标对齐容器内 `/root/taa/certs/`，并在模板渲染时动态注入证书路径。

**Tech Stack:** Go 1.22+, Linux ioctl (`/dev/csv-guest`), Hygon CSV Remote Attestation, GM/T 国密 (SM2/SM3), Bash, Docker.

---

### Task 1: 迁移证书至 `deploy/certs/` 并彻底清理遗留 `attestation/` 目录

**Files:**
- Create: `deploy/certs/hrk.cert`
- Create: `deploy/certs/hsk_cek.cert`
- Delete: `attestation/` (整个目录及其下全部文件)

- [x] **Step 1: 创建目标目录并复制证书文件**

```bash
mkdir -p deploy/certs
cp attestation/hrk.cert deploy/certs/hrk.cert
cp attestation/hsk_cek.cert deploy/certs/hsk_cek.cert
chmod 0644 deploy/certs/hrk.cert deploy/certs/hsk_cek.cert
```

- [x] **Step 2: 验证新证书文件完整性**

```bash
ls -l deploy/certs/
test -s deploy/certs/hrk.cert && test -s deploy/certs/hsk_cek.cert
cmp attestation/hrk.cert deploy/certs/hrk.cert
cmp attestation/hsk_cek.cert deploy/certs/hsk_cek.cert
```
Expected: 文件存在、大小一致（hrk.cert 832B, hsk_cek.cert 2916B），cmp 返回码 0。

- [x] **Step 3: 删除根目录 `attestation/` 目录**

```bash
git rm -r attestation/
```

- [x] **Step 4: 暂存证书文件并确认工作区状态**

```bash
git add deploy/certs/hrk.cert deploy/certs/hsk_cek.cert
git status -s deploy/certs/ attestation/
```

- [x] **Step 5: 提交更改**

```bash
git commit -m "refactor(attestation): migrate certificates to deploy/certs and remove legacy attestation directory"
```

---

### Task 2: 配置模型扩展 (`internal/config` 与模板文件)

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `configs/taa-production.json`
- Modify: `configs/taa-docker.json`
- Modify: `configs/taa-local.json`

- [x] **Step 1: 编写配置解析失败的单元测试**

在 `internal/config/config_test.go` 文件末尾增加针对 `attestation` 字段解析及回退的测试用例：

```go
func TestLoadStartupConfigReadsAttestationCertPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	content := `{
		"attestation": {
			"hrkCertPath": "/custom/path/hrk.cert",
			"hskCekCertPath": "/custom/path/hsk_cek.cert"
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.AttestationHRKCertPath != "/custom/path/hrk.cert" {
		t.Errorf("AttestationHRKCertPath = %q, want %q", cfg.AttestationHRKCertPath, "/custom/path/hrk.cert")
	}
	if cfg.AttestationHSKCekCertPath != "/custom/path/hsk_cek.cert" {
		t.Errorf("AttestationHSKCekCertPath = %q, want %q", cfg.AttestationHSKCekCertPath, "/custom/path/hsk_cek.cert")
	}
}

func TestLoadStartupConfigAttestationTrimWhitespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	content := `{
		"attestation": {
			"hrkCertPath": "  /trimmed/hrk.cert  ",
			"hskCekCertPath": "  /trimmed/hsk_cek.cert  "
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.AttestationHRKCertPath != "/trimmed/hrk.cert" {
		t.Errorf("AttestationHRKCertPath = %q, want %q", cfg.AttestationHRKCertPath, "/trimmed/hrk.cert")
	}
	if cfg.AttestationHSKCekCertPath != "/trimmed/hsk_cek.cert" {
		t.Errorf("AttestationHSKCekCertPath = %q, want %q", cfg.AttestationHSKCekCertPath, "/trimmed/hsk_cek.cert")
	}
}
```

- [x] **Step 2: 运行测试验证失败**

```bash
go test -v ./internal/config -run "TestLoadStartupConfigReadsAttestationCertPaths"
```
Expected: 编译报错或断言失败（`cfg.AttestationHRKCertPath` 未定义）。

- [x] **Step 3: 在 `internal/config/config.go` 中实现配置扩展**

修改 `internal/config/config.go`：
1. 在 `StartupConfig` 结构体中添加：
```go
	AttestationHRKCertPath    string
	AttestationHSKCekCertPath string
```
2. 定义 `startupAttestationConfigFile` 并在 `startupConfigFile` 中引入：
```go
type startupAttestationConfigFile struct {
	HRKCertPath    string `json:"hrkCertPath"`
	HSKCekCertPath string `json:"hskCekCertPath"`
}

type startupConfigFile struct {
    // ... 现有字段 ...
	Attestation        startupAttestationConfigFile `json:"attestation"`
}
```
3. 在 `defaultStartupConfig()` 中增加智能自适应默认值：
```go
	hrkDefault := "/root/taa/certs/hrk.cert"
	hskDefault := "/root/taa/certs/hsk_cek.cert"
	if _, err := os.Stat(hrkDefault); err != nil {
		if _, localErr := os.Stat("deploy/certs/hrk.cert"); localErr == nil {
			hrkDefault = "deploy/certs/hrk.cert"
			hskDefault = "deploy/certs/hsk_cek.cert"
		}
	}
```
并赋给 `AttestationHRKCertPath: hrkDefault`, `AttestationHSKCekCertPath: hskDefault`。
4. 在 `applyStartupConfigFile` 中增加覆盖逻辑：
```go
	if trimmed := strings.TrimSpace(fileCfg.Attestation.HRKCertPath); trimmed != "" {
		cfg.AttestationHRKCertPath = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Attestation.HSKCekCertPath); trimmed != "" {
		cfg.AttestationHSKCekCertPath = trimmed
	}
```

- [x] **Step 4: 更新模板配置文件**

在 `configs/taa-production.json` 和 `configs/taa-docker.json` 中增加：
```json
  "attestation": {
    "hrkCertPath": "/root/taa/certs/hrk.cert",
    "hskCekCertPath": "/root/taa/certs/hsk_cek.cert"
  },
```
在 `configs/taa-local.json` 中增加：
```json
  "attestation": {
    "hrkCertPath": "deploy/certs/hrk.cert",
    "hskCekCertPath": "deploy/certs/hsk_cek.cert"
  },
```

- [x] **Step 5: 重新运行单测并验证通过**

```bash
go test -v ./internal/config/...
```
Expected: PASS 全部通过。

- [x] **Step 6: 提交更改**

```bash
git add internal/config/ configs/
git commit -m "feat(config): add attestation certificate path configuration support"
```

---

### Task 3: 底层驱动层解耦支持显式文件路径 (`pkg/csvattest`)

**Files:**
- Modify: `pkg/csvattest/verify.go`
- Modify: `pkg/csvattest/verify_test.go`

- [x] **Step 1: 编写测试用例验证显式证书路径加载**

在 `pkg/csvattest/verify_test.go` 中添加测试：

```go
func TestLoadCertChainFromFiles_Success(t *testing.T) {
	hrkPath := filepath.Join("..", "..", "deploy", "certs", "hrk.cert")
	hskCekPath := filepath.Join("..", "..", "deploy", "certs", "hsk_cek.cert")
	if _, err := os.Stat(hrkPath); err != nil {
		t.Skip("deploy/certs/hrk.cert not present, skipping real file test")
	}

	chain, err := LoadCertChainFromFiles(hrkPath, hskCekPath)
	if err != nil {
		t.Fatalf("LoadCertChainFromFiles() error = %v", err)
	}
	if len(chain.HRK) != HrkCertSize {
		t.Errorf("len(chain.HRK) = %d, want %d", len(chain.HRK), HrkCertSize)
	}
	if len(chain.HSKCEK) != HskCekSize {
		t.Errorf("len(chain.HSKCEK) = %d, want %d", len(chain.HSKCEK), HskCekSize)
	}
	if chain.Source != "local file" {
		t.Errorf("chain.Source = %q, want %q", chain.Source, "local file")
	}
}

func TestLoadCertChainFromFiles_MissingFile(t *testing.T) {
	_, err := LoadCertChainFromFiles("/nonexistent/hrk.cert", "/nonexistent/hsk.cert")
	if err == nil {
		t.Fatal("LoadCertChainFromFiles() want error for nonexistent file, got nil")
	}
}
```

- [x] **Step 2: 运行测试验证失败**

```bash
go test -v ./pkg/csvattest -run "TestLoadCertChainFromFiles"
```
Expected: FAIL（函数未定义）。

- [x] **Step 3: 在 `pkg/csvattest/verify.go` 实现显式证书路径与选项模式**

1. 实现 `LoadCertChainFromFiles`:
```go
// LoadCertChainFromFiles loads HRK and HSK/CEK certificates from the specified file paths.
func LoadCertChainFromFiles(hrkPath, hskCekPath string) (*CertChainInput, error) {
	hrk, err := readFixedFile(hrkPath, HrkCertSize)
	if err != nil {
		return nil, fmt.Errorf("read hrk cert %s: %w", hrkPath, err)
	}
	hskCek, err := readFixedFile(hskCekPath, HskCekSize)
	if err != nil {
		return nil, fmt.Errorf("read hsk_cek cert %s: %w", hskCekPath, err)
	}
	return &CertChainInput{HRK: hrk, HSKCEK: hskCek, Source: "local file"}, nil
}
```

2. 调整 `LoadLocalCertChain(certDir string)`:
```go
func LoadLocalCertChain(certDir string) (*CertChainInput, error) {
	chain, err := LoadCertChainFromFiles(filepath.Join(certDir, "hrk.cert"), filepath.Join(certDir, "hsk_cek.cert"))
	if err != nil {
		return nil, err
	}
	chain.Source = "本地文件"
	return chain, nil
}
```

3. 定义 `VerifyOptions` 并实现 `VerifyReportWithOptions`:
```go
// VerifyOptions controls attestation verification options including explicit cert paths.
type VerifyOptions struct {
	VerifyChain    bool
	HRKCertPath    string
	HSKCekCertPath string
	CertDir        string
}

// VerifyReportWithOptions verifies an attestation report using the provided options.
func VerifyReportWithOptions(data []byte, opts VerifyOptions) (*VerificationResult, error) {
	res, err := ParseReport(data)
	if err != nil {
		return nil, fmt.Errorf("parse report: %w", err)
	}

	if err := VerifyReportPEKSignature(res); err != nil {
		return nil, fmt.Errorf("verify report PEK signature: %w", err)
	}

	if !opts.VerifyChain {
		return res, nil
	}

	var certs *CertChainInput
	if opts.HRKCertPath != "" && opts.HSKCekCertPath != "" {
		certs, err = LoadCertChainFromFiles(opts.HRKCertPath, opts.HSKCekCertPath)
		if err != nil {
			return nil, fmt.Errorf("load certs from files: %w", err)
		}
	} else {
		certs, err = loadCertChain(opts.CertDir, res.ChipIDASCII)
		if err != nil {
			return nil, fmt.Errorf("load certs: %w", err)
		}
	}

	details, err := VerifyCertChain(certs, res.PEKCert)
	if err != nil {
		return nil, fmt.Errorf("verify cert chain: %w", err)
	}
	res.CertDetails = details
	return res, nil
}
```

4. 将原 `VerifyReportData(data []byte, certDir string, verifyChain bool)` 委托给 `VerifyReportWithOptions`:
```go
func VerifyReportData(data []byte, certDir string, verifyChain bool) (*VerificationResult, error) {
	return VerifyReportWithOptions(data, VerifyOptions{
		VerifyChain: verifyChain,
		CertDir:     certDir,
	})
}
```

- [x] **Step 4: 运行 `pkg/csvattest` 全量单测验证**

```bash
go test -v ./pkg/csvattest/...
```
Expected: PASS 全部通过。

- [x] **Step 5: 提交更改**

```bash
git add pkg/csvattest/
git commit -m "feat(csvattest): support explicit certificate file paths for attestation verification"
```

---

### Task 4: 业务层门面封装 (`internal/attestation`)

**Files:**
- Create: `internal/attestation/verify.go`
- Create: `internal/attestation/verify_test.go`

- [x] **Step 1: 编写业务门面单元测试**

编写 `internal/attestation/verify_test.go`:

```go
package attestation

import (
	"path/filepath"
	"testing"
)

func TestVerifyReport_ShortBuffer(t *testing.T) {
	_, err := VerifyReport([]byte("short"), "hrk.cert", "hsk.cert")
	if err == nil {
		t.Fatal("VerifyReport() want error for short buffer, got nil")
	}
}

func TestVerifyReport_MissingCerts(t *testing.T) {
	buf := make([]byte, ReportSize)
	_, err := VerifyReport(buf, "/missing/hrk.cert", "/missing/hsk.cert")
	if err == nil {
		t.Fatal("VerifyReport() want error for missing certs or invalid report, got nil")
	}
}

func TestVerifyReport_ValidCertPaths(t *testing.T) {
	hrkPath := filepath.Join("..", "..", "deploy", "certs", "hrk.cert")
	hskPath := filepath.Join("..", "..", "deploy", "certs", "hsk_cek.cert")
	buf := make([]byte, ReportSize)
	// Invalid report bytes will fail report parsing/signature cleanly without panic
	_, err := VerifyReport(buf, hrkPath, hskPath)
	if err == nil {
		t.Fatal("VerifyReport() want parse error for zeroed report, got nil")
	}
}
```

- [x] **Step 2: 运行测试验证编译失败**

```bash
go test -v ./internal/attestation -run "TestVerifyReport"
```
Expected: FAIL（`VerifyReport` 未定义）。

- [x] **Step 3: 实现 `internal/attestation/verify.go`**

```go
package attestation

import (
	"strings"

	"taa/pkg/csvattest"
)

// VerifyReport verifies an attestation report and its certificate chain using configured certificate paths.
func VerifyReport(reportData []byte, hrkCertPath, hskCekCertPath string) (*csvattest.VerificationResult, error) {
	if len(reportData) < csvattest.ReportSize {
		return nil, csvattest.ErrShortBuffer
	}

	opts := csvattest.VerifyOptions{
		VerifyChain:    true,
		HRKCertPath:    strings.TrimSpace(hrkCertPath),
		HSKCekCertPath: strings.TrimSpace(hskCekCertPath),
	}
	return csvattest.VerifyReportWithOptions(reportData, opts)
}
```

- [x] **Step 4: 运行 `internal/attestation` 全量单测验证**

```bash
go test -v ./internal/attestation/...
```
Expected: PASS 全部通过。

- [x] **Step 5: 提交更改**

```bash
git add internal/attestation/
git commit -m "feat(attestation): add attestation report verification facade"
```

---

### Task 5: 在 TAA 启动与运行时集成证书自检及动态 `verifiedPass`

**Files:**
- Modify: `internal/app/taa/app.go`
- Modify: `internal/app/taa/app_test.go`
- Modify: `internal/controller/route.go`
- Modify: `internal/controller/handler_system.go`
- Modify: `internal/controller/handler_test.go`

- [x] **Step 1: 修改 `internal/controller` 接收证书路径并执行自检**

1. 在 `internal/controller/route.go` 中，为 `TAAState` 添加证书路径字段并更新构造函数：
```go
type TAAState struct {
    // ... 现有字段 ...
	AttestationFile string
	HRKCertPath     string
	HSKCekCertPath  string
    // ...
}

func NewTAAState(attestationFile, platformIP, dockerID, hrkCertPath, hskCekCertPath string, sm2Key *teecrypto.SM2PrivateKey, userData []byte, sec SecurityConfig) *TAAState
```
2. 在 `internal/controller/handler_system.go` 中的 `buildAttestationResult` 执行自检：
```go
	// 执行报告自检验证
	verifiedPass := false
	var verifyMsg string
	if _, verifyErr := attestation.VerifyReport(reportData, s.HRKCertPath, s.HSKCekCertPath); verifyErr != nil {
		log.Printf("get attestation self-verification failed: %v", verifyErr)
		verifyMsg = "自检验证失败: " + verifyErr.Error()
	} else {
		log.Printf("get attestation self-verification passed")
		verifiedPass = true
		verifyMsg = "success"
	}

	return reportData, formattedValues, verifiedPass, verifyMsg
```

- [x] **Step 2: 修改 `internal/app/taa/app.go` 启动自检与透传**

1. 修改 `prepareAttestationReport` 签名与逻辑：
```go
func prepareAttestationReport(ctx context.Context, userData []byte, hrkCertPath, hskCekCertPath string) (bool, error) {
	log.Printf("generating attestation report: output=%s", fixedAttestationFile)
	if err := attestation.Generate(ctx, attestation.Config{
		OutputPath: fixedAttestationFile,
		UserData:   userData,
	}); err != nil {
		log.Printf("WARNING: generating attestation report failed, continuing with empty report: %v", err)
		if writeErr := os.WriteFile(fixedAttestationFile, nil, 0o600); writeErr != nil {
			return false, fmt.Errorf("write empty attestation report: %w", writeErr)
		}
		return false, nil
	}

	reportBytes, err := os.ReadFile(fixedAttestationFile)
	if err != nil || len(reportBytes) == 0 {
		return false, nil
	}

	// 自检
	if _, verifyErr := attestation.VerifyReport(reportBytes, hrkCertPath, hskCekCertPath); verifyErr != nil {
		log.Printf("WARNING: attestation self-verification failed: %v", verifyErr)
		return false, nil
	}

	log.Printf("attestation report verified successfully: %s", fixedAttestationFile)
	return true, nil
}
```
2. 更新 `registerPlatform` 接收 `verifiedPass bool`：
```go
func registerPlatform(ctx context.Context, platformIP, dockerID, publicKeyPEM string, timestamp int64, verifiedPass bool) error
```
在 `controller.NoticeRegister` 或平台注册请求中正确传递 `verifiedPass`。
3. 在 `RunWithConfig` 中：
   - 提取 `cfg.AttestationHRKCertPath` 与 `cfg.AttestationHSKCekCertPath`。
   - 调用 `verifiedPass, err := prepareAttestationReport(ctx, userData, cfg.AttestationHRKCertPath, cfg.AttestationHSKCekCertPath)`。
   - 初始化 `controller.NewTAAState(fixedAttestationFile, cfg.PlatformIP, cfg.DockerID, cfg.AttestationHRKCertPath, cfg.AttestationHSKCekCertPath, ...)`。
   - `registerPlatform(ctx, ..., verifiedPass)`。

- [x] **Step 3: 修复并扩展 `internal/controller/handler_test.go` 与 `internal/app/taa/app_test.go`**

更新测试中 `NewTAAState` 的调用，传入测试证书路径（如 `filepath.Join(tmpDir, "hrk.cert")`），确保全部相关单测通过。

- [x] **Step 4: 运行 `app` 与 `controller` 测试**

```bash
go test -v ./internal/app/taa/... ./internal/controller/...
```
Expected: PASS 全部通过。

- [x] **Step 5: 提交更改**

```bash
git add internal/app/taa/ internal/controller/
git commit -m "feat(taa): integrate certificate chain self-verification into startup and runtime handlers"
```

---

### Task 6: 改造部署脚本 `deploy.sh`

**Files:**
- Modify: `deploy.sh`

- [x] **Step 1: 更新证书源目录与目标目录**

修改 `deploy.sh`:
1. 替换 `ATT_DIR` 为 `CERT_DIR`:
```bash
CERT_DIR="${CERT_DIR:-$PROJECT_DIR/deploy/certs}"
ATT_HRK_SOURCE="${ATT_HRK_SOURCE:-$CERT_DIR/hrk.cert}"
ATT_HSK_SOURCE="${ATT_HSK_SOURCE:-$CERT_DIR/hsk_cek.cert}"
```
2. 更新容器内工作目录及初始化：
   - 目标证书目录：`$TAA_CONTAINER_WORKDIR/certs/`
   - 将各个模式中拷贝证书至容器根目录的 `docker cp ... /root/taa/hrk.cert` 修改为拷贝至 `$TAA_CONTAINER_WORKDIR/certs/hrk.cert` 和 `hsk_cek.cert`。
   - 确保容器目录初始化命令包含 `mkdir -p '$TAA_CONTAINER_WORKDIR/certs'`。

- [x] **Step 2: 更新 `write_taa_config` 动态注入 `attestation` 配置块**

在 `deploy.sh` 的 `write_taa_config` 函数中的 Python 脚本段添加：
```python
attestation = cfg.setdefault("attestation", {})
attestation["hrkCertPath"] = f"{workdir}/certs/hrk.cert"
attestation["hskCekCertPath"] = f"{workdir}/certs/hsk_cek.cert"
```
（其中 `workdir` 对应传入的容器工作目录，若无则使用目标路径 `/root/taa`）。

- [x] **Step 3: 验证部署脚本语法**

```bash
bash -n deploy.sh
```
Expected: 退出码 0，无任何语法错误。

- [x] **Step 4: 提交更改**

```bash
git add deploy.sh
git commit -m "fix(deploy): update certificate source paths and inject dynamic attestation config"
```

---

### Task 7: 全系统回归测试与构建验收

**Files:**
- 全局

- [x] **Step 1: 执行全量单元测试**

```bash
go test ./...
```
Expected: 所有包单测全部通过。

- [x] **Step 2: 验证主程序与平台 Mock 构建**

```bash
go build -o bin/taa ./cmd/taa
go build -o bin/platform-mock ./cmd/platform-mock
```
Expected: 成功生成 `bin/taa` 与 `bin/platform-mock`，退出码 0。

- [x] **Step 3: 验证整个仓库中无废弃 `attestation/` 路径残留**

```bash
git grep "attestation/hrk.cert" || true
git grep "attestation/hsk_cek.cert" || true
git grep "attestation/csv_c" || true
```
Expected: 没有任何活跃代码或脚本指向已删除的历史路径。

- [x] **Step 4: 提交最终整体验收与文档同步**

```bash
git status
```
确认工作树干净无多余脏数据。
