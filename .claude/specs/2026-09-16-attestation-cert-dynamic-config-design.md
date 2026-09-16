# 远程证明证书动态配置化与加载自检重构设计文档

## 1. 背景与目标

### 1.1 现状分析
在此前重构中，TAA 已将海光 CSV 远程证明生成逻辑从外部 C 语言进程调用（`get-attestation`）重构为纯 Go 底层驱动（`pkg/csvattest`），摆脱了对 Cgo 及外部 C 编译环境的依赖。然而目前代码库中仍存在以下几处硬编码与历史包袱：
1. **证书位置与代码写死**：`pkg/csvattest/verify.go` 中的 `LoadLocalCertChain` 强绑定 `certDir` 并硬编码查找 `"hrk.cert"` 与 `"hsk_cek.cert"` 文件名，缺乏显式自定义路径支持；
2. **配置文件缺失证书字段**：`configs/taa-*.json` 与 `internal/config/config.go` 中未提供证书路径配置项，无法根据不同部署环境灵活变更证书位置；
3. **部署脚本残留旧路径与硬编码**：`deploy.sh` 依然定义 `ATT_DIR="${ATT_DIR:-$PROJECT_DIR/attestation}"`，并将证书固定复制到容器根目录 `/root/taa/`；
4. **历史冗余目录残留**：根目录下的 `attestation/` 目录中保留了大量已被纯 Go 替代的遗留 C 源码（`csv_c/`、`csv_sdk/`）及过期说明文档，仅有其下的 `hrk.cert` 和 `hsk_cek.cert` 两个证书文件仍被部署脚本引用；
5. **缺少运行时完整自检闭环**：TAA 在启动生成报告和处理 `/v1/taa/getAttestation` 请求时，未能利用本地证书对生成的报告进行证书链自检校验，`verifiedPass` 状态在生成成功后被默认标记为 `true`，存在未检即过的安全隐患。

### 1.2 重构目标
1. **证书规范迁移与归档**：在 `deploy/certs/` 目录下集中纳管 `hrk.cert` 与 `hsk_cek.cert`，彻底删除无依赖的历史 `attestation/` 目录；
2. **配置驱动解耦**：在 `configs/taa-*.json` 与 `StartupConfig` 中引入模块化的 `attestation` 证书路径配置项，支持显式指定 `hrkCertPath` 和 `hskCekCertPath`；
3. **驱动与业务自检增强**：`pkg/csvattest` 开放显式证书路径加载接口，`internal/attestation` 增加证书链自检验证能力，TAA 启动与运行中执行真实自检并动态赋予 `verifiedPass`；
4. **部署自动化闭环**：`deploy.sh` 全流程调整证书源路径至 `deploy/certs/`，目标路径统一为 `$TAA_CONTAINER_WORKDIR/certs/`，并动态注入生成的配置文件；
5. **保证环境兼容与健壮性**：在非 TEE（如本地开发 Docker / 本机）无真实设备或无有效证书的环境下具备优雅降级能力，全量单元测试 100% 稳定通过。

---

## 2. 目录迁移与清理方案

### 2.1 证书文件迁移
- 创建目录：`deploy/certs/`
- 迁移文件：
  - `attestation/hrk.cert` -> `deploy/certs/hrk.cert`
  - `attestation/hsk_cek.cert` -> `deploy/certs/hsk_cek.cert`
- 权限与格式：保持原有二进制 DER 格式不变，权限设置为 `0644`。

### 2.2 彻底清理 `attestation/` 目录
在证书完整迁移后，彻底删除根目录 `attestation/` 及其所有子目录与文件：
- `attestation/csv_c/`（历史 C 源码、驱动及 Makefile）
- `attestation/csv_sdk/`（历史 C 语言 SDK）
- `attestation/CLAUDE.md` / `attestation/readme.txt`（过时文档）
- `attestation/` 根目录本身

---

## 3. 配置模型扩展 (`internal/config` & `configs/`)

### 3.1 配置文件结构扩展
在 `configs/taa-production.json`、`configs/taa-docker.json` 与 `configs/taa-local.json` 中统一新增 `attestation` 对象：

#### 生产与 Docker 容器环境 (`taa-production.json` / `taa-docker.json`)
```json
{
  "addr": ":6001",
  "securityScan": true,
  "modelDir": "/root/taa/models",
  "dataDir": "/root/taa/data",
  "resultDir": "/root/taa/results",
  "modelInputDir": "/opt/taa/input",
  "modelOutputDir": "/opt/taa/output/result",
  "modelLogDir": "/opt/taa/output/log",
  "modelProgressDir": "/opt/taa/output/progress",
  "keysDir": "/opt/taa/keys",
  "attestation": {
    "hrkCertPath": "/root/taa/certs/hrk.cert",
    "hskCekCertPath": "/root/taa/certs/hsk_cek.cert"
  },
  "llm": {
    "enabled": true,
    "endpoint": "http://127.0.0.1:11434",
    "model": "qwen2.5-coder:3b",
    "policy": "assist",
    "failClosed": true,
    "dir": "/root/taa/ollama-qwen"
  }
}
```

#### 本地调试环境 (`taa-local.json`)
```json
{
  "attestation": {
    "hrkCertPath": "deploy/certs/hrk.cert",
    "hskCekCertPath": "deploy/certs/hsk_cek.cert"
  }
}
```

### 3.2 Go 结构体定义 (`internal/config/config.go`)

```go
type StartupConfig struct {
    // ... 现有字段保持不变 ...
    AttestationHRKCertPath    string
    AttestationHSKCekCertPath string
}

type startupAttestationConfigFile struct {
    HRKCertPath    string `json:"hrkCertPath"`
    HSKCekCertPath string `json:"hskCekCertPath"`
}

type startupConfigFile struct {
    // ... 现有字段保持不变 ...
    Attestation startupAttestationConfigFile `json:"attestation"`
}
```

### 3.3 默认值与解析规则
1. `defaultStartupConfig()` 提供智能自适应默认值：
   - 默认优先使用 `/root/taa/certs/hrk.cert` 与 `/root/taa/certs/hsk_cek.cert`。
   - 若上述文件不存在但本地工作区存在 `deploy/certs/hrk.cert`，自动适配为本地路径，保障本地开发免配置直接运行。
2. `applyStartupConfigFile` 逻辑：
   - 当 `fileCfg.Attestation.HRKCertPath` 非空且去除首尾空格后有效时，覆盖 `cfg.AttestationHRKCertPath`。
   - 当 `fileCfg.Attestation.HSKCekCertPath` 非空且去除首尾空格后有效时，覆盖 `cfg.AttestationHSKCekCertPath`。

---

## 4. 底层驱动层解耦与增强 (`pkg/csvattest`)

### 4.1 开放显式文件加载接口 (`pkg/csvattest/verify.go`)
保留现有 `LoadLocalCertChain(certDir string)` 向下兼容，底层抽象并导出新函数：

```go
// LoadCertChainFromFiles 根据指定的证书绝对或相对路径加载 HRK 根证书与 HSK/CEK 证书
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

原有 `LoadLocalCertChain(certDir string)` 调整为：
```go
func LoadLocalCertChain(certDir string) (*CertChainInput, error) {
    return LoadCertChainFromFiles(filepath.Join(certDir, "hrk.cert"), filepath.Join(certDir, "hsk_cek.cert"))
}
```

### 4.2 扩展带证书路径的报告验证接口
```go
// VerifyOptions 包含了远程证明报告校验的各项参数
type VerifyOptions struct {
    VerifyChain    bool
    HRKCertPath    string
    HSKCekCertPath string
    CertDir        string // 兼容历史目录模式
}

// VerifyReportWithOptions 使用指定选项校验证明报告与证书链
func VerifyReportWithOptions(data []byte, opts VerifyOptions) (*VerificationResult, error)
```
- 当 `opts.HRKCertPath` 与 `opts.HSKCekCertPath` 均有效时，直接调用 `LoadCertChainFromFiles` 进行本地证书链加载与校验；
- 当仅提供 `opts.CertDir` 时，回退到原有的 `loadCertChain(certDir, ...)` 逻辑；
- 保持原有的 `VerifyReport(reportFile string, verifyChain bool)` 和 `VerifyReportData(data []byte, certDir string, verifyChain bool)` 签名与行为不变。

---

## 5. 业务自检链路设计 (`internal/attestation` & `internal/controller`)

### 5.1 业务门面层封装 (`internal/attestation/verify.go`)
在 `internal/attestation` 包中新增报告校验封装：

```go
// VerifyReport 使用配置的证书路径对海光 CSV 证明报告执行签名与证书链自检
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

### 5.2 启动自检与注册流程 (`internal/app/taa/app.go`)

```
+-----------------------------------------------------------------------------+
|                          TAA 启动流程 (RunWithConfig)                         |
+-----------------------------------------------------------------------------+
                                      │
                                      ▼
+-----------------------------------------------------------------------------+
|  1. 生成临时 SM2 密钥对并将公钥注入 USERDATA                                   |
+-----------------------------------------------------------------------------+
                                      │
                                      ▼
+-----------------------------------------------------------------------------+
|  2. prepareAttestationReport(ctx, userData, hrkCertPath, hskCekCertPath)    |
|     - 调用 attestation.Generate 生成 attestation.report                      |
|     - 若生成成功且非空：                                                      |
|       * 调用 attestation.VerifyReport 执行本地证书链自检                     |
|       * 校验成功 -> 记录自检成功日志，verifiedPass = true                     |
|       * 校验失败 -> 记录警告日志，verifiedPass = false                       |
|     - 若生成失败（非 TEE 模拟环境）：                                          |
|       * 写入空报告，记录降级警告日志，verifiedPass = false                     |
+-----------------------------------------------------------------------------+
                                      │
                                      ▼
+-----------------------------------------------------------------------------+
|  3. registerPlatform(ctx, platformIP, dockerID, pubKey, timestamp, verified) |
|     - 将真实的 verifiedPass 状态准确上报管控平台，杜绝虚假上报                  |
+-----------------------------------------------------------------------------+
```

### 5.3 动态证明获取接口改造 (`internal/controller/handler_system.go`)
- `TAAState` 结构体新增 `HRKCertPath` 与 `HSKCekCertPath` 字段；
- `buildAttestationResult(ctx context.Context, attestationFile string, userData []byte)`：
  1. 生成证明报告落盘；
  2. 读取报告内容并提取 `attestationValues`；
  3. 执行自检：调用 `attestation.VerifyReport(reportData, s.HRKCertPath, s.HSKCekCertPath)`；
  4. 依据自检结果动态赋予 `verifiedPass`（校验成功为 `true`；失败为 `false`，并记录详细原因）；
  5. 响应 `/v1/taa/getAttestation` 接口返回动态计算的 `verifiedPass`。

---

## 6. 部署脚本与自动化适配 (`deploy.sh`)

### 6.1 路径变量重定向
```bash
CERT_DIR="${CERT_DIR:-$PROJECT_DIR/deploy/certs}"
ATT_HRK_SOURCE="${ATT_HRK_SOURCE:-$CERT_DIR/hrk.cert}"
ATT_HSK_SOURCE="${ATT_HSK_SOURCE:-$CERT_DIR/hsk_cek.cert}"
```
- `require_file` 检查更新为 `$ATT_HRK_SOURCE` 与 `$ATT_HSK_SOURCE`。

### 6.2 容器与远端目标路径规范
- 容器内目标路径：`$TAA_CONTAINER_WORKDIR/certs/`（即 `/root/taa/certs/`）。
- 部署动作：
  1. 初始化目录：`mkdir -p '$TAA_CONTAINER_WORKDIR/certs'`
  2. 拷贝证书：
     - 本地 Docker 模式：
       ```bash
       docker cp "$ATT_HRK_SOURCE" "$container:$TAA_CONTAINER_WORKDIR/certs/hrk.cert"
       docker cp "$ATT_HSK_SOURCE" "$container:$TAA_CONTAINER_WORKDIR/certs/hsk_cek.cert"
       ```
     - Remote 模式：
       SCP 传输至 `$REMOTE_DIR/certs/` 后，再注入目标容器 `$TAA_CONTAINER_WORKDIR/certs/`。
     - 镜像导出模式 (`--export-image`)：
       向构建临时容器拷贝 `$ATT_HRK_SOURCE` 与 `$ATT_HSK_SOURCE` 至 `/root/taa/certs/` 目录。

### 6.3 配置文件动态注入 (`write_taa_config`)
更新 `write_taa_config` Python 渲染部分：
- 在生成的配置文件中确保包含 `attestation` 块：
  ```python
  attestation = cfg.setdefault("attestation", {})
  attestation["hrkCertPath"] = f"{workdir}/certs/hrk.cert"
  attestation["hskCekCertPath"] = f"{workdir}/certs/hsk_cek.cert"
  ```
- 保证生成的配置文件中的路径与部署的物理路径严格匹配。

---

## 7. 错误处理与降级策略

| 场景 | 现象与错误行为 | 系统应对策略 |
| :--- | :--- | :--- |
| **真实海光 CSV 硬件环境** | 报告生成成功，证书存在且匹配 | 自检验证通过，记录 ChipID 及签名信息，`verifiedPass = true` 正常上报 |
| **证书路径配置错误 / 证书文件不存在** | `LoadCertChainFromFiles` 返回文件读取失败 | 记录 ERROR/WARN 日志说明具体哪个证书缺失，优雅降级：`verifiedPass = false`，服务正常启动以供排障 |
| **证书内容损坏或大小不合规** | 证书字节数小于标准（HRK 832B / HSK_CEK 2916B） | 拦截并返回具体长度不足错误，`verifiedPass = false`，不产生 panic |
| **非 TEE 开发环境 (Docker/本地)** | 无 `/dev/csv-guest` 设备，报告生成失败 | 遵循既有降级规范写入空报告，记录警告，跳过证书链校验，`verifiedPass = false` 正常启动 |

---

## 8. 测试策略与验证计划

### 8.1 单元测试清单
1. **`internal/config/config_test.go`**：
   - `TestLoadStartupConfig_AttestationCerts`：测试从 JSON 正常解析 `attestation.hrkCertPath` 与 `attestation.hskCekCertPath`。
   - `TestLoadStartupConfig_AttestationDefaults`：测试省略 `attestation` 节点时的默认值自适应行为。
   - `TestLoadStartupConfig_AttestationTrimWhitespace`：测试空白字符串过滤与防御。
2. **`pkg/csvattest/verify_test.go`**：
   - `TestLoadCertChainFromFiles_Success`：使用 `deploy/certs/` 真实证书测试加载解析。
   - `TestLoadCertChainFromFiles_MissingFile`：测试不存在路径时的错误包装与提示。
   - `TestVerifyReportWithOptions_CustomPaths`：测试显式路径驱动下的全量校验。
3. **`internal/attestation/verify_test.go`**：
   - 验证 `attestation.VerifyReport` 业务门面在正确/错误/短缓冲输入下的响应。
4. **`internal/controller/handler_test.go`**：
   - 测试 `/v1/taa/getAttestation` 接口在配置了证书路径时的执行链路与返回值验证。

### 8.2 集成与编译验收
1. `go build -o bin/taa ./cmd/taa` 确保编译无误；
2. `go build -o bin/platform-mock ./cmd/platform-mock` 确保编译无误；
3. `go test ./...` 确保全部单测 100% 绿色通过；
4. `bash -n deploy.sh` 确保脚本语法正确；
5. 验证原 `attestation/` 目录彻底移除，全局无断裂引用。
