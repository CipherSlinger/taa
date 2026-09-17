# TEE-TLS 1.3 国密安全传输与可信 LLM 解耦设计规范

## 1. 概��与设计目标

### 1.1 背景与动因
随着 TAA（Trusted Application Agent）与 LLM 推理引擎逐步向跨 Pod、跨机密虚机（Confidential VM）的多容器分布式机密计算架构演进：
1. **移除 UDS**：基于 Linux 内核单机文件系统抽象的 Unix Domain Socket（UDS）无法跨内核通信，需要彻底移除。
2. **安全通信与零信任证明**：在跨 Pod 传输场景下，必须对通信链路进行高强度加密，并在建立连接时完成海光 CSV（China Secure Virtualization）硬件远程证明（Remote Attestation）。
3. **架构解耦与独立切仓**：将通用机密传输层（`teetls`）与面向 LLM 的推理审计协议交互层（`teellm`）从 TAA 的 `internal/` 目录中完全抽离，置于根目录独立包中，保持单向依赖与零反向耦合，便于后续独立为单独的 Git 仓库维护。

### 1.2 核心设计原则
* **国密全栈 (All-in ShangMi)**：TLS 1.3 密码套件严格对齐 RFC 8998 规范，签名算法使用 **SM2**，杂凑哈希算法使用 **SM3**，对称加密使用 **SM4-GCM**。
* **硬件级远程证明与防替换绑定 (RA-TLS 1.3)**：在 X.509 证书中内嵌海光 CSV 证明报告（Report）与证书链（HRK/HSK/CEK），将证书公钥的 SM3 指纹硬绑定至 CSV 报告的 `USER_DATA` 槽位，杜绝中间人证书偷换。
* **分级策略仲裁 (Strict vs Permissive)**：支持对 CSV 固件测量值（Measurement）与 Debug 状态进行分级校验，兼顾生产严格零信任与开发联调。
* **模块零反向耦合 (Zero Reverse Dependency)**：依赖单向流动：`TAA` ──▶ `teellm` ──▶ `teetls` ──▶ `pkg/csvattest`。

---

## 2. 总体架构与模块拓扑

### 2.1 目录组织结构

```
/home/hjy/taa/
├── teetls/                       # 独立模块 1：通用 TEE-TLS 1.3 国密传输与远程证明库
│   ├── config.go                 # 配置结构 (AttestationMode, CertPaths, Measurements)
│   ├── cert.go                   # 临时 SM2 证书生成、公钥 SM3 计算与 X.509 扩展编码
│   ├── evidence.go               # 海光 CSV 报告与证书链的 ASN.1/TLV 序列化定义
│   ├── verifier.go               # VerifyPeerCertificate 核心流水线 (证书链/公钥/度量)
│   ├── provider.go               # 硬件驱动提供者抽象 (HygonHardwareProvider / MockProvider)
│   ├── transport.go              # Dial / Listen / http.Transport 便捷封装
│   └── teetls_test.go            # 握手、证明校验与异常注入测试
│
├── teellm/                       # 独立模块 2：可信 LLM 通信协议、客户端与服务端桩
│   ├── types.go                  # teellm-protocol/v1 协议信封 (Request/Response Envelope)
│   ├── client.go                 # Client 接口及基于 TEE-TLS 1.3 的 REST 客户端实现
│   ├── server.go                 # 可信 LLM 服务端桩 / HTTP Handler 辅助函数
│   ├── circuit_breaker.go        # 三态熔断器与单探针半开恢复
│   ├── retry.go                  # 带 20% Jitter 的指数退避重试引擎
│   ├── validator.go              # 端点校验与 SSRF 阻断 (禁用 UDS, 强制 HTTPS)
│   └── teellm_test.go            # 协议编解码、端到端通信、熔断自愈测试
│
├── internal/                     # TAA 核心业务逻辑
│   ├── codeaudit/                # 代码审计业务 (全面接入 teellm.Client)
│   ├── config/                   # 启动配置 (移除 UDS 字段，新增 TEE-TLS 国密配置)
│   └── app/taa/                  # TAA 主进程启动与探活 (调用 teellm.Client)
│
└── pkg/                          # 既有底层基础包
    ├── crypto/                   # 国密 SM2/SM3/SM4 底层算法库
    └── csvattest/                # 海光 CSV IOCTL 底层调用与签名验证驱动
```

### 2.2 依赖���束规范
1. `teetls` 严禁 import `teellm`、`internal/*`。
2. `teellm` 严禁 import `internal/*`。
3. `TAA` 作为消费者，import `teellm`，不直接耦合底层 `teetls` 握手实现。
4. 彻底删除 `internal/inference/` 目录及其所有文件。

---

## 3. `teetls` 详细设计 (RFC 8998 国密 TLS 1.3 远程证明)

### 3.1 密码算法参数体系 (RFC 8998)
* **协议版本**：TLS 1.3（`0x0304`）。
* **加密套件 (CipherSuite)**：`TLS_SM4_GCM_SM3` (`0x00C6`)。
* **椭圆曲线 (NamedGroup)**：`curveSM2` (`0x0029`，SM2 椭圆曲线用于 ECDHE 临时密钥交换)。
* **签名体系 (SignatureScheme)**：`sm2sig_sm3` (`0x0708`，SM2 配合 SM3 摘要进行签名)。
* **哈希算法 (Hash)**：`SM3`（256 位，用于密钥派生 HKDF-SM3 与握手日志摘要）。
* **记录层 (Record Layer)**：`SM4-GCM`（128-bit Key, 12-byte Nonce, 16-byte Tag）。

### 3.2 自定义 X.509 扩展规范 (CSV Evidence)
* **自定义扩展 OID**：`1.3.6.1.4.1.58270.1.1`（Hygon CSV Attestation Evidence OID）。
* **ASN.1 结构定义**：
  ```go
  type CSVEvidenceExtension struct {
      Version     int    `asn1:"default:1"`
      Report      []byte `asn1:"tag:0"`          // 2048 字节海光芯片签名的 CSV 报告
      HRKCert     []byte `asn1:"tag:1,optional"` // 海光根证书 DER
      HSKCekCert  []byte `asn1:"tag:2,optional"` // 芯片背书/派生证书链 DER
  }
  ```
* 扩展标记为 `Critical: false`，保证标准 X.509 工具可正常解析。

### 3.3 公钥指纹与海光 CSV 硬件绑定
1. 握手方生成临时 SM2 密钥对。
2. 计算叶子证书 SM2 公钥的 SM3 摘要：
   $$\text{SM2PubKeyDigest} = \text{SM3}(\text{leafSM2PubKeyDER}) \quad (32 \text{ 字节})$$
3. 将此 32 字节摘要写入海光 CSV 报告请求的 `USER_DATA[0:32]`，后 32 字节填入 Nonce 或零。
4. 调用 `/dev/csv-guest` 生成硬件签名的 CSV Report。

### 3.4 握手验证流水线 (`VerifyPeerCertificate`)
在握手回调中执行四道顺序校验：
1. **扩展解析**：定位 OID `1.3.6.1.4.1.58270.1.1` 扩展并解码 `CSVEvidenceExtension`。若缺失则直接报错中断握手。
2. **硬件签名链校验**：调用 `pkg/csvattest.VerifyReportWithOptions`，验证 CEK -> HSK -> HRK 证书链合法性及芯片对 Report 的 SM2 签名。
3. **防中间人替换校验 (Anti-MITM Binding)**：计算对端叶子证书公钥的 SM3，比对 `Report.UserData[0:32] == SM3(PeerSM2PublicKey)`。不匹配立即阻断。
4. **度量与策略校验**：
   * **Debug 状态检测**：若策略开启且模式为 `Strict`，检测 `Report.Policy & CSV_POLICY_DEBUG != 0`，若为调试态则拒绝。
   * **度量白名单检测**：若配置了 `ExpectedMeasurements`，比对报告的 `Measure` 字段：
     * `Strict` 模式：度量不匹配立即中断连接。
     * `Permissive` 模式：度量不匹配时输出告警日志，允许连接建立。

### 3.5 接口与抽象定义
```go
type AttestationMode string
const (
    ModeStrict     AttestationMode = "strict"
    ModePermissive AttestationMode = "permissive"
)

type Config struct {
    Mode                 AttestationMode
    HRKCertPath          string
    HSKCekCertPath       string
    ExpectedMeasurements []string
    RequireClientAttest  bool
    EvidenceProvider     EvidenceProvider
}

type EvidenceProvider interface {
    GetEvidence(pubKeyDigest [32]byte) (*CSVEvidenceExtension, error)
}
```

---

## 4. `teellm` 详细设计 (可信 LLM 协议与服务层)

### 4.1 协议信封规范 (`teellm-protocol/v1`)
升级协议版本为 `teellm-protocol/v1`：
* **`RequestEnvelope`**：
  * `ProtocolVersion`: `"teellm-protocol/v1"`
  * `RequestID`: UUID 字符串
  * `Action`: `"VERIFY_FINDING"`, `"ANALYZE_FILE"`, `"HEALTH_CHECK"`
  * `Auth`: `{ "authType": "bearer", "token": "..." }`
  * `FindingPayload`: `{ "ruleId": "...", "category": "...", "severity": "...", "description": "...", "target": { ... } }`
  * `Policy`: `{ "mode": "gate" | "assist", "temperature": 0.2, "maxCompletionTokens": 1024 }`
* **`ResponseEnvelope`**：
  * `ProtocolVersion`: `"teellm-protocol/v1"`
  * `RequestID`: 对应请求 ID
  * `Status`: `"SUCCESS"`, `"SERVICE_UNAVAILABLE"`, `"INVALID_REQUEST"` 等
  * `Decision`:
    * `Verdict`: `"MALICIOUS"`, `"SUSPICIOUS"`, `"BENIGN"`, `"UNCERTAIN"`
    * `Confidence`: 置信度
    * `Explanation`: 审计理由
    * `SuggestedRemediation`: 修复建议
  * `Metrics`: 耗时与 Token 统计
  * `EngineInfo`: 后端模型元数据

### 4.2 客户端弹性防御体系
1. **SSRF 与端点过滤**：
   * 端点必须为 `https://`（基于 TEE-TLS 1.3）。
   * 严格禁止 `unix://` 与明文 `http://`。
   * 无条件阻断云元数据地址 `169.254.169.254`、通配绑定 `0.0.0.0` 及 IPv6 缺省地址。
   * 支持主机名白名单校验（`AllowedHosts`）。
2. **三态熔断保护 (`CircuitBreaker`)**：
   * 连续失败达阈值（默认 3 次）转为 `OPEN` 快速熔断。
   * 冷却时间（默认 30 秒）后进入 `HALF-OPEN`，通过单探针锁仅放行 1 笔探测请求，成功后平滑恢复 `CLOSED`。
3. **带抖动指数退避重试 (`ExecuteWithRetryContext`)**：
   * 对网络抖动、5xx、429 等可重试错误执行带 20% Jitter 的重试。
4. **1MB 报文硬限制**：
   * 采用 `io.LimitReader` 防止后端异常报文造成客户端内存溢出。

### 4.3 服务端桩 (`teellm.Server`)
提供开箱即用的 HTTP 路由 Handler：
* `POST /v1/verify`：接收 `RequestEnvelope`，触发后端处理并返回 `ResponseEnvelope`。
* `GET /healthz`：返回服务运行健康状态。

---

## 5. TAA 重构与迁移设计

### 5.1 彻底移除 UDS
1. 删除 `internal/inference/adapter_uds.go`。
2. 删除 `internal/inference/` 目录中所有文件，统一迁移至 `teellm`。
3. 清除 `internal/config/config.go` 中的 `LLMUDSPath` 结构体字段及相关解析逻辑。
4. 启动配置新增 TEE-TLS 字段：
   * `LLMHRKCertPath`: 海光根证书路径
   * `LLMHSKCekCertPath`: 海光 HSK/CEK 证书路径
   * `LLMAttestationMode`: `"strict"` 或 `"permissive"`
   * `LLMExpectedMeasurements`: 期望度量值列表
   * `LLMRequireMutualAttest`: 是否要求双向远程证明

### 5.2 业务仲裁与调用迁移
1. **`internal/codeaudit/llm.go`**：
   * 类型别名切换：`type LLMClient = teellm.Client`。
   * 配置工厂调用：`teellm.NewClient(cfg)`。
2. **`internal/codeaudit/verifier.go`**：
   * 使用 `teellm.RequestEnvelope`、`teellm.FindingPayload`。
   * 保留既有的 Gate 阻断（FailClosed 下存在 HIGH/MEDIUM 且非 BENIGN 时标记 `Passed = false`）与 Assist 降级（标记 `LLMDegraded = true`）逻辑。
   * 严格保留 `BENIGN` 判定在文件外发摘要中的过滤排除机制。
3. **`internal/app/taa/app.go`**：
   * 启动探测改为调用 `teellm.Client.HealthCheck(ctx)`。

---

## 6. 测试与验证方案

### 6.1 `teetls` 测试集 (`teetls/teetls_test.go`)
* **握手与数据传输测试**：基于 RFC 8998 TLS 1.3 SM2/SM3/SM4-GCM 实现 Client-Server 闭环握手与全双工数据传输。
* **扩展编解码测试**：验证 X.509 自定义 OID 扩展的 ASN.1 DER 编码与解码准确性。
* **防中间人公钥篡改测试**：模拟中间人替换 SM2 证书公钥，验证客户端是否坚决阻断连接。
* **策略模式测试**：
  * `Strict` 模式：验证度量值不匹配、Debug 标志为 true 时准确阻断。
  * `Permissive` 模式：验证度量值不匹配时记录告警并放行。
* **双向证明测试**：验证 mRA-TLS 模式下双方均完成对彼此 CSV 报告���核验。

### 6.2 `teellm` 测试集 (`teellm/teellm_test.go`)
* **端到端集成测试**：启动基于 `teetls` 的本地测试服务，验证 Client 发起 `VerifyFinding` 得到正确的 `DecisionResult`。
* **熔断与自愈测试**：触发三态熔断，测试 `CLOSED` ➔ `OPEN` ➔ `HALF-OPEN` ➔ `CLOSED` 状态转移与单探针互斥。
* **异常拦截测试**：验证非法 scheme、非白名单主机、2MB 超大响应拦截。

### 6.3 TAA 整体回归测试
* 执行 `go test ./...`，确保 `teetls`、`teellm`、`internal/codeaudit`、`internal/config`、`internal/app/taa` 全量通过，无数据竞态。
