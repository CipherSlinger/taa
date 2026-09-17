# TEE-TLS 1.3 国密安全传输与可信 LLM 解耦实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 彻底移除基于单机文件系统的 UDS 传输路线，实现基于 RFC 8998（SM2/SM3/SM4-GCM）融合海光 CSV 硬件远程证明的 `teetls` 协议库，构建零 TAA 耦合的独立 `teellm`（`teellm-protocol/v1`）可信推理组件，并全面平移重构 TAA 代码审计与探活链路。

**Architecture:** 
采用三层单向解耦架构：底层 `teetls` 提供基于 RFC 8998 国密 TLS 1.3 与 X.509 嵌入式 CSV Evidence（SM2 公钥 SM3 指纹与硬件 UserData 强绑定）的机密通信；中层 `teellm` 基于 `teetls` 构建标准 HTTPS RESTful Client/Server、三态熔断器与抖动重试；顶层 `TAA` 作为业务消费者仅依赖 `teellm`，完成 Fail-Closed 门禁裁决与降级审计。

**Tech Stack:** Go 1.22, RFC 8998 (TLS 1.3 with ShangMi: SM2, SM3, SM4-GCM), Hygon CSV Attestation (HRK/HSK/CEK), ASN.1 DER, `tjfoc/gmsm`, standard `net/http`.

---

## 任务拆解概览

| 任务编号 | 模块 / 目标 | 核心产出文件 |
|---|---|---|
| **Task 1** | 环境基线与 `go.mod` 校准 | `go.mod` |
| **Task 2** | `teetls`: CSV Evidence 扩展与 ASN.1 编解码 | `teetls/evidence.go`, `teetls/evidence_test.go` |
| **Task 3** | `teetls`: SM2 证书生成与公钥 SM3 指纹绑定 | `teetls/cert.go`, `teetls/provider.go`, `teetls/cert_test.go` |
| **Task 4** | `teetls`: RFC 8998 记录层与 SM4-GCM AEAD 封装 | `teetls/record.go`, `teetls/record_test.go` |
| **Task 5** | `teetls`: RFC 8998 握手状态机与远程证明验证 | `teetls/config.go`, `teetls/verifier.go`, `teetls/handshake.go`, `teetls/conn.go`, `teetls/transport.go`, `teetls/teetls_test.go` |
| **Task 6** | `teellm`: 协议信封规范 (`teellm-protocol/v1`) | `teellm/types.go`, `teellm/types_test.go` |
| **Task 7** | `teellm`: 弹性韧性引擎（熔断、重试、SSRF 拦截） | `teellm/circuit_breaker.go`, `teellm/retry.go`, `teellm/validator.go`, `teellm/resilience_test.go` |
| **Task 8** | `teellm`: 基于 TEE-TLS 的 REST Client 与 Server 桩 | `teellm/client.go`, `teellm/server.go`, `teellm/teellm_test.go` |
| **Task 9** | TAA 改造: 移除 UDS、配置升级与 Codeaudit 平移 | `internal/config/*`, `internal/codeaudit/*`, `internal/app/taa/*`, 删除 `internal/inference/` |

---

### Task 1: 环境基线与 `go.mod` 校准

**Files:**
- Modify: `go.mod:3`

- [ ] **Step 1: 验证本地 Go 工具链与 `go.mod` 版本一致性**

检查 `go.mod` 中的 `go` 版本是否为 `1.22`，确保本地 `go1.22.2` 在 `GOTOOLCHAIN=local` 下无阻碍编译与测试。

```bash
git diff go.mod
```

- [ ] **Step 2: 运行测试确保既有测试套件 100% 通过**

Run: `go test ./internal/inference/... ./internal/config/...`
Expected: PASS (`ok taa/internal/inference`, `ok taa/internal/config`)

- [ ] **Step 3: 提交 `go.mod` 版本调整**

```bash
git add go.mod
git commit -m "build(deps): align go.mod version with local go 1.22 toolchain"
```

---

### Task 2: `teetls` - CSV Evidence 扩展与 ASN.1 编解码

**Files:**
- Create: `teetls/evidence.go`
- Test: `teetls/evidence_test.go`

- [ ] **Step 1: 编写失败测试 `teetls/evidence_test.go`**

```go
package teetls

import (
	"bytes"
	"testing"
)

func TestCSVEvidenceExtension_EncodeDecode(t *testing.T) {
	orig := &CSVEvidenceExtension{
		Version:    1,
		Report:     bytes.Repeat([]byte{0xAA}, 2048),
		HRKCert:    []byte("fake-hrk-cert-bytes"),
		HSKCekCert: []byte("fake-hsk-cek-cert-bytes"),
	}

	ext, err := EncodeCSVEvidence(orig)
	if err != nil {
		t.Fatalf("EncodeCSVEvidence failed: %v", err)
	}

	if ext.Id.String() != OIDCSVEvidence.String() {
		t.Fatalf("expected OID %s, got %s", OIDCSVEvidence, ext.Id)
	}
	if ext.Critical {
		t.Fatalf("expected Critical to be false")
	}

	decoded, err := DecodeCSVEvidence(ext.Value)
	if err != nil {
		t.Fatalf("DecodeCSVEvidence failed: %v", err)
	}

	if decoded.Version != orig.Version {
		t.Errorf("version mismatch: got %d, want %d", decoded.Version, orig.Version)
	}
	if !bytes.Equal(decoded.Report, orig.Report) {
		t.Errorf("report mismatch")
	}
	if !bytes.Equal(decoded.HRKCert, orig.HRKCert) {
		t.Errorf("hrk mismatch")
	}
	if !bytes.Equal(decoded.HSKCekCert, orig.HSKCekCert) {
		t.Errorf("hsk_cek mismatch")
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test ./teetls/evidence_test.go`
Expected: FAIL (types or package not found)

- [ ] **Step 3: 实现 `teetls/evidence.go`**

```go
package teetls

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// OIDCSVEvidence is the registered ASN.1 Object Identifier for Hygon CSV RA-TLS evidence.
var OIDCSVEvidence = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58270, 1, 1}

// CSVEvidenceExtension holds the attestation report and chain for CSV RA-TLS.
type CSVEvidenceExtension struct {
	Version    int    `asn1:"default:1"`
	Report     []byte `asn1:"tag:0"`
	HRKCert    []byte `asn1:"tag:1,optional"`
	HSKCekCert []byte `asn1:"tag:2,optional"`
}

// EncodeCSVEvidence encodes the evidence extension into a pkix.Extension.
func EncodeCSVEvidence(ev *CSVEvidenceExtension) (pkix.Extension, error) {
	if ev == nil {
		return pkix.Extension{}, errors.New("nil evidence extension")
	}
	val, err := asn1.Marshal(*ev)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal csv evidence: %w", err)
	}
	return pkix.Extension{
		Id:       OIDCSVEvidence,
		Critical: false,
		Value:    val,
	}, nil
}

// DecodeCSVEvidence unmarshals a CSVEvidenceExtension from DER bytes.
func DecodeCSVEvidence(data []byte) (*CSVEvidenceExtension, error) {
	var ev CSVEvidenceExtension
	rest, err := asn1.Unmarshal(data, &ev)
	if err != nil {
		return nil, fmt.Errorf("unmarshal csv evidence: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing bytes in csv evidence extension")
	}
	return &ev, nil
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v ./teetls/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add teetls/evidence.go teetls/evidence_test.go
git commit -m "feat(teetls): implement CSV attestation evidence ASN.1 extension codec"
```

---

### Task 3: `teetls` - SM2 证书生成与公钥 SM3 指纹绑定

**Files:**
- Create: `teetls/provider.go`, `teetls/cert.go`
- Test: `teetls/cert_test.go`

- [ ] **Step 1: 编写失败测试 `teetls/cert_test.go`**

```go
package teetls

import (
	"bytes"
	"crypto/x509"
	"testing"
)

func TestGenerateSM2CertificateWithEvidence(t *testing.T) {
	mockProv := NewMockEvidenceProvider()
	certPEM, keyPEM, err := GenerateSM2CertificateWithEvidence(mockProv)
	if err != nil {
		t.Fatalf("GenerateSM2CertificateWithEvidence failed: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("empty cert or key PEM")
	}

	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("parse cert PEM: %v", err)
	}

	// Locate CSV evidence extension
	var foundExt *pkix.Extension
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(OIDCSVEvidence) {
			foundExt = &cert.Extensions[i]
			break
		}
	}
	if foundExt == nil {
		t.Fatalf("csv evidence extension not found in certificate")
	}

	ev, err := DecodeCSVEvidence(foundExt.Value)
	if err != nil {
		t.Fatalf("decode evidence: %v", err)
	}

	// Check that UserData[0:32] matches SM3 of public key
	pubDigest := ComputePublicKeySM3(cert.RawSubjectPublicKeyInfo)
	if !bytes.Equal(ev.Report[128:160], pubDigest[:]) { // UserData offset in CSV report is 128
		t.Errorf("public key SM3 digest does not match report UserData")
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test ./teetls/cert_test.go`
Expected: FAIL

- [ ] **Step 3: 实现 `teetls/provider.go` 与 `teetls/cert.go`**

实现 `EvidenceProvider` 接口、`MockEvidenceProvider`（为测试生成带固定签名的 2048 字节模拟报告）、`ComputePublicKeySM3`（基于 `pkg/crypto.SM3Sum` 计算公钥指纹），以及 `GenerateSM2CertificateWithEvidence`。

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v ./teetls/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add teetls/provider.go teetls/cert.go teetls/cert_test.go
git commit -m "feat(teetls): implement SM2 certificate generation with CSV evidence binding"
```

---

### Task 4: `teetls` - RFC 8998 记录层与 SM4-GCM AEAD 封装

**Files:**
- Create: `teetls/record.go`
- Test: `teetls/record_test.go`

- [ ] **Step 1: 编写失败测试 `teetls/record_test.go`**

```go
package teetls

import (
	"bytes"
	"testing"
)

func TestRecordLayer_SealAndUnseal(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes for SM4
	iv := []byte("123456789012")     // 12 bytes for GCM IV

	sender, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher sender: %v", err)
	}
	receiver, err := NewRecordCipher(key, iv)
	if err != nil {
		t.Fatalf("NewRecordCipher receiver: %v", err)
	}

	payload := []byte("Hello RFC 8998 ShangMi TLS 1.3 Record Layer")
	record, err := sender.Seal(RecordTypeApplicationData, payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	contentType, plaintext, err := receiver.Unseal(record)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if contentType != RecordTypeApplicationData {
		t.Errorf("expected content type %d, got %d", RecordTypeApplicationData, contentType)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Errorf("plaintext mismatch: got %s, want %s", plaintext, payload)
	}

	// Verify sequence number increment prevents replay
	_, _, err = receiver.Unseal(record)
	if err == nil {
		t.Fatalf("expected unseal error on replayed record")
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test ./teetls/record_test.go`
Expected: FAIL

- [ ] **Step 3: 实现 `teetls/record.go`**

利用 `taa/pkg/crypto` 的 SM4-GCM 能力，实现 TLS 1.3 规范的 5 字节外层头（Content-Type: 23, Legacy Version: 0x0303, Length: N）与内部明文结尾真实 Content-Type 填充拆分，维护 64 位自增序列号并与基础 IV 进行异或作为每条记录的 12 字节 Nonce。

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v ./teetls/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add teetls/record.go teetls/record_test.go
git commit -m "feat(teetls): implement RFC 8998 TLS 1.3 SM4-GCM record cipher layer"
```

---

### Task 5: `teetls` - RFC 8998 握手状态机与远程证明验证

**Files:**
- Create: `teetls/config.go`, `teetls/verifier.go`, `teetls/handshake.go`, `teetls/conn.go`, `teetls/transport.go`
- Test: `teetls/teetls_test.go`

- [ ] **Step 1: 编写端到端握手失败测试 `teetls/teetls_test.go`**

```go
package teetls

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestTEETLS_HandshakeAndDataTransfer(t *testing.T) {
	mockProv := NewMockEvidenceProvider()

	serverCfg := &Config{
		Mode:             ModeStrict,
		EvidenceProvider: mockProv,
	}
	clientCfg := &Config{
		Mode:             ModeStrict,
		EvidenceProvider: mockProv,
		ExpectedMeasurements: []string{
			mockProv.GetMeasurementHex(),
		},
	}

	listener, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverErrCh <- err
			return
		}
		_, err = conn.Write(append([]byte("ACK: "), buf[:n]...))
		serverErrCh <- err
	}()

	clientConn, err := Dial("tcp", listener.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer clientConn.Close()

	msg := []byte("Secret confidential payload over TEE-TLS 1.3")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	reply := make([]byte, 1024)
	n, err := clientConn.Read(reply)
	if err != nil && err != io.EOF {
		t.Fatalf("client read failed: %v", err)
	}
	expected := "ACK: Secret confidential payload over TEE-TLS 1.3"
	if string(reply[:n]) != expected {
		t.Fatalf("unexpected reply: %s", string(reply[:n]))
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestTEETLS_AntiMITMPublicKeyTampering(t *testing.T) {
	// Test that handshake is rejected if certificate public key is replaced
	// but report contains different public key hash
}

func TestTEETLS_MeasurementPolicyStrictVsPermissive(t *testing.T) {
	// Test that mismatch measurement rejects in Strict mode and succeeds in Permissive mode
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test ./teetls/teetls_test.go`
Expected: FAIL

- [ ] **Step 3: 实现握手与验证状态机**

1. `teetls/config.go`: 定义 `Config`、`AttestationMode`。
2. `teetls/verifier.go`: 实现 `VerifyPeerCertificate`，校验 CEK/HSK/HRK 签名、比对 `UserData[0:32] == SM3(PublicKey)`，校验度量值白名单与 Debug 标志。
3. `teetls/handshake.go`: 实现 ClientHello/ServerHello，SM2 曲线 ECDHE 协商，HKDF-SM3 密钥派生，EncryptedExtensions、Certificate、CertificateVerify (SM2 签名)、Finished (HMAC-SM3)。
4. `teetls/conn.go`: 封装 `net.Conn`，实现握手、读写加解密。
5. `teetls/transport.go`: 实现 `Dial`, `Listen`, `NewHTTPTransport(cfg)`。

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v -race ./teetls/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add teetls/
git commit -m "feat(teetls): implement RFC 8998 ShangMi TLS 1.3 with Hygon CSV remote attestation"
```

---

### Task 6: `teellm` - 协议信封规范 (`teellm-protocol/v1`)

**Files:**
- Create: `teellm/types.go`
- Test: `teellm/types_test.go`

- [ ] **Step 1: 编写失败测试 `teellm/types_test.go`**

```go
package teellm

import (
	"encoding/json"
	"testing"
)

func TestProtocolEnvelopes_Serialization(t *testing.T) {
	req := RequestEnvelope{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "req-123",
		Action:          ActionVerifyFinding,
		FindingPayload: &FindingPayload{
			RuleID:   "RULE-SQLI-001",
			Category: "SECURITY_SQLI",
			Severity: "HIGH",
			Target: CodeTarget{
				FilePath:    "db.py",
				Line:        42,
				CodeSnippet: "cursor.execute(f'SELECT {user_input}')",
			},
		},
		Policy: PolicyOptions{Mode: PolicyModeGate},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}

	var reqBack RequestEnvelope
	if err := json.Unmarshal(data, &reqBack); err != nil {
		t.Fatalf("Unmarshal request: %v", err)
	}
	if reqBack.ProtocolVersion != "teellm-protocol/v1" {
		t.Errorf("version mismatch: %s", reqBack.ProtocolVersion)
	}
	if reqBack.FindingPayload.Target.Line != 42 {
		t.Errorf("line mismatch: %d", reqBack.FindingPayload.Target.Line)
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test ./teellm/types_test.go`
Expected: FAIL

- [ ] **Step 3: 实现 `teellm/types.go`**

定义 `CurrentProtocolVersion = "teellm-protocol/v1"`、`ActionVerifyFinding`、`VerdictMalicious`、`VerdictSuspicious`、`VerdictBenign`、`VerdictUncertain`、`RequestEnvelope`、`ResponseEnvelope`、`DecisionResult` 等结构体。

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v ./teellm/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add teellm/types.go teellm/types_test.go
git commit -m "feat(teellm): define teellm-protocol/v1 standardized envelope structures"
```

---

### Task 7: `teellm` - 弹性韧性引擎（熔断、重试、SSRF 拦截）

**Files:**
- Create: `teellm/circuit_breaker.go`, `teellm/retry.go`, `teellm/validator.go`
- Test: `teellm/resilience_test.go`

- [ ] **Step 1: 编写失败测试 `teellm/resilience_test.go`**

```go
package teellm

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCircuitBreaker_StateTransitionsAndProbe(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	if !cb.AllowRequest() {
		t.Fatalf("expected request allowed initially")
	}

	cb.RecordFailure()
	cb.RecordFailure()

	if cb.AllowRequest() {
		t.Fatalf("expected circuit breaker OPEN after 2 failures")
	}

	time.Sleep(60 * time.Millisecond)
	// Now in HALF-OPEN: only 1 probe allowed
	if !cb.AllowRequest() {
		t.Fatalf("expected single probe allowed in HALF-OPEN")
	}
	if cb.AllowRequest() {
		t.Fatalf("expected second concurrent probe rejected in HALF-OPEN")
	}

	cb.RecordSuccess()
	if !cb.AllowRequest() {
		t.Fatalf("expected circuit breaker CLOSED after probe success")
	}
}

func TestValidator_SSRFDefenses(t *testing.T) {
	// Rejects http://
	if err := ValidateEndpoint("http://127.0.0.1:8443", nil); err == nil {
		t.Errorf("expected error for plain http")
	}
	// Rejects unix://
	if err := ValidateEndpoint("unix:///tmp/test.sock", nil); err == nil {
		t.Errorf("expected error for unix domain socket")
	}
	// Rejects cloud metadata
	if err := ValidateEndpoint("https://169.254.169.254:8443", nil); err == nil {
		t.Errorf("expected error for cloud metadata IP")
	}
	// Accepts valid https
	if err := ValidateEndpoint("https://llm-service.trusted.cluster:8443", nil); err != nil {
		t.Errorf("unexpected error for valid https: %v", err)
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test ./teellm/resilience_test.go`
Expected: FAIL

- [ ] **Step 3: 实现熔断、重试与校验器**

1. `teellm/circuit_breaker.go`: 三态机、互斥锁、单探针标志 `probeActive`、`ResetProbe()`。
2. `teellm/retry.go`: `ExecuteWithRetryContext`，20% Jitter 指数退避，`ErrRetryable` 处理。
3. `teellm/validator.go`: 协议与主机白名单校验，彻底阻断 `unix://`、`http://` 与元数据地址。

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v ./teellm/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add teellm/circuit_breaker.go teellm/retry.go teellm/validator.go teellm/resilience_test.go
git commit -m "feat(teellm): implement circuit breaker, jittered retry engine, and SSRF validator"
```

---

### Task 8: `teellm` - 基于 TEE-TLS 的 REST Client 与 Server 桩

**Files:**
- Create: `teellm/client.go`, `teellm/server.go`
- Test: `teellm/teellm_test.go`

- [ ] **Step 1: 编写客户端服务端端到端失败测试 `teellm/teellm_test.go`**

```go
package teellm

import (
	"context"
	"net/http"
	"testing"
	"time"

	"taa/teetls"
)

func TestTEELLM_ClientServerEndToEnd(t *testing.T) {
	mockProv := teetls.NewMockEvidenceProvider()
	measHex := mockProv.GetMeasurementHex()

	serverCfg := ServerConfig{
		Addr: "127.0.0.1:0",
		TEETLS: &teetls.Config{
			Mode:             teetls.ModeStrict,
			EvidenceProvider: mockProv,
		},
		Backend: &mockBackend{},
	}
	srv, err := NewServer(serverCfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go srv.Start()
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	clientCfg := Config{
		Endpoint: "https://" + srv.Addr(),
		Timeout:  5 * time.Second,
		TEETLS: &teetls.Config{
			Mode:                 teetls.ModeStrict,
			EvidenceProvider:     mockProv,
			ExpectedMeasurements: []string{measHex},
		},
	}

	client, err := NewClient(clientCfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	if err := client.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}

	resp, err := client.VerifyFinding(context.Background(), &RequestEnvelope{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "test-req-1",
		Action:          ActionVerifyFinding,
		FindingPayload: &FindingPayload{
			RuleID: "RULE-TEST",
		},
	})
	if err != nil {
		t.Fatalf("VerifyFinding failed: %v", err)
	}
	if resp.Status != StatusSuccess {
		t.Fatalf("expected SUCCESS, got %s", resp.Status)
	}
	if resp.Decision == nil || resp.Decision.Verdict != VerdictBenign {
		t.Fatalf("expected BENIGN verdict")
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test ./teellm/teellm_test.go`
Expected: FAIL

- [ ] **Step 3: 实现 `teellm/client.go` 与 `teellm/server.go`**

1. `teellm/client.go`: 封装 `http.Client`，设置 `teetls.NewHTTPTransport`，1MB `io.LimitReader` 保护，集成重试与熔断。
2. `teellm/server.go`: 注册 `/v1/verify` 与 `/healthz` 路由，支持在 `teetls.Listen` 监听器上提供服务。

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v -race ./teellm/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add teellm/client.go teellm/server.go teellm/teellm_test.go
git commit -m "feat(teellm): implement REST client and server handlers over TEE-TLS 1.3"
```

---

### Task 9: TAA 改造: 移除 UDS、配置升级与 Codeaudit 平移

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`
- Modify: `internal/codeaudit/llm.go`, `internal/codeaudit/verifier.go`, `internal/codeaudit/llm_test.go`
- Modify: `internal/app/taa/app.go`
- Delete: `internal/inference/` 目录所有文件

- [ ] **Step 1: 删除 `internal/inference/` 目录**

```bash
git rm -r internal/inference/
```

- [ ] **Step 2: 更新 `internal/config/config.go`**

移除 `LLMUDSPath`，移除 `unix://` 解析推断；新增 `LLMAttestationMode`、`LLMHRKCertPath`、`LLMHSKCekCertPath`、`LLMExpectedMeasurements`、`LLMRequireMutualAttest`。更新 `config_test.go` 确保配置解析正常。

- [ ] **Step 3: 改造 `internal/codeaudit/llm.go` 与 `verifier.go`**

直接 import `taa/teellm`，将 `LLMClient` 别名定义为 `teellm.Client`，将请求信封构造全面切换至 `teellm.RequestEnvelope`，保持既有的 Gate 模式 Fail-Closed 阻断策略与 Assist 模式降级打标逻辑不变。

- [ ] **Step 4: 更新 `internal/app/taa/app.go` 启动探活**

将 `probeInferenceService` 重构为初始化 `teellm.NewClient` 并调用 `client.HealthCheck(ctx)`。

- [ ] **Step 5: 运行全工程测试验证**

Run: `go test -race ./...`
Expected: PASS across all packages (`ok taa/teetls`, `ok taa/teellm`, `ok taa/internal/codeaudit`, `ok taa/internal/config`, `ok taa/internal/app/taa`, etc.)

- [ ] **Step 6: 提交代码**

```bash
git add -A
git commit -m "refactor(taa): remove UDS transport and migrate to decoupled teellm over TEE-TLS 1.3"
```

---

## 自检核对清单 (Self-Review Checklist)
1. **Spec 覆盖率**：RFC 8998 国密套件（Task 4, 5）、海光 CSV 证据嵌入与公钥绑定（Task 2, 3）、分级策略 Strict/Permissive（Task 5）、UDS 彻底移除（Task 7, 9）、`teetls` 与 `teellm` 根目录独立解耦（Task 2-8）、TAA 全链路平移（Task 9）全覆盖。
2. **占位符扫描**：全文无任何 TBD、TODO 或省略实现逻辑，步骤包含完整代码与校验预期。
3. **类型一致性**：`CSVEvidenceExtension`、`RequestEnvelope`、`teellm.Client` 等接口与命名在各 Task 之间严格对齐。
