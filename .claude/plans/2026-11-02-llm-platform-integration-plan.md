# LLM 侧平台接入（注册 / 心跳 / 日志 / 远程证明）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `teellm-service` 中新增向平台注册、维持心跳、批量上报运行日志三条出方向通道，并在新增的明文 `:8444` 上提供 `/v1/llm/getAttestation`，同时把现有 `/v1/verify`、`/healthz` 统一改名为 `/v1/llm/*`。

**Architecture:** 出方向由新增的 `teellm/platformagent` 包负责：一个 `Agent` 持有内存环形日志缓冲，注册成功后起心跳与日志定时器，全链路明文 JSON POST 到平台 `/v1/llm/*`，失败只写本地 stderr、不做持久化 outbox。入方向由 `teellm.Server` 第二个明文 listener 承担 `getAttestation`，它与 TEE-TLS 握手共用同一个 `*teetls.Config` 的证书缓存，因此返回的报告与握手出示的证书是同一份。

**Tech Stack:** Go 1.22、`github.com/CipherSlinger/teetls`（含 `pkg/csvattest`）、标准库 `net/http` + `encoding/json`、`httptest`。

**Spec:** `.claude/specs/2026-11-02-llm-platform-integration-design.md`

---

## 文件结构

| 文件 | 职责 |
| --- | --- |
| `teellm/server.go` | mux 改名；`ServerConfig.AttestationAddr`；第二个明文 listener 的建立与关闭 |
| `teellm/client.go` | 请求路径改为 `/v1/llm/verify`、`/v1/llm/healthz` |
| `teellm/attestation.go`（新增） | `AttestationSnapshot` 类型与 `BuildAttestationSnapshot`；明文 `getAttestation` handler |
| `teellm/platformagent/config.go`（新增） | 上报器配置、默认值、校验 |
| `teellm/platformagent/logs.go`（新增） | 有界环形日志缓冲 `LogBuffer`（不依赖 `taa/pkg/logger`） |
| `teellm/platformagent/attestation.go`（新增） | 把 `teellm.AttestationSnapshot` 转成注册报文所需的字段 |
| `teellm/platformagent/register.go`（新增） | `POST /v1/llm/register` 报文与发送 |
| `teellm/platformagent/heartbeat.go`（新增） | `POST /v1/llm/heartbeat` 报文与发送 |
| `teellm/platformagent/reporter.go`（新增） | `Agent`：注册重试、心跳循环、日志批量推送、失败状态机 |
| `teellm/cmd/teellm-service/main.go` | 读 `server.attestationAddr` 与 `platform` 段，构造并启动 `Agent` |
| `teellm/configs/teellm-production.json`、`teellm/configs/teellm-docker.json` | 新增 `attestationAddr` 与顶层 `platform` 段 |
| `teellm/README.md` | 接口表路径与 `:8444` 说明、配置段说明 |
| `build-teellm-image.sh` | `EXPOSE 8443` → `EXPOSE 8443 8444` |
| `deploy-llm.sh` | 新增 `TEELLM_ATTESTATION_PORT`、`TEELLM_PLATFORM_ADDR`；`prepare_config` 注入两段 |
| `tools/platform-mock/internal/handlers_llm.go`（新增） | `/v1/llm/register`、`/v1/llm/heartbeat`、`/v1/llm/taaLog` 明文处理 |
| `tools/platform-mock/internal/llm_state.go`（新增） | LLM 侧注册/心跳状态存储与 status 端点 |
| `tools/platform-mock/internal/server.go` | 挂载上述路由 |
| `teellm/teellm_test.go`、`teellm/resilience_test.go`、`internal/codeaudit/llm_test.go`、`internal/app/taa/app_test.go` | 路径字符串同步改名 |

---

## Task 1: 现有接口改名为 `/v1/llm/*`

**Files:**
- Modify: `teellm/server.go:61-62,71,136`
- Modify: `teellm/client.go:152,216`
- Modify: `teellm/teellm_test.go:411`
- Modify: `teellm/resilience_test.go:281`
- Modify: `internal/codeaudit/llm_test.go:654,763`
- Modify: `internal/app/taa/app_test.go:454,481`

- [ ] **Step 1: 先改测试里的路径字符串（让它们先失败）**

`teellm/teellm_test.go:411`：

```go
	resp, err := http.Post("http://"+srv.Addr()+"/v1/llm/verify", "application/json", bytes.NewReader(hugeBody))
```

`teellm/resilience_test.go:281`：

```go
		"https://localhost:8443/v1/llm/verify",
```

`internal/codeaudit/llm_test.go:654` 与 `:763`，两处都改为：

```go
		if r.URL.Path == "/v1/llm/verify" {
```

`internal/app/taa/app_test.go:454` 与 `:481`，两处都改为：

```go
		if r.URL.Path == "/v1/llm/healthz" {
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd /home/hjy/taa && go test ./teellm/ ./internal/codeaudit/ ./internal/app/taa/ -run 'TestServer|TestOllamaClientSuccess|TestProbeInferenceService' -count=1`

Expected: FAIL —— `teellm_test.go` 的那条得到 404 而不是 413；`app_test.go` 的探针拿到 404 → `ErrInvalidStatus`。

- [ ] **Step 3: 改服务端路由**

`teellm/server.go:60-62` 改为：

```go
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/llm/verify", s.handleVerify)
	mux.HandleFunc("/v1/llm/healthz", s.handleHealthz)
```

同一文件第 71 行与第 136 行的文档注释同步：

```go
// handleVerify handles finding verification requests under POST /v1/llm/verify.
```

```go
// handleHealthz handles health check queries under GET /v1/llm/healthz.
```

- [ ] **Step 4: 改客户端请求路径**

`teellm/client.go:152`：

```go
		httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/llm/verify", bytes.NewReader(reqBytes))
```

`teellm/client.go:216`：

```go
		httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/v1/llm/healthz", nil)
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd /home/hjy/taa && go test ./teellm/ ./internal/codeaudit/ ./internal/app/taa/ -count=1`

Expected: `ok` 三段。`internal/codeaudit` 较慢，可单独跑。

- [ ] **Step 6: 更新 README 的接口图**

`teellm/README.md:69` 改为：

```
 |   |  - HTTP/1.1 Endpoint (/v1/llm/verify, /v1/llm/healthz) |   |
```

- [ ] **Step 7: 提交**

```bash
cd /home/hjy/taa && git add teellm/server.go teellm/client.go teellm/teellm_test.go teellm/resilience_test.go teellm/README.md internal/codeaudit/llm_test.go internal/app/taa/app_test.go
git commit -m "refactor(teellm): move the HTTP surface under /v1/llm"
```

---

## Task 2: 明文 `:8444` 上的 `getAttestation`

**Files:**
- Create: `teellm/attestation.go`
- Create: `teellm/attestation_test.go`
- Modify: `teellm/server.go`

- [ ] **Step 1: 写失败的 handler 测试**

创建 `teellm/attestation_test.go`：

```go
package teellm

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/CipherSlinger/teetls"
	"github.com/CipherSlinger/teetls/pkg/csvattest"
)

type attestationResponse struct {
	Msg    string `json:"msg"`
	Error  int    `json:"error"`
	Result struct {
		RequestID         string `json:"requestId"`
		VerifiedPass      bool   `json:"verifiedPass"`
		Attestation       string `json:"attestation"`
		AttestationValues string `json:"attestationValues"`
		Certificate       string `json:"certificate"`
	} `json:"result"`
}

func newPlaintextAttestationServer(t *testing.T) *Server {
	t.Helper()
	provider := teetls.NewMockEvidenceProvider()
	srv, err := NewServer(ServerConfig{
		Addr:            "127.0.0.1:0",
		AttestationAddr: "127.0.0.1:0",
		TEETLS: &teetls.Config{
			Mode:                          teetls.ModePermissive,
			EvidenceProvider:              provider,
			InsecureSkipAttestationVerify: true,
		},
		Backend: &mockBackend{},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func TestGetAttestationReturnsReportBoundToCertificate(t *testing.T) {
	srv := newPlaintextAttestationServer(t)

	resp, err := http.Post("http://"+srv.AttestationAddr()+"/v1/llm/getAttestation",
		"application/json", strings.NewReader(`{"requestId":"req-1"}`))
	if err != nil {
		t.Fatalf("post failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var decoded attestationResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoded.Result.RequestID != "req-1" {
		t.Fatalf("requestId = %q, want req-1", decoded.Result.RequestID)
	}
	if !decoded.Result.VerifiedPass {
		t.Fatalf("expected the mock report to self-verify, msg=%q", decoded.Msg)
	}

	report, err := base64.StdEncoding.DecodeString(decoded.Result.Attestation)
	if err != nil {
		t.Fatalf("attestation is not base64: %v", err)
	}
	if len(report) != csvattest.ReportSize {
		t.Fatalf("report size = %d, want %d", len(report), csvattest.ReportSize)
	}
	if _, err := csvattest.ParseReport(report); err != nil {
		t.Fatalf("report does not parse: %v", err)
	}

	cert, err := teetls.ParseCertificatePEM([]byte(decoded.Result.Certificate))
	if err != nil {
		t.Fatalf("returned certificate does not parse: %v", err)
	}

	// The whole point of the plaintext channel: the report binds this exact key.
	parsed, err := csvattest.ParseReport(report)
	if err != nil {
		t.Fatalf("parse report: %v", err)
	}
	want := teetls.ComputePublicKeySM3(cert.RawSubjectPublicKeyInfo)
	if len(parsed.UserData) < 32 || string(parsed.UserData[:32]) != string(want[:]) {
		t.Fatalf("report userdata does not bind the returned certificate")
	}
}

func TestGetAttestationRejectsEmptyRequestID(t *testing.T) {
	srv := newPlaintextAttestationServer(t)

	resp, err := http.Post("http://"+srv.AttestationAddr()+"/v1/llm/getAttestation",
		"application/json", strings.NewReader(`{"requestId":""}`))
	if err != nil {
		t.Fatalf("post failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestServerWithoutAttestationAddrHasNoPlaintextListener(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		Addr:    "127.0.0.1:0",
		TEETLS:  &teetls.Config{Mode: teetls.ModePermissive, EvidenceProvider: teetls.NewMockEvidenceProvider(), InsecureSkipAttestationVerify: true},
		Backend: &mockBackend{},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()
	if addr := srv.AttestationAddr(); addr != "" {
		t.Fatalf("AttestationAddr = %q, want empty", addr)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd /home/hjy/taa/teellm && go test -run 'TestGetAttestation|TestServerWithoutAttestation' -count=1 ./`

Expected: 编译失败 —— `unknown field AttestationAddr in struct literal`、`srv.AttestationAddr undefined`。

- [ ] **Step 3: 实现 `teellm/attestation.go`**

```go
package teellm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	cx509 "crypto/x509"

	"github.com/CipherSlinger/teetls"
	"github.com/CipherSlinger/teetls/pkg/csvattest"
)

// AttestationValues carries the report fields the platform stores verbatim.
// The JSON tags match taa/internal/attestation.ReportValues exactly, so the
// platform's existing display and verification code needs no change.
type AttestationValues struct {
	UserData string `json:"userdata"`
	MNonce   string `json:"mnonce"`
	Digest   string `json:"digest"`
	ChipID   string `json:"chipId"`
}

// AttestationSnapshot is one consistent view of what this instance presents:
// the certificate it authenticates with, the CSV report embedded in that
// certificate's evidence extension, and whether that report self-verifies.
//
// Every field is taken from the same cached certificate. Re-fetching a report
// from the device would open a window where the report and the certificate
// disagree, and "report belongs to this certificate" is precisely what the
// platform is checking.
type AttestationSnapshot struct {
	CertificatePEM []byte
	PublicKeyPEM   string
	Report         []byte
	Values         AttestationValues
	VerifiedPass   bool
	// VerifyMessage carries the reason a failed self-check failed, so the
	// response can say "自检验证失败: <原因>" the way TAA does.
	VerifyMessage string
}

// ValuesJSON renders Values the way the platform expects to receive it: a JSON
// object carried inside a JSON string field.
func (s *AttestationSnapshot) ValuesJSON() string {
	data, err := json.Marshal(s.Values)
	if err != nil {
		return ""
	}
	return string(data)
}

// BuildAttestationSnapshot reads the certificate currently cached by cfg and
// decodes the CSV evidence embedded in it. It never triggers a second hardware
// IOCTL: the certificate cache is the single source for both this call and the
// TEE-TLS handshake.
func BuildAttestationSnapshot(ctx context.Context, cfg *teetls.Config) (*AttestationSnapshot, error) {
	if cfg == nil {
		return nil, errors.New("attestation snapshot requires a TEE-TLS config")
	}

	certPEM, _, err := cfg.GetOrGenerateCertificateContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain current certificate: %w", err)
	}
	cert, err := teetls.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse current certificate: %w", err)
	}

	var evidenceDER []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(teetls.OIDCSVEvidence) {
			evidenceDER = ext.Value
			break
		}
	}
	if evidenceDER == nil {
		return nil, teetls.ErrMissingCSVEvidence
	}
	evidence, err := teetls.DecodeCSVEvidence(evidenceDER)
	if err != nil {
		return nil, fmt.Errorf("decode csv evidence: %w", err)
	}

	res, err := csvattest.ParseReport(evidence.Report)
	if err != nil {
		return nil, fmt.Errorf("parse attestation report: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: cert.RawSubjectPublicKeyInfo})
	verified, verifyMsg := snapshotVerifies(evidence, cfg, cert)

	return &AttestationSnapshot{
		CertificatePEM: append([]byte(nil), certPEM...),
		PublicKeyPEM:   string(pubPEM),
		Report:         append([]byte(nil), evidence.Report...),
		Values: AttestationValues{
			UserData: hex.EncodeToString(res.UserData),
			MNonce:   hex.EncodeToString(res.MNonce),
			Digest:   hex.EncodeToString(res.Digest),
			ChipID:   strings.TrimRight(string(res.ChipID), "\x00"),
		},
		VerifiedPass:  verified,
		VerifyMessage: verifyMsg,
	}, nil
}

// snapshotVerifies runs the same chain check the platform will run, plus the
// public-key binding check. A failure here does not withhold the report; it
// only marks it unverified, matching how TAA degrades on a failed self-check.
func snapshotVerifies(evidence *teetls.CSVEvidenceExtension, cfg *teetls.Config, cert *cx509.Certificate) (bool, string) {
	opts := csvattest.VerifyOptions{VerifyChain: true}
	switch {
	case cfg.HRKCertPath != "" && cfg.HSKCekCertPath != "":
		opts.TrustedHRKCertPath = cfg.HRKCertPath
		opts.HSKCekCertPath = cfg.HSKCekCertPath
	case len(cfg.TrustedHRKCert) > 0 && len(evidence.HSKCekCert) > 0:
		opts.TrustedHRKCertBytes = cfg.TrustedHRKCert
		opts.HSKCekCertBytes = evidence.HSKCekCert
	case len(evidence.HRKCert) > 0 && len(evidence.HSKCekCert) > 0:
		opts.TrustedHRKCertBytes = evidence.HRKCert
		opts.HSKCekCertBytes = evidence.HSKCekCert
	default:
		return false, "没有可信 HRK/HSK-CEK 证书可用于链验"
	}

	res, err := csvattest.VerifyReportWithOptions(evidence.Report, opts)
	if err != nil {
		return false, err.Error()
	}
	bound := teetls.ComputePublicKeySM3(cert.RawSubjectPublicKeyInfo)
	if len(res.UserData) < 32 || !bytes.Equal(res.UserData[:32], bound[:]) {
		return false, "报告 userdata 与证书公钥的 SM3 不一致"
	}
	return true, ""
}

// apiResponse is the envelope TAA already answers with, reproduced here so the
// platform parses both with one decoder.
type apiResponse struct {
	Msg    string `json:"msg"`
	Result any    `json:"result"`
	Error  int    `json:"error"`
}

type getAttestationRequest struct {
	RequestID string `json:"requestId"`
}

func writeAPIResponse(w http.ResponseWriter, status int, msg string, result any, errorCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiResponse{Msg: msg, Result: result, Error: errorCode})
}

// handleGetAttestation answers the platform over the plaintext listener. The
// response carries the certificate as well as the report: on a plaintext
// channel the peer never saw the certificate in a handshake, and without it
// the report cannot be tied to any key.
func (s *Server) handleGetAttestation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(MaxResponsePayloadBytes)+1))
	if err != nil {
		writeAPIResponse(w, http.StatusBadRequest, "读取请求体失败", nil, http.StatusBadRequest)
		return
	}
	if len(body) > MaxResponsePayloadBytes {
		writeAPIResponse(w, http.StatusRequestEntityTooLarge, "请求体超过 1MB 限制", nil, http.StatusRequestEntityTooLarge)
		return
	}

	var req getAttestationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAPIResponse(w, http.StatusBadRequest, "请求解析失败: "+err.Error(), nil, http.StatusBadRequest)
		return
	}
	if req.RequestID == "" {
		writeAPIResponse(w, http.StatusBadRequest, "requestId 不能为空", nil, http.StatusBadRequest)
		return
	}

	snapshot, err := BuildAttestationSnapshot(r.Context(), s.cfg.TEETLS)
	if err != nil {
		writeAPIResponse(w, http.StatusInternalServerError, "获取远程证明失败: "+err.Error(), nil, http.StatusInternalServerError)
		return
	}

	msg := "success"
	if !snapshot.VerifiedPass {
		msg = "自检验证失败: " + snapshot.VerifyMessage
	}

	writeAPIResponse(w, http.StatusOK, msg, map[string]any{
		"requestId":         req.RequestID,
		"verifiedPass":      snapshot.VerifiedPass,
		"attestation":       base64.StdEncoding.EncodeToString(snapshot.Report),
		"attestationValues": snapshot.ValuesJSON(),
		"certificate":       string(snapshot.CertificatePEM),
	}, 0)
}
```

- [ ] **Step 4: 在 `server.go` 上挂第二个 listener**

把 `teellm/server.go` 的 `ServerConfig` 与 `Server` 改为：

```go
// ServerConfig specifies configuration options for initializing the TEE-LLM Server.
type ServerConfig struct {
	Addr string
	// AttestationAddr, when non-empty, starts a plaintext HTTP listener that
	// serves only POST /v1/llm/getAttestation. Empty leaves it unmounted, so a
	// pure inference deployment exposes no unauthenticated port.
	AttestationAddr string
	TEETLS          *teetls.Config
	Backend         Backend
}

// Server provides the HTTP REST server for teellm-protocol/v1.
type Server struct {
	cfg                 ServerConfig
	listener            net.Listener
	httpSrv             *http.Server
	attestationListener net.Listener
	attestationSrv      *http.Server
	backend             Backend
}
```

`NewServer` 在创建完主 listener 后追加：

```go
	if cfg.AttestationAddr != "" && cfg.TEETLS == nil {
		_ = listener.Close()
		return nil, errors.New("attestation listener requires a TEE-TLS config")
	}

	s := &Server{
		cfg:      cfg,
		listener: listener,
		backend:  cfg.Backend,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/llm/verify", s.handleVerify)
	mux.HandleFunc("/v1/llm/healthz", s.handleHealthz)

	s.httpSrv = &http.Server{
		Handler: mux,
	}

	if cfg.AttestationAddr != "" {
		attestationListener, listenErr := net.Listen("tcp", cfg.AttestationAddr)
		if listenErr != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("attestation listen error: %w", listenErr)
		}
		attestationMux := http.NewServeMux()
		attestationMux.HandleFunc("/v1/llm/getAttestation", s.handleGetAttestation)
		s.attestationListener = attestationListener
		s.attestationSrv = &http.Server{Handler: attestationMux}
	}

	return s, nil
```

`Start` 改为：

```go
// Start runs the TEE-TLS server and, when configured, the plaintext attestation
// listener. It returns nil when the primary server is cleanly closed.
func (s *Server) Start() error {
	if s.attestationSrv != nil {
		go func() {
			// The attestation port is auxiliary and plaintext: its failure must be
			// visible but must not take inference down with it.
			if err := s.attestationSrv.Serve(s.attestationListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[WARN] [teellm] plaintext attestation listener stopped: %v", err)
			}
		}()
	}

	err := s.httpSrv.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
```

`Close` 与新增 `AttestationAddr`：

```go
// Close gracefully closes the HTTP server and both listeners.
func (s *Server) Close() error {
	if s.attestationSrv != nil {
		_ = s.attestationSrv.Close()
	}
	return s.httpSrv.Close()
}

// AttestationAddr returns the plaintext attestation address, or "" when the
// listener is not mounted.
func (s *Server) AttestationAddr() string {
	if s.attestationListener != nil {
		return s.attestationListener.Addr().String()
	}
	return ""
}
```

并给 `server.go` 的 import 增加 `"log"`。

- [ ] **Step 5: 运行测试确认通过**

Run: `cd /home/hjy/taa/teellm && go test -run 'TestGetAttestation|TestServerWithoutAttestation' -count=1 -v ./`

Expected: PASS，三条测试均为 `--- PASS`。

- [ ] **Step 6: 跑完整 teellm 测试**

Run: `cd /home/hjy/taa && go test ./teellm/... -count=1`

Expected: `ok`。

- [ ] **Step 7: 提交**

```bash
cd /home/hjy/taa && git add teellm/attestation.go teellm/attestation_test.go teellm/server.go
git commit -m "feat(teellm): serve getAttestation on a plaintext listener"
```

---

## Task 3: 上报器配置与环形日志缓冲

**Files:**
- Create: `teellm/platformagent/config.go`
- Create: `teellm/platformagent/logs.go`
- Create: `teellm/platformagent/logs_test.go`

- [ ] **Step 1: 写失败的缓冲测试**

创建 `teellm/platformagent/logs_test.go`：

```go
package platformagent

import (
	"strings"
	"testing"
	"time"
)

func TestLogBufferAssignsContiguousSeq(t *testing.T) {
	buf := NewLogBuffer(10)
	buf.Add(LevelInfo, "teellm", "one")
	buf.Add(LevelWarn, "teellm", "two")

	entries := buf.Drain()
	if len(entries) != 2 {
		t.Fatalf("drained %d entries, want 2", len(entries))
	}
	if entries[0].Seq != 1 || entries[1].Seq != 2 {
		t.Fatalf("seq = %d,%d, want 1,2", entries[0].Seq, entries[1].Seq)
	}
	if entries[0].Message != "one" || entries[1].Message != "two" {
		t.Fatalf("unexpected messages: %+v", entries)
	}
}

func TestLogBufferDrainIsIncremental(t *testing.T) {
	buf := NewLogBuffer(10)
	buf.Add(LevelInfo, "teellm", "one")
	_ = buf.Drain()
	buf.Add(LevelInfo, "teellm", "two")

	entries := buf.Drain()
	if len(entries) != 1 {
		t.Fatalf("drained %d entries, want 1", len(entries))
	}
	if entries[0].Seq != 2 {
		t.Fatalf("seq = %d, want 2", entries[0].Seq)
	}
}

func TestLogBufferDropsOldestWhenFull(t *testing.T) {
	buf := NewLogBuffer(4)
	for i := 0; i < 10; i++ {
		buf.Add(LevelInfo, "teellm", "line")
	}
	if got := buf.Count(); got > 4 {
		t.Fatalf("buffer holds %d entries, want at most 4", got)
	}
	entries := buf.Drain()
	for _, e := range entries {
		if e.Seq < 7 {
			t.Fatalf("kept seq %d, want only the newest", e.Seq)
		}
	}
}

func TestFormatMessageMatchesTAAShape(t *testing.T) {
	entry := Entry{
		Seq:       1,
		Timestamp: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC),
		Level:     LevelInfo,
		Component: "teellm",
		Message:   "ollama ready",
	}
	want := "[2026-11-02 10:00:00] [INFO] [teellm] ollama ready"
	if got := entry.FormatMessage(); got != want {
		t.Fatalf("FormatMessage = %q, want %q", got, want)
	}
}

func TestFormatMessageDefaults(t *testing.T) {
	entry := Entry{Seq: 2, Timestamp: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)}
	got := entry.FormatMessage()
	if !strings.Contains(got, "[INFO] [system]") {
		t.Fatalf("FormatMessage = %q, want the INFO/system defaults", got)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd /home/hjy/taa/teellm && go test ./platformagent/ -count=1`

Expected: 编译失败 —— `undefined: NewLogBuffer`。

- [ ] **Step 3: 实现 `logs.go`**

```go
package platformagent

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// Level is the severity of a captured log record.
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Entry is one structured log record. Seq increases monotonically from 1 and
// never repeats, which is what the platform's contiguous-batch contract needs.
type Entry struct {
	Seq       uint64
	Timestamp time.Time
	Level     Level
	Component string
	Message   string
}

// FormatMessage renders the record in the same shape TAA reports, so the
// platform's log viewer handles both without a branch.
func (e Entry) FormatMessage() string {
	ts := e.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	tsStr := ts.UTC().Format("2006-01-02 15:04:05")
	lvl := strings.ToUpper(string(e.Level))
	if lvl == "" {
		lvl = "INFO"
	}
	comp := e.Component
	if comp == "" {
		comp = "system"
	}
	return fmt.Sprintf("[%s] [%s] [%s] %s", tsStr, lvl, comp, e.Message)
}

// LogBuffer is a bounded, thread-safe log ring. It keeps the newest maxSize
// records and hands them out incrementally.
//
// It is a deliberate reimplementation of taa/pkg/logger.Store rather than an
// import: teellm is a separate module and cannot depend on taa internals.
type LogBuffer struct {
	mu      sync.Mutex
	entries []Entry
	maxSize int
	cursor  int
	nextSeq uint64
}

// NewLogBuffer creates a buffer holding at most maxSize records.
func NewLogBuffer(maxSize int) *LogBuffer {
	if maxSize <= 0 {
		maxSize = DefaultLogBufferSize
	}
	return &LogBuffer{
		entries: make([]Entry, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add records one message and mirrors it to stderr, so an unreachable platform
// still leaves a local trail in teellm-service.log.
func (b *LogBuffer) Add(level Level, component, format string, args ...any) {
	if b == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	entry := Entry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Component: component,
		Message:   msg,
	}
	log.Printf("%s", entry.FormatMessage())

	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextSeq++
	entry.Seq = b.nextSeq

	// Drop the oldest half when full, and move the read cursor back with it so
	// it never points past the start of the slice.
	if len(b.entries) >= b.maxSize {
		drop := b.maxSize / 2
		if drop <= 0 {
			drop = 1
		}
		b.entries = append(b.entries[:0], b.entries[drop:]...)
		if b.cursor >= drop {
			b.cursor -= drop
		} else {
			b.cursor = 0
		}
	}
	b.entries = append(b.entries, entry)
}

// Drain returns everything recorded since the previous Drain and advances the
// read cursor.
func (b *LogBuffer) Drain() []Entry {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cursor >= len(b.entries) {
		return nil
	}
	out := make([]Entry, len(b.entries)-b.cursor)
	copy(out, b.entries[b.cursor:])
	b.cursor = len(b.entries)
	return out
}

// Count reports how many records the buffer currently holds.
func (b *LogBuffer) Count() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}
```

- [ ] **Step 4: 实现 `config.go`**

```go
package platformagent

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Defaults applied by New when a field is left at zero.
const (
	DefaultDockerID                 = "taa-teellm"
	DefaultHeartbeatInterval        = 30 * time.Second
	DefaultLogFlushInterval         = 5 * time.Second
	DefaultRegisterRefreshInterval  = 6 * time.Hour
	DefaultRegisterRetryWindow      = 10 * time.Minute
	DefaultLogBufferSize            = 2000
	DefaultHeartbeatSeconds         = 30
	DefaultLogFlushSeconds          = 5
	DefaultRegisterRefreshSeconds   = 21600
	DefaultMaxLogBatchSize          = 100
	DefaultRequestTimeout           = 10 * time.Second
)

// Register retry ladder. It mirrors the shape of TAA's register retry: double
// from a short delay up to a cap, inside a bounded window.
const (
	registerRetryInitialDelay = 1 * time.Second
	registerRetryMaxDelay     = 60 * time.Second
)

// Config configures the platform reporter.
type Config struct {
	// PlatformAddr is the platform base URL, e.g. http://172.16.10.181:18081.
	// Empty disables reporting entirely.
	PlatformAddr string
	// DockerID identifies this LLM instance on the platform.
	DockerID string
	// HeartbeatInterval is the liveness period. Default 30s.
	HeartbeatInterval time.Duration
	// LogFlushInterval is how often buffered logs are pushed. Default 5s.
	LogFlushInterval time.Duration
	// RegisterRefreshInterval re-registers periodically so the platform keeps a
	// report bound to the certificate this process is currently presenting.
	RegisterRefreshInterval time.Duration
	// RegisterRetryWindow bounds the startup registration retry loop.
	RegisterRetryWindow time.Duration
	// LogBufferSize is the ring capacity, and also the cap on the pending queue.
	LogBufferSize int
	// Logs is the shared buffer. When nil an internal one is created; the caller
	// keeps a reference so it can instrument the service.
	Logs *LogBuffer
	// HTTPClient overrides the client used for every call. Tests inject one.
	HTTPClient *http.Client
}

// withDefaults fills zero fields and normalises the platform address.
func (c Config) withDefaults() Config {
	if c.DockerID == "" {
		c.DockerID = DefaultDockerID
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if c.LogFlushInterval <= 0 {
		c.LogFlushInterval = DefaultLogFlushInterval
	}
	if c.RegisterRefreshInterval <= 0 {
		c.RegisterRefreshInterval = DefaultRegisterRefreshInterval
	}
	if c.RegisterRetryWindow <= 0 {
		c.RegisterRetryWindow = DefaultRegisterRetryWindow
	}
	if c.LogBufferSize <= 0 {
		c.LogBufferSize = DefaultLogBufferSize
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: DefaultRequestTimeout}
	}
	c.PlatformAddr = strings.TrimRight(strings.TrimSpace(c.PlatformAddr), "/")
	if c.PlatformAddr != "" && !strings.Contains(c.PlatformAddr, "://") {
		c.PlatformAddr = "http://" + c.PlatformAddr
	}
	return c
}

// validate checks the fields that cannot be defaulted.
func (c Config) validate() error {
	if strings.TrimSpace(c.DockerID) == "" {
		return errors.New("platformagent: dockerId is required")
	}
	if !strings.HasPrefix(c.PlatformAddr, "http://") && !strings.HasPrefix(c.PlatformAddr, "https://") {
		return fmt.Errorf("platformagent: unsupported platform address %q", c.PlatformAddr)
	}
	return nil
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd /home/hjy/taa/teellm && go test ./platformagent/ -count=1 -v`

Expected: PASS，5 条测试。

- [ ] **Step 6: 提交**

```bash
cd /home/hjy/taa && git add teellm/platformagent/config.go teellm/platformagent/logs.go teellm/platformagent/logs_test.go
git commit -m "feat(platformagent): add reporter config and bounded log buffer"
```

---

## Task 4: 注册、心跳与日志上报报文

**Files:**
- Create: `teellm/platformagent/attestation.go`
- Create: `teellm/platformagent/register.go`
- Create: `teellm/platformagent/heartbeat.go`
- Create: `teellm/platformagent/reporter.go`（只含发送原语，循环在 Task 5）
- Create: `teellm/platformagent/reporter_test.go`

- [ ] **Step 1: 写失败的报文测试**

创建 `teellm/platformagent/reporter_test.go`：

```go
package platformagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CipherSlinger/teellm"
)

// fakeSnapshot returns a fixed snapshot so payload shape can be asserted
// without any TEE hardware or certificate machinery.
func fakeSnapshot() *teellm.AttestationSnapshot {
	return &teellm.AttestationSnapshot{
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"),
		PublicKeyPEM:   "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n",
		Report:         []byte{0x01, 0x02, 0x03},
		Values: teellm.AttestationValues{
			UserData: "aa",
			MNonce:   "bb",
			Digest:   "cc",
			ChipID:   "CHIP",
		},
		VerifiedPass: true,
	}
}

func newTestAgent(t *testing.T, platformURL string) *Agent {
	t.Helper()
	agent, err := New(Config{
		PlatformAddr: platformURL,
		DockerID:     "taa-teellm",
		Snapshot: func(context.Context) (*teellm.AttestationSnapshot, error) {
			return fakeSnapshot(), nil
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return agent
}

func TestRegisterPayloadMatchesTAAFieldNames(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/llm/register" {
			t.Errorf("path = %q, want /v1/llm/register", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("register body is not JSON: %v", err)
		}
		_, _ = w.Write([]byte(`{"msg":"success","result":{},"error":0}`))
	}))
	defer server.Close()

	agent := newTestAgent(t, server.URL)
	if err := agent.registerOnce(context.Background()); err != nil {
		t.Fatalf("registerOnce failed: %v", err)
	}

	for _, key := range []string{
		"dockerId", "authInfo", "taaPublicKey", "attestationValues",
		"timestamp", "verifiedPass", "attestation",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("register payload is missing %q", key)
		}
	}
	if _, ok := got["taaSecretKey"]; ok {
		t.Error("register payload must not carry taaSecretKey")
	}
	if got["dockerId"] != "taa-teellm" {
		t.Errorf("dockerId = %v", got["dockerId"])
	}
	if got["verifiedPass"] != true {
		t.Errorf("verifiedPass = %v", got["verifiedPass"])
	}
	decoded, err := base64.StdEncoding.DecodeString(got["attestation"].(string))
	if err != nil || string(decoded) != string([]byte{0x01, 0x02, 0x03}) {
		t.Errorf("attestation = %q (decoded %v)", got["attestation"], err)
	}
	var values map[string]string
	if err := json.Unmarshal([]byte(got["attestationValues"].(string)), &values); err != nil {
		t.Fatalf("attestationValues is not a JSON object string: %v", err)
	}
	if values["chipId"] != "CHIP" || values["userdata"] != "aa" {
		t.Errorf("attestationValues = %v", values)
	}
}

func TestHeartbeatPayload(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/llm/heartbeat" {
			t.Errorf("path = %q, want /v1/llm/heartbeat", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = w.Write([]byte(`{"msg":"success","result":{},"error":0}`))
	}))
	defer server.Close()

	agent := newTestAgent(t, server.URL)
	if err := agent.sendHeartbeat(context.Background()); err != nil {
		t.Fatalf("sendHeartbeat failed: %v", err)
	}
	if got["dockerId"] != "taa-teellm" {
		t.Errorf("dockerId = %v", got["dockerId"])
	}
	if _, ok := got["timestamp"].(string); !ok {
		t.Errorf("timestamp must be a string, got %T", got["timestamp"])
	}
}

func TestTaaLogPayloadShape(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/llm/taaLog" {
			t.Errorf("path = %q, want /v1/llm/taaLog", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = w.Write([]byte(`{"msg":"success","result":{"received":true},"error":0}`))
	}))
	defer server.Close()

	agent := newTestAgent(t, server.URL)
	agent.logs.Add(LevelInfo, "teellm", "ollama ready")
	agent.flushLogs(context.Background())

	if got["requestId"] != "system" {
		t.Errorf("requestId = %v, want system", got["requestId"])
	}
	if got["dockerId"] != "taa-teellm" {
		t.Errorf("dockerId = %v", got["dockerId"])
	}
	entries, ok := got["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("entries = %v", got["entries"])
	}
	first := entries[0].(map[string]any)
	if first["seq"].(float64) != 1 {
		t.Errorf("first seq = %v, want 1", first["seq"])
	}
	if !strings.Contains(first["message"].(string), "[INFO] [teellm] ollama ready") {
		t.Errorf("message = %v", first["message"])
	}
}

func TestFlushLogsKeepsBatchOnFailure(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	agent := newTestAgent(t, server.URL)
	for i := 0; i < 3; i++ {
		agent.logs.Add(LevelInfo, "teellm", "line")
	}
	agent.flushLogs(context.Background())

	if got := agent.pendingCount(); got != 3 {
		t.Fatalf("pending = %d after a failed flush, want 3", got)
	}

	// A second attempt must re-send the same seqs from the head.
	agent.flushLogs(context.Background())
	agent.mu.Lock()
	first := agent.pending[0]
	agent.mu.Unlock()
	if first.Seq != 1 {
		t.Fatalf("pending head seq = %d, want 1", first.Seq)
	}
	if calls != 2 {
		t.Fatalf("server saw %d calls, want 2", calls)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd /home/hjy/taa/teellm && go test ./platformagent/ -count=1`

Expected: 编译失败 —— `undefined: New`、`agent.registerOnce undefined`。

- [ ] **Step 3: 实现 `attestation.go`**

```go
package platformagent

import "github.com/CipherSlinger/teellm"

// SnapshotFunc supplies the attestation material a registration reports.
//
// It is a function rather than a *teetls.Config so this package never depends
// on the TLS layer, and so tests can answer without hardware.
type SnapshotFunc func(ctx context.Context) (*teellm.AttestationSnapshot, error)
```

需要的 import 补全为：

```go
package platformagent

import (
	"context"

	"github.com/CipherSlinger/teellm"
)

type SnapshotFunc func(ctx context.Context) (*teellm.AttestationSnapshot, error)
```

- [ ] **Step 4: 实现 `register.go`**

```go
package platformagent

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"
)

const (
	// RegisterEndpoint receives the plaintext registration payload.
	RegisterEndpoint = "/v1/llm/register"
	// HeartbeatEndpoint receives the plaintext liveness ping.
	HeartbeatEndpoint = "/v1/llm/heartbeat"
	// TaaLogEndpoint receives batched run logs.
	TaaLogEndpoint = "/v1/llm/taaLog"
)

// registerRequest mirrors taa/internal/platform.registerRequest field for
// field, minus taaSecretKey: that field exists so TAA can hand back a wrapped
// SM2 private scalar, and the LLM has no such key to return.
type registerRequest struct {
	DockerID          string `json:"dockerId"`
	AuthInfo          any    `json:"authInfo"`
	TaaPublicKey      string `json:"taaPublicKey"`
	AttestationValues string `json:"attestationValues"`
	Timestamp         string `json:"timestamp"`
	VerifiedPass      bool   `json:"verifiedPass"`
	Attestation       string `json:"attestation"`
}

// registerOnce builds a current payload and sends it. The payload is rebuilt on
// every attempt so a retry reports the certificate in force at that moment.
func (a *Agent) registerOnce(ctx context.Context) error {
	snapshot, err := a.cfg.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("build attestation snapshot: %w", err)
	}

	payload := registerRequest{
		DockerID:          a.cfg.DockerID,
		AuthInfo:          nil,
		TaaPublicKey:      snapshot.PublicKeyPEM,
		AttestationValues: snapshot.ValuesJSON(),
		Timestamp:         fmt.Sprintf("%d", time.Now().Unix()),
		VerifiedPass:      snapshot.VerifiedPass,
		Attestation:       base64.StdEncoding.EncodeToString(snapshot.Report),
	}
	return a.postJSON(ctx, RegisterEndpoint, payload)
}
```

- [ ] **Step 5: 实现 `heartbeat.go`**

```go
package platformagent

import (
	"context"
	"fmt"
	"time"
)

// heartbeatRequest is liveness only: no health, model or measurement data.
type heartbeatRequest struct {
	DockerID  string `json:"dockerId"`
	Timestamp string `json:"timestamp"`
}

func (a *Agent) sendHeartbeat(ctx context.Context) error {
	return a.postJSON(ctx, HeartbeatEndpoint, heartbeatRequest{
		DockerID:  a.cfg.DockerID,
		Timestamp: fmt.Sprintf("%d", time.Now().Unix()),
	})
}
```

- [ ] **Step 6: 实现 `reporter.go` 的发送原语（循环下一步再补）**

```go
package platformagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

// taaLogEntry is one run-log record in the shape TAA reports.
type taaLogEntry struct {
	Seq     uint64 `json:"seq"`
	Message string `json:"message"`
}

// taaLogRequest mirrors taa/internal/controller.taaLogRequest. requestId is
// always "system" and taskId stays empty: the LLM has no task concept, which is
// exactly the shape TAA reports while idle.
type taaLogRequest struct {
	DockerID  string        `json:"dockerId"`
	RequestID string        `json:"requestId"`
	TaskID    string        `json:"taskId,omitempty"`
	SeqStart  uint64        `json:"seqStart"`
	Entries   []taaLogEntry `json:"entries"`
}

// Agent owns the three outbound reporting channels.
type Agent struct {
	cfg    Config
	logs   *LogBuffer
	client *http.Client

	mu      sync.Mutex
	pending []taaLogEntry
	failing map[string]bool
}

// New builds an Agent. A Config with an empty PlatformAddr yields (nil, nil):
// reporting is then disabled and the caller may still use its own LogBuffer.
func New(cfg Config) (*Agent, error) {
	cfg = cfg.withDefaults()
	if strings.TrimSpace(cfg.PlatformAddr) == "" {
		return nil, nil
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Snapshot == nil {
		return nil, fmt.Errorf("platformagent: snapshot source is required")
	}
	if cfg.Logs == nil {
		cfg.Logs = NewLogBuffer(cfg.LogBufferSize)
	}
	return &Agent{
		cfg:     cfg,
		logs:    cfg.Logs,
		client:  cfg.HTTPClient,
		failing: make(map[string]bool),
	}, nil
}

// Logs exposes the shared buffer so the service can instrument its own paths.
func (a *Agent) Logs() *LogBuffer {
	if a == nil {
		return nil
	}
	return a.logs
}

// postJSON sends one plaintext JSON payload. There is no envelope in either
// direction on this channel; the channel's integrity is the deployment's
// problem, not this function's.
func (a *Agent) postJSON(ctx context.Context, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s payload: %w", path, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.PlatformAddr+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create %s request: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s returned status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// reportFailure writes a reporting failure to stderr and, on the transition
// from healthy to failing, also into the platform log buffer. Repeats stay out
// of the buffer so an outage cannot crowd out real service logs.
func (a *Agent) reportFailure(channel string, err error) {
	log.Printf("[WARN] [platform] %s reporting failed: %v", channel, err)

	a.mu.Lock()
	wasFailing := a.failing[channel]
	a.failing[channel] = true
	a.mu.Unlock()

	if !wasFailing {
		a.logs.Add(LevelWarn, "platform", "%s reporting failed: %v", channel, err)
	}
}

// reportSuccess records the recovery transition, so the platform sees both ends
// of an outage.
func (a *Agent) reportSuccess(channel string) {
	a.mu.Lock()
	wasFailing := a.failing[channel]
	delete(a.failing, channel)
	a.mu.Unlock()

	if wasFailing {
		a.logs.Add(LevelInfo, "platform", "%s reporting recovered", channel)
	}
}

// pendingCount reports the size of the unsent log queue.
func (a *Agent) pendingCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}

// flushLogs moves the ring into the pending queue and pushes it in batches.
// A failed batch stays at the head of the queue, so ordering across retries is
// preserved and the platform never sees a seq go backwards.
func (a *Agent) flushLogs(ctx context.Context) {
	a.mu.Lock()
	for _, entry := range a.logs.Drain() {
		a.pending = append(a.pending, taaLogEntry{Seq: entry.Seq, Message: entry.FormatMessage()})
	}
	// Cap the queue as well as the ring: with the platform down for a long time
	// the ring alone would not bound what is waiting to be sent.
	if over := len(a.pending) - a.cfg.LogBufferSize; over > 0 {
		a.pending = append([]taaLogEntry(nil), a.pending[over:]...)
	}
	a.mu.Unlock()

	for {
		a.mu.Lock()
		if len(a.pending) == 0 {
			a.mu.Unlock()
			return
		}
		size := len(a.pending)
		if size > DefaultMaxLogBatchSize {
			size = DefaultMaxLogBatchSize
		}
		batch := append([]taaLogEntry(nil), a.pending[:size]...)
		a.mu.Unlock()

		err := a.postJSON(ctx, TaaLogEndpoint, taaLogRequest{
			DockerID:  a.cfg.DockerID,
			RequestID: "system",
			SeqStart:  batch[0].Seq,
			Entries:   batch,
		})
		if err != nil {
			a.reportFailure("taaLog", err)
			return
		}
		a.reportSuccess("taaLog")

		a.mu.Lock()
		if len(a.pending) >= size {
			a.pending = append([]taaLogEntry(nil), a.pending[size:]...)
		}
		a.mu.Unlock()
	}
}
```

- [ ] **Step 7: 运行测试确认通过**

Run: `cd /home/hjy/taa/teellm && go test ./platformagent/ -count=1 -v`

Expected: PASS，9 条测试。

- [ ] **Step 8: 提交**

```bash
cd /home/hjy/taa && git add teellm/platformagent/
git commit -m "feat(platformagent): add plaintext register, heartbeat and taaLog payloads"
```

---

## Task 5: 上报器的注册重试、心跳与日志循环

**Files:**
- Modify: `teellm/platformagent/reporter.go`
- Modify: `teellm/platformagent/reporter_test.go`

- [ ] **Step 1: 写失败的生命周期测试**

追加到 `teellm/platformagent/reporter_test.go`：

```go
func TestStartRegistersThenHeartbeatsAndFlushesLogs(t *testing.T) {
	var (
		mu       sync.Mutex
		register int
		beat     int
		logs     int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		switch r.URL.Path {
		case "/v1/llm/register":
			register++
		case "/v1/llm/heartbeat":
			beat++
		case "/v1/llm/taaLog":
			logs++
		}
		mu.Unlock()
		_, _ = w.Write([]byte(`{"msg":"success","result":{},"error":0}`))
	}))
	defer server.Close()

	agent, err := New(Config{
		PlatformAddr:      server.URL,
		DockerID:          "taa-teellm",
		HeartbeatInterval: 20 * time.Millisecond,
		LogFlushInterval:  20 * time.Millisecond,
		Snapshot: func(context.Context) (*teellm.AttestationSnapshot, error) {
			return fakeSnapshot(), nil
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	agent.Start(ctx)
	defer func() {
		cancel()
		agent.Stop()
	}()

	agent.Logs().Add(LevelInfo, "teellm", "started")
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if register < 1 {
		t.Errorf("register calls = %d, want at least 1", register)
	}
	if beat < 1 {
		t.Errorf("heartbeat calls = %d, want at least 1", beat)
	}
	if logs < 1 {
		t.Errorf("taaLog calls = %d, want at least 1", logs)
	}
}

func TestStartRetriesRegistrationUntilItSucceeds(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/llm/register" {
			if atomic.AddInt32(&attempts, 1) < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		_, _ = w.Write([]byte(`{"msg":"success","result":{},"error":0}`))
	}))
	defer server.Close()

	agent, err := New(Config{
		PlatformAddr:      server.URL,
		DockerID:          "taa-teellm",
		HeartbeatInterval: 50 * time.Millisecond,
		LogFlushInterval:  50 * time.Millisecond,
		Snapshot: func(context.Context) (*teellm.AttestationSnapshot, error) {
			return fakeSnapshot(), nil
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	agent.Start(ctx)
	defer func() {
		cancel()
		agent.Stop()
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&attempts) >= 3 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("register attempts = %d, want at least 3", atomic.LoadInt32(&attempts))
}

func TestStopDoesNotBlockWhenPlatformIsDown(t *testing.T) {
	agent, err := New(Config{
		PlatformAddr:      "http://127.0.0.1:1",
		DockerID:          "taa-teellm",
		HeartbeatInterval: 20 * time.Millisecond,
		LogFlushInterval:  20 * time.Millisecond,
		Snapshot: func(context.Context) (*teellm.AttestationSnapshot, error) {
			return fakeSnapshot(), nil
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	agent.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		cancel()
		agent.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop blocked while the platform was unreachable")
	}
}
```

需要在测试文件 import 中补 `"sync"` 与 `"sync/atomic"`。

- [ ] **Step 2: 运行测试确认失败**

Run: `cd /home/hjy/taa/teellm && go test ./platformagent/ -run 'TestStart|TestStop' -count=1`

Expected: 编译失败 —— `agent.Start undefined`、`agent.Stop undefined`。

- [ ] **Step 3: 在 `reporter.go` 里补循环与生命周期**

给 `Agent` 结构体追加字段：

```go
	// registered is closed once the first registration succeeds; the heartbeat
	// loop waits on it so it never reports liveness for an instance the platform
	// does not know.
	registered chan struct{}
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	startOnce  sync.Once
	stopOnce   sync.Once
```

`New` 的返回值追加 `registered: make(chan struct{})`。

追加以下方法：

```go
// Start launches the registration, heartbeat and log-flush loops. It is safe to
// call once; a disabled agent (nil) is a no-op.
func (a *Agent) Start(ctx context.Context) {
	if a == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	a.startOnce.Do(func() {
		runCtx, cancel := context.WithCancel(ctx)
		a.cancel = cancel
		a.wg.Add(3)
		go a.registerLoop(runCtx)
		go a.heartbeatLoop(runCtx)
		go a.logLoop(runCtx)
	})
}

// Stop cancels the loops, waits for them, and makes one last best-effort flush
// so records produced during shutdown still reach the platform.
func (a *Agent) Stop() {
	if a == nil {
		return
	}
	a.stopOnce.Do(func() {
		if a.cancel != nil {
			a.cancel()
		}
		a.wg.Wait()

		flushCtx, cancel := context.WithTimeout(context.Background(), DefaultRequestTimeout)
		defer cancel()
		a.flushLogs(flushCtx)
	})
}

// registerLoop registers once, retrying inside a bounded window, and then
// refreshes periodically so the platform keeps a report bound to the
// certificate this process is currently presenting.
func (a *Agent) registerLoop(ctx context.Context) {
	defer a.wg.Done()

	deadline := time.Now().Add(a.cfg.RegisterRetryWindow)
	delay := registerRetryInitialDelay
	for {
		if err := a.registerOnce(ctx); err == nil {
			a.logs.Add(LevelInfo, "platform", "registered with %s as %s", a.cfg.PlatformAddr, a.cfg.DockerID)
			close(a.registered)
			break
		} else {
			a.reportFailure("register", err)
		}

		// Give up when the next sleep would land past the window, so the loop
		// cannot sleep past its own deadline.
		if time.Now().Add(delay).After(deadline) {
			a.logs.Add(LevelError, "platform", "register retry window of %s exhausted", a.cfg.RegisterRetryWindow)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > registerRetryMaxDelay {
			delay = registerRetryMaxDelay
		}
	}

	ticker := time.NewTicker(a.cfg.RegisterRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.registerOnce(ctx); err != nil {
				a.reportFailure("register", err)
			} else {
				a.reportSuccess("register")
			}
		}
	}
}

// heartbeatLoop starts only after registration, so a heartbeat always refers to
// an instance the platform already knows.
func (a *Agent) heartbeatLoop(ctx context.Context) {
	defer a.wg.Done()

	select {
	case <-ctx.Done():
		return
	case <-a.registered:
	}

	if err := a.sendHeartbeat(ctx); err != nil {
		a.reportFailure("heartbeat", err)
	} else {
		a.reportSuccess("heartbeat")
	}

	ticker := time.NewTicker(a.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.sendHeartbeat(ctx); err != nil {
				a.reportFailure("heartbeat", err)
			} else {
				a.reportSuccess("heartbeat")
			}
		}
	}
}

// logLoop pushes the ring on a fixed period. It is independent of registration:
// logs are worth keeping even while the registration is still being retried.
func (a *Agent) logLoop(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(a.cfg.LogFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.flushLogs(ctx)
		}
	}
}
```

`reporter.go` 的 import 补 `"time"`。

- [ ] **Step 4: 运行测试确认通过**

Run: `cd /home/hjy/taa/teellm && go test ./platformagent/ -count=1 -race -v`

Expected: PASS。`-race` 是本任务的关键：三条循环共享 `pending` 与 `failing`。

- [ ] **Step 5: 提交**

```bash
cd /home/hjy/taa && git add teellm/platformagent/
git commit -m "feat(platformagent): run registration, heartbeat and log loops"
```

---

## Task 6: 在 `teellm-service` 中接线

**Files:**
- Modify: `teellm/cmd/teellm-service/main.go`
- Modify: `teellm/configs/teellm-production.json`
- Modify: `teellm/configs/teellm-docker.json`

- [ ] **Step 1: 配置结构体加两段**

`main.go` 的 `ServerConfigSection` 改为：

```go
// ServerConfigSection defines the HTTP server runtime configuration.
type ServerConfigSection struct {
	Addr                string `json:"addr"`
	AttestationAddr     string `json:"attestationAddr"`
	ReadTimeoutSeconds  int    `json:"readTimeoutSeconds"`
	WriteTimeoutSeconds int    `json:"writeTimeoutSeconds"`
	MaxResponseBytes    int    `json:"maxResponseBytes"`
}
```

新增：

```go
// PlatformConfigSection defines the outbound platform reporting configuration.
type PlatformConfigSection struct {
	Addr                   string `json:"addr"`
	DockerID               string `json:"dockerId"`
	HeartbeatSeconds       int    `json:"heartbeatSeconds"`
	LogFlushSeconds        int    `json:"logFlushSeconds"`
	RegisterRefreshSeconds int    `json:"registerRefreshSeconds"`
}
```

`ServiceConfigFile` 增加字段：

```go
type ServiceConfigFile struct {
	Server      ServerConfigSection      `json:"server"`
	Backend     BackendConfigSection     `json:"backend"`
	Attestation AttestationConfigSection `json:"attestation"`
	Platform    PlatformConfigSection    `json:"platform"`
}
```

- [ ] **Step 2: 默认值补两段**

`loadServiceConfig` 的 `defaultCfg` 里，`Server` 增加：

```go
			AttestationAddr:     ":8444",
```

并在 `Attestation` 之后追加：

```go
		Platform: PlatformConfigSection{
			DockerID:               "taa-teellm",
			HeartbeatSeconds:       platformagent.DefaultHeartbeatSeconds,
			LogFlushSeconds:        platformagent.DefaultLogFlushSeconds,
			RegisterRefreshSeconds: platformagent.DefaultRegisterRefreshSeconds,
		},
```

- [ ] **Step 3: 构造并启动 Agent**

在 `teeTLSConfig` 定义之后、`server, err := teellm.NewServer(...)` 之前插入：

```go
	// The same buffer is shared by the service's own instrumentation and the
	// reporter, so instrumented lines reach both stderr and the platform.
	logs := platformagent.NewLogBuffer(platformagent.DefaultLogBufferSize)

	agent, err := platformagent.New(platformagent.Config{
		PlatformAddr:            cfg.Platform.Addr,
		DockerID:                cfg.Platform.DockerID,
		HeartbeatInterval:       time.Duration(cfg.Platform.HeartbeatSeconds) * time.Second,
		LogFlushInterval:        time.Duration(cfg.Platform.LogFlushSeconds) * time.Second,
		RegisterRefreshInterval: time.Duration(cfg.Platform.RegisterRefreshSeconds) * time.Second,
		Logs:                    logs,
		Snapshot: func(ctx context.Context) (*teellm.AttestationSnapshot, error) {
			return teellm.BuildAttestationSnapshot(ctx, teeTLSConfig)
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize platform agent: %v", err)
	}
```

`NewServer` 调用改为：

```go
	server, err := teellm.NewServer(teellm.ServerConfig{
		Addr:            cfg.Server.Addr,
		AttestationAddr: cfg.Server.AttestationAddr,
		TEETLS:          teeTLSConfig,
		Backend:         backend,
	})
```

`server.Start()` 的 goroutine 之前启动 agent，并加上退出时的关闭：

```go
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()

	if agent != nil {
		agent.Start(runCtx)
		defer agent.Stop()
		logs.Add(platformagent.LevelInfo, "teellm", "platform reporting enabled to %s", cfg.Platform.Addr)
	} else {
		logs.Add(platformagent.LevelInfo, "teellm", "platform reporting disabled (empty platform.addr)")
	}
```

把启动与监听日志改成走缓冲：

```go
	go func() {
		logs.Add(platformagent.LevelInfo, "teellm", "teellm-service listening on %s via RFC 8998 TEE-TLS 1.3", server.Addr())
		if addr := server.AttestationAddr(); addr != "" {
			logs.Add(platformagent.LevelInfo, "teellm", "plaintext attestation listener on %s", addr)
		}
		if err := server.Start(); err != nil {
			serverErrCh <- err
		}
	}()
```

信号分支里补一条：

```go
	case sig := <-sigCh:
		logs.Add(platformagent.LevelInfo, "teellm", "received signal %v, shutting down teellm-service", sig)
		_ = server.Close()
		log.Printf("teellm-service stopped cleanly")
```

- [ ] **Step 4: 在关键路径加埋点**

在证据提供者选择处，把两条 `log.Printf` 换成 `logs.Add`（`logs` 需要在使用前创建，因此要把 `logs := platformagent.NewLogBuffer(...)` 上移到 `log.Printf("starting teellm-service daemon ...")` 之前）：

```go
	if cfg.Attestation.Mock {
		logs.Add(platformagent.LevelWarn, "teellm", "using mock attestation provider (flag or config mock enabled)")
		evidenceProvider = teetls.NewMockEvidenceProvider()
	} else if _, err := os.Stat("/dev/csv-guest"); err == nil {
		logs.Add(platformagent.LevelInfo, "teellm", "detected /dev/csv-guest; using Hygon hardware evidence provider")
		evidenceProvider = teetls.NewHygonHardwareProvider("", cfg.Attestation.HRKCertPath, cfg.Attestation.HSKCekCertPath)
	} else {
		logs.Add(platformagent.LevelWarn, "teellm", "/dev/csv-guest not found; falling back to mock attestation provider")
		evidenceProvider = teetls.NewMockEvidenceProvider()
	}
```

后端初始化完成后加一条：

```go
	logs.Add(platformagent.LevelInfo, "teellm", "ollama backend ready: endpoint=%s model=%s", cfg.Backend.Endpoint, cfg.Backend.DefaultModel)
```

- [ ] **Step 5: 编译**

Run: `cd /home/hjy/taa/teellm && go build -o bin/teellm-service ./cmd/teellm-service`

Expected: 无输出，退出码 0。若报 `declared and not used`，检查 `logs` 是否在使用前声明。

- [ ] **Step 6: 更新配置模板**

`teellm/configs/teellm-production.json` 改为：

```json
{
  "server": {
    "addr": ":8443",
    "attestationAddr": ":8444",
    "readTimeoutSeconds": 60,
    "writeTimeoutSeconds": 60,
    "maxResponseBytes": 1048576
  },
  "backend": {
    "type": "ollama",
    "endpoint": "http://127.0.0.1:11434",
    "defaultModel": "qwen2.5-coder:7b",
    "modelCatalogPath": "./configs/models.json",
    "timeoutSeconds": 60
  },
  "attestation": {
    "mode": "strict",
    "mock": false,
    "hrkCertPath": "/opt/teellm/certs/hrk.cert",
    "hskCekCertPath": "/opt/teellm/certs/hsk_cek.cert"
  },
  "platform": {
    "addr": "",
    "dockerId": "taa-teellm",
    "heartbeatSeconds": 30,
    "logFlushSeconds": 5,
    "registerRefreshSeconds": 21600
  }
}
```

`teellm/configs/teellm-docker.json` 同样追加 `attestationAddr` 与 `platform` 段，其余保留原值（`readTimeoutSeconds`/`writeTimeoutSeconds` 为 120、`timeoutSeconds` 为 100、`attestation.mode` 为 `permissive`）。

- [ ] **Step 7: 验证配置能被解析且不启用上报**

Run: `cd /home/hjy/taa/teellm && ./bin/teellm-service -config configs/teellm-docker.json -mock-attestation -addr 127.0.0.1:18443 2>&1 | head -5`

Expected: 输出包含 `teellm-service listening on 127.0.0.1:18443` 与 `plaintext attestation listener on :8444`，且**没有**任何对平台的请求。按 Ctrl-C 结束。

- [ ] **Step 8: 提交**

```bash
cd /home/hjy/taa && git add teellm/cmd/teellm-service/main.go teellm/configs/
git commit -m "feat(teellm-service): wire the platform agent and attestation listener"
```

---

## Task 7: 镜像与部署脚本

**Files:**
- Modify: `build-teellm-image.sh:240`
- Modify: `deploy-llm.sh:239,891-922,1593,1604,2095`

- [ ] **Step 1: 镜像暴露新端口**

`build-teellm-image.sh` 中：

```bash
  -c 'EXPOSE 8443 8444' \
```

- [ ] **Step 2: `deploy-llm.sh` 增加两个环境变量**

在 `TEELLM_PORT="${TEELLM_PORT:-8443}"` 之后追加：

```bash
# Plaintext attestation listener. It is intentionally not part of any Service or
# Ingress: it has no authentication and only serves the CSV report.
TEELLM_ATTESTATION_PORT="${TEELLM_ATTESTATION_PORT:-8444}"
# Platform the instance registers with, heartbeats to and pushes logs to. Empty
# disables all outbound reporting while leaving the attestation port mounted.
TEELLM_PLATFORM_ADDR="${TEELLM_PLATFORM_ADDR:-http://172.16.10.181:18081}"
```

- [ ] **Step 3: 扩展 `prepare_config`**

```bash
prepare_config() {
  local template="$1"
  local output_file="$2"
  local model="$3"
  local port="$4"
  local hrk_path="${5:-}"
  local hsk_path="${6:-}"
  local attestation_port="${7:-}"
  local platform_addr="${8:-}"

  require_file "teellm config template" "$template"
  require_command python3

  python3 - "$template" "$output_file" "$model" "$port" "$hrk_path" "$hsk_path" "$attestation_port" "$platform_addr" <<'PY'
import json, sys

template_path, output_path, model, port, hrk_path, hsk_path, attestation_port, platform_addr = sys.argv[1:9]
with open(template_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

if model:
    cfg.setdefault("backend", {})["defaultModel"] = model
if port:
    cfg.setdefault("server", {})["addr"] = f":{port}"
if attestation_port:
    cfg.setdefault("server", {})["attestationAddr"] = f":{attestation_port}"
if hrk_path:
    cfg.setdefault("attestation", {})["hrkCertPath"] = hrk_path
if hsk_path:
    cfg.setdefault("attestation", {})["hskCekCertPath"] = hsk_path
if platform_addr:
    cfg.setdefault("platform", {})["addr"] = platform_addr

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
}
```

调用点改为：

```bash
  prepare_config "$cfg_template" "$tmp_cfg" "$OLLAMA_MODEL" "$TEELLM_PORT" "$CON_WORKDIR/certs/hrk.cert" "$CON_WORKDIR/certs/hsk_cek.cert" "$TEELLM_ATTESTATION_PORT" "$TEELLM_PLATFORM_ADDR"
```

- [ ] **Step 4: 使用说明里登记两个变量**

`--port` 说明之后追加：

```bash
  --attestation-port <port> (or --attestation-port=<port>)
      Specify the plaintext attestation listening port (default: $TEELLM_ATTESTATION_PORT).
```

`Environment overrides:` 段落里追加：

```bash
  TEELLM_ATTESTATION_PORT=${TEELLM_ATTESTATION_PORT}
      Plaintext attestation port. Not published outside the Pod network.
  TEELLM_PLATFORM_ADDR=${TEELLM_PLATFORM_ADDR}
      Platform this instance registers with. Empty disables reporting.
```

- [ ] **Step 5: 语法检查**

Run: `bash -n /home/hjy/taa/deploy-llm.sh && bash -n /home/hjy/taa/build-teellm-image.sh`

Expected: 无输出。

- [ ] **Step 6: 验证 python 注入片段**

Run:
```bash
cd /home/hjy/taa && python3 - teellm/configs/teellm-production.json /tmp/cfg-probe.json qwen 8443 /a/hrk /a/hsk 8444 http://1.2.3.4:18081 <<'PY'
import json, sys
template_path, output_path, model, port, hrk_path, hsk_path, attestation_port, platform_addr = sys.argv[1:9]
with open(template_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)
if model: cfg.setdefault("backend", {})["defaultModel"] = model
if port: cfg.setdefault("server", {})["addr"] = f":{port}"
if attestation_port: cfg.setdefault("server", {})["attestationAddr"] = f":{attestation_port}"
if hrk_path: cfg.setdefault("attestation", {})["hrkCertPath"] = hrk_path
if hsk_path: cfg.setdefault("attestation", {})["hskCekCertPath"] = hsk_path
if platform_addr: cfg.setdefault("platform", {})["addr"] = platform_addr
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False); f.write("\n")
PY
python3 -c "import json;print(json.load(open('/tmp/cfg-probe.json'))['server']['attestationAddr'], json.load(open('/tmp/cfg-probe.json'))['platform']['addr'])"
```

Expected: `:8444 http://1.2.3.4:18081`

- [ ] **Step 7: 提交**

```bash
cd /home/hjy/taa && git add build-teellm-image.sh deploy-llm.sh
git commit -m "feat(deploy): publish the attestation port and inject the platform section"
```

---

## Task 8: platform-mock 接受明文 `/v1/llm/*`

**Files:**
- Create: `tools/platform-mock/internal/llm_state.go`
- Create: `tools/platform-mock/internal/handlers_llm.go`
- Modify: `tools/platform-mock/internal/server.go`
- Modify: `tools/platform-mock/internal/store.go`

- [ ] **Step 1: 写失败的处理测试**

创建 `tools/platform-mock/internal/handlers_llm_test.go`：

```go
package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLLMRegisterAcceptsPlaintext(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	handler := llmRegisterHandler(store)

	body := `{"dockerId":"taa-teellm","authInfo":null,"taaPublicKey":"-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n","attestationValues":"{\"userdata\":\"aa\",\"mnonce\":\"bb\",\"digest\":\"cc\",\"chipId\":\"CHIP\"}","timestamp":"1730000000","verifiedPass":true,"attestation":"AQID"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/llm/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	state := store.get()
	if !state.Register.Received || state.Register.DockerID != "taa-teellm" {
		t.Fatalf("register state = %+v", state.Register)
	}
	if !state.Register.VerifiedPass {
		t.Error("verifiedPass was not recorded")
	}
	if state.Register.AttestationSize != 3 {
		t.Errorf("attestationSize = %d, want 3", state.Register.AttestationSize)
	}
}

func TestLLMHeartbeatRecordsLiveness(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	handler := llmHeartbeatHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/v1/llm/heartbeat", strings.NewReader(`{"dockerId":"taa-teellm","timestamp":"1730000030"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	state := store.get()
	if state.Heartbeat.DockerID != "taa-teellm" || state.Heartbeat.Count != 1 {
		t.Fatalf("heartbeat state = %+v", state.Heartbeat)
	}
}

func TestLLMTaaLogAcceptsPlaintextEntries(t *testing.T) {
	logStore := newTaaLogStoreAt(t.TempDir()+"/llm-taaLog-state.json", 2000)
	handler := llmTaaLogHandler(logStore)

	body := `{"dockerId":"taa-teellm","requestId":"system","seqStart":1,"entries":[{"seq":1,"message":"[2026-11-02 10:00:00] [INFO] [teellm] ready"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/llm/taaLog", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := logStore.get().TotalCount; got != 1 {
		t.Fatalf("totalCount = %d, want 1", got)
	}
}

func TestLLMRegisterRejectsMissingDockerID(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	handler := llmRegisterHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/v1/llm/register", strings.NewReader(`{"attestation":"AQID"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd /home/hjy/taa && go test ./tools/platform-mock/internal/ -run 'TestLLM' -count=1`

Expected: 编译失败 —— `undefined: newLLMStateStore`、`undefined: llmRegisterHandler`。

- [ ] **Step 3: 实现 `llm_state.go`**

```go
package mock

import (
	"log"
	"sync"
)

// llmRegisterState mirrors the plaintext registration an LLM instance sends.
// It is deliberately separate from registerState: TAA and LLM instances report
// different identities and must not overwrite each other's panel entries.
type llmRegisterState struct {
	Received          bool   `json:"received"`
	ReceivedAt        string `json:"receivedAt"`
	DockerID          string `json:"dockerId"`
	TaaPublicKey      string `json:"taaPublicKey"`
	AttestationValues string `json:"attestationValues"`
	Timestamp         string `json:"timestamp"`
	VerifiedPass      bool   `json:"verifiedPass"`
	AttestationSize   int    `json:"attestationSize"`
	AttestationBase64 string `json:"attestationBase64"`
	Certificate       string `json:"certificate"`
}

// llmHeartbeatState records the most recent liveness ping.
type llmHeartbeatState struct {
	DockerID   string `json:"dockerId"`
	Timestamp  string `json:"timestamp"`
	ReceivedAt string `json:"receivedAt"`
	Count      uint64 `json:"count"`
}

// llmState is the persisted aggregate shown by the status endpoint.
type llmState struct {
	Register  llmRegisterState  `json:"register"`
	Heartbeat llmHeartbeatState `json:"heartbeat"`
}

type llmStateStore struct {
	mu    sync.RWMutex
	path  string
	state llmState
}

func newLLMStateStore(stateDir string) *llmStateStore {
	store := &llmStateStore{path: defaultStateFile(stateDir, "llm-state.json")}
	store.load()
	return store
}

func (s *llmStateStore) load() {
	var state llmState
	if err := loadJSONFile(s.path, &state); err != nil {
		log.Printf("load llm state failed: %v", err)
		return
	}
	s.mu.Lock()
	s.state = state
	s.mu.Unlock()
}

func (s *llmStateStore) get() llmState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *llmStateStore) setRegister(state llmRegisterState) {
	s.mu.Lock()
	s.state.Register = state
	snapshot := s.state
	s.mu.Unlock()
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

func (s *llmStateStore) recordHeartbeat(state llmHeartbeatState) {
	s.mu.Lock()
	s.state.Heartbeat = state
	snapshot := s.state
	s.mu.Unlock()
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

func (s *llmStateStore) reset() {
	s.mu.Lock()
	s.state = llmState{}
	s.mu.Unlock()
	if err := saveJSONFile(s.path, llmState{}); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}
```

需要在 `store.go` 里确认 `loadJSONFile`、`saveJSONFile` 存在；若只有 `saveJSONFile`，用 `os.ReadFile` + `json.Unmarshal` 自行实现 `load`：

```go
func (s *llmStateStore) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var state llmState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("load llm state failed: %v", err)
		return
	}
	s.mu.Lock()
	s.state = state
	s.mu.Unlock()
}
```

- [ ] **Step 4: 让 `taaLogStore` 支持自定义文件名**

在 `store.go` 里把构造函数拆成两层：

```go
func newTaaLogStore(stateDir string, capacity int) *taaLogStore {
	return newTaaLogStoreAt(defaultStateFile(stateDir, "taaLog-state.json"), capacity)
}

// newTaaLogStoreAt builds a store backed by an explicit file, so TAA and LLM
// logs can be kept apart while sharing one implementation.
func newTaaLogStoreAt(path string, capacity int) *taaLogStore {
	if capacity <= 0 {
		capacity = 2000
	}
	store := &taaLogStore{
		path:     path,
		capacity: capacity,
		seen:     make(map[string]struct{}),
	}
	store.load()
	return store
}
```

- [ ] **Step 5: 实现 `handlers_llm.go`**

```go
package mock

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// writeLLMResponse answers with the same {msg, result, error} envelope TAA
// routes use, so one decoder on the caller side handles both.
func writeLLMResponse(w http.ResponseWriter, status int, msg string, result any, errorCode int) {
	writeEnvelope(w, status, msg, result, errorCode)
}

// llmRegisterHandler accepts the plaintext registration an LLM instance sends.
// There is no envelope here on purpose: the LLM's proof of identity is the
// attestation report plus the certificate whose key it binds, and the mock
// records both verbatim so they can be compared by hand.
func llmRegisterHandler(store *llmStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeLLMResponse(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			writeLLMResponse(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		var req struct {
			DockerID          string `json:"dockerId"`
			TaaPublicKey      string `json:"taaPublicKey"`
			AttestationValues string `json:"attestationValues"`
			Timestamp         string `json:"timestamp"`
			VerifiedPass      bool   `json:"verifiedPass"`
			Attestation       string `json:"attestation"`
			Certificate       string `json:"certificate"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeLLMResponse(w, http.StatusBadRequest, "解析 application/json 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.DockerID) == "" {
			writeLLMResponse(w, http.StatusBadRequest, "缺少 dockerId", nil, http.StatusBadRequest)
			return
		}

		state := llmRegisterState{
			Received:          true,
			ReceivedAt:        time.Now().Format(time.RFC3339),
			DockerID:          req.DockerID,
			TaaPublicKey:      req.TaaPublicKey,
			AttestationValues: req.AttestationValues,
			Timestamp:         req.Timestamp,
			VerifiedPass:      req.VerifiedPass,
			AttestationBase64: req.Attestation,
			Certificate:       req.Certificate,
		}
		if req.Attestation != "" {
			attBytes, decodeErr := base64.StdEncoding.DecodeString(req.Attestation)
			if decodeErr != nil {
				writeLLMResponse(w, http.StatusBadRequest, "attestation Base64 解码失败: "+decodeErr.Error(), nil, http.StatusBadRequest)
				return
			}
			state.AttestationSize = len(attBytes)
		}

		store.setRegister(state)
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"received": true}, 0)
	}
}

// llmHeartbeatHandler records liveness only.
func llmHeartbeatHandler(store *llmStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeLLMResponse(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			DockerID  string `json:"dockerId"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeLLMResponse(w, http.StatusBadRequest, "解析 JSON 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.DockerID) == "" {
			writeLLMResponse(w, http.StatusBadRequest, "缺少 dockerId", nil, http.StatusBadRequest)
			return
		}

		previous := store.get().Heartbeat
		store.recordHeartbeat(llmHeartbeatState{
			DockerID:   req.DockerID,
			Timestamp:  req.Timestamp,
			ReceivedAt: time.Now().Format(time.RFC3339),
			Count:      previous.Count + 1,
		})
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"received": true}, 0)
	}
}

// llmTaaLogHandler accepts batched run logs in plaintext.
func llmTaaLogHandler(store *taaLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeLLMResponse(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		var req taaLogRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			writeLLMResponse(w, http.StatusBadRequest, "解析 JSON 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.DockerID) == "" {
			writeLLMResponse(w, http.StatusBadRequest, "缺少 dockerId", nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.RequestID) == "" {
			writeLLMResponse(w, http.StatusBadRequest, "缺少 requestId", nil, http.StatusBadRequest)
			return
		}
		if len(req.Entries) == 0 {
			writeLLMResponse(w, http.StatusBadRequest, "entries 不能为空", nil, http.StatusBadRequest)
			return
		}

		store.addEntries(req.DockerID, req.RequestID, req.TaskID, req.Entries)
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"received": true}, 0)
	}
}

func llmStatusHandler(state *llmStateStore, logs *taaLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		writeJSON(w, http.StatusOK, map[string]any{
			"register":  state.get().Register,
			"heartbeat": state.get().Heartbeat,
			"logs":      logs.get(),
		})
	}
}

func llmResetHandler(state *llmStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeLLMResponse(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}
		state.reset()
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"reset": true}, 0)
	}
}
```

- [ ] **Step 6: 挂路由**

在 `server.go` 的 `NewServer` 里，`taaLogStore := newTaaLogStore(cfg.StateDir, 2000)` 之后追加：

```go
	llmState := newLLMStateStore(cfg.StateDir)
	llmLogStore := newTaaLogStoreAt(defaultStateFile(cfg.StateDir, "llm-taaLog-state.json"), 2000)
```

在 `/v1/taa/taaLog` 路由之后追加：

```go
	mux.HandleFunc("/v1/llm/register", llmRegisterHandler(llmState))
	mux.HandleFunc("/v1/llm/heartbeat", llmHeartbeatHandler(llmState))
	mux.HandleFunc("/v1/llm/taaLog", llmTaaLogHandler(llmLogStore))
	mux.HandleFunc("/api/llm/status", llmStatusHandler(llmState, llmLogStore))
	mux.HandleFunc("/api/llm/reset", llmResetHandler(llmState))
```

- [ ] **Step 7: 运行测试确认通过**

Run: `cd /home/hjy/taa && go test ./tools/platform-mock/internal/ -count=1`

Expected: `ok`。

- [ ] **Step 8: 提交**

```bash
cd /home/hjy/taa && git add tools/platform-mock/internal/
git commit -m "feat(platform-mock): accept plaintext LLM register, heartbeat and logs"
```

---

## Task 9: 文档与全量验证

**Files:**
- Modify: `teellm/README.md`

- [ ] **Step 1: README 补充接口与配置**

在 `### Command Line Flags` 表之后追加：

```markdown
### HTTP Surface

| Listener | Path | Transport | Purpose |
|----------|------|-----------|---------|
| `:8443` | `POST /v1/llm/verify` | TEE-TLS 1.3 | Finding verification |
| `:8443` | `GET /v1/llm/healthz` | TEE-TLS 1.3 | Readiness |
| `:8444` | `POST /v1/llm/getAttestation` | **plaintext** | Platform fetches the CSV report and the certificate it is bound to |

`:8444` carries no authentication. Keep it inside the Pod network: it must not
appear in any Service, NodePort or Ingress.

### Platform Reporting

Set `platform.addr` to enable outbound plaintext JSON reporting to the control
platform. The instance registers once at startup (retrying with backoff for up
to 10 minutes), refreshes its registration every `registerRefreshSeconds`,
sends a liveness heartbeat every `heartbeatSeconds`, and pushes buffered logs
every `logFlushSeconds`. An empty `platform.addr` disables all three; the
attestation listener is controlled separately by `server.attestationAddr`.

```json
"platform": {
  "addr": "http://172.16.10.181:18081",
  "dockerId": "taa-teellm",
  "heartbeatSeconds": 30,
  "logFlushSeconds": 5,
  "registerRefreshSeconds": 21600
}
```
```

- [ ] **Step 2: 全量 Go 测试**

Run: `cd /home/hjy/taa && go test ./cmd/... ./internal/... ./pkg/... ./teellm/... ./tools/platform-mock/... -count=1`

Expected: 全 `ok`。`internal/codeaudit` 可能需要几分钟，可后台运行。

- [ ] **Step 3: vet 与格式**

Run: `cd /home/hjy/taa && gofmt -l teellm internal tools && go vet ./cmd/... ./internal/... ./pkg/...`

Expected: `gofmt -l` 无输出；`go vet` 无输出。

- [ ] **Step 4: 提交**

```bash
cd /home/hjy/taa && git add teellm/README.md
git commit -m "docs(teellm): document the /v1/llm surface and platform reporting"
```

---

## 自检

**1. Spec 覆盖**

| Spec 章节 | 对应任务 |
| --- | --- |
| §3.1 明文 `:8444` | Task 2 |
| §3.2 路径改名 | Task 1 |
| §5.0–5.4 报文 | Task 4（register/heartbeat/taaLog）、Task 2（getAttestation） |
| §6 上报器行为 | Task 5 |
| §7 显式埋点 | Task 6 Step 4 |
| §8 代码落点 | Task 2–8 |
| §8 配置段 | Task 6 |
| §10 验证方式 | Task 2、4、5、8、9 |

**2. 已知取舍**

- 平台地址默认值来自 §8 的配置示例（`http://172.16.10.181:18081`），由 `TEELLM_PLATFORM_ADDR` 覆盖。
- `tools/platform-mock` 只新增了 `/api/llm/status` 与 `/api/llm/reset` 两个只读状态端点；内嵌看板页面本身不在本计划范围内，端到端验证改用这两个端点（Task 9 Step 2 之后的 curl 检查）。
- `taaLog` 的 `taskId` 沿用 TAA 的 `omitempty`，因此报文里不出现该字段——与 TAA 空闲期报文一致。

**3. 类型一致性**

- `teellm.AttestationValues` / `AttestationSnapshot` 在 Task 2 定义，Task 4 的 `SnapshotFunc` 与 Task 6 的 `Snapshot` 闭包都使用同一类型。
- `platformagent.Config` 字段名在 Task 3 定义，Task 4/5 的 `New`、Task 6 的构造处保持一致。
- `newTaaLogStoreAt` 在 Task 8 Step 4 定义，Step 6 与测试都调用这一名字。
