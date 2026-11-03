# 审计逻辑下沉 TAA、teellm 收敛为纯推理服务 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把提示词、verdict 解析与 LLM 客户端从 `teellm/` 移到 TAA，teellm 只保留通用 `/v1/llm/generate` 推理服务。

**Architecture:** TAA 新增 `internal/llmclient`（TEE-TLS 传输、重试、熔断、`/v1/llm/generate`），`internal/codeaudit` 负责提示词与 parseDecision；teellm 服务端删除 `/v1/llm/verify` 与全部审计类型，提供 `{prompt, options} → {text}` 的通用接口。

**Tech Stack:** Go 1.22+、`teetls`（ShangMi TLS 1.3）、Ollama HTTP API、`httptest`。

**前置约束：**
- `teellm/` 是 git 子模块：所有 `teellm/` 内的改动先在子模块里提交，再在父仓库 `git add teellm` 提交一个 `chore(teellm): bump submodule ...`。
- 共享检出可能有他人未提交的改动，**只 add 本任务涉及的文件**。
- 提交信息用英文 Conventional Commits，不添加任何 AI 署名。

---

## Task 1: 新增 `internal/llmclient` 协议类型

**Files:**
- Create: `internal/llmclient/types.go`
- Test: `internal/llmclient/types_test.go`

- [ ] **Step 1: 写失败的测试**

`internal/llmclient/types_test.go`：

```go
package llmclient

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateRequestSerialization(t *testing.T) {
	req := GenerateRequest{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "verify-1",
		Model:           "qwen2.5-coder:3b",
		Prompt:          "hello",
		Options:         map[string]any{"temperature": 0},
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	for _, want := range []string{`"protocolVersion"`, `"requestId"`, `"model"`, `"prompt"`, `"options"`, `"temperature":0`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("payload missing %s: %s", want, raw)
		}
	}
}

func TestGenerateRequestOmitsEmptyModel(t *testing.T) {
	raw, err := json.Marshal(GenerateRequest{ProtocolVersion: CurrentProtocolVersion, RequestID: "r", Prompt: "p"})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(raw), `"model"`) {
		t.Fatalf("empty model must be omitted: %s", raw)
	}
}

func TestGenerateResponseDecode(t *testing.T) {
	var resp GenerateResponse
	body := `{"protocolVersion":"teellm-protocol/v1","requestId":"r","status":"SUCCESS","model":"m","text":"answer"}`
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Status != StatusSuccess || resp.Text != "answer" || resp.Model != "m" {
		t.Fatalf("decoded = %+v", resp)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd /home/hjy/taa && go test ./internal/llmclient/ -run 'TestGenerate' -count=1`
Expected: FAIL，`undefined: GenerateRequest`。

- [ ] **Step 3: 创建 `internal/llmclient/types.go`**

```go
// Package llmclient is the transport client for the remote LLM inference
// service. It knows prompts and generated text; it has no knowledge of code
// audit, findings or verdicts.
package llmclient

import (
	"errors"
	"time"
)

// CurrentProtocolVersion identifies the wire protocol spoken on /v1/llm/*.
const CurrentProtocolVersion = "teellm-protocol/v1"

// MaxResponsePayloadBytes bounds one response body (1MB).
const MaxResponsePayloadBytes = 1 << 20

// DefaultHealthCheckTimeout is the budget a health check gets when the caller
// sets no HealthCheckTimeout of its own.
//
// It is far longer than an ordinary request timeout because /v1/llm/healthz is
// not a ping: the service answers it only once the model is loaded, which on a
// cold service is seconds of disk and memory work. Budgeting it like an
// ordinary request yields a readiness gate a cold service can never pass - and
// retrying does not help, because cutting an attempt off cancels the load it
// was waiting on, so the next attempt starts the load again from nothing.
const DefaultHealthCheckTimeout = 120 * time.Second

// Status values returned by the inference service.
const (
	StatusSuccess            = "SUCCESS"
	StatusInvalidRequest     = "INVALID_REQUEST"
	StatusModelNotFound      = "MODEL_NOT_FOUND"
	StatusInternalError      = "INTERNAL_ERROR"
	StatusServiceUnavailable = "SERVICE_UNAVAILABLE"
)

var (
	// ErrPayloadTooLarge is returned when the response payload exceeds 1MB.
	ErrPayloadTooLarge = errors.New("response payload exceeds 1MB limit")
	// ErrInvalidStatus is returned when the server returns an unexpected non-success HTTP status.
	ErrInvalidStatus = errors.New("unexpected response status")
	// ErrCircuitOpen is returned while the circuit breaker rejects requests.
	ErrCircuitOpen = errors.New("circuit breaker is open")
	// ErrRetryable marks an error eligible for retry.
	ErrRetryable = errors.New("retryable error")
)

// GenerateRequest is one inference request: a prompt and optional sampling
// options, both opaque to this package.
type GenerateRequest struct {
	ProtocolVersion string         `json:"protocolVersion"`
	RequestID       string         `json:"requestId"`
	Model           string         `json:"model,omitempty"`
	Prompt          string         `json:"prompt"`
	Options         map[string]any `json:"options,omitempty"`
}

// GenerateResponse carries the model's raw text output.
type GenerateResponse struct {
	ProtocolVersion string `json:"protocolVersion"`
	RequestID       string `json:"requestId"`
	Status          string `json:"status"`
	ErrorMessage    string `json:"errorMessage,omitempty"`
	Model           string `json:"model,omitempty"`
	Text            string `json:"text,omitempty"`
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd /home/hjy/taa && go test ./internal/llmclient/ -count=1`
Expected: `ok  taa/internal/llmclient`。

- [ ] **Step 5: 提交**

```bash
cd /home/hjy/taa
git add internal/llmclient/types.go internal/llmclient/types_test.go
git commit -m "feat(llmclient): add the generic generate protocol types"
```

---

## Task 2: 移植重试、熔断与 endpoint 校验

**Files:**
- Create: `internal/llmclient/retry.go`（从 `teellm/retry.go` 复制）
- Create: `internal/llmclient/circuit_breaker.go`（从 `teellm/circuit_breaker.go` 复制）
- Create: `internal/llmclient/validator.go`（从 `teellm/validator.go` 复制）
- Create: `internal/llmclient/resilience_test.go`（从 `teellm/resilience_test.go` 复制）

- [ ] **Step 1: 复制三个实现文件并改包名**

```bash
cd /home/hjy/taa
for f in retry.go circuit_breaker.go validator.go; do
  sed 's/^package teellm$/package llmclient/' "teellm/$f" > "internal/llmclient/$f"
done
```

- [ ] **Step 2: 复制测试文件并改包名**

```bash
cd /home/hjy/taa
sed 's/^package teellm$/package llmclient/' teellm/resilience_test.go > internal/llmclient/resilience_test.go
```

- [ ] **Step 3: 编译并运行移植过来的测试**

Run: `cd /home/hjy/taa && go test ./internal/llmclient/ -count=1`
Expected: `ok`，且包含 `TestCircuitBreaker_*`、`TestExecuteWithRetryContext_*`、`TestValidateEndpoint_*`。

- [ ] **Step 4: 提交**

```bash
cd /home/hjy/taa
git add internal/llmclient/retry.go internal/llmclient/circuit_breaker.go internal/llmclient/validator.go internal/llmclient/resilience_test.go
git commit -m "refactor(llmclient): move retry, circuit breaker and endpoint validation from teellm"
```

---

## Task 3: 移植客户端并改用 `/v1/llm/generate`

**Files:**
- Create: `internal/llmclient/client.go`
- Test: `internal/llmclient/client_test.go`

- [ ] **Step 1: 写失败测试**

`internal/llmclient/client_test.go`：

```go
package llmclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestClient(t *testing.T, url string) Client {
	t.Helper()
	c, err := NewClient(Config{Endpoint: url})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestGeneratePostsPromptAndReturnsText(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/llm/generate" {
			t.Errorf("path = %q, want /v1/llm/generate", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"protocolVersion":"teellm-protocol/v1","requestId":"r1","status":"SUCCESS","model":"m","text":"answer"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	resp, err := c.Generate(context.Background(), &GenerateRequest{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "r1",
		Model:           "m",
		Prompt:          "hello",
		Options:         map[string]any{"temperature": 0},
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if resp.Text != "answer" || resp.Status != StatusSuccess {
		t.Fatalf("response = %+v", resp)
	}
	if got["prompt"] != "hello" {
		t.Errorf("prompt sent = %v", got["prompt"])
	}
	if got["requestId"] != "r1" {
		t.Errorf("requestId sent = %v", got["requestId"])
	}
}

func TestGenerateRetriesTransientStatus(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"SUCCESS","text":"ok"}`))
	}))
	defer server.Close()

	c, err := NewClient(Config{
		Endpoint:       server.URL,
		MaxRetries:     3,
		RetryBaseDelay: time.Millisecond,
		RetryMaxDelay:  time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer c.Close()

	if _, err := c.Generate(context.Background(), &GenerateRequest{ProtocolVersion: CurrentProtocolVersion, Prompt: "p"}); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestHealthCheckOutlastsTheRequestTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	c, err := NewClient(Config{
		Endpoint:           server.URL,
		Timeout:            50 * time.Millisecond,
		HealthCheckTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck must outlast the request timeout: %v", err)
	}
}

func TestHealthCheckRemainsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	c, err := NewClient(Config{
		Endpoint:           server.URL,
		Timeout:            50 * time.Millisecond,
		HealthCheckTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.HealthCheck(ctx); err == nil {
		t.Fatal("HealthCheck must fail when the endpoint outlasts its budget")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd /home/hjy/taa && go test ./internal/llmclient/ -run 'TestGenerate|TestHealthCheck' -count=1`
Expected: FAIL，`undefined: Client` / `undefined: NewClient` / `undefined: Config`。

- [ ] **Step 3: 创建 `internal/llmclient/client.go`**

```go
package llmclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CipherSlinger/teetls"
)

// Config configures the LLM inference client.
type Config struct {
	Endpoint string
	// Timeout bounds an ordinary request. Zero means no deadline: generation
	// time is a property of the deployment's hardware and model, and cutting a
	// request short mid-generation is indistinguishable, to the caller, from
	// the service being unavailable. It does not bound a health check; see
	// HealthCheckTimeout.
	Timeout                        time.Duration
	HealthCheckTimeout             time.Duration
	AllowedHosts                   []string
	TEETLS                         *teetls.Config
	CircuitBreakerFailureThreshold int
	CircuitBreakerCooldown         time.Duration
	MaxRetries                     int
	RetryBaseDelay                 time.Duration
	RetryMaxDelay                  time.Duration
}

// Client talks to the remote inference service.
type Client interface {
	Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error)
	HealthCheck(ctx context.Context) error
	Close() error
}

type client struct {
	cfg          Config
	httpClient   *http.Client
	healthClient *http.Client
	cb           *CircuitBreaker
	endpoint     string
}

// NewClient creates and validates a new inference client.
func NewClient(cfg Config) (Client, error) {
	if err := ValidateEndpoint(cfg.Endpoint, cfg.AllowedHosts); err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	if cfg.CircuitBreakerFailureThreshold <= 0 {
		cfg.CircuitBreakerFailureThreshold = 3
	}
	if cfg.CircuitBreakerCooldown <= 0 {
		cfg.CircuitBreakerCooldown = 30 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = 100 * time.Millisecond
	}
	if cfg.RetryMaxDelay <= 0 {
		cfg.RetryMaxDelay = 2 * time.Second
	}
	// cfg.Timeout is left untouched: zero is the zero value of http.Client's
	// timeout, which means "no deadline", and that is the intended default
	// rather than a configuration mistake to correct.
	if cfg.HealthCheckTimeout <= 0 {
		cfg.HealthCheckTimeout = DefaultHealthCheckTimeout
	}

	cb := NewCircuitBreaker(cfg.CircuitBreakerFailureThreshold, cfg.CircuitBreakerCooldown)

	var httpClient *http.Client
	if cfg.TEETLS != nil {
		httpClient = teetls.NewHTTPClient(cfg.TEETLS)
		httpClient.Timeout = cfg.Timeout
	} else {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}

	// A second client, sharing the transport so the connection pool and any
	// TEE-TLS state stay common, but carrying the health budget instead of the
	// request budget.
	healthClient := *httpClient
	healthClient.Timeout = cfg.HealthCheckTimeout

	endpoint := strings.TrimRight(cfg.Endpoint, "/")

	return &client{
		cfg:          cfg,
		httpClient:   httpClient,
		healthClient: &healthClient,
		cb:           cb,
		endpoint:     endpoint,
	}, nil
}

// isTransientStatus reports whether an HTTP status code represents a transient server failure.
func isTransientStatus(code int) bool {
	return code == http.StatusTooManyRequests ||
		code == http.StatusInternalServerError ||
		code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

// Generate sends one prompt to the inference service and returns its raw text.
func (c *client) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error) {
	if !c.cb.AllowRequest() {
		return nil, ErrCircuitOpen
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal generate request: %w", err)
	}

	var respEnvelope *GenerateResponse
	err = ExecuteWithRetryContext(ctx, c.cfg.MaxRetries, c.cfg.RetryBaseDelay, c.cfg.RetryMaxDelay, func(attempt int) error {
		httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/llm/generate", bytes.NewReader(reqBytes))
		if reqErr != nil {
			return reqErr
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, doErr := c.httpClient.Do(httpReq)
		if doErr != nil {
			if ctx != nil && ctx.Err() != nil {
				c.cb.ResetProbe()
				return ctx.Err()
			}
			c.cb.RecordFailure()
			return fmt.Errorf("%w: %v", ErrRetryable, doErr)
		}
		defer resp.Body.Close()

		if isTransientStatus(resp.StatusCode) {
			c.cb.RecordFailure()
			return fmt.Errorf("%w: server returned transient status %d", ErrRetryable, resp.StatusCode)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%w: unexpected HTTP status %d", ErrInvalidStatus, resp.StatusCode)
		}

		limitedReader := io.LimitReader(resp.Body, int64(MaxResponsePayloadBytes)+1)
		bodyBytes, readErr := io.ReadAll(limitedReader)
		if readErr != nil {
			c.cb.RecordFailure()
			return fmt.Errorf("%w: read response body: %v", ErrRetryable, readErr)
		}
		if len(bodyBytes) > MaxResponsePayloadBytes {
			return ErrPayloadTooLarge
		}

		var parsedEnv GenerateResponse
		if jsonErr := json.Unmarshal(bodyBytes, &parsedEnv); jsonErr != nil {
			return fmt.Errorf("decode response envelope: %w", jsonErr)
		}

		respEnvelope = &parsedEnv
		c.cb.RecordSuccess()
		return nil
	})

	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			c.cb.ResetProbe()
		}
		return nil, err
	}

	return respEnvelope, nil
}

// HealthCheck executes a health check against the inference endpoint.
func (c *client) HealthCheck(ctx context.Context) error {
	if !c.cb.AllowRequest() {
		return ErrCircuitOpen
	}

	err := ExecuteWithRetryContext(ctx, c.cfg.MaxRetries, c.cfg.RetryBaseDelay, c.cfg.RetryMaxDelay, func(attempt int) error {
		httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/v1/llm/healthz", nil)
		if reqErr != nil {
			return reqErr
		}

		resp, doErr := c.healthClient.Do(httpReq)
		if doErr != nil {
			if ctx != nil && ctx.Err() != nil {
				c.cb.ResetProbe()
				return ctx.Err()
			}
			c.cb.RecordFailure()
			return fmt.Errorf("%w: %v", ErrRetryable, doErr)
		}
		defer resp.Body.Close()

		if isTransientStatus(resp.StatusCode) {
			c.cb.RecordFailure()
			return fmt.Errorf("%w: server returned transient status %d", ErrRetryable, resp.StatusCode)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%w: unexpected HTTP status %d", ErrInvalidStatus, resp.StatusCode)
		}

		limitedReader := io.LimitReader(resp.Body, int64(MaxResponsePayloadBytes)+1)
		bodyBytes, readErr := io.ReadAll(limitedReader)
		if readErr != nil {
			c.cb.RecordFailure()
			return fmt.Errorf("%w: read response body: %v", ErrRetryable, readErr)
		}
		if len(bodyBytes) > MaxResponsePayloadBytes {
			return ErrPayloadTooLarge
		}

		c.cb.RecordSuccess()
		return nil
	})

	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			c.cb.ResetProbe()
		}
		return err
	}

	return nil
}

// Close releases any idle HTTP transport connections.
func (c *client) Close() error {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd /home/hjy/taa && go test ./internal/llmclient/ -count=1`
Expected: `ok`。

- [ ] **Step 5: 提交**

```bash
cd /home/hjy/taa
git add internal/llmclient/client.go internal/llmclient/client_test.go
git commit -m "feat(llmclient): port the inference client to the generic generate endpoint"
```

---

## Task 4: codeaudit 承接提示词与 verdict 解析

**Files:**
- Create: `internal/codeaudit/prompt.go`
- Modify: `internal/codeaudit/llm.go`
- Modify: `internal/codeaudit/verifier.go:1-180`
- Test: `internal/codeaudit/prompt_test.go`（新建）
- Test: `internal/codeaudit/llm_test.go`、`internal/codeaudit/verifier` 相关测试、`failclosed_test.go`、`gate_semantics_test.go`、`internal/controller/audit_model_import_test.go`

- [ ] **Step 1: 写失败的提示词测试**

`internal/codeaudit/prompt_test.go`：

```go
package codeaudit

import (
	"strings"
	"testing"
)

func TestBuildFindingPromptCarriesEveryField(t *testing.T) {
	f := Finding{
		RuleID:        "EMB_003",
		Category:      "exfiltration",
		Severity:      SeverityHigh,
		Description:   "documented rule text",
		File:          "train.py",
		Line:          42,
		CodeSnippet:   "print(dataset)",
		ContextBefore: "before line",
		ContextAfter:  "after line",
	}
	got := BuildFindingPrompt(f, f.ContextAfter)

	for _, want := range []string{
		"train.py", "第 42 行", "before line", "print(dataset)", "after line",
		"EMB_003", "exfiltration", SeverityHigh, "documented rule text",
		"良性判定规则优先", "请严格按以下 JSON 格式回答",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt is missing %q", want)
		}
	}
}

func TestBuildFindingPromptUsesProvidedContextAfter(t *testing.T) {
	f := Finding{File: "a.py", Line: 1, CodeSnippet: "x", ContextBefore: "b", ContextAfter: "original"}
	got := BuildFindingPrompt(f, "cp3 evidence")
	if !strings.Contains(got, "cp3 evidence") || strings.Contains(got, "original") {
		t.Fatalf("prompt must use the provided contextAfter:\n%s", got)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd /home/hjy/taa && go test ./internal/codeaudit/ -run 'TestBuildFindingPrompt' -count=1`
Expected: FAIL，`undefined: BuildFindingPrompt`。

- [ ] **Step 3: 创建 `internal/codeaudit/prompt.go`**

把 `teellm/ollama_backend.go` 里的 `findingAnalysisPromptTemplate` **逐字**复制过来，只改包名：

```go
package codeaudit

import "fmt"

// findingAnalysisPromptTemplate is the audit rubric handed to the model for one
// finding. It was moved here verbatim from the inference service: the wording,
// the rubric's leading position and its trailing reminder are load-bearing for
// the verdicts this deployment has been measured on, so they must not be
// reworded during the move.
const findingAnalysisPromptTemplate = `你是一个代码安全审计专家。请分析以下代码片段是否存在窃取数据、外传数据或其他恶意行为。

## 判定优先级与安全边界
1. 恶意/可疑判定 (MALICIOUS 或 SUSPICIOUS)：
   - 必须有上下文明确表明代码在窃取或外发凭据（密钥、令牌、密码、证书、私钥、敏感配置文件）；
   - 或明确在通过未授权网络、隐写载荷、非法持久化通道外传真实的敏感原始数据/特征矩阵；
   - 只有确凿恶意利用证据时才可判定为 MALICIOUS 或 SUSPICIOUS。

2. 良性判定 (BENIGN)（严格消除训练与日志误报）：
   - 日志与标准输出（如 EMB_003）：打印数据集名称/路径标识/类别标签/状态分隔线（例如 print(dataset + '--------')、print(dataset)）、打印训练批次统计、模型参数结构、计算进度、评估指标（如 accuracy、loss、AUC、sensitivity、specificity、F1-score、ci 置信区间等），均属完全正常的训练与科研评估日志，绝非敏感数据泄露，必须判为 BENIGN；
   - 依赖检测与测试打桩（如 DYN_001）：在测试脚本（如 test_*.py）或顶层保护块中使用 __import__ 或 importlib.import_module 探测可选模块、或为缺失依赖（如 torch/numpy/tensorboardX）挂载 MagicMock 模拟对象，属于纯良性的测试用例兼容逻辑，绝非动态恶意执行，必须判为 BENIGN；
   - 结果保存与导出（如 EMB_001/EMB_002/EMB_004）：正常保存训练生成的模型权重（如 torch.save(model.state_dict(), ...)）、导出评估图表（如 matplotlib/plt 保存 ROC 曲线或分布图）、写入评估结果指标文件，必须判为 BENIGN；
   - 常规配置读取、环境参数封装、合法子进程参数调用等框架良性用法，必须判为 BENIGN。

3. 不确定判定 (UNCERTAIN)：
   - 仅在上下文严重缺失、证据不足且语义完全无法确认意图时返回。

## 代码片段
文件: %s (第 %d 行)
` + "```python" + `
%s
>>> %s   ← 触发规则的代码
%s
` + "```" + `

## 触发的规则
规则ID: %s
类别: %s
严重度: %s
规则说明: %s

## 判定提醒
上述良性判定规则优先：EMB_001/EMB_002/EMB_003/EMB_004 与 DYN_001 均属良性用法，除非有确凿的窃取或外发敏感数据证据，否则必须判为 BENIGN。

## 请回答
1. verdict: MALICIOUS(恶意) / SUSPICIOUS(可疑) / BENIGN(正常) / UNCERTAIN(不确定)
2. reason: 一句话说明理由（中文）
3. risk: 如果恶意，数据会怎样被利用

请严格按以下 JSON 格式回答，不要包含其他内容:
{"verdict": "...", "reason": "...", "risk": "..."}
`

// BuildFindingPrompt renders the audit prompt for one finding. contextAfter is
// passed explicitly because the caller may replace the source context with CPG
// evidence.
func BuildFindingPrompt(f Finding, contextAfter string) string {
	return fmt.Sprintf(findingAnalysisPromptTemplate,
		f.File, f.Line,
		f.ContextBefore, f.CodeSnippet, contextAfter,
		f.RuleID, f.Category, f.Severity, f.Description,
	)
}
```

> 注意：复制时逐字核对模板正文与 `teellm/ollama_backend.go:15-56` 一致；尺寸/措辞任何改动都视为行为变更。

- [ ] **Step 4: 添加 verdict 解析类型（`internal/codeaudit/llm.go`）**

`llm.go` 里已有 `LLMDecision` 与 `parseDecision`，保持不动；把客户端接口改成通用形态：

```go
import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/CipherSlinger/teellm"   // 删除这一行
	"github.com/CipherSlinger/teetls"

	"taa/internal/llmclient"
)

// LLMClient is the transport the verifier talks to. It is the generic
// inference client: prompt in, text out.
type LLMClient = llmclient.Client
```

`NewInferenceClient` 改为：

```go
func NewInferenceClient(cfg LLMConfig) (LLMClient, error) {
	teeTLSConfig := buildTEETLSConfig(cfg)

	return llmclient.NewClient(llmclient.Config{
		Endpoint:                       cfg.Endpoint,
		Timeout:                        cfg.Timeout,
		AllowedHosts:                   cfg.AllowedHosts,
		TEETLS:                         teeTLSConfig,
		CircuitBreakerFailureThreshold: cfg.CircuitBreakerThreshold,
		CircuitBreakerCooldown:         time.Duration(cfg.CooldownSec) * time.Second,
	})
}
```

`llmArbitrationPolicy` 常量删除（协议里不再有 policy）。`LLMConfig.Temperature` 的注释改为：

```go
	// Temperature is the sampling temperature sent with every generate
	// request. nil means 0: deterministic decoding, so the same finding yields
	// the same verdict. A non-nil value re-enables sampling; identical findings
	// may then be judged differently, and under fail-closed a single MALICIOUS
	// draw blocks the import.
	Temperature *float32
```

- [ ] **Step 5: 改写 `verifier.go` 的请求段**

把 `VerifyReport` 中构造 `teellm.RequestEnvelope` 到读取 `resp.Decision` 的整段替换为：

```go
		prompt := BuildFindingPrompt(*f, ctxAfter)

		options := map[string]any{"temperature": 0.0}
		if cfg.Temperature != nil {
			options["temperature"] = *cfg.Temperature
		}

		req := &llmclient.GenerateRequest{
			ProtocolVersion: llmclient.CurrentProtocolVersion,
			RequestID:       fmt.Sprintf("verify-%d", time.Now().UnixNano()),
			Prompt:          prompt,
			Options:         options,
		}
		if cfg.Model != "" {
			req.Model = cfg.Model
		}

		resp, err := client.Generate(ctx, req)
		if err != nil || resp == nil || resp.Status != llmclient.StatusSuccess {
			f.LLMVerdict = "UNCERTAIN"
			if errors.Is(err, llmclient.ErrCircuitOpen) {
				f.LLMReason = "SERVICE_UNAVAILABLE: circuit breaker open"
			} else if err != nil {
				f.LLMReason = fmt.Sprintf("SERVICE_UNAVAILABLE: %v", err)
			} else if resp != nil {
				f.LLMReason = fmt.Sprintf("SERVICE_UNAVAILABLE: %s", resp.Status)
			} else {
				f.LLMReason = "SERVICE_UNAVAILABLE: nil response"
			}
			hasInferenceFailure = true
			continue
		}

		decision := parseDecision(resp.Text)
		f.LLMVerdict = decision.Verdict
		f.LLMReason = decision.Reason
		f.LLMRisk = decision.Risk
```

同时把 `recomputeReportPassed` 里的 `teellm.VerdictBenign` 换成本地常量：

```go
const verdictBenign = "BENIGN"
```

并在 `llm.go` 里补上该常量；`verifier.go` 中所有 `teellm.VerdictBenign` 改为 `verdictBenign`。

`num_predict` 不新增配置字段：仓库里没有 `maxCompletionTokens`，TAA 目前只发送
`temperature`，`num_predict` 沿用服务端模型目录的默认值（200）。服务端仍然允许请求的
`options` 覆盖它（Task 6），为将来保留。

- [ ] **Step 6: 更新测试替身**

`internal/codeaudit/llm_test.go` 的 `mockLLMClient` 改为：

```go
func (m *mockLLMClient) Generate(_ context.Context, req *llmclient.GenerateRequest) (*llmclient.GenerateResponse, error) {
	...
}
func (m *mockLLMClient) HealthCheck(context.Context) error { return nil }
func (m *mockLLMClient) Close() error                     { return nil }
```

`AnalyzeFile` 保留，但实现内部改为直接返回预设 `FileSummary`（不再经过 `teellm` 类型）。

`internal/controller/audit_model_import_test.go`、`internal/codeaudit/failclosed_test.go`、`gate_semantics_test.go` 中构造 `teellm.*` 的地方改成 `llmclient.*`；模拟服务端从 `/v1/llm/verify` 改为 `/v1/llm/generate`，返回体改成：

```json
{"protocolVersion":"teellm-protocol/v1","requestId":"...","status":"SUCCESS","text":"{\"verdict\":\"BENIGN\",\"reason\":\"ok\",\"risk\":\"\"}"}
```

- [ ] **Step 7: 运行审计测试**

Run: `cd /home/hjy/taa && go test ./internal/codeaudit/ ./internal/controller/ -count=1`
Expected: `ok`（controller 全量较慢，若超时先单独跑 `-run 'Audit|LLM'`）。

- [ ] **Step 8: 提交**

```bash
cd /home/hjy/taa
git add internal/codeaudit internal/controller/audit_model_import_test.go
git commit -m "refactor(codeaudit): own the audit prompt and verdict parsing"
```

---

## Task 5: 收尾 TAA 内部引用与模块依赖

**Files:**
- Modify: `internal/app/taa/app.go:344-360`
- Modify: `internal/controller/import_processing.go:879`
- Modify: `go.mod`、`go.sum`（移除 `github.com/CipherSlinger/teellm`）

- [ ] **Step 1: 替换健康检查常量**

`internal/app/taa/app.go`：

```go
	probeTimeout := llmclient.DefaultHealthCheckTimeout
```

`internal/controller/import_processing.go`：

```go
const auditLLMHealthCheckTimeout = llmclient.DefaultHealthCheckTimeout
```

两个文件都加 import：

```go
	"taa/internal/llmclient"
```

- [ ] **Step 2: 确认父模块不再 import teellm**

Run: `cd /home/hjy/taa && grep -rn "CipherSlinger/teellm" --include="*.go" cmd/ internal/ pkg/ tools/`
Expected: 无输出。

- [ ] **Step 3: 移除 go.mod 依赖**

```bash
cd /home/hjy/taa
go mod tidy
grep -n "teellm" go.mod || echo "teellm dependency removed"
```

Expected: 打印 `teellm dependency removed`，且 `replace` 行一并消失。

- [ ] **Step 4: 构建与测试**

Run: `cd /home/hjy/taa && go build ./cmd/... ./internal/... ./pkg/... && go test ./internal/app/... ./internal/controller/ -count=1`
Expected: 构建成功，测试 `ok`。

- [ ] **Step 5: 提交**

```bash
cd /home/hjy/taa
git add internal/app/taa/app.go internal/controller/import_processing.go go.mod go.sum
git commit -m "refactor(taa): drop the teellm module dependency from the parent"
```

---

## Task 6: teellm 服务端改为通用 generate

**Files:**
- Modify: `teellm/types.go`（重写）
- Modify: `teellm/server.go`
- Modify: `teellm/ollama_backend.go`
- Test: `teellm/server_test.go`（新建）
- Test: `teellm/ollama_backend_test.go`（重写审计相关用例）

- [ ] **Step 1: 写失败的服务端测试**

`teellm/server_test.go`：

```go
package teellm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type stubBackend struct {
	gotReq *GenerateRequest
	resp   *GenerateResponse
	err    error
}

func (b *stubBackend) Generate(_ context.Context, req *GenerateRequest) (*GenerateResponse, error) {
	b.gotReq = req
	return b.resp, b.err
}

func (b *stubBackend) HandleHealthCheck(context.Context) error { return nil }

func newPlainServer(t *testing.T, backend Backend) *Server {
	t.Helper()
	srv, err := NewServer(ServerConfig{Addr: "127.0.0.1:0", Backend: backend})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func TestGenerateHandlerReturnsText(t *testing.T) {
	backend := &stubBackend{resp: &GenerateResponse{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "r1",
		Status:          StatusSuccess,
		Model:           "m",
		Text:            "answer",
	}}
	srv := newPlainServer(t, backend)

	body, _ := json.Marshal(GenerateRequest{ProtocolVersion: CurrentProtocolVersion, RequestID: "r1", Prompt: "hello"})
	resp, err := http.Post("http://"+srv.Addr()+"/v1/llm/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if got.Text != "answer" {
		t.Fatalf("text = %q", got.Text)
	}
	if backend.gotReq == nil || backend.gotReq.Prompt != "hello" {
		t.Fatalf("backend saw %+v", backend.gotReq)
	}
}

func TestGenerateHandlerRejectsMissingPrompt(t *testing.T) {
	srv := newPlainServer(t, &stubBackend{})
	body := `{"protocolVersion":"teellm-protocol/v1","requestId":"r1"}`
	resp, err := http.Post("http://"+srv.Addr()+"/v1/llm/generate", "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(raw, []byte("INVALID_REQUEST")) {
		t.Fatalf("body = %s", raw)
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd /home/hjy/taa/teellm && go test ./ -run 'TestGenerateHandler' -count=1`
Expected: FAIL，`undefined: GenerateRequest` / `HandleVerifyFinding` 接口不匹配。

- [ ] **Step 3: 重写 `teellm/types.go`**

```go
package teellm

// CurrentProtocolVersion represents the supported protocol version.
const CurrentProtocolVersion = "teellm-protocol/v1"

// MaxRequestPayloadBytes bounds one request body (1MB).
const MaxRequestPayloadBytes = 1 << 20

// Status constants representing response status codes.
const (
	StatusSuccess            = "SUCCESS"
	StatusInvalidRequest     = "INVALID_REQUEST"
	StatusModelNotFound      = "MODEL_NOT_FOUND"
	StatusInternalError      = "INTERNAL_ERROR"
	StatusServiceUnavailable = "SERVICE_UNAVAILABLE"
)

// GenerateRequest is one inference request. The service treats prompt and
// options as opaque: it knows nothing about what the caller is asking the model
// to do.
type GenerateRequest struct {
	ProtocolVersion string         `json:"protocolVersion"`
	RequestID       string         `json:"requestId"`
	Model           string         `json:"model,omitempty"`
	Prompt          string         `json:"prompt"`
	Options         map[string]any `json:"options,omitempty"`
}

// GenerateResponse carries the model's raw text output.
type GenerateResponse struct {
	ProtocolVersion string `json:"protocolVersion"`
	RequestID       string `json:"requestId"`
	Status          string `json:"status"`
	ErrorMessage    string `json:"errorMessage,omitempty"`
	Model           string `json:"model,omitempty"`
	Text            string `json:"text,omitempty"`
}
```

同时删除 `teellm/types_test.go`（其中的协议用例已被 Task 1 的 `llmclient/types_test.go` 取代）。

- [ ] **Step 4: 改写 `teellm/server.go`**

- `Backend` 接口改为：

```go
type Backend interface {
	Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error)
	HandleHealthCheck(ctx context.Context) error
}
```

- 路由：`mux.HandleFunc("/v1/llm/generate", s.handleGenerate)`
- 删除 `handleVerify`，新增：

```go
// handleGenerate handles POST /v1/llm/generate.
func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limited := io.LimitReader(r.Body, int64(MaxRequestPayloadBytes)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		http.Error(w, "read request body error", http.StatusBadRequest)
		return
	}
	if len(body) > MaxRequestPayloadBytes {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(&GenerateResponse{
			ProtocolVersion: CurrentProtocolVersion,
			Status:          StatusInvalidRequest,
			ErrorMessage:    "request body exceeds 1MB limit",
		})
		return
	}

	var req GenerateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(&GenerateResponse{
			ProtocolVersion: CurrentProtocolVersion,
			Status:          StatusInvalidRequest,
			ErrorMessage:    "invalid request JSON: " + err.Error(),
		})
		return
	}
	if strings.TrimSpace(req.Prompt) == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(&GenerateResponse{
			ProtocolVersion: CurrentProtocolVersion,
			RequestID:       req.RequestID,
			Status:          StatusInvalidRequest,
			ErrorMessage:    "prompt must not be empty",
		})
		return
	}

	resp, err := s.backend.Generate(r.Context(), &req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(&GenerateResponse{
			ProtocolVersion: CurrentProtocolVersion,
			RequestID:       req.RequestID,
			Status:          StatusInternalError,
			ErrorMessage:    err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
```

`server.go` 需要新增 `strings` import。

- [ ] **Step 5: 改写 `teellm/ollama_backend.go`**

删除：`findingAnalysisPromptTemplate`、`rawDecision`、`HandleVerifyFinding`、`parseDecisionJSON`、`EngineInfo`/`DecisionResult` 相关返回。

新增：

```go
// Generate dispatches one prompt to Ollama. Model catalog options are applied
// first and the request's own options override them, so a caller can raise or
// lower generation settings without the service knowing why.
func (b *OllamaBackend) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error) {
	if req == nil || strings.TrimSpace(req.Prompt) == "" {
		return &GenerateResponse{
			ProtocolVersion: CurrentProtocolVersion,
			RequestID:       reqIDOrEmpty(req),
			Status:          StatusInvalidRequest,
			ErrorMessage:    "prompt must not be empty",
		}, errors.New("prompt must not be empty")
	}

	model := b.defaultModel
	if strings.TrimSpace(req.Model) != "" {
		model = strings.TrimSpace(req.Model)
	}

	genOptions := map[string]any{
		"num_predict": 200,
	}
	if b.catalog != nil {
		if profile := b.catalog.GetProfile(model); profile != nil && len(profile.Options) > 0 {
			for k, v := range profile.Options {
				genOptions[k] = v
			}
		}
	}
	for k, v := range req.Options {
		genOptions[k] = v
	}

	ollamaReqBody := ollamaGenerateReq{
		Model:   model,
		Prompt:  req.Prompt,
		Stream:  false,
		Options: genOptions,
	}

	reqBytes, err := json.Marshal(ollamaReqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal ollama request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint+"/api/generate", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("create ollama request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama generate request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
		return nil, fmt.Errorf("ollama returned HTTP %d: %s", httpResp.StatusCode, string(body))
	}

	var genResp ollamaGenerateResp
	if err := json.NewDecoder(httpResp.Body).Decode(&genResp); err != nil {
		return nil, fmt.Errorf("decode ollama response: %w", err)
	}

	return &GenerateResponse{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       req.RequestID,
		Status:          StatusSuccess,
		Model:           model,
		Text:            genResp.Response,
	}, nil
}
```

`reqIDOrEmpty` 保留。

- [ ] **Step 6: 重写 `teellm/ollama_backend_test.go` 的审计用例**

保留 `TestOllamaBackend_HandleHealthCheck`。删除 `TestOllamaBackend_HandleVerifyFinding`、`TestOllamaBackend_TemperatureIsPinned`、`TestFindingAnalysisPrompt*`。新增：

```go
func TestOllamaBackend_GenerateMergesOptions(t *testing.T) {
	var got map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"response":"answer"}`))
	}))
	defer upstream.Close()

	catalog := DefaultModelCatalog()
	backend, err := NewOllamaBackend(OllamaBackendConfig{
		Endpoint:     upstream.URL,
		DefaultModel: "qwen2.5-coder:0.5b",
		Catalog:      catalog,
	})
	if err != nil {
		t.Fatalf("NewOllamaBackend failed: %v", err)
	}

	resp, err := backend.Generate(context.Background(), &GenerateRequest{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "r1",
		Prompt:          "hello",
		Options:         map[string]any{"temperature": 0, "num_predict": 42},
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if resp.Text != "answer" || resp.Status != StatusSuccess {
		t.Fatalf("response = %+v", resp)
	}

	opts, _ := got["options"].(map[string]any)
	if opts["temperature"] != float64(0) {
		t.Errorf("temperature = %v", opts["temperature"])
	}
	if opts["num_predict"] != float64(42) {
		t.Errorf("num_predict = %v, want the request's override", opts["num_predict"])
	}
	if got["prompt"] != "hello" {
		t.Errorf("prompt = %v", got["prompt"])
	}
}

func TestOllamaBackend_GenerateRejectsEmptyPrompt(t *testing.T) {
	backend, err := NewOllamaBackend(OllamaBackendConfig{Endpoint: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("NewOllamaBackend failed: %v", err)
	}
	resp, err := backend.Generate(context.Background(), &GenerateRequest{})
	if err == nil {
		t.Fatal("expected an error for an empty prompt")
	}
	if resp == nil || resp.Status != StatusInvalidRequest {
		t.Fatalf("response = %+v", resp)
	}
}
```

- [ ] **Step 7: 运行 teellm 包测试**

Run: `cd /home/hjy/taa/teellm && go test ./ -count=1`
Expected: `ok`（此时 `client.go`/`retry.go`/`circuit_breaker.go`/`validator.go` 仍存在，下一任务删除）。

- [ ] **Step 8: 子模块提交**

```bash
cd /home/hjy/taa/teellm
git add types.go server.go ollama_backend.go server_test.go ollama_backend_test.go types_test.go
git commit -m "feat(teellm): serve generic generation instead of audit verification"
cd /home/hjy/taa
git add teellm
git commit -m "chore(teellm): bump submodule for the generic generate endpoint"
```

---

## Task 7: 删除 teellm 侧的客户端与审计残留

**Files:**
- Delete: `teellm/client.go`、`teellm/retry.go`、`teellm/circuit_breaker.go`、`teellm/validator.go`
- Delete: `teellm/resilience_test.go`、`teellm/client_health_timeout_test.go`、`teellm/teellm_test.go`

- [ ] **Step 1: 删除文件**

```bash
cd /home/hjy/taa/teellm
git rm client.go retry.go circuit_breaker.go validator.go
git rm resilience_test.go client_health_timeout_test.go teellm_test.go
```

- [ ] **Step 2: 确认没有残留引用**

Run: `cd /home/hjy/taa/teellm && grep -rn "VerifyFinding\|RequestEnvelope\|DecisionResult\|FindingPayload\|PolicyOptions\|Verdict" --include="*.go" .`
Expected: 无输出。

- [ ] **Step 3: 运行 teellm 全量测试**

Run: `cd /home/hjy/taa/teellm && go build ./... && go test ./... -count=1`
Expected: 全部 `ok`。

- [ ] **Step 4: 子模块提交**

```bash
cd /home/hjy/taa/teellm
git commit -m "refactor(teellm): remove the audit client and audit protocol types"
cd /home/hjy/taa
git add teellm
git commit -m "chore(teellm): bump submodule for the audit removal"
```

---

## Task 8: 更新文档

**Files:**
- Modify: `teellm/README.md:69`、`:233-260`
- Modify: `README.md`（若含 `/v1/llm/verify` 描述）
- Modify: `docs/api-design.md:1905-1920`
- Modify: `.claude/specs/2026-11-03-audit-teellm-boundary-design.md`（状态改为“已实施”）

- [ ] **Step 1: `teellm/README.md` 替换接口表**

```markdown
### HTTP Surface

All three endpoints share the single TEE-TLS 1.3 listener on `:8443`.

| Path | Method | Purpose |
|------|--------|---------|
| `/v1/llm/generate` | POST | Generic inference: prompt in, raw text out |
| `/v1/llm/healthz` | GET | Readiness |
| `/v1/llm/getAttestation` | POST | Platform fetches the CSV report and the certificate it is bound to |

The service knows nothing about the caller's task. Sampling options
(`temperature`, `num_predict`, ...) travel in the request's `options` object and
override the model catalog's profile defaults; whatever they are, the service
passes them through to Ollama unchanged.

Request and response:

```json
{"protocolVersion":"teellm-protocol/v1","requestId":"r1","model":"qwen2.5-coder:3b","prompt":"...","options":{"temperature":0}}
{"protocolVersion":"teellm-protocol/v1","requestId":"r1","status":"SUCCESS","model":"qwen2.5-coder:3b","text":"..."}
```
```

同时把架构图里的 `(/v1/llm/verify, /v1/llm/healthz)` 改为 `(/v1/llm/generate, /v1/llm/healthz, /v1/llm/getAttestation)`。

- [ ] **Step 2: `docs/api-design.md` §7.3 附近**

把“`/v1/llm/verify`（审计判定）与 `/v1/llm/healthz`（就绪检查）是 TAA 调 LLM 的接口”改为：

```markdown
同端口上的 `/v1/llm/generate`（通用推理）与 `/v1/llm/healthz`（就绪检查）是 **TAA 调 LLM** 的接口，
平台不参与，不在本文范围内。审计提示词、裁决解析与 fail-closed 判定全部位于 TAA 侧；
LLM 只把提示词转给模型并返回原始文本。
```

- [ ] **Step 3: 检查 TAA README**

Run: `cd /home/hjy/taa && grep -n "/v1/llm/verify" README.md deploy.md CHANGELOG.md`
Expected: 无输出；若有，按同样口径改为 `/v1/llm/generate`（CHANGELOG 的历史条目不改）。

- [ ] **Step 4: 子模块 + 父仓库提交**

```bash
cd /home/hjy/taa/teellm
git add README.md
git commit -m "docs(teellm): document the generic generate endpoint"
cd /home/hjy/taa
git add teellm docs/api-design.md README.md
git commit -m "docs(architecture): move audit semantics to the TAA side"
```

---

## Task 9: 全量验证

- [ ] **Step 1: 全量 Go 测试**

Run:

```bash
cd /home/hjy/taa && go test ./cmd/... ./internal/... ./pkg/... ./tools/platform-mock/... -count=1
cd /home/hjy/taa/teellm && go test ./... -count=1
```

Expected: 全部 `ok`。

- [ ] **Step 2: 格式与 vet**

Run:

```bash
cd /home/hjy/taa && gofmt -l internal/llmclient internal/codeaudit
cd /home/hjy/taa && go vet ./cmd/... ./internal/... ./pkg/...
cd /home/hjy/taa/teellm && go vet ./...
```

Expected: `gofmt -l` 无输出；`go vet` 无输出。

- [ ] **Step 3: 端到端冒烟**

```bash
cd /home/hjy/taa/teellm
go build -o /tmp/teellm-service ./cmd/teellm-service
timeout 6 /tmp/teellm-service -config configs/teellm-docker.json -mock-attestation -addr 127.0.0.1:18445 > /tmp/teellm-generate.log 2>&1
cat /tmp/teellm-generate.log
```

Expected: 出现 `teellm-service listening on 127.0.0.1:18445`，无 panic。

- [ ] **Step 4: 确认依赖方向**

```bash
cd /home/hjy/taa && grep -rn "CipherSlinger/teellm" --include="*.go" cmd/ internal/ pkg/ tools/ || echo "TAA no longer imports teellm"
cd /home/hjy/taa/teellm && grep -rn "FindingPayload\|Verdict\|VerifyFinding" --include="*.go" . || echo "teellm has no audit vocabulary"
```

Expected: 两条都打印各自的提示语。

- [ ] **Step 5: 最终提交（如有遗留）**

```bash
cd /home/hjy/taa && git status --short
```

只提交本计划涉及的改动；共享检出里的其他在途改动不动。

---

## 自检

**1. Spec 覆盖**

| Spec 章节 | 对应任务 |
| --- | --- |
| §3.1 teellm 保留的接口 | Task 6 |
| §3.2 TAA 承接（llmclient / prompt） | Task 1–4 |
| §4 线协议 | Task 1、Task 6 |
| §5 关键决策 1–5 | Task 4（提示词/temperature）、Task 5（依赖）、Task 6（num_predict） |
| §6.1 teellm 删除项 | Task 6、7 |
| §6.2 TAA 落点 | Task 1–5 |
| §7 失败语义 | Task 4（错误映射）、Task 6（400/500） |
| §8 部署与兼容 | 文档 Task 8（同版本升级说明） |
| §9 验证方式 | Task 1–9 的测试与 Task 9 |

**2. 已知取舍**

- 提示词模板逐字搬迁，任何措辞变化都视为审计行为变更。
- `FileAnalyzer` 生产路径不实现，保持 mock-only。
- 父模块 `go.mod` 保留 `teetls`。

**3. 类型一致性**

- `llmclient.GenerateRequest`/`GenerateResponse` 在 Task 1 定义，Task 3/4 使用同一名字。
- `llmclient.Client` 在 Task 3 定义，Task 4 以别名 `LLMClient = llmclient.Client` 使用。
- `teellm.GenerateRequest`/`GenerateResponse` 与 `llmclient` 的同名类型是两个模块的线上镜像，字段必须逐字一致（Task 1 与 Task 6）。
- `verdictBenign` 常量在 Task 4 定义，`verifier.go` 全部改用它。
