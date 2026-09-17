# TAA 与 Qwen 推理引擎完全独立解耦与安全通信协议实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 彻底剥离 TAA 内嵌的推理引擎子进程生命周期管理，建立基于标准化协议 `taa-isp/v1` 的独立通信客户端包 `internal/inference`（支持 UDS 与 HTTP REST、SSRF 防御、熔断与重试机制），重构 `internal/codeaudit` 对接新客户端，并对齐 fail-closed 安全策略矩阵。

**Architecture:** 采用分层解耦架构：
1. **底层传输与协议信封 (`internal/inference`)**：定义标准请求与响应信封模型���端点安全校验器（拦截 SSRF/云元数据）、熔断器与重试引擎、UDS 与 HTTP 传输适配器；
2. **配置层 (`internal/config`)**：扩展 `llm` 配置段以支持传输通道、UDS 路径、认证 Token 与弹性参数，并严格保持向后兼容；
3. **业务消费层 (`internal/codeaudit`)**：解耦原有私有 `OllamaClient`，全面切至 `InferenceClient` 接口，并重构裁决与降级逻辑；
4. **生命周期与部署层 (`internal/app/taa`, `deploy.sh`)**：移除 TAA 进程内 `start-ollama.sh` 子进程管理逻辑，转换为快速启动探针，为容器/Pod 解耦铺平道路。

**Tech Stack:** Go 1.26, Unix Domain Sockets, HTTP/REST, GM/T 国密与 SHA-256 哈希, 标准库 context/net/sync.

---

### Task 1: 建立独立推理协议与数据结构包 `internal/inference/types.go`

**Files:**
- Create: `internal/inference/types.go`
- Create: `internal/inference/client.go`
- Create: `internal/inference/types_test.go`
- Test: `internal/inference/types_test.go`

- [ ] **Step 1: 编写 `types_test.go` 测试用例**

创建 `internal/inference/types_test.go`：
```go
package inference_test

import (
	"encoding/json"
	"testing"

	"taa/internal/inference"
)

func TestRequestEnvelope_Serialization(t *testing.T) {
	req := inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-001",
		TaskID:          "task-001",
		Timestamp:       1789728000,
		Nonce:           "abcdef1234567890",
		DeadlineMs:      30000,
		Action:          inference.ActionVerifyFinding,
		FindingPayload: &inference.FindingPayload{
			RuleID:      "TAA-SEC-001",
			Category:    "command_injection",
			Severity:    "HIGH",
			Description: "Unsanitized command execution",
			Target: inference.CodeTarget{
				FilePath:      "train.py",
				Line:          42,
				CodeSnippet:   "os.system(cmd)",
				ContentSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		Policy: inference.PolicyOptions{
			Mode:        inference.PolicyModeGate,
			Temperature: 0.1,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request envelope failed: %v", err)
	}

	var parsed inference.RequestEnvelope
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal request envelope failed: %v", err)
	}

	if parsed.ProtocolVersion != inference.CurrentProtocolVersion {
		t.Errorf("got protocol %s, want %s", parsed.ProtocolVersion, inference.CurrentProtocolVersion)
	}
	if parsed.FindingPayload.Target.Line != 42 {
		t.Errorf("got line %d, want 42", parsed.FindingPayload.Target.Line)
	}
}

func TestResponseEnvelope_Serialization(t *testing.T) {
	resp := inference.ResponseEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-001",
		Status:          inference.StatusSuccess,
		Decision: &inference.DecisionResult{
			Verdict:    inference.VerdictMalicious,
			Confidence: 0.95,
			RiskLevel:  "HIGH",
			ReasonCode: "CONFIRMED_COMMAND_INJECTION",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response envelope failed: %v", err)
	}

	var parsed inference.ResponseEnvelope
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal response envelope failed: %v", err)
	}

	if parsed.Decision.Verdict != inference.VerdictMalicious {
		t.Errorf("got verdict %s, want %s", parsed.Decision.Verdict, inference.VerdictMalicious)
	}
}
```

- [ ] **Step 2: 运行测试验证其因包缺失而失败**

Run: `go test ./internal/inference/...`
Expected: FAIL (package not found or build failure)

- [ ] **Step 3: 实现 `internal/inference/types.go` 与 `client.go`**

创建 `internal/inference/types.go`：
```go
package inference

// CurrentProtocolVersion represents the supported protocol version.
const CurrentProtocolVersion = "taa-isp/v1"

// Action constants.
const (
	ActionVerifyFinding = "VERIFY_FINDING"
	ActionAnalyzeFile   = "ANALYZE_FILE"
	ActionHealthCheck   = "HEALTH_CHECK"
)

// Verdict constants.
const (
	VerdictMalicious  = "MALICIOUS"
	VerdictSuspicious = "SUSPICIOUS"
	VerdictBenign     = "BENIGN"
	VerdictUncertain  = "UNCERTAIN"
)

// Status constants.
const (
	StatusSuccess            = "SUCCESS"
	StatusInvalidRequest     = "INVALID_REQUEST"
	StatusUnauthorized       = "UNAUTHORIZED"
	StatusServiceOverloaded  = "SERVICE_OVERLOADED"
	StatusModelNotFound      = "MODEL_NOT_FOUND"
	StatusInternalError      = "INTERNAL_ERROR"
	StatusServiceUnavailable = "SERVICE_UNAVAILABLE"
)

// PolicyMode constants.
const (
	PolicyModeGate   = "gate"
	PolicyModeAssist = "assist"
)

// AuthConfig defines authentication credentials for the inference endpoint.
type AuthConfig struct {
	AuthType string `json:"authType"` // "none", "token"
	Token    string `json:"token,omitempty"`
}

// ModelReference identifies the model to be targeted for inference.
type ModelReference struct {
	Name             string `json:"name"`
	Tag              string `json:"tag,omitempty"`
	MinContextTokens int    `json:"minContextTokens,omitempty"`
}

// CodeTarget identifies the location and slice of code under audit.
type CodeTarget struct {
	FilePath      string `json:"filePath"`
	Line          int    `json:"line"`
	CodeSnippet   string `json:"codeSnippet"`
	ContextBefore string `json:"contextBefore,omitempty"`
	ContextAfter  string `json:"contextAfter,omitempty"`
	ContentSHA256 string `json:"contentSha256,omitempty"`
}

// FindingPayload contains details of a static finding being verified.
type FindingPayload struct {
	RuleID      string     `json:"ruleId"`
	Category    string     `json:"category"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
	Target      CodeTarget `json:"target"`
}

// PolicyOptions configures the runtime audit policy.
type PolicyOptions struct {
	Mode                 string  `json:"mode"`
	EnableReasoningChain bool    `json:"enableReasoningChain,omitempty"`
	Temperature          float32 `json:"temperature,omitempty"`
	MaxCompletionTokens  int     `json:"maxCompletionTokens,omitempty"`
}

// RequestEnvelope is the standardized request structure for ISP.
type RequestEnvelope struct {
	ProtocolVersion string          `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	TaskID          string          `json:"taskId,omitempty"`
	Timestamp       int64           `json:"timestamp"`
	Nonce           string          `json:"nonce"`
	DeadlineMs      int64           `json:"deadlineMs"`
	Auth            AuthConfig      `json:"auth,omitempty"`
	ModelRef        ModelReference  `json:"modelRef,omitempty"`
	Action          string          `json:"action"`
	FindingPayload  *FindingPayload `json:"findingPayload,omitempty"`
	Policy          PolicyOptions   `json:"policy"`
}

// DecisionResult represents the semantic arbitration verdict.
type DecisionResult struct {
	Verdict              string  `json:"verdict"`
	Confidence           float32 `json:"confidence"`
	RiskLevel            string  `json:"riskLevel"`
	ReasonCode           string  `json:"reasonCode"`
	Explanation          string  `json:"explanation"`
	SuggestedRemediation string  `json:"suggestedRemediation,omitempty"`
	ReasoningChain       string  `json:"reasoningChain,omitempty"`
}

// Metrics tracks the execution overhead of the inference request.
type Metrics struct {
	LatencyMs        int64 `json:"latencyMs"`
	PromptTokens     int   `json:"promptTokens"`
	CompletionTokens int   `json:"completionTokens"`
}

// EngineInfo reports metadata about the backend model and runtime.
type EngineInfo struct {
	Backend     string `json:"backend"`
	ModelLoaded string `json:"modelLoaded"`
	ModelDigest string `json:"modelDigest,omitempty"`
}

// ResponseEnvelope is the standardized response structure for ISP.
type ResponseEnvelope struct {
	ProtocolVersion string          `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	Status          string          `json:"status"`
	ErrorMessage    string          `json:"errorMessage,omitempty"`
	Decision        *DecisionResult `json:"decision,omitempty"`
	Metrics         Metrics         `json:"metrics,omitempty"`
	EngineInfo      EngineInfo      `json:"engineInfo,omitempty"`
}
```

创建 `internal/inference/client.go`：
```go
package inference

import (
	"context"
)

// InferenceClient specifies the unified interface for model inference.
type InferenceClient interface {
	// VerifyFinding arbitrates a detected security finding.
	VerifyFinding(ctx context.Context, req *RequestEnvelope) (*ResponseEnvelope, error)

	// HealthCheck performs a readiness probe on the inference service.
	HealthCheck(ctx context.Context) error

	// Close releases any network or IPC resources.
	Close() error
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v ./internal/inference/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/inference/
git commit -m "feat(inference): define standardized protocol envelope and client interface"
```

---

### Task 2: 实现端点安全校验器 (`internal/inference/validator.go`)

**Files:**
- Create: `internal/inference/validator.go`
- Create: `internal/inference/validator_test.go`
- Test: `internal/inference/validator_test.go`

- [ ] **Step 1: 编写 `validator_test.go` 测试用例**

创建 `internal/inference/validator_test.go`：
```go
package inference_test

import (
	"testing"

	"taa/internal/inference"
)

func TestValidateEndpoint_Allowed(t *testing.T) {
	allowedList := []string{"127.0.0.1", "localhost", "inference-service"}
	v := inference.NewEndpointValidator(allowedList, false)

	validEndpoints := []string{
		"http://127.0.0.1:11434",
		"http://localhost:11434",
		"http://inference-service:8080/v1/generate",
		"unix:///run/taa/ipc/inference.sock",
	}

	for _, ep := range validEndpoints {
		if err := v.Validate(ep); err != nil {
			t.Errorf("expected endpoint %q to be valid, got: %v", ep, err)
		}
	}
}

func TestValidateEndpoint_Blocked(t *testing.T) {
	allowedList := []string{"127.0.0.1", "localhost"}
	v := inference.NewEndpointValidator(allowedList, false)

	blockedEndpoints := []string{
		"http://169.254.169.254/latest/meta-data", // Cloud metadata
		"http://evil.com:11434",                    // Unlisted domain
		"http://0.0.0.0:11434",                     // Any address
		"ftp://127.0.0.1:21",                       // Invalid scheme
		"gopher://127.0.0.1:70",                    // Dangerous scheme
		"",                                         // Empty
	}

	for _, ep := range blockedEndpoints {
		if err := v.Validate(ep); err == nil {
			t.Errorf("expected endpoint %q to be rejected, but passed", ep)
		}
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test -v ./internal/inference -run TestValidateEndpoint`
Expected: FAIL (undefined: NewEndpointValidator)

- [ ] **Step 3: 实现 `internal/inference/validator.go`**

创建 `internal/inference/validator.go`：
```go
package inference

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// EndpointValidator enforces SSRF defenses and host whitelisting.
type EndpointValidator struct {
	allowedHosts    map[string]struct{}
	blockPrivateIPs bool
}

// NewEndpointValidator constructs a validator with configured allowed hosts.
func NewEndpointValidator(allowedHosts []string, blockPrivateIPs bool) *EndpointValidator {
	hostMap := make(map[string]struct{}, len(allowedHosts))
	for _, h := range allowedHosts {
		trimmed := strings.ToLower(strings.TrimSpace(h))
		if trimmed != "" {
			hostMap[trimmed] = struct{}{}
		}
	}
	return &EndpointValidator{
		allowedHosts:    hostMap,
		blockPrivateIPs: blockPrivateIPs,
	}
}

// Validate checks whether an endpoint URL is secure and permitted.
func (v *EndpointValidator) Validate(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return errors.New("endpoint cannot be empty")
	}

	// Support unix domain sockets directly.
	if strings.HasPrefix(endpoint, "unix://") {
		path := strings.TrimPrefix(endpoint, "unix://")
		if path == "" {
			return errors.New("unix socket path cannot be empty")
		}
		return nil
	}

	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported protocol scheme %q: only http, https, and unix are allowed", scheme)
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return errors.New("endpoint host cannot be empty")
	}

	// Block cloud metadata services and any-addresses unconditionally.
	if hostname == "169.254.169.254" || hostname == "0.0.0.0" || hostname == "::" {
		return fmt.Errorf("access to restricted address %q is forbidden", hostname)
	}

	// Enforce allowed hosts whitelist if configured.
	if len(v.allowedHosts) > 0 {
		if _, ok := v.allowedHosts[hostname]; !ok {
			return fmt.Errorf("host %q is not in the allowed endpoint whitelist", hostname)
		}
	}

	// Optionally block private/internal IPs if strict external checking is required.
	if v.blockPrivateIPs {
		ip := net.ParseIP(hostname)
		if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
			return fmt.Errorf("private and loopback IP %q is blocked by security policy", hostname)
		}
	}

	return nil
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v ./internal/inference -run TestValidateEndpoint`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/inference/validator.go internal/inference/validator_test.go
git commit -m "feat(inference): implement endpoint security and SSRF validator"
```

---

### Task 3: 实现熔断器与重试引擎 (`internal/inference/circuit_breaker.go`)

**Files:**
- Create: `internal/inference/circuit_breaker.go`
- Create: `internal/inference/circuit_breaker_test.go`
- Test: `internal/inference/circuit_breaker_test.go`

- [ ] **Step 1: 编写 `circuit_breaker_test.go` 测试用例**

创建 `internal/inference/circuit_breaker_test.go`：
```go
package inference_test

import (
	"errors"
	"testing"
	"time"

	"taa/internal/inference"
)

func TestCircuitBreaker_StateTransitions(t *testing.T) {
	cb := inference.NewCircuitBreaker(3, 100*time.Millisecond)

	// Initially CLOSED
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to be CLOSED and allow requests")
	}

	// Record 3 failures
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	// Should transition to OPEN
	if cb.Allow() {
		t.Fatal("expected circuit breaker to be OPEN after 3 failures")
	}

	// Wait for cooldown
	time.Sleep(120 * time.Millisecond)

	// Should transition to HALF-OPEN (allow probe)
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to allow probe in HALF-OPEN")
	}

	// Record success -> transitions back to CLOSED
	cb.RecordSuccess()
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to be CLOSED after successful probe")
	}
}

func TestExecuteWithRetry_Success(t *testing.T) {
	attempts := 0
	op := func() error {
		attempts++
		if attempts < 2 {
			return inference.ErrRetryable
		}
		return nil
	}

	err := inference.ExecuteWithRetry(op, 2, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("expected retry to succeed, got: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestExecuteWithRetry_NonRetryable(t *testing.T) {
	attempts := 0
	op := func() error {
		attempts++
		return errors.New("fatal client error")
	}

	err := inference.ExecuteWithRetry(op, 3, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected non-retryable error to fail immediately")
	}
	if attempts != 1 {
		t.Fatalf("expected exactly 1 attempt for fatal error, got %d", attempts)
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test -v ./internal/inference -run TestCircuitBreaker`
Expected: FAIL (undefined: NewCircuitBreaker)

- [ ] **Step 3: 实现 `internal/inference/circuit_breaker.go`**

创建 `internal/inference/circuit_breaker.go`：
```go
package inference

import (
	"errors"
	"math/rand"
	"sync"
	"time"
)

// ErrRetryable indicates a transient failure that can be retried.
var ErrRetryable = errors.New("transient retryable error")

// ErrCircuitOpen is returned when requests are rejected by an open circuit breaker.
var ErrCircuitOpen = errors.New("circuit breaker is OPEN: inference service is unavailable")

// State represents the circuit breaker operational state.
type State int

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

// CircuitBreaker guards against cascading failures when inference backends degrade.
type CircuitBreaker struct {
	mu           sync.Mutex
	state        State
	failCount    int
	threshold    int
	cooldown     time.Duration
	lastFailTime time.Time
}

// NewCircuitBreaker constructs a CircuitBreaker instance.
func NewCircuitBreaker(threshold int, cooldown time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 3
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &CircuitBreaker{
		threshold: threshold,
		cooldown:  cooldown,
		state:     StateClosed,
	}
}

// Allow reports whether a new request is permitted to proceed.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if now.Sub(cb.lastFailTime) > cb.cooldown {
			cb.state = StateHalfOpen
			return true
		}
		return false
	case StateHalfOpen:
		return true
	default:
		return true
	}
}

// RecordSuccess transitions the circuit breaker back to Closed.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failCount = 0
	cb.state = StateClosed
}

// RecordFailure increments failure counts and opens the breaker if threshold is hit.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failCount++
	cb.lastFailTime = time.Now()
	if cb.failCount >= cb.threshold {
		cb.state = StateOpen
	}
}

// ExecuteWithRetry executes an operation with exponential backoff and jitter for retryable errors.
func ExecuteWithRetry(op func() error, maxRetries int, baseDelay time.Duration) error {
	var err error
	delay := baseDelay

	for attempt := 0; attempt <= maxRetries; attempt++ {
		err = op()
		if err == nil {
			return nil
		}

		// Only retry on transient/retryable errors.
		if !errors.Is(err, ErrRetryable) {
			return err
		}

		if attempt == maxRetries {
			break
		}

		// Add 20% jitter.
		jitter := float64(delay) * (0.8 + 0.4*rand.Float64())
		time.Sleep(time.Duration(jitter))
		delay *= 2
		if delay > 5*time.Second {
			delay = 5 * time.Second
		}
	}
	return err
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v ./internal/inference -run TestCircuitBreaker`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/inference/circuit_breaker.go internal/inference/circuit_breaker_test.go
git commit -m "feat(inference): implement circuit breaker and retry engine"
```

---

### Task 4: 实现 HTTP 与 UDS 客户端适配器 (`adapter_http.go`, `adapter_uds.go`)

**Files:**
- Create: `internal/inference/adapter_http.go`
- Create: `internal/inference/adapter_uds.go`
- Create: `internal/inference/factory.go`
- Create: `internal/inference/adapter_test.go`
- Test: `internal/inference/adapter_test.go`

- [ ] **Step 1: 编写适配器集成测试**

创建 `internal/inference/adapter_test.go`：
```go
package inference_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"taa/internal/inference"
)

func TestHTTPAdapter_VerifyFinding_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		resp := inference.ResponseEnvelope{
			ProtocolVersion: inference.CurrentProtocolVersion,
			RequestID:       "req-test-1",
			Status:          inference.StatusSuccess,
			Decision: &inference.DecisionResult{
				Verdict:    inference.VerdictBenign,
				Confidence: 0.9,
				RiskLevel:  "LOW",
				ReasonCode: "VALIDATED_SAFE",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	cfg := inference.Config{
		Transport: "http",
		Endpoint:  ts.URL,
		AuthToken: "test-token",
		Timeout:   2 * time.Second,
	}

	client, err := inference.NewClient(cfg)
	if err != nil {
		t.Fatalf("create client failed: %v", err)
	}
	defer client.Close()

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-test-1",
		Action:          inference.ActionVerifyFinding,
	}

	resp, err := client.VerifyFinding(context.Background(), req)
	if err != nil {
		t.Fatalf("verify finding failed: %v", err)
	}

	if resp.Decision.Verdict != inference.VerdictBenign {
		t.Errorf("got verdict %s, want %s", resp.Decision.Verdict, inference.VerdictBenign)
	}
}

func TestHTTPAdapter_HealthCheck(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := inference.Config{
		Transport: "http",
		Endpoint:  ts.URL,
		Timeout:   1 * time.Second,
	}

	client, err := inference.NewClient(cfg)
	if err != nil {
		t.Fatalf("create client failed: %v", err)
	}
	defer client.Close()

	if err := client.HealthCheck(context.Background()); err != nil {
		t.Errorf("health check failed: %v", err)
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test -v ./internal/inference -run TestHTTPAdapter`
Expected: FAIL (undefined: NewClient)

- [ ] **Step 3: 实现 `adapter_http.go`, `adapter_uds.go`, `factory.go`**

创建 `internal/inference/adapter_http.go`：
```go
package inference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPAdapter communicates with an inference gateway over HTTP/REST.
type HTTPAdapter struct {
	endpoint       string
	authToken      string
	client         *http.Client
	circuitBreaker *CircuitBreaker
	validator      *EndpointValidator
}

// NewHTTPAdapter creates an HTTP inference adapter.
func NewHTTPAdapter(endpoint, token string, timeout time.Duration, cb *CircuitBreaker, v *EndpointValidator) (*HTTPAdapter, error) {
	if err := v.Validate(endpoint); err != nil {
		return nil, fmt.Errorf("endpoint validation failed: %w", err)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &HTTPAdapter{
		endpoint:       endpoint,
		authToken:      token,
		client:         &http.Client{Timeout: timeout},
		circuitBreaker: cb,
		validator:      v,
	}, nil
}

// VerifyFinding sends a structured finding verification request.
func (a *HTTPAdapter) VerifyFinding(ctx context.Context, req *RequestEnvelope) (*ResponseEnvelope, error) {
	if !a.circuitBreaker.Allow() {
		return nil, ErrCircuitOpen
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var respEnv ResponseEnvelope
	retryOp := func() error {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/v1/verify", bytes.NewReader(body))
		if err != nil {
			return err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if a.authToken != "" {
			httpReq.Header.Set("Authorization", "Bearer "+a.authToken)
		}

		resp, err := a.client.Do(httpReq)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrRetryable, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return fmt.Errorf("%w: HTTP %d", ErrRetryable, resp.StatusCode)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("inference server returned HTTP %d", resp.StatusCode)
		}

		respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			return err
		}

		return json.Unmarshal(respBytes, &respEnv)
	}

	if err := ExecuteWithRetry(retryOp, 2, 200*time.Millisecond); err != nil {
		a.circuitBreaker.RecordFailure()
		return nil, err
	}

	a.circuitBreaker.RecordSuccess()
	return &respEnv, nil
}

// HealthCheck verifies availability of the HTTP endpoint.
func (a *HTTPAdapter) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Close releases resources.
func (a *HTTPAdapter) Close() error {
	a.client.CloseIdleConnections()
	return nil
}
```

创建 `internal/inference/adapter_uds.go`：
```go
package inference

import (
	"context"
	"net"
	"net/http"
	"time"
)

// NewUDSAdapter creates an inference adapter using Unix Domain Sockets.
func NewUDSAdapter(socketPath string, timeout time.Duration, cb *CircuitBreaker) (*HTTPAdapter, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial("unix", socketPath)
	}

	transport := &http.Transport{
		DialContext: dialer,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return &HTTPAdapter{
		endpoint:       "http://unix",
		client:         client,
		circuitBreaker: cb,
		validator:      NewEndpointValidator(nil, false),
	}, nil
}
```

创建 `internal/inference/factory.go`：
```go
package inference

import (
	"fmt"
	"strings"
	"time"
)

// Config defines client initialization settings.
type Config struct {
	Transport               string
	Endpoint                string
	UDSPath                 string
	AuthToken               string
	Timeout                 time.Duration
	AllowedHosts            []string
	CircuitBreakerThreshold int
	CooldownSec             int
}

// NewClient initializes an InferenceClient based on the supplied configuration.
func NewClient(cfg Config) (InferenceClient, error) {
	threshold := cfg.CircuitBreakerThreshold
	if threshold <= 0 {
		threshold = 3
	}
	cooldown := time.Duration(cfg.CooldownSec) * time.Second
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	cb := NewCircuitBreaker(threshold, cooldown)

	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	if transport == "uds" || (transport == "" && cfg.UDSPath != "") {
		return NewUDSAdapter(cfg.UDSPath, cfg.Timeout, cb)
	}

	validator := NewEndpointValidator(cfg.AllowedHosts, false)
	return NewHTTPAdapter(cfg.Endpoint, cfg.AuthToken, cfg.Timeout, cb, validator)
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v ./internal/inference -run TestHTTPAdapter`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/inference/adapter_http.go internal/inference/adapter_uds.go internal/inference/factory.go internal/inference/adapter_test.go
git commit -m "feat(inference): implement HTTP and UDS client adapters and factory"
```

---

### Task 5: 扩展 `internal/config` 支持推理通信配置并确保向后兼容

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: 编写配置向后兼容与新字段解析测试**

在 `internal/config/config_test.go` 中添加：
```go
func TestStartupConfig_InferenceOptions(t *testing.T) {
	jsonContent := `{
		"llm": {
			"enabled": true,
			"transport": "uds",
			"udsPath": "/run/taa/ipc/inference.sock",
			"endpoint": "http://127.0.0.1:11434",
			"model": "qwen2.5-coder:3b",
			"policy": "gate",
			"failClosed": true,
			"authToken": "secret-token",
			"requestTimeoutMs": 15000
		}
	}`

	tmpFile := filepath.Join(t.TempDir(), "taa-config.json")
	if err := os.WriteFile(tmpFile, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := config.LoadStartupConfig(tmpFile)
	if err != nil {
		t.Fatalf("load startup config: %v", err)
	}

	if cfg.LLMTransport != "uds" {
		t.Errorf("got transport %q, want 'uds'", cfg.LLMTransport)
	}
	if cfg.LLMUDSPath != "/run/taa/ipc/inference.sock" {
		t.Errorf("got udsPath %q", cfg.LLMUDSPath)
	}
	if cfg.LLMAuthToken != "secret-token" {
		t.Errorf("got token %q", cfg.LLMAuthToken)
	}
	if cfg.LLMTimeoutMs != 15000 {
		t.Errorf("got timeout %d", cfg.LLMTimeoutMs)
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test -v ./internal/config -run TestStartupConfig_InferenceOptions`
Expected: FAIL (unknown fields in StartupConfig)

- [ ] **Step 3: 修改 `internal/config/config.go` 补充字段**

在 `StartupConfig` 及 `startupLLMConfigFile` 中添加新配置字段，并在解析时赋予默认值（如 `LLMTransport` 缺省为 "http"）：
```go
// In StartupConfig:
LLMTransport string
LLMUDSPath   string
LLMAuthToken string
LLMTimeoutMs int64

// In startupLLMConfigFile:
Transport        string `json:"transport"`
UDSPath          string `json:"udsPath"`
AuthToken        string `json:"authToken"`
RequestTimeoutMs int64  `json:"requestTimeoutMs"`
```

- [ ] **Step 4: 运行所有配置测试验证通过**

Run: `go test -v ./internal/config/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): support transport, UDS path, and authentication for inference"
```

---

### Task 6: 重构 `internal/codeaudit` 对接 `internal/inference` 客户端

**Files:**
- Modify: `internal/codeaudit/llm.go`
- Modify: `internal/codeaudit/verifier.go`
- Modify: `internal/codeaudit/llm_test.go`
- Test: `internal/codeaudit/llm_test.go`

- [ ] **Step 1: 编写针对 `InferenceClient` 的 Verifier 单测**

在 `internal/codeaudit/llm_test.go` 中验证当 `InferenceClient` 判定为 `MALICIOUS` 时，`verifier` 正确阻断：
```go
type mockInferenceClient struct {
	verdict string
	err     error
}

func (m *mockInferenceClient) VerifyFinding(ctx context.Context, req *inference.RequestEnvelope) (*inference.ResponseEnvelope, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &inference.ResponseEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		Status:          inference.StatusSuccess,
		Decision: &inference.DecisionResult{
			Verdict:    m.verdict,
			Confidence: 0.9,
			RiskLevel:  "HIGH",
		},
	}, nil
}
func (m *mockInferenceClient) HealthCheck(ctx context.Context) error { return m.err }
func (m *mockInferenceClient) Close() error                           { return nil }
```

- [ ] **Step 2: 修改 `internal/codeaudit` 替换为新客户端接口**

重构 `internal/codeaudit/llm.go` 中的 `LLMClient` 适配层，桥接至 `inference.InferenceClient`；
重构 `internal/codeaudit/verifier.go`，在推理失败时严格执行 fail-closed 决策：
- 当 `policy == "gate"` 且遇到 `inference.ErrCircuitOpen` 或服务故障时，若命中 HIGH/MEDIUM 规则直接判定报告不通过，标记 `SERVICE_UNAVAILABLE`；
- 当 `policy == "assist"` 时，降级放行并标明 `llm_degraded: true`。

- [ ] **Step 3: 运行 `internal/codeaudit` 测试验证通过**

Run: `go test -v ./internal/codeaudit/...`
Expected: PASS

- [ ] **Step 4: 提交代码**

```bash
git add internal/codeaudit/llm.go internal/codeaudit/verifier.go internal/codeaudit/llm_test.go
git commit -m "refactor(codeaudit): migrate verifier to standardized inference client"
```

---

### Task 7: 移除 TAA 主程序内嵌推理进程管理并回归验证

**Files:**
- Modify: `internal/app/taa/app.go`
- Modify: `internal/app/taa/app_test.go`
- Modify: `deploy.sh`
- Modify: `TODO`
- Test: `go test ./...`

- [ ] **Step 1: 修改 `internal/app/taa/app.go`**

- 移除 `ensureQwenAvailable`、`isOllamaReady` 等拉起 `start-ollama.sh` 的逻辑；
- 初始化 `inference.NewClient(cfg)`，仅在启动阶段执行健康心跳探针，若不可用仅打印日志警告或退出（依据 FailClosed 设定）。

- [ ] **Step 2: 修改 `deploy.sh` 解耦启动脚本**

移除 `deploy.sh` 中强行在 TAA 容器内后台启动 Ollama 并写 `/tmp/ollama.log` 的逻辑，保持独立容器编排设计。

- [ ] **Step 3: 更新 `TODO` 任务清单**

在 `TODO` 文件中将 `TAA 与 Qwen 推理引擎完全独立解耦 + 标准化通信协议` 标记为已完成 `[x]`。

- [ ] **Step 4: 执行全量测试套件验证**

Run: `go test -v ./...`
Expected: 全部测试通过，无编译失败或回归破坏。

- [ ] **Step 5: 提交代码**

```bash
git add internal/app/taa/app.go internal/app/taa/app_test.go deploy.sh TODO
git commit -m "refactor(taa): decouple embedded inference subprocess and align lifecycle"
```
