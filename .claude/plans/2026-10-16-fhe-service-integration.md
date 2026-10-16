# FHE 服务接入 TAA 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 TAA 在 `server.type=fhe` 下作为编排网关把 Latti FHE 服务接入现有 import/switch/export 契约，并让 platform-mock 在没有 GPU 的机器上也能跑通全链。

**Architecture:** 新增 `internal/fhe` 包承载 FHE 契约的全部逻辑（目录布局、公钥内容寻址缓存、`/api/v1` 客户端、任务编排与终态状态机、回调幂等）。控制器只在 `processImportedResource` 里加一个分支，把 FHE 当成与 `executeTraining` 平级的一支执行后端；`import` 落盘即触发任务，回调优先、轮询兜底；结果原样落 `ResultDir` 并复用 `buildAndSaveTrainingReport`，因此 `export` 无需改动即能取到产物。

**Tech Stack:** Go 1.22（`CGO_ENABLED=0 GOOS=linux` 静态构建）、标准库 `net/http` + `httptest`、SM3（`taa/pkg/crypto`）、`taa/internal/resource` 下载器、`go test`。

**规范来源：** `.claude/specs/2026-10-16-fhe-service-integration-design.md`（已确认）。本计划实现该 spec 的全部内容，不做 spec 之外的重构。

---

## 文件结构

| 文件 | 职责 |
|---|---|
| `internal/fhe/layout.go`（新建） | 共享目录契约：标识符严格校验 + 路径构造。纯函数，无 I/O。 |
| `internal/fhe/config.go`（新建） | `fhe.Config` 运行期配置 + `Validate()` + 回调 token 常数时间比对。 |
| `internal/fhe/client.go`（新建） | FHE `/api/v1` 客户端：health / models / activate / tasks / cancel / continue / results download。 |
| `internal/fhe/keycache.go`（新建） | 内容寻址公钥缓存：命中判定、下载、SM3 校验、原子落盘。 |
| `internal/fhe/runner.go`（新建） | 单任务编排 + 终态状态机 + 回调幂等。 |
| `internal/fhe/client_test.go`、`layout_test.go`、`keycache_test.go`、`runner_test.go`（新建） | 单测 + `httptest` fake FHE server 契约测试。 |
| `internal/config/config.go`（改） | `server.type` 解析与校验；新增 `fhe` 段。 |
| `internal/config/fhe_config_test.go`（新建） | 配置校验单测。 |
| `internal/controller/route.go`（改） | `TAAState.FHE` / `fheActiveTaskID` 字段、`SetFHERunner`、`fheEnabled()`。 |
| `internal/controller/handler_task.go`（改） | `importRequest` 加两字段；两个 handler 的分支校验。 |
| `internal/controller/fhe_processing.go`（新建） | FHE 模型落盘与 FHE 任务执行（含跳过泄露检查的裁决落盘）。 |
| `internal/controller/fhe_callback.go`（新建） | 回调端点 handler。 |
| `internal/controller/router.go`（改） | 注册 `/v1/taa/fheCallback`。 |
| `internal/controller/handler_export.go`（改） | FHE 实例忽略请求携带的 `publicKey`。 |
| `internal/controller/handler_task.go` `stopTrainingHandler`（改） | FHE 任务映射到 `/tasks/{id}/cancel`。 |
| `internal/app/taa/app.go`（改） | 装配 runner；`type=fhe` 跳过启动期证明。 |
| `configs/taa-fhe.json`（新建） | FHE 实例配置模板。 |
| `deploy-fhe.sh`（新建） | GPU 节点 FHE 侧部署脚本。 |
| `tools/platform-mock/internal/handlers_fhe.go`（新建） | mock 侧"提交 FHE 任务"端点。 |
| `tools/fake-fhe/`（新建） | 无 GPU 机器上扮演 `/api/v1` 的假服务端。 |
| `README.md`（改） | 配置字段表补 `server.type` 与 `fhe` 段。 |

---

## Task 1: `internal/fhe` 包骨架与目录契约

**Files:**
- Create: `internal/fhe/layout.go`
- Test: `internal/fhe/layout_test.go`

标识符校验是安全边界：`evalKeyFileHash` 与 `modelHash` 直接当目录名用，平台传 `../../etc` 就能把文件写出去。先做这个，后面所有文件都依赖它。

- [ ] **Step 1: 写失败的测试**

创建 `internal/fhe/layout_test.go`：

```go
package fhe

import "testing"

const (
	testHashA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testHashB = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func TestValidHashRejectsUnsafeIdentifiers(t *testing.T) {
	bad := []string{
		"",
		"../../etc",
		"..",
		".",
		"/etc/passwd",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",   // 63
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", // 65
		"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",  // uppercase
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",  // non-hex
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde/",
		"0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef",
	}
	for _, s := range bad {
		if ValidHash(s) {
			t.Errorf("ValidHash(%q) = true, want false", s)
		}
	}
	if !ValidHash(testHashA) {
		t.Errorf("ValidHash(%q) = false, want true", testHashA)
	}
}

func TestValidTaskID(t *testing.T) {
	good := []string{"task-1", "task_1", "task.1", "T1", "a"}
	for _, s := range good {
		if err := ValidTaskID(s); err != nil {
			t.Errorf("ValidTaskID(%q) = %v, want nil", s, err)
		}
	}
	bad := []string{"", "..", ".", "../x", "a/b", "a\\b", "a b", "a\x00b", string(make([]byte, 200))}
	for _, s := range bad {
		if err := ValidTaskID(s); err == nil {
			t.Errorf("ValidTaskID(%q) = nil, want error", s)
		}
	}
}

func TestLayoutPaths(t *testing.T) {
	l := NewLayout("/data")

	cases := []struct {
		name string
		got  string
		err  error
		want string
	}{
		{"ModelDir", "", nil, "/data/models/" + testHashA},
		{"KeyDir", "", nil, "/data/keys/" + testHashA},
		{"KeyPath", "", nil, "/data/keys/" + testHashA + "/eval_context.bin"},
		{"TaskDir", "", nil, "/data/tasks/task-1"},
		{"TaskInputPath", "", nil, "/data/tasks/task-1/input.zip"},
		{"ResultPath", "", nil, "/data/results/task-1/output.zip"},
	}
	var err error
	cases[0].got, cases[0].err = l.ModelDir(testHashA)
	cases[1].got, cases[1].err = l.KeyDir(testHashA)
	cases[2].got, cases[2].err = l.KeyPath(testHashA)
	cases[3].got, cases[3].err = l.TaskDir("task-1")
	cases[4].got, cases[4].err = l.TaskInputPath("task-1")
	cases[5].got, cases[5].err = l.ResultPath("task-1")

	for _, c := range cases {
		if c.err != nil {
			t.Fatalf("%s: unexpected error: %v", c.name, c.err)
		}
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	if _, err = l.KeyPath("../escape"); err == nil {
		t.Error("KeyPath accepted a traversal hash, want error")
	}
	if _, err = l.ModelDir(testHashB); err != nil {
		t.Errorf("ModelDir(%q) = %v, want nil", testHashB, err)
	}
	if _, err = l.TaskInputPath("../escape"); err == nil {
		t.Error("TaskInputPath accepted a traversal task id, want error")
	}
}

func TestLayoutRejectsEmptyRoot(t *testing.T) {
	if _, err := NewLayout("").KeyPath(testHashA); err == nil {
		t.Error("empty data dir accepted, want error")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/fhe/... -run 'TestValidHash|TestValidTaskID|TestLayout' -v`
Expected: FAIL — `no required module provides package taa/internal/fhe` / undefined symbols.

- [ ] **Step 3: 写实现**

创建 `internal/fhe/layout.go`：

```go
// Package fhe drives the Latti FHE service from TAA.
//
// The service exposes a small HTTP surface under /api/v1 and no upload
// endpoint at all: it reads its inputs from a fixed directory layout on local
// disk and writes its results back there. Everything in this package exists to
// honour that contract - build the paths, publish the inputs, create the task,
// wait for the terminal state, and hand the result back.
package fhe

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const evalKeyFileName = "eval_context.bin"

// sm3HexPattern matches an SM3 digest: exactly 64 lowercase hex characters.
//
// This is a security boundary, not a formatting preference. Both the eval key
// digest and the model digest are used verbatim as directory names, so a value
// outside this set ("../../etc", an absolute path, a name with a separator)
// would let a caller write and read outside the shared data directory. Every
// path builder in this file runs its identifier through here first.
var sm3HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// taskIDPattern bounds a task id to a single, portable path segment.
var taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidHash reports whether s is a usable SM3 hex digest.
func ValidHash(s string) bool {
	return sm3HexPattern.MatchString(s)
}

// ValidTaskID rejects a task id that is not a single safe path segment.
func ValidTaskID(s string) error {
	if !taskIDPattern.MatchString(s) {
		return fmt.Errorf("invalid task id %q: want 1-128 characters of [A-Za-z0-9._-] starting with an alphanumeric", s)
	}
	return nil
}

// Layout builds paths inside the directory TAA and the FHE service share.
//
// Both processes must see the same absolute paths - the contract is a bind
// mount, and a path that resolves differently on either side silently makes the
// service read nothing.
type Layout struct {
	dataDir string
}

// NewLayout returns the layout rooted at dataDir, which must be non-empty.
func NewLayout(dataDir string) Layout {
	return Layout{dataDir: strings.TrimSpace(dataDir)}
}

// DataDir returns the shared root.
func (l Layout) DataDir() string { return l.dataDir }

func (l Layout) root() (string, error) {
	if l.dataDir == "" {
		return "", fmt.Errorf("fhe data dir is empty")
	}
	return l.dataDir, nil
}

func (l Layout) join(parts ...string) (string, error) {
	root, err := l.root()
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{root}, parts...)...), nil
}

// ModelDir is <data>/models/<modelHash>, the parent of the server/ directory the
// service activates. The digest is the model registry id.
func (l Layout) ModelDir(modelHash string) (string, error) {
	if !ValidHash(modelHash) {
		return "", fmt.Errorf("invalid model hash %q: want 64 lowercase hex characters", modelHash)
	}
	return l.join("models", modelHash)
}

// KeyDir is <data>/keys/<userID>. Note the absence of a model id: one eval
// context serves every model, because they all share the same FHE parameter set.
func (l Layout) KeyDir(userID string) (string, error) {
	if !ValidHash(userID) {
		return "", fmt.Errorf("invalid user id %q: want 64 lowercase hex characters", userID)
	}
	return l.join("keys", userID)
}

// KeyPath is the file the service reads: <data>/keys/<userID>/eval_context.bin.
func (l Layout) KeyPath(userID string) (string, error) {
	dir, err := l.KeyDir(userID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, evalKeyFileName), nil
}

// TaskDir is <data>/tasks/<taskID>.
func (l Layout) TaskDir(taskID string) (string, error) {
	if err := ValidTaskID(taskID); err != nil {
		return "", err
	}
	return l.join("tasks", taskID)
}

// TaskInputPath is the input archive the service reads for a task.
func (l Layout) TaskInputPath(taskID string) (string, error) {
	dir, err := l.TaskDir(taskID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "input.zip"), nil
}

// ResultPath is the archive the service writes for a task.
func (l Layout) ResultPath(taskID string) (string, error) {
	if err := ValidTaskID(taskID); err != nil {
		return "", err
	}
	return l.join("results", taskID, "output.zip")
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/fhe/... -run 'TestValidHash|TestValidTaskID|TestLayout' -v`
Expected: PASS（4 个测试）。

- [ ] **Step 5: 提交**

```bash
git add internal/fhe/layout.go internal/fhe/layout_test.go
git commit -m "feat(fhe): add the shared-directory layout and identifier validation"
```

---

## Task 2: `fhe.Config`

**Files:**
- Create: `internal/fhe/config.go`
- Test: `internal/fhe/config_test.go`

- [ ] **Step 1: 写失败的测试**

创建 `internal/fhe/config_test.go`：

```go
package fhe

import (
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		Endpoint:              "http://127.0.0.1:58996",
		DataDir:               "/opt/fhe-data",
		KeyCacheDir:           "/root/taa/fhe-keys",
		CallbackBaseURL:       "http://172.16.10.130:6001",
		CallbackToken:         "s3cret",
		MaxEvalKeyBytes:       DefaultMaxEvalKeyBytes,
		PollInterval:          DefaultPollInterval,
		RequestTimeout:        DefaultRequestTimeout,
		TaskTimeout:           DefaultTaskTimeout,
		ActivateModelOnImport: true,
	}
}

func TestConfigValidateAcceptsCompleteConfig(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestConfigValidateRejectsMissingRequiredFields(t *testing.T) {
	mutators := map[string]func(*Config){
		"endpoint":         func(c *Config) { c.Endpoint = "" },
		"dataDir":          func(c *Config) { c.DataDir = "  " },
		"keyCacheDir":      func(c *Config) { c.KeyCacheDir = "" },
		"callbackBaseUrl":  func(c *Config) { c.CallbackBaseURL = "" },
		"callbackToken":    func(c *Config) { c.CallbackToken = "" },
	}
	for name, mutate := range mutators {
		c := validConfig()
		mutate(&c)
		err := c.Validate()
		if err == nil {
			t.Errorf("missing %s: Validate() = nil, want error", name)
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("missing %s: error %q does not name the field", name, err)
		}
	}
}

func TestConfigValidateRejectsBadBounds(t *testing.T) {
	negative := validConfig()
	negative.MaxEvalKeyBytes = 0
	if err := negative.Validate(); err == nil {
		t.Error("maxEvalKeyBytes=0 accepted, want error")
	}

	badEndpoint := validConfig()
	badEndpoint.Endpoint = "127.0.0.1:58996"
	if err := badEndpoint.Validate(); err == nil {
		t.Error("endpoint without a scheme accepted, want error")
	}

	badPoll := validConfig()
	badPoll.PollInterval = 0
	if err := badPoll.Validate(); err == nil {
		t.Error("pollInterval=0 accepted, want error")
	}

	badTimeout := validConfig()
	badTimeout.TaskTimeout = 0
	if err := badTimeout.Validate(); err == nil {
		t.Error("taskTimeout=0 accepted, want error")
	}
}

func TestConfigTokenMatches(t *testing.T) {
	c := validConfig()
	if !c.TokenMatches("s3cret") {
		t.Error("TokenMatches(exact) = false, want true")
	}
	for _, bad := range []string{"", "s3cre", "s3cret ", "S3CRET", "s3cretx"} {
		if c.TokenMatches(bad) {
			t.Errorf("TokenMatches(%q) = true, want false", bad)
		}
	}
	empty := validConfig()
	empty.CallbackToken = ""
	if empty.TokenMatches("") {
		t.Error("an unset token must not match an empty presented token")
	}
}

func TestConfigCallbackURL(t *testing.T) {
	c := validConfig()
	got := c.CallbackURL()
	want := "http://172.16.10.130:6001/v1/taa/fheCallback?token=s3cret"
	if got != want {
		t.Errorf("CallbackURL() = %q, want %q", got, want)
	}

	c.CallbackBaseURL = "http://172.16.10.130:6001/"
	if got := c.CallbackURL(); got != want {
		t.Errorf("CallbackURL() with a trailing slash = %q, want %q", got, want)
	}
}

func TestConfigDefaults(t *testing.T) {
	if DefaultMaxEvalKeyBytes != int64(6)<<30 {
		t.Errorf("DefaultMaxEvalKeyBytes = %d, want %d", DefaultMaxEvalKeyBytes, int64(6)<<30)
	}
	// The default must stay above the measured eval_context.bin (3,329,929,205 B)
	// and must not be confused with codeAudit.resultCheck.maxFileBytes (3 GiB),
	// which is 103.7 MiB too small to download a real key.
	if DefaultMaxEvalKeyBytes <= 3329929205 {
		t.Errorf("DefaultMaxEvalKeyBytes = %d, must exceed the measured key size 3329929205", DefaultMaxEvalKeyBytes)
	}
	if DefaultPollInterval != 5*time.Second || DefaultTaskTimeout != 30*time.Minute {
		t.Errorf("unexpected defaults: poll=%s task=%s", DefaultPollInterval, DefaultTaskTimeout)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/fhe/... -run 'TestConfig' -v`
Expected: FAIL — undefined `Config`, `DefaultMaxEvalKeyBytes`, `TokenMatches`, `CallbackURL`.

- [ ] **Step 3: 写实现**

创建 `internal/fhe/config.go`：

```go
package fhe

import (
	"crypto/subtle"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultMaxEvalKeyBytes bounds the eval key download.
	//
	// This cap must stay separate from codeAudit.resultCheck.maxFileBytes. That
	// setting is the import download cap and defaults to 3 GiB, while a measured
	// eval_context.bin is 3,329,929,205 B - 103.7 MiB over. Reusing it makes the
	// key impossible to download at all. 6 GiB leaves room for parameter growth
	// while remaining a finite bound.
	DefaultMaxEvalKeyBytes = int64(6) << 30 // 6442450944

	DefaultPollInterval   = 5 * time.Second
	DefaultRequestTimeout = 30 * time.Second
	DefaultTaskTimeout    = 30 * time.Minute
)

// Config is the runtime configuration of the FHE integration on a
// server.type=fhe instance.
type Config struct {
	// Endpoint is the FHE API base, e.g. http://127.0.0.1:58996.
	Endpoint string
	// DataDir is the shared directory: the local path of the same bind mount the
	// FHE containers see as /data.
	DataDir string
	// KeyCacheDir holds eval keys by content digest, so a repeat user never
	// re-downloads several gigabytes.
	KeyCacheDir string
	// CallbackBaseURL is how the FHE service reaches this TAA instance, e.g.
	// http://172.16.10.130:6001.
	CallbackBaseURL string
	// CallbackToken authenticates the callback endpoint. An unauthenticated
	// callback endpoint is open to every process on the host, so an empty token
	// is refused rather than defaulted.
	CallbackToken string
	// MaxEvalKeyBytes bounds the eval key download; see DefaultMaxEvalKeyBytes.
	MaxEvalKeyBytes int64
	// PollInterval is the fallback poll period while waiting for a task.
	PollInterval time.Duration
	// RequestTimeout bounds one HTTP call to the FHE service.
	RequestTimeout time.Duration
	// TaskTimeout bounds a whole task, polls and callback together.
	TaskTimeout time.Duration
	// ActivateModelOnImport calls /models/activate right after a model is staged.
	ActivateModelOnImport bool
}

// Validate rejects a configuration this package cannot safely run with. It is
// deliberately strict: a half-configured FHE instance would fail at task time,
// after the platform has already been told the import succeeded.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return fmt.Errorf("fhe.endpoint is required")
	}
	u, err := url.Parse(strings.TrimSpace(c.Endpoint))
	if err != nil {
		return fmt.Errorf("fhe.endpoint %q is not a valid URL: %w", c.Endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("fhe.endpoint %q must use the http or https scheme", c.Endpoint)
	}
	if u.Host == "" {
		return fmt.Errorf("fhe.endpoint %q has no host", c.Endpoint)
	}
	if strings.TrimSpace(c.DataDir) == "" {
		return fmt.Errorf("fhe.dataDir is required")
	}
	if strings.TrimSpace(c.KeyCacheDir) == "" {
		return fmt.Errorf("fhe.keyCacheDir is required")
	}
	if strings.TrimSpace(c.CallbackBaseURL) == "" {
		return fmt.Errorf("fhe.callbackBaseUrl is required")
	}
	if strings.TrimSpace(c.CallbackToken) == "" {
		return fmt.Errorf("fhe.callbackToken is required")
	}
	if c.MaxEvalKeyBytes <= 0 {
		return fmt.Errorf("fhe.maxEvalKeyBytes must be positive, got %d", c.MaxEvalKeyBytes)
	}
	if c.PollInterval <= 0 {
		return fmt.Errorf("fhe.pollIntervalMs must be positive, got %s", c.PollInterval)
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("fhe.requestTimeoutMs must be positive, got %s", c.RequestTimeout)
	}
	if c.TaskTimeout <= 0 {
		return fmt.Errorf("fhe.taskTimeoutMs must be positive, got %s", c.TaskTimeout)
	}
	return nil
}

// TokenMatches compares a presented callback token against the configured one in
// constant time, so the comparison leaks nothing about how much of a guess was
// correct. An unconfigured token never matches, not even an empty presented one.
func (c Config) TokenMatches(presented string) bool {
	if c.CallbackToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(c.CallbackToken)) == 1
}

// CallbackURL is the URL handed to the FHE service so it can report a terminal
// state back to this instance.
func (c Config) CallbackURL() string {
	return strings.TrimRight(strings.TrimSpace(c.CallbackBaseURL), "/") +
		"/v1/taa/fheCallback?token=" + url.QueryEscape(c.CallbackToken)
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/fhe/... -run 'TestConfig' -v`
Expected: PASS（6 个测试）。

- [ ] **Step 5: 提交**

```bash
git add internal/fhe/config.go internal/fhe/config_test.go
git commit -m "feat(fhe): add the FHE runtime config with startup validation"
```

---

## Task 3: `/api/v1` 客户端

**Files:**
- Create: `internal/fhe/client.go`
- Test: `internal/fhe/client_test.go`

`GET /tasks/{id}` 的逐 case 结构在交付包里没有文档（只文档了回调里的 `status` / `entry` / `result_id` / `error` / `result_zip`）。因此客户端把 `status` 当承重字段，逐 case 只做尽力解析：解析不到只影响进度百分比，不影响成败判定。任务最终仍由 `TaskTimeout` 兜底，未知状态不会让任务永远挂住。

- [ ] **Step 1: 写失败的测试**

创建 `internal/fhe/client_test.go`：

```go
package fhe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, srv
}

func TestNewClientRejectsBadEndpoint(t *testing.T) {
	for _, bad := range []string{"", "   ", "127.0.0.1:58996", "ftp://host/api", "http://"} {
		if _, err := NewClient(bad, time.Second); err == nil {
			t.Errorf("NewClient(%q) = nil error, want error", bad)
		}
	}
}

func TestNewClientAcceptsEndpointWithOrWithoutPrefix(t *testing.T) {
	for _, raw := range []string{"http://h:1", "http://h:1/", "http://h:1/api/v1"} {
		c, err := NewClient(raw, time.Second)
		if err != nil {
			t.Fatalf("NewClient(%q): %v", raw, err)
		}
		if c.baseURL != "http://h:1/api/v1" {
			t.Errorf("NewClient(%q).baseURL = %q, want %q", raw, c.baseURL, "http://h:1/api/v1")
		}
	}
}

func TestCreateTaskSendsUserHeaderAndBody(t *testing.T) {
	var gotBody map[string]any
	var gotUser string

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tasks" {
			t.Errorf("path = %q, want /api/v1/tasks", r.URL.Path)
		}
		gotUser = r.Header.Get("X-User-Id")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"task_id":"task-1","status":"queued"}`))
	})

	req := CreateTaskRequest{
		UserID:             testHashA,
		ModelID:            testHashB,
		TaskID:             "task-1",
		CallbackURL:        "http://taa/v1/taa/fheCallback?token=x",
		CancelOnDisconnect: false,
	}
	if err := c.CreateTask(context.Background(), req); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if gotUser != testHashA {
		t.Errorf("X-User-Id = %q, want %q", gotUser, testHashA)
	}
	for k, want := range map[string]any{
		"user_id": testHashA, "model_id": testHashB, "task_id": "task-1",
		"callback_url": "http://taa/v1/taa/fheCallback?token=x", "cancel_on_disconnect": false,
	} {
		if got := gotBody[k]; got != want {
			t.Errorf("body[%q] = %v, want %v", k, got, want)
		}
	}
}

func TestCreateTaskSurfacesNon2xx(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	err := c.CreateTask(context.Background(), CreateTaskRequest{TaskID: "t", UserID: testHashA})
	if err == nil {
		t.Fatal("CreateTask = nil, want error")
	}
	var apiErr *APIError
	if !asAPIError(err, &apiErr) {
		t.Fatalf("error %v is not an *APIError", err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Error(), "boom") {
		t.Errorf("error %q does not carry the response body", apiErr.Error())
	}
}

func TestTaskParsesCasesAndProgress(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tasks/task-1" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"task_id":"task-1","status":"running","cases":[
			{"entry":"case-00.ct","result_id":"case-00.result.bin"},
			{"entry":"case-01.ct"},
			{"entry":"case-02.ct","error":"oops"}]}`))
	})
	st, err := c.Task(context.Background(), "task-1", testHashA)
	if err != nil {
		t.Fatalf("Task: %v", err)
	}
	if st.Status != "running" {
		t.Errorf("Status = %q, want running", st.Status)
	}
	done, total := st.Progress()
	if done != 2 || total != 3 {
		t.Errorf("Progress() = (%d, %d), want (2, 3)", done, total)
	}
	if failed := st.Failed(); failed != 1 {
		t.Errorf("Failed() = %d, want 1", failed)
	}
}

func TestTaskToleratesUnknownShape(t *testing.T) {
	// The per-case shape on GET /tasks/{id} is not documented. An unrecognised
	// body must still yield the status, and progress must degrade to (0, 0)
	// rather than fail the call.
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"task_id":"task-1","status":"completed","whatever":{"nested":true}}`))
	})
	st, err := c.Task(context.Background(), "task-1", testHashA)
	if err != nil {
		t.Fatalf("Task: %v", err)
	}
	if st.Status != "completed" {
		t.Errorf("Status = %q, want completed", st.Status)
	}
	if done, total := st.Progress(); done != 0 || total != 0 {
		t.Errorf("Progress() = (%d, %d), want (0, 0)", done, total)
	}
}

func TestTaskFallsBackToResultsKey(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"completed","results":[{"entry":"a","result_id":"a.bin"}]}`))
	})
	st, err := c.Task(context.Background(), "task-1", testHashA)
	if err != nil {
		t.Fatalf("Task: %v", err)
	}
	if done, total := st.Progress(); done != 1 || total != 1 {
		t.Errorf("Progress() = (%d, %d), want (1, 1)", done, total)
	}
}

func TestActivateModelAndHealth(t *testing.T) {
	var activateQuery string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/models/activate":
			activateQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})
	ctx := context.Background()
	if err := c.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if err := c.ActivateModel(ctx, testHashB); err != nil {
		t.Fatalf("ActivateModel: %v", err)
	}
	if activateQuery != "model_id="+testHashB {
		t.Errorf("activate query = %q, want %q", activateQuery, "model_id="+testHashB)
	}
}

func TestCancelAndContinue(t *testing.T) {
	var paths []string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		_, _ = w.Write([]byte(`{}`))
	})
	ctx := context.Background()
	if err := c.CancelTask(ctx, "task-1", testHashA); err != nil {
		t.Fatalf("CancelTask: %v", err)
	}
	if err := c.ContinueTask(ctx, "task-1", testHashA); err != nil {
		t.Fatalf("ContinueTask: %v", err)
	}
	want := []string{"POST /api/v1/tasks/task-1/cancel", "POST /api/v1/tasks/task-1/continue"}
	if len(paths) != 2 || paths[0] != want[0] || paths[1] != want[1] {
		t.Errorf("paths = %v, want %v", paths, want)
	}
}

func TestDownloadResultWritesFile(t *testing.T) {
	payload := []byte("zip-bytes")
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tasks/task-1/results/download" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write(payload)
	})
	dst := filepath.Join(t.TempDir(), "out", "output.zip")
	if err := c.DownloadResult(context.Background(), "task-1", testHashA, dst); err != nil {
		t.Fatalf("DownloadResult: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("result = %q, want %q", got, payload)
	}
}

func TestIsTerminalAndIsSuccess(t *testing.T) {
	terminal := []string{"completed", "succeeded", "failed", "error", "cancelled", "canceled", "timeout", "expired", " COMPLETED "}
	for _, s := range terminal {
		if !IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "queued", "running", "pending", "unknown"} {
		if IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = true, want false", s)
		}
	}
	for _, s := range []string{"completed", "succeeded", "SUCCESS"} {
		if !IsSuccess(s) {
			t.Errorf("IsSuccess(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"failed", "cancelled", ""} {
		if IsSuccess(s) {
			t.Errorf("IsSuccess(%q) = true, want false", s)
		}
	}
}
```

测试里用了 `asAPIError` 与 `APIError`，Step 3 一并实现。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/fhe/... -run 'TestNewClient|TestCreateTask|TestTask|TestActivate|TestCancel|TestDownload|TestIsTerminal' -v`
Expected: FAIL — undefined `Client`、`APIError`、`CreateTaskRequest`。

- [ ] **Step 3: 写实现**

创建 `internal/fhe/client.go`：

```go
package fhe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxErrorBodyBytes bounds how much of an error response is copied into an error
// message.
const maxErrorBodyBytes = 4 << 10

// APIError is a non-2xx answer from the FHE service.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	body := strings.TrimSpace(e.Body)
	if body == "" {
		return fmt.Sprintf("fhe %s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	}
	return fmt.Sprintf("fhe %s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, body)
}

func asAPIError(err error, target **APIError) bool {
	return errors.As(err, target)
}

// Client talks to the FHE service's /api/v1 surface.
//
// Only the calls TAA makes are implemented. The service is unauthenticated and
// takes the tenant from the X-User-Id header, so every task-scoped call carries
// the eval key digest as that header.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient returns a client for endpoint, which may or may not already carry
// the /api/v1 prefix.
func NewClient(endpoint string, timeout time.Duration) (*Client, error) {
	raw := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if raw == "" {
		return nil, fmt.Errorf("fhe endpoint is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse fhe endpoint %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("fhe endpoint %q must use the http or https scheme", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("fhe endpoint %q has no host", raw)
	}
	base := raw
	if !strings.HasSuffix(base, "/api/v1") {
		base += "/api/v1"
	}
	return &Client{baseURL: base, http: &http.Client{Timeout: timeout}}, nil
}

func (c *Client) do(ctx context.Context, method, path, userID string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode fhe %s %s body: %w", method, path, err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build fhe %s %s request: %w", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if userID != "" {
		req.Header.Set("X-User-Id", userID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fhe %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: string(snippet)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode fhe %s %s response: %w", method, path, err)
	}
	return nil
}

// Health checks that the service answers.
func (c *Client) Health(ctx context.Context) error {
	var st map[string]any
	return c.do(ctx, http.MethodGet, "/health", "", nil, &st)
}

// ActivateModel asks the service to scan and hot-load a model. The call is
// idempotent, so it may be repeated.
func (c *Client) ActivateModel(ctx context.Context, modelID string) error {
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/models/activate?model_id="+url.QueryEscape(modelID), "", nil, &st)
}

// CreateTaskRequest is the body of POST /tasks.
type CreateTaskRequest struct {
	UserID             string `json:"user_id"`
	ModelID            string `json:"model_id"`
	TaskID             string `json:"task_id"`
	CallbackURL        string `json:"callback_url"`
	CancelOnDisconnect bool   `json:"cancel_on_disconnect"`
}

// CreateTask submits a task. The input package must already be on disk.
func (c *Client) CreateTask(ctx context.Context, req CreateTaskRequest) error {
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/tasks", req.UserID, req, &st)
}

// CaseStatus is one entry of a task's case list.
type CaseStatus struct {
	Entry    string `json:"entry"`
	ResultID string `json:"result_id"`
	Error    string `json:"error"`
}

// TaskStatus is what the service reports for a task.
//
// Only Status is load-bearing: it is the field the service's own callback
// documents. The per-case list feeds percentage reporting alone, so an
// unrecognised shape degrades progress reporting without touching the outcome -
// a task whose status never becomes terminal still ends at TaskTimeout.
type TaskStatus struct {
	TaskID    string       `json:"task_id"`
	Status    string       `json:"status"`
	ResultZip string       `json:"result_zip"`
	Cases     []CaseStatus `json:"cases"`
	Results   []CaseStatus `json:"results"`
}

func (t TaskStatus) caseList() []CaseStatus {
	if len(t.Cases) > 0 {
		return t.Cases
	}
	return t.Results
}

// Progress returns the finished case count and the total the service reported.
// Both are zero when no case list was recognised.
func (t TaskStatus) Progress() (done, total int) {
	cases := t.caseList()
	for _, c := range cases {
		if c.ResultID != "" || c.Error != "" {
			done++
		}
	}
	return done, len(cases)
}

// Failed returns the number of cases the service reported as failed.
func (t TaskStatus) Failed() int {
	n := 0
	for _, c := range t.caseList() {
		if c.Error != "" {
			n++
		}
	}
	return n
}

// Task fetches a task's state.
func (c *Client) Task(ctx context.Context, taskID, userID string) (TaskStatus, error) {
	var st TaskStatus
	err := c.do(ctx, http.MethodGet, "/tasks/"+url.PathEscape(taskID), userID, nil, &st)
	return st, err
}

// CancelTask maps TAA's stopTraining onto the service's cancel endpoint.
func (c *Client) CancelTask(ctx context.Context, taskID, userID string) error {
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/tasks/"+url.PathEscape(taskID)+"/cancel", userID, nil, &st)
}

// ContinueTask re-runs the unfinished cases of a task that already exists, which
// is how a replayed import is retried instead of creating a second task.
func (c *Client) ContinueTask(ctx context.Context, taskID, userID string) error {
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/tasks/"+url.PathEscape(taskID)+"/continue", userID, nil, &st)
}

// DownloadResult fetches output.zip and writes it to dst, creating parent
// directories. It is the fallback used when the shared directory does not hold
// the result - for instance when TAA and the service are not on one host.
func (c *Client) DownloadResult(ctx context.Context, taskID, userID, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/tasks/"+url.PathEscape(taskID)+"/results/download", nil)
	if err != nil {
		return fmt.Errorf("build result download request: %w", err)
	}
	if userID != "" {
		req.Header.Set("X-User-Id", userID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("download fhe result: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return &APIError{Method: http.MethodGet, Path: "/tasks/" + taskID + "/results/download",
			StatusCode: resp.StatusCode, Body: string(snippet)}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create result dir: %w", err)
	}
	tmp := dst + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create result temp file: %w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write result file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close result file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("move result into place: %w", err)
	}
	return nil
}

// IsTerminal reports whether a status means the task will not change again.
func IsTerminal(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "succeeded", "success",
		"failed", "error",
		"cancelled", "canceled",
		"timeout", "timed_out",
		"expired", "deleted":
		return true
	}
	return false
}

// IsSuccess reports whether a terminal status means the task produced results.
func IsSuccess(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "succeeded", "success":
		return true
	}
	return false
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/fhe/... -run 'TestNewClient|TestCreateTask|TestTask|TestActivate|TestCancel|TestDownload|TestIsTerminal' -v`
Expected: PASS（9 个测试）。

- [ ] **Step 5: 提交**

```bash
git add internal/fhe/client.go internal/fhe/client_test.go
git commit -m "feat(fhe): add the /api/v1 client and terminal-state helpers"
```

---

## Task 4: 公钥内容寻址缓存

**Files:**
- Create: `internal/fhe/keycache.go`
- Test: `internal/fhe/keycache_test.go`

复用 `resource.DownloadToTempFile`（`internal/resource/downloader.go`），但**必须传本包自己的上限**——它默认走 `codeAudit.resultCheck.maxFileBytes` 那条 3 GiB 的语义，实测公钥 3.101 GiB 会被它拒掉。

- [ ] **Step 1: 写失败的测试**

创建 `internal/fhe/keycache_test.go`：

```go
package fhe

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// sm3HexOf computes the SM3 digest of b the same way the cache does, by writing
// it to a file and hashing that file.
func sm3HexOf(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	_, hex, err := hashFileSM3(p)
	if err != nil {
		t.Fatalf("hash blob: %v", err)
	}
	return hex
}

func TestKeyCacheEnsureDownloadsAndVerifies(t *testing.T) {
	payload := []byte("eval-key-bytes")
	hash := sm3HexOf(t, payload)
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c, err := NewKeyCache(t.TempDir(), DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	got, err := c.Ensure(hash, srv.URL+"/eval_context.bin")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got != filepath.Join(c.dir, hash, "eval_context.bin") {
		t.Errorf("Ensure path = %q", got)
	}
	if b, err := os.ReadFile(got); err != nil || string(b) != string(payload) {
		t.Fatalf("cached bytes = %q, err = %v", b, err)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("downloads = %d, want 1", hits)
	}

	// Second call must be served from the cache: the point of the cache is that a
	// repeat task for the same user never re-downloads several gigabytes.
	again, err := c.Ensure(hash, srv.URL+"/eval_context.bin")
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if again != got {
		t.Errorf("second Ensure path = %q, want %q", again, got)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Errorf("downloads after a cache hit = %d, want 1", hits)
	}
}

func TestKeyCacheRejectsHashMismatchAndCleansUp(t *testing.T) {
	payload := []byte("real-bytes")
	wrong := sm3HexOf(t, []byte("other-bytes"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dir := t.TempDir()
	c, err := NewKeyCache(dir, DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	_, err = c.Ensure(wrong, srv.URL+"/eval_context.bin")
	if err == nil {
		t.Fatal("Ensure with a mismatched hash = nil, want error")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error %q does not mention a mismatch", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, wrong)); !os.IsNotExist(statErr) {
		t.Error("a rejected key was left in the cache")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("cache dir has %d entries after a rejection, want 0", len(entries))
	}
}

func TestKeyCacheRejectsInvalidHashBeforeAnyIO(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
	}))
	defer srv.Close()

	c, err := NewKeyCache(t.TempDir(), DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	for _, bad := range []string{"", "..", "../../etc", "short", strings.ToUpper(testHashA)} {
		if _, err := c.Ensure(bad, srv.URL); err == nil {
			t.Errorf("Ensure(%q) = nil, want error", bad)
		}
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Errorf("an invalid hash triggered %d downloads, want 0", hits)
	}
}

func TestKeyCacheRejectsOversizedDownload(t *testing.T) {
	payload := []byte(strings.Repeat("x", 4096))
	hash := sm3HexOf(t, payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c, err := NewKeyCache(t.TempDir(), 1024)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	if _, err := c.Ensure(hash, srv.URL); err == nil {
		t.Fatal("Ensure of an oversized key = nil, want error")
	}
}

func TestKeyCacheRequiresAURLOnAMiss(t *testing.T) {
	c, err := NewKeyCache(t.TempDir(), DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	if _, err := c.Ensure(testHashA, "  "); err == nil {
		t.Fatal("Ensure with no url on a miss = nil, want error")
	}
}

func TestNewKeyCacheValidatesArguments(t *testing.T) {
	if _, err := NewKeyCache("", 1024); err == nil {
		t.Error("empty dir accepted, want error")
	}
	if _, err := NewKeyCache(t.TempDir(), 0); err == nil {
		t.Error("zero max bytes accepted, want error")
	}
}
```

测试里用了 `hashFileSM3`——在 `keycache.go` 里声明成一个薄包装，让测试与被测代码走同一条哈希路径。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/fhe/... -run 'TestKeyCache|TestNewKeyCache' -v`
Expected: FAIL — undefined `KeyCache`、`NewKeyCache`、`hashFileSM3`。

- [ ] **Step 3: 写实现**

创建 `internal/fhe/keycache.go`：

```go
package fhe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"taa/internal/resource"
	teecrypto "taa/pkg/crypto"
)

// hashFileSM3 is the digest used for every content-addressed name in this
// package: SM3, hex encoded.
func hashFileSM3(path string) (int64, string, error) {
	return teecrypto.HashFileSM3(path)
}

// KeyCache stores evaluation keys under <dir>/<sm3 hex>/eval_context.bin.
//
// The cache exists because a key is multi-gigabyte and a user's second task uses
// the same one: without it, every task would re-download 3.1 GiB and re-verify
// it. Because the directory name *is* the digest, a hit needs no re-verification
// - only bytes that hashed to that name can be sitting there.
//
// Entries are never evicted. Every cached key is a user, and dropping one costs
// another multi-gigabyte download; disk is sized for the expected user count
// instead.
type KeyCache struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
}

// NewKeyCache prepares the cache directory and returns it.
func NewKeyCache(dir string, maxBytes int64) (*KeyCache, error) {
	d := strings.TrimSpace(dir)
	if d == "" {
		return nil, fmt.Errorf("fhe key cache dir is empty")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("fhe max eval key bytes must be positive, got %d", maxBytes)
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, fmt.Errorf("create fhe key cache dir %s: %w", d, err)
	}
	return &KeyCache{dir: d, maxBytes: maxBytes}, nil
}

// Dir returns the cache root.
func (c *KeyCache) Dir() string { return c.dir }

// Path returns the cache path of a digest, or an error when the digest is not a
// valid SM3 hex value. The digest becomes a directory name, so this check is what
// keeps a hostile value from escaping the cache directory.
func (c *KeyCache) Path(hash string) (string, error) {
	h := strings.TrimSpace(hash)
	if !ValidHash(h) {
		return "", fmt.Errorf("invalid eval key hash %q: want 64 lowercase hex characters", hash)
	}
	return filepath.Join(c.dir, h, evalKeyFileName), nil
}

// Ensure makes the key identified by hash available locally and returns its path.
// A cached key is returned as-is; a miss downloads from url, verifies the digest,
// and only then moves the file into place, so a partially written or rejected
// download can never be mistaken for a cached key.
func (c *KeyCache) Ensure(hash, url string) (string, error) {
	dst, err := c.Path(hash)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := os.Stat(dst); err == nil {
		return dst, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat cached eval key %s: %w", dst, err)
	}

	if strings.TrimSpace(url) == "" {
		return "", fmt.Errorf("eval key %s is not cached and no download url was given", hash)
	}

	// The cap is this package's own, never the import cap: a real key is 3.101 GiB
	// and codeAudit.resultCheck.maxFileBytes defaults to 3 GiB.
	tmp, _, err := resource.DownloadToTempFile(url, c.maxBytes)
	if err != nil {
		return "", fmt.Errorf("download eval key: %w", err)
	}
	defer os.Remove(tmp)

	_, got, err := hashFileSM3(tmp)
	if err != nil {
		return "", fmt.Errorf("hash the downloaded eval key: %w", err)
	}
	if !strings.EqualFold(got, strings.TrimSpace(hash)) {
		return "", fmt.Errorf("eval key hash mismatch: declared %s, downloaded %s", hash, got)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", fmt.Errorf("create eval key dir: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return "", fmt.Errorf("move eval key into the cache: %w", err)
	}
	return dst, nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/fhe/... -run 'TestKeyCache|TestNewKeyCache' -v`
Expected: PASS（6 个测试）。

- [ ] **Step 5: 提交**

```bash
git add internal/fhe/keycache.go internal/fhe/keycache_test.go
git commit -m "feat(fhe): add the content-addressed eval key cache"
```

---

## Task 5: 任务编排与终态状态机

**Files:**
- Create: `internal/fhe/runner.go`
- Test: `internal/fhe/runner_test.go`

回调与轮询会竞争同一个终态。用 `sync.Once` 收敛：两条路径调同一个 `finish`，只有第一条真正推进状态并关闭 `done`，另一条拿到同一份结果。FHE 服务按 0/1/4/16 s 重试回调，重试也走这条路径，因此天然幂等。

- [ ] **Step 1: 写失败的测试**

创建 `internal/fhe/runner_test.go`：

```go
package fhe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeFHE is an in-process stand-in for the /api/v1 surface. It is what lets the
// whole contract be exercised on a machine with no GPU: the real service is
// CUDA-only (sm_89) and cannot run here.
type fakeFHE struct {
	mu           sync.Mutex
	tasks        map[string]string   // task id -> status
	caseDone     map[string]int      // task id -> finished case count
	caseTotal    int
	activateHits int
	createHits   int
	continueHits int
	callbackURL  string
	// resultBytes is what /results/download serves.
	resultBytes []byte
	// resultOnDisk makes the task write results/<id>/output.zip, as the real
	// service does through the shared directory.
	resultOnDisk bool
	layout       Layout
}

func newFakeFHE(t *testing.T, layout Layout) (*fakeFHE, *httptest.Server) {
	t.Helper()
	f := &fakeFHE{
		tasks:        map[string]string{},
		caseDone:     map[string]int{},
		caseTotal:    3,
		resultBytes:  []byte("result-zip"),
		resultOnDisk: true,
		layout:       layout,
	}
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeFHE) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	switch {
	case path == "/api/v1/health":
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	case path == "/api/v1/models/activate":
		f.activateHits++
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	case path == "/api/v1/tasks" && r.Method == http.MethodPost:
		f.createHits++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		id, _ := body["task_id"].(string)
		f.callbackURL, _ = body["callback_url"].(string)
		if _, exists := f.tasks[id]; exists {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"task exists"}`))
			return
		}
		f.tasks[id] = "running"
		f.caseDone[id] = 0
		_, _ = w.Write([]byte(`{"task_id":"` + id + `","status":"running"}`))
	case strings.HasSuffix(path, "/continue") && r.Method == http.MethodPost:
		f.continueHits++
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/tasks/"), "/continue")
		f.tasks[id] = "running"
		_, _ = w.Write([]byte(`{"status":"running"}`))
	case strings.HasSuffix(path, "/cancel") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/tasks/"), "/cancel")
		f.tasks[id] = "cancelled"
		_, _ = w.Write([]byte(`{"status":"cancelled"}`))
	case strings.HasSuffix(path, "/results/download"):
		_, _ = w.Write(f.resultBytes)
	case strings.HasPrefix(path, "/api/v1/tasks/"):
		id := strings.TrimPrefix(path, "/api/v1/tasks/")
		status, ok := f.tasks[id]
		if !ok {
			http.Error(w, "no such task", http.StatusNotFound)
			return
		}
		if status == "completed" && f.resultOnDisk {
			if p, err := f.layout.ResultPath(id); err == nil {
				_ = os.MkdirAll(filepath.Dir(p), 0o755)
				if _, err := os.Stat(p); err != nil {
					_ = os.WriteFile(p, f.resultBytes, 0o644)
				}
			}
		}
		done := f.caseDone[id]
		if !IsTerminal(status) {
			done = f.caseTotal - 1
		}
		cases := ""
		for i := 0; i < f.caseTotal; i++ {
			if i > 0 {
				cases += ","
			}
			if i < done {
				cases += fmt.Sprintf(`{"entry":"case-%02d.ct","result_id":"case-%02d.result.bin"}`, i, i)
			} else {
				cases += fmt.Sprintf(`{"entry":"case-%02d.ct"}`, i)
			}
		}
		_, _ = fmt.Fprintf(w, `{"task_id":%q,"status":%q,"cases":[%s]}`, id, status, cases)
	default:
		http.Error(w, "unexpected path "+path, http.StatusNotFound)
	}
}

// completeTask moves a task to its terminal state, as the worker eventually does.
func (f *fakeFHE) completeTask(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tasks[id] = "completed"
	f.caseDone[id] = f.caseTotal
}

func (f *fakeFHE) status(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tasks[id]
}

func (f *fakeFHE) callback() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callbackURL
}

// newTestRunner wires a Runner against a fake service and a temp shared dir.
func newTestRunner(t *testing.T, srvURL string, layout Layout) *Runner {
	t.Helper()
	cfg := Config{
		Endpoint:        srvURL,
		DataDir:         layout.DataDir(),
		KeyCacheDir:     t.TempDir(),
		CallbackBaseURL: "http://taa.test:6001",
		CallbackToken:   "tok",
		MaxEvalKeyBytes: DefaultMaxEvalKeyBytes,
		PollInterval:    20 * time.Millisecond,
		RequestTimeout:  5 * time.Second,
		TaskTimeout:     5 * time.Second,
	}
	r, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// specFor stages an eval key and an input archive and returns a matching spec.
func specFor(t *testing.T, r *Runner, keySrvURL string, keyBytes, inputBytes []byte) TaskSpec {
	t.Helper()
	keyHash := sm3HexOf(t, keyBytes)
	in := filepath.Join(t.TempDir(), "input.zip")
	if err := os.WriteFile(in, inputBytes, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	return TaskSpec{
		TaskID:       "task-1",
		RequestID:    "req-1",
		UserID:       keyHash,
		ModelID:      testHashB,
		EvalKeyHash:  keyHash,
		EvalKeyURL:   keySrvURL + "/eval_context.bin",
		InputZipPath: in,
	}
}

func TestRunnerExecuteStagesSharedDirectoryAndCompletes(t *testing.T) {
	layout := NewLayout(t.TempDir())
	keyBytes := []byte("eval-key-bytes")
	inputBytes := []byte("input-zip-bytes")

	keySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyBytes)
	}))
	defer keySrv.Close()

	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	spec := specFor(t, r, keySrv.URL, keyBytes, inputBytes)

	// Complete the task as soon as it is created, so the first poll after the
	// create call already sees a terminal state.
	go func() {
		for i := 0; i < 200; i++ {
			if fake.status("task-1") != "" {
				fake.completeTask("task-1")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	out, err := r.Execute(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Status != StatusCompleted {
		t.Errorf("Status = %q, want %q", out.Status, StatusCompleted)
	}
	if out.ResultZip == "" {
		t.Fatal("ResultZip is empty, want the shared-directory output.zip")
	}
	if b, err := os.ReadFile(out.ResultZip); err != nil || string(b) != string(fake.resultBytes) {
		t.Errorf("result bytes = %q, err = %v", b, err)
	}
	if out.Total != 3 || out.Failed != 0 {
		t.Errorf("Total/Failed = %d/%d, want 3/0", out.Total, out.Failed)
	}

	// The key and the input package must be published where the service reads them.
	keyDst, _ := layout.KeyPath(spec.EvalKeyHash)
	if b, err := os.ReadFile(keyDst); err != nil || string(b) != string(keyBytes) {
		t.Errorf("published key = %q, err = %v", b, err)
	}
	inDst, _ := layout.TaskInputPath("task-1")
	if b, err := os.ReadFile(inDst); err != nil || string(b) != string(inputBytes) {
		t.Errorf("published input = %q, err = %v", b, err)
	}

	// The callback URL must carry the token, and must be pointed at our endpoint.
	cb := fake.callback()
	if !strings.Contains(cb, "/v1/taa/fheCallback") || !strings.Contains(cb, "token=tok") {
		t.Errorf("callback url = %q", cb)
	}
	if fake.activateHits != 0 {
		t.Errorf("activateHits = %d, want 0 (model activation belongs to importModel)", fake.activateHits)
	}
}

func TestRunnerExecuteRejectsInvalidIdentifiers(t *testing.T) {
	layout := NewLayout(t.TempDir())
	_, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)

	base := TaskSpec{
		TaskID: "task-1", UserID: testHashA, ModelID: testHashB,
		EvalKeyHash: testHashA, EvalKeyURL: "http://x/y", InputZipPath: "/nonexistent",
	}
	cases := map[string]func(*TaskSpec){
		"eval key hash": func(s *TaskSpec) { s.EvalKeyHash = "../../etc"; s.UserID = "../../etc" },
		"model hash":    func(s *TaskSpec) { s.ModelID = "../x" },
		"task id":       func(s *TaskSpec) { s.TaskID = "../x" },
	}
	for name, mutate := range cases {
		s := base
		mutate(&s)
		if _, err := r.Execute(context.Background(), s, nil); err == nil {
			t.Errorf("%s: Execute = nil, want error", name)
		}
	}
}

func TestRunnerDeliverIsIdempotent(t *testing.T) {
	layout := NewLayout(t.TempDir())
	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	r.registerTestRun("task-1", TaskSpec{TaskID: "task-1", UserID: testHashA, ModelID: testHashB})

	payload := CallbackPayload{TaskID: "task-1", Status: "completed", ResultZip: "results/task-1/output.zip"}
	if !r.Deliver(payload) {
		t.Fatal("first Deliver = false, want true")
	}
	for i := 0; i < 3; i++ {
		if r.Deliver(payload) {
			t.Fatalf("Deliver #%d = true, want false (the service retries at 0/1/4/16s)", i+2)
		}
	}
	_ = fake
}

func TestRunnerDeliverUnknownTaskIsIgnored(t *testing.T) {
	layout := NewLayout(t.TempDir())
	_, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	if r.Deliver(CallbackPayload{TaskID: "nope", Status: "completed"}) {
		t.Error("Deliver for an unknown task = true, want false")
	}
}

func TestRunnerCallbackWinsOverPollingExactlyOnce(t *testing.T) {
	layout := NewLayout(t.TempDir())
	_, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	// The service never reports a terminal state here: only the callback can end
	// the task, which is what makes the race observable.
	r.registerTestRun("task-1", TaskSpec{TaskID: "task-1", UserID: testHashA, ModelID: testHashB})

	var wg sync.WaitGroup
	var delivered int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.Deliver(CallbackPayload{TaskID: "task-1", Status: "completed"}) {
				atomic.AddInt64(&delivered, 1)
			}
		}()
	}
	run := r.lookupForTest("task-1")
	wg.Wait()
	<-run.done

	if got := atomic.LoadInt64(&delivered); got != 1 {
		t.Errorf("deliveries that advanced the task = %d, want exactly 1", got)
	}
}

func TestRunnerExecuteTimesOut(t *testing.T) {
	layout := NewLayout(t.TempDir())
	keyBytes := []byte("k")
	keySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyBytes)
	}))
	defer keySrv.Close()
	_, srv := newFakeFHE(t, layout)

	cfg := Config{
		Endpoint: srv.URL, DataDir: layout.DataDir(), KeyCacheDir: t.TempDir(),
		CallbackBaseURL: "http://taa.test:6001", CallbackToken: "tok",
		MaxEvalKeyBytes: DefaultMaxEvalKeyBytes,
		PollInterval:    10 * time.Millisecond,
		RequestTimeout:  5 * time.Second,
		TaskTimeout:     150 * time.Millisecond,
	}
	r, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := r.Execute(context.Background(), specFor(t, r, keySrv.URL, keyBytes, []byte("i")), nil)
	if err == nil {
		t.Fatal("Execute on a task that never terminates = nil, want error")
	}
	if out.Status != StatusFailed {
		t.Errorf("Status = %q, want %q", out.Status, StatusFailed)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error %q does not mention the timeout", err)
	}
}

func TestRunnerExecuteRetriesAnExistingTask(t *testing.T) {
	layout := NewLayout(t.TempDir())
	keyBytes := []byte("k")
	keySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyBytes)
	}))
	defer keySrv.Close()
	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	spec := specFor(t, r, keySrv.URL, keyBytes, []byte("i"))

	// Simulate a replayed import: the task already exists on the service. The
	// runner must resume it with /continue instead of creating a second task.
	fake.mu.Lock()
	fake.tasks["task-1"] = "failed"
	fake.caseDone["task-1"] = 1
	fake.mu.Unlock()

	go func() {
		for i := 0; i < 200; i++ {
			fake.mu.Lock()
			status := fake.tasks["task-1"]
			fake.mu.Unlock()
			if status == "running" {
				fake.completeTask("task-1")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	out, err := r.Execute(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Status != StatusCompleted {
		t.Errorf("Status = %q, want completed", out.Status)
	}
	if fake.continueHits != 1 {
		t.Errorf("continueHits = %d, want 1", fake.continueHits)
	}
}

func TestRunnerCancelMapsToTheCancelEndpoint(t *testing.T) {
	layout := NewLayout(t.TempDir())
	fake, srv := newFakeFHE(t, layout)
	r := newTestRunner(t, srv.URL, layout)
	r.registerTestRun("task-1", TaskSpec{TaskID: "task-1", UserID: testHashA, ModelID: testHashB})
	fake.mu.Lock()
	fake.tasks["task-1"] = "running"
	fake.mu.Unlock()

	if err := r.Cancel(context.Background(), "task-1"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if got := fake.status("task-1"); got != "cancelled" {
		t.Errorf("service status = %q, want cancelled", got)
	}
	run := r.lookupForTest("task-1")
	select {
	case <-run.done:
	default:
		t.Fatal("Cancel did not finish the local run")
	}
	if run.outcome.Status != StatusCancelled {
		t.Errorf("local status = %q, want %q", run.outcome.Status, StatusCancelled)
	}
}

func TestParseCallback(t *testing.T) {
	p, err := ParseCallback([]byte(`{"task_id":"t1","status":"completed","result_zip":"results/t1/output.zip","cases":[{"entry":"a","result_id":"a.bin"}]}`))
	if err != nil {
		t.Fatalf("ParseCallback: %v", err)
	}
	if p.TaskID != "t1" || p.Status != "completed" || len(p.Cases) != 1 {
		t.Errorf("parsed = %+v", p)
	}

	// camelCase is accepted too: the exact casing of the callback is the
	// service's to choose, and guessing wrong must not drop a terminal state.
	p, err = ParseCallback([]byte(`{"taskId":"t2","status":"failed","resultZip":"x"}`))
	if err != nil {
		t.Fatalf("ParseCallback camelCase: %v", err)
	}
	if p.TaskID != "t2" || p.ResultZip != "x" {
		t.Errorf("parsed = %+v", p)
	}

	for _, bad := range []string{`{}`, `{"status":"completed"}`, `{`, `{"task_id":"t"}`, ``} {
		if _, err := ParseCallback([]byte(bad)); err == nil {
			t.Errorf("ParseCallback(%q) = nil, want error", bad)
		}
	}
}

func TestNewValidatesConfigAndCreatesDirs(t *testing.T) {
	layout := NewLayout(t.TempDir())
	cfg := Config{
		Endpoint: "http://127.0.0.1:1", DataDir: layout.DataDir(), KeyCacheDir: t.TempDir(),
		CallbackBaseURL: "http://taa:6001", CallbackToken: "t",
		MaxEvalKeyBytes: DefaultMaxEvalKeyBytes, PollInterval: time.Second,
		RequestTimeout: time.Second, TaskTimeout: time.Minute,
	}
	if _, err := New(cfg, nil); err != nil {
		t.Fatalf("New: %v", err)
	}
	bad := cfg
	bad.CallbackToken = ""
	if _, err := New(bad, nil); err == nil {
		t.Error("New with an empty callback token = nil, want error")
	}
}
```

测试用到 `r.registerTestRun` 与 `r.lookupForTest`——在 `runner.go` 里作为导出到测试的薄封装实现（生产代码只走 `prepare` 与 `lookup`）。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/fhe/... -run 'TestRunner|TestParseCallback|TestNewValidates' -v`
Expected: FAIL — undefined `Runner`、`New`、`TaskSpec`、`CallbackPayload`。

- [ ] **Step 3: 写实现**

创建 `internal/fhe/runner.go`：

```go
package fhe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Task status values this package produces locally. The service's own status
// string is passed through as-is; these three are used when no service status is
// available.
const (
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// Level is a log severity the runner emits.
type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Logger receives the runner's progress messages. It is nil-safe: a nil Logger
// discards everything, which is what tests use.
type Logger func(level Level, scope, format string, args ...any)

// TaskSpec is everything needed to run one FHE task.
type TaskSpec struct {
	TaskID    string
	RequestID string
	// UserID is the eval key digest, and doubles as the FHE-side user id.
	UserID string
	// ModelID is the model package digest, and doubles as the FHE-side model id.
	ModelID     string
	EvalKeyHash string
	EvalKeyURL  string
	// InputZipPath is the local plaintext archive the caller already resolved.
	// Reusing it avoids downloading the same bytes twice and reuses the import
	// download cap the caller already enforced.
	InputZipPath string
}

// TaskOutcome is a task's terminal state.
type TaskOutcome struct {
	Status    string
	Total     int
	Failed    int
	ResultZip string
	Err       error
}

// CallbackPayload is what the FHE service POSTs when a task reaches a terminal
// state.
type CallbackPayload struct {
	TaskID    string       `json:"task_id"`
	Status    string       `json:"status"`
	ResultZip string       `json:"result_zip"`
	Cases     []CaseStatus `json:"cases"`
}

// ParseCallback decodes a callback body. Both snake_case and camelCase spellings
// are accepted: the casing is the service's to choose, and rejecting the wrong
// guess would drop a terminal state and leave the task to time out.
func ParseCallback(body []byte) (CallbackPayload, error) {
	var raw struct {
		TaskID       string       `json:"task_id"`
		TaskIDCamel  string       `json:"taskId"`
		Status       string       `json:"status"`
		ResultZip    string       `json:"result_zip"`
		ResultZipCamel string     `json:"resultZip"`
		Cases        []CaseStatus `json:"cases"`
		Results      []CaseStatus `json:"results"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return CallbackPayload{}, fmt.Errorf("decode fhe callback: %w", err)
	}
	p := CallbackPayload{
		TaskID:    firstNonEmpty(raw.TaskID, raw.TaskIDCamel),
		Status:    strings.TrimSpace(raw.Status),
		ResultZip: firstNonEmpty(raw.ResultZip, raw.ResultZipCamel),
		Cases:     raw.Cases,
	}
	if len(p.Cases) == 0 {
		p.Cases = raw.Results
	}
	if p.TaskID == "" {
		return CallbackPayload{}, fmt.Errorf("fhe callback has no task id")
	}
	if p.Status == "" {
		return CallbackPayload{}, fmt.Errorf("fhe callback for task %s has no status", p.TaskID)
	}
	return p, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// taskRun is the in-flight state of one task, shared between the polling
// goroutine and the callback handler.
type taskRun struct {
	spec    TaskSpec
	done    chan struct{}
	once    sync.Once
	outcome TaskOutcome
}

// Runner drives FHE tasks.
//
// One runner serves the whole process: it owns the key cache, the shared
// directory, and the table of in-flight tasks that lets a callback delivered on
// an unrelated HTTP request advance the task its importer is waiting on.
type Runner struct {
	cfg    Config
	layout Layout
	keys   *KeyCache
	client *Client
	logf   Logger

	mu    sync.Mutex
	tasks map[string]*taskRun
}

// New builds a runner, creating the key cache directory.
func New(cfg Config, logf Logger) (*Runner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client, err := NewClient(cfg.Endpoint, cfg.RequestTimeout)
	if err != nil {
		return nil, err
	}
	keys, err := NewKeyCache(cfg.KeyCacheDir, cfg.MaxEvalKeyBytes)
	if err != nil {
		return nil, err
	}
	return &Runner{
		cfg:    cfg,
		layout: NewLayout(cfg.DataDir),
		keys:   keys,
		client: client,
		logf:   logf,
		tasks:  map[string]*taskRun{},
	}, nil
}

// Config returns the runner's configuration.
func (r *Runner) Config() Config { return r.cfg }

// Layout returns the shared-directory layout.
func (r *Runner) Layout() Layout { return r.layout }

// Client returns the underlying API client.
func (r *Runner) Client() *Client { return r.client }

func (r *Runner) log(level Level, format string, args ...any) {
	if r.logf == nil {
		return
	}
	r.logf(level, "fhe", format, args...)
}

func (r *Runner) lookup(taskID string) *taskRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tasks[taskID]
}

// registerTestRun exposes task registration to tests without going through the
// service. Production code registers through prepare.
func (r *Runner) registerTestRun(taskID string, spec TaskSpec) *taskRun {
	run := &taskRun{spec: spec, done: make(chan struct{})}
	r.mu.Lock()
	r.tasks[taskID] = run
	r.mu.Unlock()
	return run
}

func (r *Runner) lookupForTest(taskID string) *taskRun { return r.lookup(taskID) }

func (r *Runner) forget(taskID string) {
	r.mu.Lock()
	delete(r.tasks, taskID)
	r.mu.Unlock()
}

// finish resolves a run exactly once and reports whether this call is the one
// that resolved it. Every path to a terminal state goes through here, which is
// what makes the service's 0/1/4/16s callback retries and a callback/poll race
// collapse into a single transition.
func (r *Runner) finish(run *taskRun, out TaskOutcome) (TaskOutcome, bool) {
	won := false
	run.once.Do(func() {
		run.outcome = out
		won = true
		close(run.done)
	})
	return run.outcome, won
}

// ResolveTask reports the terminal state of an in-flight task.
func (r *Runner) ResolveTask(taskID string) (TaskOutcome, bool) {
	run := r.lookup(taskID)
	if run == nil {
		return TaskOutcome{}, false
	}
	select {
	case <-run.done:
		return run.outcome, true
	default:
		return TaskOutcome{}, false
	}
}

// Deliver records a terminal callback. It returns true only for the delivery
// that actually advanced the task, so a retry or a race with the poller is a
// no-op.
func (r *Runner) Deliver(p CallbackPayload) bool {
	run := r.lookup(p.TaskID)
	if run == nil {
		r.log(LevelWarn, "收到未知任务的回调，已忽略: taskId=%s", p.TaskID)
		return false
	}
	_, won := r.finish(run, r.outcomeFromStatus(run.spec, TaskStatus{
		TaskID: p.TaskID, Status: p.Status, ResultZip: p.ResultZip, Cases: p.Cases,
	}))
	return won
}

// Cancel maps TAA's stopTraining onto the service's cancel endpoint and resolves
// the local run.
func (r *Runner) Cancel(ctx context.Context, taskID string) error {
	run := r.lookup(taskID)
	userID := ""
	if run != nil {
		userID = run.spec.UserID
	}
	sendCtx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	defer cancel()
	if err := r.client.CancelTask(sendCtx, taskID, userID); err != nil {
		return err
	}
	if run != nil {
		r.finish(run, TaskOutcome{Status: StatusCancelled, Err: fmt.Errorf("fhe task %s was cancelled", taskID)})
	}
	return nil
}

// Execute runs one task to a terminal state.
//
// It publishes the eval key and the input archive into the shared directory,
// creates the task, then waits for the callback or the poll fallback, whichever
// arrives first, bounded by TaskTimeout. onProgress, when non-nil, receives the
// finished and total case counts the service reported.
func (r *Runner) Execute(ctx context.Context, spec TaskSpec, onProgress func(done, total int)) (TaskOutcome, error) {
	run, err := r.prepare(spec)
	if err != nil {
		return TaskOutcome{Status: StatusFailed, Err: err}, err
	}
	defer r.forget(spec.TaskID)

	createCtx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	err = r.client.CreateTask(createCtx, CreateTaskRequest{
		UserID:             spec.UserID,
		ModelID:            spec.ModelID,
		TaskID:             spec.TaskID,
		CallbackURL:        r.cfg.CallbackURL(),
		CancelOnDisconnect: false,
	})
	cancel()
	if err != nil {
		// A replayed import must resume the task that already exists rather than
		// create a second one: the input package is still on disk and the service
		// keeps per-case results, so /continue reruns only what is unfinished.
		probeCtx, probeCancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
		_, probeErr := r.client.Task(probeCtx, spec.TaskID, spec.UserID)
		probeCancel()
		if probeErr != nil {
			out := TaskOutcome{Status: StatusFailed, Err: fmt.Errorf("create fhe task: %w", err)}
			r.finish(run, out)
			return out, out.Err
		}
		r.log(LevelInfo, "任务已存在，改用 continue 重跑未完成 case: taskId=%s", spec.TaskID)
		contCtx, contCancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
		contErr := r.client.ContinueTask(contCtx, spec.TaskID, spec.UserID)
		contCancel()
		if contErr != nil {
			out := TaskOutcome{Status: StatusFailed, Err: fmt.Errorf("continue existing fhe task: %w (create failed: %v)", contErr, err)}
			r.finish(run, out)
			return out, out.Err
		}
	}

	return r.wait(ctx, run, onProgress)
}

// prepare validates the spec, publishes the key and the input package, and
// registers the run. Registration happens before the task is created so a
// callback that arrives immediately still finds the run.
func (r *Runner) prepare(spec TaskSpec) (*taskRun, error) {
	if !ValidHash(spec.EvalKeyHash) {
		return nil, fmt.Errorf("invalid eval key hash %q: want 64 lowercase hex characters", spec.EvalKeyHash)
	}
	if !ValidHash(spec.ModelID) {
		return nil, fmt.Errorf("invalid model hash %q: want 64 lowercase hex characters", spec.ModelID)
	}
	if err := ValidTaskID(spec.TaskID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(spec.InputZipPath) == "" {
		return nil, fmt.Errorf("input archive path is empty")
	}

	keySrc, err := r.keys.Ensure(spec.EvalKeyHash, spec.EvalKeyURL)
	if err != nil {
		return nil, err
	}
	keyDst, err := r.layout.KeyPath(spec.EvalKeyHash)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyDst), 0o755); err != nil {
		return nil, fmt.Errorf("create the shared key dir: %w", err)
	}
	if err := linkOrCopy(keySrc, keyDst); err != nil {
		return nil, fmt.Errorf("publish the eval key into the shared dir: %w", err)
	}

	inDst, err := r.layout.TaskInputPath(spec.TaskID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(inDst), 0o755); err != nil {
		return nil, fmt.Errorf("create the shared task dir: %w", err)
	}
	if err := copyFileAtomic(spec.InputZipPath, inDst); err != nil {
		return nil, fmt.Errorf("publish the input archive into the shared dir: %w", err)
	}

	run := &taskRun{spec: spec, done: make(chan struct{})}
	r.mu.Lock()
	r.tasks[spec.TaskID] = run
	r.mu.Unlock()
	r.log(LevelInfo, "已下发 FHE 任务: taskId=%s, userId=%s, modelId=%s", spec.TaskID, spec.UserID, spec.ModelID)
	return run, nil
}

func (r *Runner) wait(ctx context.Context, run *taskRun, onProgress func(done, total int)) (TaskOutcome, error) {
	deadline := time.NewTimer(r.cfg.TaskTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		if out, ok := r.pollOnce(ctx, run, onProgress); ok {
			r.finish(run, out)
			final, _ := r.finish(run, out)
			return final, final.Err
		}
		select {
		case <-run.done:
			select {
			case <-ctx.Done():
			default:
			}
			return run.outcome, run.outcome.Err
		case <-ticker.C:
		case <-deadline.C:
			out, _ := r.finish(run, TaskOutcome{
				Status: StatusFailed,
				Err:    fmt.Errorf("fhe task %s timed out after %s", run.spec.TaskID, r.cfg.TaskTimeout),
			})
			r.log(LevelError, "FHE 任务超时: taskId=%s, timeout=%s", run.spec.TaskID, r.cfg.TaskTimeout)
			return out, out.Err
		case <-ctx.Done():
			out, _ := r.finish(run, TaskOutcome{Status: StatusFailed, Err: ctx.Err()})
			return out, out.Err
		}
	}
}

// pollOnce asks the service for the task state once. It reports ok when the task
// reached a terminal state.
func (r *Runner) pollOnce(ctx context.Context, run *taskRun, onProgress func(done, total int)) (TaskOutcome, bool) {
	pollCtx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	defer cancel()

	st, err := r.client.Task(pollCtx, run.spec.TaskID, run.spec.UserID)
	if err != nil {
		// A poll failure is never fatal: the callback is the primary channel and
		// the timeout is the backstop, so a transient error only means trying again.
		r.log(LevelWarn, "轮询 FHE 任务状态失败，将继续重试: taskId=%s, err=%v", run.spec.TaskID, err)
		return TaskOutcome{}, false
	}
	if onProgress != nil {
		if done, total := st.Progress(); total > 0 {
			onProgress(done, total)
		}
	}
	if !IsTerminal(st.Status) {
		return TaskOutcome{}, false
	}
	return r.outcomeFromStatus(run.spec, st), true
}

// outcomeFromStatus converts a terminal service status into a run outcome,
// locating the result archive.
func (r *Runner) outcomeFromStatus(spec TaskSpec, st TaskStatus) TaskOutcome {
	out := TaskOutcome{Status: strings.ToLower(strings.TrimSpace(st.Status))}
	out.Total, out.Failed = st.Progress()
	if out.Status == "" {
		out.Status = StatusFailed
	}
	if !IsSuccess(out.Status) {
		out.Err = fmt.Errorf("fhe task %s ended with status %q (%d/%d cases failed)",
			spec.TaskID, st.Status, out.Failed, out.Total)
	}
	if p, err := r.layout.ResultPath(spec.TaskID); err == nil {
		if _, statErr := os.Stat(p); statErr == nil {
			out.ResultZip = p
		}
	}
	return out
}

// CopyResult makes the task's result archive available at dst and returns the
// path it used.
//
// The shared directory is the primary source, because TAA and the FHE service
// are on one host and reading a file beats re-downloading it. A service that did
// not write there - a split deployment, or a task whose results were cleaned up -
// is covered by the download fallback.
func (r *Runner) CopyResult(ctx context.Context, spec TaskSpec, out TaskOutcome, dst string) (string, error) {
	if out.ResultZip != "" {
		if err := copyFileAtomic(out.ResultZip, dst); err != nil {
			return "", fmt.Errorf("copy the shared-directory result: %w", err)
		}
		return out.ResultZip, nil
	}
	dlCtx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	defer cancel()
	if err := r.client.DownloadResult(dlCtx, spec.TaskID, spec.UserID, dst); err != nil {
		return "", fmt.Errorf("download the task result: %w", err)
	}
	return "", nil
}

// linkOrCopy hard-links src to dst, falling back to a copy when the two are not
// on one filesystem. A hard link is what keeps publishing a 3.1 GiB eval key
// free; the copy fallback costs one extra copy, not a wrong result.
//
// The destination is left mode 0644 because the FHE service reads it from a
// container running as a different user. On a hard link this also relaxes the
// source's mode, which is fine: the cache holds public keys.
func linkOrCopy(src, dst string) error {
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Link(src, dst); err == nil {
		return os.Chmod(dst, 0o644)
	}
	if err := copyFileAtomic(src, dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o644)
}

// copyFileAtomic stages the copy next to its destination and renames it into
// place, so a reader never observes a half-written archive.
func copyFileAtomic(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".partial"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
```

导入块是 `bytes` **不要**加（本文件用不到），`io` 被 `copyFileAtomic` 用到、保留。回调体的解析由调用方（Task 10 的 handler）自己限长后调用 `ParseCallback`。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/fhe/... -run 'TestRunner|TestParseCallback|TestNewValidates' -v`
Expected: PASS（10 个测试）。

- [ ] **Step 5: 跑整个包**

Run: `go test ./internal/fhe/... -v`
Expected: PASS（全部）。

- [ ] **Step 6: 提交**

```bash
git add internal/fhe/runner.go internal/fhe/runner_test.go
git commit -m "feat(fhe): add the task runner with a callback-first terminal state machine"
```

---

## Task 6: 配置段 `server.type` 与 `fhe`

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/fhe_config_test.go`

- [ ] **Step 1: 写失败的测试**

创建 `internal/config/fhe_config_test.go`：

```go
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "taa.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

const fheConfigBody = `{
  "server": { "addr": ":6001", "type": "fhe" },
  "platform": { "addr": "http://127.0.0.1:59999" },
  "fhe": {
    "endpoint": "http://127.0.0.1:58996",
    "dataDir": "/opt/fhe-data",
    "keyCacheDir": "/root/taa/fhe-keys",
    "callbackBaseUrl": "http://172.16.10.130:6001",
    "callbackToken": "shared-token",
    "maxEvalKeyBytes": 6442450944,
    "pollIntervalMs": 5000,
    "requestTimeoutMs": 30000,
    "taskTimeoutMs": 1800000,
    "activateModelOnImport": true
  }
}`

func TestServerTypeDefaultsToTee(t *testing.T) {
	p := writeConfig(t, `{"server": {"addr": ":6001"}}`)
	cfg, err := LoadStartupConfig(p)
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.ServerType != ServerTypeTEE {
		t.Errorf("ServerType = %q, want %q", cfg.ServerType, ServerTypeTEE)
	}
	if cfg.FHE != nil {
		t.Errorf("FHE = %+v, want nil on a tee instance", cfg.FHE)
	}
}

func TestServerTypeRejectsUnknownValue(t *testing.T) {
	p := writeConfig(t, `{"server": {"addr": ":6001", "type": "gpu"}}`)
	_, err := LoadStartupConfig(p)
	if err == nil {
		t.Fatal("unknown server.type accepted, want error")
	}
	if !strings.Contains(err.Error(), "server.type") {
		t.Errorf("error %q does not name server.type", err)
	}
	if !strings.Contains(err.Error(), "tee") || !strings.Contains(err.Error(), "fhe") {
		t.Errorf("error %q does not list the accepted values", err)
	}
}

func TestFHESectionIsParsedWhenTypeIsFHE(t *testing.T) {
	p := writeConfig(t, fheConfigBody)
	cfg, err := LoadStartupConfig(p)
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.ServerType != ServerTypeFHE {
		t.Fatalf("ServerType = %q, want %q", cfg.ServerType, ServerTypeFHE)
	}
	if cfg.FHE == nil {
		t.Fatal("FHE = nil, want a parsed section")
	}
	if cfg.FHE.Endpoint != "http://127.0.0.1:58996" {
		t.Errorf("Endpoint = %q", cfg.FHE.Endpoint)
	}
	if cfg.FHE.DataDir != "/opt/fhe-data" {
		t.Errorf("DataDir = %q", cfg.FHE.DataDir)
	}
	if cfg.FHE.KeyCacheDir != "/root/taa/fhe-keys" {
		t.Errorf("KeyCacheDir = %q", cfg.FHE.KeyCacheDir)
	}
	if cfg.FHE.CallbackToken != "shared-token" {
		t.Errorf("CallbackToken = %q", cfg.FHE.CallbackToken)
	}
	if cfg.FHE.MaxEvalKeyBytes != 6442450944 {
		t.Errorf("MaxEvalKeyBytes = %d", cfg.FHE.MaxEvalKeyBytes)
	}
	if cfg.FHE.PollIntervalMs != 5000 || cfg.FHE.RequestTimeoutMs != 30000 || cfg.FHE.TaskTimeoutMs != 1800000 {
		t.Errorf("timeouts = %d/%d/%d", cfg.FHE.PollIntervalMs, cfg.FHE.RequestTimeoutMs, cfg.FHE.TaskTimeoutMs)
	}
	if !cfg.FHE.ActivateModelOnImport {
		t.Error("ActivateModelOnImport = false, want true")
	}
}

func TestFHEConfigDefaultsAreFilled(t *testing.T) {
	p := writeConfig(t, `{
	  "server": {"type": "fhe"},
	  "fhe": {
	    "endpoint": "http://127.0.0.1:58996",
	    "dataDir": "/opt/fhe-data",
	    "keyCacheDir": "/root/taa/fhe-keys",
	    "callbackBaseUrl": "http://172.16.10.130:6001",
	    "callbackToken": "t"
	  }}`)
	cfg, err := LoadStartupConfig(p)
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.FHE.MaxEvalKeyBytes != DefaultFHEMaxEvalKeyBytes {
		t.Errorf("MaxEvalKeyBytes = %d, want the default %d", cfg.FHE.MaxEvalKeyBytes, DefaultFHEMaxEvalKeyBytes)
	}
	if cfg.FHE.PollIntervalMs != DefaultFHEPollIntervalMs {
		t.Errorf("PollIntervalMs = %d", cfg.FHE.PollIntervalMs)
	}
	if cfg.FHE.RequestTimeoutMs != DefaultFHERequestTimeoutMs {
		t.Errorf("RequestTimeoutMs = %d", cfg.FHE.RequestTimeoutMs)
	}
	if cfg.FHE.TaskTimeoutMs != DefaultFHETaskTimeoutMs {
		t.Errorf("TaskTimeoutMs = %d", cfg.FHE.TaskTimeoutMs)
	}
	if !cfg.FHE.ActivateModelOnImport {
		t.Error("ActivateModelOnImport must default to true")
	}
}

func TestFHEConfigRejectsMissingRequiredFields(t *testing.T) {
	base := map[string]string{
		"endpoint":        `"http://127.0.0.1:58996"`,
		"dataDir":         `"/opt/fhe-data"`,
		"keyCacheDir":     `"/root/taa/fhe-keys"`,
		"callbackBaseUrl": `"http://172.16.10.130:6001"`,
		"callbackToken":   `"token"`,
	}
	for missing := range base {
		var b strings.Builder
		b.WriteString(`{"server":{"type":"fhe"},"fhe":{`)
		first := true
		for k, v := range base {
			if k == missing {
				continue
			}
			if !first {
				b.WriteString(",")
			}
			first = false
			b.WriteString(`"` + k + `":` + v)
		}
		// An explicitly empty value must be rejected the same way as an absent one.
		if !first {
			b.WriteString(",")
		}
		b.WriteString(`"` + missing + `":""}}`)

		if _, err := LoadStartupConfig(writeConfig(t, b.String())); err == nil {
			t.Errorf("missing/empty %s accepted, want error", missing)
		} else if !strings.Contains(err.Error(), "fhe."+missing) {
			t.Errorf("missing %s: error %q does not name the field", missing, err)
		}
	}
}

func TestFHEConfigRequiredWhenTypeIsFHE(t *testing.T) {
	if _, err := LoadStartupConfig(writeConfig(t, `{"server":{"type":"fhe"}}`)); err == nil {
		t.Fatal("type=fhe with no fhe section accepted, want error")
	}
}

func TestFHESectionIsWarnedAndIgnoredWhenTypeIsTEE(t *testing.T) {
	body := `{"server":{"type":"tee"},"fhe":{"endpoint":"http://127.0.0.1:58996","dataDir":"/opt/fhe-data"}}`
	cfg, err := LoadStartupConfig(writeConfig(t, body))
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.FHE != nil {
		t.Errorf("FHE = %+v, want nil: the section must be ignored on a tee instance", cfg.FHE)
	}
}

func TestFHEConfigRejectsBadEndpoint(t *testing.T) {
	for _, bad := range []string{`"127.0.0.1:58996"`, `"ftp://host"`, `"://"`} {
		body := `{"server":{"type":"fhe"},"fhe":{
		  "endpoint":` + bad + `,"dataDir":"/d","keyCacheDir":"/k",
		  "callbackBaseUrl":"http://t","callbackToken":"x"}}`
		if _, err := LoadStartupConfig(writeConfig(t, body)); err == nil {
			t.Errorf("endpoint %s accepted, want error", bad)
		}
	}
}

func TestFHEConfigRejectsNonPositiveBounds(t *testing.T) {
	body := `{"server":{"type":"fhe"},"fhe":{
	  "endpoint":"http://h:1","dataDir":"/d","keyCacheDir":"/k",
	  "callbackBaseUrl":"http://t","callbackToken":"x","maxEvalKeyBytes":-1}}`
	if _, err := LoadStartupConfig(writeConfig(t, body)); err == nil {
		t.Error("negative maxEvalKeyBytes accepted, want error")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/config/... -run 'TestServerType|TestFHE' -v`
Expected: FAIL — undefined `ServerTypeTEE`、`cfg.FHE`、`DefaultFHEMaxEvalKeyBytes`。

- [ ] **Step 3: 在 `internal/config/config.go` 加字段与类型**

`startupServerConfigFile`（`config.go:194`，当前只有 `Addr`）加 `Type`：

```go
type startupServerConfigFile struct {
	Addr string `json:"addr"`
	Type string `json:"type"`
}
```

`startupConfigFile`（`config.go:154`，`Server` 是**值类型不是指针**）加一行 `FHE *fheConfigFile`：

```go
type startupConfigFile struct {
	Server      startupServerConfigFile      `json:"server"`
	Platform    startupPlatformConfigFile    `json:"platform"`
	Storage     startupStorageConfigFile     `json:"storage"`
	Model       startupModelConfigFile       `json:"model"`
	CodeAudit   startupCodeAuditConfigFile   `json:"codeAudit"`
	Attestation startupAttestationConfigFile `json:"attestation"`
	// FHE is a pointer because "absent" and "present but empty" must be
	// distinguishable: a type=fhe instance with no section at all is a different
	// mistake from one with an empty callbackToken, and both are startup errors.
	FHE *fheConfigFile `json:"fhe"`

	RemovedSecurity json.RawMessage `json:"security"`
	RemovedLLM      json.RawMessage `json:"llm"`
	...
}
```

其余字段照旧不动。同文件加：

```go
// Server instance roles, selected by the server.type config key.
const (
	// ServerTypeTEE is the CSV guest that audits models and attests to the
	// platform. It is the default, so every existing config keeps its behaviour.
	ServerTypeTEE = "tee"
	// ServerTypeFHE orchestrates the FHE service on a GPU host. Such an instance
	// is not a TEE, does not attest, and runs no training pipeline.
	ServerTypeFHE = "fhe"
)

// FHE section defaults. maxEvalKeyBytes is deliberately independent of
// codeAudit.resultCheck.maxFileBytes: a measured eval_context.bin is
// 3,329,929,205 B and the result-check cap defaults to 3 GiB, which is 103.7 MiB
// too small to download a real key.
const (
	DefaultFHEMaxEvalKeyBytes   = int64(6) << 30 // 6442450944
	DefaultFHEPollIntervalMs    = 5000
	DefaultFHERequestTimeoutMs  = 30000
	DefaultFHETaskTimeoutMs     = 1800000
)

// FHEConfig is the parsed fhe section. It is only consulted when
// server.type=fhe.
type FHEConfig struct {
	Endpoint              string `json:"endpoint"`
	DataDir               string `json:"dataDir"`
	KeyCacheDir           string `json:"keyCacheDir"`
	CallbackBaseURL       string `json:"callbackBaseUrl"`
	CallbackToken         string `json:"callbackToken"`
	MaxEvalKeyBytes       int64  `json:"maxEvalKeyBytes"`
	PollIntervalMs        int    `json:"pollIntervalMs"`
	RequestTimeoutMs      int    `json:"requestTimeoutMs"`
	TaskTimeoutMs         int    `json:"taskTimeoutMs"`
	ActivateModelOnImport bool   `json:"activateModelOnImport"`
}

type fheConfigFile = FHEConfig
```

`StartupConfig`（`config.go:17`）加两个字段，放在 `Addr` / `PlatformIP` / `DockerID` / `Contract` 之后：

```go
type StartupConfig struct {
	Addr       string
	PlatformIP string
	DockerID   string
	Contract   string
	// ServerType is "tee" (the default) or "fhe", from server.type.
	ServerType string
	// FHE is non-nil only on a server.type=fhe instance.
	FHE *FHEConfig
	...
}
```

- [ ] **Step 4: 在 `applyStartupConfigFile` 里解析**

在 `applyStartupConfigFile`（`config.go:599`）里，紧跟 `server.addr` 那两行之后插入：

```go
	if trimmed := strings.ToLower(strings.TrimSpace(fileCfg.Server.Type)); trimmed != "" {
		cfg.ServerType = trimmed
	}
```

并在函数末尾（既有字段全部赋完之后）追加：

```go
	// The fhe section is only meaningful on an fhe instance. A tee instance that
	// carries one is a deployment mistake, but not a fatal one: warn and drop it
	// so the instance keeps behaving exactly as it did before the section existed.
	if fileCfg.FHE != nil {
		if cfg.ServerType == ServerTypeFHE {
			f := *fileCfg.FHE
			applyFHEDefaults(&f)
			cfg.FHE = &f
		} else {
			log.Printf("WARN: startup config carries an fhe section but server.type is %q; the section is ignored", cfg.ServerType)
		}
	}
```

`log` 若未导入则加 `"log"`。同文件加：

```go
// applyFHEDefaults fills the optional fhe fields. Required fields are left as
// they are: an empty required field must be rejected, not silently defaulted.
func applyFHEDefaults(f *FHEConfig) {
	if f.MaxEvalKeyBytes == 0 {
		f.MaxEvalKeyBytes = DefaultFHEMaxEvalKeyBytes
	}
	if f.PollIntervalMs == 0 {
		f.PollIntervalMs = DefaultFHEPollIntervalMs
	}
	if f.RequestTimeoutMs == 0 {
		f.RequestTimeoutMs = DefaultFHERequestTimeoutMs
	}
	if f.TaskTimeoutMs == 0 {
		f.TaskTimeoutMs = DefaultFHETaskTimeoutMs
	}
}
```

`ActivateModelOnImport` 的默认值：JSON 里缺字段时 Go 得到 `false`，无法和显式 `false` 区分。用指针：

```go
	ActivateModelOnImport *bool `json:"activateModelOnImport"`
```

然后 `applyFHEDefaults`：

```go
	if f.ActivateModelOnImport == nil {
		v := true
		f.ActivateModelOnImport = &v
	}
```

并把 `FHEConfig.ActivateModelOnImport` 声明为 `*bool`。测试里的断言随之改成解引用：

```go
	if cfg.FHE.ActivateModelOnImport == nil || !*cfg.FHE.ActivateModelOnImport {
		t.Error("ActivateModelOnImport must default to true")
	}
```

（`TestFHESectionIsParsedWhenTypeIsFHE` 里同样改成 `*cfg.FHE.ActivateModelOnImport`。）

`cfg.ServerType` 需要一个 `tee` 初值，否则「配置里没写 `server.type`」会得到空串并落进 `validateServerType` 的拒绝分支。在 `LoadStartupConfig`（`config.go:344`）构造 `StartupConfig` 的那处字面量里写上 `ServerType: ServerTypeTEE`，与 `applyStartupConfigFile`「只在非空时覆盖」配套。

- [ ] **Step 5: 在 `validateStartupConfig` 里加校验**

`validateStartupConfig`（`config.go:442`）改成下面这样，其余五个校验函数一行不动：

```go
func validateStartupConfig(cfg StartupConfig) error {
	if err := validateServerType(cfg); err != nil {
		return err
	}
	if err := validateFHEConfig(cfg); err != nil {
		return err
	}
	if err := validateCodeScanEngine(cfg); err != nil {
		return err
	}
	if err := validateSemgrepTimeout(cfg); err != nil {
		return err
	}
	if err := validateLLMTemperature(cfg); err != nil {
		return err
	}
	if err := validateBinaryAudit(cfg); err != nil {
		return err
	}
	return validateLLMPolicy(cfg)
}

// validateServerType rejects an unrecognised server.type rather than falling back
// to tee. A silent fallback would leave a deployment believing it runs one kind
// of instance while it runs the other.
func validateServerType(cfg StartupConfig) error {
	switch cfg.ServerType {
	case ServerTypeTEE, ServerTypeFHE:
		return nil
	}
	return fmt.Errorf("unsupported server.type %q in startup config: must be one of %s, %s",
		cfg.ServerType, ServerTypeTEE, ServerTypeFHE)
}

// validateFHEConfig enforces the fhe section on an fhe instance. All five
// connection fields are required: a half-configured instance would fail at task
// time, after the platform was already told the import succeeded. callbackToken
// especially - an unauthenticated callback endpoint is open to every process on
// the host.
func validateFHEConfig(cfg StartupConfig) error {
	if cfg.ServerType != ServerTypeFHE {
		return nil
	}
	if cfg.FHE == nil {
		return fmt.Errorf("server.type is %q but the startup config has no fhe section", ServerTypeFHE)
	}
	required := []struct {
		name  string
		value string
	}{
		{"endpoint", cfg.FHE.Endpoint},
		{"dataDir", cfg.FHE.DataDir},
		{"keyCacheDir", cfg.FHE.KeyCacheDir},
		{"callbackBaseUrl", cfg.FHE.CallbackBaseURL},
		{"callbackToken", cfg.FHE.CallbackToken},
	}
	for _, r := range required {
		if strings.TrimSpace(r.value) == "" {
			return fmt.Errorf("fhe.%s is required when server.type is %q", r.name, ServerTypeFHE)
		}
	}
	if err := validateFHEEndpoint(cfg.FHE.Endpoint); err != nil {
		return err
	}
	if cfg.FHE.MaxEvalKeyBytes <= 0 {
		return fmt.Errorf("unsupported fhe.maxEvalKeyBytes %d in startup config: must be positive", cfg.FHE.MaxEvalKeyBytes)
	}
	for _, b := range []struct {
		name  string
		value int
	}{
		{"pollIntervalMs", cfg.FHE.PollIntervalMs},
		{"requestTimeoutMs", cfg.FHE.RequestTimeoutMs},
		{"taskTimeoutMs", cfg.FHE.TaskTimeoutMs},
	} {
		if b.value <= 0 {
			return fmt.Errorf("unsupported fhe.%s %d in startup config: must be positive", b.name, b.value)
		}
	}
	return nil
}

func validateFHEEndpoint(endpoint string) error {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return fmt.Errorf("unsupported fhe.endpoint %q in startup config: %v", endpoint, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("unsupported fhe.endpoint %q in startup config: must be an absolute http or https URL", endpoint)
	}
	return nil
}
```

`net/url` 若未导入则加。

- [ ] **Step 6: 跑测试确认通过**

Run: `go test ./internal/config/... -run 'TestServerType|TestFHE' -v`
Expected: PASS（8 个测试）。

- [ ] **Step 7: 跑整个 config 包，确认既有行为未变**

Run: `go test ./internal/config/...`
Expected: PASS（既有配置测试全绿；`server.type` 缺省为 `tee`，三份既有模板无需改动）。

- [ ] **Step 8: 提交**

```bash
git add internal/config/config.go internal/config/fhe_config_test.go
git commit -m "feat(config): add server.type and the fhe config section"
```

---

## Task 7: 控制器状态与装配

**Files:**
- Modify: `internal/controller/route.go`
- Modify: `internal/app/taa/app.go`

- [ ] **Step 1: 在 `TAAState` 上加字段**

`route.go` 的 `TAAState` 结构体加：

```go
	// FHE is nil unless this instance runs as server.type=fhe. A nil runner is
	// the single switch every FHE branch keys on, so a tee instance cannot
	// accidentally enter an FHE path.
	FHE *fhe.Runner
	// fheActiveTaskID is the FHE task currently in flight, so stopTraining can be
	// mapped onto the service's cancel endpoint. It is empty when no FHE task runs.
	fheActiveTaskID string
```

`route.go` 的 import 块加 `"taa/internal/fhe"`。

- [ ] **Step 2: 加访问器**

`route.go` 里（`setCurrentOp` 附近）：

```go
// SetFHERunner installs the FHE runner. It is called once at boot on a
// server.type=fhe instance, before the HTTP server starts.
func (s *TAAState) SetFHERunner(r *fhe.Runner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FHE = r
}

// fheEnabled reports whether this instance orchestrates the FHE service.
func (s *TAAState) fheEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.FHE != nil
}

// fheRunner returns the FHE runner, or nil on a tee instance.
func (s *TAAState) fheRunner() *fhe.Runner {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.FHE
}

func (s *TAAState) setFHEActiveTask(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fheActiveTaskID = taskID
}

func (s *TAAState) clearFHEActiveTask(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fheActiveTaskID == taskID {
		s.fheActiveTaskID = ""
	}
}

func (s *TAAState) fheActiveTask() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fheActiveTaskID
}
```

- [ ] **Step 3: 在 `app.go` 里装配**

`internal/app/taa/app.go` 的 `buildSecurityConfig` 之后新增：

```go
// buildFHERunner returns the FHE runner for this instance, or nil when the
// instance is a tee. The runner is the only thing that talks to the FHE service,
// so nil here means every FHE code path stays unreachable.
func buildFHERunner(cfg config.StartupConfig) (*fhe.Runner, error) {
	if cfg.ServerType != config.ServerTypeFHE {
		return nil, nil
	}
	if cfg.FHE == nil {
		return nil, fmt.Errorf("server.type is %q but the startup config has no fhe section", config.ServerTypeFHE)
	}
	f := *cfg.FHE
	activate := true
	if f.ActivateModelOnImport != nil {
		activate = *f.ActivateModelOnImport
	}
	return fhe.New(fhe.Config{
		Endpoint:              f.Endpoint,
		DataDir:               f.DataDir,
		KeyCacheDir:           f.KeyCacheDir,
		CallbackBaseURL:       f.CallbackBaseURL,
		CallbackToken:         f.CallbackToken,
		MaxEvalKeyBytes:       f.MaxEvalKeyBytes,
		PollInterval:          time.Duration(f.PollIntervalMs) * time.Millisecond,
		RequestTimeout:        time.Duration(f.RequestTimeoutMs) * time.Millisecond,
		TaskTimeout:           time.Duration(f.TaskTimeoutMs) * time.Millisecond,
		ActivateModelOnImport: activate,
	}, nil)
}
```

在 `NewTAAState` 调用处（约 179 行）之后紧接着：

```go
	fheRunner, err := buildFHERunner(cfg)
	if err != nil {
		return nil, fmt.Errorf("build the FHE runner: %w", err)
	}
	if fheRunner != nil {
		state.SetFHERunner(fheRunner)
		// The runner needs a logger, and TAAState owns the log store, so the
		// adapter is installed after the state exists.
		fheRunner.SetLogger(func(level fhe.Level, scope, format string, args ...any) {
			switch level {
			case fhe.LevelWarn:
				state.Logs.Add(controller.LogWarn, scope, format, args...)
			case fhe.LevelError:
				state.Logs.Add(controller.LogError, scope, format, args...)
			default:
				state.Logs.Add(controller.LogInfo, scope, format, args...)
			}
		})
		log.Printf("instance type: fhe (endpoint=%s, dataDir=%s)", cfg.FHE.Endpoint, cfg.FHE.DataDir)
	} else {
		log.Printf("instance type: tee")
	}
```

`fhe.Runner` 需要一个 `SetLogger`：

在 `internal/fhe/runner.go` 加：

```go
// SetLogger installs the logger after construction, for callers that only have
// a logger once the state they log into exists.
func (r *Runner) SetLogger(logf Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logf = logf
}
```

`logf` 现在被两个 goroutine 读，要加锁读。把 `log` 方法改成：

```go
func (r *Runner) log(level Level, format string, args ...any) {
	r.mu.Lock()
	logf := r.logf
	r.mu.Unlock()
	if logf == nil {
		return
	}
	logf(level, "fhe", format, args...)
}
```

并确认 `go test -race ./internal/fhe/...` 通过。

- [ ] **Step 4: `type=fhe` 跳过启动期证明**

现场签名是 `prepareAttestationReport(ctx context.Context, userData []byte, hrkCertPath, hskCekCertPath string) (bool, error)`（`app.go:568`）：第一个返回值是 `verifiedPass`，报告写到包级常量 `fixedAttestationFile`，**不由调用方传路径**。它已经会降级（生成失败就写一个空报告、返回 `(false, nil)`），所以 FHE 实例要做的不是「传空路径」，而是**根本不调用它**，直接给 `verifiedPass = false`——省掉的是那次注定失败的 CSV 调用和它刷出的 WARN。

把 `app.go:141` 那一处：

```go
	// 4. Generate attestation report containing UserData and perform certificate self-verification
	verifiedPass, err := prepareAttestationReport(ctx, userData, cfg.AttestationHRKCertPath, cfg.AttestationHSKCekCertPath)
	if err != nil {
		return err
	}
```

改成：

```go
	// 4. Generate attestation report containing UserData and perform certificate self-verification
	//
	// A server.type=fhe instance is not a TEE: it runs on a plain GPU host with no
	// /dev/csv-guest, so the report can only fail and fill the log with warnings.
	// The skip is explicit rather than inferred from that failure, and
	// verifiedPass stays false - the platform must not read "fhe" as "attested".
	verifiedPass := false
	if cfg.ServerType == config.ServerTypeFHE {
		log.Printf("instance type is fhe: remote attestation is not provided by this instance")
	} else {
		var err error
		verifiedPass, err = prepareAttestationReport(ctx, userData, cfg.AttestationHRKCertPath, cfg.AttestationHSKCekCertPath)
		if err != nil {
			return err
		}
	}
```

`err` 在上面已被 `deriveUserData` 声明过，所以内层用 `var err error` 遮蔽、外层保持可用；注册路径（`registerPlatform(..., verifiedPass)`）与后台重试都不用改。

- [ ] **Step 5: 编译并跑测试**

Run: `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`
Expected: 构建成功。

Run: `go test ./internal/controller/... ./internal/app/...`
Expected: PASS。已知 `TestControllerConcurrency`（异步流水线活过 `t.TempDir()` 清理）约 7.5% 概率自失败，与本改动无关；失败时重跑一次确认。

- [ ] **Step 6: 提交**

```bash
git add internal/controller/route.go internal/app/taa/app.go internal/fhe/runner.go
git commit -m "feat(controller): wire the FHE runner into TAA state and skip attestation on fhe"
```

---

## Task 8: `import` 契约变更与字段校验

**Files:**
- Modify: `internal/controller/handler_task.go`
- Create: `internal/controller/fhe_processing.go`
- Modify: `internal/controller/import_processing.go`

- [ ] **Step 1: `importRequest` 加两个字段**

`handler_task.go`：

```go
type importRequest struct {
	ResourceURL   string  `json:"resourceUrl"`
	RequestID     string  `json:"requestId"`
	TaskID        string  `json:"taskId"`
	PublicKey     *string `json:"publicKey,omitempty"`
	RuntimeConfig string  `json:"runtimeConfig,omitempty"`

	// EvalKeyURL and EvalKeyFileHash are the FHE contract's additions.
	//
	// EvalKeyURL does double duty: it selects the FHE branch (a non-empty value
	// means this is an FHE task, not a training run), and it is where the eval key
	// is fetched from when it is not already cached. EvalKeyFileHash is the SM3
	// digest of that key; it names the cache entry and is the FHE-side user id.
	//
	// The hash is required even on a cache hit: it declares which user the task
	// belongs to, which the URL alone cannot say.
	EvalKeyURL      string `json:"evalKeyUrl,omitempty"`
	EvalKeyFileHash string `json:"evalKeyFileHash,omitempty"`
}
```

- [ ] **Step 2: 在 `importHandler` 里判分支**

在 `importHandler` 解析完 `ResourceURL`/`RequestID`/`TaskID` 之后、`unwrapDataKeyCipherFromURL` 之前插入：

```go
	req.EvalKeyURL = strings.TrimSpace(req.EvalKeyURL)
	req.EvalKeyFileHash = strings.TrimSpace(req.EvalKeyFileHash)
	if err := s.validateFHEFields(req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
	}
```

在 `fhe_processing.go` 里实现：

```go
// validateFHEFields enforces the two eval key fields against the instance type.
//
// On an fhe instance both are mandatory: this instance exists to run FHE tasks,
// so an import without them has no meaning. On a tee instance their presence is
// an error rather than something to ignore - silently dropping them would let the
// platform believe an FHE task was submitted when nothing was.
func (s *TAAState) validateFHEFields(req importRequest) error {
	hasURL := strings.TrimSpace(req.EvalKeyURL) != ""
	hasHash := strings.TrimSpace(req.EvalKeyFileHash) != ""

	if !s.fheEnabled() {
		if hasURL || hasHash {
			return fmt.Errorf("本实例类型为 tee，不接受 evalKeyUrl / evalKeyFileHash 字段")
		}
		return nil
	}
	if !hasURL || !hasHash {
		return fmt.Errorf("本实例类型为 fhe，evalKeyUrl 与 evalKeyFileHash 必须同时提供")
	}
	if !fhe.ValidHash(req.EvalKeyFileHash) {
		return fmt.Errorf("evalKeyFileHash 必须是 64 位小写十六进制 SM3 摘要")
	}
	return nil
}
```

- [ ] **Step 3: 建 `fhe_processing.go`，先只放 `validateFHEFields`**

创建 `internal/controller/fhe_processing.go`，**本步只写这一个函数**，文件的其余内容在 Task 9 追加：

```go
package controller

import (
	"fmt"
	"strings"

	"taa/internal/fhe"
)

// validateFHEFields enforces the two eval key fields against the instance type.
//
// On an fhe instance both are mandatory: this instance exists to run FHE tasks,
// so an import without them has no meaning. On a tee instance their presence is
// an error rather than something to ignore - silently dropping them would let the
// platform believe an FHE task was submitted when nothing was.
func (s *TAAState) validateFHEFields(req importRequest) error {
	hasURL := strings.TrimSpace(req.EvalKeyURL) != ""
	hasHash := strings.TrimSpace(req.EvalKeyFileHash) != ""

	if !s.fheEnabled() {
		if hasURL || hasHash {
			return fmt.Errorf("本实例类型为 tee，不接受 evalKeyUrl / evalKeyFileHash 字段")
		}
		return nil
	}
	if !hasURL || !hasHash {
		return fmt.Errorf("本实例类型为 fhe，evalKeyUrl 与 evalKeyFileHash 必须同时提供")
	}
	if !fhe.ValidHash(req.EvalKeyFileHash) {
		return fmt.Errorf("evalKeyFileHash 必须是 64 位小写十六进制 SM3 摘要")
	}
	return nil
}
```

- [ ] **Step 4: 编译**

Run: `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`
Expected: 构建成功。（行为测试在 Task 9 的 `fhe_processing_test.go` 里，因为要驱动真实的 handler。）

- [ ] **Step 5: 提交**

```bash
git add internal/controller/handler_task.go internal/controller/fhe_processing.go
git commit -m "feat(controller): accept and validate the eval key fields on import"
```

---

## Task 9: FHE 任务执行与结果落盘

**Files:**
- Modify: `internal/controller/fhe_processing.go`
- Modify: `internal/controller/import_processing.go`（加分支；仅复用既有 `buildAndSaveTrainingReport`）

- [ ] **Step 1: 加分支并实现模型落盘与任务派发**

先在 `import_processing.go` 的 `processImportedResource` 里插入分支。位置是解密步骤（`if isDecrypted { defer os.Remove(plaintextPath) }`）之后、`trainRecord := ...` 之前：

```go
	// An fhe instance hands the resolved resource straight to the FHE service
	// instead of the training pipeline. The branch sits here, after decryption, so
	// the two instance types share one download/decode path and one concurrency
	// gate, and diverge only in what they do with the bytes.
	if s.fheEnabled() {
		s.processImportedResourceFHE(req, phase, isModel, plaintextPath, startedAt)
		return
	}
```

再把下列内容追加到 `internal/controller/fhe_processing.go`（`validateFHEFields` 已在该文件里，导入块补上新增的包）：

```go
import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"taa/internal/fhe"
	"taa/internal/resource"
	"taa/internal/platform"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

// processImportedResourceFHE runs the FHE branch of an import.
//
// A model package is staged into the shared directory and activated; a data
// package is staged as a task input and submitted, which is what triggers FHE
// execution - the platform does not call switch to start a run.
func (s *TAAState) processImportedResourceFHE(req importRequest, phase int, isModel bool, plaintextPath string, startedAt time.Time) {
	runner := s.fheRunner()
	if runner == nil {
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, isModel, startedAt, "FHE 运行器未初始化")
		return
	}
	defer s.setCurrentOp("idle")

	if isModel {
		s.importFHEModel(req, phase, plaintextPath, startedAt, runner)
		return
	}
	s.executeFHETask(req, phase, plaintextPath, startedAt, runner)
}

// importFHEModel stages a model package into the shared directory and activates it.
//
// It deliberately does not go through beginModelImportAndAudit: an FHE model is a
// set of FHE layers and parameters the runtime loads, not user-supplied
// executable code, so there is no code audit to owe and no export public key to
// record. Skipping that call is what keeps the model-import path envelope-free.
func (s *TAAState) importFHEModel(req importRequest, phase int, plaintextPath string, startedAt time.Time, runner *fhe.Runner) {
	size, hash, err := teecrypto.HashFileSM3(plaintextPath)
	if err != nil {
		s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("计算模型包哈希失败: %v", err))
		return
	}
	s.setModelChecksum(map[string]any{"size": size, "algorithm": "sm3", "value": hash})

	if req.PublicKey != nil && strings.TrimSpace(*req.PublicKey) != "" {
		s.Logs.Add(LogWarn, "importModel", "FHE 实例不提供导出信封，忽略请求携带的 publicKey")
	}

	layout := runner.Layout()
	modelDir, err := layout.ModelDir(hash)
	if err != nil {
		s.reportImportFailure(req, phase, true, startedAt, err.Error())
		return
	}
	if err := os.MkdirAll(modelDir, 0o755); err != nil {
		s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("创建模型目录失败: %v", err))
		return
	}
	if err := extractArchiveToDir(modelDir, plaintextPath); err != nil {
		s.reportImportFailure(req, phase, true, startedAt, fmt.Sprintf("解压模型包失败: %v", err))
		return
	}
	// The package layout is the delivery bundle's, not ours to guess: an archive
	// without server/ is the wrong package, and inventing a level for it would
	// surface much later as an activation failure.
	if _, err := os.Stat(filepath.Join(modelDir, "server")); err != nil {
		s.reportImportFailure(req, phase, true, startedAt, "模型包结构不符：解压后缺少 server/ 目录")
		return
	}
	s.Logs.Add(LogInfo, "importModel", "FHE 模型已落盘: modelId=%s, dir=%s", hash, modelDir)

	s.reportModelImportAsync(req.RequestID, req.TaskID, 0, "模型导入成功", map[string]any{
		"size": size, "algorithm": "sm3", "value": hash,
	})

	if runner.Config().ActivateModelOnImport {
		ctx, cancel := context.WithTimeout(context.Background(), runner.Config().RequestTimeout)
		err := runner.Client().ActivateModel(ctx, hash)
		cancel()
		if err != nil {
			// Activation is idempotent and retried on the next import, so a failure
			// here is reported but does not fail the import: the model is on disk and
			// the service also loads it lazily on the first task.
			s.Logs.Add(LogWarn, "importModel", "FHE 模型激活失败(将在首次任务时重试): modelId=%s, err=%v", hash, err)
		} else {
			s.Logs.Add(LogInfo, "importModel", "FHE 模型已激活: modelId=%s", hash)
		}
	}

	s.Logs.Add(LogInfo, "import", "阶段%d: FHE 模型导入完成(免代码审计)，等待数据下发触发 FHE 任务: taskId=%s", phase, req.TaskID)
}
```

- [ ] **Step 2: 实现 `executeFHETask`**

追加到同一个文件：

```go
// executeFHETask stages the input archive, submits the FHE task, waits for its
// terminal state, and writes the result into the task's ResultDir.
//
// The result archive is kept byte-for-byte under its delivery-bundle name
// output.zip, alongside a training_report.json written by the same helper the
// training path uses. Reusing that report is what lets export work unchanged:
// it requires training_report.json to exist, and it is the same file the
// platform already knows how to read.
func (s *TAAState) executeFHETask(req importRequest, phase int, plaintextPath string, startedAt time.Time, runner *fhe.Runner) {
	isArchive, err := isArchiveFile(plaintextPath)
	if err != nil || !isArchive {
		s.reportImportFailure(req, phase, false, startedAt, "输入包不是压缩包，FHE 任务输入必须是 zip")
		return
	}

	s.mu.RLock()
	modelHash := ""
	if v, ok := s.ModelChecksum["value"].(string); ok {
		modelHash = v
	}
	s.mu.RUnlock()
	if modelHash == "" {
		s.reportImportFailure(req, phase, false, startedAt, "尚未导入模型：FHE 任务需要先通过 importModel 下发模型包")
		return
	}

	resultDir := resultDirForRequestTask(s.Security.ResultDir, req.RequestID, req.TaskID)
	if err := os.MkdirAll(resultDir, 0o755); err != nil {
		s.reportImportFailure(req, phase, false, startedAt, fmt.Sprintf("创建结果目录失败: %v", err))
		return
	}

	spec := fhe.TaskSpec{
		TaskID:       req.TaskID,
		RequestID:    req.RequestID,
		UserID:       req.EvalKeyFileHash,
		ModelID:      modelHash,
		EvalKeyHash:  req.EvalKeyFileHash,
		EvalKeyURL:   req.EvalKeyURL,
		InputZipPath: plaintextPath,
	}

	s.setFHEActiveTask(req.TaskID)
	defer s.clearFHEActiveTask(req.TaskID)
	s.promoteCurrentTaskToFHE()

	s.Logs.Add(LogInfo, "fhe", "开始执行 FHE 任务: taskId=%s, userId=%s, modelId=%s", req.TaskID, spec.UserID, spec.ModelID)
	outcome, execErr := runner.Execute(context.Background(), spec, func(done, total int) {
		if total <= 0 {
			return
		}
		s.reportFHEProgress(req.RequestID, req.TaskID, float64(done)/float64(total)*100)
	})

	status, failureReason, code, msg := "succeeded", "", 0, ""
	if execErr != nil {
		status = "failed"
		failureReason = execErr.Error()
		code = reportCodeFHEFailure
		msg = fmt.Sprintf("FHE 任务失败: %s", execErr.Error())
		s.Logs.Add(LogError, "fhe", "FHE 任务失败: taskId=%s, err=%v", req.TaskID, execErr)
	} else {
		s.Logs.Add(LogInfo, "fhe", "FHE 任务完成: taskId=%s, cases=%d, failed=%d", req.TaskID, outcome.Total, outcome.Failed)
	}

	// The ciphertext result is not scanned for plaintext leakage: the artifacts
	// are FHE ciphertexts, which is exactly what this instance exists to move. The
	// verdict is still recorded, because export reads it under fail-closed and a
	// missing verdict would turn a correct export into a 500.
	verdict := &resource.ResultCheckVerdict{
		Passed:    true,
		Details:   []string{"skipped: FHE ciphertext result"},
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if store, err := s.importIndexStore(); err != nil {
		s.Logs.Add(LogWarn, "fhe", "加载导入索引失败，跳过裁决未能落盘: %v", err)
	} else if err := store.SetResultCheck(req.RequestID, req.TaskID, verdict); err != nil {
		s.Logs.Add(LogWarn, "fhe", "保存跳过裁决失败: %v", err)
	}

	resultPath := ""
	if execErr == nil {
		dst := filepath.Join(resultDir, "output.zip")
		_, err := runner.CopyResult(context.Background(), spec, outcome, dst)
		if err != nil {
			status = "failed"
			failureReason = fmt.Sprintf("取回 FHE 结果失败: %v", err)
			code = reportCodeFHEFailure
			msg = failureReason
			s.Logs.Add(LogError, "fhe", "取回 FHE 结果失败: taskId=%s, err=%v", req.TaskID, err)
		} else {
			resultPath = dst
			s.Logs.Add(LogInfo, "fhe", "FHE 结果已落盘: %s", dst)
		}
	}
	_ = resultPath

	report, err := s.buildAndSaveTrainingReport(req.TaskID, startedAt, time.Now().UTC(), status, 0, failureReason, s.getLastAudit(), false, resultDir, verdict)
	if err != nil {
		s.Logs.Add(LogError, "fhe", "生成结果报告失败: %v", err)
		return
	}
	s.reportTrainingAsync(req.RequestID, req.TaskID, code, msg, string(report))
	s.Logs.Add(LogInfo, "import", "FHE 导入流程完成: taskId=%s, phase=%d", req.TaskID, phase)
}

// promoteCurrentTaskToFHE marks the in-flight import as a running task.
//
// It sets CurrentOp to "training" and nothing else. That string is load-bearing:
// isTrainingBusyLocked（route.go:673）keys on it, so without it a status query
// during an FHE run would report the instance as free while a task is using the
// GPU. It is deliberately the existing value rather than a new "fhe" one, because
// effectiveOpLocked returns CurrentOp verbatim to the platform and a value the
// platform has never seen would be a status it cannot render.
//
// TrainingRunning stays false on purpose: no training process exists, and setting
// that flag would make stopTraining try to kill a process group that is not there.
// The FHE task is tracked by fheActiveTaskID instead, which is what stopTraining
// checks first.
//
// activeTask.Type is likewise left alone. tryAcquireTask already set it to
// "data_import" or "training", and it is echoed to the platform as taskType by
// the panic-recovery path（route.go:890）, so overwriting it with a new string
// would send an unknown task type on the one path that is already going wrong.
func (s *TAAState) promoteCurrentTaskToFHE() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentOp = "training"
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "task", "持久化 FHE 任务状态失败: %v", err)
	}
}

// reportFHEProgress forwards a task's percentage to the platform.
func (s *TAAState) reportFHEProgress(requestID, taskID string, percent float64) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()
	if platformIP == "" {
		return
	}
	go func() {
		if err := platform.ReportProgress(context.Background(), platformIP, dockerID, requestID, taskID, percent, time.Now().UTC()); err != nil {
			s.Logs.Add(LogWarn, "fhe", "上报 FHE 任务进度失败: %v", err)
		}
	}()
}
```

`reportCodeFHEFailure` 加到 `internal/controller/result_files.go`——`reportCodeResultLeak = 2` 就在那里（`result_files.go:25`），编号保持在一处：

```go
// reportCodeFHEFailure is the /v1/taa/reportRes code for a failed FHE task. It is
// deliberately its own code rather than reusing the training-failure one: the two
// instance types fail for different reasons, and a single code would make the
// platform's log unable to tell them apart. 3 is the next free number after
// reportCodeResultLeak.
const reportCodeFHEFailure = 3
```

`platform` 包在 `fhe_processing.go` 里需要导入 `"taa/internal/platform"`（`ReportProgress` 在那里，`reporter.go:255`）。

- [ ] **Step 3: 编译**

Run: `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`
Expected: 构建成功。

- [ ] **Step 4: 写控制器层测试**

创建 `internal/controller/fhe_processing_test.go`：

```go
package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateFHEFieldsOnTEEInstance(t *testing.T) {
	s := &TAAState{}
	if err := s.validateFHEFields(importRequest{}); err != nil {
		t.Errorf("empty fields on a tee instance = %v, want nil", err)
	}
	for _, req := range []importRequest{
		{EvalKeyURL: "http://x/key"},
		{EvalKeyFileHash: strings.Repeat("a", 64)},
		{EvalKeyURL: "http://x/key", EvalKeyFileHash: strings.Repeat("a", 64)},
	} {
		err := s.validateFHEFields(req)
		if err == nil {
			t.Errorf("FHE fields on a tee instance = nil, want an error for %+v", req)
		} else if !strings.Contains(err.Error(), "tee") {
			t.Errorf("error %q does not name the instance type", err)
		}
	}
}

func TestValidateFHEFieldsOnFHEInstance(t *testing.T) {
	s := &TAAState{FHE: newStubRunner(t)}
	if err := s.validateFHEFields(importRequest{EvalKeyURL: "http://x/key"}); err == nil {
		t.Error("url without a hash = nil, want error")
	}
	if err := s.validateFHEFields(importRequest{EvalKeyFileHash: strings.Repeat("a", 64)}); err == nil {
		t.Error("hash without a url = nil, want error")
	}
	if err := s.validateFHEFields(importRequest{
		EvalKeyURL: "http://x/key", EvalKeyFileHash: strings.Repeat("A", 64),
	}); err == nil {
		t.Error("uppercase hash = nil, want error")
	}
	if err := s.validateFHEFields(importRequest{
		EvalKeyURL: "http://x/key", EvalKeyFileHash: strings.Repeat("a", 64),
	}); err != nil {
		t.Errorf("valid pair = %v, want nil", err)
	}
}

func TestFHEImportRequestFieldsDecode(t *testing.T) {
	body := `{"resourceUrl":"http://x/in.zip","requestId":"r","taskId":"t",
	          "evalKeyUrl":"http://x/eval_context.bin","evalKeyFileHash":"` + strings.Repeat("a", 64) + `"}`
	var req importRequest
	if err := decodeImportRequest(body, &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.EvalKeyURL != "http://x/eval_context.bin" {
		t.Errorf("EvalKeyURL = %q", req.EvalKeyURL)
	}
	if req.EvalKeyFileHash != strings.Repeat("a", 64) {
		t.Errorf("EvalKeyFileHash = %q", req.EvalKeyFileHash)
	}
}

// postImport drives the real handler, so the branch validation is exercised
// through the HTTP surface the platform actually uses.
func postImport(t *testing.T, s *TAAState, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/import", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.importHandler(rec, req)
	return rec
}

func TestImportRejectsFHEFieldsOnTEEInstance(t *testing.T) {
	s, _ := setupTestState(t)
	rec := postImport(t, s, `{"resourceUrl":"http://x/in.zip","requestId":"r","taskId":"t",
	  "evalKeyUrl":"http://x/k","evalKeyFileHash":"`+strings.Repeat("a", 64)+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "tee") {
		t.Errorf("body = %s", rec.Body.String())
	}
}
```

测试文件顶部补上这个文件需要的导入：

```go
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"taa/internal/fhe"
)
```

`newStubRunner` 与 `decodeImportRequest` 是测试辅助，定义在同一个文件底部：

```go
// newStubRunner builds a runner with no live service behind it. The branch
// validation only reads the runner's presence, so no service is needed.
func newStubRunner(t *testing.T) *fhe.Runner {
	t.Helper()
	r, err := fhe.New(fhe.Config{
		Endpoint: "http://127.0.0.1:1", DataDir: t.TempDir(), KeyCacheDir: t.TempDir(),
		CallbackBaseURL: "http://taa:6001", CallbackToken: "t",
		MaxEvalKeyBytes: fhe.DefaultMaxEvalKeyBytes,
		PollInterval:    time.Second, RequestTimeout: time.Second, TaskTimeout: time.Minute,
	}, nil)
	if err != nil {
		t.Fatalf("fhe.New: %v", err)
	}
	return r
}

func decodeImportRequest(body string, req *importRequest) error {
	return json.Unmarshal([]byte(body), req)
}
```

`setupTestState(t)` 在 `handler_test.go:27` 已存在，签名是 `setupTestState(t *testing.T) (*TAAState, string)`。上面与后面所有测试都用 `s, _ := setupTestState(t)` 取 state。

Task 10 与 Task 11 的测试文件在同一个包里，直接复用 `setupTestState` / `newStubRunner`，**不要重新定义**。`s.fheCallbackHandler` 等 handler 是包内方法，测试可以像上面 `s.importHandler` 那样直接调用，不必经 `httptest.Server`。

`setupTestState` 返回的 state 带 `ScanEnabled: false` 与临时目录，正合本文件的需要。`NewTAAState` 会把 `Logs` 初始化为 `NewLogStore(1000)`（`route.go:544`），所以 `s.Logs` 非 nil、可直接断言。

- [ ] **Step 5: 跑测试**

Run: `go test ./internal/controller/... -run 'TestValidateFHEFields|TestFHEImportRequestFieldsDecode|TestImportRejectsFHEFields' -v`
Expected: PASS（4 个测试）。

- [ ] **Step 6: 提交**

```bash
git add internal/controller/handler_task.go internal/controller/import_processing.go \
        internal/controller/fhe_processing.go internal/controller/fhe_processing_test.go
git commit -m "feat(controller): run FHE tasks on import and land their results"
```

---

## Task 10: 回调端点与 stopTraining 映射

**Files:**
- Create: `internal/controller/fhe_callback.go`
- Modify: `internal/controller/router.go`
- Modify: `internal/controller/handler_task.go`（`stopTrainingHandler`）
- Test: `internal/controller/fhe_callback_test.go`

- [ ] **Step 1: 写失败的测试**

创建 `internal/controller/fhe_callback_test.go`：

```go
package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postCallback(t *testing.T, s *TAAState, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/v1/taa/fheCallback"
	if token != "" {
		url += "?token=" + token
	}
	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.fheCallbackHandler(rec, req)
	return rec
}

func TestFHECallbackRejectsMissingOrWrongTokenWithoutConfirmingTheEndpoint(t *testing.T) {
	s, _ := setupTestState(t)
	s.SetFHERunner(newStubRunner(t))

	// The configured token is "t"; none of these is it.
	for _, token := range []string{"", "wrong", "T", "tt", "t "} {
		rec := postCallback(t, s, token, `{"task_id":"t1","status":"completed"}`)
		// 404 rather than 401: a caller without the token must not learn that this
		// endpoint exists.
		if rec.Code != http.StatusNotFound {
			t.Errorf("token %q: status = %d, want 404", token, rec.Code)
		}
	}
}

func TestFHECallbackIsAbsentOnTEEInstance(t *testing.T) {
	s, _ := setupTestState(t)
	rec := postCallback(t, s, "anything", `{"task_id":"t1","status":"completed"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 on a tee instance", rec.Code)
	}
}

func TestFHECallbackRejectsMalformedBody(t *testing.T) {
	s, _ := setupTestState(t)
	s.SetFHERunner(newStubRunner(t))
	rec := postCallback(t, s, "t", `{"status":"completed"}`) // no task id
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestFHECallbackAcceptsAndIsIdempotent(t *testing.T) {
	s, _ := setupTestState(t)
	r := newStubRunner(t)
	s.SetFHERunner(r)

	rec := postCallback(t, s, "t", `{"task_id":"t1","status":"completed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	// The service retries at 0/1/4/16s, so every retry must also answer 200 - a
	// non-2xx would make it keep retrying a task that is already resolved.
	for i := 0; i < 3; i++ {
		rec = postCallback(t, s, "t", `{"task_id":"t1","status":"completed"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("retry %d: status = %d, want 200", i+1, rec.Code)
		}
	}
}

`newStubRunner` 的 `callbackToken` 是 `"t"`，回调测试用它既有的那个 token 即可，不另建一个 helper。
```

`stopTraining` 的 FHE 分支测试：

```go
func TestStopTrainingCancelsTheActiveFHETask(t *testing.T) {
	s, _ := setupTestState(t)
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		_, _ = w.Write([]byte(`{"status":"cancelled"}`))
	}))
	defer srv.Close()

	r, err := fhe.New(fhe.Config{
		Endpoint: srv.URL, DataDir: t.TempDir(), KeyCacheDir: t.TempDir(),
		CallbackBaseURL: "http://taa:6001", CallbackToken: "t",
		MaxEvalKeyBytes: fhe.DefaultMaxEvalKeyBytes,
		PollInterval:    time.Second, RequestTimeout: time.Second, TaskTimeout: time.Minute,
	}, nil)
	if err != nil {
		t.Fatalf("fhe.New: %v", err)
	}
	s.SetFHERunner(r)
	s.setFHEActiveTask("task-1")

	rec := httptest.NewRecorder()
	s.stopTrainingHandler(rec, httptest.NewRequest(http.MethodPost, "/v1/taa/stopTraining", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if len(got) != 1 || got[0] != "POST /api/v1/tasks/task-1/cancel" {
		t.Errorf("calls = %v, want [POST /api/v1/tasks/task-1/cancel]", got)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/controller/... -run 'TestFHECallback|TestStopTrainingCancelsTheActiveFHETask' -v`
Expected: FAIL — undefined `fheCallbackHandler`。

- [ ] **Step 3: 实现回调端点**

创建 `internal/controller/fhe_callback.go`：

```go
package controller

import (
	"io"
	"net/http"

	"taa/internal/fhe"
)

// maxFHECallbackBytes bounds a callback body. The real payload is a small JSON
// document listing cases; the bound exists so a caller holding the token cannot
// make TAA allocate without limit.
const maxFHECallbackBytes = 4 << 20

// fheCallbackHandler receives the FHE service's terminal-state notification.
//
// The service posts the same payload up to four times (0/1/4/16s backoff), so this
// endpoint is idempotent by construction: only the delivery that resolves the
// task does anything, and every delivery answers 200 - a non-2xx would keep the
// service retrying a task that is already finished.
func (s *TAAState) fheCallbackHandler(w http.ResponseWriter, r *http.Request) {
	runner := s.fheRunner()
	if runner == nil {
		// A tee instance has no FHE tasks. Answering 404 rather than 400 also keeps
		// this endpoint invisible on instances that do not serve it.
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !runner.Config().TokenMatches(r.URL.Query().Get("token")) {
		// 404, not 401: a caller that does not hold the token must not learn that
		// this endpoint exists.
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxFHECallbackBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, "读取回调请求体失败", err))
		return
	}
	if len(body) > maxFHECallbackBytes {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "回调请求体过大"))
		return
	}

	payload, err := fhe.ParseCallback(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
	}

	if runner.Deliver(payload) {
		s.Logs.Add(LogInfo, "fhe", "收到 FHE 任务终态回调: taskId=%s, status=%s", payload.TaskID, payload.Status)
	}
	writeEnvelope(w, http.StatusOK, "ok", nil, 0)
}
```

`pkgerrors` 若是本包已有的导入别名，沿用；否则加 `pkgerrors "taa/pkg/errors"`。

- [ ] **Step 4: 注册路由**

`router.go` 的 `taaRoutes` 加一行：

```go
		{"/v1/taa/fheCallback", state.fheCallbackHandler},
```

- [ ] **Step 5: `stopTraining` 映射到 cancel**

`handler_task.go` 的 `stopTrainingHandler` 开头插入：

```go
	// An FHE task is cancelled through the service's own endpoint: there is no
	// local process group to kill, and the worker is the only thing that can stop
	// the run.
	if runner := s.fheRunner(); runner != nil {
		if taskID := s.fheActiveTask(); taskID != "" {
			if err := runner.Cancel(r.Context(), taskID); err != nil {
				s.Logs.Add(LogError, "fhe", "取消 FHE 任务失败: taskId=%s, err=%v", taskID, err)
				writeErr(w, http.StatusInternalServerError,
					pkgerrors.Wrap(pkgerrors.CodeInternal, "取消 FHE 任务失败", err))
				return
			}
			writeEnvelope(w, http.StatusOK, "FHE 任务已取消", nil, 0)
			return
		}
	}
```

- [ ] **Step 6: 跑测试**

Run: `go test ./internal/controller/... -run 'TestFHECallback|TestStopTraining' -v`
Expected: PASS。

- [ ] **Step 7: 提交**

```bash
git add internal/controller/fhe_callback.go internal/controller/fhe_callback_test.go \
        internal/controller/router.go internal/controller/handler_task.go
git commit -m "feat(controller): add the authenticated FHE callback endpoint and cancel mapping"
```

---

## Task 11: `export` 在 FHE 实例上不做信封

**Files:**
- Modify: `internal/controller/handler_export.go`
- Test: `internal/controller/fhe_export_test.go`

- [ ] **Step 1: 写失败的测试**

创建 `internal/controller/fhe_export_test.go`：

```go
package controller

import (
	"strings"
	"testing"
)

// TestExportIgnoresRequestPublicKeyOnFHEInstance pins the plaintext-export
// behaviour: an FHE instance exists to move ciphertext, and the platform decrypts
// it client-side, so an envelope would only put one more layer around bytes that
// are already encrypted.
func TestExportIgnoresRequestPublicKeyOnFHEInstance(t *testing.T) {
	s, _ := setupTestState(t)
	s.SetFHERunner(newStubRunner(t))

	key := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n"
	s.mu.Lock()
	s.ExportPublicKey = ""
	s.mu.Unlock()

	if got := s.exportPublicKeyForRequest(&key); got != "" {
		t.Errorf("exportPublicKeyForRequest = %q, want empty on an FHE instance", got)
	}

	var logged bool
	for _, entry := range s.Logs.All() {
		if strings.Contains(entry.Message, "忽略请求携带的 publicKey") {
			logged = true
		}
	}
	if !logged {
		t.Error("ignoring the key was not logged; a silent drop hides the mismatch")
	}
}

func TestExportUsesRequestPublicKeyOnTEEInstance(t *testing.T) {
	s, _ := setupTestState(t)
	key := "  pem  "
	if got := s.exportPublicKeyForRequest(&key); got != "pem" {
		t.Errorf("exportPublicKeyForRequest = %q, want %q", got, "pem")
	}
}
```

日志用 `logger.Store.All() []logger.Entry` 读（`pkg/logger/logger.go:205`），`Entry.Message` 是已格式化好的字符串，`Entry.Component` 是 `"export"`。用 `All()` 而不是 `Drain()`——`Drain` 会清空缓冲区，断言之后测试里再想看日志就没了。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/controller/... -run 'TestExportIgnoresRequestPublicKey|TestExportUsesRequestPublicKey' -v`
Expected: FAIL — undefined `exportPublicKeyForRequest`。

- [ ] **Step 3: 抽出并实现**

`handler_export.go` 里把现有的 publicKey 取值逻辑抽成一个方法：

```go
// exportPublicKeyForRequest resolves the public key an export should encrypt to.
//
// A server.type=fhe instance always returns empty: it never records an export
// public key, and the export envelope is out of scope for this instance type. A
// key carried in the request would otherwise reintroduce the envelope, so it is
// ignored with a warning rather than silently honoured - the caller expects an
// envelope when it sends one, and a silent drop would leave it unable to read the
// result.
func (s *TAAState) exportPublicKeyForRequest(req *string) string {
	if s.fheEnabled() {
		if req != nil && strings.TrimSpace(*req) != "" {
			s.Logs.Add(LogWarn, "export", "FHE 实例不提供导出信封，忽略请求携带的 publicKey")
		}
		return ""
	}
	if req == nil {
		return ""
	}
	return strings.TrimSpace(*req)
}
```

把 handler 里原来的

```go
	if req.PublicKey != nil {
		reqPubKey = strings.TrimSpace(*req.PublicKey)
	}
```

替换成：

```go
	reqPubKey = s.exportPublicKeyForRequest(req.PublicKey)
```

- [ ] **Step 4: 跑测试**

Run: `go test ./internal/controller/... -run 'TestExport' -v`
Expected: PASS（含既有 export 测试）。

- [ ] **Step 5: 提交**

```bash
git add internal/controller/handler_export.go internal/controller/fhe_export_test.go
git commit -m "feat(export): keep the export envelope off fhe instances"
```

---

## Task 12: 配置模板与文档

**Files:**
- Create: `configs/taa-fhe.json`
- Modify: `README.md`

- [ ] **Step 1: 写 `configs/taa-fhe.json`**

先读 `configs/taa-production.json`，逐段照抄，只改 `server` 段并追加 `fhe` 段——模板之间除本计划说明的差异外必须一致，否则部署时会踩到没人预期的默认值差异。

```
"server": { "addr": ":6001", "type": "fhe" },
"fhe": {
  "endpoint": "http://127.0.0.1:58996",
  "dataDir": "/opt/fhe-data",
  "keyCacheDir": "/root/taa/fhe-keys",
  "callbackBaseUrl": "http://172.16.10.130:6001",
  "callbackToken": "",
  "maxEvalKeyBytes": 6442450944,
  "pollIntervalMs": 5000,
  "requestTimeoutMs": 30000,
  "taskTimeoutMs": 1800000,
  "activateModelOnImport": true
}
```

`callbackToken` 留空是**刻意的**：它必须由部署方填。启动期校验会拒绝空值，所以在模板里留空、在部署脚本里注入，比给一个能跑起来的默认口令安全。

- [ ] **Step 2: 更新 `README.md`**

在配置字段表里补两行：

- `server.type`：实例角色，`tee`（缺省）或 `fhe`。`fhe` 表示该实例在 GPU 节点上编排 FHE 服务，不做代码审计、不做远程证明、不跑训练链路。
- `fhe` 段：仅 `server.type=fhe` 时读取。`endpoint` / `dataDir` / `keyCacheDir` / `callbackBaseUrl` / `callbackToken` 五项必填；`maxEvalKeyBytes`（默认 6 GiB）**独立于** `codeAudit.resultCheck.maxFileBytes`，实测公钥 3.101 GiB 超出后者默认的 3 GiB。

再补一段说明 FHE 实例的接口差异：

- `POST /v1/taa/import` 需带 `evalKeyUrl` 与 `evalKeyFileHash`（SM3 十六进制小写 64 字符）；`tee` 实例带这两个字段会返回 400。
- `importModel` 在 FHE 实例上把模型包铺到 `<fhe.dataDir>/models/<modelHash>/`，要求包内存在 `server/`。
- **执行由 `import` 落盘触发**，不需要先调 `switch`；`switch` 只切阶段。
- 新增 `POST /v1/taa/fheCallback?token=<callbackToken>`，供 FHE 服务回报终态；token 不符返回 404。
- `export` 在 FHE 实例上总是明文 zip（内含 `output.zip` 与 `training_report.json`），请求携带的 `publicKey` 会被忽略并记 WARN。

- [ ] **Step 3: 验证配置能被加载**

Run: `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa && ./bin/taa --config configs/taa-fhe.json --dry-run 2>&1 | head -5`

若无 `--dry-run`，改为临时把 `callbackToken` 填一个值让启动期校验通过、观察进程是否越过配置阶段后退出：

Run: `./bin/taa --help`
Expected: 找到配置路径的传参方式。**空 `callbackToken` 必须启动失败**，这是这一步的验证点；失败信息里应出现 `fhe.callbackToken is required`。

- [ ] **Step 4: 提交**

```bash
git add configs/taa-fhe.json README.md
git commit -m "docs(fhe): add the fhe config template and document the instance type"
```

---

## Task 13: `deploy-fhe.sh`

**Files:**
- Create: `deploy-fhe.sh`

- [ ] **Step 1: 读 `deploy-llm.sh` 的骨架**

Run: `grep -n "^[a-z_]*()\|^set -\|^usage\|^HOST_\|^[A-Z_]*=" deploy-llm.sh | head -60`

照它的参数风格、`set -euo pipefail`、usage 与日志前缀写，不引入新的约定。

- [ ] **Step 2: 写脚本**

`deploy-fhe.sh` 负责 GPU 节点上 FHE 侧的部署，按顺序做五件事：

```bash
#!/usr/bin/env bash
# Deploy the FHE side on a GPU host: import the image, stage the runtime and the
# models into the shared directory, start the api/worker/redis stack, then start
# this host's TAA instance with server.type=fhe.
#
# This script owns the FHE side; deploy.sh owns the TAA image itself.

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/latti-fhe-handoff}"
HOST_DATA_DIR="${HOST_DATA_DIR:-/opt/fhe-data}"
HOST_RUNTIME_DIR="${HOST_RUNTIME_DIR:?HOST_RUNTIME_DIR must point at third_party/latti-ai-runtime}"
TAA_FHE_CONFIG="${TAA_FHE_CONFIG:-configs/taa-fhe.json}"
TAA_CALLBACK_BASE_URL="${TAA_CALLBACK_BASE_URL:?TAA_CALLBACK_BASE_URL must be reachable from the FHE containers}"
TAA_CALLBACK_TOKEN="${TAA_CALLBACK_TOKEN:?TAA_CALLBACK_TOKEN must be set; an unauthenticated callback endpoint is open to every local process}"
API_HOST_PORT="${API_HOST_PORT:-58996}"

log() { printf '[deploy-fhe] %s\n' "$*"; }
die() { printf '[deploy-fhe] ERROR: %s\n' "$*" >&2; exit 1; }
```

步骤：

1. **导入镜像**：`docker load -i "$HANDOFF_DIR/image/latti-server-latest.tar.gz"`，然后断言 `docker images latti/latti-server:latest` 存在。
2. **校验大件，跳过坏的那条**：

   ```bash
   # The bundle's SHA256SUMS lists client/latti-client-wasm-0.1.0.zip while the
   # shipped file is latti-wasm-0.1.1.zip, so an unconditional `sha256sum -c`
   # always fails. Verify the two artifacts that matter, by their real names.
   verify_one() {
     local rel="$1" want
     want="$(awk -v f="$rel" '$2 == f || $2 == "*"f {print $1}' "$HANDOFF_DIR/SHA256SUMS")"
     [ -n "$want" ] || die "SHA256SUMS has no entry for $rel"
     local got
     got="$(sha256sum "$HANDOFF_DIR/$rel" | awk '{print $1}')"
     [ "$got" = "$want" ] || die "checksum mismatch for $rel: got $got want $want"
     log "verified $rel"
   }
   verify_one image/latti-server-latest.tar.gz
   verify_one third_party/latti-ai-runtime.tar.gz
   ```
3. **铺运行时与模型**：`rsync -a --delete "$HANDOFF_DIR/third_party/latti-ai-runtime/" "$HOST_RUNTIME_DIR/"`；`mkdir -p "$HOST_DATA_DIR"/{models,keys,tasks,results}`；`cp -a "$HANDOFF_DIR/data/models/." "$HOST_DATA_DIR/models/"`。
4. **渲染 node.toml 并起栈**：`cd "$HANDOFF_DIR/deploy/docker" && ./scripts/run-node.sh up -d`（`HOST_DATA_DIR` / `HOST_RUNTIME_DIR` 由 `env/node.local.env` 提供，脚本不覆盖它）。
5. **预检**：

   ```bash
   curl -fsS "http://127.0.0.1:${API_HOST_PORT}/api/v1/health" >/dev/null || die "FHE health check failed"
   [ -w "$HOST_DATA_DIR" ] || die "$HOST_DATA_DIR is not writable"
   # A model must activate before a task can run. The bundled cifar10 model is the
   # one the delivery bundle measured against.
   curl -fsS -X POST "http://127.0.0.1:${API_HOST_PORT}/api/v1/models/activate?model_id=cifar10" >/dev/null \
     || die "model activation failed"
   ```
6. **渲染 TAA 配置并起 TAA**：把 `TAA_CALLBACK_BASE_URL` / `TAA_CALLBACK_TOKEN` / `HOST_DATA_DIR` 注入 `configs/taa-fhe.json`，用 `jq` 写一份临时配置到 `$HOST_DATA_DIR/taa-fhe.rendered.json`：

   ```bash
   jq --arg url "$TAA_CALLBACK_BASE_URL" --arg token "$TAA_CALLBACK_TOKEN" \
      --arg endpoint "http://127.0.0.1:${API_HOST_PORT}" --arg data "$HOST_DATA_DIR" \
      '.fhe.callbackBaseUrl = $url | .fhe.callbackToken = $token
       | .fhe.endpoint = $endpoint | .fhe.dataDir = $data' \
      "$TAA_FHE_CONFIG" > taa-fhe.rendered.json
   ```
   再按 `deploy.sh` 起 TAA 容器的方式启动，多挂一条 `-v "$HOST_DATA_DIR:$HOST_DATA_DIR"`。

- [ ] **Step 3: 语法检查**

Run: `bash -n deploy-fhe.sh && shellcheck deploy-fhe.sh || true`
Expected: `bash -n` 无输出（语法通过）；shellcheck 的告警逐条判断。

- [ ] **Step 4: 无 GPU 时 dry-run**

Run: `DRY_RUN=1 ./deploy-fhe.sh`
Expected: 脚本在 `DRY_RUN=1` 下只打印将要执行的命令而不执行。若 Step 2 未实现 `DRY_RUN`，补上：

```bash
run() {
  if [ "${DRY_RUN:-0}" = "1" ]; then printf '[deploy-fhe] would run: %s\n' "$*"; return 0; fi
  "$@"
}
```

并把所有外部命令调用改成 `run docker load -i ...`、`run rsync ...` 等。

- [ ] **Step 5: 提交**

```bash
git add deploy-fhe.sh
git commit -m "feat(deploy): add the GPU-host FHE deployment script"
```

---

## Task 14: platform-mock 与 fake FHE 服务端

**Files:**
- Create: `tools/fake-fhe/main.go`
- Create: `tools/platform-mock/internal/handlers_fhe.go`
- Modify: `tools/platform-mock/internal/server.go`
- Test: `tools/platform-mock/internal/handlers_fhe_test.go`

交付边界是「服务端 + mock 全链」。本轮只做 **mock 的 HTTP 端点**，不做前端卡片——产品级前端在 spec 的「明确不做」里。这样全链可以用 `curl` 与 `go test` 验证，不依赖浏览器。

- [ ] **Step 1: 写 fake FHE 服务端**

创建 `tools/fake-fhe/main.go`：

```go
// Command fake-fhe stands in for the Latti FHE service so the whole TAA
// integration can be exercised on a machine with no GPU.
//
// The real service is CUDA-only (build-info/manifest.json pins
// cuda_architecture 89, Ada) and cannot run here. This one implements the same
// /api/v1 surface and the same shared-directory contract, substituting a trivial
// transform for the homomorphic evaluation: it copies each case's ciphertext to
// <case>.result.bin. It is a contract test double, not a cryptographic
// implementation, and must never be deployed as one.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type task struct {
	ID        string
	UserID    string
	ModelID   string
	Status    string
	Callback  string
	Cases     []caseResult
}

type caseResult struct {
	Entry    string `json:"entry"`
	ResultID string `json:"result_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

type server struct {
	dataDir  string
	delay    time.Duration
	mu       sync.Mutex
	tasks    map[string]*task
	inflight map[string]bool
}

func main() {
	dataDir := flag.String("data-dir", "", "shared data directory (required)")
	addr := flag.String("addr", "127.0.0.1:58996", "listen address")
	delay := flag.Duration("delay", 200*time.Millisecond, "simulated per-task work")
	flag.Parse()
	if *dataDir == "" {
		log.Fatal("fake-fhe: -data-dir is required")
	}
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatalf("fake-fhe: %v", err)
	}
	s := &server{dataDir: *dataDir, delay: *delay, tasks: map[string]*task{}, inflight: map[string]bool{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.health)
	mux.HandleFunc("/api/v1/models", s.models)
	mux.HandleFunc("/api/v1/models/activate", s.activate)
	mux.HandleFunc("/api/v1/tasks", s.createTask)
	mux.HandleFunc("/api/v1/tasks/", s.taskRoutes)
	log.Printf("fake-fhe listening on %s, data dir %s", *addr, *dataDir)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
```

`taskRoutes` 分派 `/tasks/{id}`、`/tasks/{id}/cancel`、`/tasks/{id}/continue`、`/tasks/{id}/results/download`。`createTask` 读 `user_id` / `model_id` / `task_id` / `callback_url`，校验 `keys/<user_id>/eval_context.bin` 与 `models/<model_id>/server/` 存在（**与真服务一致：缺了就该失败**），读 `tasks/<id>/input.zip`，在后台按 case 逐个产出结果写进 `results/<id>/output.zip`，完成或失败后 POST 回调并按 0/1/4/16 s 退避重试。

关键一点：**假服务必须像真服务一样只认本地目录**，否则 mock 全链会绿在一个真服务做不到的前提上。

- [ ] **Step 2: 跑一遍假服务，手工确认契约**

Run:
```bash
go build -o bin/fake-fhe ./tools/fake-fhe
mkdir -p /tmp/fhe-smoke/{models,keys,tasks,results}
echo key > /tmp/fhe-smoke/keys/$(printf 'a%.0s' {1..64})/eval_context.bin 2>/dev/null || \
  { mkdir -p /tmp/fhe-smoke/keys/$(printf 'a%.0s' {1..64}); printf key > /tmp/fhe-smoke/keys/$(printf 'a%.0s' {1..64})/eval_context.bin; }
./bin/fake-fhe -data-dir /tmp/fhe-smoke -addr 127.0.0.1:58996 &
curl -fsS http://127.0.0.1:58996/api/v1/health
```
Expected: `{"status":"ok"}`。测完 `kill %1`。

- [ ] **Step 3: 写 mock 端点**

创建 `tools/platform-mock/internal/handlers_fhe.go`：一个 `POST /api/fhe/submit`，接收两个已上传文件的路径（复用现有上传目录，它已经挂在 `/files/` 上，就是本地 MinIO 的替身）：

```go
// fheSubmitHandler drives the whole FHE chain from the mock: it hashes the eval
// key with SM3, then calls TAA's import with the two new fields, exactly as a
// real platform would.
//
// The key and the input are uploaded first through the existing /api/upload
// endpoint and referenced here by name, which is what makes this a full-chain
// exercise: the mock never touches the shared directory itself.
func fheSubmitHandler(cfg Config, taaAddr string) http.HandlerFunc
```

请求体：

```json
{ "evalKeyFile": "<uploaded name>", "inputZip": "<uploaded name>",
  "requestId": "...", "taskId": "..." }
```

处理流程：

1. 解析两个文件在上传目录里的绝对路径，拒绝任何逃出上传目录的名字（`filepath.Clean` 后必须仍以 `uploadDir` 为前缀）。
2. 用 `teecrypto.HashFileSM3`（`taa/pkg/crypto` 已在 mock 的导入里）算 `evalKeyFileHash`。
3. 组装 TAA 的 import 请求：

   ```go
   body := map[string]any{
       "resourceUrl":     cfg.Addr + "/files/" + inputZip,
       "requestId":       req.RequestID,
       "taskId":          req.TaskID,
       "evalKeyUrl":      cfg.Addr + "/files/" + evalKeyFile,
       "evalKeyFileHash": hash,
   }
   ```
4. 转发到 TAA 的 `/v1/taa/import`（走 `taaAddr`，与既有 mock→TAA 调用同一路径与超时策略），把 TAA 的响应原样回给调用方。

在 `server.go` 的路由表里加：

```go
	mux.HandleFunc("/api/fhe/submit", fheSubmitHandler(cfg, taaAddr))
```

- [ ] **Step 4: 写 mock 端点测试**

创建 `tools/platform-mock/internal/handlers_fhe_test.go`：用 `httptest` 起一个记录请求的假 TAA，断言 `evalKeyUrl` / `evalKeyFileHash` / `resourceUrl` 三个字段的取值，以及 SM3 摘要与文件内容一致；再断言 `../` 形式的名字被拒。

- [ ] **Step 5: 跑测试**

Run: `go test ./tools/platform-mock/... -run 'TestFHESubmit' -v`
Expected: PASS。

- [ ] **Step 6: 端到端串一遍（无 GPU）**

Run:
```bash
go build -o bin/platform-mock ./tools/platform-mock/cmd/platform-mock
go build -o bin/taa ./cmd/taa
go build -o bin/fake-fhe ./tools/fake-fhe
# 1) 起 fake-fhe（-data-dir 指向 TAA 配置里的 fhe.dataDir）
# 2) 起 TAA，用一份 callbackToken 非空的 configs/taa-fhe.json
# 3) 起 platform-mock，taaAddr 指向 TAA
# 4) 通过 mock 上传模型包、eval key、input.zip，调 /api/fhe/submit
# 5) 断言 mock 收到 reportProgress 与 reportRes，且 TAA 的 ResultDir 下有 output.zip 与 training_report.json
# 6) 调 /v1/taa/export，断言拿到明文 zip 且内含 output.zip
```
Expected: 六步全绿。把实际命令与输出记进提交信息。

- [ ] **Step 7: 提交**

```bash
git add tools/fake-fhe tools/platform-mock/internal/handlers_fhe.go \
        tools/platform-mock/internal/handlers_fhe_test.go tools/platform-mock/internal/server.go
git commit -m "feat(mock): add the FHE submit endpoint and a fake FHE service"
```

---

## 完成后的收尾

- [ ] 全量测试（**分步跑，不并行**——同一检出里并发跑测试会让结论不可信）：

```bash
go test ./internal/fhe/... ./internal/config/... ./internal/controller/... ./tools/platform-mock/...
```

- [ ] 加 `-race` 跑一遍 FHE 包与控制器（回调/轮询竞争与 `SetLogger` 的并发读是这一轮的重点）：

```bash
go test -race ./internal/fhe/... ./internal/controller/...
```

- [ ] 静态构建：

```bash
CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa
```

- [ ] 确认 `configs/taa-production.json` / `taa-docker.json` / `taa-initrd.json` **未被改动**（它们都是 tee 实例，`server.type` 缺省即 `tee`）：

```bash
git diff --stat -- configs/taa-production.json configs/taa-docker.json configs/taa-initrd.json
```
Expected: 无输出。

- [ ] 未在本机验证的部分写清楚：真 FHE 栈、真 GPU 推理、交付包基线（冷 108.9 s / 热 78.6 s）只能在 A130 上跑；本机能覆盖的是单测与 fake FHE 契约测试。

---

## 已知风险（来自 spec，实现时不要再重新发现一遍）

1. `resident_max_servers=4` × 单用户约 15.5 GiB ≈ 62 GiB > 该卡 49,140 MiB。按决策 16 保留交付包默认，但生产上多用户并发时需要显式设 `HEONGPU_DEVICE_POOL_MAX_BYTES` 并调低常驻数。
2. `userId = evalKeyFileHash` 意味着**浏览器重新生成密钥 = 一个新用户**，旧用户的常驻上下文会滞留在显存里直到常驻槽位被挤满。运维文档要写明。
3. 公钥缓存不自动淘汰，每个用户 3.1 GiB（`keys/<hash>/` 有硬链接则共享 inode，跨文件系统回退 copy 则翻倍）。按预期用户数预留磁盘。
4. 交付包的 `SHA256SUMS` 是坏的（列的是 `latti-client-wasm-0.1.0.zip`，实际是 `latti-wasm-0.1.1.zip`）。`deploy-fhe.sh` 按实际文件名校验，不无条件 `sha256sum -c`。
5. 回调鉴权是单共享串，够用但不强；FHE 与 TAA 不再同机时需要换成每任务一次性凭据。
6. `type=fhe` 实例不再有训练链路：不带 evalKey 字段的 import 会被 400 拒绝。
7. `GET /tasks/{id}` 的逐 case 结构没有文档。客户端只把 `status` 当承重字段，逐 case 尽力解析，因此猜错的代价只落在进度百分比上；任务最终由 `TaskTimeout` 兜底。**在 A130 上跑真链路时，第一件事是把 `GET /tasks/{id}` 的真实响应抓下来，若结构与 `cases[].result_id` 不同，改 `TaskStatus.caseList` 一处即可。**
