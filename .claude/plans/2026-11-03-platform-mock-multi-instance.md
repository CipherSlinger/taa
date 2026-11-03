# platform-mock 并发多实例 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让一个 platform-mock 进程同时服务多个 TAA 实例，注册、密钥、上报、进度、日志和控制台视图按 `dockerId` 完全隔离；单实例是退化情形，旧行为不变。

**Architecture:** 新增 `instanceManager`，把现有 8 个 store 组织成每个 `dockerId` 一份的 `instanceStores`，落到 `<state-dir>/instances/i-<sha256(id)[:16]>/`，启动时迁移旧版根目录状态。keystore 从单钥改为 `dockerId -> key` 映射并保留旧单钥回退。入站按 envelope 外层 `dockerId` 选钥（仅作提示，验签后才采信明文里的身份），出站目标由注册请求的 `RemoteAddr` 推导并写入 `instance.json`。控制台所有 `/api/*` 接受 `?dockerId=`，反代按 `?dockerId=` 选目标并在转发前删除该参数。

**Tech Stack:** Go 1.24（`net/http`、`httputil.ReverseProxy`、`embed`）、原生 JS、Bash。

---

## File Structure

| 文件 | 责任 |
| --- | --- |
| `tools/platform-mock/internal/instances.go`（新建） | `instanceStores`、`instanceManager`、目录命名、旧状态迁移、实例选择、`?dockerId=` 解析 |
| `tools/platform-mock/internal/instances_test.go`（新建） | 管理器、迁移、默认实例选择、目标解析 |
| `tools/platform-mock/internal/keystore.go` | 每实例密钥映射、旧单钥回退、按 `dockerId` 加封/解封 |
| `tools/platform-mock/internal/handlers_taa.go` | 入站 handler 改为按实例写 store；注册推导目标 |
| `tools/platform-mock/internal/handlers_api.go` | `/api/instances`、按实例状态/重置、聚合 dashboard |
| `tools/platform-mock/internal/handlers_upload.go` | 上传加密回退公钥按选中实例取 |
| `tools/platform-mock/internal/proxy.go` | `deriveTAATarget`、按目标缓存反代、context 携带 `dockerId` |
| `tools/platform-mock/internal/server.go` | 组装 manager、注册全部新签名 handler、总是挂载 `/taa/` |
| `tools/platform-mock/internal/envelope_helpers_test.go` | 测试管理器 helper、按实例加封 helper |
| `tools/platform-mock/internal/static/index.html` | 实例选择器 |
| `tools/platform-mock/internal/static/js/api.js` | `mockFetch`、`withDockerId`、`loadInstances`、`taaFetch` 追加 `dockerId` |
| `tools/platform-mock/internal/static/js/app.js` / `js/logs.js` | `/api/*` 调用改用 `mockFetch` |
| `deploy.sh` | `MULTI_INSTANCE=1` |
| `deploy-platform-mock.sh` | `--taa-target` 语义文档 |
| `tools/platform-mock/README.md`、`deploy.md`、`CHANGELOG.md` | 文档 |

**关键兼容规则（贯穿所有任务）：** 写路径永远不为陌生 `dockerId` 创建目录。

```go
// instanceForWrite picks the bundle an inbound callback writes to.
// New instances are created only by registration; a callback from an id the
// mock has never registered falls back to the legacy bundle instead of
// creating a directory per spoofed id.
func (m *instanceManager) instanceForWrite(dockerID string, accepted bool) *instanceStores {
	if accepted && dockerID != "" {
		return m.getOrCreate(dockerID)
	}
	if b := m.lookup(dockerID); b != nil {
		return b
	}
	return m.getOrCreate("")
}
```

这条规则同时让现有单测继续成立：测试把自建 store 装进 legacy bundle（`dockerID == ""`），请求体里的 `dockerId` 在管理器里不存在时仍写回该 store。

---

### Task 1: instance manager 与旧状态迁移

**Files:**
- Create: `tools/platform-mock/internal/instances.go`
- Create: `tools/platform-mock/internal/instances_test.go`

- [ ] **Step 1: 写失败测试**

创建 `tools/platform-mock/internal/instances_test.go`：

```go
package mock

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestInstanceDirNameIsStableAndSafe(t *testing.T) {
	if got := instanceDirName(""); got != "i-legacy" {
		t.Fatalf("instanceDirName(\"\") = %q, want i-legacy", got)
	}
	a := instanceDirName("../../etc/passwd")
	b := instanceDirName("../../etc/passwd")
	if a != b {
		t.Fatalf("instanceDirName is not deterministic: %q vs %q", a, b)
	}
	if len(a) != len("i-")+16 {
		t.Fatalf("instanceDirName length = %d, want 18", len(a))
	}
	if filepath.Base(a) != a {
		t.Fatalf("instanceDirName %q escapes its parent", a)
	}
	if a == instanceDirName("another-id") {
		t.Fatal("two different dockerIds share a directory name")
	}
}

func TestInstanceManagerScansExistingInstances(t *testing.T) {
	root := t.TempDir()
	mgr := newInstanceManager(root, Config{})
	b := mgr.getOrCreate("docker-a")
	b.setTarget("http://10.0.0.1:6001")

	reopened := newInstanceManager(root, Config{})
	got := reopened.lookup("docker-a")
	if got == nil {
		t.Fatal("docker-a was not scanned back from disk")
	}
	if got.target() != "http://10.0.0.1:6001" {
		t.Fatalf("target = %q, want http://10.0.0.1:6001", got.target())
	}
}

func TestInstanceManagerMigratesLegacyState(t *testing.T) {
	root := t.TempDir()
	legacy := registerState{
		Received:   true,
		Accepted:   true,
		DockerID:   "legacy-docker",
		ReceivedAt: "2026-01-01T00:00:00Z",
	}
	if err := saveJSONFile(filepath.Join(root, "register-state.json"), legacy); err != nil {
		t.Fatalf("write legacy register state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "reportRes-state.json"), []byte(`{"current":{"received":true},"history":[]}`), 0o644); err != nil {
		t.Fatalf("write legacy report state: %v", err)
	}

	mgr := newInstanceManager(root, Config{})
	b := mgr.lookup("legacy-docker")
	if b == nil {
		t.Fatal("legacy registration was not migrated")
	}
	if !b.register.get().Accepted {
		t.Fatal("migrated register state lost its accepted flag")
	}
	if !b.reportRes.get().Received {
		t.Fatal("migrated report state was not moved")
	}
	if _, err := os.Stat(filepath.Join(root, "register-state.json")); !os.IsNotExist(err) {
		t.Fatal("legacy register-state.json still exists in the root")
	}
	if _, err := os.Stat(filepath.Join(b.dir, "instance.json")); err != nil {
		t.Fatalf("instance.json was not written: %v", err)
	}
}

func TestInstanceManagerDoesNotMigrateOverExistingInstancesDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, instancesDirName, "i-existing"), 0o755); err != nil {
		t.Fatalf("create instances dir: %v", err)
	}
	if err := saveJSONFile(filepath.Join(root, "register-state.json"), registerState{DockerID: "stale"}); err != nil {
		t.Fatalf("write stale register state: %v", err)
	}

	newInstanceManager(root, Config{})
	if _, err := os.Stat(filepath.Join(root, "register-state.json")); err != nil {
		t.Fatal("the stale root file was moved even though instances/ already exists")
	}
}

func TestInstanceManagerDefaultPrefersAcceptedThenNewest(t *testing.T) {
	root := t.TempDir()
	mgr := newInstanceManager(root, Config{})

	a := mgr.getOrCreate("docker-a")
	a.register.set(registerState{Received: true, Accepted: true, ReceivedAt: "2026-01-01T00:00:00Z"})
	b := mgr.getOrCreate("docker-b")
	b.register.set(registerState{Received: true, Accepted: true, ReceivedAt: "2026-02-01T00:00:00Z"})
	c := mgr.getOrCreate("docker-c")
	c.register.set(registerState{Received: true, Accepted: false, ReceivedAt: "2026-03-01T00:00:00Z"})

	if got := mgr.defaultID(); got != "docker-b" {
		t.Fatalf("defaultID() = %q, want docker-b", got)
	}

	resolved, err := mgr.resolve(httptest.NewRequest("GET", "/api/register/status", nil))
	if err != nil {
		t.Fatalf("resolve without dockerId: %v", err)
	}
	if resolved.dockerID != "docker-b" {
		t.Fatalf("resolved instance = %q, want docker-b", resolved.dockerID)
	}
}

func TestInstanceManagerResolveRejectsUnknownDockerID(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	req := httptest.NewRequest("GET", "/api/register/status?dockerId=missing", nil)
	if _, err := mgr.resolve(req); err != errInstanceNotFound {
		t.Fatalf("resolve(unknown) error = %v, want errInstanceNotFound", err)
	}
	if _, err := mgr.resolve(httptest.NewRequest("GET", "/api/register/status", nil)); err != errNoInstance {
		t.Fatalf("resolve(empty) error = %v, want errNoInstance", err)
	}
}

func TestInstanceForWriteNeverCreatesDirectoriesForUnknownIDs(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	got := mgr.instanceForWrite("never-registered", true)
	if got.dockerID != "" {
		t.Fatalf("instanceForWrite created bundle for %q, want the legacy bundle", got.dockerID)
	}
	if mgr.lookup("never-registered") != nil {
		t.Fatal("instanceForWrite created a directory for an unknown dockerId")
	}

	created := mgr.instanceForWrite("registered", true)
	if created == nil || created.dockerID != "registered" {
		t.Fatal("instanceForWrite did not create the accepted instance")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./tools/platform-mock/internal -run 'TestInstance|TestInstanceForWrite' -count=1`
Expected: `FAIL`/`undefined: instanceDirName`（编译失败）。

- [ ] **Step 3: 实现 `instances.go`**

创建 `tools/platform-mock/internal/instances.go`：

```go
package mock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const instancesDirName = "instances"

var (
	errInstanceNotFound = errors.New("指定的 dockerId 不存在")
	errNoInstance       = errors.New("no TAA instance registered yet")
)

// legacyStateFiles are the files the single-instance layout kept in the state
// directory root. Migration moves them into one instance directory.
var legacyStateFiles = []string{
	"register-state.json",
	"report-state.json",
	"reportRes-state.json",
	"reportModelImport-state.json",
	"reportAudit-state.json",
	"reportProgress-state.json",
	"modelLog-state.json",
	"taaLog-state.json",
}

type instanceMeta struct {
	DockerID  string `json:"dockerId"`
	TaaTarget string `json:"taaTarget,omitempty"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// instanceStores bundles the eight persisted stores that belong to one TAA
// instance. The store types are reused unchanged: only the directory differs,
// so every existing file format keeps working.
type instanceStores struct {
	mu       sync.RWMutex
	dockerID string
	dir      string
	meta     instanceMeta

	register          *registerStateStore
	reportResourceRes *reportStateStore
	reportRes         *reportStateStore
	reportModelImport *reportStateStore
	reportAudit       *reportStateStore
	progress          *progressStateStore
	modelLog          *modelLogStore
	taaLog            *taaLogStore
}

// instanceDirName derives the directory from the dockerId. The hash keeps
// arbitrary ids (path separators included) from escaping the instances root.
func instanceDirName(dockerID string) string {
	if dockerID == "" {
		return "i-legacy"
	}
	sum := sha256.Sum256([]byte(dockerID))
	return "i-" + hex.EncodeToString(sum[:])[:16]
}

func newInstanceStores(dir, dockerID string) *instanceStores {
	now := time.Now().Format(time.RFC3339)
	return &instanceStores{
		dockerID:          dockerID,
		dir:               dir,
		meta:              instanceMeta{DockerID: dockerID, CreatedAt: now, UpdatedAt: now},
		register:          newRegisterStateStore(dir),
		reportResourceRes: newReportStateStore(dir),
		reportRes:         newReportStateStore(dir, "reportRes-state.json"),
		reportModelImport: newReportStateStore(dir, "reportModelImport-state.json"),
		reportAudit:       newReportStateStore(dir, "reportAudit-state.json"),
		progress:          newProgressStateStore(dir),
		modelLog:          newModelLogStore(dir, 2000),
		taaLog:            newTaaLogStore(dir, 2000),
	}
}

func loadInstanceStores(dir, dockerID string) *instanceStores {
	b := newInstanceStores(dir, dockerID)
	meta, err := loadJSONFile[instanceMeta](filepath.Join(dir, "instance.json"))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load instance metadata from %s failed: %v", dir, err)
		}
		return b
	}
	if meta.DockerID != "" {
		b.dockerID = meta.DockerID
	}
	b.meta = meta
	if b.meta.CreatedAt == "" {
		b.meta.CreatedAt = time.Now().Format(time.RFC3339)
	}
	if b.meta.UpdatedAt == "" {
		b.meta.UpdatedAt = b.meta.CreatedAt
	}
	return b
}

func (b *instanceStores) target() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.meta.TaaTarget
}

// setTarget records the address TAA registered from. The address is kept in
// instance.json, not in register-state.json, so a console reset of the register
// card does not silently break outbound traffic.
func (b *instanceStores) setTarget(target string) {
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	b.mu.Lock()
	if b.meta.TaaTarget == target {
		b.mu.Unlock()
		return
	}
	b.meta.TaaTarget = target
	b.meta.UpdatedAt = time.Now().Format(time.RFC3339)
	meta := b.meta
	b.mu.Unlock()
	b.saveMeta(meta)
}

func (b *instanceStores) saveMeta(meta instanceMeta) {
	if b.dir == "" {
		return
	}
	if err := os.MkdirAll(b.dir, 0o755); err != nil {
		log.Printf("create instance directory %s failed: %v", b.dir, err)
		return
	}
	if err := saveJSONFile(filepath.Join(b.dir, "instance.json"), meta); err != nil {
		log.Printf("save instance metadata to %s failed: %v", b.dir, err)
	}
}

// instanceManager owns the per-dockerId bundles. Its map is guarded by mu;
// each bundle's stores keep their own locks.
type instanceManager struct {
	mu     sync.RWMutex
	root   string
	cfg    Config
	byID   map[string]*instanceStores
	scanned bool

	staticTarget     string
	discoveredTarget string
}

func newInstanceManager(stateDir string, cfg Config) *instanceManager {
	m := &instanceManager{
		root:         stateDir,
		cfg:          cfg,
		byID:         make(map[string]*instanceStores),
		staticTarget: strings.TrimRight(strings.TrimSpace(cfg.TAATarget), "/"),
	}
	if m.root != "" {
		m.migrateLegacy()
		if err := os.MkdirAll(filepath.Join(m.root, instancesDirName), 0o755); err != nil {
			log.Printf("create instances directory under %s failed: %v", m.root, err)
		}
		m.scan()
	}
	if m.staticTarget == "" {
		m.discoveredTarget = discoverTAAAddr(cfg.TAAPod, cfg.TAANS, strings.TrimSpace(cfg.TAAPort))
	}
	return m
}

func (m *instanceManager) migrateLegacy() {
	instRoot := filepath.Join(m.root, instancesDirName)
	if _, err := os.Stat(instRoot); err == nil {
		for _, name := range legacyStateFiles {
			if _, statErr := os.Stat(filepath.Join(m.root, name)); statErr == nil {
				log.Printf("legacy state file %s is ignored because %s already exists", name, instRoot)
			}
		}
		return
	}

	found := false
	for _, name := range legacyStateFiles {
		if _, err := os.Stat(filepath.Join(m.root, name)); err == nil {
			found = true
			break
		}
	}
	if !found {
		return
	}

	dockerID := ""
	if state, err := loadJSONFile[registerState](filepath.Join(m.root, "register-state.json")); err == nil {
		dockerID = strings.TrimSpace(state.DockerID)
	}
	dir := filepath.Join(instRoot, instanceDirName(dockerID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("create migration directory %s failed: %v", dir, err)
		return
	}
	for _, name := range legacyStateFiles {
		src := filepath.Join(m.root, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.Rename(src, filepath.Join(dir, name)); err != nil {
			log.Printf("migrate legacy state file %s failed: %v", src, err)
		}
	}
	b := newInstanceStores(dir, dockerID)
	now := time.Now().Format(time.RFC3339)
	b.meta.CreatedAt = now
	b.meta.UpdatedAt = now
	b.saveMeta(b.meta)
	log.Printf("migrated legacy single-instance state into %s (dockerId=%q)", dir, dockerID)
}

func (m *instanceManager) scan() {
	entries, err := os.ReadDir(filepath.Join(m.root, instancesDirName))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("scan instances failed: %v", err)
		}
		m.scanned = true
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(m.root, instancesDirName, entry.Name())
		meta, err := loadJSONFile[instanceMeta](filepath.Join(dir, "instance.json"))
		if err != nil {
			log.Printf("skip instance directory %s without readable instance.json: %v", dir, err)
			continue
		}
		b := loadInstanceStores(dir, meta.DockerID)
		m.byID[b.dockerID] = b
	}
	m.scanned = true
}

func (m *instanceManager) getOrCreate(dockerID string) *instanceStores {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.byID[dockerID]; ok {
		return b
	}
	dir := ""
	if m.root != "" {
		dir = filepath.Join(m.root, instancesDirName, instanceDirName(dockerID))
	}
	b := newInstanceStores(dir, dockerID)
	b.saveMeta(b.meta)
	m.byID[dockerID] = b
	return b
}

func (m *instanceManager) lookup(dockerID string) *instanceStores {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byID[dockerID]
}

func (m *instanceManager) list() []*instanceStores {
	m.mu.RLock()
	bundles := make([]*instanceStores, 0, len(m.byID))
	for _, b := range m.byID {
		bundles = append(bundles, b)
	}
	m.mu.RUnlock()
	sort.SliceStable(bundles, func(i, j int) bool {
		return instanceLess(bundles[i], bundles[j])
	})
	return bundles
}

func instanceLess(a, b *instanceStores) bool {
	sa, sb := a.register.get(), b.register.get()
	if sa.Accepted != sb.Accepted {
		return sa.Accepted
	}
	if sa.Received != sb.Received {
		return sa.Received
	}
	if sa.ReceivedAt != sb.ReceivedAt {
		return sa.ReceivedAt > sb.ReceivedAt
	}
	return a.dockerID < b.dockerID
}

func (m *instanceManager) defaultBundle() *instanceStores {
	bundles := m.list()
	if len(bundles) == 0 {
		return nil
	}
	return bundles[0]
}

func (m *instanceManager) defaultID() string {
	if b := m.defaultBundle(); b != nil {
		return b.dockerID
	}
	return ""
}

// instanceForWrite picks the bundle an inbound callback writes to. New
// instances are created only by registration; a callback from an id the mock
// has never registered falls back to the legacy bundle instead of creating a
// directory per spoofed id.
func (m *instanceManager) instanceForWrite(dockerID string, accepted bool) *instanceStores {
	if accepted && dockerID != "" {
		return m.getOrCreate(dockerID)
	}
	if b := m.lookup(dockerID); b != nil {
		return b
	}
	return m.getOrCreate("")
}

func requestedDockerID(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return strings.TrimSpace(r.URL.Query().Get("dockerId"))
}

func (m *instanceManager) resolve(r *http.Request) (*instanceStores, error) {
	if id := requestedDockerID(r); id != "" {
		if b := m.lookup(id); b != nil {
			return b, nil
		}
		return nil, errInstanceNotFound
	}
	if b := m.defaultBundle(); b != nil {
		return b, nil
	}
	return nil, errNoInstance
}

// resolveLenient is for the console endpoints that must answer before any TAA
// has registered (the readiness probe is one). An explicitly unknown dockerId
// is still an error; only the "nothing registered yet" case degrades to the
// empty legacy bundle.
func (m *instanceManager) resolveLenient(r *http.Request) (*instanceStores, error) {
	b, err := m.resolve(r)
	if err == errNoInstance {
		return m.getOrCreate(""), nil
	}
	return b, err
}

// targetFor resolves the outbound address for one instance.
//
// Precedence, in order: a single instance with -taa-target keeps the old static
// address; otherwise the address derived from that instance's registration;
// then the static target; then Pod discovery. An instance never borrows another
// instance's address.
func (m *instanceManager) targetFor(requestedID string) (string, string, error) {
	var b *instanceStores
	if requestedID != "" {
		b = m.lookup(requestedID)
		if b == nil {
			return "", "", errInstanceNotFound
		}
	} else {
		b = m.defaultBundle()
	}

	if b != nil {
		id := b.dockerID
		if len(m.list()) <= 1 && m.staticTarget != "" {
			return id, m.staticTarget, nil
		}
		if target := b.target(); target != "" {
			return id, target, nil
		}
		if m.staticTarget != "" {
			return id, m.staticTarget, nil
		}
		if m.discoveredTarget != "" {
			return id, m.discoveredTarget, nil
		}
		return id, "", fmt.Errorf("TAA 地址未配置: 实例 %q 没有推导地址，且未设置 -taa-target 或 -taa-pod", id)
	}

	if m.staticTarget != "" {
		return "", m.staticTarget, nil
	}
	if m.discoveredTarget != "" {
		return "", m.discoveredTarget, nil
	}
	return "", "", errNoInstance
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./tools/platform-mock/internal -run 'TestInstance|TestInstanceForWrite' -count=1`
Expected: `ok  taa/tools/platform-mock/internal`。

- [ ] **Step 5: 提交**

```bash
git add tools/platform-mock/internal/instances.go tools/platform-mock/internal/instances_test.go
git commit -m "feat(platform-mock): add per-instance state manager"
```

---

### Task 2: 每实例密钥映射（保留旧单钥回退）

**Files:**
- Modify: `tools/platform-mock/internal/keystore.go`
- Test: `tools/platform-mock/internal/keystore_test.go`

- [ ] **Step 1: 写失败测试**

在 `keystore_test.go` 末尾追加：

```go
func TestKeystoreKeepsOneKeyPerInstance(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	if err := ks.setTaaPublicKeyFor("docker-a", &keyA.PublicKey); err != nil {
		t.Fatalf("register key A: %v", err)
	}
	if err := ks.setTaaPublicKeyFor("docker-b", &keyB.PublicKey); err != nil {
		t.Fatalf("register key B: %v", err)
	}

	for id, want := range map[string]*crypto.SM2PrivateKey{"docker-a": keyA, "docker-b": keyB} {
		got, err := crypto.MarshalSM2PublicKeyHex(ks.taaPublicFor(id))
		if err != nil {
			t.Fatalf("encode key for %s: %v", id, err)
		}
		expected, _ := crypto.MarshalSM2PublicKeyHex(&want.PublicKey)
		if got != expected {
			t.Fatalf("key for %s = %s, want %s", id, got, expected)
		}
	}
	if ks.taaPublicFor("docker-c") != nil {
		t.Fatal("an unregistered dockerId resolved to a key")
	}
}

func TestKeystorePersistsOneKeyPerInstance(t *testing.T) {
	stateDir := t.TempDir()
	ks, err := newKeystore(stateDir, "", nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	if err := ks.setTaaPublicKeyFor("docker-a", &keyA.PublicKey); err != nil {
		t.Fatalf("register key A: %v", err)
	}
	if err := ks.setTaaPublicKeyFor("docker-b", &keyB.PublicKey); err != nil {
		t.Fatalf("register key B: %v", err)
	}

	reopened, err := newKeystore(stateDir, "", nil)
	if err != nil {
		t.Fatalf("reopen the keystore: %v", err)
	}
	for _, id := range []string{"docker-a", "docker-b"} {
		if reopened.taaPublicFor(id) == nil {
			t.Fatalf("key for %s did not survive a restart", id)
		}
	}
}

func TestKeystoreFallsBackToTheLegacySingleKey(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	legacy, _ := crypto.GenerateSM2KeyPair()
	if err := ks.setTaaPublicKey(&legacy.PublicKey); err != nil {
		t.Fatalf("register the legacy key: %v", err)
	}
	if ks.taaPublicFor("any-docker") == nil {
		t.Fatal("the legacy single key was not offered as a fallback")
	}
}

func TestKeystoreRejectsAPlaintextDockerIDMismatch(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	keyA, _ := crypto.GenerateSM2KeyPair()
	if err := ks.setTaaPublicKeyFor("docker-a", &keyA.PublicKey); err != nil {
		t.Fatalf("register key A: %v", err)
	}

	platformPriv := ks.platformPrivate()
	keys, err := envelope.NewKeys(&platformPriv.PublicKey, keyA, ks.userIDBytes())
	if err != nil {
		t.Fatalf("build the TAA envelope keys: %v", err)
	}
	// The hint says A, the plaintext claims B: both are non-empty and differ.
	sealed, err := keys.Seal([]byte(`{"dockerId":"docker-b"}`), "docker-a")
	if err != nil {
		t.Fatalf("seal the mismatched body: %v", err)
	}
	if _, _, err := ks.openBodyWithID(sealed); err == nil {
		t.Fatal("a hint/plaintext dockerId mismatch was accepted")
	}
}

func TestKeystoreOpensWithTheHintedInstanceKey(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	_ = ks.setTaaPublicKeyFor("docker-a", &keyA.PublicKey)
	_ = ks.setTaaPublicKeyFor("docker-b", &keyB.PublicKey)

	platformPriv := ks.platformPrivate()
	keys, err := envelope.NewKeys(&platformPriv.PublicKey, keyA, ks.userIDBytes())
	if err != nil {
		t.Fatalf("build the TAA envelope keys: %v", err)
	}
	sealed, err := keys.Seal([]byte(`{"dockerId":"docker-a"}`), "docker-a")
	if err != nil {
		t.Fatalf("seal as A: %v", err)
	}
	plaintext, id, err := ks.openBodyWithID(sealed)
	if err != nil {
		t.Fatalf("open as A: %v", err)
	}
	if id != "docker-a" {
		t.Fatalf("recovered dockerId = %q, want docker-a", id)
	}
	if string(plaintext) != `{"dockerId":"docker-a"}` {
		t.Fatalf("plaintext = %s", plaintext)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./tools/platform-mock/internal -run 'TestKeystore' -count=1`
Expected: 编译失败，`undefined: ...setTaaPublicKeyFor`。

- [ ] **Step 3: 修改 keystore**

在 `platformKeyState` 中新增字段：

```go
type platformKeyState struct {
	PrivateKeyPEM  string            `json:"privateKeyPem"`
	PublicKeyHex   string            `json:"publicKeyHex"`
	TaaPublicKey   string            `json:"taaPublicKeyHex,omitempty"`
	TaaPublicKeys  map[string]string `json:"taaPublicKeysHex,omitempty"`
}
```

`keystore` 结构体替换 `taaPub`：

```go
type keystore struct {
	mu           sync.RWMutex
	path         string
	userID       []byte
	priv         *teecrypto.SM2PrivateKey
	taaPubs      map[string]*teecrypto.SM2PublicKey
	legacyTaaPub *teecrypto.SM2PublicKey
}
```

`loadOrCreateKeystore` 里，把原来解析 `state.TaaPublicKey` 的代码替换为：

```go
		ks.taaPubs = make(map[string]*teecrypto.SM2PublicKey)
		for id, hexKey := range state.TaaPublicKeys {
			pub, err := teecrypto.ParseSM2PublicKeyHex(hexKey)
			if err != nil {
				log.Printf("persisted TAA public key for %q is unparseable and is dropped: %v", id, err)
				continue
			}
			ks.taaPubs[id] = pub
		}
		if strings.TrimSpace(state.TaaPublicKey) != "" {
			pub, err := teecrypto.ParseSM2PublicKeyHex(state.TaaPublicKey)
			if err != nil {
				log.Printf("persisted legacy TAA public key is unparseable, waiting for the next registration: %v", err)
			} else {
				ks.legacyTaaPub = pub
			}
		}
```

`persistLocked` 的 key 段替换为：

```go
	state := platformKeyState{PrivateKeyPEM: string(privPEM), PublicKeyHex: pubHex}
	if s.legacyTaaPub != nil {
		taaHex, err := teecrypto.MarshalSM2PublicKeyHex(s.legacyTaaPub)
		if err != nil {
			return fmt.Errorf("encode the legacy TAA public key: %w", err)
		}
		state.TaaPublicKey = taaHex
	}
	if len(s.taaPubs) > 0 {
		state.TaaPublicKeys = make(map[string]string, len(s.taaPubs))
		for id, pub := range s.taaPubs {
			taaHex, err := teecrypto.MarshalSM2PublicKeyHex(pub)
			if err != nil {
				return fmt.Errorf("encode the TAA public key for %q: %w", id, err)
			}
			state.TaaPublicKeys[id] = taaHex
		}
	}
```

把 `taaPublic`/`hasTaaPublicKey`/`setTaaPublicKey`/`sealForTAA`/`openBody`/`openFromTAAResponse` 这一段替换为（旧方法保留为单实例包装，现有调用点不动）：

```go
// taaPublicFor returns the key registered for dockerID. An empty identity, or
// an id with no key of its own, falls back to the legacy single key so a state
// directory written before multi-instance keeps working.
func (s *keystore) taaPublicFor(dockerID string) *teecrypto.SM2PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if dockerID != "" {
		if pub, ok := s.taaPubs[dockerID]; ok {
			return pub
		}
	}
	return s.legacyTaaPub
}

func (s *keystore) taaPublic() *teecrypto.SM2PublicKey {
	return s.taaPublicFor("")
}

func (s *keystore) hasTaaPublicKey() bool {
	return s.taaPublic() != nil
}

// setTaaPublicKeyFor records one instance's key. Re-registering the same
// dockerId is a key rotation and replaces only that instance's entry.
func (s *keystore) setTaaPublicKeyFor(dockerID string, pub *teecrypto.SM2PublicKey) error {
	s.mu.Lock()
	if dockerID == "" {
		s.legacyTaaPub = pub
	} else {
		if s.taaPubs == nil {
			s.taaPubs = make(map[string]*teecrypto.SM2PublicKey)
		}
		s.taaPubs[dockerID] = pub
	}
	err := s.persistLocked()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	log.Printf("TAA public key registered and persisted: dockerId=%q", dockerID)
	return nil
}

func (s *keystore) setTaaPublicKey(pub *teecrypto.SM2PublicKey) error {
	return s.setTaaPublicKeyFor("", pub)
}

func (s *keystore) sealForTAAFor(dockerID string, plaintext []byte) ([]byte, error) {
	s.mu.RLock()
	priv := s.priv
	taaPub := s.taaPublicFor(dockerID)
	userID := s.userID
	s.mu.RUnlock()
	if priv == nil {
		return nil, fmt.Errorf("platform SM2 private key is not available")
	}
	if taaPub == nil {
		if dockerID == "" {
			return nil, fmt.Errorf("no TAA public key registered yet: wait for TAA to register before sending it requests")
		}
		return nil, fmt.Errorf("no TAA public key registered for dockerId %q: wait for that instance to register", dockerID)
	}
	return envelope.SealForPlatform(priv, taaPub, userID, plaintext)
}

func (s *keystore) sealForTAA(plaintext []byte) ([]byte, error) {
	return s.sealForTAAFor("", plaintext)
}

// openBodyWithID opens a sealed callback and returns both the plaintext and the
// identity that signed it.
//
// The outer dockerId is only a key-selection hint: it is never trusted. The
// signature is verified with the hinted instance's key (or the legacy key), and
// only then is the plaintext dockerId read. Both non-empty and different means
// the envelope was built for one instance and claims another, which is refused.
func (s *keystore) openBodyWithID(body []byte) ([]byte, string, error) {
	env, err := envelope.Parse(body)
	if err != nil {
		return nil, "", err
	}
	hint := strings.TrimSpace(env.DockerID)
	plaintext, err := s.openFromTAAResponseFor(hint, env)
	if err != nil {
		return nil, "", err
	}
	var probe struct {
		DockerID string `json:"dockerId"`
	}
	_ = json.Unmarshal(plaintext, &probe)
	plainID := strings.TrimSpace(probe.DockerID)
	if hint != "" && plainID != "" && hint != plainID {
		return nil, "", fmt.Errorf("envelope dockerId %q does not match the plaintext dockerId %q", hint, plainID)
	}
	if plainID != "" {
		return plaintext, plainID, nil
	}
	return plaintext, hint, nil
}

func (s *keystore) openBody(body []byte) ([]byte, error) {
	plaintext, _, err := s.openBodyWithID(body)
	return plaintext, err
}

func (s *keystore) openFromTAAResponseFor(dockerID string, env *envelope.Envelope) ([]byte, error) {
	s.mu.RLock()
	priv := s.priv
	taaPub := s.taaPublicFor(dockerID)
	userID := s.userID
	s.mu.RUnlock()
	if priv == nil {
		return nil, fmt.Errorf("platform SM2 private key is not available")
	}
	if taaPub == nil {
		if dockerID == "" {
			return nil, fmt.Errorf("no TAA public key registered yet")
		}
		return nil, fmt.Errorf("no TAA public key registered for dockerId %q", dockerID)
	}
	return envelope.OpenFromPlatform(priv, taaPub, userID, env)
}

func (s *keystore) openFromTAAResponse(env *envelope.Envelope) ([]byte, error) {
	return s.openFromTAAResponseFor("", env)
}
```

注意：`openBodyWithID` 对 `taaPubs` 为 nil 的 map 读取是安全的。

- [ ] **Step 4: 运行全部 keystore 与入站测试**

Run: `go test ./tools/platform-mock/internal -run 'TestKeystore|TestReport|TestRegister' -count=1`
Expected: `ok  taa/tools/platform-mock/internal`。

- [ ] **Step 5: 提交**

```bash
git add tools/platform-mock/internal/keystore.go tools/platform-mock/internal/keystore_test.go
git commit -m "feat(platform-mock): keep one TAA key per dockerId"
```

---

### Task 3: 入站回调按实例落盘

**Files:**
- Modify: `tools/platform-mock/internal/handlers_taa.go`
- Modify: `tools/platform-mock/internal/envelope_helpers_test.go`
- Modify: `tools/platform-mock/internal/server_test.go`（38 处构造点）
- Modify: `tools/platform-mock/internal/server.go`（仅入站路由，先保证编译）

- [ ] **Step 1: 增加测试管理器 helper**

在 `envelope_helpers_test.go` 末尾追加：

```go
// testManagerWith builds an instance manager whose bundle uses dockerID and a
// temp root. Tests that built a store themselves install it through configure.
// With dockerID == "" the bundle is the legacy one, which instanceForWrite
// falls back to for ids the manager has never seen - that is what keeps the
// single-instance handler tests unchanged.
func testManagerWith(t *testing.T, dockerID string, configure func(*instanceStores)) *instanceManager {
	t.Helper()
	root := t.TempDir()
	dir := root
	if dockerID != "" {
		dir = filepath.Join(root, instancesDirName, instanceDirName(dockerID))
	}
	b := newInstanceStores(dir, dockerID)
	if configure != nil {
		configure(b)
	}
	return &instanceManager{
		root:    root,
		cfg:     Config{},
		byID:    map[string]*instanceStores{dockerID: b},
		scanned: true,
	}
}

// registerInstanceForTest runs a real registration through registerHandler, so
// the manager, the keystore and the derived target all take the production path.
func registerInstanceForTest(t *testing.T, mgr *instanceManager, dockerID string, priv *crypto.SM2PrivateKey) {
	t.Helper()
	ks := currentPlatformKeys()
	hexKey, err := crypto.MarshalSM2PublicKeyHex(&priv.PublicKey)
	if err != nil {
		t.Fatalf("encode %s's public key: %v", dockerID, err)
	}
	body := fmt.Sprintf(
		`{"dockerId":%q,"authInfo":null,"taaPublicKey":%q,"timestamp":"2026-01-01T00:00:00Z","verifiedPass":true}`,
		dockerID, hexKey,
	)
	keys, err := envelope.NewKeys(&ks.platformPrivate().PublicKey, priv, ks.userIDBytes())
	if err != nil {
		t.Fatalf("build envelope keys for %s: %v", dockerID, err)
	}
	sealed, err := keys.Seal([]byte(body), dockerID)
	if err != nil {
		t.Fatalf("seal the registration for %s: %v", dockerID, err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/register", bytes.NewReader(sealed))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	registerHandler(mgr, true).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register %s: status = %d, body = %s", dockerID, w.Code, w.Body.String())
	}
}
```

同时给 `envelope_helpers_test.go` 的 import 加上 `bytes`、`fmt`、`path/filepath`。

- [ ] **Step 2: 写失败测试：两个实例的 store 不再互相覆盖**

新建 `tools/platform-mock/internal/instances_inbound_test.go`：

```go
package mock

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

func TestTwoInstancesKeepSeparateReportState(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	setPlatformKeys(ks)
	defer setPlatformKeys(platformKeyStore())

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)

	postReport := func(priv *crypto.SM2PrivateKey, dockerID string) *httptest.ResponseRecorder {
		body := []byte(`{"dockerId":"` + dockerID + `","requestId":"req-1","taskId":"task-1","code":0,"report":"ok"}`)
		keys, err := envelope.NewKeys(&ks.platformPrivate().PublicKey, priv, ks.userIDBytes())
		if err != nil {
			t.Fatalf("build keys: %v", err)
		}
		sealed, err := keys.Seal(body, dockerID)
		if err != nil {
			t.Fatalf("seal report: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportRes", bytes.NewReader(sealed))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		reportResHandler(mgr).ServeHTTP(w, req)
		return w
	}

	if w := postReport(keyA, "docker-a"); w.Code != http.StatusOK {
		t.Fatalf("report from A: status = %d, body = %s", w.Code, w.Body.String())
	}
	if w := postReport(keyB, "docker-b"); w.Code != http.StatusOK {
		t.Fatalf("report from B: status = %d, body = %s", w.Code, w.Body.String())
	}

	if got := mgr.lookup("docker-a").reportRes.get().DockerID; got != "docker-a" {
		t.Fatalf("instance A report dockerId = %q, want docker-a", got)
	}
	if got := mgr.lookup("docker-b").reportRes.get().DockerID; got != "docker-b" {
		t.Fatalf("instance B report dockerId = %q, want docker-b", got)
	}
	if mgr.lookup("docker-a").reportRes.get().ReceivedAt == mgr.lookup("docker-b").reportRes.get().ReceivedAt {
		t.Log("both received at the same second; separation is asserted by dockerId above")
	}
}

func TestReportWithAnotherInstancesKeyIsRefused(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	setPlatformKeys(ks)
	defer setPlatformKeys(platformKeyStore())

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)

	// Hint A, sign with B.
	body := []byte(`{"dockerId":"docker-a","requestId":"req-1"}`)
	keys, err := envelope.NewKeys(&ks.platformPrivate().PublicKey, keyB, ks.userIDBytes())
	if err != nil {
		t.Fatalf("build keys: %v", err)
	}
	sealed, err := keys.Seal(body, "docker-a")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/reportRes", bytes.NewReader(sealed))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	reportResHandler(mgr).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", w.Code, w.Body.String())
	}
}
```

- [ ] **Step 3: 运行确认失败**

Run: `go test ./tools/platform-mock/internal -run 'TestTwoInstances|TestReportWithAnother' -count=1`
Expected: 编译失败（`reportResHandler` 仍接受 `*reportStateStore`、`registerHandler` 参数不匹配）。

- [ ] **Step 4: 改 `openTAARequestBody` 与 8 个入站 handler**

`handlers_taa.go` 顶部替换：

```go
// openTAARequestBody reads a request TAA sent and returns the plaintext and the
// instance identity that signed it. The identity comes from the envelope hint,
// cross-checked against the plaintext, so handlers can select the right store
// without decoding the outer object as business JSON.
func openTAARequestBody(r *http.Request) ([]byte, string, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取请求体失败: %w", err)
	}
	plaintext, dockerID, err := currentPlatformKeys().openBodyWithID(body)
	if err != nil {
		return nil, "", fmt.Errorf("报文解密或验签失败: %w", err)
	}
	return plaintext, dockerID, nil
}
```

每个 handler 的改动如下（只列需要改的行；其余逻辑保持不变）：

| 函数 | 新签名 | store 字段 |
| --- | --- | --- |
| `registerHandler` | `registerHandler(mgr *instanceManager, allowEmptyAttestation bool)` | `register` |
| `reportResourceResHandler` | `(mgr *instanceManager)` | `reportResourceRes` |
| `reportResHandler` | `(mgr *instanceManager)` | `reportRes` |
| `reportModelImportHandler` | `(mgr *instanceManager)` | `reportModelImport` |
| `reportAuditHandler` | `(mgr *instanceManager)` | `reportAudit` |
| `reportProgressHandler` | `(mgr *instanceManager)` | `progress` |
| `modelLogHandler` | `(mgr *instanceManager)` | `modelLog` |
| `taaLogHandler` | `(mgr *instanceManager)` | `taaLog` |

`registerHandler` 的写点：

```go
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			state.StatusCode = http.StatusBadRequest
			state.Message = "读取请求体失败: " + err.Error()
			mgr.instanceForWrite("", false).register.set(state)
			writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
			return
		}

		plaintext, registeredPub, err := currentPlatformKeys().openRegister(rawBody)
		if err != nil {
			state.StatusCode = http.StatusUnauthorized
			state.Message = "报文解密或验签失败: " + err.Error()
			mgr.instanceForWrite("", false).register.set(state)
			writeEnvelope(w, http.StatusUnauthorized, state.Message, nil, http.StatusUnauthorized)
			return
		}

		var req registerRequest
		if err := json.Unmarshal(plaintext, &req); err != nil {
			state.StatusCode = http.StatusBadRequest
			state.Message = "解析 application/json 失败: " + err.Error()
			mgr.instanceForWrite("", false).register.set(state)
			writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
			return
		}
```

其后所有 `store.set(state)` 改为 `bundle.register.set(state)`，并在第一次写入前插入：

```go
		// Until the request is accepted the bundle is the instance that is
		// already known under this id (or the legacy bundle): a rejected
		// registration must not create a directory for a stranger.
		bundle := mgr.instanceForRegistration(state.DockerID, state.Accepted)
```

`instanceForRegistration` 在 `instances.go` 追加：

```go
// instanceForRegistration creates the bundle only for an accepted
// registration. A rejected one is recorded on an existing or legacy bundle.
func (m *instanceManager) instanceForRegistration(dockerID string, accepted bool) *instanceStores {
	return m.instanceForWrite(dockerID, accepted)
}
```

把原来 `if err := currentPlatformKeys().setTaaPublicKey(registeredPub); err != nil {` 改为（本任务先沿用单钥包装，Task 4 改成按 id）：

```go
		if err := currentPlatformKeys().setTaaPublicKey(registeredPub); err != nil {
```

其余 7 个 handler 的机械改动：

```go
// 例如 reportResourceResHandler：
		bodyBytes, dockerID, err := openTAARequestBody(r)
		if err != nil {
			state.StatusCode = http.StatusUnauthorized
			state.Message = err.Error()
			mgr.instanceForWrite(dockerID, false).reportResourceRes.set(state)
			writeEnvelope(w, http.StatusUnauthorized, state.Message, nil, http.StatusUnauthorized)
			return
		}
		...
		mgr.instanceForWrite(dockerID, state.Accepted).reportResourceRes.set(state)
```

每个 handler 把全部 `store.set(state)` 替换为
`mgr.instanceForWrite(dockerID, state.Accepted).<字段>.set(state)`，
把状态/重置读取处的 `store.get()` 保持不变（该 handler 只写）。

log handler（`modelLogHandler`、`taaLogHandler`）把：

```go
		_, err := openTAARequestBody(r)
```
改为
```go
		_, dockerID, err := openTAARequestBody(r)
```
并把 `store.addEntries(...)` 改为：

```go
		added := mgr.instanceForWrite(dockerID, true).modelLog.addEntries(dockerID, req.RequestID, req.TaskID, req.Entries)
```
（`taaLogHandler` 用 `.taaLog`）。拒绝分支里的 `store.set(state)` 同理换成
`mgr.instanceForWrite(dockerID, false).<字段>.set(state)`。

`reportProgressHandler` 的字段是 `progress`。

- [ ] **Step 5: 改 `server.go` 的入站路由**

把 8 个 store 的构造和注入替换为 manager（本步只改入站 8 行，控制台路由在 Task 6 改）：

```go
	mgr := newInstanceManager(cfg.StateDir, cfg)

	mux.HandleFunc("/v1/taa/register", registerHandler(mgr, cfg.AllowEmptyAttestation))
	mux.HandleFunc("/v1/taa/reportResourceRes", reportResourceResHandler(mgr))
	mux.HandleFunc("/v1/taa/reportRes", reportResHandler(mgr))
	mux.HandleFunc("/v1/taa/reportModelImport", reportModelImportHandler(mgr))
	mux.HandleFunc("/v1/taa/reportAudit", reportAuditHandler(mgr))
	mux.HandleFunc("/v1/taa/reportProgress", reportProgressHandler(mgr))
	mux.HandleFunc("/v1/taa/modelLog", modelLogHandler(mgr))
	mux.HandleFunc("/v1/taa/taaLog", taaLogHandler(mgr))
```

保留旧的 store 构造行暂时给还没改的控制台路由用；若编译冲突，直接把控制台路由一并改到 Task 6 的签名（Task 6 会给出完整代码）。

- [ ] **Step 6: 更新 38 处测试构造点**

在 `server_test.go` 与 `handlers_fhe_test.go` 中按下列对照替换（`grep -n` 定位，全部替换）：

```go
reportResHandler(store)
→ reportResHandler(testManagerWith(t, "", func(b *instanceStores) { b.reportRes = store }))

reportModelImportHandler(store)
→ reportModelImportHandler(testManagerWith(t, "", func(b *instanceStores) { b.reportModelImport = store }))

reportAuditHandler(store)
→ reportAuditHandler(testManagerWith(t, "", func(b *instanceStores) { b.reportAudit = store }))

reportProgressHandler(store)
→ reportProgressHandler(testManagerWith(t, "", func(b *instanceStores) { b.progress = store }))

modelLogHandler(store)
→ modelLogHandler(testManagerWith(t, "", func(b *instanceStores) { b.modelLog = store }))

taaLogHandler(store)
→ taaLogHandler(testManagerWith(t, "", func(b *instanceStores) { b.taaLog = store }))

registerHandler(store, false)
→ registerHandler(testManagerWith(t, "docker-1", func(b *instanceStores) { b.register = store }), false)
```

`TestRegisterHandlerAcceptsJSONPayload` 的注册体使用 `dockerId: "docker-1"`；若实际值不同，用该测试里的 dockerId 替换 helper 的第一个参数。

- [ ] **Step 7: 运行入站与全部 server 测试**

Run: `go test ./tools/platform-mock/internal -count=1`
Expected: `ok  taa/tools/platform-mock/internal`。若 `server.go` 因控制台 handler 旧签名编译失败，先完成 Task 6 再回来跑本步；任务拆分只是提交粒度，编译必须整体通过。

- [ ] **Step 8: 提交**

```bash
git add tools/platform-mock/internal/handlers_taa.go tools/platform-mock/internal/envelope_helpers_test.go \
  tools/platform-mock/internal/instances.go tools/platform-mock/internal/instances_inbound_test.go \
  tools/platform-mock/internal/server_test.go tools/platform-mock/internal/server.go
git commit -m "feat(platform-mock): route inbound callbacks to per-instance stores"
```

---

### Task 4: 注册推导目标并按实例采纳密钥

**Files:**
- Modify: `tools/platform-mock/internal/proxy.go`（新增 `deriveTAATarget`）
- Modify: `tools/platform-mock/internal/handlers_taa.go`
- Modify: `tools/platform-mock/internal/store.go`（`registerState` 增加 `TaaTarget`）
- Test: `tools/platform-mock/internal/instances_inbound_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `instances_inbound_test.go`：

```go
func TestDeriveTAATarget(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		port       string
		want       string
	}{
		{"ipv4", "10.244.0.7:54321", "6001", "http://10.244.0.7:6001"},
		{"ipv6", "[fd00::7]:54321", "6001", "http://[fd00::7]:6001"},
		{"bare ip", "10.244.0.7", "6001", "http://10.244.0.7:6001"},
		{"default port", "10.244.0.7:1234", "", "http://10.244.0.7:6001"},
		{"empty", "", "6001", ""},
		{"garbage", "not-an-address", "6001", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveTAATarget(tc.remoteAddr, tc.port); got != tc.want {
				t.Fatalf("deriveTAATarget(%q, %q) = %q, want %q", tc.remoteAddr, tc.port, got, tc.want)
			}
		})
	}
}

func TestRegistrationDerivesAndKeepsItsOwnTargetAndKey(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	setPlatformKeys(ks)
	defer setPlatformKeys(platformKeyStore())

	mgr := newInstanceManager(t.TempDir(), Config{TAAPort: "6001"})
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)

	for _, id := range []string{"docker-a", "docker-b"} {
		b := mgr.lookup(id)
		if b == nil {
			t.Fatalf("%s bundle missing", id)
		}
		// httptest.NewRequest uses 192.0.2.1:1234 as RemoteAddr.
		if got := b.target(); got != "http://192.0.2.1:6001" {
			t.Fatalf("%s target = %q, want http://192.0.2.1:6001", id, got)
		}
		if ks.taaPublicFor(id) == nil {
			t.Fatalf("%s key was not adopted", id)
		}
	}
	if ks.taaPublicFor("docker-a") == ks.taaPublicFor("docker-b") {
		t.Fatal("both instances share one key")
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./tools/platform-mock/internal -run 'TestDeriveTAATarget|TestRegistrationDerives' -count=1`
Expected: `undefined: deriveTAATarget`。

- [ ] **Step 3: 实现 `deriveTAATarget`**

在 `proxy.go` 顶部 import 加 `net`，追加：

```go
// deriveTAATarget builds the TAA base URL from the address the registration
// came from. The port is the configured TAA port, not the source port: the
// source port is ephemeral. A RemoteAddr that yields no usable host returns ""
// and leaves the instance without a derived target; registration still
// succeeds, and outbound calls report the missing address explicitly.
func deriveTAATarget(remoteAddr, port string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if net.ParseIP(host) == nil {
		log.Printf("cannot derive the TAA target from RemoteAddr %q: %v", remoteAddr, err)
		return ""
	}
	if strings.TrimSpace(port) == "" {
		port = defaultTAAPort
	}
	return "http://" + net.JoinHostPort(host, port)
}
```

- [ ] **Step 4: `registerState` 增加目标字段**

`store.go` 的 `registerState` 在 `DockerID` 后加：

```go
	TaaTarget          string `json:"taaTarget,omitempty"`
```

- [ ] **Step 5: 注册 handler 写目标并采纳实例密钥**

在 `registerHandler` 中，把 Task 3 插入的 `bundle := ...` 一行替换为：

```go
		bundle := mgr.instanceForRegistration(state.DockerID, state.Accepted)
		if state.Accepted {
			if target := deriveTAATarget(r.RemoteAddr, mgr.cfg.TAAPort); target != "" {
				bundle.setTarget(target)
			}
			state.TaaTarget = bundle.target()
		}
```

把密钥采纳改为：

```go
		if err := currentPlatformKeys().setTaaPublicKeyFor(state.DockerID, registeredPub); err != nil {
```

- [ ] **Step 6: 运行测试**

Run: `go test ./tools/platform-mock/internal -run 'TestDeriveTAATarget|TestRegistrationDerives|TestTwoInstances|TestRegister' -count=1`
Expected: `ok  taa/tools/platform-mock/internal`。

- [ ] **Step 7: 提交**

```bash
git add tools/platform-mock/internal/proxy.go tools/platform-mock/internal/handlers_taa.go \
  tools/platform-mock/internal/store.go tools/platform-mock/internal/instances_inbound_test.go
git commit -m "feat(platform-mock): derive each instance's TAA target at registration"
```

---

### Task 5: 出站寻址与动态反代

**Files:**
- Modify: `tools/platform-mock/internal/proxy.go`
- Modify: `tools/platform-mock/internal/handlers_api.go`（出站 3 个）
- Modify: `tools/platform-mock/internal/handlers_fhe.go`
- Modify: `tools/platform-mock/internal/server.go`
- Test: `tools/platform-mock/internal/instances_outbound_test.go`（新建）

- [ ] **Step 1: 写失败测试**

新建 `tools/platform-mock/internal/instances_outbound_test.go`：

```go
package mock

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

func TestTAAProxyRoutesByDockerIDAndStripsTheQuery(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	setPlatformKeys(ks)
	defer setPlatformKeys(platformKeyStore())

	newBackend := func(name string) (*httptest.Server, *[]byte, *string) {
		var body []byte
		var path string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path = r.URL.Path
			body, _ = io.ReadAll(r.Body)
			payload, err := envelope.OpenFromPlatform(ks.platformPrivate(), &testTAAKey(t).PublicKey, ks.userIDBytes(), mustParseEnvelope(t, body))
			_ = err
			_ = payload
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(sealAsTAA(t, `{"msg":"success","result":{"backend":"`+name+`"},"error":0}`))
		}))
		return srv, &body, &path
	}
	backendA, bodyA, pathA := newBackend("a")
	defer backendA.Close()
	backendB, bodyB, pathB := newBackend("b")
	defer backendB.Close()
	_ = bodyA
	_ = bodyB

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)
	mgr.lookup("docker-a").setTarget(backendA.URL)
	mgr.lookup("docker-b").setTarget(backendB.URL)

	srv := NewServer(Config{Addr: ":0", StateDir: t.TempDir(), UploadDir: t.TempDir()})
	// NewServer installs its own manager and keystore; use this test's ones
	// through the handler so registration state is visible.
	handler := loggingReverseProxyHandler(dynamicTAAProxyHandler(mgr, newProxyPool()))

	req := httptest.NewRequest(http.MethodPost, "/v1/taa/health?dockerId=docker-a", strings.NewReader(`{"probe":1}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	_ = srv

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if *pathA != "/v1/taa/health" {
		t.Fatalf("backend A path = %q, want /v1/taa/health", *pathA)
	}
	if *pathB != "" {
		t.Fatalf("backend B received a request it should not have: %q", *pathB)
	}
	if !strings.Contains(w.Body.String(), `"backend":"a"`) {
		t.Fatalf("response = %s, want backend a", w.Body.String())
	}
}

func TestTAAProxyStripsDockerIDBeforeForwarding(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	setPlatformKeys(ks)
	defer setPlatformKeys(platformKeyStore())

	var seenQuery string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(sealAsTAA(t, `{"ok":true}`))
	}))
	defer backend.Close()

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	mgr.lookup("docker-a").setTarget(backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/v1/taa/status?dockerId=docker-a&keep=1", nil)
	w := httptest.NewRecorder()
	dynamicTAAProxyHandler(mgr, newProxyPool()).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if strings.Contains(seenQuery, "dockerId") {
		t.Fatalf("forwarded query still contains dockerId: %q", seenQuery)
	}
	if !strings.Contains(seenQuery, "keep=1") {
		t.Fatalf("forwarded query lost the unrelated parameter: %q", seenQuery)
	}
}

func mustParseEnvelope(t *testing.T, body []byte) *envelope.Envelope {
	t.Helper()
	env, err := envelope.Parse(body)
	if err != nil {
		t.Fatalf("parse the forwarded envelope: %v", err)
	}
	return env
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./tools/platform-mock/internal -run 'TestTAAProxy' -count=1`
Expected: `undefined: dynamicTAAProxyHandler` / `newProxyPool`。

- [ ] **Step 3: 改造 `proxy.go`**

1. import 增加 `net/http/httputil`、`net/url`、`sync`。
2. 追加 context key 与读取函数：

```go
type dockerIDContextKey struct{}

func dockerIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(dockerIDContextKey{}).(string); ok {
		return id
	}
	return ""
}
```

3. `proxyJSONToTAA` 签名改为：

```go
func proxyJSONToTAA(ctx context.Context, dockerID, taaAddr, endpoint string, body []byte) (int, []byte, error) {
```

函数体里 `sealForTAA(body)` → `sealForTAAFor(dockerID, body)`，
`openTAAResponse(respBody)` → `openTAAResponse(dockerID, respBody)`。

4. `openTAAResponse` 改为：

```go
func openTAAResponse(dockerID string, body []byte) []byte {
	env, err := envelope.Parse(body)
	if err != nil {
		return body
	}
	plaintext, err := currentPlatformKeys().openFromTAAResponseFor(dockerID, env)
	if err != nil {
		log.Printf("could not open a TAA response envelope: %v", err)
		return body
	}
	return plaintext
}
```

5. `sealProxyRequestBody` 里改为：

```go
		sealed, err := currentPlatformKeys().sealForTAAFor(dockerIDFromContext(r.Context()), body)
```

6. `openProxyResponse` 里改为：

```go
	plaintext := openTAAResponse(dockerIDFromContext(resp.Request.Context()), data)
```

7. 追加 proxy pool 与动态 handler：

```go
// proxyPool caches one reverse proxy per target URL. The per-request instance
// identity travels in the request context, so a cached proxy is still correct
// for every instance that shares a target.
type proxyPool struct {
	mu      sync.Mutex
	proxies map[string]*httputil.ReverseProxy
}

func newProxyPool() *proxyPool {
	return &proxyPool{proxies: make(map[string]*httputil.ReverseProxy)}
}

func (p *proxyPool) forTarget(target string) (*httputil.ReverseProxy, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if proxy, ok := p.proxies[target]; ok {
		return proxy, nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid TAA target %q: %v", target, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("TAA proxy error: %s %s → %v", r.Method, r.URL.Path, err)
		writeEnvelope(w, http.StatusBadGateway, "TAA proxy error: "+err.Error(), nil, http.StatusBadGateway)
	}
	proxy.ModifyResponse = openProxyResponse
	p.proxies[target] = proxy
	return proxy, nil
}

// dynamicTAAProxyHandler selects the target per request, from ?dockerId= or the
// default instance. The query parameter is removed before forwarding: the
// identity is the mock's own addressing, not part of TAA's protocol.
func dynamicTAAProxyHandler(mgr *instanceManager, pool *proxyPool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, target, err := mgr.targetFor(requestedDockerID(r))
		if err != nil {
			writeEnvelope(w, http.StatusBadGateway, "TAA 代理不可用: "+err.Error(), nil, http.StatusBadGateway)
			return
		}
		proxy, err := pool.forTarget(target)
		if err != nil {
			writeEnvelope(w, http.StatusBadGateway, "TAA 代理不可用: "+err.Error(), nil, http.StatusBadGateway)
			return
		}
		ctx := context.WithValue(r.Context(), dockerIDContextKey{}, id)
		r = r.Clone(ctx)
		if r.URL != nil {
			q := r.URL.Query()
			if _, ok := q["dockerId"]; ok {
				q.Del("dockerId")
				r.URL.RawQuery = q.Encode()
			}
		}
		sealProxyRequestBody(proxy).ServeHTTP(w, r)
	})
}
```

- [ ] **Step 4: 改出站 API handler**

`handlers_api.go` 的 `taaStatusHandler`、`taaGetResourceInfoHandler`、`taaStopTrainingHandler` 全部改为 `(mgr *instanceManager)`，并在读取请求体/发请求前统一插入：

```go
		id, target, err := mgr.targetFor(requestedDockerID(r))
		if err != nil {
			writeEnvelope(w, http.StatusServiceUnavailable, "TAA 地址未配置: "+err.Error(), nil, http.StatusServiceUnavailable)
			return
		}
```

然后把 `proxyJSONToTAA(r.Context(), taaAddr, ...)` 改为
`proxyJSONToTAA(r.Context(), id, target, ...)`，并删除原来的 `if taaAddr == ""` 分支。

`taaStopTrainingHandler` 的错误分支保持旧文案与状态码：

```go
		id, target, err := mgr.targetFor(requestedDockerID(r))
		if err != nil {
			writeEnvelope(w, http.StatusBadGateway, "未配置 TAA 目标地址（-taa-target 或 TAA_POD）", nil, http.StatusBadGateway)
			return
		}
```

`handlers_fhe.go`：`fheSubmitHandler(cfg Config, mgr *instanceManager)`；把
`if strings.TrimSpace(taaAddr) == ""` 分支替换为：

```go
		id, target, err := mgr.targetFor(requestedDockerID(r))
		if err != nil {
			writeEnvelope(w, http.StatusServiceUnavailable, "TAA 地址未配置: "+err.Error(), nil, http.StatusServiceUnavailable)
			return
		}
```

并把 `proxyJSONToTAA(r.Context(), taaAddr, "/v1/taa/import", body)` 改为
`proxyJSONToTAA(r.Context(), id, target, "/v1/taa/import", body)`。

- [ ] **Step 5: 改 `server.go` 挂载反代**

删除 `taaAddr` 计算与单 proxy 构造，改为：

```go
	mgr := newInstanceManager(cfg.StateDir, cfg)
	if mgr.staticTarget != "" {
		log.Printf("TAA reverse proxy: static target %s", mgr.staticTarget)
	} else {
		log.Printf("TAA reverse proxy: per-instance targets from registration (discovered fallback %q)", mgr.discoveredTarget)
	}
```

把 `/taa/` 挂载改为（无条件）：

```go
	mux.Handle("/taa/", loggingReverseProxyHandler(http.StripPrefix("/taa", dynamicTAAProxyHandler(mgr, newProxyPool()))))
```

并把 `Server.taaAddr` 字段与 `taaAddr: taaAddr` 初始化删除。`import "net/url"`、`"net/http/httputil"` 从 `server.go` 删除。

- [ ] **Step 6: 改出站测试构造点**

```go
taaGetResourceInfoHandler(taa.URL)
→ taaGetResourceInfoHandler(testManagerWith(t, "", func(b *instanceStores) { b.setTarget(taa.URL) }))

taaStopTrainingHandler(taaServer.URL)
→ taaStopTrainingHandler(testManagerWith(t, "", func(b *instanceStores) { b.setTarget(taaServer.URL) }))

taaStopTrainingHandler("")
→ taaStopTrainingHandler(testManagerWith(t, "", nil))

fheSubmitHandler(cfg, taa.URL)
→ fheSubmitHandler(cfg, testManagerWith(t, "", func(b *instanceStores) { b.setTarget(taa.URL) }))

fheSubmitHandler(cfg, "  ")
→ fheSubmitHandler(cfg, testManagerWith(t, "", nil))
```

- [ ] **Step 7: 运行反代与出站测试**

Run: `go test ./tools/platform-mock/internal -run 'TestTAA|TestFHE|TestRegistration' -count=1`
Expected: `ok  taa/tools/platform-mock/internal`。

- [ ] **Step 8: 提交**

```bash
git add tools/platform-mock/internal/proxy.go tools/platform-mock/internal/handlers_api.go \
  tools/platform-mock/internal/handlers_fhe.go tools/platform-mock/internal/server.go \
  tools/platform-mock/internal/server_test.go tools/platform-mock/internal/handlers_fhe_test.go \
  tools/platform-mock/internal/instances_outbound_test.go
git commit -m "feat(platform-mock): proxy and send to each instance's own TAA target"
```

---

### Task 6: 控制台 API（实例列表、按实例状态与重置）

**Files:**
- Modify: `tools/platform-mock/internal/handlers_api.go`
- Modify: `tools/platform-mock/internal/handlers_upload.go`
- Modify: `tools/platform-mock/internal/server.go`
- Test: `tools/platform-mock/internal/instances_api_test.go`（新建）

- [ ] **Step 1: 写失败测试**

新建 `tools/platform-mock/internal/instances_api_test.go`：

```go
package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"taa/pkg/crypto"
)

func TestInstancesEndpointListsEveryInstanceAndMarksTheDefault(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	setPlatformKeys(ks)
	defer setPlatformKeys(platformKeyStore())

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)
	mgr.lookup("docker-a").reportRes.set(reportState{DockerID: "docker-a", Received: true, ReceivedAt: "2026-05-01T00:00:00Z"})

	req := httptest.NewRequest(http.MethodGet, "/api/instances", nil)
	w := httptest.NewRecorder()
	instancesHandler(mgr).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var payload struct {
		Result struct {
			Instances []instanceSummary `json:"instances"`
			Default   string            `json:"defaultDockerId"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode instances: %v", err)
	}
	if len(payload.Result.Instances) != 2 {
		t.Fatalf("instances = %d, want 2", len(payload.Result.Instances))
	}
	if payload.Result.Default == "" {
		t.Fatal("defaultDockerId is empty")
	}
	foundTarget := false
	for _, item := range payload.Result.Instances {
		if item.DockerID == "docker-a" {
			if item.LastReportAt != "2026-05-01T00:00:00Z" {
				t.Fatalf("lastReportAt = %q", item.LastReportAt)
			}
			foundTarget = item.TaaTarget != ""
		}
	}
	if !foundTarget {
		t.Fatal("the registered target is missing from the instance summary")
	}
}

func TestRegisterStatusAnswersBeforeAnyRegistration(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/register/status", nil)
	w := httptest.NewRecorder()
	registerStatusHandler(mgr).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the readiness probe; body = %s", w.Code, w.Body.String())
	}
	var payload apiResponse
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Error != 0 {
		t.Fatalf("envelope error = %d, want 0", payload.Error)
	}
}

func TestRegisterResetAllAndOne(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	setPlatformKeys(ks)
	defer setPlatformKeys(platformKeyStore())

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)

	reset := registerResetHandler(mgr)
	reset.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/register/reset?dockerId=docker-a", nil))
	if mgr.lookup("docker-a").register.get().Received {
		t.Fatal("docker-a was not reset")
	}
	if !mgr.lookup("docker-b").register.get().Received {
		t.Fatal("resetting docker-a also reset docker-b")
	}

	reset.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/register/reset", nil))
	if mgr.lookup("docker-b").register.get().Received {
		t.Fatal("reset-all did not clear docker-b")
	}

	w := httptest.NewRecorder()
	reset.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/register/reset?dockerId=missing", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("reset of an unknown dockerId = %d, want 404", w.Code)
	}
}

func TestDashboardIncludesTheInstanceList(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	setPlatformKeys(ks)
	defer setPlatformKeys(platformKeyStore())

	mgr := newInstanceManager(t.TempDir(), Config{TAATarget: "http://10.0.0.9:6001"})
	keyA, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/status?dockerId=docker-a", nil)
	w := httptest.NewRecorder()
	dashboardStatusHandler(mgr).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var payload struct {
		Result struct {
			DockerID string            `json:"dockerId"`
			Target   string            `json:"taaTarget"`
			Items    []instanceSummary `json:"instances"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if payload.Result.DockerID != "docker-a" {
		t.Fatalf("dockerId = %q", payload.Result.DockerID)
	}
	if payload.Result.Target != "http://10.0.0.9:6001" {
		t.Fatalf("taaTarget = %q", payload.Result.Target)
	}
	if len(payload.Result.Items) != 1 {
		t.Fatalf("instances = %d, want 1", len(payload.Result.Items))
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./tools/platform-mock/internal -run 'TestInstancesEndpoint|TestRegisterStatusAnswers|TestRegisterResetAll|TestDashboardIncludes' -count=1`
Expected: `undefined: instancesHandler`。

- [ ] **Step 3: 重写控制台 handler**

`handlers_api.go` 顶部 import 增加 `errors`。

追加公共代码：

```go
func writeInstanceError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, errInstanceNotFound):
		writeEnvelope(w, http.StatusNotFound, err.Error(), nil, http.StatusNotFound)
		return true
	case errors.Is(err, errNoInstance):
		writeEnvelope(w, http.StatusServiceUnavailable, err.Error(), nil, http.StatusServiceUnavailable)
		return true
	}
	return false
}

type instanceSummary struct {
	DockerID      string `json:"dockerId"`
	Accepted      bool   `json:"accepted"`
	Received      bool   `json:"received"`
	ReceivedAt    string `json:"receivedAt"`
	TaaTarget     string `json:"taaTarget"`
	LastReportAt  string `json:"lastReportAt"`
	ModelLogCount int    `json:"modelLogCount"`
	TaaLogCount   int    `json:"taaLogCount"`
	Default       bool   `json:"default"`
}

func lastReportAt(b *instanceStores) string {
	latest := ""
	for _, store := range []*reportStateStore{b.reportResourceRes, b.reportRes, b.reportModelImport, b.reportAudit} {
		if at := store.get().ReceivedAt; at > latest {
			latest = at
		}
	}
	return latest
}

func summarizeInstance(b *instanceStores) instanceSummary {
	reg := b.register.get()
	return instanceSummary{
		DockerID:      b.dockerID,
		Accepted:      reg.Accepted,
		Received:      reg.Received,
		ReceivedAt:    reg.ReceivedAt,
		TaaTarget:     b.target(),
		LastReportAt:  lastReportAt(b),
		ModelLogCount: b.modelLog.get().TotalCount,
		TaaLogCount:   b.taaLog.get().TotalCount,
	}
}

func instanceListPayload(mgr *instanceManager) ([]instanceSummary, string) {
	defaultBundle := mgr.defaultBundle()
	defaultID := ""
	if defaultBundle != nil {
		defaultID = defaultBundle.dockerID
	}
	items := make([]instanceSummary, 0)
	for _, b := range mgr.list() {
		item := summarizeInstance(b)
		item.Default = defaultBundle != nil && b.dockerID == defaultBundle.dockerID
		items = append(items, item)
	}
	return items, defaultID
}

func instancesHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		items, defaultID := instanceListPayload(mgr)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"instances":       items,
			"defaultDockerId": defaultID,
		}, 0)
	}
}

func targetForDisplay(mgr *instanceManager, dockerID string) string {
	_, target, err := mgr.targetFor(dockerID)
	if err != nil {
		return ""
	}
	return target
}
```

`dashboardStatusHandler` 替换为：

```go
func dashboardStatusHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 GET 方法", nil, http.StatusMethodNotAllowed)
			return
		}
		b, err := mgr.resolveLenient(r)
		if writeInstanceError(w, err) {
			return
		}
		items, defaultID := instanceListPayload(mgr)
		res := map[string]any{
			"register":        b.register.get(),
			"modelImport":     reportStateResult(b.reportModelImport.get()),
			"audit":           reportStateResult(b.reportAudit.get()),
			"progress":        b.progress.get(),
			"taaTarget":       targetForDisplay(mgr, b.dockerID),
			"dockerId":        b.dockerID,
			"instances":       items,
			"defaultDockerId": defaultID,
		}
		writeEnvelope(w, http.StatusOK, "ok", res, 0)
	}
}
```

`registerStatusHandler` 替换为：

```go
// registerStatusHandler always answers HTTP 200 when no instance exists: the
// deploy scripts poll it as a readiness probe. The envelope error field still
// carries the last registration's status code once one has happened.
func registerStatusHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolve(r)
		if errors.Is(err, errNoInstance) {
			writeEnvelope(w, http.StatusOK, "", registerState{}, 0)
			return
		}
		if writeInstanceError(w, err) {
			return
		}
		state := b.register.get()
		writeEnvelope(w, http.StatusOK, state.Message, state, state.StatusCode)
	}
}
```

`registerResetHandler` 替换为：

```go
func instanceResetHandler(mgr *instanceManager, apply func(*instanceStores)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}
		if id := requestedDockerID(r); id != "" {
			b := mgr.lookup(id)
			if b == nil {
				writeEnvelope(w, http.StatusNotFound, errInstanceNotFound.Error(), nil, http.StatusNotFound)
				return
			}
			apply(b)
		} else {
			for _, b := range mgr.list() {
				apply(b)
			}
		}
		writeEnvelope(w, http.StatusOK, "reset", nil, 0)
	}
}

func registerResetHandler(mgr *instanceManager) http.HandlerFunc {
	return instanceResetHandler(mgr, func(b *instanceStores) { b.register.reset() })
}
```

`reportStatusHandler` / `reportResetHandler` 改为带 picker：

```go
func reportStatusHandler(mgr *instanceManager, pick func(*instanceStores) *reportStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolve(r)
		if writeInstanceError(w, err) {
			return
		}
		store := pick(b)
		state := store.get()
		msg, errorCode := reportStateEnvelope(state)
		res := reportStateResult(state)
		res["history"] = store.getHistory()
		writeEnvelope(w, http.StatusOK, msg, res, errorCode)
	}
}

func reportResetHandler(mgr *instanceManager, pick func(*instanceStores) *reportStateStore) http.HandlerFunc {
	return instanceResetHandler(mgr, func(b *instanceStores) { pick(b).reset() })
}
```

`progressStatusHandler` / `progressResetHandler` / `modelLogStatusHandler` / `modelLogResetHandler` /
`taaLogStatusHandler` / `taaLogResetHandler` 全部改为 `(mgr *instanceManager)`，模式相同：

```go
func progressStatusHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolve(r)
		if writeInstanceError(w, err) {
			return
		}
		state := b.progress.get()
		msg := state.Message
		if msg == "" {
			msg = "success"
		}
		var errCode int
		if !state.Accepted && state.Received {
			errCode = state.StatusCode
		}
		writeEnvelope(w, http.StatusOK, msg, state, errCode)
	}
}

func progressResetHandler(mgr *instanceManager) http.HandlerFunc {
	return instanceResetHandler(mgr, func(b *instanceStores) { b.progress.reset() })
}

func modelLogStatusHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolve(r)
		if writeInstanceError(w, err) {
			return
		}
		state := b.modelLog.get()
		if state.Entries == nil {
			state.Entries = []modelLogEntry{}
		}
		writeEnvelope(w, http.StatusOK, "success", state, 0)
	}
}

func modelLogResetHandler(mgr *instanceManager) http.HandlerFunc {
	return instanceResetHandler(mgr, func(b *instanceStores) { b.modelLog.reset() })
}

func taaLogStatusHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolve(r)
		if writeInstanceError(w, err) {
			return
		}
		state := b.taaLog.get()
		if state.Entries == nil {
			state.Entries = []taaLogEntry{}
		}
		writeEnvelope(w, http.StatusOK, "success", state, 0)
	}
}

func taaLogResetHandler(mgr *instanceManager) http.HandlerFunc {
	return instanceResetHandler(mgr, func(b *instanceStores) { b.taaLog.reset() })
}
```

`taaTargetHandler` 替换为：

```go
func taaTargetHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolveLenient(r)
		if writeInstanceError(w, err) {
			return
		}
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"taaTarget": targetForDisplay(mgr, b.dockerID),
		}, 0)
	}
}
```

保留 `resetHandler` 给请求日志使用。

- [ ] **Step 4: 上传 handler 按实例取公钥**

`handlers_upload.go`：

```go
func uploadHandler(addr, uploadDir string, mgr *instanceManager) http.HandlerFunc {
```

在方法检查后插入：

```go
		b, resolveErr := mgr.resolveLenient(r)
		if writeInstanceError(w, resolveErr) {
			return
		}
```

把 `registerStores[0].get().TaaPublicKey` 替换为 `b.register.get().TaaPublicKey`。

- [ ] **Step 5: 改 `server.go` 控制台路由**

```go
	mux.HandleFunc("/api/instances", instancesHandler(mgr))
	mux.HandleFunc("/api/dashboard/status", dashboardStatusHandler(mgr))
	mux.HandleFunc("/api/register/status", registerStatusHandler(mgr))
	mux.HandleFunc("/api/register/reset", registerResetHandler(mgr))
	mux.HandleFunc("/api/reportResourceRes/status", reportStatusHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportResourceRes }))
	mux.HandleFunc("/api/reportResourceRes/reset", reportResetHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportResourceRes }))
	mux.HandleFunc("/api/reportRes/status", reportStatusHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportRes }))
	mux.HandleFunc("/api/reportRes/reset", reportResetHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportRes }))
	mux.HandleFunc("/api/reportModelImport/status", reportStatusHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportModelImport }))
	mux.HandleFunc("/api/reportModelImport/reset", reportResetHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportModelImport }))
	mux.HandleFunc("/api/reportAudit/status", reportStatusHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportAudit }))
	mux.HandleFunc("/api/reportAudit/reset", reportResetHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportAudit }))
	mux.HandleFunc("/api/reportProgress/status", progressStatusHandler(mgr))
	mux.HandleFunc("/api/reportProgress/reset", progressResetHandler(mgr))
	mux.HandleFunc("/api/modelLog/status", modelLogStatusHandler(mgr))
	mux.HandleFunc("/api/modelLog/reset", modelLogResetHandler(mgr))
	mux.HandleFunc("/api/taaLog/status", taaLogStatusHandler(mgr))
	mux.HandleFunc("/api/taaLog/reset", taaLogResetHandler(mgr))
	mux.HandleFunc("/api/taa-target", taaTargetHandler(mgr))
	mux.HandleFunc("/api/upload", uploadHandler(cfg.Addr, uploadDir, mgr))
	mux.HandleFunc("/api/fhe/submit", fheSubmitHandler(cfg, mgr))
	mux.HandleFunc("/api/taa/status", taaStatusHandler(mgr))
	mux.HandleFunc("/api/taa/getResourceInfo", taaGetResourceInfoHandler(mgr))
	mux.HandleFunc("/api/taa/stopTraining", taaStopTrainingHandler(mgr))
```

删除 Task 3 遗留的旧 store 构造行（`registerStore`、`reportStore` 等 8 行）。

- [ ] **Step 6: 更新控制台测试构造点**

```go
progressStatusHandler(store) → progressStatusHandler(testManagerWith(t, "", func(b *instanceStores) { b.progress = store }))
progressResetHandler(store) → progressResetHandler(testManagerWith(t, "", func(b *instanceStores) { b.progress = store }))
modelLogStatusHandler(store) → modelLogStatusHandler(testManagerWith(t, "", func(b *instanceStores) { b.modelLog = store }))
modelLogResetHandler(store) → modelLogResetHandler(testManagerWith(t, "", func(b *instanceStores) { b.modelLog = store }))
taaLogStatusHandler(store) → taaLogStatusHandler(testManagerWith(t, "", func(b *instanceStores) { b.taaLog = store }))
taaLogResetHandler(store) → taaLogResetHandler(testManagerWith(t, "", func(b *instanceStores) { b.taaLog = store }))
reportStatusHandler(store) → reportStatusHandler(testManagerWith(t, "", func(b *instanceStores) { b.reportRes = store }), func(b *instanceStores) *reportStateStore { return b.reportRes })
reportResetHandler(store) → reportResetHandler(testManagerWith(t, "", func(b *instanceStores) { b.reportRes = store }), func(b *instanceStores) *reportStateStore { return b.reportRes })
uploadHandler("127.0.0.1:6001", uploadDir, registerStores...) → uploadHandler("127.0.0.1:6001", uploadDir, testManagerWith(t, "", func(b *instanceStores) { if len(registerStores) > 0 { b.register = registerStores[0] } }))
```

`newUploadTestServer` 内部改一次即可，它的调用方不变。

- [ ] **Step 7: 运行全部测试**

Run: `go test ./tools/platform-mock/internal -count=1`
Expected: `ok  taa/tools/platform-mock/internal`。

- [ ] **Step 8: 提交**

```bash
git add tools/platform-mock/internal/handlers_api.go tools/platform-mock/internal/handlers_upload.go \
  tools/platform-mock/internal/server.go tools/platform-mock/internal/server_test.go \
  tools/platform-mock/internal/instances_api_test.go
git commit -m "feat(platform-mock): expose per-instance console APIs"
```

---

### Task 7: 控制台实例选择器

**Files:**
- Modify: `tools/platform-mock/internal/static/index.html`
- Modify: `tools/platform-mock/internal/static/js/api.js`
- Modify: `tools/platform-mock/internal/static/js/app.js`
- Modify: `tools/platform-mock/internal/static/js/logs.js`
- Test: `tools/platform-mock/internal/server_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `server_test.go`：

```go
func TestFrontendInstanceSelector(t *testing.T) {
	for _, want := range []string{
		`id="instanceSelect"`,
		"function currentDockerId()",
		"function withDockerId(url)",
		"function mockFetch(url, opts)",
		"function loadInstances()",
		"fetch('/api/instances'",
		"instanceSelect').style.display",
		"dockerId=",
	} {
		if !strings.Contains(frontendBundle, want) {
			t.Fatalf("frontendBundle missing %q", want)
		}
	}
	// The instance-scoped calls must go through mockFetch, otherwise switching
	// the selector would still show the default instance's data.
	for _, want := range []string{
		"mockFetch('/api/register/status'",
		"mockFetch('/api/reportRes/status'",
		"mockFetch('/api/modelLog/status'",
		"mockFetch('/api/taaLog/status'",
		"mockFetch('/api/dashboard/status'",
	} {
		if !strings.Contains(frontendBundle, want) {
			t.Fatalf("frontendBundle missing instance-aware call %q", want)
		}
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test ./tools/platform-mock/internal -run TestFrontendInstanceSelector -count=1`
Expected: FAIL，`frontendBundle missing "id=\"instanceSelect\""`。

- [ ] **Step 3: 加选择器到 HTML**

`static/index.html` 第二行工具栏里，`<label for="taaAddr">` 之前插入：

```html
        <label for="instanceSelect" id="instanceSelectLabel" style="font-size:13px; font-weight:650; white-space:nowrap; margin:0; display:none;">实例</label>
        <select id="instanceSelect" style="display:none; max-width:260px; padding:6px 10px; font-size:13px; border-radius:6px; border:1px solid var(--line); background:var(--bg);" title="选择要查看的 TAA 实例"></select>
```

当 `loadInstances` 发现实例数大于 1 时，同时显示 `instanceSelect` 和 `instanceSelectLabel`；否则隐藏两者。

- [ ] **Step 4: 在 `api.js` 加实例工具**

追加到 `api.js` 顶部（`getTaaAddr` 之后）：

```js
// ── Instance selection ──
//
// Every instance-scoped /api/* call carries ?dockerId=. The selection is held
// in one module-level variable so polling functions keep their existing shape.
let currentInstanceDockerId = '';

function currentDockerId() {
  return currentInstanceDockerId;
}

function withDockerId(url) {
  const id = currentDockerId();
  if (!id) return url;
  const sep = url.indexOf('?') === -1 ? '?' : '&';
  return url + sep + 'dockerId=' + encodeURIComponent(id);
}

function mockFetch(url, opts) {
  return fetch(withDockerId(url), opts);
}

function applyInstanceList(list, defaultId) {
  const sel = document.getElementById('instanceSelect');
  const label = document.getElementById('instanceSelectLabel');
  if (!sel) return;
  const previous = sel.value || currentInstanceDockerId;
  sel.innerHTML = '';
  list.forEach((item) => {
    const opt = document.createElement('option');
    opt.value = item.dockerId || '';
    const name = item.dockerId || '(legacy)';
    opt.textContent = item.accepted ? name : name + ' (未注册)';
    sel.appendChild(opt);
  });
  if (previous && list.some((item) => (item.dockerId || '') === previous)) {
    sel.value = previous;
  } else {
    sel.value = defaultId || '';
  }
  currentInstanceDockerId = sel.value;
  const show = list.length > 1;
  sel.style.display = show ? '' : 'none';
  if (label) label.style.display = show ? '' : 'none';
}

async function loadInstances() {
  let payload = null;
  try {
    const res = await fetch('/api/instances', { cache: 'no-store' });
    payload = await res.json();
  } catch (_) {
    return;
  }
  const result = (payload && payload.result) || {};
  applyInstanceList(result.instances || [], result.defaultDockerId || '');
}

function initInstanceSelector() {
  const sel = document.getElementById('instanceSelect');
  if (sel) {
    sel.addEventListener('change', () => {
      currentInstanceDockerId = sel.value;
      if (typeof refreshStatus === 'function') refreshStatus();
      if (typeof refreshReportResStatus === 'function') refreshReportResStatus();
      if (typeof refreshReportModelImportStatus === 'function') refreshReportModelImportStatus();
      if (typeof refreshReportAuditStatus === 'function') refreshReportAuditStatus();
      if (typeof refreshReportProgress === 'function') refreshReportProgress();
      if (typeof refreshDashboardStatus === 'function') refreshDashboardStatus();
      if (typeof fetchModelLogs === 'function') fetchModelLogs();
      if (typeof fetchTaaLogs === 'function') fetchTaaLogs();
    });
  }
  loadInstances();
  setInterval(loadInstances, 5000);
}
```

`taaFetch` 改为：

```js
  let url = target + endpoint;
  if (target.endsWith('/taa')) {
    url = withDockerId(url);
  }
  return fetch(url, {
```

- [ ] **Step 5: `app.js` 启动时初始化并改用 `mockFetch`**

在 `DOMContentLoaded` 回调里，`initConsoleMode();` 之后插入：

```js
  initInstanceSelector();
```

把以下调用替换（全部出现处）：

```go
fetch('/api/register/status'          → mockFetch('/api/register/status'
fetch('/api/register/reset'           → mockFetch('/api/register/reset'
fetch('/api/reportRes/status'         → mockFetch('/api/reportRes/status'
fetch('/api/reportRes/reset'          → mockFetch('/api/reportRes/reset'
fetch('/api/reportModelImport/status' → mockFetch('/api/reportModelImport/status'
fetch('/api/reportModelImport/reset'  → mockFetch('/api/reportModelImport/reset'
fetch('/api/reportAudit/status'       → mockFetch('/api/reportAudit/status'
fetch('/api/reportAudit/reset'        → mockFetch('/api/reportAudit/reset'
fetch('/api/reportProgress/status'    → mockFetch('/api/reportProgress/status'
fetch('/api/reportProgress/reset'     → mockFetch('/api/reportProgress/reset'
fetch('/api/dashboard/status'         → mockFetch('/api/dashboard/status'
fetch('/api/taa-target'               → mockFetch('/api/taa-target'
fetch('/api/taa/stopTraining'         → mockFetch('/api/taa/stopTraining'
fetch('/api/fhe/submit'               → mockFetch('/api/fhe/submit'
fetch('/api/upload/delete'            → mockFetch('/api/upload/delete'
postFormWithProgress('/api/upload'    → postFormWithProgress(withDockerId('/api/upload')
```

`/api/uploads` 与 `/api/uploads/reset` 是全局上传目录，保持原样。`url:` 字段里的展示字符串保持原样。

- [ ] **Step 6: `logs.js` 改用 `mockFetch`**

```go
fetch('/api/modelLog/status' → mockFetch('/api/modelLog/status'
fetch('/api/modelLog/reset'  → mockFetch('/api/modelLog/reset'
fetch('/api/taaLog/status'   → mockFetch('/api/taaLog/status'
fetch('/api/taaLog/reset'    → mockFetch('/api/taaLog/reset'
```

- [ ] **Step 7: 运行前端测试**

Run: `go test ./tools/platform-mock/internal -run 'TestFrontendInstanceSelector|TestHealthCheckIntegrated|TestIndexHandler' -count=1`
Expected: `ok  taa/tools/platform-mock/internal`。

- [ ] **Step 8: 提交**

```bash
git add tools/platform-mock/internal/static/index.html tools/platform-mock/internal/static/js/api.js \
  tools/platform-mock/internal/static/js/app.js tools/platform-mock/internal/static/js/logs.js \
  tools/platform-mock/internal/server_test.go
git commit -m "feat(platform-mock): add console instance selector"
```

---

### Task 8: 部署脚本、文档与全量验证

**Files:**
- Modify: `deploy.sh`
- Modify: `deploy-platform-mock.sh`（帮助文本）
- Modify: `deploy.md`
- Modify: `tools/platform-mock/README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: `deploy.sh` 增加 `MULTI_INSTANCE`**

在变量区（`LOCAL_PLATFORM_PORT` 定义附近）加：

```bash
MULTI_INSTANCE="${MULTI_INSTANCE:-0}"
```

本地 docker 模式的 mock 启动段（`deploy.sh` 中 `--taa-target "$LOCAL_TAA_URL"` 所在行）改为：

```bash
  local -a mock_args=(local start --port "$LOCAL_PLATFORM_PORT")
  if [ "$MULTI_INSTANCE" != "1" ]; then
    mock_args+=(--taa-target "$LOCAL_TAA_URL")
  fi
  ./deploy-platform-mock.sh "${mock_args[@]}"
```

远端 k8s 模式的 Pod 发现段改为：

```bash
  if [ "$MULTI_INSTANCE" = "1" ]; then
    log "MULTI_INSTANCE=1: skipping single-Pod discovery; targets come from each registration"
    ./deploy-platform-mock.sh remote start --host "$REMOTE_HOST" --port "$LOCAL_PLATFORM_PORT" --taa-port "$CON_PORT"
  else
    # ... the existing discovery branch, unchanged ...
  fi
```

具体包裹方式按 `deploy.sh` 现有缩进调整；关键是 `MULTI_INSTANCE=1` 时**不传** `--taa-target`，并显式传 `--taa-port "$CON_PORT"`。

- [ ] **Step 2: `deploy-platform-mock.sh` 帮助文本**

`--taa-target` 一行改为：

```text
  --taa-target URL           Single-instance fixed TAA address; omit to derive
                             each instance's address from its registration
```

`--taa-port PORT` 一行改为：

```text
  --taa-port PORT            Port used for discovery and for per-instance target derivation
```

- [ ] **Step 3: 文档**

`tools/platform-mock/README.md` 追加一节：

```markdown
## 多实例

平台默认同时服务多个 TAA 实例，实例身份是注册报文里的 `dockerId`。

- 状态目录：`<state-dir>/instances/i-<sha256(dockerId)[:16]>/`，每个实例一份
  `register-state.json`、`report*-state.json`、日志与 `instance.json`。
- 旧版单实例状态文件会在启动时迁移到对应实例目录；`instances/` 已存在时不迁移。
- 出站地址由注册请求的来源 IP 推导：`http://<RemoteAddr IP>:<taa-port>`。
  部署在反向代理/端口转发之后时来源 IP 会失真，此时改用 `-taa-target`（单实例固定地址）。
- 控制台所有 `/api/*` 接受 `?dockerId=`；不传时使用最近一次成功注册的实例。
- `GET /api/instances` 返回实例列表与 `defaultDockerId`。
- `/taa/*` 反代按 `?dockerId=` 选择目标，转发前会删除该参数。
```

`deploy.md` 的 platform-mock 小节追加：

```markdown
**多实例（默认）**

省略 `--taa-target` 即进入多实例模式：每个实例注册时按来源 IP 推导自己的地址。
`deploy.sh` 用 `MULTI_INSTANCE=1` 打开这个模式：

```bash
MULTI_INSTANCE=1 ./deploy.sh docker
MULTI_INSTANCE=1 ./deploy.sh remote
```

`deploy-platform-mock.sh` 直接调用时：

```bash
./deploy-platform-mock.sh local start --taa-port 6001
```

单实例固定地址仍用 `--taa-target http://<ip>:6001`。
```

`CHANGELOG.md` 顶部追加一条（日期 2026-11-03）：

```markdown
## [Unreleased]

### Added
- platform-mock 支持并发多实例：状态、密钥、上报、进度、日志按 `dockerId` 隔离，
  出站地址由注册来源 IP 推导，控制台提供实例选择器与 `/api/instances`。
  旧版单实例状态在启动时自动迁移；`deploy.sh` 用 `MULTI_INSTANCE=1` 启用。

### Known limitations
- 来源 IP 在反向代理/端口转发之后会失真；该场景请继续使用 `--taa-target`。
```

- [ ] **Step 4: 脚本语法与 dry-run 验证**

```bash
bash -n deploy.sh
bash -n deploy-platform-mock.sh
```

Expected: 无输出，退出码 0。

```bash
MULTI_INSTANCE=1 ./deploy.sh docker -n 2>&1 | grep -n "taa-target"
```

Expected: 多实例分支下 mock 启动参数中不出现 `--taa-target`（若 `deploy.sh` 的 dry-run 开关名不同，按其帮助文本选择 `-n` 或 `--dry-run`）。

```bash
./deploy-platform-mock.sh local start --dry-run --skip-build
```

Expected: 打印 `would start ...`，参数中不含 `-taa-target`。

- [ ] **Step 5: 全量验证**

```bash
gofmt -w tools/platform-mock
go vet ./tools/platform-mock/...
go test ./tools/platform-mock/... -race -count=1
go build -o /tmp/platform-mock ./tools/platform-mock/cmd/platform-mock
go test ./cmd/... ./internal/... ./pkg/... -count=1
```

Expected: 全部 `ok`；`/tmp/platform-mock` 构建成功。

- [ ] **Step 6: 提交**

```bash
git add deploy.sh deploy-platform-mock.sh deploy.md tools/platform-mock/README.md CHANGELOG.md
git commit -m "feat(deploy): enable multi-instance platform-mock"
```

---

## Self-Review

**Spec coverage**

| Spec 章节 | 任务 |
| --- | --- |
| 实例身份（提示只选钥、验签、明文交叉校验） | Task 2 `openBodyWithID` |
| 状态隔离目录与 `instance.json` | Task 1 |
| 实例管理器 API / 默认实例 / resolve | Task 1 |
| 旧状态迁移 | Task 1 |
| 密钥分表与旧单钥回退 | Task 2 |
| 出站寻址 `deriveTAATarget` | Task 4、Task 1 `targetFor` |
| 目标优先级 | Task 1 `targetFor` |
| HTTP API 表 | Task 3（入站）、Task 5（出站）、Task 6（控制台） |
| 反代按目标缓存、context 传 id、剥离查询参数 | Task 5 |
| 控制台选择器与 `mockFetch` | Task 7 |
| 部署脚本 `MULTI_INSTANCE=1` | Task 8 |
| 错误处理（503/404/502、非法注册不建目录） | Task 1、Task 6 |
| 测试清单 1–10 | Task 3、4、5、6 的用例如数覆盖 |
| 文档 | Task 8 |

**类型与命名一致性**

- 管理器方法在全文统一：`getOrCreate`、`lookup`、`list`、`defaultBundle`、`defaultID`、
  `instanceForWrite`、`instanceForRegistration`、`resolve`、`resolveLenient`、`targetFor`。
- keystore 方法统一：`taaPublicFor`、`setTaaPublicKeyFor`、`sealForTAAFor`、
  `openBodyWithID`、`openFromTAAResponseFor`；旧方法保留为 `""` 包装。
- handler 签名统一为 `(mgr *instanceManager)`；报告状态/重置额外带
  `pick func(*instanceStores) *reportStateStore`。
- 测试 helper 统一：`testManagerWith(t, dockerID, configure)`、`registerInstanceForTest`。

**已知执行顺序约束**

Task 3 改了 `server.go` 的入站路由但控制台路由仍是旧签名，编译可能中断；执行时把 Task 3
Step 5 与 Task 6 Step 5 视为一次编译单元，或先完成 Task 6 再跑 Task 3 的全量测试。提交仍按任务拆分。
