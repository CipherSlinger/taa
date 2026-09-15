# 模型日志与训练进度上报 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在训练执行期间从模型方约定目录增量读取 JSONL 日志和最新 JSON 进度，并主动调用平台 `/v1/taa/modelLog`、`/v1/taa/reportProgress`，同时将训练代码输出迁移到 `/opt/taa/output/result/`。

**Architecture:** 保留现有 `report.go` 的平台 HTTP 发送模式，在其上增加两个带请求校验和公共响应校验的回调函数。新增独立的 `model_reporting.go` 负责目录扫描、JSONL offset、进度快照和后台 watcher；`executeTraining` 仅负责创建/停止 watcher，并继续把 result 目录内容复制到任务结果目录。启动配置向 `SecurityConfig` 传递 result/log/progress 三个目录，默认值固定为 `/opt/taa/output/result`、`/opt/taa/output/log`、`/opt/taa/output/progress`。

**Tech Stack:** Go、`net/http`、`encoding/json`、`os.ReadDir`、`time.Ticker`、现有 TAAState/StartupConfig、httptest。

---

## 文件边界

- Modify: `internal/controller/report.go` — 新增 `/v1/taa/modelLog`、`/v1/taa/reportProgress` 的请求模型、校验和发送函数；不改变既有 `ReportRes`/`ReportModelImport` 行为。
- Create: `internal/controller/model_reporting.go` — JSONL 日志增量读取、最新进度 JSON 解析、watcher 和上报容错。
- Create: `internal/controller/model_reporting_test.go` — 客户端 payload、目录读取和 watcher 行为测试。
- Modify: `internal/controller/route.go` — `SecurityConfig` 增加 log/progress 目录及 getter；把默认模型输出目录改成 `.../output/result`，保留 output 根目录路径替换兼容性。
- Modify: `internal/config/config.go` — 增加可选 `modelLogDir`、`modelProgressDir` 配置，缺省采用固定目录；`modelOutputDir` 缺省改为 result 目录。
- Modify: `internal/app/taa/app.go` — 构建安全配置、创建三个输出子目录、日志配置摘要。
- Modify: `internal/controller/import_processing.go` — 训练开始时清理 result/log/progress，启动 watcher，执行完 runtimeConfig 后停止 watcher 并最终 flush。
- Modify: `internal/controller/route_test.go`、`internal/config/config_test.go`、`internal/app/taa/app_test.go` — 更新默认路径断言并补充替换规则断言。
- Modify: `docs/TAA模型提供方开发与接口对接规范.md` — 将输出目录和文件轮询约定同步为 result/log/progress；保留 progress JSON 的字段定义。
- Modify: `docs/taa接口设计文档.md`、`api/openapi.yaml` — 同步两个实际回调接口的请求模型、默认路径说明（若 OpenAPI 当前已包含对应回调模型，则只补齐字段和路径，不重复建模）。

### Task 1: 增加两个平台回调客户端

**Files:**
- Modify: `internal/controller/report.go`
- Create: `internal/controller/model_reporting_test.go`

- [ ] **Step 1: Write failing serialization and response tests**

在 `model_reporting_test.go` 使用 `httptest.NewServer` 验证：

```go
func TestReportModelLogPayload(t *testing.T) {
    var got map[string]any
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost || r.URL.Path != modelLogEndpoint {
            t.Fatalf("request = %s %s", r.Method, r.URL.Path)
        }
        if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
            t.Fatal(err)
        }
        _, _ = io.WriteString(w, `{"msg":"success","result":{"received":true},"error":0}`)
    }))
    defer server.Close()

    err := ReportModelLog(context.Background(), server.URL, "docker-1", "req-1", "", 1,
        []ModelLogEntry{{Seq: 1, Message: "epoch=1"}})
    if err != nil {
        t.Fatal(err)
    }
    if got["dockerId"] != "docker-1" || got["requestId"] != "req-1" {
        t.Fatalf("identity payload = %#v", got)
    }
    if got["taskId"] != nil {
        t.Fatalf("optional taskId should be omitted, payload = %#v", got)
    }
    if got["seqStart"] != float64(1) {
        t.Fatalf("seqStart = %#v", got["seqStart"])
    }
}

func TestReportProgressRejectsInvalidPercent(t *testing.T) {
    err := ReportProgress(context.Background(), "127.0.0.1:1", "docker-1", "req-1", "", 100.1, time.Now().UTC())
    if err == nil || !strings.Contains(err.Error(), "percent") {
        t.Fatalf("error = %v, want percent validation error", err)
    }
}
```

另外验证平台返回 `error != 0` 或响应 JSON 非法时函数返回错误，HTTP 200 但未收到公共成功响应不能被当作成功。

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `go test ./internal/controller -run 'TestReport(ModelLogPayload|ProgressRejectsInvalidPercent)' -count=1`

Expected: FAIL because `ReportModelLog`、`ReportProgress`、`ModelLogEntry` 和 endpoint constants 尚未定义。

- [ ] **Step 3: Implement request models and client functions**

在 `report.go` 增加：

```go
const (
    modelLogEndpoint       = "/v1/taa/modelLog"
    reportProgressEndpoint = "/v1/taa/reportProgress"
)

type ModelLogEntry struct {
    Seq     uint64 `json:"seq"`
    Message string `json:"message"`
}

type modelLogRequest struct {
    DockerID string         `json:"dockerId"`
    RequestID string         `json:"requestId"`
    TaskID   string         `json:"taskId,omitempty"`
    SeqStart uint64         `json:"seqStart"`
    Entries  []ModelLogEntry `json:"entries"`
}

type reportProgressRequest struct {
    DockerID  string  `json:"dockerId"`
    RequestID string  `json:"requestId"`
    TaskID    string  `json:"taskId,omitempty"`
    Percent   float64 `json:"percent"`
    Timestamp string  `json:"timestamp"`
}

type platformAck struct {
    Msg    string `json:"msg"`
    Result struct { Received bool `json:"received"` } `json:"result"`
    Error  int    `json:"error"`
}
```

`ReportModelLog` 必须要求 platform address、docker ID、request ID 非空，允许 task ID 为空，要求 entries 非空且 `seqStart == entries[0].Seq`；`ReportProgress` 必须要求 percent 在 `[0,100]` 且 timestamp 非零。两个函数通过 POST 发送后解码 `platformAck`，只有 HTTP 200、`Error == 0`、`Result.Received == true` 才返回 nil。不要复用会自动补齐 task ID 的既有 `validateAndNormalizePlatformParams`，以保留 task ID 可选语义。

- [ ] **Step 4: Run focused tests and confirm pass**

Run: `go test ./internal/controller -run 'TestReport(ModelLogPayload|ProgressRejectsInvalidPercent)' -count=1`

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add internal/controller/report.go internal/controller/model_reporting_test.go
git commit -m "feat(上报): 增加模型日志和训练进度回调"
```

### Task 2: 增加输出目录配置和路径替换

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/controller/route.go`
- Modify: `internal/app/taa/app.go`
- Test: `internal/config/config_test.go`
- Test: `internal/app/taa/app_test.go`
- Test: `internal/controller/route_test.go`

- [ ] **Step 1: Add failing default/config path tests**

新增断言：

```go
if cfg.ModelOutputDir != "/opt/taa/output/result" { t.Fatalf("ModelOutputDir = %q", cfg.ModelOutputDir) }
if cfg.ModelLogDir != "/opt/taa/output/log" { t.Fatalf("ModelLogDir = %q", cfg.ModelLogDir) }
if cfg.ModelProgressDir != "/opt/taa/output/progress" { t.Fatalf("ModelProgressDir = %q", cfg.ModelProgressDir) }
```

并在安全配置测试中检查 `GetModelOutputDir()`、`GetModelLogDir()`、`GetModelProgressDir()` 都返回绝对清理后的路径。

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `go test ./internal/config ./internal/app/taa ./internal/controller -run 'Test(Default|SecurityConfig|BuildSecurity)' -count=1`

Expected: FAIL because the new config fields/getters and result default do not exist。

- [ ] **Step 3: Implement configuration and directory initialization**

在 `StartupConfig`/JSON 文件结构中增加 `ModelLogDir` (`modelLogDir`) 和 `ModelProgressDir` (`modelProgressDir`)；默认值分别为 `/opt/taa/output/log`、`/opt/taa/output/progress`，`ModelOutputDir` 默认值改为 `/opt/taa/output/result`。在 `SecurityConfig` 增加同名字段和：

```go
func (sec SecurityConfig) GetModelLogDir() string
func (sec SecurityConfig) GetModelProgressDir() string
```

两个 getter 复用输入/输出 getter 的绝对路径清理逻辑。`buildSecurityConfig` 和 `ensureSecurityDirectories` 必须传递并创建 result、log、progress 三个目录。

更新运行时路径替换：`<output>`、`<out>`、`TAA_OUTPUT_DIR` 指向 result 目录；字符串替换器按顺序先替换 `/opt/taa/output/log`、`/opt/taa/output/progress`、`/opt/taa/output/result`，再替换旧的 `/opt/taa/output`，保证模型使用固定日志/进度路径时不会被旧根路径规则误改。现有自定义 output 测试继续使用自定义 result 目录。

- [ ] **Step 4: Run focused tests and confirm pass**

Run: `go test ./internal/config ./internal/app/taa ./internal/controller -run 'Test(Default|SecurityConfig|BuildSecurity|ResolveRuntime)' -count=1`

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/controller/route.go internal/app/taa/app.go internal/config/config_test.go internal/app/taa/app_test.go internal/controller/route_test.go
git commit -m "feat(目录): 调整模型输出并增加日志进度目录"
```

### Task 3: 实现 JSONL 日志和 JSON 进度读取器

**Files:**
- Create: `internal/controller/model_reporting.go`
- Modify: `internal/controller/model_reporting_test.go`

- [ ] **Step 1: Write failing reader tests**

覆盖：JSONL 首次读取、第二次读取不重复、无换行的半行暂不消费、最新 JSON 进度选择、非法 JSON 和越界 percent 被跳过：

```go
func TestLogReaderConsumesCompleteJSONLLinesOnly(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "train.jsonl")
    if err := os.WriteFile(path, []byte("{\"message\":\"one\"}\n{\"message\":\"two\"}"), 0o644); err != nil { t.Fatal(err) }
    reader := newJSONLLogReader(dir)
    first, err := reader.ReadNew()
    if err != nil { t.Fatal(err) }
    if len(first) != 1 || first[0].Message != "one" || first[0].Seq != 1 { t.Fatalf("first = %#v", first) }
    if second, err := reader.ReadNew(); err != nil { t.Fatal(err) } else if len(second) != 0 { t.Fatalf("second = %#v", second) }
    f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
    _, _ = f.WriteString("\n")
    _ = f.Close()
    third, err := reader.ReadNew()
    if err != nil { t.Fatal(err) }
    if len(third) != 1 || third[0].Message != "two" || third[0].Seq != 2 { t.Fatalf("third = %#v", third) }
}

func TestProgressReaderUsesLatestValidJSON(t *testing.T) {
    dir := t.TempDir()
    writeProgressFile(t, filepath.Join(dir, "old.json"), `{"percent":10,"timestamp":"2026-09-15T00:00:00Z"}`)
    writeProgressFile(t, filepath.Join(dir, "new.json"), `{"percent":35.5,"timestamp":"2026-09-15T00:01:00Z"}`)
    got, ok, err := readLatestProgress(dir)
    if err != nil || !ok || got.Percent != 35.5 { t.Fatalf("got=%+v ok=%v err=%v", got, ok, err) }
}
```

- [ ] **Step 2: Run reader tests and confirm failure**

Run: `go test ./internal/controller -run 'Test(LogReader|ProgressReader)' -count=1`

Expected: FAIL because reader types/functions are absent。

- [ ] **Step 3: Implement readers**

在 `model_reporting.go` 定义：

```go
type progressSnapshot struct { Percent float64; Timestamp time.Time; Key string }
type logFileCursor struct { Offset int64 }
type jsonlLogReader struct { dir string; files map[string]logFileCursor; nextSeq uint64 }
func newJSONLLogReader(dir string) *jsonlLogReader
func (r *jsonlLogReader) ReadNew() ([]ModelLogEntry, error)
func readLatestProgress(dir string) (progressSnapshot, bool, error)
```

日志读取规则：递归或单层扫描 `dir` 下常规 `.jsonl` 文件，按路径排序；从每个文件保存的 byte offset 开始读取；只消费以换行结尾的完整行；每行优先解析 JSON 对象的 `message` 字段，字段不存在时将去掉空白的整行作为 message，空行跳过；每发现一条完整日志分配任务内从 1 开始的递增 `seq`。文件截断时将 offset 重置为 0。读取错误返回给 watcher 记录但不终止训练。

进度读取规则：扫描目录下常规 `.json` 文件，按 ModTime 最新选择；反序列化 `{ "percent": number, "timestamp": string }`；timestamp 用 RFC3339/RFC3339Nano 解析，percent 必须在 0～100；非法文件返回 `ok=false` 而不是影响训练。`Key` 使用 percent 与 timestamp 的规范化组合，避免同一快照重复上报。

- [ ] **Step 4: Run reader tests and confirm pass**

Run: `go test ./internal/controller -run 'Test(LogReader|ProgressReader)' -count=1`

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add internal/controller/model_reporting.go internal/controller/model_reporting_test.go
git commit -m "feat(读取): 增加模型日志进度目录读取"
```

### Task 4: 接入训练 watcher 和回调容错

**Files:**
- Modify: `internal/controller/model_reporting.go`
- Modify: `internal/controller/import_processing.go`
- Modify: `internal/controller/model_reporting_test.go`
- Modify: `internal/controller/route.go`（仅在需要暴露目录 getter 时）

- [ ] **Step 1: Write failing watcher integration test**

用 `httptest.Server` 记录两个路径，创建 `SecurityConfig` 的临时 log/progress 目录，启动 watcher，写入 JSONL 和 progress JSON，等待收到两个请求，然后停止 watcher 并断言停止后最终 flush 仍会发送新日志；平台返回 500 时断言 `Stop()` 不返回训练错误。

测试请求断言至少包括：

```go
if r.URL.Path == modelLogEndpoint { gotLog = true }
if r.URL.Path == reportProgressEndpoint { gotProgress = true }
```

另测 watcher 不会因平台返回 `{"error":1}` 或日志目录不存在而退出。

- [ ] **Step 2: Run watcher test and confirm failure**

Run: `go test ./internal/controller -run 'Test(ReportWatcher|ModelReporting)' -count=1`

Expected: FAIL because watcher and training integration are absent。

- [ ] **Step 3: Implement watcher lifecycle**

在 `model_reporting.go` 定义：

```go
type reportWatcher struct {
    ctx context.Context
    cancel context.CancelFunc
    wg sync.WaitGroup
    state *TAAState
    requestID string
    taskID string
    logs *jsonlLogReader
    lastProgressKey string
    interval time.Duration
}
func (s *TAAState) startModelReportWatcher(ctx context.Context, requestID, taskID string) *reportWatcher
func (w *reportWatcher) Stop()
func (w *reportWatcher) flush()
```

watcher 启动后用 `time.Ticker` 轮询，单次 tick 先读取日志并按最多 100 条组批调用 `ReportModelLog`，再读取最新进度；两个回调在 watcher 内串行执行。日志发送失败时保留 pending batch，下一 tick 使用相同序号重试；平台网络错误、408、429、5xx 最多重试 3 次并采用 100ms/300ms/900ms 退避，所有失败只写 TAA 结构化 warning，不返回训练 goroutine。进度按 `lastProgressKey` 去重，失败时不更新 key。`Stop()` 取消 ticker、等待 goroutine 退出，然后同步执行最终 `flush()`，确保不会泄漏 goroutine。

- [ ] **Step 4: Integrate watcher around runtimeConfig**

在 `executeTraining` 的 runtimeConfig 前：

```go
for _, dir := range []string{
    s.Security.GetModelOutputDir(),
    s.Security.GetModelLogDir(),
    s.Security.GetModelProgressDir(),
} {
    if err := os.MkdirAll(dir, 0o755); err != nil { ... }
    if err := cleanDirContents(dir); err != nil { ... }
}
watcher := s.startModelReportWatcher(context.Background(), trainReq.RequestID, trainReq.TaskID)
```

使用 `defer watcher.Stop()`，确保 runtimeConfig 成功、失败和 panic 路径都停止 watcher；停止后再继续现有结果复制和训练报告流程。`TAA_OUTPUT_DIR`、`<output>` 等仍指向 result 目录；日志和进度目录由模型方按固定绝对路径或可选环境配置写入。watcher 失败不能改变 `runRuntimeConfig` 的返回值。

- [ ] **Step 5: Run watcher and import tests**

Run: `go test ./internal/controller -run 'Test(ReportWatcher|ModelReporting|RunRuntimeConfig|Import)' -count=1`

Expected: PASS。

- [ ] **Step 6: Commit**

```bash
git add internal/controller/model_reporting.go internal/controller/import_processing.go internal/controller/model_reporting_test.go
 git commit -m "feat(训练): 接入模型日志进度实时上报"
```

### Task 5: 同步协议文档并执行完整验证

**Files:**
- Modify: `docs/TAA模型提供方开发与接口对接规范.md`
- Modify: `docs/taa接口设计文档.md`
- Modify: `api/openapi.yaml`
- Modify: `README.md`（仅当其中仍明确写死旧 output 路径）

- [ ] **Step 1: Update documented path and payload contracts**

同步为：

```text
/opt/taa/output/result/    # 训练代码输出
/opt/taa/output/log/       # JSONL 模型日志
/opt/taa/output/progress/  # JSON 进度文件
```

明确 `modelLog.entries[]` 只有 `seq`、`message`；`reportProgress` 只有 `dockerId`、`requestId`、可选 `taskId`、`percent`、`timestamp`；两个回调成功响应只包含 `result.received`。明确日志序号由 TAA 在本次任务内分配，JSONL 末尾未换行的半行将在下一轮补齐后上报。

- [ ] **Step 2: Run documentation checks**

Run: `git diff --check` and a targeted search:

```bash
grep -RInE '/opt/taa/output($|[^/])|progress\.json|modelLog|reportProgress' docs api README.md
```

Expected: 新接口和三个新目录有明确说明；除兼容性说明外，不再把训练代码输出描述为 `/opt/taa/output/` 根目录。

- [ ] **Step 3: Run full verification**

Run:

```bash
go test ./...
go vet ./...
gofmt -l internal/controller internal/config internal/app/taa
```

Expected: `go test`、`go vet` 返回 0；`gofmt -l` 无输出。若本机 Go 版本低于 `go.mod`，记录实际版本错误，不将其误报为测试失败。

- [ ] **Step 4: Review diff and commit**

```bash
git diff --check
git status --short
git diff --stat
git add docs/TAA模型提供方开发与接口对接规范.md docs/taa接口设计文档.md api/openapi.yaml README.md
git commit -m "docs(接口): 同步模型日志进度上报与输出目录"
```

只提交本 worktree 中本次功能涉及的文件，不提交主工作区的 TODO、配置、部署脚本或其他未相关修改。

### Task 6: 合并 master 并移除 worktree

**Files:**
- Worktree branch: `worktree-model-reporting`
- Base branch: local `master`

- [ ] **Step 1: Verify worktree is clean and record commits**

Run: `git status --short` and `git log --oneline master..HEAD`。

Expected: worktree 无未提交功能改动，列出本功能提交；设计规格提交 `a963809` 也应包含在分支历史中。

- [ ] **Step 2: Preserve unrelated main-worktree modifications**

在主工作区合并前检查 `/home/hjy/taa` 的 `TODO`、`configs/taa-production.json`、`deploy.sh`、`internal/controller/report.go`、`internal/app/mock/server.go` 等修改。不要丢弃它们；如未提交修改阻止 merge，使用带唯一标签的临时 stash，记录 SHA，合并后用 `git stash apply <sha>` 恢复并删除该 stash，不使用裸 `git stash/pop`。

- [ ] **Step 3: Merge into local master**

从主工作区执行：

```bash
cd /home/hjy/taa
git checkout master
git merge --no-ff worktree-model-reporting -m "feat(训练): 实现模型日志和进度上报"
```

若合并因 `internal/controller/report.go` 的用户修改冲突，先停止并保留冲突现场，不擅自覆盖；采用三方合并保留两边逻辑后再运行验证。

- [ ] **Step 4: Verify merged master**

Run in `/home/hjy/taa`:

```bash
git status --short
git show --check --stat HEAD
go test ./...
```

Expected: merge commit检查通过；测试结果如环境支持则全通过，否则记录 Go 版本阻塞。

- [ ] **Step 5: Remove the worktree**

只有合并成功且验证完成后，从主工作区执行：

```bash
git worktree remove /home/hjy/taa/.claude/worktrees/model-reporting
git worktree prune
git status --short
```

确认 worktree 已移除、master 保留合并提交、未相关修改仍在主工作区。
