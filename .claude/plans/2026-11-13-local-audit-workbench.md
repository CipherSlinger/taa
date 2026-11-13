# 代码审计工作台改为本地明文审计 + 纵向实时流程图

## Context

`tools/platform-mock` 的「代码审计工作台」目前把上传包封装成 SM2/SM4 信封，再通过
`/v1/taa/importModel` 下发到真实 TAA，依赖实例注册与网络可达。作为代码审计的测试工具，
它应当脱离 TAA：明文归档直接进 mock 后端，在本进程内按 TAA 相同的审计设计流程
（Tier 1 静态扫描 → 二进制通道 → Tier 2 AI 语义判定 → 结论汇总）执行，结论写入同一套
任务记录。同时「审计任务」右侧的「本次审计」信息卡要换成纵向流程图，随执行实时高亮
当前步骤。

用户已确认：

1. **AI 判定**：能连上已配置的 TEE-LLM 网关就参与；未配置或不可达时该步骤标记「跳过」，
   仍产出静态 + 二进制结论（不采用 TAA 的 fail-closed）。
2. **下发模式**：完全改为本地审计，移除工作台到真实 TAA 的下发路径；其余 mock 功能
   （反向代理、真实回调接收）不变。

## 现状关键事实

- 提交入口 `internal/server.go:169`；读接口 `server.go:159-165`。
- `internal/audit_submit.go` 当前链路：实例解析 → multipart → 加密方式 → 公钥 →
  `storeUploadedPayload` → `proxyJSONToTAA`。
- `internal/audit_jobs.go`：按 dockerId 分桶；`begin` 写 pending，`record` 解析
  `{conclusion,file_reports,duration_ms}` 并原地替换 pending；`overview` 只统计 done。
  已发布 `*auditJob` 会被读者在锁外读取，状态变更必须复制结构体再替换槽位
  （`audit_jobs.go:368-375`）。`now` 是测试时钟，每次调用前进一分钟，`record` 只读一次。
- TAA 审计入口 `internal/codeaudit/verifier.go:344`：静态扫描（含行数）→ 二进制通道 →
  合并 → finding 级 LLM → file 级 LLM → `AssembleAuditReport`。
- TAA 判定映射 `internal/controller/import_processing.go:792-858`：code 0/1 来自
  `conclusion.passed`，code 2 为审计失败；上报 JSON 由 `codeaudit_projection.go:26-59`
  投影为 `{conclusion,file_reports,duration_ms}`。
- 解包 `internal/resource/archive.go`：`IsArchiveFile`（魔数）、`ExtractArchiveToDir`
  （先解到临时目录再原子 rename，带 zip-slip 防护）。
- `internal/codeaudit` 无 cgo，platform-mock 与 TAA 同属 module `taa`，可直接 import；
  mock 静态构建（`CGO_ENABLED=0`）不受影响。
- 前端：`internal/static/index.html:1040-1174` 为审计任务视图；`audit-console.js`
  `renderFlow`（1371-1399）驱动横向三段条，提交/轮询在 1455-1671。

## 后端设计

### 1. `internal/codeaudit` 增加空操作安全的阶段回调

`verifier.go`：

```go
// Audit phase names reported through AuditConfig.OnStage.
const (
    StageStatic   = "static"
    StageBinary   = "binary"
    StageAI       = "ai"
    StageConclude = "conclude"
)

type AuditConfig struct {
    LLM    LLMConfig
    Binary BinaryConfig
    // OnStage, when non-nil, is called at the boundary of each phase. It is
    // observational only: a nil hook changes nothing, and the hook cannot
    // alter the audit's outcome. It runs synchronously and must not block.
    OnStage func(stage string)
}

func (c AuditConfig) stage(name string) { if c.OnStage != nil { c.OnStage(name) } }
```

调用点（`GenerateAuditReport`）：
- 静态扫描前 `cfg.stage(StageStatic)`（dir/engine 校验之后）；
- 静态扫描返回后、`runBinaryChannel` 前 `StageBinary`；
- 合并之后、LLM 判定块之前 `StageAI`（无论 LLM 是否实际启用，由调用方决定是否标 skipped）；
- `AssembleAuditReport` 前 `StageConclude`。

新增 `internal/codeaudit/verifier_stage_test.go`：断言顺序为
`static,binary,ai,conclude`；nil 回调不 panic；有无回调两次运行的报告 JSON 完全一致；
LLM 关闭时序列仍完整。

### 2. `internal/audit_jobs.go` 增加阶段状态

```go
const localAuditInstanceKey = "local"

var localAuditStepKeys = []string{"receive", "extract", "static", "binary", "ai", "conclude"}

type auditJobSummary struct {
    ...
    Stage  string            `json:"stage,omitempty"`  // current step key, or "done"
    Stages map[string]string `json:"stages,omitempty"` // step -> pending|active|done|skipped|error
}
```

- `begin`：初始化 `Stages`（六步 `pending`，`receive=active`），`Stage="receive"`。
- 新增 `setStage(dockerID, requestID, step, state string)`：只更新仍为 pending 的行；
  复制结构体、克隆 map 后替换槽位；不调用 `now()`。
- 新增 `failAt(dockerID, requestID, step, reason string)`：pending 行 → `Status=failed`、
  `Error=reason`、`Stages[step]="error"`、`Stage=step`；保留先前步骤。
- `record`：替换同 requestId 的本地 pending 行时继承其 `Stages`，置
  `Stages["conclude"]="done"`、`Stage="done"`；真实 `reportAudit` 行没有 `Stages`
  （omitempty），JSON 形状不变。
- 服务端算好每步状态，前端只负责着色；不再单独发 `aiSkipped`。

### 3. 新增本地执行器 `internal/audit_local.go`

```go
type localAuditRunner struct {
    jobs    *auditJobStore
    engine  codeaudit.StaticEngine
    binary  codeaudit.BinaryConfig
    llm     *llmConsole   // endpoint/settings/model resolver
    workRoot string       // cfg.UploadDir

    mu   sync.Mutex
    busy bool             // one local audit at a time
    baseCtx context.Context
    cancel  context.CancelFunc

    // auditFn is a test seam; production points at codeaudit.GenerateAuditReport.
    auditFn func(context.Context, string, codeaudit.AuditConfig, codeaudit.LLMClient) (*codeaudit.AuditReport, error)
}
```

- `newLocalAuditRunner(jobs, cfg, console)`：
  - engine：`codeaudit.DefaultEngine()`（内置 regex）；单点构造，以后加 semgrep 只改这里。
  - binary：`codeaudit.DefaultBinaryConfig()`（默认启用）。
  - LLM：`endpoint := console.teeTLSEndpoint()`；为空则 `LLMConfig{Enabled:false}`、
    `client=nil`。否则
    `LLMConfig{Enabled:true, AttestationEnabled:true, Endpoint:"https://"+endpoint,
    Model: console.state.get().Model 或 codeaudit.DefaultLLMConfig().Model,
    FailClosed:false, Timeout:0, CircuitBreakerThreshold:3, CooldownSec:30,
    TEETLS:&teetls.Config{Mode: settings.Mode, SkipChainVerify: settings.SkipChainVerify}}`，
    再 `codeaudit.NewInferenceClient`。与 console 的 generate 路径同一套 TLS 姿态
    （permissive、跳过链验证）。`FailClosed:false` 就是用户选择的「连不上跳过」开关。
- `acquire()/release()`：互斥的忙闸门，返回 false 时提交端 409；`release` 在 goroutine
  defer 中执行（含 panic recover）。
- `start(workDir, archivePath, originalName, requestID, taskID)`：
  1. 标记 `receive=done`、`extract=active`；
     `resource.ExtractArchiveToDir(filepath.Join(workDir,"src"), archivePath)`，
     失败 → `failAt("extract", …)` 并结束。
  2. `setStage(static/binary/ai/conclude)`：由 `OnStage` 回调映射为
     「前一步 done、当前步 active」；`conclude` 回调后完成。
  3. 调 `auditFn(ctx, 解压目录, AuditConfig{LLM, Binary, OnStage}, client)`。
  4. 失败 → `failAt(当前步, "审计失败: "+err)`，**不再调用 record**（避免把 failed
     行覆盖成 done）。
  5. 成功 → 复刻投影 JSON：
     `{"conclusion":audit.Conclusion,"file_reports":audit.FileReports,
     "duration_ms":audit.ScanMetadata.ScanDurationMs}`；若
     `!LLM.Enabled || client==nil || audit.ScanMetadata.LLMDegraded || len(audit.FileReports)==0`
     则 `setStage("ai","skipped")`，否则 `setStage("ai","done")`；然后
     `record(local, requestID, taskID, code, raw)`，code 0/1 来自 `conclusion.Passed`。
  6. `defer os.RemoveAll(workDir)`，成功失败都清理。

### 4. 重写 `internal/audit_submit.go`（handler）

- 删除：`encryptMode`、公钥、`storeUploadedPayload`/`removeStoredUpload`（helper 本身
  保留，`/api/upload` 仍用）、`buildAuditImportBody`、`auditImportRejection`、
  `writeInstanceErrorJSON`、`validateRuntimeConfig`、`auditSubmitDefaultRuntimeConfig`、
  `auditSubmitTimeout`、`auditPayloadIsArchive`（改用 `resource.IsArchiveFile`）。
- 新流程：
  1. 仅 POST；`ParseMultipartForm(auditSubmitMemoryLimit)`（32 MiB 只是内存阈值，不是上限）。
  2. `FormFile("file")`；空文件 400。
  3. `runner.acquire()` 失败 → **409** `{"ok":false,"error":"已有审计任务正在执行，请等待其完成后再提交"}`。
  4. `os.MkdirTemp(cfg.UploadDir, "local-audit-*")`，把 part 复制为 `package`。
  5. `resource.IsArchiveFile(path)` 失败 → 清理 + release + **400**
     `"待审计文件必须是 zip、gzip 或 tar 归档"`。
  6. 生成 requestId/taskId（保留自动生成）；`jobs.begin(local, …)`。
  7. 立即返回
     `200 {ok:true,jobId,requestId,taskId,at,filename,originalName,size,stage:"receive",
     stages:{...},message:"已接收，正在控制台进程内执行审计"}`。
  8. `runner.start(...)` 启动异步审计。
- `server.go`：构造 `localAudits := newLocalAuditRunner(auditJobs, cfg, console)`，
  路由改为 `auditSubmitHandler(localAudits)`；服务关闭时调用 `runner.stop()` 取消
  在途审计。

### 5. `internal/audit_console.go` 读侧固定本地键

- `instance(requested)` 忽略入参，返回
  `(localAuditInstanceKey, auditConsoleInstance{DockerID:"local", Kind:"local",
  Address:"进程内", Online:true})`。
- `handleOverview/handleJobs/handleJobDetail` 都读写 `local` 桶；无实例注册也能用；
  `?dockerId=` 被忽略（前端继续带也无害）。
- 真实 `reportAudit` 回调仍按 dockerId 写各自桶；本工作台只展示本地任务（README 说明）。

## 前端设计

### 1. 右侧「本次审计」→ 纵向流程图（`index.html` 1147-1173）

```html
<aside class="audit-card audit-launch-side">
  <div class="audit-card-head"><div>
    <h3 class="audit-card-title">本次审计</h3>
    <p class="audit-card-desc">本地执行 · 不连接 TAA 实例</p>
  </div></div>
  <ol id="auditStepper" class="audit-stepper" aria-label="审计流程">
    <li class="audit-stepper-step" data-step="receive" data-state="idle">
      <span class="audit-stepper-dot"></span>
      <span class="audit-stepper-body">
        <span class="audit-stepper-title">接收明文包</span>
        <span class="audit-stepper-desc">校验归档并落盘</span>
      </span></li>
    <!-- extract / static / binary / ai / conclude 同构 -->
  </ol>
  <dl class="audit-meta-list">
    <div class="audit-meta-row"><dt>任务标识</dt>
      <dd><span id="auditTaskIdPreview" class="audit-meta-mono">提交时自动生成</span></dd></div>
    <div class="audit-meta-row"><dt>文件</dt><dd id="auditRunFile">—</dd></div>
  </dl>
  <p class="audit-meta-note">明文归档在本机解压，审计结束后临时目录自动删除。</p>
</aside>
```

六步：`receive`、`extract`、`static`、`binary`、`ai`、`conclude`。
**移除横向三段条** `#auditFlowSteps`（1121-1144）：纵向流程图已覆盖同一状态且更细，
两个指示器会互相矛盾。上传进度条保留。

### 2. JS（`audit-console.js`）

- 删除 `FLOW_STEPS`/`flowStepOf`/`renderFlow` 及调用；新增
  `STEP_KEYS = ['receive','extract','static','binary','ai','conclude']` 与
  `renderStepper(job)`：直接使用后端 `job.stages`（缺省时按 `job.stage` 推导），
  为每步设置 `data-state = pending|active|done|skipped|error`。
- 提交：移除 `state.dockerId` 前置检查（1543-1546）；FormData 只带 `file/requestId/
  taskId`；`optimisticPendingJob` 的 `dockerId='local'`、`stages` 取响应值；
  成功提示「已接收，本地审计执行中」；删除 `friendlySubmitError`（409/400 文案直接展示）。
- 轮询：`SUBMIT_POLL_MS` 3000 → 1000，每 tick 用当前 job 调 `renderStepper`；
  `SUBMIT_POLL_WINDOW_MS` 5 min → 15 min（LLM 阶段可能很长）。
- 点击任务行/详情也 `renderStepper(job)`，历史任务显示最终各步状态。
- 文案（不再出现「加密」「下发」「TAA 机密域」）：`index.html` 概览结论空态（1007）、
  视图描述（1043）、文件类型默认值（1094）、提交提示（1108）、任务列表空态（1209）；
  `audit-console.js` `setChosenFile` 默认值（1427）、已选文件提示（1437）、提交中/完成
  提示（1557/1583/1591/1596）、失败任务提示（1260）、概览警示（1058-1059）。
  概览实例改为「本地审计引擎」；`auditTaskIdPreview` 继续使用同一 id。

### 3. CSS（`audit-console.css`）

新增 `.audit-stepper` 纵排：`li` 绝对定位左侧圆点 + `::before` 竖向连接线（最后一项
隐藏），右侧标题/描述。状态：pending 灰、active 橙 + 呼吸动画、done 绿、skipped 灰
虚线圆点、error 红。窄屏保持纵排、缩小间距。不复用/改动现有 `.audit-flow*`。

## README 更新

- 「审计任务」条目：明文归档、本机解压、同一 TAA 审计流程、AI 可跳过、一次一个任务
  （409）、临时目录自动清理。
- 端点段落：`POST /api/audit/console/submit` multipart 仅 `file` + 可选
  `requestId`/`taskId`；删除 `encryptMode`/`runtimeConfig`。
- 「审计概览」来源改为本地任务；说明真实 `reportAudit` 回调仍按 dockerId 记录、
  不出现在本工作台。
- 目录树补 `audit_local.go`。

## 测试与验证

Go：

- `internal/codeaudit/verifier_stage_test.go`：阶段顺序、nil 安全、报告 JSON 不变。
- `internal/audit_local_test.go`：
  - 提交 `auditTestZip` 后轮询到 `status=done`；断言 `local` 桶、code 0/1、
    `raw` 只含 `conclusion/file_reports/duration_ms`、临时目录已删除、
    响应不含 url/encrypted/dataKeyCipher。
  - 阶段状态：`receive/extract/static/conclude=done`；LLM 未配置时 `ai=skipped`；
    解压失败时 `extract=error` 且 `status=failed`。
  - 409：用 `auditFn` 阻塞第一次审计，第二次提交返回 409 且不新增任务。
  - 非归档 400、不产生任务、临时目录已清理；无实例注册时读接口 200 且任务可见。
- `internal/audit_jobs` 既有测试文件补：`setStage` 只改 pending（复制槽位）、
  `failAt` 保留先前步骤、`record` 继承 `Stages` 并置 conclude done。
- 调整 `audit_submit_test.go`（删除下发/加密/公钥/sealed stub 用例）与
  `audit_console_test.go`（`newAuditConsole(jobs)` 新签名、固定 `local` 实例块）。

命令（仓库根）：

```bash
go test ./tools/platform-mock/...
go test ./internal/codeaudit/ -run 'Stage' -count=1
go build -o bin/platform-mock ./tools/platform-mock/cmd/platform-mock
gofmt -w tools/platform-mock internal/codeaudit
```

手工 UI（headless Chrome，脚本放仓库外 `/tmp/pmconsole`）：启动 mock → 登录 → 上传含
`os.system`/`eval` 的 zip → 截图确认六步依次高亮、AI 未配置时显示「跳过」、结论落库；
再验证第二次并发提交 409、`.txt` 400、400px 与暗色主题。

## 风险与实施顺序

1. `codeaudit.OnStage` + 测试（对生产审计零影响）。
2. 任务存储阶段字段 + 本地执行器 + 单测。
3. handler/路由/console 读侧 + 单测。
4. 前端（markup/JS/CSS）+ README + 手动验证。
5. 风险：`record` 与 `failAt` 的锁内先后（失败不再调 `record`）；大包占满 `uploadDir`；
   TEE-LLM 冷加载长时间停留在 `ai` 步（`Timeout:0` 与 TAA 取舍一致）；真实回调不再
   出现在工作台（已确认的产品变化，README 写明）。
6. 提交拆分：`feat(codeaudit): observe audit phases via an optional stage hook`、
   `feat(platform-mock): run audit workbench audits in-process`、
   `feat(platform-mock): show live audit stages in a vertical rail`。
