# 合并代码审计：模型代码 + 当前依赖集，一次审计、一次上报

## Context

**为什么改。** 今天 TAA 有两条彼此独立的审计链路：

- `importModel` 解压后，后台异步审计 `Security.ModelDir`，以 `scope=""` 上报 `reportAudit`
- `importDeps` 安装完成后，在流水线内同步审计 `<depsDir>/<sm3>`，以 `scope="deps"` 上报 `reportAudit`

两条链路各扫各的目录、各出一份报告。于是「模型代码 + 它实际加载的依赖」作为一个整体从未被审计过：跨二者的数据流（模型代码 import 了依赖里的某个模块，污点从依赖流入模型代码）不在任何一次扫描的视野里。用户要求：**无论下发模型还是下发依赖，都重新触发一次覆盖「完整模型代码 + 所有依赖」的合并审计，然后重新上报一次 `reportAudit`。**

**要达成的结果。** 一次静态扫描 + 一次 LLM 审查覆盖两个根；一份 `AuditReport`；一次 `/v1/taa/reportAudit` 回调。

**与既有 spec 的关系。** `.claude/specs/2026-10-08-model-dependency-delivery-design.md:61-62` 明确写着「把依赖放在 `ModelDir` **同级**的内容寻址目录，a/b/c/d 四者同时消失：**无需改审计范围**」。本次改动**推翻该前提**，因此必须另开一份 spec（见 Task 0），不能只改 plan。

---

## 语义契约（本次改动后的事实，后续所有实现与文档都以它为准）

### 1. 审计范围 = 触发方交付的代码 ∪ 当前生效的另一侧

| 触发 | 审计根（按序） |
|---|---|
| `importModel` | `Security.ModelDir`（本次刚解压的） ＋ 当前绑定依赖目录（若已绑定且目录存在） |
| `importDeps` | `<depsDir>/<本次 sm3>`（本次刚安装的候选目录） ＋ `Security.ModelDir`（若模型已导入且目录存在） |

- **「所有依赖」＝仅当前生效的那一套**，即 `filepath.Join(GetDepsDir(), DepsHash)`。磁盘上历史遗留的 `<depsDir>/<旧 sm3>` 目录（`deps_import.go:63-64` 承认其永久存在、无 GC）**不在范围内**。
- 一个根只在「生效」时才进入审计：模型根要求 `ModelImported`，依赖根要求目录 `os.Stat` 成功。这是为了保住「先下发依赖、后下发模型」这条既有可用路径——把一个不存在的目录交给 `GenerateAuditReport` 会让 `filepath.Walk` 报错，进而 `code=2`，在 fail-closed 下等于把合法的依赖下发拒掉。
- 模型根恒排在前面（`AuditTarget.Directory` 取它），依赖根在后。

### 2. `scope` 的取值不变，语义变了

`""` / `"deps"` 两个线上取值**一个都不动**（platform-mock 的校验 `handlers_taa.go:542-544`、`docs/api-design.md:458` 都不用改），但它现在的含义从「审计了什么」变成「**是谁触发的**」。两条路径审计的范围已经完全相同，`scope` 只剩溯源作用。

### 3. `code` = 合并审计的整体结论

`0` 通过 / `1` 未通过 / `2` 执行失败或按 fail-closed 判定 LLM 不可用。`code` 描述的是**这一次合并审计**，不是触发方那一侧的局部结论。因此会出现 `code=1` 而 TAA 什么都没清除、任务仍然成功的情形——这一情形由新增的**分根结论**（见 §4）消歧。

### 4. 报告新增分根结论

`AuditReport.Target` 增加 `directories []string`（本次实际覆盖了哪几个根），并新增一个按根的分项列表，每项含 `directory` / `files_scanned` / `findings_count` / `passed`。这样 `code=1` 的报文里，平台能直接看出**是哪个根出的问题**，不必靠 `file_reports[].file_path` 的前缀自行推断。

这是**新增字段，不改既有字段的含义**：`report` 字段在 `reportAudit` 里是不透明字符串，在训练报告里是 `codeaudit` 对象，两者都只增键。既有消费者（platform-mock 原样落盘并回显）不受影响。

### 5. 回滚：只回滚触发方那一侧，且只在触发方被牵连时

合并审计跑完后，**唯一会发生的清除是触发方自己的那一个根**：

- 触发方 = 模型 → `cleanDirContents(Security.ModelDir)`（保持既有做法：清空内容、保留目录）
- 触发方 = 依赖 → `rollbackDepsImport(candidateDir)`（删目录并在必要时清绑定）

**分工（2026-10-09 踩过一次，务必照办）：执行器不做任何物理清除**，它只返回 `TriggerClean`；
清除由**各自的调用方**执行，判据就是 `!TriggerClean`。两条链路原本都自己删——
模型侧在三条路径上各调一次 `cleanDirContents`，依赖侧在 `runDepsAudit` 里三条路径各调一次
`os.RemoveAll`——这些都要**收窄为调用方的一处 `!TriggerClean` 闸门**，而**不是删除**。

Task 4 的首版把模型侧的清除当「已由执行器覆盖」直接删掉，结果被拒的模型代码留在磁盘上、
两条既有安全测试（`TestAuditFailureCleanDirAndAbort`、`TestPhase1ModelAuditFailureAbortsTraining`）
反转成断言「文件仍在」——那是一个 fail-open，且**变异测试替它背了书**：新测试断言的是错的契约，
于是「把清除加回来」这个变异看起来像是被正确杀掉了。写测试前先确认契约来自 spec §3.5，而不是来自上一句 brief。

判据：`code == 2`（整体没跑成，无从区分哪一侧有问题），**或** 报告里存在归属于触发方那个根的 finding，**或** 扫描被截断（见 Task 3 的 `TriggerClean` 算法）。若 findings 全在另一侧且扫描完整：报告与 `code` 如实反映失败，但**不删任何东西、本次导入判成功**。

### 6. 幂等短路取消，审计标记机制删除

- 删掉 `deps_import.go:120-128` 的 `auditMarkerExists` 短路：每次下发依赖都重新解包、重新安装、重新审计。
- 删掉 `.taa_audit_ok` 整套机制（`depsAuditMarker` / `depsAuditMarkerVersion` / `auditMarkerExists` / `writeAuditMarker`，`deps_import.go:207-240`）。理由：审计结论现在取决于「与哪份模型代码一起扫」，一个只记录了依赖侧 hash 的标记已经**不成立**（`deps_import.go:219-224` 的注释自己就承认版本号是唯一的失效手柄，而它与模型无关）；短路取消后 `auditMarkerExists` 没有调用方，`writeAuditMarker` 写的文件没人读。磁盘上已存在的 `.taa_audit_ok` 文件**不做迁移**——无人读，无害。
- 模型侧本来就没有标记，每次都重审，不变。

### 7. 资源闸门不动

`MaxFindings = 200`（`scanner.go:23`）与 `DefaultSemgrepTimeout = 5min`（`semgrep_engine.go:24`）保持原值。**已知代价**：合并后输入约为原先的两倍，越限截断的概率上升，而截断会让 `Report.ProvesCleanScan()` 返回 false（`rules.go:126`）→ `AssembleAuditReport` 把 `scanPassed=false`（`audit.go:354`）→ 在 fail-closed 下**整份报告阻断**。这是用户明确接受的取舍，实现时不得顺手调大。

---

## 不变量与已接受的代价（实现时不要"顺手修好"）

1. **非触发方的 findings 不产生任何动作**，包括模型侧的问题不会阻止训练启动。若一次依赖下发触发的合并审计发现模型代码有问题，模型照旧留在原地、照旧可训练，改动只是把结论写进报告并上报 `code=1`。这是「不跨侧清除」的直接推论，属于本次改动的既定语义，不是缺陷。若日后要收紧，应当另开一个显式闸门（例如「最近一次合并审计未通过则拒绝 startTraining」），不在本次范围。
2. **重复下发同一依赖集会被重复审计。** 结合记忆 `teellm-audit-blocks-benign-code-nondeterministically`（未改动的良性代码约每 10 条误判 1 条 MALICIOUS 并 fail-closed 阻断），取消幂等意味着**同一份依赖重投有可观测概率被自己拒掉**。这是「每次都重审」的既定代价。
3. **合并扫描不改变 fail-closed 姿态**：仍然 fail-closed，`ScanEnabled=false` 仍然整段跳过审计（`deps_import.go:330-333`、`import_processing.go:613-616`），且跳过时仍然不写任何标记。

---

## Task 0：新 spec（`.claude/specs/`）

**Files:** Create `.claude/specs/2026-10-09-combined-code-audit-design.md`

内容即上文「Context + 语义契约 + 不变量」，另需显式登记两件事：

1. 对 `.claude/specs/2026-10-08-model-dependency-delivery-design.md:61-62` 的推翻，并说明 §2.4（`codeaudit` 无路径排除能力）为什么在本次方案下不再是约束（本次不往 `ModelDir` 里塞依赖，仍然同级，只是**审计时同时看两个根**）。
2. `scope` 语义漂移的订正（该 spec `:292` 写的是 `model` | `deps`，实现与文档实际是 `""` | `deps`），一并记录。

`.claude/` 在 `.gitignore` 里，提交需 `git add -f`。

---

## Task 1：`internal/codeaudit` 支持多根扫描

**Files:** Modify `internal/codeaudit/engine.go`、`scanner.go`、`semgrep_engine.go`、`verifier.go`、`audit.go`

**要点（具体签名以 Plan agent 的结论为准，下列为已确定的部分）：**

- `StaticEngine`（`engine.go:27-38`）**新增**一个方法而非改动既有三个方法的签名：
  `ScanDirectoriesWithLines(dirs []string) (*Report, map[string]int, error)`
  既有的 `ScanDirectory` / `ScanDirectoryWithLines` 保留并委托给新方法（单元素切片）。这样 `internal/coordinator/flow_model.go:87` 与 `verifier.go:320` 的既有调用点不动。`StaticEngine` 的实现者只有 `regexEngine` 与 `semgrepEngine`；测试替身 `namedEngine`（`internal/controller/audit_model_import_test.go:475-480`）内嵌真引擎，自动继承新方法。
- `Scanner` 新增 `ScanDirectoriesWithLines(dirs []string)`：对每个根各 walk 一次，findings 与 lineCounts 取并集。`report_fields_test.go` 的 `truncatingScanner` 是 `*Scanner`，不受接口变化影响。
- `semgrepEngine`：每个根各 walk 一次，把 target 拼进**同一个**切片，仍只发起**一次** semgrep 调用（`semgrepArgs` 本来就是 `append(args, targets...)`，`semgrep_engine.go:349`）。完成度校验（`semgrep_engine.go:385-398`）按 `cleanAbs` 集合比对，对任意 target 并集成立——**实现前先写一个测试证明这一点**，不要只靠推断。
- `verifier.go` 新增 `GenerateAuditReportForDirs(ctx, dirs []string, engine, cfg, client)`；`GenerateAuditReport(ctx, dir, ...)` 变成它的单元素封装。`dir == ""` / `engine == nil` 两个前置检查保持在封装层。

**验收：** `go test ./internal/codeaudit/... -count=1` 全绿；新增用例覆盖「两个根各有一个命中文件，一次调用同时报出」与「其中一个根为空目录」。

---

## Task 2：多根元数据与 finding 归属

**Files:** Modify `internal/codeaudit/audit.go`（+ 若 CPG 需要，`cpg_analysis.go`）

- `AuditTarget`（`audit.go:28`）新增 `Directories []string \`json:"directories,omitempty"\``；`Directory` 保持 = 主根（模型根），不改含义、不删字段。
- 新增按根分项结构与生成函数，挂在 `AuditReport` 上（§4）。`AssembleAuditReport` 增加一个接收根列表的参数——**注意**它在 `audit.go:326` 是导出函数，改签名要同步 `verifier.go:372` 与 `audit_test.go`。
- 新增归属helper：`ReportHasFindingsUnder(report *AuditReport, root string) bool`。实现必须处理三件事并在测试里逐个钉住：相对根 vs 绝对根（统一 `filepath.Abs` + `filepath.Clean`）、两个根互为前缀、以及一个文件不属于任何根。`filepath.Rel` 的 `..` 判定优于 `strings.HasPrefix`（后者会把 `/a/modelX` 误判为 `/a/model` 下的文件）。
- **CPG 符号解析（本次改动里最不确定的一块）：** `enrichFindingsWithCPG(dir, targets, findings)`（`semgrep_engine.go:232`）与 `NewSymbolResolver(dir)`（`cpg_analysis.go:169-172`）目前都以单一 root 建符号索引。

  依赖根必须以「**模块搜索路径**」的身份进入解析，而不是被当成第二个独立工程——因为模型代码 `import numpy` 时，`numpy` 实际来自 `<depsDir>/<sm3>/numpy`，正是训练运行时通过 `PYTHONPATH` 注入的那一条（`deps_env.go:19-36`）。**首选**：给 `NewSymbolResolver` 增加一个可选的附加搜索根参数，让模型根作主根、依赖根作搜索路径。

  **如果**该改动无法在 `cpg/resolver.go` 里做到最小化（**该文件同时被本检出里另一个参与者的未合并 `feat(cpg)` 分支改动**），则退化为：每个根各建一个 resolver、各自 enrich、findings 取并集，`cpg/resolver.go` **一行不动**。此时保真度损失是**跨根数据流（模型代码 → 依赖模块）检测不到**——而那恰恰是选择「真·单次审计」而非「两次扫描」的理由，因此退化方案**必须**在 Task 0 的 spec 里显式登记为已知盲区，不得静默降级。

  实现者必须先读 `cpg/resolver.go` 再定，选定后把结论与理由写进 spec；**不允许在没有读过该文件的情况下按首选方案动手**。

---

## Task 1/2 的审查后发现（2026-10-09，两阶段审查的第一阶段）

对 `401ab6c` 的 spec 合规审查在三个文件里**未发现功能性缺陷**，两条承重语义
（`ScanProvedClean` 不折叠 `Passed`、`RootReport.Passed` 的三元式）经独立核实无误。
但它报了两条 low，都已由我复核为真：

1. **缺一个「根存在但为空」的用例**（对得上 Task 1 的验收条款，属于漏做）。`multiroot_test.go`
   的每个用例里每个根都至少写了一个文件。行为本身正确——空根 `FilesScanned=0`，
   `passed` 由审计总判决定（`ScanProvedClean && FindingsCount == 0` 对空根恒成立）——
   但没有测试钉住它。**要补**，与 Task 7 同段跑测试。
2. **重复根会在报告里产生重复的 `RootReport`**（低危，当前不可达）。`withRoots`
   （`scanner.go:218-226`）对 `len(dirs) > 1` 原样写入不去重，`reportRoots`（`audit.go:491`）
   原样返回，`buildRootReports` 逐项产出，于是 `["/m","/m"]` 得到两条同根分项、各自计数相同；
   而 walk 侧（`scanner.go:321-323` 的 `p == root` 分支）已把第二次跳过。生产调用方传的是
   `config.validateDepsDirPlacement` 强制互为兄弟的 `ModelDir` 与 `<depsDir>/<sm3>`，
   到不了这里。**决定：不修**（无调用方需要，spec 未要求，符合本仓库「不顺手修好」的纪律），
   仅登记在此，供日后 `GenerateAuditReportForDirs` 出现新调用方时参考。若届时确实要修，
   落点应是 `withRoots`——它是 `Report.Directories` 的唯一写入点。

另有一条**不是缺陷的对称性差异**，一并记下免得被当成 bug 重查：regex 引擎的 cap 用
`filepath.SkipAll` **提前停 walk**（`scanner.go:358-362`），semgrep 引擎则在**走完全部根之后**
才对 findings 切片（`semgrep_engine.go:253-257`）——semgrep 已经把结果跑出来了，提前停没有意义。
两者都正确置 `Truncated`，都 fail-closed，行为一致。

---

## Task 3：controller 侧的合并审计执行器

**Files:** Create `internal/controller/combined_audit.go`；Modify `internal/controller/deps_audit.go`

一个文件、两个函数，两条链路共用：

```go
// combinedAuditRoots returns the roots a combined audit covers for the given trigger:
// the code this request delivered, plus the other side as currently in effect. A root
// enters only when it is in effect -- the model root needs ModelImported, the
// dependency root needs its directory to exist -- because handing a missing directory
// to the audit fails the walk and, under fail-closed, rejects a legitimate delivery.
func (s *TAAState) combinedAuditRoots(triggerSide, triggerDir string) []string

// combinedAuditResult is the outcome of one combined audit.
type combinedAuditResult struct {
    Passed       bool // the audit as a whole passed
    TriggerClean bool // no finding and no execution failure attributable to the triggering root
    Executed     bool // false when the ScanEnabled=false short-circuit skipped the audit
    Report       *codeaudit.AuditReport
    Summary      string
}

// runCombinedAudit audits every root combinedAuditRoots returns, reports the result
// exactly once under the scope for the triggering side, and reports back which side
// came out clean. It owns the audit-state bookkeeping (ActiveAuditTaskID /
// ActiveAuditRequestID / CurrentAuditOp / AuditRunning / clearAuditState) so both
// callers behave identically.
func (s *TAAState) runCombinedAudit(req codeAuditRequest, triggerSide, triggerDir string) combinedAuditResult
```

`codeAuditRequest{RequestID, TaskID}` 是**新类型**（仓库里原先没有），定义在 `combined_audit.go`：
两条流水线的请求结构体在这两个字段上拼法相同，执行器用自有类型取参，才不会因为任一条
流水线的请求结构体长出新字段而被牵连改动。

内部必须与既有的两处逐条对齐，**不得遗漏**：`ScanEnabled=false` 短路返回 `Executed=false`；fail-closed 下先 `isLLMServiceAvailable` 探测，不可用即 `code=2`；`GenerateAuditReportForDirs` 出错即 `code=2`；成功则 `code` 由 `audit.Conclusion.Passed` 决定；上报走 `reportAuditScopedAsync`（`import_processing.go:728`），`report` 用 `auditReportJSON`（`codeaudit_projection.go:49`）。

### `TriggerClean` 的算法（**本节原先写错，2026-10-09 订正**）

**原先写的是**「`code==2` → false；否则 `!ReportHasFindingsUnder(report, triggerDir)`」——
**这是一个 fail-open，已被实现者依据 spec §3.5 挡下**。它漏掉的情形是：一次**截断**的扫描，
其保留下来的 findings 恰好全在另一侧。此时 `!ReportHasFindingsUnder` 为 true → 触发方被判干净
→ 一次没跑完的扫描放行了本次交付，而今天截断是**两侧都清**的。spec §3.5 与 §8.6 早就写明了
正确的判据，是计划正文这一行抄漏了 `ScanProvedClean`。**Task 4/5 不得回退到这个版本。**

正确判据（`combined_audit.go` 已实现，与 spec §3.5 逐字一致）：

```
implicated = !report.Conclusion.Passed &&
             ( !report.ScanMetadata.ScanProvedClean
               || codeaudit.ReportHasFindingsUnder(report, triggerDir) )
TriggerClean = !implicated
```

`ScanEnabled=false`（没跑）与 `code==2`（跑砸了）都表现为「没有报告」，但前者**不得清除**、
后者**必须清除**——单个布尔量区分不了，由 `Executed` 拆开：

| 情形 | `Executed` | `TriggerClean` | 调用方 |
| :--- | :--- | :--- | :--- |
| `ScanEnabled=false` | false | **true** | 不清除、不发出（跳过不等于通过，但没跑过的审计不牵连任何根） |
| LLM 不可用 / 执行出错 | true | **false** | 清除触发方、`code=2`、`report=""` |
| 审计通过 | true | true | 不清除 |
| 触发方脏，或扫描被截断 | true | **false** | 清除触发方 |
| 只有另一侧脏 | true | true | **不清除**，导入判成功，`code=1` |

调用方唯一可据以行动的字段是 `TriggerClean`（`Executed` 只用来区分「跳过」与「跑砸了」，
两者的 `TriggerClean` 已经不同）。

---

## Task 4：改接模型链路

**Files:** Modify `internal/controller/import_processing.go`（`auditAndReportModelImport` :611、`startModelAuditAsync` :589）

- `auditAndReportModelImport` 改为调用 `runCombinedAudit(codeAuditRequest{...}, codeAuditTriggerModel, s.Security.ModelDir)`，返回 `result.TriggerClean`（即「模型侧是否干净」）。
- 三条 `cleanDirContents(s.Security.ModelDir)`（`:631`、`:641`、`:654`）收窄为**只在触发方被牵连时**执行。`code=2` 两条路径仍是触发方被牵连，照旧清。
- `s.setLastAudit(audit)` 从「每次审计完成都写」改为**写入合并审计的报告**（两条触发路径都写，理由见下）。
- `startModelAuditAsync` 的 `if !passed { clearImportedState; stopActiveTraining }` 现在按 `TriggerClean` 决策——findings 全在依赖侧时不再清模型、不再停训练。
- **`LastAudit` 语义变化（需在代码注释里写明）：** `route.go:155`、`deps_audit.go:15-18` **与 `import_processing.go:727-728`** 三处都断言「`LastAudit` 只装模型审计结论，依赖审计不得覆盖」或「空 scope = 模型代码审计，`deps` = 依赖包审计」。第三处是 2026-10-09 补查出来的（原计划漏点），原文为「An empty scope means the model code audit; "deps" means the dependency package audit」——改动后 scope 表示**触发源**而非审计对象，三处**全部为假**，必须一起改写。改动后合并审计**永远包含模型根**（只要模型生效），因此两条触发路径都写 `LastAudit` 才是正确的。这会改变训练报告里 `codeaudit` 一节的内容，需要一条测试钉住。

---

## Task 5：改接依赖链路，删除幂等短路与标记机制

**Files:** Modify `internal/controller/deps_import.go`、`internal/controller/deps_state.go`（如需）

- 删除 `deps_import.go:120-128` 的幂等短路。
- 删除 `deps_import.go:207-240`（两个常量 + `auditMarkerExists` + `writeAuditMarker`）与 `:186-199` 的写入分支。`processImportedDeps` 顶部的流水线注释（`:88-95`）与 `rollbackDepsImport` 的长注释（`:242-274`）里凡是提到 marker 的句子一并改写——**注释与代码不符在本仓库已被证明会误导后续判断**。
- `auditAndReportDeps`（`:329-335`）与 `runDepsAudit`（`deps_audit.go:39-79`）合并进 Task 3 的执行器；`deps_audit.go` 只剩它对三个盲区的说明（`:20-31`）与对「无测试钩子」的说明（`:33-38`），迁到新文件的函数注释上。
- 失败路径：依赖侧被牵连时 `rollbackDepsImport(depsDir)` 照旧（`:181`），只有在依赖侧被牵连时才走。
  **注意这与 `runDepsAudit` 现在做的事不同**：后者自己 `os.RemoveAll(depsDir)`，共三处
  （LLM 不可用、引擎出错、`!Passed`）。执行器一处都不删，所以这三处全部消失，
  由 `processImportedDeps` 的 `!result.TriggerClean` 单闸门经 `rollbackDepsImport` 接管——
  与 Task 4 在模型侧犯的错是同一个形状，别重犯。
  `rollbackDepsImport` 的长注释里「runDepsAudit removes the directory itself on every path that
  returns false ... it is kept deliberately」那一段随之**整段为假**，必须重写，不能留着。
- **顺手收掉 `route.go` 两处把审计槽称作「模型代码审计」的注释**（`:169` 的 `AuditRunning`
  字段注释、`:547` 的 `isAuditBusyLocked` 函数注释）。改动后两条触发路径都会置 `AuditRunning`
  且 `CurrentAuditOp = "auditing"`，所以它们说的是「审计」而不是「模型审计」。**只改注释**，
  不改 `:652` 那条**用户可见**的 409 文案——见下方「登记：刻意不改」。

---

## 登记：刻意不改（2026-10-09）

- **`route.go:652` 的 409 文案**「当前已有模型代码审计正在执行中」及其在
  `docs/api-design.md:1405` 的镜像。这条不精确是**改动前就有的**：`route.go:643-644`
  的注释自己就写着 model/deps 两条导入「drive the shared audit subsystem」，
  所以依赖触发的审计本来也会落到这条文案上。改一个**用户可见且已被平台/文档引用**的
  接口字符串有兼容成本，收益只是措辞，不值得。**登记于此，不修。**
- 同理 `docs/api-design.md:1454` 把 `auditing` 记作「模型代码审计进行中」。改动后**更接近**
  真实（合并审计总是包含模型根，只要模型生效），只有在「先下发依赖、模型尚未导入」时才不准。
  不改，但**不能**据此认为 §3.6 的 scope 语义与这条冲突——scope 说的是触发源，
  这条说的是占用中的审计槽叫什么，两者不矛盾。

---

## Task 6：文档

**6a 已完成**（`docs/api-design.md`，见 git log）。**本节余下的是 6b**，文件足迹：

**Files:** Modify `internal/platform/reporter.go`（仅注释）、`tools/platform-mock/internal/handlers_taa.go`（`scope` 拒绝文案）、`tools/platform-mock/internal/server_test.go`（钉文案的断言）

- §3.6：`scope` 字段说明表（`:462-465`）改写为「触发源」语义；`:446` 的触发时机改为「模型解压后 / 依赖安装完成后**都**触发一次覆盖模型代码与当前依赖集的合并审计」；`:469`「`scope="deps"` 时 report 格式与模型审计完全一致」改为「两条路径的 report 结构完全相同，仅 `scope` 不同」；`:524` 补一句 report 新增分根字段。
- §3.6 的 `code` 说明处补上 §3 的消歧：`code` 是合并审计的整体结论，与「本次导入是否成功」不是同一件事。
- §3.10 的「两条回调」说明（`:802`）**保持不变**——审计失败仍先发 `reportAudit(scope="deps")` 再发 `reportDeps(code=1)`。但需补一句：当 findings 全在模型侧时，两者的 code 会不一致（`reportAudit code=1` / `reportDeps code=0`），这是有意设计。
- §4.7：依赖下发的幂等性描述（若文档提及 `.taa_audit_ok` 或重复下发复用）改为「每次下发都重新解包、安装并审计」。

**platform-mock 无需功能性改动**（已逐字核过 `tools/platform-mock/internal/handlers_taa.go:483-563`）：`report` 被当作不透明字符串原样落盘（`state.RawBody` / `state.Report`），校验只有 `code ∈ {0,1,2}` 与 `scope ∈ {"", "deps"}`，两者取值集合都没变。唯一值得顺手改的是拒绝文案 `"scope 仅支持 deps(依赖包审计) 或空字符串(模型代码审计)"`（`:542-544`）——它把 scope 描述成「审计对象」，改动后应描述成「触发源」。改文案要连带更新 `TestReportAuditScopeHandling`（`server_test.go:2711`）里钉住该文案的断言。

**`internal/platform/reporter.go` 的两处 scope 定义（2026-10-09 补查，原计划漏点）**——这里是 scope 在**上线报文里唯一被定义**的地方，任务 6a 改 `docs/` 却漏了它，改完之后「代码注释说旧语义、文档说新语义」：

- `:240-242` `ReportAuditScoped` 的文档注释原文：「an extra scope field that **distinguishes the model audit from the dependency audit**. An empty scope means model audit and stays wire-compatible with older platform versions.」——两句都为假（不再区分审计对象；空 scope 现在表示**模型侧触发**，而非「模型审计」）。改写为「触发源」语义，并点明线上取值未变、只是含义变了。
- `:272` `ReportAudit` 的文档注释原文：「ReportAudit reports **the model code audit** result to the platform.」——改为「a combined audit triggered by a model delivery」。

**只改注释，不改行为**。两个函数的签名与 `scope` 取值一律不动：`TestReportAuditScopedCarriesScope` / `TestReportAuditOmitsScopeWhenUnscoped`（`reporter_test.go:36` / `:60`）钉的是线上取值，那两处**必须保持不动**，Task 7 的表格里已登记。改完后跑 `go test ./internal/platform/... -count=1` 与 `go test ./tools/platform-mock/internal/... -count=1` 一起（同属 Task 6b 的测试窗口）。

---

## Task 7：测试与验证

**需要改写或删除的既有测试（已点名）：**

| 测试 | 位置 | 处置 |
|---|---|---|
| `TestProcessImportedDepsSkipsWhenAlreadyAudited` | `deps_import_test.go:171` | 语义反转：改为断言同 hash 二次下发**仍然**重新安装并重新审计 |
| `TestProcessImportedDepsScanDisabledWritesNoMarker` | `:206` | 断言点从「不写 marker」改为「跳过审计且不产生任何清除」 |
| `TestAuditMarkerVersionGate` | `:526` | 删除（机制已删） |
| `TestProcessImportedDepsReauditsForeignMarkerDir` | `:555` | 删除（机制已删） |
| `TestRunDepsAuditRemovesDirOnFailure` / `LLMUnavailableFailsClosed` / `EngineErrorFailsClosed` | `:590` / `:708` / `:752` | 改驱动新的执行器；`scope=="deps"` 断言保留 |
| `TestProcessImportedDepsKeepsBindingWhenNewAuditFails` | `:361` | 保留，并在其基础上补一条「模型侧 findings 不影响依赖绑定」 |
| `TestAuditFailureCleanDirAndAbort` | `security_hardening_test.go:319` | 保留；确认失败仍清 `ModelDir` |
| `TestPhase1ModelAuditFailureAbortsTraining` | `import_flow_new_test.go:155` | 保留；补一条「findings 仅在依赖侧时训练不被中止」 |
| `audit_model_import_test.go` 的 `:229/:275/:325` | — | fixture 只写 `ModelDir`；补一个依赖目录的 fixture，覆盖合并路径 |
| `TestReportAuditScopedCarriesScope` / `TestReportAuditOmitsScopeWhenUnscoped` | `internal/platform/reporter_test.go:36` / `:60` | **不动**——线上取值没变 |

**新增测试（每条都要先在变异下证明有判别力）：**

1. `internal/codeaudit`：多根扫描一次报出两个根各自的命中；单根调用与既有行为逐字节一致。
   补一条 **「根存在但不含任何源文件」**——`FilesScanned == 0` 且 `passed` 随审计总判
   （Task 1 审查发现的漏做项，见上）。
2. `internal/codeaudit`：`ReportHasFindingsUnder` 的前缀陷阱用例（`/a/model` vs `/a/modelX`）。
3. `internal/controller`：**触发方干净、另一侧脏** → `reportAudit code=1` 且 `reportDeps code=0`，且**没有任何目录被删**（这是本次最核心的新语义，必须有端到端断言）。
4. `internal/controller`：触发方脏 → 只清触发方那一侧，另一侧原样。
5. `internal/controller`：`code=2` → 触发方被清；另一侧不被清。
6. `internal/controller`：模型报告 `codeaudit` 一节现在来自合并审计。

**变异纪律（本项目已有两次踩坑记录）：** 变异**值或条件**，不要删行使变量变成未使用（那会得到 `FAIL [build failed]`，什么也证明不了）；变异后确认失败的是**预期的那个断言**。

**跑测试的方式：** `go test ./...` 与 `go build ./...` 在本仓库**不可用**——`models/audit/holdout-sources/semgrep-rules-develop/` 有 248 个伪装成 `.go` 的 semgrep YAML 且无 `go.mod`。一律按包跑：

```
go build -o bin/taa ./cmd/taa
go test ./internal/codeaudit/... -count=1
go test ./internal/controller/... -count=1 -p 1
go test ./internal/platform/... -count=1
go test ./tools/platform-mock/internal/... -count=1
```

**验证层订正（2026-10-09，实测）：** 本仓库**不存在**端到端脚手架——无 `scripts/`、
无 Makefile 目标、全仓没有任何启动 `bin/taa` 的脚本。原计划写的「起真进程 + platform-mock
作对端」无从执行，且即使搭起来也不可靠：审计要 `ScanEnabled=true` 加活的 LLM 端点，
而记忆 `be-host-inference-cpu-collapse` 记录任一 CPU 竞争者就让 llama-server 慢 36 倍。

因此判据落在 `internal/controller` 里既有的一层：`deps_import_test.go`、`audit_model_import_test.go`、
`handler_test.go` 等已用 `httptest.NewServer` 驱动真 router、真 handler、真流水线，
配桩引擎与桩 LLM client（`ScanEnabled:false` 的 `setupTestState` 之外另有一套）。
`reportAudit` 的 `scope` / `code` 断言本来就在这一层。

1. 只下发模型（无依赖）→ 一次 `reportAudit(scope="", code=0)`，
   `report.roots == [{directory: modelDir, passed: true}]`。
2. 再下发一套干净依赖 → 一次 `reportAudit(scope="deps", code=0)`，
   `report.roots` 含两个根，两处分项 `passed` 均为 true。
3. 重投**同一个**依赖包 → install 与 audit **再次发生**（对照 2 的日志行数），`code` 仍为 0。
   这一条直接证明幂等短路确实没了。
4. findings 只在模型侧时下发依赖 → `reportAudit(scope="deps", code=1)` 且 `roots` 里只有
   模型根 `passed=false`，`reportDeps(code=0)`，**模型与依赖目录都没有被删**。
5. findings 在依赖侧时下发依赖 → `reportAudit(code=1)` + `reportDeps(code=1)`，依赖目录被删，
   **模型目录原样**。
6. **截断触发时，即使可见 findings 全在另一侧，触发方仍被清除。** 这一条钉住 spec §3.5
   堵掉的 fail-open：只按 finding 归属回滚会让一次截断的扫描放行。它必须有一条独立断言，
   否则这个洞会在「改完看起来都对」的状态下留在库里。
7. `ScanEnabled=false` → 跳过审计，`reportAudit` 不发出，依赖正常绑定，不留任何标记文件。

真进程冒烟测试仍可做，但它是**加分项**，不作为判据——判据以第 1~7 条为准。

---

## 并发与提交

- 并发 subagent 上限 2，禁止嵌套。Task 1+2（`internal/codeaudit/**`）与 Task 6a（`docs/api-design.md`）文件足迹不相交且只有前者跑测试，可并行。Task 3/4/5 都改 `internal/controller/**`，**必须串行**。Task 7 单独一段跑测试。
- **任何两个会执行 `go test` 的 agent 不得并发。** 因此 Task 6 拆两半：**6a** 只改 `docs/api-design.md`（不跑测试，可与 Task 1+2 并行）；**6b** 改 platform-mock 的 `scope` 拒绝文案与其测试（跑 `go test ./tools/platform-mock/...`，必须单独占一个测试窗口）。
- **投影层是本次的一处隐藏依赖面**（2026-10-09 补）：`report` 字段不是整份 `AuditReport`，而是 `projectCodeAuditSection`（`internal/controller/codeaudit_projection.go:21`）的**投影**，它只挑 `conclusion` 与 `file_reports`。分根结论若只挂在 `AuditTarget` 下就**到不了平台**，§3.3 的 `code=1` 消歧随之落空。该投影要扩为 `{conclusion, file_reports, roots}`，**一处覆盖两条消费方**：它同时喂 `reportAudit` 的 `report`（via `auditReportJSON`）与训练报告的 `codeaudit` 段（`import_processing.go:1019` → `internal/runtime/report.go:106`）。随 Task 3。
- **`internal/coordinator` 是死代码，一律不碰**（2026-10-09 实测）：模块名 `taa`，`cmd/taa/main.go` 只 import `taa/internal/app/taa`，全仓 `grep -rn 'taa/internal/coordinator'` **零命中**。该包内含一套**平行的**模型导入+审计实现（`flow_model.go:87-115`：单根 `GenerateAuditReport`、失败 `os.RemoveAll(ModelDir)`、无 scope 的 `ReportAudit`、整份 `json.Marshal` 上线），以及 `projectAuditToMap`（`flow_training.go:286`）——`projectCodeAuditSection` 的逐字副本。它靠自己的测试维持全绿，**看起来像活的**。原计划「coordinator 那份投影随 Task 4」作废：改死代码是纯维护负担，且「两份拷贝保持一致」不是本次的目标。已记入记忆 `coordinator-package-is-dead-code`。
- 本检出与其它参与者共享：`tools/csv2-vm/csv2-vm.sh` 与 `teellm/`（子模块）一律不碰；`git add` 只用显式路径，禁止 `git add .` / `-A` / `-u`。
- 提交信息用英文、Conventional Commits，**不得出现任何 AI 署名**。

---

## 风险（按严重度）

1. **CPG 与另一个参与者的 `feat(cpg)` 未合并分支冲突。** `internal/codeaudit/cpg*` 是他们的在制品。缓解：Task 2 选改动面最小的方案；开工前用 `git reflog show <branch>` 与 `ps -eo pid,lstart,etimes,cmd | grep claude` 复查对方是否仍在写。
2. **合并扫描抬高截断/超时概率，而截断在 fail-closed 下等于整体拒收。** 阈值按用户决定不动，因此这是既定代价；但必须有一条测试证明「单根超限仍能被 `Truncated` 正确标记」，避免把新增的多根路径做成静默吞掉截断。
3. **`LastAudit` 语义变化会改变训练报告里 `codeaudit` 一节的内容。** 这是有意的（合并审计永远包含模型根），但有**三处**注释（`deps_audit.go:15-18`、`route.go:155`、`import_processing.go:727-728`）还写着相反的话，必须同步改写，否则下一个人会按旧注释判断。
4. **模型侧问题不再阻止训练**（见「不变量」第 1 条）。这是「不跨侧清除」的既定后果，但它是本次改动里唯一一处**安全姿态实际放宽**的地方，需要在 spec 里显式登记，供日后决定是否补一个显式闸门。
