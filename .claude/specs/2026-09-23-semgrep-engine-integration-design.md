# Semgrep 引擎接入 TAA 生产审计链路 —— 设计规范 (Design Spec)

- **Date**: 2026-09-23
- **Spec Path**: `.claude/specs/2026-09-23-semgrep-engine-integration-design.md`
- **Status**: **设计待评审，未实施**。本规范是设计文档，写下时不改任何生产代码。
- **上游依赖**：
  - 证据：`.claude/specs/2026-09-22-semgrep-engine-noninferiority-evidence-design.md`（判定「通过」）
  - 证据报告：`models/audit/audit-results/engine-compare/REPORT.md`
  - 目标态：`.claude/specs/2026-09-17-semgrep-audit-engine-design.md`
  - 先例：`.claude/specs/2026-09-17-inference-engine-decoupling-security-protocol-design.md`
- **Scope**: Tier 1 静态层的引擎替换（`internal/codeaudit`）+ 部署面（镜像与规则文件）。**不含** Tier 2（LLM 仲裁）改动，**不含**目标态 4 阶流水线的完整实现。

---

## 1. 决策记录

以下三项由用户在 2026-09-23 通过选择项确定，是本规范的前提，**不在本规范内重新论证**：

| # | 决策项 | 选定 | 落点 |
|---|---|---|---|
| **D1** | 接入边界 | **Go 内 `exec` semgrep CLI**，复用评测侧 JSON 契约，改动限定在 `internal/codeaudit`；**不**采用独立扫描服务 | §6 |
| **D2** | semgrep 不可用时的行为 | **fail-closed 阻断**，结论标 `UNCERTAIN` | §8 |
| **D3** | 证据门槛 | **先建留出集并跑通，再接入生产** | §9 |

被否选项：D1 的「独立扫描服务」（本次不采纳）；D3 的「先接入、证据后补」。

---

## 2. 这次接入买到什么、不买到什么

**必须先说清楚，否则接入会被误读成检测能力提升。**

### 2.1 不买到：检测能力

证据报告 §7.3 记录，P0-bis 已把两臂的 `rule_id` 集合差异**从 30/50、44/100 有意归零至 0**；报告 §4 的三对不一致清单**均为空**。也就是说：

> **当前 semgrep 规则集是 Go regex 基线的镜像。** 在两个引擎上跑同一批规则，得到的判定逐样本相同——这**正是**非劣性判定「通过」的含义，也**正是**它不构成能力提升的原因。

代价却是实测的：扫描 **0.009 → 4.343 s/样本（≈483×）**，整轮 **+614.1 s（+53%）**（报告 §2）。

### 2.2 买到：能力的前置条件

目标态架构（2026-09-17）要的四项能力——别名归一化、跨行污点、AST 作用域切片、多语言——**regex 引擎在结构上不可能提供**。接入 semgrep 是拿到这些能力的**必要前置**，其价值兑现发生在**接入之后**的规则演进里，而不是接入这一刻。

**本规范因此把「接入」定义为一次行为中性的引擎替换**：接入后生产判定应当**与接入前逐样本相同**（这正是留出集要验证的，§9）。任何检测能力变化都必须走**接入之后**的独立证据流程，不得夹带在接入里。

> **推论（须写进评审结论）**：若组织当前**不需要** §2.2 的能力，则本次接入是**净成本**，不应做。

### 2.3 证据的适用边界（不得扩大）

| 证据支持的 | 证据**不**支持的 |
|---|---|
| 在 `audit-100` 上两臂判定逐样本相同，3 次重复稳定 | 「semgrep 可安全替换生产 regex」（`audit-100` 是**拟合集**，报告 §7.2） |
| 规则级一致性未被下游放大成判定级差异 | 「纯换引擎」的因果结论（证据只支持**整包替换**，报告 §7.1） |
| 六轮 `scan_incomplete_count = 0` | 未参与对齐的代码上的行为 |

---

## 3. 生产现状：接入面（已逐条核实）

### 3.1 扫描入口

`DefaultScanner()` 有**三个**调用点，实际只有**一个**是生产活跃路径：

| 位置 | 所在函数 | 生产状态 |
|---|---|---|
| `verifier.go:300` | `GenerateAuditReport` Phase 1 | ✅ **唯一活跃接缝**（经 `import_processing.go:632`、`coordinator/flow_model.go:87` 到达） |
| `verifier.go:187` | `CheckImportWithLLM` | ⚠️ 仅被 `llm_test.go` 引用，生产无调用者 |
| `scanner.go:210` | `CheckImport` | ⚠️ 全仓无调用者（含测试） |

三者都收敛到 `DefaultScanner().ScanDirectory*`，所以引擎替换可以只改这一处收敛点，但**后两个导出函数必须一并处理或明确弃用**——否则它们会静默继续用 regex，而名字看起来仍在工作。

### 3.2 生产消费哪一行（本项目已在此处犯过两次错）

`import_processing.go:645` 取 `audit.Conclusion.Passed`，其定义在 `audit.go:283-295`：

```go
switch policy {
case "gate":
    passed = stats.High == 0 && stats.Medium == 0   // MEDIUM 也拦截
default:
    passed = stats.High == 0                        // 只拦 HIGH
}
if ctx.ScanPassed != nil && !*ctx.ScanPassed { passed = false }
```

- 生产**默认策略是 `assist`**（`config.go:254`），不是 `gate`。
- `config.go:197-207` 已实现 `llm.policy` 的 fail-fast，只接受 `{"assist","gate"}`。
- **判定是「存在性」的**：只看 `High == 0` / `Medium == 0`，与 finding **条数无关**。这条性质在 §7.4 有用。

### 3.3 潜伏缺陷（接入必须处理）

`verifier.go:160-178` 的 `recalculatePassed` 注释自称 gate 分支，实现却是 `report.Passed = highCount == 0`——**MEDIUM 不拦截**，与 `audit.go` 的 gate 语义相反。因为生产消费 `audit.go` 的值，该分歧目前被遮蔽；但同一个字符串 `"gate"` 在同一个包里有两种含义。`recalculateStaticPassed`（`verifier.go:232-246`）是第三处相同写法。

### 3.4 已有的、可直接复用的接缝

| 接缝 | 位置 | 价值 |
|---|---|---|
| `Finding.CPGEvidence` | `rules.go:40`；被 `verifier.go:48-51` 用于**覆盖** `ContextAfter` | ✅ **现成的证据注入点**：把 AST 切片/污点轨迹塞进这个字符串即可进入 LLM Prompt，**无需改 TEE-LLM 协议** |
| `Finding.TaintTrace []TaintStep` | `rules.go:41`（类型在 `rules.go:14-23`） | ⚠️ 类型已定义，但**未进入** `teellm.FindingPayload`/`CodeTarget`（`teellm/types.go:52-68`）。结构化污点要真正到达 LLM 需扩协议 |
| `ConclusionContext.ScanPassed *bool` | `audit.go:259`、`:293` | ✅ **现成的 fail-closed 通道**：置 `false` 会强制 `passed = false`，**两种策略下都生效**。D2 直接落在这里 |
| 规则 YAML 已 force-track | `models/audit/semgrep/rules/{python,go,shell}/rules.yaml` | ✅ 可部署（`models/` 被 gitignore，这三个文件是 `-f` 加进去的） |

### 3.5 现存缺陷：`MaxFindings` 静默截断

`scanner.go:96-99` 与 `:280-283`：命中数达 `MaxFindings`（默认 200）时 `findings = findings[:MaxFindings]` 并 `filepath.SkipAll`。**`buildReport` 不记录任何「已截断」标志**，`Report.FilesCount` 只是走到一半的文件数。

后果：**第 200 条之后的 HIGH 命中会被丢掉，`passed` 可能因此为 `true`。** 这是当前 regex 引擎里一条真实存在的**静默放行**通道，且目标态架构 §8.1 要求的 `scan_complete == true` 前置条件在生产里**根本没有对应字段**。

> 接入 spec 必须顺带修掉它：`Report` 增加 `Truncated bool`，截断即视为 `scan_complete = false`。

### 3.6 规则集现状

生产 Go：**13 条**，`rules.go:69-221`，`Severity` 只有 HIGH/MEDIUM 两个常量（`rules.go:9-10`）。

| 严重度 | 条数 | 规则 ID |
|---|---|---|
| HIGH | 9 | `NET_001` `NET_002` `CMD_001` `OBF_001` `PER_001` `EXF_001` `EMB_001` `EMB_002` `EMB_004` |
| MEDIUM | 4 | `DYN_001` `FIL_001` `ENV_001` `EMB_003` |

线上 semgrep 规则：`python/rules.yaml` **13 条**，id 形如 `taa-<family>-python`，`metadata.rule_family` 回指 Go 的规则 ID。严重度用的是 semgrep 自己的词汇（ERROR/WARNING）。

---

## 4. **新事实**：semgrep 不在容器里（需裁决）

这是选定 D1 时**尚未核实**的一项，落地前必须解决。

| 事实 | 证据 |
|---|---|
| TAA 守护进程跑在容器**内部** | `deploy-docker.sh:426` `docker exec -d … nohup bash ./start.sh`；容器内 `/root/taa/taa`（20 MB，可执行） |
| 容器内**没有** semgrep | `docker exec taa-env-slim-v2 sh -lc 'command -v semgrep'` → 无；`import semgrep` → `ModuleNotFoundError` |
| 宿主**有** semgrep 1.177.0 | `/home/hjy/.local/bin/semgrep` |
| 可部署镜像是**从运行中的容器 commit** 出来的 | `deploy-docker.sh:2` "Package a deployable TAA + TEE-LLM image from the local development container" |
| 容器里没有 pip 包，但**有** `pip3` 24.0 / Python 3.12.3 | 实测 |

**因此「Go 内 exec semgrep CLI」隐含一个 D1 未覆盖的子决策**：semgrep 必须以某种方式进入容器。

| 选项 | 做法 | 代价 |
|---|---|---|
| **(a) 装进镜像** | 容器内 `pip3 install semgrep==1.177.0`，随镜像冻结 | 可部署产物变大；供应链面扩大；**对平台上报的度量值的影响未经核实**（见下） |
| **(b) 绑定宿主 semgrep** | 容器挂载宿主二进制 | 与「镜像自包含」矛盾；宿主路径/版本成为隐含依赖；`--network host` 是网络而非文件系统 |
| **(c) 宿主侧 exec** | 守护进程经某个本地接口请宿主跑 semgrep | **实质退回被否的「独立扫描服务」**，与 D1 不符 |

**推荐 (a)**，理由：只有 (a) 与「镜像自包含、可在 TEE 内复现」一致，且版本可 pin。

> ⚠️ **未核实、不得声称**：`internal/platform/register.go:29` 会把 TEE attestation report 上报给控制平台；`LLMExpectedMeasurements`（`config.go:159`）是**对端** TEE-LLM 的度量白名单，**不是**本镜像的。**往镜像里加 semgrep 是否改变平台侧校验的本机度量，本规范不掌握证据，列为实施前的阻塞性核实项（§12 Q1）。** 在核实之前，不得在任何文档里声称「接入不影响度量」。

---

## 5. 硬约束：D1 与 2026-09-17 解耦规范正面冲突

D1 已定，本规范不重新论证，但**必须记录残余风险与它的缓解条件**，否则等于假装冲突不存在。

**冲突的形状**：解耦规范之所以存在，是因为「大模型推理出现 GPU 显存溢出 (OOM)、死锁或内存泄漏时，将直接拖垮 TAA 核心证明与任务协调守护进程」。而 `exec` 把 semgrep 放进**守护进程自己的进程树**，也就放进了**同一个容器**——与 2026-09-17 要修的失效模式同构。

**且这个失效模式在本项目已被实测两次**（证据报告 §7.6、§9.10 第 11 条）：

| 观测 | 数据 |
|---|---|
| 全量 semgrep 扫描 + 容器内 ollama 并发 | 容器 `Exited (137)`（OOM） |
| 六轮采集中的一次（未被 OOM 杀，但推理停摆） | 容器存活、`RestartCount=0`，**2 次调用撞上 60 s `urlopen` 上限**（91.7 s / 120.1 s，当轮成功调用中位数 12.2 s） |
| 该轮恰是扫描成本最高的一轮 | — |

**结论：semgrep 会饿死同机 LLM，这是实测而非推测。** 容器总内存 9.703 GiB，ollama 与（未来的）semgrep 同处其中。

### 5.1 缓解条件（写入实施要求，非建议）

1. **扫描与 LLM 仲裁不得并发。** 4 阶流水线的 Phase 1（扫描）与 Phase 2/3（LLM）在 `GenerateAuditReport` 里本来就是顺序的——这是幸运，不是设计。实施时必须**显式保证**它不被改成并发。
2. **扫描进程必须有内存上限与硬超时。** `semgrep_runner.py:179` 用 `timeout=120`（评测侧）；生产侧须单独定值并**在超时后走 fail-closed**（§8），不得当作「无命中」。
3. **扫描期间不得有第二个重内存任务。** 部署文档须写明。
4. **留出集验证必须包含「扫描 + LLM 同时受载」的场景**（§9），因为评测矩阵是串行的，**没有覆盖**这个组合。

> **残余风险须在评审时由用户确认接受**。若不可接受，唯一的结构性出路是 D1 改为独立服务——本规范记录该出口，但不擅自改 D1。

---

## 6. 接口设计（Go 侧）

### 6.1 引擎抽象

引入一个最小接口，让两个引擎同形，并使「选择哪个引擎」成为**一处**可配置、可回滚的决策：

```go
// internal/codeaudit/engine.go
//
// StaticEngine is the Tier 1 static scanning boundary. Two implementations
// exist: the regex baseline (Scanner) and the Semgrep CLI adapter.
type StaticEngine interface {
    ScanDirectory(dir string) (*Report, error)
    ScanDirectoryWithLines(dir string) (*Report, map[string]int, error)
    // Name reports the engine identity written into Report.Engine.
    Name() string
}
```

- `regexEngine` —— 包住现有 `*Scanner`，**行为零变化**。
- `semgrepEngine` —— 新增，`exec` semgrep CLI 并解析其 JSON。
- 选择由 `DefaultEngine()` 单点决定，落在 `LLMConfig` 之外的新 `EngineConfig`（`internal/codeaudit` 或 `internal/config`，见 §6.5）。
- `verifier.go:300` 与 `verifier.go:187`、`scanner.go:210` 三处统一改为经 `DefaultEngine()`。

**`Name()` 存在的理由**：报告必须能自证是哪个引擎产出的。P4（`generate_matrix_results.py` 的 `engine` 字段由 mode 名推断）已经因为「字段只写不读、唯一作用是被人引用」被修过一次；同样的错误不能再犯。

### 6.2 `Report` 的字段扩展

目标态 §8.1 的四条前置条件在生产里没有对应字段，必须补：

```go
type Report struct {
    // ... 既有字段不变 ...

    Engine         string `json:"engine"`                    // "regex" | "semgrep"
    EngineVersion  string `json:"engine_version,omitempty"`  // semgrep --version 的输出
    ScanComplete   bool   `json:"scan_complete"`             // §8.1 第 1 条
    ParserErrors   int    `json:"parser_errors"`             // §8.1 第 2 条
    Truncated      bool   `json:"truncated"`                 // 命中数触顶，见 §3.5
    UnsupportedExts int   `json:"unsupported_extensions"`    // §8.1 第 3 条
    ProcessExitCode int   `json:"process_exit_code"`         // §8.1 第 4 条
}
```

**兼容性**：`ScanComplete` 为 `false` 的零值语义是危险的——`regexEngine` 必须**显式**置 `true`（regex 是同步纯内存匹配，不存在「扫描未完成」状态，与评测侧 P2 对 regex 臂的处理一致）。Go 的零值 `false` 会让「忘了赋值」看起来像「扫描失败」，方向安全，但仍须显式赋值并有测试守住。

### 6.3 `Finding` 的字段扩展

```go
EngineRuleID string `json:"engine_rule_id,omitempty"` // semgrep 的 check_id，如 taa-cmd-exec-python
RuleFamily   string `json:"rule_family,omitempty"`    // 回指的 TAA 规则 ID，如 CMD_001
```

`RuleID` **保持**为 TAA 规则 ID（`CMD_001`），使下游（`BuildFileReport`、`SuggestionForRule`、`projectCodeAuditSection`、TEE-LLM 的 `RuleID`）**无需改动**。这是让接入保持行为中性的关键选择：`metadata.rule_family` 是映射的唯一来源。

### 6.4 规则集与路径

- Go 侧不内嵌规则：`exec` semgrep 时 `--config <RulesDir>`，`RulesDir` 随镜像部署。
- 规则文件来源是仓库里已 force-track 的 `models/audit/semgrep/rules/`；镜像内落点须在 §11 的实施项中固定，并**与评测侧 `semgrep_runner.py` 指向同一份内容**（否则评测证据与生产规则不再对应）。
- 本轮**只启用 `python/rules.yaml`**：生产 `DefaultConfig().Extensions = []string{".py"}`。`go/`、`shell/` 三份规则存在但不是本次范围（§13）。
- 命令形状复用评测侧契约（`semgrep_runner.py:187-202`）：
  ```
  semgrep scan --config <RULES> --json --quiet --disable-version-check --no-git-ignore \
          --include '*.<ext>' … <target_dir>
  ```
  注意 `--no-git-ignore`：生产必须扫到被 `.gitignore` 排除的文件（那正是攻击者会放东西的地方）。

### 6.5 配置与 fail-fast

沿用 `config.go:197-207` 对 `llm.policy` 已建立的模式（白名单 + load 期报错），新增引擎选择项：

```go
var staticEngines = []string{"regex", "semgrep"}

// 未识别的引擎名必须在配置加载期报错，而不是静默退回 regex：
// 静默退回会让「以为开了 semgrep」的部署实际跑 regex，且报告里的
// engine 字段还会诚实地写着 regex —— 没人会去看它。
```

**刻意不设默认值偏移**：接入完成前默认仍为 `regex`；切换默认引擎是 §9 留出集通过**之后**的独立动作。

---

## 7. 严重度映射（本规范的核心，不许只写规则映射）

### 7.1 现行映射，以及它为什么是巧合

评测侧 `semgrep_runner.py:25-30`：

```python
SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "CRITICAL": "CRITICAL"}
```

实测当前 13 条规则的分布：

| semgrep | 条数 | 规则族 | 生产 Go |
|---|---|---|---|
| `ERROR` | 9 | CMD_001 NET_001 NET_002 OBF_001 EXF_001 PER_001 EMB_001 EMB_002 EMB_004 | 全为 HIGH ✅ |
| `WARNING` | 4 | DYN_001 FIL_001 ENV_001 EMB_003 | 全为 MEDIUM ✅ |

**9/9 与 4/4 精确吻合，但这只是当前规则集的巧合，不是不变量。** 一旦新增一条规则、或某个规则的严重度被改动，朴素映射就会静默漂移。

### 7.2 一处必须点名的缺陷：未知严重度默认 MEDIUM

`semgrep_runner.py:71`：`severity = self.SEVERITY_MAP.get(raw_sev, "MEDIUM")`。

**未知严重度静默变 MEDIUM，在 `assist` 下就是「不拦截」。** 这与本项目已经修过的失效模式（「扫描异常导致的无结果」被当作「代码安全放行」）同类：一个未知状态读成了「还好」。

**生产 Go 侧必须改为 fail-fast**：认不出的 severity 不得默认到某一档，应使该 finding 以 `UNCERTAIN` 进入 fail-closed（§8），或直接判扫描失败。评测侧的口径本轮**不改**（改了就使已完成的 6 轮不可比），登记为后续项。

### 7.3 目标态 §5 与生产 Go 在三条规则上冲突

| 规则 | 目标态 §5 | 生产 Go | 冲突 |
|---|---|---|---|
| `DYN_001` | HIGH | **MEDIUM** | 目标态更高 |
| `FIL_001` | HIGH | **MEDIUM** | 目标态更高 |
| `EXF_001` | **CRITICAL** | **HIGH** | 目标态引入生产不存在的等级 |

`rules.go:9-10` 只定义 `SeverityHigh`、`SeverityMedium`；`audit.go:242` 处理 `"LOW"`；**全链路没有 `CRITICAL` 的静态规则**。

**裁决：接入采用「生产 Go 的严重度」= 基准验证过的镜像集。**

理由（这是本规范最重要的一条论证）：

1. 非劣性证据是在**镜像集**上取得的。改严重度会改变被测量的处理本身，**使已取得的证据立即失效**。
2. 后果是可计算的、且不小：`DYN_001`/`FIL_001` 升为 HIGH 后，在**生产默认的 `assist`** 下会**新增阻断**。证据报告 §7.5 已量化过同类效应（`assist` 下被拦良性样本仅 6 个 / FPR 0.12；升 HIGH 会显著抬高它）。
3. 目标态 §5 的严重度列**没有**任何证据支撑——它是设计意图，不是实测。

**因此**：目标态 §5 的严重度差异按**后续独立变更**处理，各自走 RED→GREEN→重跑留出集的完整流程。**不得夹带在本次接入里。**

### 7.4 finding 条数差异对门禁是中性的，但对成本不是

- **门禁中性**：`passed` 只看 `High == 0 && Medium == 0`（§3.2），是**存在性**判定。semgrep 每条匹配都报、regex 每行只报首条（`scanner.go:137` 的 `break`），条数不同**不改变门禁结果**。
- **成本非中性**：Phase 2 对 finding **逐条**调 LLM（`verifier.go:33-108`）。条数变多 → LLM 调用变多 → 成本线性上升。
- 证据侧的对齐是**集合级**的（逐文件比 `rule_id` 集合），不是**多重集级**的；`bypass_rate` 两臂同为 0.22（存在性一致），`per_sample_llm_sec` 两臂 ≈1.0×。**on `audit-100` 条数大致相当，但这未在真实模型代码上验证。**

**实施要求**：`MaxFindings` 截断（§3.5）在 semgrep 下会**更容易触发**，因为条数更多。截断必须置 `Truncated = true` 并走 fail-closed，不得静默。

### 7.5 `verifier.go` / `audit.go` 的 gate 分歧必须在本次一并收敛

§3.3 的三处 `Passed` 赋值必须统一到 `audit.go` 的语义（gate = HIGH + MEDIUM 都拦）。做法：让 `recalculatePassed` / `recalculateStaticPassed` 接受 `policy` 参数并委托给同一个判定函数，而不是各自重写一遍。

**这是本次接入必须顺手修的，不是可选优化**：接入引入新的严重度来源（semgrep 的 severity 字符串），若三处语义仍不一致，新来源会同时踩中两种解释。

---

## 8. Fail-closed 契约的落地（D2）

### 8.1 通道：复用 `ConclusionContext.ScanPassed`

`audit.go:293-295` 的 `ScanPassed` 是现成的、**两种策略下都生效**的强制失败通道。接入后的映射：

```
semgrep 未安装 / 非零退出 / 超时 / 解析错误 / 命中数截断
        → Report.ScanComplete = false
        → AssembleAuditReport 取 s := scanReport.Passed; ScanPassed = &s
        → ComputeConclusionContext: passed = false
        → import_processing.go:645 取 Conclusion.Passed = false → 阻断 + 清除模型代码
```

已核实的既有同类先例：`import_processing.go:623-630` 在 LLM 不可用时**直接判失败并清除已解压模型代码**，不降级为纯静态放行。D2 与它一致。

### 8.2 与目标态 §8.1 的差异必须写清

目标态 §8.1 把四条前置条件挂在「**50%+ 极速旁路放行**」上——即「零 finding 才能旁路 LLM」。生产确实有这个旁路（`verifier.go:306` 的 `len(scanReport.Findings) > 0`，零 finding 时不调 LLM），但**它从未被描述成一条契约，也没有任何前置条件**。

**本规范把 §8.1 的四条前置条件落到这个已有的旁路上**，而不新造一条旁路。即：只有 `ScanComplete && ParserErrors == 0 && UnsupportedExts == 0 && ProcessExitCode == 0` 时，才允许「零 finding → 直接放行」；否则一律 `passed = false`。

### 8.3 `UNCERTAIN` 的方向性（沿用证据侧结论）

证据报告 §7.7：`UNCERTAIN ≠ BENIGN`，所以 fail-closed 后静态命中**保留**，从不被开脱。生产侧同一性质由 `verifier.go:121` 与 `:143` 保证（只有 `VerdictBenign` 才算开脱）。**接入不得改变这一点**——semgrep 的 `dataflow_trace` 只增强证据，不改变裁决语义。

---

## 9. 证据门槛：留出集规格（D3）

**在留出集通过之前，默认引擎不得切到 semgrep。**

### 9.1 为什么必须新建

证据报告 §7.2 已写明：`audit-100` 是**拟合集**——P0-bis 的规则对齐以它和 59 条 fixture 为参照做的，`EMB_001` 的过报也是由它的全量审计抓出并修掉的。**规则移植的漏报恰恰只在未见构造上暴露。**

### 9.2 留出集要求（硬性）

| # | 要求 | 理由 |
|---|---|---|
| 1 | **独立来源**：样本不得由本次规则的作者构造，不得复用 `FAMILY_SPECS`/`PROJECT_ALLOCATION` 的生成参数 | 避免重演 `audit-100` 的拟合 |
| 2 | **对抗构造优先**：别名（`import socket as s`）、解构重命名、跨行流转、动态 `getattr`/`importlib` | 正是目标态 §2 列出的 regex 四大盲区 |
| 3 | **标注口径与 `audit-100` 一致**（`expected_severity`、`ground truth` 主攻击规则） | 使判定规则可复用 |
| 4 | **规模**：良性/恶意各不少于 50 | `ΔFPR` 最小可分辨步长 0.02，与主基准对齐 |
| 5 | **判定规则沿用 0 容差**：`ΔFPR ≤ 0` 且 `Δrecall ≥ 0`，逐对成立 | 证据 spec §5.3 已定，不放松 |
| 6 | **两臂同测**（regex 与 semgrep），3 轮配对 | 单臂无法归因 |

### 9.3 留出集必须额外覆盖的两项（`audit-100` 没覆盖）

1. **扫描与 LLM 同时受载**（§5.1 第 4 条）：串行的 6 轮矩阵**没有**覆盖这个组合，而它正是实测两次失效的场景。
2. **大目录/大文件**：`audit-100` 是小型合成样本（4.3 s/样本）。真实模型代码的扫描时长与内存占用未测量，直接外推是**不成立的**；`MaxFindings` 截断（§3.5、§7.4）也只在真实规模上才会被触发。

### 9.4 判定的两种合法措辞

- 留出集**通过** → 允许把默认引擎切到 semgrep（§6.5），进入灰度。
- 留出集**未通过** → 回到规则对齐循环；**不得**因为「主基准已通过」而放宽。

---

## 10. 分阶段实施（TDD）

每阶段 RED → 验证 RED 原因 → GREEN → 验证 GREEN → REFACTOR。测试落 `tests/`（Python 侧）与 `internal/codeaudit/*_test.go`（Go 侧）。**每阶段独立可回滚。**

| 阶段 | 内容 | 产出 | 风险 |
|---|---|---|---|
| **A** | 严重度映射 + `verifier.go`/`audit.go` gate 语义收敛（§7.3、§7.5） | 单一判定函数 + 表驱动测试 | 低，纯 Go |
| **B** | `StaticEngine` 抽象 + `regexEngine` 包装（§6.1） | 行为**零变化**，全测试绿 | 低，纯重构 |
| **C** | `Report`/`Finding` 字段扩展 + `MaxFindings` 截断标志（§3.5、§6.2） | 截断不再静默 | 中，触及判定输入 |
| **D** | `semgrepEngine` 实现（§6.4）：exec、解析、`metadata.rule_family` 映射、`CPGEvidence` 注入 | 离线可跑 | 中 |
| **E** | fail-closed 管线（§8）：五类失败 → `ScanComplete=false` | 注入式测试 | **高，这是安全属性** |
| **F** | 配置项 + fail-fast（§6.5） | 未识别引擎名报错 | 低 |
| **G** | 镜像与规则文件（§4） | 容器内可跑 semgrep | **高，阻塞项见 §12 Q1** |
| **H** | 留出集验证（§9） | 通过才允许切默认引擎 | — |

**阶段 E 的 RED 必须是「注入失败 → 断言阻断」而非「断言计数」**：本项目的先例是 P2 的 fail-open 守卫测试（「构造 `findings == []` 且 `scan_complete is False`，断言不计为 TN」）。同类测试在 Go 侧必须有**五条**（未安装、非零退出、超时、解析错误、截断）。

---

## 11. 回滚与 kill switch

1. **引擎选择是配置项** → 回滚 = 改配置回 `regex`，无需回滚二进制。"regex 引擎在接入后必须保持完整可用" 是硬要求，**不得**在接入时删除。
2. **报告 schema 兼容**：新增字段全部 `omitempty` 或零值安全，使切换引擎不改变下游解析（`projectCodeAuditSection`、`auditReportJSON`、训练报告）。
3. **kill switch 的独立性**：semgrep 路径出现未知失败时，必须能**只**回退引擎而保留其余（fail-closed、policy fail-fast）改进。
4. **灰度**：阶段 H 通过后，先在单实例切换并留观察窗口，再改默认值。

---

## 12. 未决问题（实施前须裁决）

| # | 问题 | 阻塞什么 | 备注 |
|---|---|---|---|
| **Q1** | 往镜像里装 semgrep 是否改变平台侧校验的本机 TEE 度量？ | 阶段 G | **§4 的未核实项。核实前不得声称「接入不影响度量」** |
| **Q2** | 目标态 §5 的严重度差异（`DYN_001`/`FIL_001` → HIGH、`EXF_001` → CRITICAL）何时做、要不要引入 CRITICAL 等级？ | 阶段 A 之后的独立变更 | 本规范裁决为**不在接入内做**（§7.3），但需用户确认这个延后 |
| **Q3** | D1 的残余风险（§5）是否接受？若不接受，是否改用独立服务？ | 阶段 D | D1 已定，此处仅确认风险接受 |
| **Q4** | 结构化污点是否值得扩 TEE-LLM 协议（`CodeTarget` 加字段）？还是先用 `CPGEvidence` 文本承载？ | 阶段 D | 文本承载**今天就能用**（§3.4），扩协议是跨仓库变更 |
| **Q5** | 生产 semgrep 超时取值？（评测侧是 120 s） | 阶段 D、§5.1 第 2 条 | 须与 max 内存上限一起定 |
| **Q6** | `CheckImportWithLLM`（`verifier.go:182`）与 `CheckImport`（`scanner.go:206`）是改还是弃用？ | 阶段 B | 两者生产均无调用者，但都是导出符号 |

---

## 13. 明确不做的事

1. **不实现多语言。** `go/rules.yaml`（6 条）、`shell/rules.yaml`（3 条）存在，但生产 `Extensions` 只有 `.py`；扩语言是独立变更，须各自建留出集。
2. **不实现目标态 4 阶流水线的完整形态。** Stage 2 的 AST 符号归一化、Stage 3 的双模并发、§4 的语言矩阵都**超出本次范围**。本次接入只用到 semgrep 的 Search 能力，与评测证据的形态一致。
3. **不改 Tier 2。** Prompt、模型、策略语义、`teellm` 协议（Q4 除外）均不动。
4. **不改评测侧口径。** 包括 §7.2 的未知严重度默认值——改了会使已完成的 6 轮不可比，登记为后续项。
5. **不在本次引入 `CRITICAL` 等级。** 见 §7.3。

---

## 14. 与既有 spec 的关系

| Spec | 关系 |
|---|---|
| `2026-09-22-semgrep-engine-noninferiority-evidence-design.md` | **前置**。其判定是本规范的准入条件；其 §7.2（拟合集）、§7.1（整包替换）、§5.3（0 容差）三条限制被本规范继承 |
| `2026-09-17-semgrep-audit-engine-design.md` | **目标态**。本规范是实现它的第一步，但**只实现其中的 Fail-Closed 契约（§8）与规则严重度语义**；其 §5 严重度列与生产冲突处已按 §7.3 裁决为延后 |
| `2026-09-17-inference-engine-decoupling-security-protocol-design.md` | **张力**。D1 的 `exec` 边界与该规范所修的失效模式同构（§5）。本规范以 §5.1 的四条实施要求缓解，并把残余风险提交评审确认 |
| `2026-09-22-semgrep-engine-evidence-plan.md` | 已完成的证据实施计划，与本规范无重叠 |

---

## 15. 里程碑总结（须经评审确认）

- ✅ 证据：`audit-100` 上非劣性通过（**拟合集**，不覆盖留出集）
- ⬜ 本规范评审（含 §12 的 Q1–Q6）
- ⬜ 阶段 A–F 实施
- ⬜ 阶段 G（阻塞于 Q1）
- ⬜ 阶段 H：留出集通过
- ⬜ 切换默认引擎 + 灰度
