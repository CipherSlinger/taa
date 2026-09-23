# Semgrep 引擎非劣性证据 —— 阶段 6 报告

- **Date**: 2026-09-22
- **Spec**: `.claude/specs/2026-09-22-semgrep-engine-noninferiority-evidence-design.md`
- **Plan**: `.claude/plans/2026-09-22-semgrep-engine-evidence-plan.md`
- **数据**: `paired-analysis.json`（本轮全部数字由 `models/audit/tools/engine_compare_report.py` 从 6 轮的 `summary.json` / `sample-results.jsonl` 派生；报告不手抄任何数字）
- **判定**: **通过**（依据 §5.3 三条，见 §6）

**本报告回答的唯一问题**：把 Tier 1 静态层从 Go regex 换为 Semgrep，在 `audit-100` 上是否**非劣**（FPR 不升、recall 不降）。**它不回答**「semgrep 检测能力是否更强」，也不回答「在未见过的代码上是否可替换」——理由见 §7.1、§7.2。

---

## 1. 运行环境

| 项 | 值 |
|---|---|
| 评测器参数 | `--audit-mode static-llm --policy gate --llm-backend ollama --llm-model qwen2.5-coder:3b --llm-seed 42 --max-findings 50 --extensions .py` |
| 规则集 | `default-rules-13`（两臂各 13 条，已对齐，见 §7.3） |
| 提示版本 | `audit-prompt-v1` |
| 基准版本 | `2026-08-30`（`audit-100`：50 良性 B1–B5 / 50 恶意 M1–M5） |
| Semgrep | 1.177.0，`/home/hjy/.local/bin/semgrep`，sha256 `418846853224d55bc0b3049db10b562b7c83e27c28892c4721dc66f4c69ebf4b` |
| LLM | `qwen2.5-coder:3b`，digest `f72c60cabf6237b07f6e632b2c48d533cef25eda2efbd34bed21c5e9c01e6225`，容器 `taa-env-slim-v2` |
| 容器状态 | 采集全程 `RestartCount=0`，`StartedAt=2026-09-22T06:57:07.767755457Z` 未变（无 OOM 重启）。**但容器存活 ≠ LLM 健康**：`semgrep-run3` 有 2 次调用超时，见 §7.6 |
| LLM 失效 | 六轮 468 次仲裁中 16 次 fail-closed：14 次回复解析失败、2 次调用超时；**无一次落在良性样本上**，见 §7.6、§7.7 |
| 主机 | BE 单机 9.9GB，6 轮严格串行 |

**受测代码的身份用 blob 而非 commit 表示**，因为采集横跨多个提交，而判定依赖的是评测路径本身未变：

```
efba6d38288fda407c17cdc8cf6c761a52f81109  models/audit/tools/audit_benchmark_eval.py
a4130043751645ce38585079fb0cd133bc3e0638  models/audit/tools/semgrep_runner.py
8cfdf4641ddbd1c7d659e0515b2d6ad648c21055  models/examples/code_security_analyzer.py
```

这三个 blob 在驱动起始版本 `67847a8` 与报告时 HEAD 之间**逐字节相同**（`git diff --name-only 67847a8 HEAD` 的改动全部落在事后分析器、文档与夹具测试上，评测器不读其中任何一个）。因此这 6 轮是由同一份评测代码产出的。

---

## 2. 逐臂逐次结果表（spec §6.2）

| engine | run | n | FPR | recall | accuracy | precision | F1 | attr_prec | bypass_rate | fail_closed | incomplete | scan s/样本 | LLM s/样本 | 总时长 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| regex | 1 | 100 | 0.5600 | 1.0000 | 0.7200 | 0.6410 | 0.7813 | 1.0000 | 0.22 | 2 | 0 | 0.008 | 22.828 | 1781.6 |
| semgrep | 1 | 100 | 0.5600 | 1.0000 | 0.7200 | 0.6410 | 0.7813 | 1.0000 | 0.22 | 2 | 0 | 4.373 | 24.497 | 2348.3 |
| regex | 2 | 100 | 0.5600 | 1.0000 | 0.7200 | 0.6410 | 0.7813 | 1.0000 | 0.22 | 4 | 0 | 0.010 | 10.621 | 829.7 |
| semgrep | 2 | 100 | 0.5600 | 1.0000 | 0.7200 | 0.6410 | 0.7813 | 1.0000 | 0.22 | 1 | 0 | 4.259 | 11.026 | 1286.1 |
| regex | 3 | 100 | 0.5600 | 1.0000 | 0.7200 | 0.6410 | 0.7813 | 1.0000 | 0.22 | 4 | 0 | 0.009 | 10.740 | 838.9 |
| semgrep | 3 | 100 | 0.5600 | 1.0000 | 0.7200 | 0.6410 | 0.7813 | 1.0000 | 0.22 | 3 | 0 | 4.398 | 15.617 | 1658.2 |

**混淆矩阵六轮全同**：`tp=50 fp=28 tn=22 fn=0`，已由独立脚本从 `sample-results.jsonl` 重算复核，与各轮 `summary.json` 逐项吻合。

**95% bootstrap 区间**（`n_bootstraps=1000, seed=42`，六轮全同）：

| 指标 | 点估计 | 95% CI |
|---|---|---|
| FPR | 0.5600 | [0.4286, 0.6939] |
| recall | 1.0000 | [1.0000, 1.0000] |
| accuracy | 0.7200 | [0.6300, 0.8000] |
| precision | 0.6410 | [0.5278, 0.7439] |
| F1 | 0.7813 | [0.6909, 0.8531] |
| attribution_precision | 1.0000 | [1.0000, 1.0000] |

> **`recall` 的区间是退化的，不含不确定性信息。** 它是 `malicious_not_flagged = 0`（50 个恶意样本全部被静态臂命中）加上 LLM 从未完整开脱任一恶意样本的结果。该区间**不能**当作"召回精度极高"的证据引用，只能读作"本语料上 recall 恒为 1"。同理 `attribution_precision` 亦退化。

**成本**（spec §5.1 要求两项分开）：

| 项 | regex | semgrep | 比值 |
|---|---|---|---|
| 扫描 s/样本（三轮均值） | 0.009 | 4.343 | **≈ 483×** |
| LLM s/样本（78 个进仲裁样本） | 10.621 – 22.828 | 11.026 – 24.497 | ≈ 1.0× |
| 整轮 s（三轮均值） | 1150.1 | 1764.2 | **+614.1 s/轮（+53%）** |

LLM 成本在两臂上等价（同一模型、同一提示），引擎替换的全部增量在扫描层：**每轮多约 10.2 分钟，约 +53%**，绝对量 +456.4 ～ +819.3 s/轮。

---

## 3. 配对判定表（spec §6.3）

逐对在同一样本集（n=100）上做逐样本配对比较：

| pair | ΔFPR | ΔFPR 配对 bootstrap 95% CI | McNemar p | Δrecall | Δrecall 配对 bootstrap 95% CI | McNemar p | 时长差 |
|---|---|---|---|---|---|---|---|
| 1 | +0.0000 | [0.0000, 0.0000] | 1.0000 | +0.0000 | [0.0000, 0.0000] | 1.0000 | +566.7 s |
| 2 | +0.0000 | [0.0000, 0.0000] | 1.0000 | +0.0000 | [0.0000, 0.0000] | 1.0000 | +456.4 s |
| 3 | +0.0000 | [0.0000, 0.0000] | 1.0000 | +0.0000 | [0.0000, 0.0000] | 1.0000 | +819.3 s |

McNemar 的 b、c 均为 0（不一致样本数为 0，见 §4），故 p = 1.0 是"无 discordant 对"的定义值，**不是**"检验功效不足"的征兆——它与 §4 的空清单是同一件事的两种表述。

---

## 4. 不一致样本清单（spec §6.4）

**三对的清单均为空**：在 100 个样本上，两臂的判定**逐样本完全相同**——同样的 50 个恶意样本被拦截，同样的 28 个良性样本被误报，同样的 22 个良性样本被放行。不存在「regex 通过 / semgrep 拦截」或反向的样本。

这比 `Δ = 0` 更强：Δ 为 0 也可能由方向相反的两组不一致样本相抵而成。**本轮的 Δ=0 不是相抵，是零 discordance。** 因此不存在需要按 `trap_type` 与规则集合做根因归因的样本。

> ⚠️ **适用范围（2026-09-23 补，见 §7.13）**：上面这个「逐样本完全相同」是**在本轮实测所用策略（`gate`）下**成立的。**它不能外推到生产默认策略 `assist`**——在 `assist` 下，同样这 100 个样本上两臂的判定**不一致**（三对均为 `ΔFPR = +0.04`，同向）。原因不是本节的比较有错，而是 `gate` 这个测量仪器对两臂真正的差异**结构性失明**。**本节结论必须连同 §7.13 一起引用，单独引用即为超范围。**

---

## 5. 按 family 归因表（spec §6.5）

| family | 标签 | n | FPR (regex) | FPR (semgrep) | recall (regex) | recall (semgrep) |
|---|---|---|---|---|---|---|
| B1 | benign | 10 | 0.0 | 0.0 | — | — |
| B2 | benign | 10 | **1.0** | **1.0** | — | — |
| B3 | benign | 10 | **1.0** | **1.0** | — | — |
| B4 | benign | 10 | **0.8** | **0.8** | — | — |
| B5 | benign | 10 | 0.0 | 0.0 | — | — |
| M1 | malicious | 10 | — | — | 1.0 | 1.0 |
| M2 | malicious | 10 | — | — | 1.0 | 1.0 |
| M3 | malicious | 10 | — | — | 1.0 | 1.0 |
| M4 | malicious | 10 | — | — | 1.0 | 1.0 |
| M5 | malicious | 10 | — | — | 1.0 | 1.0 |

两臂**每一格都相同**，逐 family 亦无差异。28 个误报全部来自 B2（10）+ B3（10）+ B4（8）。

**这张表说明了 FPR 0.56 的来源，而它与引擎无关**：`benign_not_flagged = 22`（B1 10 + B5 10 + B4 2）恰为被放行的 22 个样本；其余 28 个良性样本**有**静态命中，而**六轮共 468 次仲裁（168 次良性 + 300 次恶意）中，LLM 一次都没有开脱过任何样本**——良性开脱 0，恶意开脱也是 0（逐轮重算）。B2/B3 全族的命中本就只有 MEDIUM（见 §7.5），B4 亦有 6 个样本带 HIGH 命中。

即：**本基准的 FPR 不是"扫描器误报率"，而是"LLM 从不开脱"这一事实的表现**，两臂同等承担。

---

## 6. 结论行（spec §6.6）

### **通过**

依据 spec §5.3 三条：

| 条件 | 实测 | 满足 |
|---|---|---|
| 1. 每一对 `ΔFPR_i ≤ 0` | 三对均为 `+0.0000` | ✅ |
| 2. 每一对 `Δrecall_i ≥ 0` | 三对均为 `+0.0000` | ✅ |
| 3. 六轮 `incomplete` 均为 0 | 六轮 `scan_incomplete_count = 0`、`round_complete = true`、`scored_count = 100` | ✅ |

**这个 PASS 能读成什么**（spec §8 已在采集前写死，此处照引，不扩大）：

- ✅ 「在这份语料上，两臂的**判定**逐样本完全相同，3 次重复稳定」
- ✅ 「规则级的一致性没有被下游（LLM 仲裁、`gate` 策略、判定口径）放大成判定级差异」
- ❌ **不等于**「semgrep 检测能力优于或等于 regex」——两臂在本语料上的规则差异已被 P0-bis **先行消除**，本轮不产出检测能力比较
- ❌ **不等于**「semgrep 可安全替换生产 regex」——本语料是**拟合集**（§7.2）
- ❌ **不覆盖** severity 敏感的生产语义（§7.5）
- ❌ **不可外推到生产默认策略 `assist`**——PASS 是 `gate` 下的读数，而 `gate` 对裁决盲；`assist` 下三对 `ΔFPR = +0.04` 同向（**§7.13，本报告最重要的限制**）
- ⚠️ **代价是实打实的**：每轮 +614 s（+53%），全部在扫描层

---

## 7. 限制与威胁（spec §6.7）

### 7.1 上下文形态与引擎捆绑，PASS 只支持「整包替换」

semgrep 臂用 AST 作用域、regex 臂用 ±N 行窗口，二者与"引擎"捆绑为同一处理（与目标态架构一致）。因此本 PASS 支持的是**「regex→semgrep 整包替换」**这一决策，**不支持**"纯换引擎"的因果结论。

### 7.2 `audit-100` 是拟合集，不是留出集（最重要的解释性限制）

阶段 3 的规则对齐（P0-bis）是**以本语料与 59 条 fixture 为参照**把 semgrep 规则逐条镜像到 regex 基线上做的；`EMB_001` 的过报也是由**本语料**的全量审计抓出并修掉的。因此本 PASS 证明的是**对齐在完整链路上成立**，而**不覆盖未参与对齐的代码**——规则移植的漏报恰恰只在未见构造上暴露。要支撑"可替换"需要留出集（spec §12.5），本轮**不应**声称已完成。

### 7.3 规则集差异不可避免，且已先行归零

两臂规则并非逐条等价。阶段 3.5/3.6 的两次审计（`rule-parity-audit.json`）把 59 条 fixture 与 100 个语料样本的 `rule_id` 集合差异从 30/50、44/100 归零至 0。**归零本身是本轮的有意前提**（否则受测臂携带对照组没有的检测能力，PASS 无法归因）。已知的残余非等价性见 spec §11.3，`OBF_001` 镜像的代价见 §11.4。

### 7.4 代理指标

离线 regex 臂是 Python 侧 `StaticScanner`，是 Go 生产扫描器（`internal/codeaudit`）的**镜像实现**。两处规则 ID 一致（13 条），但实现语言不同，结论对生产 Go 引擎是**代理性**的。生产侧 `MaxFindings=200` 静默截断与 `SkipDirs` 未排除依赖目录等差异不在本评测覆盖范围内。

### 7.5 评测镜像对 HIGH/MEDIUM 不敏感，而生产语义对它敏感

> ⚠️ **本节曾写错，以下是核实后的版本。** 初稿称"生产 `gate` 下 MEDIUM 从不单独拦截"，引用 `verifier.go:160-178`。**两处都错**：生产消费的不是 `Report.Passed`，而是 `AuditReport.Conclusion.Passed`；且该函数在 `gate` 下 **MEDIUM 也拦截**。详见下。

**生产实际消费哪一个**：`import_processing.go:645` 取 `audit.Conclusion.Passed`，其定义在 `audit.go:283-295`：

```go
switch policy {
case "gate":
    // Gate mode: block on High and Medium risk findings. Low (benign) findings pass.
    passed = stats.High == 0 && stats.Medium == 0        // MEDIUM 也拦截
default:
    // Assist mode (default): block on High risk findings.
    passed = stats.High == 0                             // 只拦 HIGH
}
if ctx.ScanPassed != nil && !*ctx.ScanPassed { passed = false }
```

因此 severity 的拦截门槛**取决于 `llm.policy`**，而**生产默认是 `assist`**（`config.go:254`），不是 `gate`。本轮评测用的是 `--policy gate`。

**另有一处生产内部不一致须记录**：`verifier.go:160-178`（`recalculatePassed`，注释自称是 gate 分支）写的是 `report.Passed = highCount == 0`，即 MEDIUM 不拦截——**与 `audit.go` 的 gate 语义相反**。因为生产消费 `audit.go` 的值，该分歧目前被遮蔽；但同一个 `"gate"` 在同一个包里有两种含义，属潜在缺陷，接入 spec 必须处理（见该 spec 的 severity 映射一节）。

**评测镜像**（`audit_benchmark_eval.py:718-755`）则把 `gate`/`assist` 实现为两个分支：`gate` 分支**不看 severity**，只要有非 `BENIGN` 裁决（或 `llm_unavailable`/`parse_error`）就拦截；`assist` 分支看 severity，拦 `CRITICAL`/`HIGH`。本轮跑的是前者，故镜像在 `gate` 下是 severity-blind 的。

实测（`gate-semantics-audit.json`，固化为可复跑用例 `tests/test_corpus_gate_semantics.py`）：

| family | blocking | non_blocking | not_flagged |
|---|---|---|---|
| M1 / M2 / M4 / M5 | 10 / 10 / 10 / 10 | 0 | 0 |
| **M3** | **0** | **10** | 0 |
| B1 / B5 | 0 | 0 | 10 / 10 |
| B2 / B3 | 0 | 10 / 10 | 0 |
| B4 | 6 | 2 | 2 |

**M3 与绝对 recall 的解释**：M3 全族 10 个样本的命中只有 MEDIUM（`ENV_001`/`FIL_001`，即其 `expected_severity="MEDIUM"` 所声明者）——**语料的有意设计**，非缺陷。

> ⚠️ **本节此处的初版结论已被实测推翻（第三次修正）**。初版称「生产 `assist` 不拦截 M3，故绝对 recall 高估上限 0.20」。**实测：M3 在 `assist` 下 10/10 全部拦截**，六个轮次无一例外，逐个样本 `classified_high == 1`。原因是 `ClassifyFindingRisk`（`audit.go:191-231`）**让 LLM 裁决覆盖静态严重度**：M3 的 MEDIUM 静态命中被 LLM 判为 `MALICIOUS` → 分类为 **HIGH** → `assist`（只拦 HIGH）照样拦。**「高估 0.20」不存在。**

**生产实测（权威口径）**：`internal/codeaudit.TestProductionGateSemantics` 直接调用真实的 `ComputeStatistics` / `ComputeConclusionContext` / `recalculatePassed` / `recalculateStaticPassed` 从六轮的 `audit_report.json` 重新派生，产物 `production-gate-semantics.json`。复跑：`TAA_PRODUCTION_GATE=1 go test ./internal/codeaudit/ -run TestProductionGateSemantics -v`。

终判 = `Conclusion.Passed && Report.Passed`（后者只能把结论压成 `false`，不能抬成 `true`）：

| 轮次 | `gate` FPR | `gate` recall | `assist` FPR | `assist` recall |
|---|---|---|---|---|
| regex-run1 | 0.5600 | 1.0000 | **0.5200** | **1.0000** |
| regex-run2 | 0.5600 | 1.0000 | **0.5200** | **1.0000** |
| regex-run3 | 0.5600 | 1.0000 | **0.5200** | **1.0000** |
| semgrep-run1 | 0.5600 | 1.0000 | **0.5600** | **1.0000** |
| semgrep-run2 | 0.5600 | 1.0000 | **0.5600** | **1.0000** |
| semgrep-run3 | 0.5600 | 1.0000 | **0.5600** | **1.0000** |

逐 family 良性拦截数（六轮各自稳定）：

| family | n | `gate` 拦（两臂相同） | `assist` 拦 regex | `assist` 拦 semgrep |
|---|---|---|---|---|
| B1 / B5 | 10 / 10 | 0 / 0 | 0 / 0 | 0 / 0 |
| B2 | 10 | 10 | 10 | 10 |
| **B3** | 10 | 10 | **8** | **10** |
| B4 | 10 | 8 | 8 | 8 |
| **合计** | 50 | **28** | **26** | **28** |

**另有一处由实测发现的、此前未被记录的生产行为：第二道门在救漏报。** 终判是 `Conclusion.Passed && Report.Passed`，而 `Report.Passed` 由 `recalculateStaticPassed`（`verifier.go:232-246`）按**原始静态严重度**计算。于是当 LLM 把一个**静态 HIGH** 降级为 `SUSPICIOUS`（分类成 MEDIUM）时：

- `conclusion`（`assist`，只拦分类后的 HIGH）**放行** → 该轮 `conclusion` 单独召回只有 **0.94–0.98**；
- `report`（原始静态 HIGH 计数）**拦截** → 终判召回回到 **1.0000**。

实测被它救回的样本（六轮合计 15 例，均为恶意）：

| 轮次 | `conclusion` 会放行、被 `Report.Passed` 拦回 |
|---|---|
| regex-run1 | `M5-10` |
| regex-run2 / run3 | `M5-05`, `M5-10` |
| semgrep-run1 | `M1-01`, `M1-06` |
| semgrep-run2 / run3 | `M1-01`, `M1-06`, `M5-05` |

**读法**：`assist` 下**单独看 `conclusion` 是不安全的**——它会把「LLM 降级了静态 HIGH」当成放行。生产实际是靠 `Report.Passed` 这个**第二道、按原始静态严重度**的门兜住的。这条性质在本报告初稿里没有出现（初稿只看了 `conclusion`），也不在任何既有 spec 里；**接入 spec 处理 `verifier.go`/`audit.go` 三处 `Passed` 语义分歧时必须把它一并保住**——把两处统一到 `audit.go` 的 `assist` 语义而不补回静态兜底，会让上表 15 个样本变成真实漏报。

**三处初版数字全部与实测不符**：生产 `gate` 不是 ≈0.52 而是 **0.5600**（与评测镜像逐位相同）；生产 `assist` 不是 0.12（6 个）而是 **0.52 / 0.56**（26 / 28 个）；M3 不是「`assist` 下不拦」而是**全拦**。

**对判定的影响：分策略，且这是本轮最重要的发现（见 §7.13）。** `gate` 下两臂仍然逐样本相同（Δ = 0），**本轮 PASS 作为「`gate` 下的非劣」成立**；但 `assist` 下两臂**不同**（ΔFPR = +0.04，三对同向）。

- ⚠️ **三处勘误记录，根因相同**：① spec §9.8 按规则清单**推断**「M1–M5 主攻击规则均为 HIGH」——错；② 报告初稿把生产策略认成 `gate`、把消费方引成 `Report.Passed`——错；③ 本节初版按 `Finding.Severity` 直接推门禁结果，**没有读真正计算它的 `ComputeStatistics` → `ClassifyFindingRisk`**，因而漏掉了「LLM 裁决覆盖静态严重度」这条通路——错。**三次都是「按注释与直觉推断」而非「读生产实际执行的那一行」。** 故第 ③ 次的纠正方式不再靠推理：改为**调用真实 Go 函数**并把产物落盘（`production-gate-semantics.json`），使数字可复跑而非可引用。

### 7.6 LLM 不可用是本机真实发生的失效（实测，非推测）

承载 ollama 的容器曾因并行跑 semgrep 全量扫描被 OOM 杀死（`Exited (137)`）。**危险之处在于它与 fail-open 合谋**：容器死亡时 LLM 不可达，而 fail-open 会把"无法裁决"呈现为"无命中 → 通过"，即**一次环境事故会伪装成一个更好的评测结果**。

**本轮防护与实测**：

- 6 轮严格串行、驱动由构造保证不并发。**实测容器全程 `RestartCount=0`、`StartedAt` 未变、模型 digest 未变**——未发生容器死亡。
- **但"LLM 不可用"确实发生了，只是没到容器死亡那一步**：`semgrep-run3` 中 **2 次调用** 的 `llm_state` 为 `llm_unavailable`，finding 级 `llm_reason` 为 **`ollama 调用失败: timed out`**——撞上了 `code_security_analyzer.py:707` 的 `urlopen(..., timeout=60)` 上限：该轮成功调用耗时中位数 12.2 s，这两次为 **91.7 s / 120.1 s**。这是**内存压力下的推理停摆**，与 OOM 同源（同机的 semgrep 全量扫描）、只是后果轻一档；该轮恰是扫描成本最高的一轮。
- **fail-closed 接住了它**：两个样本都是恶意样本，`UNCERTAIN` 保留了静态命中 → 计 TP，指标未受影响；`benign_fail_closed` 六轮仍为空。
- ⚠️ **但这仍是运气，不是保证**：这两次若落在**良性**样本上，产生的就是与 §7.7 同型的伪 FP——而 0 容差下一个样本即可翻转判定。**「LLM 不可用」与「解析失败」是同一风险的两个通道**，后续复跑须同时监控两者（`llm_state` 已逐样本落盘，`fail_closed_by_run` 已按样本列出）。

> 教训：我最初把"容器没重启"当作"该轮 LLM 健康"的证据，这个检查**太弱**——容器活着而推理停摆是完全可能的。能证伪它的只有逐样本 `llm_state`，这也是本轮把失败集合从"读出来"改为"派生出来"的原因。

一次**由我造成的违规已记录并作废重跑**（见 §8.1）。

### 7.7 LLM 回复解析失败会在良性样本上制造 FP（可造出假 FAIL 的两条通道之一）

**机制**（在证据层确认）：模型把 finding 的 `code_snippet` **原样**写进回复 JSON 的 `reason` 字段而不转义内层双引号，例如

```
"reason": "代码片段中使用 `subprocess.run` 执行 `sh -c "cat {target}"`，..."
```

该 JSON 非法。解析器 `extract_json_response`（`code_security_analyzer.py:321-350`）已尝试剥 markdown 围栏（`:333`）与取最外层花括号（`:342`），但**两者都救不回非法 JSON**——故围栏不是根因。失败后该 finding 得 `UNCERTAIN` → **fail-closed 保留静态命中**。

**暴露面**（实测）：78 个有命中样本中，finding 的 `code_snippet` **含双引号者 56 个**（恶意 40 / **良性 16**）。双引号是**必要非充分**条件，故风险池是 **56**，不是实际失败的少数几个。

**为什么它威胁判定而非仅抬升噪声**：

- 恶意样本上**无害**：fail-closed 后命中仍在，仍计 TP（这也解释了 `fn=0`）。
- 良性样本上**有害**：`UNCERTAIN ≠ BENIGN`，命中不被开脱 → 记为 FP，而原因与引擎无关。
- 两臂共用同一 LLM 与同一解析器、finding 集合又已对齐，故该机制对两臂暴露**相同**，产生的是**噪声而非偏倚**。但噪声可朝任一方向推动 `ΔFPR`：**若某 pair 中它落在 semgrep 臂而未落在 regex 臂，`ΔFPR > 0` → 判 FAIL，而根因不是引擎。0 容差下一个样本即可翻转判定。**

**实测的失败集合逐轮漂移，且 `--llm-seed 42` 不能使其复现**（同一输入、finding 完全相同：M5-02 在 semgrep-run1 为 `ok`、在 regex-run2 为 `parse_error`）。故**三轮是同一分布的抽样，不是逐字节重复**。

六轮共 16 次 fail-closed，逐样本列出于下（附 `llm_state` 与耗时，因为**两次失败分属两个不同通道**）：

| 轮次 | fail_closed 样本（state，耗时） |
|---|---|
| regex-run1 | M5-02 (parse_error, 40.5s), M5-07 (parse_error, 40.3s) |
| semgrep-run1 | M1-04 (parse_error, 26.1s), M1-09 (parse_error, 23.3s) |
| regex-run2 | M1-04 (parse_error, 16.9s), M1-09 (parse_error, 13.5s), M5-02 (parse_error, 17.1s), M5-07 (parse_error, 17.1s) |
| semgrep-run2 | M1-04 (parse_error, 12.9s) |
| regex-run3 | M1-04 (parse_error, 16.6s), M1-09 (parse_error, 13.2s), M5-02 (parse_error, 17.1s), M5-07 (parse_error, 17.1s) |
| semgrep-run3 | M1-02 (**llm_unavailable**, 91.7s), M1-04 (parse_error, 16.2s), M4-08 (**llm_unavailable**, 120.1s) |

即 **14 次是解析失败（本节机制）、2 次是调用超时（§7.6 机制）**。两者**后果相同**（`UNCERTAIN` → fail-closed 保留静态命中），**判据不同**（`llm_reason` 含「调用失败」还是「无法解析」）。耗时上二者同向偏高，因为退化成长输出的回复既更慢、也更可能含未转义引号。

池子**不是封闭的**：`semgrep-run3` 新增了 M1-02 与 M4-08 两个此前从未失败的样本。截至本轮共 6 个样本曾失败：`M1-02, M1-04, M1-09, M4-08, M5-02, M5-07`，**全部为恶意**。

**本轮已量到的最强形式（可核验，非断言）**：`paired-analysis.json` 的 `fail_closed_by_run.benign_fail_closed` 为**空**——六轮中**良性 `fail_closed` 计数为 0**，全部失败样本均为恶意。因此已量到的 FPR 与 `ΔFPR` **未被这条机制污染**。**这是运气好的事实，不是保证。**

> ⚠️ **若后续某 pair 出现 `ΔFPR > 0`，第一件事是查该 pair 的良性样本里有没有 fail-closed 的**（`fail_closed_by_run` 已按样本列出，两种通道都能查到），再谈引擎归因。

修复属**评测资产改动**，按 spec §12.4 的同一规则须**同时**施加于两臂并**重新测量全部 6 轮**；本轮不做（采集已进行到第 5 轮，改动会使已完成轮次与后续不可比）。登记 spec §12.6。

### 7.8 臂内复现性：判定稳定，但"结论产生方式"不稳定

`paired-analysis.json` 的 `within_arm`：

| 臂 | 对比 | 判定差异 | `llm_state` 差异 |
|---|---|---|---|
| regex | 1v2 | 0 | M1-04, M1-09 |
| regex | 1v3 | 0 | M1-04, M1-09 |
| regex | 2v3 | **0** | **无** |
| semgrep | 1v2 | 0 | M1-09 |
| semgrep | 1v3 | 0 | M1-02, M1-09, M4-08 |
| semgrep | 2v3 | 0 | M1-02, M4-08 |

**判定在全部 6 个对比中零差异**；不稳的只是 `llm_state`（即"LLM 真判了"还是"parse 失败后 fail-closed 保留了静态命中"）。逐轮样本级 `predicted_verdict` 的分布确有波动（`MALICIOUS` / `SUSPICIOUS` / `UNCERTAIN` 的计数逐轮不同），但三者**都不等于 `BENIGN`**，故样本级判定不变。

**若只比对判定，会得出"三轮逐字节相同"的错误结论。** 单列此表就是为了避免这一点。

### 7.9 时长只披露、不参与判定

`eval_duration_sec` 在同引擎同工作量下相差近一倍（regex-run1 1781.6 s vs regex-run2 829.7 s；`per_sample_llm_sec` 22.828 vs 10.621）。pair 1 的采集窗口内**用户本人在同一主机上工作**（16:00 提交 `dcc57aa`，涉及 docker 操作），我无法要求其停工。**因此单轮耗时不是稳定预算值**，时序证据仅作披露。判定（§5.3）不含任何时序条件，故不影响结论。

**离群检测**（`deviation_k=6.0, min_ratio=3.0`，基于中位数与 MAD）：

| 轮次 | `llm_duration_sec` 离群 | `scan_duration_ms` 离群 |
|---|---|---|
| regex-run1 / semgrep-run1 / semgrep-run2 | 无 | 无 |
| regex-run2 | 无 | B4-07 (9.25×), B4-08 (9.0×) |
| regex-run3 | 无 | B1-03 (3.62×) |
| semgrep-run3 | **M4-08 (9.85×), M1-02 (7.51×)**, M1-03 (4.12×) | 无 |

**值得注意（此处我最初的归因是错的，以下是实测修正）**：该检测器原本是为探测"主机被共享"而设计，但本轮标出的 `llm_duration_sec` 离群者**不是解析失败，而是 §7.6 的调用超时**。`semgrep-run3` 的三个离群样本为：

| 样本 | 耗时 | 比值 | `llm_state` |
|---|---|---|---|
| M4-08 | 120.1 s | 9.85× | `llm_unavailable`（超时） |
| M1-02 | 91.7 s | 7.51× | `llm_unavailable`（超时） |
| M1-03 | 50.3 s | 4.12× | **`ok`（未失败）** |

即：**该轮被标出的三个"异常慢"样本里，两个撞上 60 s 上限而失败，第三个 50.3 s 停在阈值之下、成功返回**——这正是"有一个 60 秒硬上限"的形状，而非"解析失败导致慢"。该轮真正的解析失败样本 M1-04 耗时 16.2 s，**低于离群阈值**，因此离群检测器根本标不出解析失败这一通道。两条 `scan_duration_ms` 离群（B4-07/B4-08、B1-03）绝对量很小（72–74 ms、29 ms vs 中位 8 ms）且与文件规模一致，不是争用信号。

**结论：无主机争用污染证据的迹象**；离群项已逐条披露，且不进入判定。**但离群检测器对本轮真正发生的两类 LLM 失效只有部分覆盖**——它能标出超时，标不出解析失败，真正可靠的信号仍是逐样本 `llm_state`。

### 7.10 `llm_available_rate` 不是失败率，勿误读

各轮 `summary.json` 的 `llm_available_rate = 0.76`，其分母含 22 个 **bypass** 样本（无命中 → 不需调用 LLM → `llm_available=false`）。因此 **0.76 ≠ "24% 调用失败"**。**真正的失败数是 `fail_closed_count`**（2/2/4/1/4/3）。该字段是评测侧统计量、不参与判定；本轮未改其口径以免使各轮 schema 不一致，改为在此点名说明。

### 7.11 模型与提示固定

结论仅对 `qwen2.5-coder:3b` + `audit-prompt-v1` 成立，不外推到其它模型或提示。

### 7.12 样本量与统计功效

n=100（50/50），`ΔFPR` 的最小可分辨步长为 0.02。本设计因此采用**0 容差**而非任何置信区间下界判据；由此得到的是**保守**结论——**通过即非劣，未通过未必代表实质劣化**。

---

### 7.13 `gate` 对裁决是盲的：本轮的 ΔFPR = 0 **不可外推**到生产默认的 `assist`（2026-09-23 补测）

**本节是本报告最重要的限制，且它是在报告发布后才被测出的。** §4 的「两臂判定逐样本完全相同」、§6 的 PASS，都**只在本轮实测所用策略 `gate` 下成立**。

**机制：`gate` 拦不拦与 LLM 裁决无关。** `gate` 的条件是 `stats.High == 0 && stats.Medium == 0`，而 `ClassifyFindingRisk` 把 `MALICIOUS`→HIGH、`SUSPICIOUS`→MEDIUM、`UNCERTAIN`→（静态 HIGH 则 HIGH）——**六轮里 `BENIGN` 出现 0 次**，所以 `gate` 下「有任何命中就拦」，裁决在 `MALICIOUS`/`SUSPICIOUS`/`UNCERTAIN` 之间怎么翻，结果都一样。**`gate` 因此对两臂真正的差异结构性失明。** `assist` 只拦分类后的 HIGH，裁决一翻，门禁就翻。

**两臂真正不同的地方在裁决，不在 finding 集合。** 逐样本比对 `(rule_id, severity, llm_verdict)` 多重集（`gate` 看不到这一层）：

| pair | 多重集不一致的样本数 | 其中良性样本 |
|---|---|---|
| 1 | 9 | `B3-04`, `B3-09` |
| 2 | 8 | `B3-04`, `B3-09` |
| 3 | 10 | `B3-04`, `B3-09` |

其余不一致样本全为恶意（`M1-01/04/06/09`、`M5-02/07/10` 等），方向混杂，故 `gate` 与 `assist` 下 recall 都不受影响。**良性侧则是单向的**：`B3-04`、`B3-09` 在**三轮 regex 均为 `SUSPICIOUS`、三轮 semgrep 均为 `MALICIOUS`**（6/6 稳定，无逐轮漂移）。于是：

> **在 `assist` 下，三对均为 `ΔFPR = +0.04`（regex 0.52 / semgrep 0.56），方向一致、无相抵。按 spec §5.3 的 0 容差（`ΔFPR ≤ 0`），在生产默认策略下这是 FAIL。**

**翻转的根因：上下文形态，而非规则。** 同一 `ENV_001`、同一行、`code_snippet` 逐字节相同（`return os.environ.get("SESSION_TIMEOUT", "3600")`），不同的是喂给 LLM 的上下文：

| 字段 | regex 臂 | semgrep 臂 |
|---|---|---|
| `context_before` | `def get_public_session_timeout() -> str:` | **`''`** |
| `context_after` | `def on_epoch_end(epoch=0, metrics=None):` | **`''`** |
| `ast_enclosing_block` | `None` | `def get_public_session_timeout() -> str:\n    return os.environ.get(...)` |

`code_security_analyzer.py:529-536` 在 `ast_enclosing_block` 非空时**用它替换** `ctx_before`（`elif finding.ast_enclosing_block: ctx_before = "# [AST Enclosing Scope]\n" + ...`）。因此两臂的 Prompt **内容确实不同**：regex 臂让模型看见函数名 `get_public_session_timeout`（良性语义）与下一个函数，semgrep 臂只给 AST 作用域块。模型在前者判 `SUSPICIOUS`、在后者判 `MALICIOUS`。

**这与 §7.1 是同一件事的更锋利版本**：§7.1 已声明 PASS 只支持「整包替换」、不支持「纯换引擎」的因果结论。现在可以补上它的**代价**——这个包（含上下文形态）的差异**不是不可见的**，它在 `assist` 下就是可见的判定差异。§7.1 说的是「无法归因」，本节说的是「有后果」。

**须读成什么：**

- ✅ PASS 作为「**`gate` 策略下**非劣」的证据成立，且是实测的。
- ❌ **PASS 不可外推到生产默认策略 `assist`**——在那里同为 100 个样本、同样两臂，ΔFPR = +0.04，三对同向。
- ❌ 因此 **§4 的「逐样本完全相同」必须连同本节引用**；单独引用即为超范围陈述。
- ⚠️ 该翻转是**引擎捆绑的上下文形态**造成的，故它对「Go 侧接入」是**直接可迁移的**：生产 Go 的 semgrep 引擎若按目标态把 AST 作用域灌进 `CPGEvidence`（`rules.go:40`，被 `verifier.go:48-51` 用于覆盖 `ContextAfter`），就会复现同一形态差，从而在生产默认策略下复现同一 ΔFPR。**接入 spec 的留出集必须在 `assist` 下判定，并须专门比对两臂的上下文构造。**

**复跑**：

```bash
TAA_PRODUCTION_GATE=1 go test ./internal/codeaudit/ -run TestProductionGateSemantics -v   # 门禁数值
python3 - <<'PY'   # (rule, severity, verdict) 多重集比对；见本节两表
import json,glob,os
from collections import Counter
def load(run):
    out={}
    for p in sorted(glob.glob(f"{run}/*/audit_report.json")):
        d=json.load(open(p)); fs=[]
        for fr in d.get("file_reports",[]):
            for f in fr.get("findings",[]):
                fs.append((f.get("rule_id"),f.get("severity"),f.get("llm_verdict") or "<none>"))
        out[os.path.basename(os.path.dirname(p))]=fs
    return out
for i in (1,2,3):
    R,S=load(f"regex-run{i}"),load(f"semgrep-run{i}")
    diff=[s for s in R if Counter(R[s])!=Counter(S[s])]
    print(f"pair {i}: {len(diff)} 个样本多重集不一致 {diff}")
PY
```

> **教训（与 §7.5 的第三次勘误同源）**：本轮把「判定」定义为**评测器在 `--policy gate` 下的判定**，而没有回头确认**生产默认跑的是哪个策略**。测量仪器选错时，Δ = 0 是仪器读数，不是被测对象的性质。**下一轮起，「用哪个策略判定」必须与生产默认策略一致。**

### 7.14 `assist` 下的误报按**通道**分解：Tier 1 自身的误报两臂完全相同，ΔFPR 全部来自 Tier 2（2026-09-23 补测）

§7.13 定位了差异**在哪两个样本上**，本节回答差异**走哪条通道**，并顺带得到一个与 semgrep 无关的结论。

生产默认策略 `assist` 的判定是 `final = 分类统计检查 && Report.Passed`（§7.5）。据此把 50 个良性样本被拦的原因切成两个**互斥**桶——先看静态 severity 有没有 HIGH，没有再看有没有 `MALICIOUS` 裁决：

| 通道 | regex | semgrep | Δ |
|---|---|---|---|
| Tier 1 静态 `HIGH` 落在良性样本 | **6** (`B4-01/02/05/06/07/10`) | **6（同一批样本）** | **0** |
| Tier 2 升级（静态无 HIGH，因 `MALICIOUS` 裁决被拦） | 20 | 22 (多 `B3-04`, `B3-09`) | **+2** |
| 合计被拦 / FPR | 26 / **0.52** | 28 / **0.56** | +0.04 |

三对 run 的静态 HIGH 集合**逐样本相同**，`B3-04`/`B3-09` 是 semgrep 侧**唯一**的净增项，反方向为空。合计值与 `production-gate-semantics.json` 的 `final_assist_fpr` 一致，故本节分解的正是生产消费的那个 `final` 值，而非仅 `conclusion`。

**结论一（关于 semgrep）：ΔFPR 不是 Tier 1 的检出质量差异。** 两个引擎在良性样本上产生的静态 HIGH 误报**逐样本一致**，差值为 0；+0.04 全部经由「上下文形态 → LLM 裁决 → 升级」这条链路。这与 §7.13 的根因分析互相印证：**换引擎本身没有让 Tier 1 更爱误报，是它喂给 LLM 的上下文变了。**

**结论二（与 semgrep 无关，且更重要）：本轮的误报主体是 Tier 2，不是 Tier 1。** regex 臂 26 例误报中 20 例（77%）、semgrep 臂 28 例中 22 例（79%）的静态命中里**根本没有 HIGH**，是 `assist` 的升级规则把一个 MEDIUM/LOW 命中提成了阻断。Tier 1 自身的误报率是 **0.12**（两臂相同），Tier 2 升级通道是 **0.40 / 0.44**。

> **即：即使把 Tier 1 换成完美的零误报扫描器，生产默认策略下的 FPR 也只从 0.52 降到 ≈0.40。** 想把 FPR 压下去，主要杠杆是 Tier 2 的升级规则（或 `assist` 对 `MALICIOUS` 的处理），不是 Tier 1 的引擎选择。

这条对本轮结论的性质有影响，须一并读：**本次「非劣」判定的是一个对 FPR 贡献约 23%（0.12/0.52）的通道**，而占大头的通道两臂本就共用、不受引擎替换影响。这不削弱 PASS 的有效性（判定的是接入这个动作的因果后果），但决定了**接入 semgrep 不应被期待降低整体误报**——它当前的净效应是把 FPR 从 0.52 推到 0.56。

**复跑**：

```bash
python3 - <<'PY'
import json,glob,os
def split(run):
    hi=set(); esc=set()
    for p in sorted(glob.glob(f"{run}/*/audit_report.json")):
        sid=os.path.basename(os.path.dirname(p))
        if not sid.startswith("B"): continue
        fs=[f for fr in json.load(open(p)).get("file_reports",[]) for f in fr.get("findings",[])]
        if any(f.get("severity")=="HIGH" for f in fs): hi.add(sid)          # bucket 1, exclusive
        elif any((f.get("llm_verdict") or "").upper()=="MALICIOUS" for f in fs): esc.add(sid)  # bucket 2
    return hi,esc
for i in (1,2,3):
    r=split(f"regex-run{i}"); s=split(f"semgrep-run{i}")
    print(f"pair {i}: static-HIGH 6={sorted(r[0])} identical={r[0]==s[0]}"
          f"  escalation {len(r[1])} vs {len(s[1])}  semgrep-only={sorted(s[1]-r[1])}")
PY
```

### 7.15 证据的 regex 臂**是否就是生产 Tier 1**：实测发现 8/100 不一致，根因是 `ENV_001` 大小写，已修复（2026-09-23 补测）

**本报告全部结论都建立在一个此前未被检验的前提上**：证据里的 "regex 臂" 是 Python 扫描器（`models/examples/code_security_analyzer.py`），而生产 Tier 1 是 Go 的 `internal/codeaudit`。两者各有一份规则表、各自维护。"非劣" 只有在两者是**同一个扫描器**时才可迁移，而这是执行问题，不是阅读问题。

新增门控测试 `TestGoEngineMatchesBenchmarkRegexArm`（`TAA_CORPUS_PARITY=1`）用**生产 Go 引擎**重扫同一份 100 样本语料，与 regex 臂自己的产物逐样本比对 `(rule_id, severity)` 多重集，行号另行比对：

| | 样本数 | 结论 |
|---|---|---|
| 首次测量（修复前） | 92/100 一致，**8 处分歧** | ❌ 不可迁移 |
| 修复后 | **100/100 一致**，含行号 | ✅ 可迁移 |

**8 处分歧全部是同一条规则、同一方向：`ENV_001/MEDIUM` 在 Python 有、在 Go 没有。** 无其他规则分歧、行号零差异、`files_scanned` 全同。根因是 Go 的 `ENV_001` 三条模式**未加 `(?i)`**，而 Python 版有（`tests/test_code_security_analyzer_v2.py:81` 专门断言 `AWS_SECRET`/`API_KEY` 命中）；模式里的备选词全是小写（`secret|token|api_key|...`），**大写变量名因此一个都不匹配**。

后果按样本标签分两侧，且都是单 finding 样本（唯一的 finding 就是这条）：

| 样本 | 标签 | 修复前 Go 的 finding 数 | 后果 |
|---|---|---|---|
| `B3-02/04/07/09` | 良性 | **0** | 生产下放行 → 误报**低于**实测基线 |
| `M3-01/03/06/08` | **恶意** | **0** | 生产下**无从阻断 → 漏报** |

`M3` 家族的恶意行为**就是**大写密钥读取（`sample.json`: "Steal secrets or tokens from environment variables"；代码 `os.getenv("AWS_SECRET_ACCESS_KEY", "")`）。所以这不是"少报一个提示"，而是**生产 Tier 1 完全看不见语料里一整个恶意家族**。这是一条**先于 semgrep、与 semgrep 无关**的生产缺陷。修复前/后的含义：

| | `assist` FPR | `assist` recall |
|---|---|---|
| 修复前（生产现状） | 0.44（放行上述 4 例良性） | **0.92**（漏上述 4 例恶意） |
| 修复后（对齐证据基线） | 0.52 | **1.0000** |

**修复**：给 `rules.go` 的 `ENV_001` 三条模式加 `(?i)`，与 Python 逐字符对齐。TDD：先写 `TestEnv001DetectsUppercaseSecretNames`（5 个大写用例 + 1 个小写对照 + **3 个反向用例**），确认 5 个失败、其余通过，再加 `(?i)`。反向用例是必要的——`(?i)` 不得把规则放大成"任意环境变量访问"（那是 semgrep 侧的行为，见下），`os.environ.get("PATH")` 仍须**不**命中。

**顺带测出一处 semgrep 侧的规则保真度缺口（潜在，本语料零后果）**：`taa-env-secret-python`（`rules.yaml:136`）用 `pattern: os.environ.get($KEY, ...)` 等形式，**完全不按 key 名过滤**，任何环境变量访问都命中；而两个 regex 臂都要求 key 含密钥词。这**理论上**会让 semgrep 报出 regex 从不报的 finding。实测该后果：

> **良性 0/50、恶意 0/50** —— 语料里每个环境变量访问的 key 名都含密钥词，故过宽在本语料上**从未真正触发**。它是一条真实的规则等价性缺口，但**不是**本次 ΔFPR 的成因；§7.13/§7.14 对差异的归因（上下文形态）不受影响。

**须读成什么：**

- ✅ **本报告的全部数值现在可迁移到生产 Tier 1**——前提由实测建立（100/100，含行号），不再依赖"两份规则表应该一致"的假设。
- ✅ `ENV_001` 的大小写缺陷是**独立的、已修复的**生产缺陷；修复使生产 Go 的静态输出在语料上与证据基线**逐字节等价**。
- ⚠️ **生产 LLM 在新可见 finding 上的裁决仍未测**：修复让 8 个样本的 finding 从 0 变为 1，其裁决行为在产物里有记录（就是同一 finding 集合），但生产容器里的 LLM 是否复现属 §9 留出集与 stage H 的范围。
- ❌ 不可把本报告的 FPR/recall 当作**修复前生产系统**的指标：修复前是 0.44/0.92，方向与直觉相反（误报更低、漏报更高）。

**复跑**：

```bash
# 等价性测量（须先有语料与产物）
TAA_CORPUS_PARITY=1 go test ./internal/codeaudit/ -run TestGoEngineMatchesBenchmarkRegexArm -v
# 规则本身的回归
go test ./internal/codeaudit/ -run TestEnv001DetectsUppercaseSecretNames -v
# semgrep 侧过宽在本语料上的后果
python3 - <<'PY'
import json,glob,os
src="models/audit/audit-results/engine-compare/regex-run1"
env=lambda sid,arm:[f["rule_id"] for fr in json.load(open(
    f"models/audit/audit-results/engine-compare/{arm}-run1/{sid}/audit_report.json"
)).get("file_reports",[]) for f in fr.get("findings",[])]
ids=sorted(os.path.basename(p.rstrip("/")) for p in glob.glob(src+"/*/"))
for lab,pre in (("benign","B"),("malicious","M")):
    sel=[s for s in ids if s.startswith(pre)]
    n=[s for s in sel if "ENV_001" in env(s,"semgrep") and "ENV_001" not in env(s,"regex")]
    print(f"{lab}: semgrep-only ENV_001 = {len(n)}/{len(sel)}")
PY
```

### 7.16 评测 semgrep 臂用的是**目录** target，而生产必须用**显式文件列表**——已核实对本报告无影响（2026-09-23）

阶段 D（`semgrepEngine` 接入）实测发现：semgrep 的目录 target **会进入 `venv/` 与 `__pycache__/`**，而 regex 臂按 `Config.SkipDirs` 跳过它们（`--no-git-ignore` 关掉的是 `.gitignore`，不是 `SkipDirs`）。评测侧 `semgrep_runner.py:187-202` 传的正是目录 target，因此需要核实本报告的 semgrep 臂是否扫了 regex 臂没扫的文件。

**核实结论：没有，本报告无需重做。**

```bash
# 语料 audit-100 下 regex 臂会跳过的目录
find models/audit/benchmarks/audit-100 -type d \( -name venv -o -name .venv -o -name __pycache__ -o -name node_modules \)
# → 10 处，全部是 __pycache__
# 其中是否有 .py（runner 传的是 --include '*.py'）
find models/audit/benchmarks/audit-100 -type d \( -name venv -o -name .venv -o -name __pycache__ -o -name node_modules \) -exec find {} -name '*.py' \;
# → 空：__pycache__ 里只有 .pyc（如 benchmark_variant.cpython-312.pyc）
```

10 处跳过目录全部是 `__pycache__`，只含 `.pyc`，而 runner 传了 `--include '*.py'`，故 semgrep 臂看到的文件集与 regex 臂相同。**两臂的 `files_scanned` 因此可比，§2/§3 的判定不受影响。**

**但这条限定不能外推**：危险是真实的而非理论的。模型导入目录携带 `venv/*.py` 十分常见，那种输入下目录 target 会让 semgrep 扫出 regex 臂从未读过的 finding，两臂的文件集与 `files_scanned` 都不再可比。生产适配器因此改为**传显式文件列表**（walk 的结果），文件集由 walk 决定、与 semgrep 的忽略规则无关，并增加了一项完整性判据：`paths.scanned` 必须覆盖全部传入 target，否则扫描以 error 失败（spec §6.4）。

---

## 8. 采集过程的偏离（须披露）

### 8.1 作废并重跑 regex-run1（我造成的）

第一版 `regex-run1` 跑到 22/100 时，我并发启动了完整测试套件（`unittest discover`），其中 `test_engine_rule_parity.py` 会对 59 条 fixture 调 semgrep —— 正是 §7.6 记录的"与容器内 ollama 并发 → OOM"组合。发现后立即停止测试套件，**该轮作废并重跑**。核对：容器 `RestartCount=0`、启动时间未变、已落盘样本全部带 `llm_verdict`（无 fail-closed）。**作废的理由是"我不该制造那个组合"，而不是"这次运气好"。**

### 8.2 驱动被会话结束杀死，作废并重跑 regex-run3

`run-six.sh` 于 17:41:50 在 `regex-run3` 扫到 91/100 时随会话终止。该轮**未写出** `summary.json` / `sample-results.jsonl`，即无任何判定可用，故整轮作废：清除半成品目录、恢复清单、复核容器与真实 `generate` 探针，再用 `/tmp/run-two.sh` 只补第 5、6 轮。新驱动用 `setsid` **脱离会话**，会话结束不再能杀死它。

**副作用（须披露）**：**pair 3 的采集窗口晚于 pair 1/2**（17:54–18:36 vs 15:57–17:41）。RUN_ORDER 的交错顺序使主机漂移表现为"run 索引之差"而非"引擎之差"，且时序不参与判定，故不改变结论；记录在此以备复核。

### 8.3 清单（`audit-benchmark-manifest.json`）的改写

评测器每次调用都会把 `benchmark_root` 改写为绝对路径。驱动在每轮结束后 `git checkout --` 恢复，故 6 轮之间语料保持逐字节一致。报告时该文件为干净状态。

---

## 9. 附录：本报告每一项数字的可复跑来源

| 报告内容 | 复跑方式 | 产物 |
|---|---|---|
| §2、§3、§4、§5、§7.8、§7.9 | `python3 models/audit/tools/engine_compare_report.py` | `paired-analysis.json` |
| §2 逐轮指标与 CI | 各轮 `summary.json` | `regex-run{1..3}/`、`semgrep-run{1..3}/` |
| §2 混淆矩阵的独立复核 | 从各轮 `sample-results.jsonl` 重算 | 同上 |
| §7.5 门禁语义 | `TAA_CORPUS_PARITY` 无关；直接 `python3 -m unittest tests.test_corpus_gate_semantics` | `gate-semantics-audit.json` |
| **§7.5 生产门禁数值、§7.13 终判** | `TAA_PRODUCTION_GATE=1 go test ./internal/codeaudit/ -run TestProductionGateSemantics -v`（调用**真实**的生产函数，不是镜像） | `production-gate-semantics.json` |
| **§7.13 两臂裁决多重集比对** | 见 §7.13 内联脚本 | 无（读各轮 `audit_report.json`） |
| §7.3 规则对等 | `python3 -m unittest tests.test_engine_rule_parity` | `rule-parity-audit.json` |
| §7.7 失败集合与污染判定 | `paired-analysis.json` 的 `fail_closed_by_run` | 同上 |

**本报告不含任何仅存在于对话记录中的数字。** 阶段 3.5 已因"证据只存在于对话里"整改过一次，本轮沿用同一原则。
