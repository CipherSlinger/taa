# Semgrep 引擎非劣性离线证据规范 (Semgrep Engine Non-Inferiority Evidence Spec)

- **Date**: 2026-09-22
- **Specification Path**: `.claude/specs/2026-09-22-semgrep-engine-noninferiority-evidence-design.md`
- **Upstream design**: `.claude/specs/2026-09-17-semgrep-audit-engine-design.md` (Target Architecture)
- **Scope**: 离线证据补全（evaluation-only），**零生产代码改动**
- **Lifecycle Status**: Evidence Gate（先证据、后接入）

---

## 1. 背景与问题陈述

`.claude/specs/2026-09-17-semgrep-audit-engine-design.md` §1.2 把 Semgrep-Native 引擎定义为**目标态（Target Architecture）**，把正则引擎定义为**现状基线**，并声明「多语言 Semgrep 规则实测与全矩阵验证作为本规范落地后的直接承接工程」。本规范就是这个承接工程：**在动生产代码之前，先取得可信的、可复现的「Semgrep 相对 regex 非劣」离线证据**。

本次调查中，以下事实已被逐条复现确认，构成本规范的问题起点。

### F1. 仓库中不存在任何可信的引擎对比数据

先说清楚**已经存在什么**（避免误读为「benchmark 从未跑过」）：

- `audit-results/audit-100-*`（20 个目录：`ollama`、`ollama-tuned`、`ollama-hardened`、`static-difficulty*` 等）是**由评测器实际跑出的真实运行**，构成 regex/LLM 轨道的调参与难度消融历史。它们**没有 `engine` 字段**（该字段是后加的），即全部是 regex 臂；它们是可用的 regex 侧基线素材。
- 缺的不是「benchmark」，而是**可信的 semgrep 臂**：如下三条所述，semgrep 侧没有任何一次有效测量。

- `models/audit/tools/generate_matrix_results.py:356-376` 将 `engine` 与 `rule_set_version` 由 **mode 名称**直接指派：
  ```python
  rule_ver = "semgrep-rules-13" if mode_name == "static-llm" else rule_ver
  engine   = "semgrep"          if mode_name == "static-llm" else "none"
  ```
  而 `tp/fp/tn/fn` 等全部指标来自文件内硬编码字面量 `MODELS_SPEC`（`generate_matrix_results.py:37` 起）。因此 `audit-results/matrix/static-llm/*/summary.json` 中「Semgrep-LLM 准确率 92%」**不是测量结果**。
- `models/audit/tools/run_benchmark_matrix.py` 调用评测器时**从不传 `--engine`**（`run_benchmark_matrix.py:61-84`），即矩阵运行实际走的都是默认 `--engine regex`。
- 现存**真实**（由评测器实际跑出、非手写）的 semgrep 标注产物只有两个，均不可用：

  | 产物 | 实际样本数 | engine 标注 | llm | 耗时 | 结果 |
  |---|---|---|---|---|---|
  | `audit-results/cpg-eval/` | **100**（50/50） | semgrep | none | 424.5s（4.2s/样本） | **100/100 全部判 malicious**：tp=50, fp=50, tn=0, fn=0 → recall 1.0, fpr 1.0；bypass=0 |
  | `audit-results/audit-100/` | **2**（全 benign） | semgrep | none | 8.36s | fp=2, tn=0 → fpr 1.0；无 malicious 样本，recall 无意义 |

  两点的含义截然不同，必须分开看：
  - `cpg-eval` 是**唯一一次真实的 100 样本 semgrep 全量运行**，其结果是**该臂在本数据集上区分度为零**（每个样本都被拦），根因即 F5 的 `FIL_001` 过宽匹配——4 个基座工程都要加载数据，`open()` 无处不在。它同时证明了「4.2s/样本」是 semgrep 的真实单样本开销量级（本机实测单次 `semgrep scan` 约 6.8s）。
  - `audit-results/audit-100/` 只是**一个 2 样本冒烟运行**，目录名（`audit-100`）与其内容（2 个样本）不符，其 `fpr=1.0 / recall=0.0` 是「2 个良性样本全被 `FIL_001` 拦截、且无恶意样本」的算术产物，**不构成任何指标**。
- 两个产物都是 `llm=none`，即 **semgrep 臂从未与 LLM 组合运行过一次**。
- 另一个识别陷阱：semgrep 规则通过 `metadata.rule_family` 复用了与正则完全相同的规则 ID（`CMD_001`/`FIL_001`/`EMB_001`…），因此样本行里的 `matched_rules` **无法用来判断是哪一臂跑出来的**——这也是 P4 要求 `engine` 必须来自真实运行记录的原因之一。

### F2. Semgrep 臂的 `code_snippet` 证据是伪造字符串（关键）

- Semgrep 自 1.100/1.101 起，在**未登录** Semgrep AppSec Platform 的社区版（CE）运行中，JSON 输出的 `extra` 字段 `lines`、`fingerprint`、`metavars`、`is_ignored` **不再返回真实内容**，而是返回字面量字符串 `"requires login"`（上游 issue `semgrep/semgrep#10734`；该字段门控已写入官方 JSON/SARIF 字段文档，下游 DefectDojo `#11480`、GitLab `!184050` 均已针对该常量做兼容）。行号字段 `start.line` / `end.line` / `start.col` 在 CE 中**仍然正确**。
- 本机复现（semgrep 1.177.0，`/home/hjy/.local/bin/semgrep`，二进制 SHA256 与 wheel `RECORD` 一致）：

  ```bash
  # 仓库自带规则 + 真实样本
  semgrep scan --config models/audit/semgrep/rules --json --quiet \
    --disable-version-check --no-git-ignore --include "*.py" \
    models/audit/benchmarks/audit-100/p1_xgboost_finance/B1-01
  # → dataset.py:33 与 model.py:118 均返回 "lines":"requires login"（两处行号不同、内容相同）

  # 手写单规则同样复现（排除「仓库规则写法」因素）
  # → "lines":"requires login"

  # 同一匹配用 SARIF 输出则内容正确（证明 semgrep-core 本身无误，仅 JSON 路径被门控）
  semgrep scan --config <same> --sarif --quiet ... /tmp/mini/x.py
  # → snippet: '    with open(p, "r") as f:'
  ```

- `models/audit/tools/semgrep_runner.py:100` 将该字段直接映射为证据：
  ```python
  "code_snippet": extra.get("lines", "").strip(),
  ```
- 而 `code_snippet` 正是大模型仲裁的输入：`models/examples/code_security_analyzer.py:452` 的 prompt 模板中
  ```
  >>> {code_snippet}   ← 触发规则的代码
  ```
  **结论：至今为止任何「semgrep + LLM」组合的结论，都是在用伪造的 `code_snippet` 进行仲裁，其结果不具备证据效力。** 这也解释了为何该组合从未被真正验证过。

### F3. 扫描失败与「扫描干净」不可区分（fail-open 静默）

- `SemgrepScannerAdapter.scan_directory`（`audit_benchmark_eval.py:321`）只返回 `List[Finding]`，**丢弃**了 `SemgrepScanResult` 的 `scan_complete` / `timed_out` / `parser_errors` / `error_message`。
- `analyse_sample`（`audit_benchmark_eval.py:755-756`）据此计算 `bypass = (len(findings) == 0)`：semgrep 未安装、超时、崩溃、规则解析失败，与「真的没有命中」得到完全相同的空列表。
- 另有静默异常吞噬点：`audit_benchmark_eval.py:332`（AST 作用域切片）、`:426`（CPG 构建与污点引擎）、`:528`（`sample.json` 解析）均为 `except Exception: pass`。

### F4. 两臂喂给 LLM 的上下文形态不同（对比公平性）

| | regex 臂（`StaticScanner`） | semgrep 臂（`SemgrepScannerAdapter`） |
|---|---|---|
| `code_snippet` | 真实命中行 `line.strip()`（`code_security_analyzer.py:299`） | `extra.lines` → **`"requires login"`** |
| `context_before` | 物理 ±3 行窗口（`i-3 .. i+3`，`code_security_analyzer.py:287-289`） | `""` |
| `ast_enclosing_block` | 无 | AST 作用域切片（真实、可用） |

`code_security_analyzer.py:524-531` 的 prompt 组装逻辑为「`context_before` 非空则用之，否则回退到 `ast_enclosing_block`」。因此 semgrep 臂实际以「伪造命中行 + 真实函数体外壳」进审，与 regex 臂的「真实命中行 + ±N 行窗口」不是同一形态的输入。

### F5. 已定位一个确定性误报根因：`FIL_001` 规则语义在移植中丢失

- Semgrep 规则 (`models/audit/semgrep/rules/python/rules.yaml:67-69`)：
  ```yaml
  pattern-either:
    - pattern: open($PATH, ...)
    - pattern: Path($PATH).read_text(...)
    - pattern: Path($PATH).read_bytes(...)
  ```
  **无敏感路径谓词**，且 `severity: ERROR` → 映射为 HIGH。
- Go 正则基线 (`internal/codeaudit/rules.go:135-143`) 要求路径字面量命中 `\.ssh|\.env|password|credential|\.aws|\.kube|id_rsa|authorized_keys`。
- 后果：**任何** `open()` 调用（含良性数据集加载）都被判为 HIGH 敏感凭据读取。实测（`--audit-mode static-llm --llm-backend none`，2 样本）：

  | 样本 | regex | semgrep |
  |---|---|---|
  | B1-01 | 0 findings → passed（TN） | `FIL_001`×2 → blocked（FP） |
  | B1-02 | 0 findings → passed（TN） | `FIL_001`×2 → blocked（FP） |

  样本 B1-01 `dataset.py:33` 的真实内容为 `with open(csv_path, "r", encoding="utf-8") as f:` —— 良性 CSV 加载。
- 该根因不是假想：`audit-results/cpg-eval/` 那次真实的 100 样本 semgrep 运行里，**100 个样本全部被拦**（tp=50, fp=50），正是这条规则把「任何文件读取」都判成 HIGH 的后果。换言之，semgrep 臂当前的失败不是统计意义上的劣化，而是**功能性失效**。

**在 F2–F4 修复之前进行的任何 semgrep 臂评测，其结果都不能作为接入决策依据。**

---

## 2. 目标与非目标

### 2.1 目标

1. 修复评测链路中使证据失效的缺陷（第 3 节 P1–P3），使 semgrep 臂能产出**真实、可追溯**的证据。
2. 在 audit-100（Python）上，以**配对（paired）非劣性判定**产出 regex 臂与 semgrep 臂的对比报告。
3. 报告必须能直接支撑「是否将 Tier 1 迁移到 Semgrep」这一决策，并对结论给出可反驳的限制条件。

### 2.2 非目标（本轮明确不做）

- **不改动生产代码**：`internal/codeaudit/**`、`internal/controller/**`、`cmd/**` 一行不改；不引入 Go 侧适配器；不在部署镜像中安装 semgrep。
- 不扩展多语言：只跑 Python，只用 `audit-100`（50 benign / 50 malicious，families B1–B5 / M1–M5，4 个基座工程）。
- 不做 CPG 消融（除非触发第 8 节的预案）。
- 不重写 `generate_matrix_results.py` 的策展矩阵（仅做第 3 节 P4 的防复发标注）。

---

## 3. 前置修复（Prerequisites）

以下修复全部位于评测工具链（`models/audit/tools/**`、`models/examples/code_security_analyzer.py` 的评测侧），不触及生产审计链路。全部须按 TDD 执行（RED → 验证 RED 原因正确 → GREEN → 验证 GREEN → REFACTOR），测试落 `tests/`，运行方式 `python3 -m unittest discover -s tests -p "test_*.py"`。

### P0（阻断级，已完成）`FIL_001` / `DYN_001` 规则按基线逐条镜像

F5 定位的 `FIL_001` 缺陷，实施时发现**不止一个**：把规则与基线（`internal/codeaudit/rules.go`）逐条对照后，共三处移植失真，且方向相反（既过宽又漏报）。

| # | 缺陷 | 后果 | 证据 |
|---|---|---|---|
| 1 | 无敏感路径谓词：`pattern: open($PATH, ...)` 匹配**任何** `open()` | **过宽**：凭据读取语义完全丢失 | `cpg-eval` 100/100 全拦；本机阴性对照 `open(csv_path, ...)` 实测命中 1 次 |
| 2 | 缺 `Path.home().joinpath(...)` 形态（基线 pattern 3） | **漏报**：基线能抓的形态本规则抓不到 | RED 实测：`Path.home().joinpath('.aws/credentials').read_text()` → `[]` |
| 3 | `severity: ERROR`→映射 HIGH，基线为 `SeverityMedium`（`rules.go:137`）；`DYN_001` 同病（基线 `rules.go:124` 亦为 MEDIUM） | **拦截路径偏移**：生产 `gate` 语义下 MEDIUM 从不拦截，HIGH 必须被 LLM 判 BENIGN 才放行 | RED 实测：修复前 `{severity}` = `{'HIGH'}` |

第 3 条不是无害差异，其机制已核到代码：`internal/codeaudit/verifier.go:160-178` 的 `recalculatePassed` 只对 HIGH 计数并令 `report.Passed = highCount == 0`——**MEDIUM 被计数但不参与 `Passed`**，而 HIGH 只要 `LLMVerdict != VerdictBenign` 就计入 `highCount` 从而拦截。因此把基线的 MEDIUM 规则移植成 HIGH，等于**给该臂新增了一条 regex 臂没有的拦截路径**，会让 semgrep 臂在基线条目上系统性地更严——这既污染 `ΔFPR`，也把「引擎差异」与「仲裁路径差异」混在一起（§9.1 已登记的混淆叠加）。

> **勘误（2026-09-22，本次核对代码时发现）**：本节初稿把该机制写成「MEDIUM 恒拦、HIGH 可被 LLM 开脱」，方向说反了。已按 `verifier.go` 更正为上表与上段。同时发现**评测镜像与生产语义在此不一致**，见 §9.8。
> 既有的 `tests/test_semgrep_rule_fixtures.py::test_medium_rules_keep_baseline_severity` 注释中同一处反了的表述，也已一并更正（该测试断言本身正确，无需改动）。

**修复**：三条分支逐条对应基线三条正则（各带自己的 `metavariable-regex` 谓词）；`severity: ERROR → WARNING`（WARNING 映射 MEDIUM）；`DYN_001` 同步改 `WARNING`。

**与基线一致地保留 `/etc/shadow` 盲区（已决）**：基线谓词是 `\.ssh|\.env|password|credential|\.aws|\.kube|id_rsa|authorized_keys`，**不含** `shadow`；`FIL_001` 原本的测试夹具用 `open('/etc/shadow')` 作正例，那是对当时过宽规则的「测试后补」，不是基线语义。本规范选择**忠实镜像基线**（`/etc/shadow` 不报），并把该断言写成测试固定下来：两臂共享同一缺口 → 判定的是引擎而非规则质量。这是一个**真实的规则质量缺口**（`/etc/shadow` 是凭据窃取的经典目标），但它对两臂同等成立，属「规则集质量问题」而非「引擎非劣性问题」，故单列为后续独立事项（见 §12.1），不在本轮处理臂里单方面加强检测——否则即为在受测处理中夹带规则改进。

**语料影响（实测，非推断）**：恶意侧 `M3`（secret_theft）家族共 7 个样本读取敏感路径，形态为 `Path(".env").read_text()`、`Path(".ssh/id_rsa").read_text()`、`Path(".aws/credentials").read_text()`，**全部落在谓词内** → 修复不损失任何 M3 召回；良性侧 `open(csv_path, ...)` 类数据加载不再命中。

**RED/GREEN**：`tests/test_semgrep_rule_fixtures.py::test_fil_001_probe` 改为 3 正例（`open('.ssh/id_rsa')`、`Path('.env').read_text()`、`Path.home().joinpath('.aws/credentials').read_text()`）+ 2 反例（良性 `open(csv_path, ...)`、`open('/etc/shadow')`）；新增 `test_medium_rules_keep_baseline_severity`。修复前二者分别因「正例漏报」与「severity=HIGH」而红，修复后 16/16 全绿。

**冒烟**：`--engine semgrep --audit-mode static-llm --llm-backend none --limit 2` → `fp` 由 **2 → 0**，`tn=2`（对照 F5 表中修复前的 `FIL_001`×2 误报）。

### P1（阻断级）`code_snippet` 改为从源文件按行切片，不再信任 `extra.lines`

- 改动点：`models/audit/tools/semgrep_runner.py:100`。
- 做法：按匹配的 `start.line` / `end.line`（CE 中正确）从目标文件读取真实命中行；`extra.lines` 若等于 `"requires login"` 或为空，一律走文件切片路径。
- **RED 测试**：在既有 `tests/test_semgrep_runner.py::TestSemgrepRunner.test_real_semgrep_scan_directory`（该测试当前只断言 `rule_id`/`scan_complete`/`passed`，从不校验 `code_snippet`，因此该缺陷一路绿灯通过）中新增断言：
  ```python
  self.assertEqual(res.findings[0]["code_snippet"], "os.system('id')")
  ```
  该断言在修复前必须失败，且失败原因是 `'requires login' != "os.system('id')"`。
- 验收：RED 确认后实现，GREEN 后 `tests/test_semgrep_runner.py` 全通过。

### P2（阻断级）扫描状态必须进入样本结果

- 改动点：`SemgrepScannerAdapter.scan_directory`（返回诚实结果对象而非裸列表）、`analyse_sample`（把 `scan_complete` / `timed_out` / `parser_errors` / `error_message` 写入样本行），并把 `audit_benchmark_eval.py:332`、`:426`、`:528` 的 `except Exception: pass` 改为「记录到样本行 + 计入汇总计数」。
- 新增样本级字段（至少）：`scan_complete: bool`、`scan_timed_out: bool`、`scan_parser_errors: int`、`scan_error: str | None`、`slice_error: str | None`。
- 新增汇总字段：`scan_incomplete_count`、`scan_error_count`。
- **判定影响（关键）**：`scan_complete == False` 的样本**不得**计入 `bypass`，也不得按「无命中 → 通过」处理。它们在指标中单列为 `incomplete`，并在报告中显式披露数量与样本清单。
- **RED 测试**：模拟 `SemgrepScanResult(scan_complete=False, timed_out=True)` 与 `is_available() == False` 两种注入，断言样本行的 `scan_complete is False`、`scan_timed_out is True`（或 `scan_error` 含 "not found"），且汇总计数正确。

### P3 LLM 采样固定种子

- 现状：`code_security_analyzer.py:695` 为 `{"temperature": 0.1, "num_predict": N}`，**无 `seed`**，同一输入多次运行不可复现。
- 改动：新增 `--llm-seed`（默认 `42`）并透传到 ollama `options.seed`；该值写入 summary，作为运行元数据的一部分。温度维持 `0.1` 不变（改变温度会改变被测量的处理本身）。
- 理由：本设计要求「每臂 3 次」并逐对判定，固定种子使每一对比较接近确定性，把「引擎差异」与「采样噪声」分离；对两臂同等施加，不引入偏向。
- **RED 测试**：断言 `--llm-seed` 被解析并出现在传给 ollama 的 payload 中（mock HTTP 层），且 summary 记录了该值。

### P4 防止 `engine` 标注再次与事实脱钩（防复发，低成本）

- 现状：`generate_matrix_results.py:356-376` 由 mode 名硬编码 `engine`/`rule_set_version`，这正是 README/CHANGELOG 出现夸大表述的机制性原因（已在 commit `dfac8b7` 修正文档）。
- 最小改动（择一，实施前确认）：
  - **(a)** 该生成器产出的 JSON 增加 `"provenance": "hand-authored-spec"` 字段，并把 `engine` 改为必填显式入参（无默认值），使「未指定」无法隐式落成 `semgrep`；
  - **(b)** 将该生成器标记为 deprecated，矩阵结论统一改由本规范的实测产物产出。
- 本文档倾向 **(a)**：改动最小、不删除既有能力，但彻底消除「静默冒名」的可能。**此项须在写实施计划时由你确认。**

---

## 4. 评测协议

### 4.1 试验设计

- **设计**：配对设计（paired by sample）。同一批 100 个样本、同一 LLM、同一策略，唯一变化的因子是 `--engine`（`regex` vs `semgrep`）。
- **重复**：每臂 3 次独立运行；第 *i* 次 regex 运行与第 *i* 次 semgrep 运行构成一对（P1/P2/P3），共 3 对。
- **串行执行**：6 次运行严格串行，避免本地 ollama 争用导致的时间与超时噪声（超时是 F3 的诱因之一）。
- **运行期间不得并发其它重内存任务（新增，实测教训）**：本机为 BE 单机（内存 9.9GB）。实施 P0 期间，并行运行 semgrep 全量扫描与本机 LLM 宿主容器，导致承载 ollama 的容器 `taa-env-slim-v2` 被 OOM 杀死（`Exited (137)`，实测）。该故障在矩阵中途发生时，其表现**恰好是 F3 的 fail-open**：LLM 不可达 → 静态判定兜底或裁决失败 → 被记成「无命中/通过」，而非报错。因此矩阵运行期间：（a）不得并行跑 semgrep 全量审计、也不得并行跑测试套件；（b）每次运行前后校验 ollama 存活与模型 digest 一致；（c）若发现 ollama 重启（digest 变化或日志中断），该轮按 §5.3 第 3 条的 `incomplete` 处置——作废重跑，不得计入判定。
- **运行前预检**：记录 `http://127.0.0.1:11434/api/tags` 返回的模型 digest（本轮实测 `qwen2.5-coder:3b` → `f72c60cabf62…`），并在每轮结束后复核；digest 变化即视为环境漂移。
- **固定量**（两臂完全一致）：`--audit-mode static-llm`、`--policy gate`、`--llm-backend ollama`、`--llm-model qwen2.5-coder:3b`、`--max-findings 50`、`--extensions .py`、`--llm-seed 42`。
  - 模型选择依据：本机 `http://127.0.0.1:11434/api/tags` 仅安装 `qwen2.5-coder:3b`；历史基线用的 `0.5b` 已不在本机，且生产配置亦为 `3b`，故两臂必须在 `3b` 上重新测量，不与历史数值混用。
- **运行环境记录**（写入报告）：`semgrep --version`、semgrep 可执行文件路径与其 SHA256、`ollama` 模型 digest、`git rev-parse HEAD`、评测器脚本的 dirty 状态。

### 4.2 运行矩阵

| # | engine | run | 结果目录 |
|---|---|---|---|
| 1 | regex | r1 | `models/audit/audit-results/engine-compare/regex-run1` |
| 2 | semgrep | r1 | `models/audit/audit-results/engine-compare/semgrep-run1` |
| 3 | regex | r2 | `models/audit/audit-results/engine-compare/regex-run2` |
| 4 | semgrep | r2 | `models/audit/audit-results/engine-compare/semgrep-run2` |
| 5 | regex | r3 | `models/audit/audit-results/engine-compare/regex-run3` |
| 6 | semgrep | r3 | `models/audit/audit-results/engine-compare/semgrep-run3` |

命令模板（在仓库根执行）：

```bash
python3 models/audit/tools/audit_benchmark_eval.py \
  --audit-mode static-llm \
  --engine <regex|semgrep> \
  --policy gate \
  --llm-backend ollama \
  --llm-model qwen2.5-coder:3b \
  --llm-seed 42 \
  --max-findings 50 \
  --extensions .py \
  --results-dir models/audit/audit-results/engine-compare/<engine>-run<N> \
  --notes "engine-compare <engine> run<N>; semgrep=<version>; seed=42"
```

### 4.3 冒烟门槛（6 次正式运行之前）

先跑 3 个样本（`--limit 3`）逐项确认，全部通过才启动正式矩阵：

1. semgrep 臂每个 finding 的 `code_snippet` 与源文件对应行逐字相等（P1 生效）。**实测通过**：语料审计逐条比对 80 个 semgrep 命中的 `code_snippet` 与源文件对应行，80/80 逐字相等、0 处不符（`rule-parity-audit.json` 的 `semgrep_snippets_verified` / `semgrep_snippet_mismatches`）。该项断言 `snippet_checked > 0`，避免「0 条被检查、0 条不符」的空集通过。
2. 人为制造失败（例如临时改坏规则 YAML 或指向不存在的可执行文件），确认样本行出现 `scan_complete=false` 且被汇总计数捕获（P2 生效）。**第一次实测未通过**：样本行正确，但汇总仍把 4 个未扫样本记成 `tn=4` / `accuracy=1.0`。按 §8 回到 RED/GREEN 循环修 `confusion_counts`（§11.7），重跑后 `round_complete=False`、`counts` 全零、`scored_count: 0`。
3. 同一命令连续跑两次，同一模型的裁决结果一致（P3 生效）。**实测通过**：`static-llm + semgrep + ollama(qwen2.5-coder:3b) + --llm-seed 42`、`--limit 12`（10 个良性 B1 全部 bypass，2 个 B2 陷阱样本实际进入 LLM 仲裁），两轮在 `predicted_label`/`predicted_risk`/`blocked`/`bypass`/`llm_state`/`scan_complete`/`matched_rules`/`error_type` 上**逐字段零差异**；两轮均 `round_complete=True`。单轮耗时 101.8s / 73.8s（仅作量级参考，§4.4 禁止据此估算正式矩阵时长）。
4. **全量规则集行为一致性审计（新增，P0 教训）**：对 audit-100 的 100 个样本，逐文件比对两臂触发的 `rule_id` 集合，差异清单必须为空，或每一条差异都被逐项解释并登记进报告。
   - 理由：P0 表明「按 YAML 逐条读规则」既不可靠也不完整——同一条规则同时存在过宽与漏报两种反向失真，且都只在**行为**上显现。semgrep 臂全量 100 样本约 424s，相对 6 次正式运行（数小时）是可忽略的前置成本，而它能拦住「矩阵跑完才发现第三条规则缺陷」这一数小时量级的返工。
   - 本项为**新增门槛**，与 §5.3 的通过条件相互独立：它判的是「两臂是否可比」，不是「哪一臂更好」。
   - **已固化为可复跑用例**：`tests/test_engine_rule_parity_corpus.py`（`TAA_CORPUS_PARITY=1` 开启）。实测已通过两轮：第一轮 75/100 差异 → 修 `EMB_001`（§11.6）→ 第二轮 **100/100 归零**。该项**判的是规则集是否可比**，因此必须**在每次改规则后重跑**，而不是只跑一次。

### 4.4 运行时长预算（6 轮跑完后以实测替换，原估算保留作对照）

**实测（6 轮正式运行，逐轮见报告 §2）**：

| 项 | regex | semgrep | 差 |
|---|---|---|---|
| 扫描 s/样本（三轮均值） | 0.009 | 4.343 | **≈ 483×** |
| LLM s/样本（78 个进仲裁样本） | 10.621 – 22.828 | 11.026 – 24.497 | ≈ 1.0× |
| 整轮 s（三轮均值） | 1150.1 | 1764.2 | **+614.1（+53%）** |

- 引擎替换的全部增量在**扫描层**：**+614 s ≈ +10.2 分钟/100 样本**，绝对量 +456.4 ～ +819.3 s/轮。LLM 成本两臂等价（同模型同提示），故不随引擎变化。
- **原估算偏低约 30%**：采集前按 `cpg-eval` 的 4.2 s/样本推出「约 7–8 分钟/100 样本的固定额外开销」，实测 10.2 分钟。偏低的来源是 regex 基线侧被高估（`StaticScanner` 实测 0.009 s/样本，而非估算所用的量级）。
- **单轮耗时不是稳定预算值**：同引擎同工作量下 `eval_duration_sec` 相差近一倍（regex-run1 1781.6 s vs regex-run2 829.7 s），原因是运行窗口内有用户本人在同机工作（详见报告 §7.9）。**预算应取区间上限，不应取均值。**
- LLM 单样本时延**仍不作预测性估算**（历史数值来源不可信，见 F1）；本表数值是测量结果，不是外推。正式矩阵前用 `--limit 5` 试跑的做法**已证伪**：语料清单是固定网格而非文件系统发现，`--limit N` 永远先取到全部绕过仲裁的良性样本，该测量是 vacuous 的（详见实施计划阶段 5）。
- 6 轮串行总墙钟：15:57:41 → 18:36:08 = **2 h 38 min**（含 §8 记录的驱动被杀与重跑间隙）。
- 串行执行期间不要并行跑其它 ollama 任务（原因见 §4.2 的 OOM 实测与 §9.11 的超时实测）。

---

## 5. 统计判定方法

### 5.1 每臂指标

- 主指标：`FPR`（benign 被判 malicious 的比例）、`recall`（malicious 被判 malicious 的比例）。
- 次指标：`accuracy`、`precision`、`F1`、`attribution_precision`、`bypass_rate`、`fail_closed_count`、`incomplete`（P2 新增）。
- 每个指标给出点估计与 95% bootstrap 置信区间（复用评测器既有 `compute_all_bootstrap_ci`，`n_bootstraps=1000`，`seed=42`）。3 次运行先给出逐次结果，再给出跨次汇总（报告须同时呈现，禁止只报最好一次）。

### 5.2 配对判定（核心）

对每一对运行 *i*（i = 1,2,3），在**同一样本集**上做逐样本配对比较：

- `ΔFPR_i = FPR_semgrep,i − FPR_regex,i`
- `Δrecall_i = recall_semgrep,i − recall_regex,i`
- `Δ` 的置信区间用**配对 bootstrap**（对样本下标重采样，`n_bootstraps=1000`，`seed=42`），而非两独立区间相减。
- 配对显著性检验：对 `FPR` 与 `recall` 各做 **McNemar 检验**（b/c 为两臂判定不一致的样本数），报告 p 值。
- **不一致样本清单**：逐对列出 `Δ` 的贡献者——`regex 通过 / semgrep 拦截`、`regex 拦截 / semgrep 通过` 两类样本的 ID、family、`trap_type`、两臂触发的规则集合。**（规则集合是 F5 类根因的唯一可行动线索。）**

### 5.3 判定规则（0 容差，非劣才算过）

**通过条件（全部满足）**：

1. 对 i = 1,2,3 的**每一对**：`ΔFPR_i ≤ 0`；
2. 对 i = 1,2,3 的**每一对**：`Δrecall_i ≥ 0`；
3. 6 次运行的 `incomplete`（`scan_complete == false`）计数均为 0。若某一轮出现 `incomplete > 0`：**该轮作废**，先定位失败原因（P2 已使失败可见），修复后重跑该轮；在 `incomplete` 归零之前，该轮结果不得进入判定与指标计算。`incomplete` 样本一律不计入 `bypass`、不按「无命中 → 通过」处理。

即：semgrep 臂在**任何**一次配对运行中，误报不得比 regex 更高、召回不得比 regex 更低。**任一条件不满足 → 判定为「未通过非劣性」，不得进入生产接入。**

同时报告（不影响通过与否，但必须披露）：McNemar p 值、Δ 的 95% 配对 bootstrap 区间、运行时长差异。

> **勘误（2026-09-23）——判定必须在与生产默认一致的策略下做出。** 上述 Δ 的**符号与大小取决于 `llm.policy`**，而本 spec 初稿未把策略写成判定条件的一部分。实测（§9.8 勘误三续、报告 §7.13）：同一份六轮数据在 `gate` 下三对 `ΔFPR = 0`（PASS），在生产默认的 `assist` 下三对 `ΔFPR = +0.04` 同向（FAIL）。原因是 `gate` 拦任何非 `BENIGN` 裁决，**对裁决失明**，而两臂的差异全在裁决里。
>
> **因此第 1、2 条应读作：「在**生产默认策略**（`assist`）下，每一对 `ΔFPR_i ≤ 0` 且 `Δrecall_i ≥ 0`」。** 本轮采集跑的是 `--policy gate`，故其 PASS **只对 `gate` 成立**，不构成对生产默认配置的非劣证据。后续采集须在 `assist` 下跑，或两策略各跑一遍并**分别**判定。

---

## 6. 报告内容与落盘

产出单一报告：`models/audit/audit-results/engine-compare/REPORT.md`（数据落同名目录 JSON），必须包含：

1. **运行环境**：`git rev-parse HEAD` + dirty 状态、semgrep 版本/路径/SHA256、ollama 模型 digest、评测器参数全量。
2. **逐臂逐次结果表**：6 行 × (FPR, recall, accuracy, precision, F1, attribution_precision, bypass_rate, fail_closed_count, incomplete, 时长)。
3. **配对判定表**：3 行 × (ΔFPR, 其配对 bootstrap 95% CI, McNemar p, Δrecall, 其 CI, McNemar p)。
4. **不一致样本清单**（见 5.2 末）。
5. **按 family 归因表**：B1–B5 / M1–M5 各自的 FPR/recall 在两臂上的差异，用于判断差异是集中在特定陷阱类型还是普遍存在。
6. **结论行**：明确写 `PASS`（满足 5.3 全部三条）或 `FAIL`，并在 `FAIL` 时给出**已定位的根因**与**未定位的差异清单**（后者是下一轮的唯一输入）。
7. **限制与威胁**（第 9 节内容直接引用）。

报告结论只能有三种措辞：**通过**、**未通过（附根因）**、**证据不足（附缺失项）**。禁止出现无数据支撑的定性表述。

---

## 7. 实施顺序

1. ~~P0（规则语义镜像）~~ **已完成**（`models/audit/semgrep/rules/python/rules.yaml`，见 §3 P0）。
2. ~~P0-bis（规则集对齐）~~ **已完成**（同上文件；由 §4.3 第 4 项审计触发，两轮，见 §11.5 与 §11.6）。
3. ~~P1~~（`code_snippet` 改为按行切片，`58de1e8`）、~~P2~~（扫描状态进入样本行，`8eb7fe7`）**已完成并各自提交**。
4. ~~P3~~（LLM 采样固定种子）**已完成**（`--llm-seed` 默认 42，分析与评测两侧 CLI 打通并写入运行元数据；温度保持 0.1）。
5. ~~P4~~（`engine`/`rule_set_version` 去除 mode 名推断，加 `provenance`，见 §13.1）**已完成**。
6. **冒烟门槛（4.3）四项全过**：第 4 项已在第二轮达到 **100/100 归零**（§11.6）；第 1–3 项在 P1–P3 的 GREEN 中已各自验证，开跑前按 §4.3 用 `--limit 3` 再复核一次。
7. `--limit 5` 实测时延 → 确认总时长预算。
8. 6 次正式运行（串行）。
9. 生成报告，按 5.3 给出 PASS/FAIL。

提交规范：遵循 Conventional Commits，英文；scope 建议 `audit-bench`。P0/P1/P2 已独立提交，P3、P0-bis（含第二轮）、P4 各自独立提交，报告与原始数据一并提交。**提交信息中不得包含任何 AI 署名。**

---

## 8. 判定后的预案（预注册）

- **若 PASS**：产出「非劣」证据，作为后续「Go 侧接入 Semgrep」独立 spec 的前置输入；本轮不写生产代码。**PASS 的边界须照 §9.8/§9.9 的实测量写明**（这两条在判定之前就已被测出，不是事后加的条件）：
  - PASS 是说「**换引擎后，在这份语料上两臂没有差别**」，**不是**说「生产会拦截这些攻击」。实测 32/100 个样本的命中强度低于生产 `gate` 的拦截门槛（M3 全族 10 个恶意样本 + 22 个良性样本），这些样本上**镜像的判定不是生产的判定**：M3 被镜像记成真阳性而生产无论 LLM 怎么判都不会拦截。因此**报告的 recall 不得被引用为「生产可拦截率」**。
  - PASS 也**不覆盖未参与规则对齐的代码**（§9.9 拟合集）。接入决策若要依据检测能力本身，而非依据「与 regex 相比无退化」，需要留出集（§12.5）或 §8 的 CPG 消融。
- **若 FAIL 且根因是规则语义缺陷**（如 F5 的 `FIL_001`）：先修规则、重跑同样的 6 次矩阵（同一判定规则），修规则属于评测资产而非生产代码，仍在授权范围内。**禁止以「把 semgrep 规则调松到与 regex 等价」为手段达成 PASS 而不记录该变更**——规则集差异必须在报告中显式列出。
- **若 FAIL 且根因指向 AST/污点带来的上下文形态差异（F4）**：此时才启用 **CPG 消融**预案——增加两臂：`semgrep（不使用 AST 作用域切片）`与`semnapi（不使用 CPG）`，以分离「引擎」与「上下文形态」的贡献。此预案**只在触发时执行**，不在本轮范围。
- **若证据不足**（如 `incomplete` 非零无法消除）：结论写「证据不足」，列出缺失项，不给出推荐。

---

## 9. 有效性与威胁（须在报告中披露）

1. **上下文形态混淆（F4）**：本设计把「引擎」与「上下文形态」捆绑为同一处理（semgrep 臂用 AST 作用域、regex 臂用 ±N 行窗口）。理由是该捆绑与目标态架构（2026-09-17 spec §3）一致；但因此**判定的 PASS 只支持「regex→semgrep 整包替换」这一决策，不支持「纯换引擎」的因果结论**。若需要后者，走第 8 节 CPG 消融预案。
2. **代理指标**：离线 regex 臂是 Python 侧 `StaticScanner`，是 Go 生产扫描器（`internal/codeaudit`）的**镜像实现**而非其自身。两处规则 ID 一致（13 条），但实现语言不同，结论对生产 Go 引擎是**代理性**的。此外生产侧 `MaxFindings=200` 静默截断与 `SkipDirs` 未排除依赖目录等差异（详见 `internal/codeaudit/scanner.go`）不在本评测覆盖范围内，不能由本报告的 PASS 推断为已解决。
3. **样本量与统计功效**：n=100（50/50），`ΔFPR` 的最小可分辨步长为 0.02。因此本设计采用「0 容差」而非任何置信区间下界判据；由此得到的是**保守**结论——通过即非劣，未通过未必代表实质劣化。
4. **模型与提示固定**：结论仅对 `qwen2.5-coder:3b` + `audit-prompt-v1` 成立，不外推到其它模型或提示。
5. **规则集差异不可避免**：两臂规则并非逐条等价（F5 即为一例）。报告须列出两臂各自触发的规则集合差异，避免把「规则差异」误读为「引擎差异」。
6. **BE 单机环境**：所有运行在同一台机器串行完成，未覆盖并发、资源受限或部署镜像（未安装 semgrep）等生产形态。
7. **本机资源争用可致 LLM 宿主被杀（实测，非推测）**：承载 ollama 的容器 `taa-env-slim-v2` 曾因并行跑 semgrep 全量扫描而被 OOM 杀死（`Exited (137)`）。**危险之处在于它与 F3 合谋**：容器死亡时 LLM 不可达，而 F3 的 fail-open 会把「无法裁决」呈现为「无命中 → 通过」，即**一次环境事故会伪装成一个更好的评测结果**。P2 因此不只是「证据完整性」修复，而是本实验防止「基础设施故障被计入指标」的必要条件。运行期间的防护见 §4.1。
8. **评测镜像对 HIGH/MEDIUM 不敏感，而生产语义对它敏感（本次核对代码时发现）**：

   > **勘误二（2026-09-23，编写接入 spec 时复核代码发现）**：本条初稿把生产消费的 `Passed` 写成 `verifier.go:160-178` 的 `report.Passed`（`highCount == 0`，MEDIUM 不拦截）。**错**——生产消费的是 `audit.go:283-295` 的 `AuditReport.Conclusion.Passed`，其 `gate` 分支为 `High == 0 && Medium == 0`，**MEDIUM 也拦截**；`High == 0`（MEDIUM 不拦截）是 **`assist`** 分支的行为，而生产**默认策略就是 `assist`**。下方第 2 点与 M3 结论按此重写。

   - **生产实际消费的判定**（`internal/controller/import_processing.go:645` 取 `audit.Conclusion.Passed`，定义在 `internal/codeaudit/audit.go:283-295`）：
     ```go
     case "gate":   passed = stats.High == 0 && stats.Medium == 0   // MEDIUM 也拦截
     default:       passed = stats.High == 0                        // assist：只拦 HIGH
     ```
     拦截门槛**取决于 `llm.policy`**，生产默认 `assist`（`config.go:254`），本轮评测跑的是 `--policy gate`。
   - **生产内部存在一处不一致（须记录并在接入 spec 处理）**：`internal/codeaudit/verifier.go:160-178`（`recalculatePassed`，注释自称 gate 分支）写 `report.Passed = highCount == 0`，即 MEDIUM 不拦截，**与 `audit.go` 的 gate 语义相反**。因生产消费 `audit.go` 的值，该分歧目前被遮蔽，但同一个 `"gate"` 在同一个包内有两种含义，属潜在缺陷。
   - 评测镜像（`models/audit/tools/audit_benchmark_eval.py:718-755`）把 `gate`/`assist` 实现为两个分支：`gate` 分支**不看 severity**（有非 `BENIGN` 裁决或 `llm_unavailable`/`parse_error` 即拦截），`assist` 分支看 severity（拦 `CRITICAL`/`HIGH`）。本轮跑前者，故镜像在 `gate` 下 severity-blind。
   - 后果：**本评测无法分辨「一条规则能否拦截」这一生产语义**——而这正是 severity 在生产中的唯一作用。因此：
     1. 报告的 PASS **不覆盖 severity 敏感的行为**；P0 的 severity 镜像（§3）是为了让两臂的规则元数据一致，其生产后果不属本轮证据范围。
     2. 若样本集里出现「MEDIUM 规则命中真实攻击」的情形，两臂在评测中都会拦截，而**生产 `assist` 下两臂都不会拦截**——这会**高估**两臂的召回（`gate` 下不会，见下）。~~当前语料中 M1–M5 的主攻击规则均为 HIGH（`rules.go` 中仅 `FIL_001`/`DYN_001`/`ENV_001`/`EMB_003` 为 MEDIUM），故该风险的暴露面限于这四条规则~~ **——该论断已被实测推翻，见下。**
     3. 修复评测镜像使其与生产语义一致，属**评测资产**改动且会改变历史可比性，须单独立项、对两臂同时施加并重新测量（见 §12.4）。

   **实测（`tests/test_corpus_gate_semantics.py`，固化为可复跑用例，产出 `gate-semantics-audit.json`）**：上文按规则清单**推断**「主攻击规则均为 HIGH」是**错的**。逐样本按「最强命中 severity 是否达到 `gate` 的拦截门槛」分桶：

   | family | blocking | non_blocking | not_flagged |
   |---|---|---|---|
   | M1 / M2 / M4 / M5 | 10 / 10 / 10 / 10 | 0 | 0 |
   | **M3** | **0** | **10** | 0 |
   | B1 / B5 | 0 | 0 | 10 / 10 |
   | B2 / B3 | 0 | 10 / 10 | 0 |
   | B4 | 6 | 2 | 2 |

   - **M3 全族 10 个样本的命中只有 MEDIUM**（`ENV_001`/`FIL_001`，即 M3 的 `expected_severity="MEDIUM"` 所声明者）——**这是语料的有意设计**（secret_theft 家族），不是缺陷。

     > **勘误三（2026-09-23，用真实 Go 函数复核后发现）**：本点初版称「M3 在生产默认 `assist` 下不拦截（实为 FN），故绝对 recall 高估上限 0.20」。**错。实测：M3 在 `assist` 下 10/10 全部拦截**，六轮无例外，逐样本 `classified_high == 1`。根因是 `ClassifyFindingRisk`（`internal/codeaudit/audit.go:191-231`）**让 LLM 裁决覆盖静态严重度**（`MALICIOUS`→HIGH、`SUSPICIOUS`→MEDIUM、`BENIGN`→LOW），而 M3 的 MEDIUM 命中被判为 `MALICIOUS` → 分类 HIGH → `assist` 照样拦。**「高估 0.20」不存在。** 下一段的三个 FPR 数字同样作废（见勘误三续）。

   - **良性侧同理**：~~28 个被镜像拦截的良性样本中，20 个（B2/B3 全族）只有 MEDIUM、2 个（B4）只有 MEDIUM、6 个（B4）有 HIGH。故被拦截的良性样本数：镜像 28（FPR 0.56）> 生产 `gate` ≈26（≈0.52）> 生产 `assist` 6（0.12）。镜像的 FPR 高于两种生产策略，可读作上界，但它对 `assist` 的高估远大于对 `gate` 的高估。两向都等量作用在两臂上（规则集相同），**故不改变两臂之差**，只改变**绝对值**的解释。~~

     > **勘误三续（实测替换）**：生产实测（`TAA_PRODUCTION_GATE=1 go test ./internal/codeaudit/ -run TestProductionGateSemantics -v`，产出 `models/audit/audit-results/engine-compare/production-gate-semantics.json`）：
     >
     > | 轮次 | `gate` FPR | `gate` recall | `assist` FPR | `assist` recall |
     > |---|---|---|---|---|
     > | regex-run1/2/3 | 0.5600 | 1.0000 | **0.5200** | 1.0000 |
     > | semgrep-run1/2/3 | 0.5600 | 1.0000 | **0.5600** | 1.0000 |
     >
     > 即 **`gate` 不是 ≈0.52 而是 0.5600（与评测镜像逐位相同）；`assist` 不是 0.12（6 个）而是 0.52 / 0.56（26 / 28 个良性样本）**。
     >
     > ⚠️ **更要紧的是最后一句「故不改变两臂之差」也是错的**：`gate` 下两臂确实逐样本相同，但**`assist` 下不同**——三对均为 `ΔFPR = +0.04`、方向一致。原因是 `gate` 拦任何非 `BENIGN` 裁决（六轮 `BENIGN` 出现 0 次），**对裁决结构性失明**，而两臂真正的差异恰恰全在裁决里（8–10 个样本/对的 `(rule, severity, verdict)` 多重集不同，finding 集合本身相同）。**按本 spec §5.3 的 0 容差，在生产默认策略下这是 FAIL。** 完整机制、根因（两臂 Prompt 的上下文形态不同：semgrep 臂 `ast_enclosing_block` 替换 `ctx_before`，regex 臂给 ±N 行窗口）与复跑方法见报告 §7.13。
     >
     > **对本 spec §5.3 判定规则的影响**：判定规则本身不改（0 容差照旧），但**「用哪个策略判定」必须与「生产默认策略」一致**。本轮用 `--policy gate`，生产默认 `assist`，两者在本语料上给出**相反**的两臂结论。后续任何引擎对比**须在 `assist` 下判定**，或在两策略下**分别**给出结论。
   - 另一个副产品（对判定有用）：**`malicious_not_flagged = 0`**，50 个恶意样本**全部**被静态臂命中。因此静态臂 recall = 1.0，任何 recall < 1.0 都来自 **LLM 把恶意样本开脱为 BENIGN**，而不是静态漏报。`benign_not_flagged = 22` 与运行里 22 个 bypass 独立吻合，两者互为交叉校验。


9. **零差异有一部分是构造出来的，且语料是被拟合过的集合（本轮最重要的解释性限制）**：阶段 3 的规则对齐（P0-bis）是**以本语料与 59 条 fixture 为参照**把 semgrep 规则逐条镜像到 regex 基线上做的，`EMB_001` 的过报也是由**本语料**的全量审计抓出并修掉的。因此 6 次运行若给出 `ΔFPR = Δrecall = 0`，它证明的是：
   - **对齐在完整链路上成立**——规则级的一致性没有被下游（LLM 仲裁、`gate` 策略、判定口径）放大成判定级差异，且 3 次重复稳定；
   - **不是**「semgrep 检测能力优于/劣于 regex」。本轮**不产出任何关于检测能力的比较结论**，因为两臂在语料上的差异已被先行消除。
   
   更关键的是：**`audit-100` 是拟合集（fitting set），不是留出集（held-out set）**。非劣性主张因此限于「在规则对齐所依据的语料上无退化」，**不覆盖未参与对齐的代码**。把本报告的 PASS 读成「semgrep 可安全替换 regex」在**未见过的新代码上**是没有证据的——规则移植的漏报（如 F5 类语义丢失）恰恰只会在未见构造上暴露。要支撑后者需要留出集，见 §12。

10. **LLM 回复解析失败会在良性样本上制造 FP（采集期间实测发现，本条是「可造出假 FAIL」的两条通道之一）**

    机制（在证据层确认，非推断）：模型把 finding 的 `code_snippet` **原样**写进回复 JSON 的 `reason` 字段而不转义内层双引号，例如
    `"reason": "代码片段中使用 \`subprocess.run\` 执行 \`sh -c "cat {target}"\`，..."` —— 该 JSON 非法。解析器 `extract_json_response`（`code_security_analyzer.py:321-350`）已尝试剥 markdown 围栏（`:333`）与取最外层花括号（`:342`），但两者都救不回**非法** JSON，故围栏不是根因。失败后该 finding 得 `llm_verdict=UNCERTAIN` → **fail-closed 保留静态命中**。

    暴露面（实测，`regex-run2` 的 78 个有命中样本）：finding 的 `code_snippet` **含双引号者 56 个**（恶意 40 / **良性 16**）；实际发生解析失败者 4 个（M1-04、M1-09、M5-02、M5-07，全在这 56 内）。即**双引号是必要条件、非充分条件**——真正的风险池是 56 而非「失败的 4 个」，且**其中 16 个是良性的**。

    为什么它威胁判定而非仅影响噪声水平：
    - **恶意样本上无害**：fail-closed 后命中仍在，仍计 TP（这也解释了 `fn=0`）。
    - **良性样本上有害**：`UNCERTAIN` **不等于** `BENIGN`，命中不被开脱 → 被记为 FP。这与「LLM 判定为恶意」在指标上无法区分，但**原因与引擎无关**。
    - 两臂共用同一 LLM 与同一解析器、finding 集合又已对齐（§11），因此该机制对两臂暴露**相同**，产生的是**噪声而非偏倚**。但噪声可朝任一方向推动 `ΔFPR`：若某 pair 中它落在 semgrep 臂而未落在 regex 臂，`ΔFPR > 0` → **判 FAIL，而根因不是引擎**。反之亦然。**一次即可翻转判定**（§5.3 为 0 容差）。

    实测的失败集合逐轮漂移（regex 2/4、semgrep 2/1），且 `--llm-seed 42` **不能**让它复现——同一输入（M5-02，finding 完全相同）在 semgrep-run1 为 `ok`、在 regex-run2 为 `parse_error`。故「三轮为同一分布的抽样」而非「逐字节重复」。

    **本轮已量到的最强形式（可核验）**：6 轮中**良性 `fail_closed` 计数为 0**，全部失败样本均为恶意。因此已量到的 FPR 与 `ΔFPR` **未被这条机制污染**；这是运气好的事实，不是保证。

    报告须披露上表与逐轮失败集合，并注明：**若某个 pair 出现 `ΔFPR > 0`，第一件事是查该 pair 的良性样本里有没有 fail-closed 的**，再谈引擎归因。修复见 §12.6（属评测资产改动，须两臂同时施加并重测全部 6 轮）。

11. **第二条通道：LLM 调用超时（6 轮跑完后复核样本行时发现，本条修正第 10 条的「唯一」措辞）**

    第 10 条把「fail-closed 制造伪 FP」单一归因为**解析**失败。复核 6 轮 16 次 fail-closed 的逐样本 `llm_state` 后可知，其中 **14 次是 `parse_error`、2 次是 `llm_unavailable`**：`semgrep-run3` 的 M1-02（91.7 s）与 M4-08（120.1 s），finding 级 `llm_reason` 为 **`ollama 调用失败: timed out`**，即撞上 `code_security_analyzer.py:707` 的 `urlopen(..., timeout=60)`。

    三条须登记的结论：

    - **后果与通道无关，判据不同**：两条通道都以 `UNCERTAIN` 收尾，都由 fail-closed 保留静态命中，对指标的威胁**完全相同**；区分它们只能看 `llm_reason` 含「调用失败」还是「无法解析」。故 §12.6 的修复若只处理 JSON 转义，**这条通道仍然敞开**。
    - **它不是容器死亡，是推理停摆**：该轮容器 `RestartCount=0`、`StartedAt` 未变，而 LLM 已不可用。**「容器存活」不足以证明「LLM 健康」**——§4.2 原本把「校验 ollama 存活与 digest 一致」当作运行期健康检查，该检查太弱，须补上逐样本 `llm_state` 复核（本轮已由 `fail_closed_by_run` 派生）。
    - **该轮恰是扫描成本最高的一轮**，与 §9.7 记录的「全量 semgrep 扫描 + 容器内 ollama 不能共存」同源，只是后果轻一档。这提示**引擎替换的真实代价不只是 +53% 时长，还包括对同机 LLM 的可用性挤压**——生产环境若 LLM 与被审计代码同机，此点须独立评估。

---

## 10. 交付物清单

- 前置修复的代码与测试（P0、P1、P2、P3；P4 待确认）及各自提交。
- `models/audit/audit-results/engine-compare/{regex,semgrep}-run{1,2,3}/` 原始产物（含逐样本行、`audit_report.json`、summary）。
- `models/audit/audit-results/engine-compare/REPORT.md`（第 6 节结构）。
- 本规范的实现计划：`.claude/plans/`（由 writing-plans 产出）。

**落盘注意（实测）**：`models/` 与 `models/audit/audit-results/` 都在 `.gitignore` 中，`models/audit/semgrep/rules/*/rules.yaml` 是既有的 **force-tracked** 文件（同 `.claude/specs/`）。因此 `REPORT.md` 与原始产物提交时必须 `git add -f`，否则会静默漏提交——这正是 P4 关注的「证据与结论脱钩」的另一条现实路径。

**另一条卫生问题（本轮发现，未修）**：每次运行评测器都会把 `models/audit/audit-benchmark-manifest.json` 的 `benchmark_root` 从相对路径改写成**绝对路径**（`/home/hjy/taa/...`），使每次运行都污染一个已跟踪文件。6 次正式运行会重复 6 次。属独立小缺陷，本轮不做（不属 P0–P4），但运行后须 `git checkout --` 该文件，且不要把它误提交。

---

## 11. 两臂规则集差异登记（§4.3 第 4 项审计的实测产出）

**2026-09-22 全量行为审计实测结果：100 个样本中 44 个文件存在两臂 `rule_id` 集合差异，涉及 7 条规则。差异不是空的。**

`FIL_001`（P0 修复的对象）**已不在差异清单中**——P0 的逐条镜像使它在 100 个样本上与 regex 完全一致，可作为「镜像法有效」的正面验证。

### 11.1 差异清单

| 规则 | 方向 | 样本数 | 实测根因 |
|---|---|---|---|
| `CMD_001` | **semgrep 漏报** | 2（M1-02, M1-07） | semgrep 要求 `shell=True`；基线另有「列表形式且首元素为 `bash`/`sh`/…」分支。M1-02 实际代码为 `subprocess.check_output(["bash", "-c", "whoami"])`。基线还覆盖 `os.exec*`、`commands.getoutput`，semgrep 完全没有。 |
| `NET_001` | **semgrep 漏报** | 4（M2-04, 05, 09, 10） | 基线含 `httpx\.(get\|post\|put\|delete)`，semgrep 的 `NET_001` 无 `httpx`。M2-04 为 `httpx.post("https://collector.example.invalid/report", ...)`。基线还覆盖 `urllib.request.urlretrieve`、`http.client.HTTPSConnection`、`httplib2`，semgrep 均无。 |
| `OBF_001` | **semgrep 漏报（结构性）** | 8（M4-01/03/04/05/06/08, M4-02/07） | **两臂规则形态根本不同**：基线是「用了 `base64.b64decode`/`pickle.loads`/`marshal`/`codecs.decode`/`binascii` 任一即报」；semgrep 把它写成了 **taint 规则**（source=解码 API，sink=`eval`/`exec`）。因此「解码后**外传**而非执行」的样本对 taint 规则完全不可见——M4-01 正是 `return base64.b64decode(encoded.encode("utf-8"))`，其 ground truth 同时标注 `OBF_001` 与 `EXF_001`。 |
| `PER_001` | **semgrep 漏报** | 10（M5-01…M5-06 等） | M5-01 为 `target = Path("/tmp/.../.bashrc")` 后 `target.open("a")`：基线匹配**路径构造行**，semgrep 要求**同一次调用**上同时满足路径谓词与模式谓词（`open($PATH, $MODE)`），两者不重合。 |
| `EMB_003` | regex 独有 | 12（全为良性：B2-*, B4-04） | semgrep 的 `EMB_003` 是三条**字面**模式（`print(raw_data)`、`print(features)`、`logging.info(f"...{raw_data}...")`），本质是「匹配变量名」；基线是宽正则。**良性侧方向对 semgrep 有利（regex 误报）。** |
| `EMB_002` | 双向 | 4（良性） | semgrep 独有于 B4-03/B4-08，regex 独有于 B4-05/B4-10，均为写入/拷贝形态差异；两侧皆良性。 |
| `EMB_004` | semgrep 独有 | 2（M4-02, M4-07） | semgrep 报 `struct.pack`/`b64encode`，regex 在同一样本上报 `OBF_001`。**同一攻击的规则归属不同，不是检出差异。** |

### 11.2 对判定的影响（为什么必须在矩阵之前修）

- 上述四条**漏报规则全部落在恶意样本上**，且 `M1-02`/`M2-04`/`M4-01`/`M5-01` 的 ground truth `primary_attack_finding` **恰好就是被漏掉的那条规则**。`attribution_precision` 的定义要求主攻击规则被触发，因此这是**归因精度的系统性损失**，不只是 recall。
- 若直接开跑矩阵，几乎必然得到 `Δrecall < 0` 的 FAIL，而其根因是**规则集差异而非引擎差异**——即 §9.1/§9.5 早已登记的那个混淆，正是本审计要拦下的东西。
- 因此按 §8「若 FAIL 且根因是规则语义缺陷：先修规则、重跑」的预案，**把规则对齐提前到矩阵之前执行**（记为 P0-bis），并以「全量审计差异归零」作为它的验收门槛。

### 11.3 已知的规则集非等价性（无法通过镜像消除）

基线是**行级正则**（`re.search` 逐行），semgrep 是 **AST 模式**。即使逐条镜像，两者仍会在跨行书写、括号嵌套、别名导入等情况下分叉。**这是「引擎差异」与「规则集差异」无法完全分离的根本来源，必须在报告中显式披露，不得归因给任一方。** §4.3 第 4 项的审计正是用来量化这一残余差异的工具。

### 11.4 `OBF_001` 镜像的代价（须披露）

忠实镜像基线意味着把 `OBF_001` 从 taint 规则**退化为搜索规则**（匹配解码 API 的使用），因为基线的语义就是「使用即报」。这会丢失 taint 版本的真实优势（只报「解码后进入执行」的高置信组合、对良性 base64 使用更宽容）。

本规范选择镜像，理由是**判定的是引擎而非规则质量**；在非劣性成立之前引入规则改进，会使结论无法归因。**taint 版 `OBF_001` 是更好的规则，应作为非劣性结论产出之后的独立改进项，且必须对两臂同时施加、重新测量。**

### 11.5 P0-bis：规则集对齐（已完成）

§11.2 的结论是「必须在矩阵之前修」。实际执行时，审计暴露的差异比 §11.1 的语料清单更广——语料只覆盖了「语料里恰好出现的写法」，因此新增了一个**差分一致性测试**来把「两臂规则语义等价」变成可执行断言：

- `tests/test_engine_rule_parity.py`：50 个夹具，期望值**由 regex 臂自身算出**（不手写），逐文件比对两臂的 `rule_id` 集合。因为 `StaticScanner` 是「每行首条命中优先」而 semgrep 报出全部命中，比对前把 semgrep 结果按 `SUSPICIOUS_PATTERNS` 顺序折叠成同样的形态——那是扫描器外壳的差异，不是规则集的差异；但**基线完全没有报出的构造仍是差异**，这正是该测试要抓的。
- **RED 实测：30/50 夹具不一致**，且失败原因全部是规则语义（无拼写类失败）。它比语料审计多抓出 `cmd_os_exec`、`cmd_check_call_shell`、`cmd_plain_popen`（semgrep 过报）、`net_http_client`、`net_httplib2`、`emb_rename_*`、`per_crontab`、`per_etc_initd`、`per_etc_systemd`、`per_systemctl_enable`、`emb_stdout_write_*` 等语料中未出现的缺口。
- **修复**：7 条规则逐条对齐（CMD_001 / NET_001 / OBF_001 / PER_001 / EMB_002 / EMB_003 / EMB_004）。其中 PER_001 与 EMB_004 的部分分支改用 `pattern-regex`——**因为基线本身就是纯文本正则**，用 AST 模式表达反而会引入基线没有的约束（PER_001 原先要求 `open($PATH, $MODE)` 且模式为写，而基线只搜文本）。
- **GREEN 实测**：50/50 夹具一致；规则数仍为 python 13，`semgrep` 解析 `parser_errors=0`。
- **两处既有夹具断言被改写**（`tests/test_semgrep_rule_fixtures.py`）：`test_per_001_persistence` 与 `test_emb_004_stego` 原先断言的是**旧 semgrep 规则独有的行为**（`/etc/cron.d/`、`struct.pack`），基线并不覆盖。按 P0 对 `/etc/shadow` 的同一原则，夹具改为两臂共享的构造，缺口登记进 §12.3——**不在受测臂单方面加强检测**。

### 11.6 P0-bis 第二轮：语料审计抓出的 `EMB_001` 过报

§7 第 5 步要求 P0-bis 之后**重跑** §4.3 第 4 项。重跑结果**仍未归零**：100 个样本中 75 个仍有差异，且全部是同一条构造——

```
train.py:99   torch.save(saved_weights, checkpoint_file)
train.py:105  torch.save(detector_state, checkpoint_file)
```

semgrep 报 `EMB_001`，regex 不报。**`EMB_001` 是 HIGH**，按 §9.8 的生产 `gate` 语义，HIGH 会被 LLM 判 `BENIGN` 才放行——75 个样本（其中大多数是良性）带上了一条基线没有的 HIGH 命中。

**根因**：`taa-emb-data-dump-python` 被移植成 `pattern: torch.save($DATA, $PATH)` 加两条否定模式（排除 `state_dict()` 与 `model.pt`）。而基线的谓词是**对载荷参数的名称清单**：`(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train)\b`。丢掉名称清单后，该规则对**任何** checkpoint 写入都命中。基线另外四条分支（`np.save`、`np.savez`、`shutil.copy`、`shutil.copytree`）在 semgrep 侧**完全不存在**。

**为什么夹具测试没抓到**：`EMB_001` 当时只有一个夹具，且是**否定**夹具（`torch.save(model.state_dict(), 'model.pt')`）——没有肯定夹具，也没有「首个实参不是数据名」的否定夹具。这是「夹具测试与语料审计不可互相替代」的具体证据：夹具测试对**有人枚举到的构造**精确，语料审计覆盖**基准真正打分的样本**。两者都必须保留。

**RED**：补 9 个 `EMB_001` 夹具后 **4/59 不一致**——`np.save`/`np.savez` 为 regex 独有，`saved_weights`/`detector_state` 为 semgrep 独有，与语料审计完全对应。

**修复**：`EMB_001` 改写为基线五条模式的 `pattern-regex` 镜像。用 `[^)\n]` 而非 `[^)]`：Python `re` 的 `.` 本就不跨行，但 `[^)]` **会跨行**，那样 semgrep 的匹配边界就比基线的逐行 `re.search` 宽（同理适用于 §11.5 的 `EMB_001` 各分支）。

**GREEN**：夹具 **59/59** 一致；语料审计 **100/100 样本、差异归零**。

**两处门槛都补了「空集通过」防护**：两个空命中列表天然相等，因此若扫描器根本没跑起来，比对会静默通过。现在两个测试都断言**对照臂确实有命中**（夹具测试要求过半夹具被基线命中，语料测试要求两臂全语料命中数 > 0）。

**§4.3 第 4 项的审计已固化为可复跑的用例**：`tests/test_engine_rule_parity_corpus.py`，用 `TAA_CORPUS_PARITY=1` 显式开启（全语料 semgrep 扫描耗时数十秒且需 semgrep 可用，不适合进默认套件）。此前的审计是一次性脚本，产物只存在于对话记录里——**证据应当可复跑，而不是可引用**。

### 11.7 P2-bis：冒烟门槛第 2 项抓出的 `confusion_counts` 失效开放

§4.3 第 2 项要求「人为制造失败，确认样本行出现 `scan_complete=false` **且被汇总计数捕获**」。实测时样本行**是对的**（4 行全部 `scan_complete=False`、`bypass=False`、`scan_error` 记录到 semgrep 不在 PATH），但汇总暴露了一个 P2 没修完的缺口：

```
counts: {'tp': 0, 'fp': 0, 'tn': 4, 'fn': 0}
accuracy: 1.0
scan_incomplete_count: 4   scan_error_count: 4
```

**四个样本一个都没扫，却被记成 4 个真阴性、accuracy 1.0。** 根因：`confusion_counts`（`audit_benchmark_eval.py`）无条件遍历 `results`，而 §5.3 第 3 条明确要求「`incomplete` 归零之前，该轮结果**不得进入判定与指标计算**」。**这是代码与 §5.3 的分歧**，与 §9.8 同类：spec 早已写下正确语义，实现没有兑现。

**为什么这个缺口必须在开矩阵前修**：它**只对受测臂有利，且方向恰好落在判定轴上**。

- semgrep 臂是两臂中**唯一可能 incomplete** 的一臂（regex 臂是同步纯内存正则，`scan_complete` 恒为 True，见 `RegexScannerAdapter`）。
- 「扫不动 → 空命中 → 记 TN」**降低 FPR**。而 `ΔFPR ≤ 0` 正是通过条件之一：扫描器挂掉会**把人推向 PASS**。
- 同一时刻 recall 因 FN 上升而**变差**，但 `scan_incomplete_count` 只是个并列计数、不拦任何数字，报告里没有任何一处会因此中断。

因此它属于 §9「防故障伪装成好结果」这一类失效，而不是一个统计口径瑕疵。

**修复**：`confusion_counts` 只对 `scored_rows()`（`scan_complete` 为真）计数，未扫样本**不落入任何格子**，而非默认成某个格子（`scan_is_scored`/`scored_rows` 两个单点函数）。bootstrap 区间走的是同一函数，因此一并被修正。

**丢弃行不能是静默的**（否则会变成另一种误报——96 个样本的混淆矩阵与 100 个样本的读起来完全一样）：

- `metric_summary` 增 `scored_count`，与 `scan_incomplete_count` 并列；
- `build_summary_report` 增 `round_complete`（任一 `scan_complete=false` 即为 False）；
- `final-report.md` 在 `round_complete=False` 时**首屏**给出作废横幅（含 `x / N` 未完成数）；
- `confusion-matrix.json` 在作废轮次落**全零**，而非「扣掉失败样本后的结果」。

**RED**：新增 `TestIncompleteScansStayOutOfTheScore` 7 条，6 条红且原因正确（3 条断言未扫样本不占格子、1 条断言 `scored_count`、2 条断言 `round_complete`）。第 7 条 `test_a_scanned_row_is_still_scored` 是**反向守卫**：排除必须键在 `scan_complete` 上，而不是「有没有 label」之类的近似条件。

**GREEN**：15/15 通过；同一条注入失败的命令重跑，`round_complete=False`、`counts` 全零、`scored_count: 0`、`final-report.md` 首屏为作废横幅。

---

### 11.8 阶段 6 的分析器：为什么不是手抄数字，以及它自己被抓到的两处缺陷

§6 的报告要引用配对判定的每一个数字（Δ、CI、McNemar p、不一致样本清单、family 归因）。这些数字**不手抄**，而由 `models/audit/tools/engine_compare_report.py` 从 6 个运行目录直接算出并落盘 `paired-analysis.json`（26 条测试）。理由与 §4.3 第 4 项把语料审计固化成用例相同：**证据要被重跑，而不是被引用**——手抄的数字一旦与原始产物脱钩，报告引用的就只是一个无法追溯的副本，这正是 P4（§11.2）关注的失效模式。

**该模块的两条硬规则**（也是它的测试所钉住的）：

- 某臂未扫完的样本**不参与配对**——未扫样本没有裁决可比，把它和另一臂的真实裁决配对，等于把基础设施故障记成检测差异；
- 一对运行只要有一侧不完整即为**作废**，作废对产出「证据不足」而非宽松解读；**缺失或半写完的运行目录**同样产出「证据不足」而不是抛异常、也不是静默地按 5 轮分析（有专门用例：删掉 `semgrep-run3` 后判为「证据不足」且原因含 `pair 3`）。

**两处缺陷（在写报告之前自查发现并修掉，见提交 `06c2c37`）**：

1. **`PairOutcome` 的 `duration_regex`/`duration_semgrep` 字段声明了却从未被赋值**，序列化出来恒为 `0.0`。§6 要求报告披露「运行时长差异」，而这个字段正是它的载体——**一个恒读 0 的字段比没有字段更糟**：它看起来像一次「两臂一样快」的测量，而实际是没测。修复：`pair_runs` 接收两臂时长，差值在 dataclass 上单点导出，序列化时并入（`asdict` 会丢掉 property）。
2. **`runs_meta` 只带整轮 `eval_duration_sec`**，因此分析层无法分离两项成本——这正是 §11.5/阶段 3.5 在评测器里刚修好的缺口，在上一层被重新造了一遍。修复：透出 `per_sample_scan_sec`/`per_sample_llm_sec`/`llm_sample_count`/`scan_error_count`/`scored_count`。

**为什么这两处是被「核对写入方」而不是被 fixture 抓到的**：`TestAnalyseAllRuns` 的 `_write_run` 自己造 `summary.json`，于是它验证的是「读取方 vs 我以为的写入方」，**写入方换了键名它照样全绿**。两处都是拿 `build_summary_report`/`metric_summary` 的真实返回键去核才发现。教训与 §4.3 第 1 项同类：**测试自己构造输入时，它验证不了与真实生产方的一致性**。修复后新增的 2 条用例把时长设为两臂**不同值**（10.0 / 42.0），因为相同值分不清「接线正确」与「两边都取到默认 0」。

**在途运行的表现（顺带验证）**：`regex-run1` 跑到一半时对其调用 `analyse_all`，得到 `verdict: 证据不足`、原因 `pair N: no sample was scored by both arms`——因为逐样本行只在整轮结束时落盘。**在途运行不是证据**，这正是设计意图。

---

## 12. 后续事项（不在本轮范围）

1. **`/etc/shadow` 等敏感路径的规则覆盖缺口（两臂共享）**：基线谓词仅含 `\.ssh|\.env|password|credential|\.aws|\.kube|id_rsa|authorized_keys`，不覆盖 `/etc/shadow`、`/etc/passwd`、`.netrc`、`.docker/config.json` 等凭据目标。这是**规则质量**问题而非**引擎**问题，对两臂同等成立，因此应在两臂上**同时**修订（同一改动、同一轮重新测量），而不是在 semgrep 臂单方面加强。建议单独立项。
2. **行级正则 vs AST 的结构性差异**（见 §11.3）：若要分离二者贡献，走 §8 的 CPG 消融预案。
3. **P0-bis 期间新发现的共享规则缺口（两臂共享，均为「基线正则写窄了」）**：
   - `PER_001` 的 `crontab` 是**裸词**，不覆盖 `/etc/cron.d/`、`/etc/cron.d`、`/etc/cron.daily/`（只有 `/etc/crontab` 含该子串）。旧 semgrep 规则用 `/etc/cron` 前缀覆盖了这些，本次对齐**按其基线语义**取消了该覆盖。
   - `EMB_004` 的五条模式均不含 `struct.pack`，旧 semgrep 规则单列了它。
   - `EMB_001` 的 `shutil.copy`/`shutil.copytree` 两条模式以 `\b` 收尾，因此 `shutil.copy(dataset_path, ...)` **不匹配**——`dataset` 后的 `_` 是词字符，`\b` 不成立。四条命名的兄弟分支（`torch.save`、`np.save`、`np.savez`）有同样的问题。两臂在这一构造上**一致地漏报**，故不属差异清单，但意味着这两条模式在实践中几乎只在实参恰好是裸词（`shutil.copy(data, …)`）时才生效。夹具 `emb_shutil_copy_dataset_path.py` 已把该行为钉住，防止有人只在 semgrep 臂「顺手修好」。
   - 以上与 §12.1 同类：**对两臂同等成立**，须同时修订。取消 semgrep 臂的额外覆盖是本轮的**有意决定**——若保留，受测臂就携带了一项对照组没有的检测能力，PASS 将无法归因。
4. **评测镜像的 `gate` 语义与生产不一致**（见 §9.8）：镜像的 `gate` 分支对 HIGH/MEDIUM 一视同仁（severity-blind），生产 `gate` 则要求 `High == 0 && Medium == 0`——**两者效果接近但机制不同**；而生产**默认策略是 `assist`**（只拦 HIGH），此时差异很大（实测 FPR 0.5600 对 0.5200/0.5600，见 §9.8 勘误三续——**初稿写的「0.56 对 0.12」是错的**）。修复它属评测资产改动、会改变历史可比性，须单独立项并对两臂同时施加后重新测量。
4b. **【高优先】判定策略须与生产默认策略一致**（见 §9.8 勘误三续、报告 §7.13）：本轮用 `--policy gate` 判定，而 `gate` 对 LLM 裁决**结构性失明**（拦任何非 `BENIGN`），因此它读不出两臂真正的差异——那些差异全在裁决里。实测结果：`gate` 下三对 `ΔFPR = 0`（PASS），**`assist` 下三对 `ΔFPR = +0.04` 同向（FAIL）**。同一份数据、同一批样本，策略一换结论相反。**任何后续引擎对比都须在 `assist` 下判定，或两策略分别给出结论**；本轮的 PASS **只能**读作「`gate` 策略下非劣」。此项优先级高于第 4 项，因为它改变的是判定的**适用范围**而非镜像的实现细节。
5. **留出集（held-out set）**（见 §9.9，本轮最重要缺口）：本轮的非劣性主张只在「规则对齐所依据的语料」上成立，而规则移植的漏报恰恰只在**未参与对齐的构造**上暴露。需要一份**不参与任何规则调整**的样本集——在规则冻结之后生成、且生成后不对规则做任何修改——才能把结论从「无退化」推进到「可替换」。这是把 NULL 结果（Δ=0）变成有意义主张的唯一途径，也是本轮**不应**声称已完成的下一步。
6. **LLM 不可用制造 FP 的通道（本轮采集期间实测发现，见 §9.10 第 10、11 条）**：两条通道后果相同、判据不同——**解析失败**（含双引号的 `code_snippet` 原样写进 JSON 字符串值而不转义 → JSON 非法）与 **调用超时**（`urlopen(..., timeout=60)` 撞上限）。两者都以 `UNCERTAIN` 收尾、都由 fail-closed 保留静态命中。恶意样本上无害（仍是 TP），但**良性样本上会凭空造出 FP**，而这不是引擎差异。两臂暴露相同（finding 集合已对齐），故为噪声非偏倚；但噪声可朝任一方向推动 ΔFPR，**足以造出假 FAIL**。
   - 修复属评测资产改动（如容错解析 / 转义修复 / 超时与重试策略），按 §12.4 的同一规则：须**同时**施加于两臂并**重新测量全部 6 轮**，不能只修一侧或只补跑个别轮次。建议单独立项。**两条通道须一并处理**——只修 JSON 转义会让超时通道继续敞开。
   - 本轮**不做**此修复，理由是采集已进行到第 5 轮，改动会使已完成的轮次与后续轮次不可比。
   - 报告须披露：风险池为 56 个样本（良性 16 / 恶意 40），6 轮实测 16 次 fail-closed（14 解析失败 + 2 超时，0–4 次/轮），且**6 轮中良性 fail_closed 计数为 0**（这是"已量到的 FPR 未被污染"的**最强形式**，可核验）。

---

## 13. 处置决定（原「待确认事项」，已定）

1. **P4 的处置方式**：采纳 **(a)** —— 加 `provenance` 字段并把 `engine` 改为必填显式入参。理由：`generate_matrix_results.py` 的 `tp/fp/tn/fn` 全部来自硬编码 `MODELS_SPEC`，它写出的 `summary.json` 与真实评测产物同形同址，而 `engine`/`rule_set_version` 原先由 **mode 名称**推断（`engine = "semgrep" if mode_name == "static-llm" else "none"`），于是「没人声称过 semgrep」也能落成 `engine: "semgrep"`。(b) 只是标注弃用，不阻止引用，挡不住这个风险。
   - 实施：`PROVENANCE = "hand-authored-spec"` 写入每条 run 与主汇总（含落盘的 per-run `summary.json`——**被引用的是它**）；`generate_matrix(track_declarations, …)` 的首个参数**必填无默认值**，缺省即 `TypeError`；声明必须覆盖三个 mode 且各自给出 `engine` 与 `rule_set_version`，否则 `ValueError`；CLI 新增**必填可重复**的 `--track MODE:ENGINE:RULE_SET_VERSION`，`main` 不再自行填值。
   - `rule_set_version` 一并去除推断：它是断言「这些数字出自 13 条 semgrep 规则」的字段，只修 `engine` 会把同一个机制留在隔壁一列。
   - 该字段原本**只写不读**（生成器内部无任何消费者），即它的唯一作用就是被引用——这正是需要防的地方。
2. **P2 中 `incomplete` 样本的处置**：维持本文档原定 —— 「不计入 bypass、不参与指标、且该轮作废重跑」（§5.3 第 3 条）。剔除后继续会让配对样本集随失败次数缩水，而判定要求的是「**每一对**都满足非劣」，缩水的样本集支撑不了该主张。
3. **P1–P3 的提交粒度**：**分次提交**，便于单独回滚。（P1 `58de1e8`、P2 `8eb7fe7` 已按此办理；P3 与 P0-bis 各自独立。）
