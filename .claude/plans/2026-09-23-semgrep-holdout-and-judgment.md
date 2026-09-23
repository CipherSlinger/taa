# 阶段 H：留出集非劣验证（实施计划）

- 关联规范：`.claude/specs/2026-09-23-semgrep-engine-integration-design.md` §9（证据门槛）、§10 阶段表 H 行
- 关联证据：`.claude/specs/2026-09-22-semgrep-engine-noninferiority-evidence-design.md`（主基准，拟合集）
- 前置阶段：A–G 已完成并提交（`1c71cd7` 为最后一次）
- 状态：**H1.1 取数普查已完成**（四源状态与实测体量见 §12.1；发现并已裁定两处预登记缺陷，见 §12.2 规则 3/7 与 §13 决策 5/6）；下一步为 **H1.2 建集**

---

## 1. 这一步要解决什么

主基准（`audit-100`）**是拟合集**：规则对齐以它为参照做的（证据 spec §9.9、本规范 §9.1）。因此它的「Δ=0」只支持「在规则对齐所依据的语料上无退化」，**不支持「可在未见过的新代码上替换」**。且同一份数据在 `assist`（生产默认）下给出**相反**结论（ΔFPR 0 → +0.04，本规范 §3.2.2）。

阶段 H 补两件事：**未见构造** + **生产默认策略下的判定**。**通过之前默认引擎保持 `regex`**（本规范 §9 开头）。

## 2. 判定口径（不可协商，来自 §9.2 要求 5/6/7）

| 项 | 取值 |
|---|---|
| 判据 | `ΔFPR ≤ 0` **且** `Δrecall ≥ 0`，**逐对成立** |
| 容差 | **0** |
| 配对 | 3 轮配对（第 *i* 次 regex ↔ 第 *i* 次 semgrep） |
| 主判定策略 | **`assist`**（生产默认，`--policy assist`） |
| 并列报告 | **同时**给出 `gate` 下的数值 |
| 两臂 | 同测 |

> 只报 `gate` 下的通过**不算通过**（§9.4）。这条收紧是从主基准实测里学到的。

## 3. 样本单元：单个 `.py` 文件（附实测理由）

**决定**：Δ 指标用的样本单元 = **一个 `.py` 文件**，不是整个包目录。

**理由（实测，非推测）**：命中密度在真实代码上远高于合成样本（实测 `requests-2.31.0`：`socket` 58 处、`os.environ` 17 处、`import … as` 25 处），而两侧都有「按条数截断」的上限：

- 生产 Go 静态侧 `MaxFindings = 200`（`internal/codeaudit/scanner.go:23`），触顶 → `Truncated = true`（`:97-101`）→ `ProvesCleanScan()` 为假（`internal/codeaudit/rules.go:124`）→ fail-closed。
- 评测侧 `--max-findings` 默认 **50**（`models/audit/tools/audit_benchmark_eval.py:1492`），且只对 `findings[:max_findings]` 调 LLM（`:875`）——**超出的 high/medium finding 永不被开脱 → 直接阻断**（`models/examples/code_security_analyzer.py:863-866`）。

两者都是**按条数而非语义**阻断，而 semgrep「每条匹配都报、regex 每行只报首条」（本规范 §7.4）→ 两臂的截断幅度**不对称** → 整包样本测出来的是截断差异，不是引擎差异。

**因此**：单文件承担 Δ 指标；**大目录/大文件另做 scale 子测量**（§8 的 H2.5）。两条路径用途不得混同。

## 4. 两个臂的来源（你于 2026-09-23 选定：真实第三方源码 + 公开标注语料）

### 4.1 良性臂 = 真实第三方 sdist，**未改一字**

- 来源：真实发布的包（`pip download --no-deps --no-binary :all:`），固定版本号。
- 作者 = 上游社区 → **要求 1 完全满足**：构造与标注都不由我们出。
- 标注：`label=benign`、`expected_final=BENIGN`、`primary_attack_finding=null`。**不做「会不会被报」的判断**——那正是 FPR 要测的量。
- 预登记选取规则见 §12。

### 4.2 恶意臂与近失良性臂 = 三个公开来源（普查已实测）

**已定组合（2026-09-23 你选定）**：semgrep-rules（主力，正例 + `# ok:` 近失负例）+ CodeQL（MIT，显式近失负例）+ DataDog（真实恶意包，补 `PER_001` 等）。

| 来源 | 许可 | 用途 | 关键限制 |
|---|---|---|---|
| `semgrep/semgrep-rules` | Semgrep Rules License v1.0（**仅内部业务使用，禁止再分发/作为服务**） | 恶意正例（1387 条 `# ruleid:`）+ 近失良性（930 条 `# ok:`） | **纯 `# ok:` 文件 = 0**（316/368 是混合）→ **必须窗口抽取** |
| `github/codeql` | **MIT** | 显式近失负例（16 `result=OK` + 11 `SPURIOUS: Alert`） | 负例总量 27，单源不足 50，只作补充与交叉验证 |
| `DataDog/malicious-software-packages-dataset` | **Apache-2.0** | 真实恶意包，补 `PER_001`/`EXF_001`（semgrep-rules 里 `PER_001` 仅 1 文件） | **真实恶意软件**（口令 `infected` 加密 zip）；**无逐行标签、无良性样本** |

**处理真实恶意样本的安全约束（写进构建脚本，不可绕过）**：

1. **只解包与扫描，绝不执行**：不得 `pip install`、不得 `import`、不得运行包内任何脚本（含 setup.py 的 install/develop 钩子——实测样本正是靠它持久化）。
2. 解包落点仅限 gitignored 的语料目录，不进入任何被跟踪路径。
3. 构建脚本不得调用 `py_compile`/`compileall`（评测侧既有测试会做，留出集**不走那条路径**）。
4. 报告中只引用**行为类别与文件路径哈希**，不粘贴恶意代码全文。

**窗口抽取（预登记；窗口口径已于 2026-09-23 按实测修订，见 §12.2 规则 7）**：`# ruleid:` / `# ok:` 的语义是「紧贴其上一行」的逐行 ground truth（出处：semgrep 官方测试文档）。窗口取「**标注行 ± 2 行**」。**原定口径「包含该行的最内层 `def`/`class` 体」被实测推翻**：Python 侧按该口径只有 41/306 条 `ok`、48/448 条 `ruleid` 落在 `def`/`class` 内（AST 测两次一致），89 个窗口里**仅 12 个**映射到我们 13 族——因为绝大多数标注在**模块层**（`ok` 252、`ruleid` 374），而原口径明写「模块层丢弃并计数」。抽取是**机械的**（只按标注行与行号定位，不看我方规则、不看判定结果）。

### 4.3 标注 → 我们规则 ID 的翻译（机械、可审计）

映射轴用现成字段：13 条 semgrep 规则都带 `metadata.category`（实测：execution / network / dynamic / credential / payload / persistence / embedded）。

| 我们的族 | category | 严重度（semgrep / Go） |
|---|---|---|
| `CMD_001` | execution | ERROR / HIGH |
| `NET_001` `NET_002` | network | ERROR / HIGH |
| `DYN_001` | dynamic | WARNING / MEDIUM |
| `FIL_001` `ENV_001` | credential | WARNING / MEDIUM |
| `OBF_001` | payload | ERROR / HIGH |
| `EXF_001` | credential | ERROR / HIGH |
| `PER_001` | persistence | ERROR / HIGH |
| `EMB_001`–`EMB_004` | embedded | ERROR/WARNING / HIGH/MEDIUM |

**严重度一律取「生产 Go」列**（镜像集）：目标态 §5 的严重度列无证据支撑，且改严重度会使已取得的证据立即失效（§7.3）。映射表条目在回填项 A 后写定，**写定即冻结**。

## 5. §9.2 十条要求 → 动作

| # | 要求 | 动作 |
|---|---|---|
| 1 | 独立来源 | 良性取 sdist 原样；恶意取公开标注语料。**不使用 `FAMILY_SPECS`/`PROJECT_ALLOCATION`**（定义在 `audit_benchmark_eval.py:76,103`） |
| 2 | 对抗构造优先 | 良性臂含真实别名/`getattr`/`importlib`；恶意臂取上游正/负例对。**我们不手工构造** |
| 3 | 标注口径与 `audit-100` 一致 | 复用同一 `sample.json` 字段。**注意实测**：真正被消费的只有 `primary_attack_finding`（算 `attribution_precision`），`findings_manifest`/`variant_file`/`expected_severity` 评测侧**一概不读**（`audit_benchmark_eval.py:514-567`、`:1040`） |
| 4 | 良性/恶意各 ≥50 | 见回填项 A；不足按 A 的退路处理，**不得降门槛** |
| 5 | 0 容差逐对 | §2 |
| 6 | 两臂同测、3 轮配对 | §2；见 §9 运行协议 |
| 7 | **`assist` 下判定** | §2 |
| 8 | **两臂 Prompt 逐样本等价性** | **今日无任何工具**，且已存在**活的不等价**（见 §6.5）。须先建捕获与比对工具，再判定 |
| 9 | **先证「regex 臂 == 生产 Go 引擎」** | **已参数化（`0bb357c`）**：`TAA_PARITY_CORPUS_ROOT` / `TAA_PARITY_RESULTS_DIR` 可选，默认值不变（100/100 一致、证据 JSON 的 sha256 前后完全相同）；两级 glob 换为可识别 `<root>/<id>/` 与 `<root>/<project>/<id>/` 两种布局的遍历；报告改写在其结果目录旁（默认解析回原路径），留出集运行不再覆盖主基准证据。留出集上**零分歧**方可判定。**调用命令见 §6.7**——`-run Parity` 匹配不到任何测试（静默 PASS），必须用全名 |
| 10 | 适配器判据在容器内复现 | **已由阶段 G 关闭**（§10.1 G-1） |

## 6. H0 —— 评测工装的前置修复（侦察已证，必须先做）

**为什么必须先做**：评测管线（`models/audit/tools/audit_benchmark_eval.py`）**是为合成语料写死的**，直接拿真实语料跑，测出来的是工装的偏差而不是引擎差异。以下五条，每条都带实测出处。

### 6.1 语料清单是**代码**，不是数据 → 新语料无法接入

`BASE_PROJECTS` 是字面量（`:51-56`），`sample_id`/`relative_path` 是合成出来的（`:244-245`：`f"{spec.family}-{index:02d}"`、`f"{base_project}/{sample_id}"`），`label` 也只来自 `FAMILY_SPECS`（`:253`）；样本 ID 与路径在运行时按 `<root>/<base_project>/<sample_id>/` 解析（`:1516`）。**没有任何 CLI 或环境变量能提供样本清单**（参数表 `:1472-1495`）。落盘的 manifest 文件**不被任何评测路径读回**。

**修复**：给评测增加一个**语料清单输入通道**（清单含 `sample_id` / `base_project` / `label` / 相对路径），留出集**不经过** `FAMILY_SPECS`/`PROJECT_ALLOCATION`。这属**评测资产改动**：须对**两臂同时施加**、单独提交、并在报告里登记（纪律见证据 spec §12.4）。

### 6.2 按条数截断 → 真实代码上的**结构性 FPR 膨胀**，且两臂不对称

`--max-findings` 默认 50（`:1492`），超出的 finding 不被开脱即阻断（`code_security_analyzer.py:863-866`）。真实第三方代码命中密度高（§3），且 semgrep 每行多条而 regex 每行只报首条（本规范 §7.4）→ 截断幅度两臂不同。

**修复选项（须预先登记、两臂同施）**：
- (a) 判定用的上限**对齐生产语义**（Go：静态 200 / LLM 20），或
- (b) 送 LLM 前按 `(rule_id, line)` 去重后再截断（使两臂的「条数」口径可比），或
- (c) 提高上限并在报告里同时给出「被截断样本数」。

三者都不改变判定口径，只改变仪器的分辨率。

**【已定，2026-09-23】(b) 送 LLM 前按 `(rule_id, line)` 去重后再截断**：regex 臂每行只报首条、semgrep 每行多条（本规范 §7.4），去重后两臂的「条数」口径才可比，截断不再单方面惩罚 semgrep；改动小、不动生产语义、**两臂同施**。上限保留 50。
> 该改动属评测资产改动：单独提交、写进报告、两臂同施（纪律见证据 spec §12.4）。

### 6.3 「整棵树任意一处 parse error」即判样本不可评 → 真实语料极易整轮作废

`scan_complete = (exit_code in (0, 1)) and parser_errors == 0`（`models/audit/tools/semgrep_runner.py:122`）。真实包常带 Python 2 文件、语法错误的 fixture、模板文件 → 一旦命中，该样本不可评（`:126`）→ 从指标里被丢弃（`audit_benchmark_eval.py:1012-1027`）→ `round_complete=False`（`:1298`）→ **配对作废、判定为「证据不足」**（`models/audit/tools/engine_compare_report.py:172-181,642-645`）。

**修复选项**：(a) 保留该语义，但**建集时按预登记规则排除不可解析文件**（用 semgrep 自身的 `errors` 归因，机械、不看判定结果）；(b) 改为 per-file 归因。

**【已定，2026-09-23】(a)**：保留「整棵树解析干净才算可评」的语义（它本身就是生产 fail-closed 的镜像），在建集阶段排除不可解析文件。**另需登记的口径差**：评测侧 per-sample 超时 120 s（`semgrep_runner.py:178`，调用处未覆盖），生产是 300 s（本规范 §12.2 Q5）。

### 6.4 两臂失败语义**不对称**：regex 臂永远「完整」，semgrep 臂可被判不完整

`RegexScannerAdapter` 无条件返回 `scan_complete=True`（`audit_benchmark_eval.py:349`），而 semgrep 臂可因 parse error / 超时 / 二进制缺失被判不完整（`semgrep_runner.py:122,182,215,225,232`）。在 0 容差判定下，这只表现为**单侧**「证据不足」——即**只有 semgrep 会被作废**，regex 不会。

**修复**：要么让 regex 臂也判完整性，要么在报告里把这条不对称**显式登记**为已知的判定偏差。**不接受「不说」**。

**【已定，2026-09-23】显式登记，不改语义**：让 regex 臂也判完整性会与历史 6 轮矩阵的可比性断裂，而该不对称在留出集上只会让 semgrep 侧**更保守**（更容易判证据不足，而不是更容易通过），方向安全。报告须单列一节写明：`round_complete=False` 只可能由 semgrep 侧触发。

### 6.5 Prompt 等价性：**今日无工具**，且**已存在活的不等价**

- 现无任何工具比对两臂送给 LLM 的 Prompt 内容（唯一近亲 `tests/test_engine_rule_parity_corpus.py` 只比 `(rule_id, line)` 集合）。
- 且不等价**已经发生**：Python regex 适配器只设 `context_before`/`context_after`，semgrep 适配器**总是**设 `ast_enclosing_block`、**有时**设 `cpg_evidence`（`audit_benchmark_eval.py:369-378,395,437`），而 `analyze_finding` **恰恰按这些字段分支**（`code_security_analyzer.py:533-546`）→ **同一规则同一行，两臂送出不同文本**；semgrep 臂还额外注入合成的 CPG finding（`:453-472`），regex 臂从不产生。

这正是 §9.2 要求 8 要防的东西，也正是主基准里 `B3-04`/`B3-09` 的成因。**要求 8 不是走过场**：先建捕获与逐样本比对工具，判定时逐条归因。

### 6.6 H0 出口

语料清单通道可用、截断口径选定并冻结、可解析性预登记规则定稿、不对称登记、Prompt 捕获工具就绪；以上各自带测试（评测侧已有 `tests/test_benchmark_samples_matrix.py`、`tests/test_engine_rule_parity_corpus.py` 可挂），单独提交，**不与留出集数据混在一次提交里**。

### 6.7 H0 出口状态（五条全部落地）

| 条 | 交付 | 提交 |
|---|---|---|
| 6.1 语料清单通道 | `--corpus-list`（JSON：`sample_id`/`base_project`/`family`/`label`/`relative_path`），替换 `FAMILY_SPECS` 展开而非叠加；拒绝未知 `label`（非 `malicious` 一律按良性计分）与重复 `sample_id`（配对按它建索引，重复即静默塌缩一对）；summary 的 `run_id`/`benchmark_version` 随语料走，不再自称 `audit-100` | `b35f76e` |
| 6.2 截断口径 | `dedupe_findings_for_llm()`：送 LLM 前按 `(file, rule_id, line)` 去重再截断，两级 prompt 同视图；报告仍拿全量 findings（条数不说谎） | `9edfda5` |
| 6.3 可解析性 | 预登记规则已定稿（§12.2 规则 4），落地在建集脚本（H1） | — |
| 6.4 两臂不对称 | 已在 §6.4 登记为已知判定偏差，报告须单列一节 | — |
| 6.5 Prompt 捕获 | `models/audit/tools/prompt_equivalence.py`：捕获（自带 `backend="none"` 分析器，**不会调用 LLM**）+ 逐样本比对，区分「命中集不同」（即引擎差，非违规）与「同一命中不同 prompt」（confound，违规并指名差异字段） | `9cd8697` |

配套：生产分析器开出 `build_finding_prompt` / `build_file_prompt` 接缝（行为保持，`6d16ee5`），使「被发送的 prompt」可被观测而无需复制一份构造逻辑。

**留出集上的调用命令（要求 9）**：

```bash
python3 models/audit/tools/audit_benchmark_eval.py \
  --benchmark-root <CORPUS_ROOT> --corpus-list <CORPUS_LIST.json> \
  --manifest-out <SCRATCH>/manifest.json --results-dir <RESULTS_DIR> \
  --engine regex --llm-backend none
TAA_CORPUS_PARITY=1 TAA_PARITY_CORPUS_ROOT=<CORPUS_ROOT> \
  TAA_PARITY_RESULTS_DIR=<RESULTS_DIR> \
  go test ./internal/codeaudit/ -v -run TestGoEngineMatchesBenchmarkRegexArm
```

> `-run Parity` **匹配不到任何测试**（Go 打印 `[no tests to run]` 并以 0 退出，看起来像通过却什么都没验证）。测试函数名是 `TestGoEngineMatchesBenchmarkRegexArm`，不得简写；改名会改动证据 JSON 的 `source` 字段，故不改名，只登记命令。
> 非 audit-100 布局**必须**给 `--corpus-list`：只给 `--benchmark-root` 时 harness 仍按 `FAMILY_SPECS` 合成样本并硬编码 `relative_path`，单层语料会生成错 `sample_id` 的工件。

### 6.8 H0 期间新发现的两处收窄（H1 必须处理，写进报告）

1. **两侧「跳过目录」集合不同**：Go 的 `DefaultConfig().SkipDirs` 含 `node_modules`/`venv`/`.venv`/`.idea`/`.vscode`/`.git`/`__pycache__`，而 Python 的 `discover_sample_py_files` **只排除点目录与 `__pycache__`**。含 `.py` 的 `venv/` 或 `node_modules/` 会让两侧读到的文件集合不同 → `files_scanned` 不匹配 → 看起来像引擎分歧。**对单文件样本（§3 的样本单元）不触发**；对 H2.5 的整目录 scale 子测量需注意。
2. **静态条数上限是单边的**：Go 静态侧 `MaxFindings = 200` 会**截断扫描**（`scanner.go:97-98,295-296`，并置 `Truncated`），而 Python 正则臂**完全无上限**（`RegexScannerAdapter`/`StaticScanner` 均不截断；`--max-findings` 只管送 LLM 的那部分）。任一留出集样本的静态命中数 ≥200，parity 就会出现 `only_in_python` 分歧，**成因与规则漂移无关**。§3 已实测真实第三方代码命中密度高，故这是 H1.4 的**必查项**（见 §12.2 规则 6）。

## 7. 阶段拆分（H1 建集与前置证明 → H2 判定运行）

### H1 —— 建集与前置证明（**不产生任何判定结论**）

1. **H1.1 取数**：按预登记规则取得两臂样本；记录每个样本的**出处、版本、URL、sha256**，落 `provenance.json`。
2. **H1.2 建集**：生成 `models/audit/benchmarks/audit-holdout/`，每样本一目录，含 `<sample>.py` + `sample.json`。
3. **H1.3 等价性证明（要求 9）**：regex 臂 vs 生产 Go 引擎，逐样本 `(rule_id, severity, line)` 比对，**零分歧**；有分歧先修，判定不得开始。
4. **H1.4 可判定性自检**：逐样本确认 `scan_complete=true`（含 6.3 的预登记排除规则已生效）、`errors` 为空；触顶则按预登记规则处理并写明，**不得静默删样本**。

**出口**：语料 + 出处清单 + 等价性证明 + 可判定性自检，四件齐备并提交。

### H2 —— 判定运行（协议先定死，再开跑）

1. **H2.1 主判定**：`assist` 下 3 轮配对（3×regex + 3×semgrep）。
2. **H2.2 并列报告**：`gate` 下同规模重跑（不作通过依据）。
3. **H2.3 Prompt 等价性逐样本比对**（要求 8）：逐条归因差异。
4. **H2.4 并发受载条件**（§9.3 第 1 条）：H2.1 期间**持续施加 semgrep 扫描负载**，复用已入库的 `models/audit/tools/semgrep_press_test.sh`（带单实例守卫与 `llama_pid`/RSS 逐样本记录）。**这是两次实测失效的场景，主基准的串行 6 轮矩阵没覆盖它。**
5. **H2.5 scale 子测量**（§9.3 第 2 条）：对真实包整目录两臂各扫一次，量时长/内存/`Truncated`/`MaxFindings`，**与单文件 Δ 判定分开报告**。
6. **H2.6 判定**：按 §2 口径，0 容差。

## 8. 出口与不通过的处置

- **通过** → 允许把默认引擎切到 semgrep（本规范 §6.5），进入灰度。
- **不通过** → 回到规则对齐循环（§9.4）；**不得**因「主基准已通过」而放宽，**不得**改判据、改样本、改映射表。改任何一项都要重走 H1 的等价性证明。

## 9. 运行协议与算力

- 逐样本成本 = 静态扫描 + 逐 finding 的 LLM 调用（评测侧上限 `--max-findings`；生产 `LLMConfig.MaxFindings = 20`，`internal/codeaudit/llm.go:45`）。
- Ollama 调用硬超时 60 s 且**无重试**（`code_security_analyzer.py:707`），失败变 `UNCERTAIN`——`gate` 下阻断、`assist` 下只在高/中危时阻断，两策略反应不同（`audit_benchmark_eval.py:717-742`）。H2.4 的并发受载正是要把这条压出来（阶段 G 实测同域并发把延迟抬高约 30 倍）。
- H2 合计 6 轮 × 2 策略 = 12 轮全量，其中 6 轮并发受载。**先跑 H2.5 估时**，再决定 H2.1/H2.2 分批。

## 10. 明确不做

- 不在本轮修 `DYN_001`/`FIL_001`/`EXF_001` 的严重度（§7.3）。
- 不在本轮收窄 `taa-env-secret-python`（§3.6：真实缺口，两臂同等）。
- 不把留出集结论外推到「任意真实模型代码」之外（报告措辞照 §2.3）。

## 11. 已知收窄（写进报告，不藏）

1. **评测管线不调用 Go 守护进程**：判定在 Python 侧复现（`code_security_analyzer.py:755-903`），生产 Go 与 regex 臂的等价性由 **Go parity 测试单独证明**（要求 9）。报告的结论边界必须照此写。
2. 单文件样本**不覆盖**整目录扫描的截断路径——由 H2.5 单独测量，两者结论不得互相替代。
3. 外部语料的标注最初是给**上游规则**的，映射表由我们写（属**翻译**，不改上游构造与标注）；与语料一同提交、冻结。
4. 每条样本的出处与 license 记入 `provenance.json`；许可条款在回填项 A 确认后写入。
5. **同一命中、两臂给的 `category` 与 `description` 不同**（H0 期间由捕获工具实测，2026-09-23，此前记录未含此轴）：同一 `CMD_001` 同一行，regex 臂送 `category='命令执行'`、`description='shell 命令执行或危险外部命令 — 可能绕过参数化保护'`，semgrep 臂送 `category='execution'`、`description='Suspicious subprocess execution detected in Python code'`。即两臂**用不同措辞向模型描述同一条规则**，加之 §6.5 的上下文差异，构成要求 8 的违规。**本轮不修**（修它等于改判定输入，会使已有证据失效），H2.3 逐条归因并在报告中写明。
6. 两侧跳过目录集合不同、静态条数上限单边（§6.8）——前者对单文件样本不触发，后者由 §12.2 规则 6 在建集时排除。
7. **DataDog 臂只用 `malicious_intent`**（§12.2 规则 3，2026-09-23 定），且该类别下的包**极小**（zip 中位 10 KB，每包 1–3 个 `.py`，多为 typosquat）——它代表的是「小体积投毒包」，**不能代表真实大型库**的命中密度。大型库方向由 §3 已实测的命中密度事实与 H2.5 scale 子测量承担，两者结论不得互相替代。
8. **semgrep-rules 的样本是 ±2 行片段**（§12.2 规则 7），不是完整函数/模块：它保留了上游逐行 ground truth，但**丢失了跨行上下文**（同一函数内其它调用的别名、`import ... as`、`getattr` 间接化）。良性臂（PyPI 整包 sdist 的单文件）仍具完整上下文，故两臂在这条上不对称——报告须写明：该不对称**不是两引擎之差**，而是两个来源的构造之差。

## 12. 来源与预登记规则（已定，冻结）

### 12.1 检索配方（普查实测，含观测到的状态与体量）

| 来源 | 取回方式 | 实测 |
|---|---|---|
| `semgrep/semgrep-rules` | `curl -L -o sr.tgz https://codeload.github.com/semgrep/semgrep-rules/tar.gz/refs/heads/develop`（整仓仅 22 MiB 解压，**无需 sparse checkout**） | `HTTP 200`、1,215,769 字节；HEAD `a84ff9cc2453ca91d581380de4b8b3f272f6f4be` |
| `github/codeql` | 只取 `python/ql/test/query-tests/Security/` 下 102 个 `.py`（约 145 KB），走 raw 逐个抓取（**不要 clone 整仓 504 MB**） | 102 个文件全部 `HTTP 200` |
| `DataDog/…-dataset` | 走 **GitHub API**（`raw.githubusercontent.com` 对该仓反复超时，实测 `exit 28`/`HTTP 000`）；只取 `samples/pypi/` 下所需包 zip；**切勿整仓 clone（约 20 GB）** | `samples/pypi/malicious_intent/` tree `HTTP 200`、2502 blob、731 MiB；解包口令 `infected` 已验证可用 |
| 良性 sdist | `pip3 download --no-deps --no-binary :all: -d <dir> <pkg>==<ver>` | 可用（`requests-2.31.0.tar.gz` 110,794 字节 已验证） |

**每个样本都必须记入 `provenance.json`**：来源 URL、commit SHA 或版本号、文件 sha256、上游标注原文（`# ruleid:`/`# ok:`/`# $ Alert` 行）、映射到的我方族。

**H1.1 实测补充的取数通道（2026-09-23，不改变上表任何来源）**：

- DataDog **不必走 API 逐包取**（API 限速 60/h，而 `malicious_intent` 有 2502 个 zip）：`git clone --filter=blob:none --no-checkout --depth 1` 仅 **5.1 MB**，随后对任意 blob 用 `git cat-file blob <sha>` 惰性取数（实测 ~1 s/个），**不受 API 限速**。整仓 clone（20 GB）仍然禁止。
- 良性 sdist 除 `pip3 download`（本机可用，~30–60 s/包）外，亦可用 **PyPI JSON API**（`https://pypi.org/pypi/<pkg>/<ver>/json` → `urls[].packagetype == "sdist"`）直取 `.tar.gz`：同一个被 pin 的工件、**不触发 pip 的构建后端（不执行包内任何脚本）**、且能顺带记录 URL 与 size 供 `provenance.json`。**建集脚本采用后者**；`pip3 download` 保留为交叉校验手段（两者 sha256 应一致）。
- DataDog 恶意包的目录布局为 `<category>/<pkg>/<version>/<zip>`（少数包把 zip 直接放在 `<pkg>/` 下），zip 内为 `<date>-<pkg>-v<ver>/<pkg>-<ver>/…`，并含上游元数据 `package_info-<pkg>-<ver>.json`。

### 12.2 预登记选取规则（写定即冻结，不按结果挑样本）

1. **良性臂（PyPI）**：取与本次规则**无关**的第三方工具（semgrep 1.177.0）的直接依赖集合，版本以 G-1 的 `pip-freeze.txt` 为准；排除路径含 `tests/`、`test_`、`fixtures/`、`examples/`、`__init__.py` 的文件；每包按**路径字典序**取前若干 `.py`，每样本一文件。
2. **近失良性臂**：semgrep-rules 的 `# ok:` 窗口（机械抽取，见 §4.2）+ CodeQL 的 `result=OK` / `SPURIOUS: Alert` 所在文件。
3. **恶意臂**：semgrep-rules 的 `# ruleid:` 窗口 + DataDog **`samples/pypi/malicious_intent/`** 下的恶意包（逐文件为样本，包级标签直接继承）。**2026-09-23 定：`compromised_lib` 排除**——其 28 个 zip 装的是**整库源码**（348 MiB），只有个别文件是后门，包级标签继承会把大量真实良性文件标成恶意，而该类别**无逐文件标签**可用；`malicious_intent` 的包则整包皆恶意，规则 3 的「包级标签直接继承」语义成立。**包内 `__init__.py` 与 `setup.py` 不排除**——规则 1 的排除项不适用于本臂，payload 恰恰常在 `__init__.py` 与 `setup.py` 的 install 钩子里。
4. **可解析性（H0.3 落地处）**：建集时对每个候选文件跑一次 semgrep，`errors` 非空者**排除并计数**，写入报告；该判定**不看**命中结果。
5. **规模**：良性（含近失）≥50、恶意 ≥50；**不足不降门槛**，按族写明「证据不足」。
6. **静态命中数上限（H0 期间新发现，2026-09-23 追加）**：要求 9 的 parity 在任一留出集样本的静态命中数 ≥200 时会因**单边截断**（Go 截断、Python 不截断，§6.8-2）产生与规则无关的分歧。故 H1.4 时对每个候选样本记录其在**去重前**的静态命中数：`< 200` 者进入语料；`≥ 200` 者**排除并计数**，并在报告中写明（**不得静默丢弃**）。与规则 4 同理：该判定**不看**命中结果与判定结论，只看条数。

7. **窗口口径（2026-09-23 按实测修订，先于任何留出集数据产生——与规则 6 同一先例）**：semgrep-rules 的样本窗口 =「标注行 ± 2 行」（含标注行自身），`textwrap.dedent` 后落盘；同一文件内窗口按 `(path, start, end)` 去重；窗口内同时含 `ruleid` 与 `ok` 标注者**丢弃并计数**（标签不唯一）。修订理由：原口径（§4.2 原定「包含该行的最内层 `def`/`class` 体，模块层丢弃」）实测在 Python 侧只映射出 **12 个**样本（6 恶意 / 6 近失，且全为 `NET_001`），不足以支撑要求 4。K=2 的实测：754 窗口 / 734 纯净 / 536 去缩进后可解析 / **152 映射**（82 恶意、70 近失，覆盖 `CMD_001`/`NET_001`/`NET_002`/`DYN_001`/`OBF_001`）。原口径（下称 A 口径）的数字在报告中**同时保留作对照**。备选口径（**未被采用，登记备查**）：K=3/5/8/12——混合窗口随 K 迅速增多（109 / 258 / 356 / 422），纯净窗口与映射量反而下降。

> 规则 6 是 §7 H1.4 已要求的「触顶则按预登记规则处理并写明」的具体化，在任何留出集数据产生**之前**写定。备选口径（**未被采用，登记备查**）：(b) 在 parity 比较中给 Python 臂镜像同一上限——会改动比较语义因而不可比；(c) 仅作收窄声明——会让「零分歧」的覆盖面小于语料本身。

### 12.3 「上游类别 → 我方族」映射表

映射由构建脚本按**上游规则 ID 的词元表**机械生成（例：`system-call`/`subprocess`/`shell` → `CMD_001`；`socket`/`request`/`urllib` → `NET_001`/`NET_002`；`eval`/`exec` → `DYN_001`；`importlib`/`getattr` 动态调用 → `DYN_001`；`file`/`path`/`credential` → `FIL_001`；`env`/`secret`/`hardcoded` → `ENV_001`；`base64`/`marshal`/`pickle`+`exec` → `OBF_001`；`exfil`/`send`/`post` → `EXF_001`；`backdoor`/`persistence`/`cron`/`authorized_keys` → `PER_001`；模型权重/数据外带 → `EMB_*`）。**具体表在 H1 生成、提交、冻结**；未映射到任何族的上游文件**排除并计数**（不静默丢弃）。严重度一律取 §4.3 的「生产 Go」列。

### 12.4 许可处置（你已定：语料不入库）

- **语料本体不提交进 git**：沿用 `audit-100` 先例（`.gitignore:7` 忽略 `models/`，其 400 个 `.py` 无一入库），留出集放 `models/audit/benchmarks/audit-holdout/`（已被忽略）。
- **提交的只有**：构建脚本、`provenance.json`、冻结的映射表、以及重建所需的固定版本清单 —— 任何人可一键重建。
- 这同时满足 Semgrep Rules License v1.0 的「仅内部业务使用、不得再分发、不得作为服务提供」；**改动上游文件时须显著标注已修改**（本次是机械窗口抽取，须在 provenance 里写明）。

## 13. 决策记录（2026-09-23，你已拍板）

| # | 决策 | 取值 |
|---|---|---|
| 1 | 留出集来源 | **真实第三方源码 + 公开标注语料**；恶意/近失臂取 **三源组合**（semgrep-rules + CodeQL + DataDog） |
| 2 | 语料入库 | **不入库**，只入配方 + 出处 + 冻结映射表 |
| 3 | H0.2 截断口径 | **送 LLM 前按 `(rule_id, line)` 去重**，上限保留 50，两臂同施 |
| 4 | H0.3/H0.4 解析错误与不对称 | **建集时排除不可解析文件**；两臂失败语义不对称**显式登记**，不改语义 |
| 5 | §4.2 窗口口径（H1.1 普查后发现） | **修订为「标注行 ± 2 行」**（§12.2 规则 7）：原口径实测只映射出 12 个样本，不足支撑要求 4；修订先于任何留出集数据产生，A 口径数字在报告中保留作对照 |
| 6 | DataDog 臂构成 | **只用 `malicious_intent`**（§12.2 规则 3）：`compromised_lib` 无逐文件标签、装的是整库源码，包级标签继承会把大量真实良性文件标成恶意 |
