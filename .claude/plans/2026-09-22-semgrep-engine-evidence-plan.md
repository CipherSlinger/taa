# Semgrep 引擎非劣性证据 —— 实施计划

- **Date**: 2026-09-22
- **Plan Path**: `.claude/plans/2026-09-22-semgrep-engine-evidence-plan.md`
- **Spec**: `.claude/specs/2026-09-22-semgrep-engine-noninferiority-evidence-design.md`
- **Status**: P0 已提交（`7f131d9`）；P1/P2 已提交（`58de1e8`、`8eb7fe7`）；P3、P0-bis（两轮）、P4 已完成待提交；阶段 4 第 4 项已归零
- **Scope**: 仅评测工具链（`models/audit/tools/**`、`models/examples/code_security_analyzer.py` 评测侧）。**零生产代码改动**。

约束：全部按 TDD（RED → 验证 RED 原因 → GREEN → 验证 GREEN → REFACTOR）；测试落 `tests/`；运行 `python3 -m unittest discover -s tests -p "test_*.py"`；提交用英文 Conventional Commits，scope `audit-bench`，无 AI 署名。

---

## 阶段 0：前置检查（每次动 semgrep 之前）

本机为 BE 单机（9.9GB），ollama 跑在容器 `taa-env-slim-v2` 内。P0 期间已实测：并发跑 semgrep 全量扫描会让该容器 `Exited (137)`，而 LLM 死亡在 fail-open 下会伪装成「扫描干净」。

```bash
docker ps -a --format '{{.Names}}\t{{.Status}}' | grep taa-env-slim-v2   # 必须是 Up
curl -s http://127.0.0.1:11434/api/tags | grep -o 'qwen2.5-coder:3b'      # 必须存在
```

任一项不满足则先恢复（`docker start taa-env-slim-v2`，再按 `deploy-docker.sh:221` 的方式在容器内起 `start-ollama.sh`），**不得**在 LLM 不可用时开始任何评测。

### 实测教训（2026-09-22，本轮）

P0-bis 第二轮期间跑全量语料审计（100 样本 semgrep）**把容器打成了 `Exited (137)`** —— 与 P0 期间观察到的现象一致，只是这次是被本流程自己触发的。9.9GB 单机上「全量 semgrep 扫描」与「ollama 常驻」不能共存。

因此：

- **语料审计必须在任何 LLM 工作之前单独跑完**，不得与评测、甚至不得与 `--limit` 试跑并行。它是**前置门槛**，不是可以后台挂着的旁路任务。
- 审计结束后**必须复核容器状态**（`docker ps -a | grep taa-env-slim-v2` 须为 `Up`）再开始计时或评测。
- 恢复步骤：`docker start taa-env-slim-v2`，再 `docker exec -d taa-env-slim-v2 sh -lc "cd /root/taa/ollama && exec env OLLAMA_HOST=127.0.0.1:11434 OLLAMA_MODELS=/root/taa/ollama/models/models OLLAMA_LIBRARY_PATH=/root/taa/ollama/lib/ollama ./start-ollama.sh > /tmp/ollama.log 2>&1"`，随后轮询 `/api/tags` 至就绪。
- 恢复后须确认模型 digest 仍为 `f72c60cabf62…`，并做一次真实 `generate` 探针（仅 `/api/tags` 命中不算就绪）。
- **`Exited (137)` 会在 fail-open 下伪装成「扫描干净」**——这正是 P2 修掉的失效模式。因此每轮正式运行前后都要记录容器状态，不能只看评测器输出。

---

## 阶段 1：P1 —— `code_snippet` 从源文件按行切片

**问题**：`semgrep_runner.py:100` 直接取 `extra.get("lines")`，而 Semgrep CE 未登录时该字段返回字面量 `"requires login"`。这个字符串正是喂给 LLM 仲裁的「触发规则的代码」。

**改动点**：`models/audit/tools/semgrep_runner.py`
1. 新增私有方法按 `start.line` / `end.line` 从目标文件切出真实命中行，带按文件缓存（同一文件多次命中时不重复读）。多行匹配用 `\n` 连接后 `strip()`。
2. `parse_output` 的 `code_snippet` 取值改为：`extra.lines` 为**非空且不等于 `"requires login"`** 时用它（保留非 CE 场景的正确行为），否则走文件切片。
3. `parse_output` 需要知道扫描根目录才能解析相对路径 → 增加可选参数 `scan_root`，由 `scan_directory` 传入。
4. 切片失败（文件读不到/行号越界）不得抛异常、也不得静默留空：把原因写入 finding 的 `slice_error` 字段（P2 会把它提升到样本行）。

**RED**：`tests/test_semgrep_runner.py::TestSemgrepRunner.test_real_semgrep_scan_directory` 新增
```python
self.assertEqual(res.findings[0]["code_snippet"], "os.system('id')")
```
预期失败原因：`'requires login' != "os.system('id')"`。

**GREEN 验收**：`python3 -m unittest tests.test_semgrep_runner -v` 全通过；且 `test_parse_semgrep_json_output` / `test_parse_taint_dataflow_trace`（两者 mock 里带真实 `lines`）不受影响——若它们被改红，说明「优先用 extra.lines」的分支写错了。

**提交**：`fix(audit-bench): slice Semgrep code snippets from the source file`

---

## 阶段 2：P2 —— 扫描状态必须进入样本结果（阻断级）

**问题**：`SemgrepScannerAdapter.scan_directory`（`audit_benchmark_eval.py:321`）返回裸 `List[Finding]`，丢弃 `scan_complete`/`timed_out`/`parser_errors`/`error_message`；`analyse_sample:755` 据此算 `bypass = (len(findings) == 0)`，于是「semgrep 没装/超时/规则解析失败」与「真的没有命中」不可区分。另有 3 处 `except Exception: pass`（`:332` AST 切片、`:426` CPG、`:528` sample.json 解析）。

**改动点**：
1. 新增 `ScanOutcome` dataclass（`findings` + `scan_complete`、`timed_out`、`parser_errors`、`error_message`、`slice_error`）。
2. `SemgrepScannerAdapter.scan_directory` → 返回 `ScanOutcome`。
3. `load_module_scanner` 对 regex 臂返回一个包装，使其同样产出 `ScanOutcome`（`scan_complete=True` 恒定，因为 `StaticScanner` 是同步纯内存正则，不存在「扫描未完成」状态）→ **两臂接口一致，`analyse_sample` 无需分支**。
4. `analyse_sample`：
   - `bypass = (len(outcome.findings) == 0) and outcome.scan_complete`（**未完成的扫描不得进入 bypass**）。
   - 样本行写入：`scan_complete`、`scan_timed_out`、`scan_parser_errors`、`scan_error`、`slice_error`。
   - `scan_complete is False` 的样本单列为 `incomplete`，不参与指标、不计入 bypass。
5. 汇总新增 `scan_incomplete_count`、`scan_error_count`，并把 3 处 `except Exception: pass` 改为「记录到样本行 + 计入汇总」。

**RED**：注入两种失败，断言样本行与汇总计数
- `SemgrepScanResult(scan_complete=False, timed_out=True)` → 样本行 `scan_complete is False`、`scan_timed_out is True`、`incomplete` 计数 +1，且该样本 `bypass is not True`。
- `is_available() == False` → `scan_error` 含 "not found"。
- 另加一条 **fail-open 守卫**：构造 `findings == []` 且 `scan_complete is False`，断言**不计为 TN**。这是本次唯一的「防故障伪装成好结果」测试，必须有。

**GREEN 验收**：新增测试 + `tests/test_audit_eval_three_track.py` 全通过（该文件覆盖三轨评测，签名变更最可能在这里暴露）。

**提交**：`fix(audit-bench): propagate Semgrep scan status into sample results`

---

## 阶段 3：P3 —— LLM 采样固定种子（已完成）

**问题**：`code_security_analyzer.py:695` 的 ollama options 为 `{"temperature": 0.1, "num_predict": N}`，**无 seed**，同输入两次运行不可复现；而判定要求「每臂 3 次配对」。

**改动点**：
1. 新增 CLI 参数 `--llm-seed`，默认 `42`；透传到 ollama `options.seed`。
2. 该值写入 summary 运行元数据。
3. **温度保持 `0.1` 不变**（改温度会改变被测量的处理本身）。

**RED**：mock HTTP 层，断言 payload 的 `options.seed == 42`（显式传其它值时等于该值），且 summary 记录了 `llm_seed`。

**GREEN 验收**：`tests/test_llm_seed.py` 6/6 通过；`tests/test_code_security_analyzer_v2.py` 9/9 通过。

**实施说明（与计划的偏差）**：两处接口是实施时才确定的——
- `code_security_analyzer.py` 原先的 argparse 内联在 `main()` 里、没有可复用的 `parse_args`，因此提取了 `parse_args(argv=None)`；这是让「CLI 默认值」可测的最小改动。
- 评测器侧新增 `build_analyzer()` 与 `run_metadata()` 两个单点函数，避免「CLI 解析到了 seed，但没传到后端」这种**summary 声称有种子而实际没固定**的假证据。

**提交**：`feat(audit-bench): add a fixed LLM sampling seed for reproducible runs`

---

## 阶段 3.5：P0-bis —— 规则集对齐（由阶段 4 第 4 项触发，已完成）

阶段 4 第 4 项的审计**没有通过**：100 个样本中 44 个文件的 `rule_id` 集合不一致，涉及 7 条规则，且**四条漏报全部落在恶意样本上，其中 M1-02/M2-04/M4-01/M5-01 的 ground truth 主攻击规则恰好就是被漏掉的那条**。按 spec §8「FAIL 且根因是规则语义缺陷 → 先修规则、重跑」，把对齐提前到矩阵之前，登记结果见 spec §11。

**实施要点**：
1. 语料审计只覆盖「语料里恰好出现的写法」，因此新增 `tests/test_engine_rule_parity.py`：50 个夹具，**期望值由 regex 臂自身算出**，逐文件比 `rule_id` 集合；比对前把 semgrep 结果按 `SUSPICIOUS_PATTERNS` 顺序折叠成「每行首条命中」的形态（那是扫描器外壳的差异，不是规则集差异），但基线完全没报出的构造仍是差异。
2. **RED：30/50 夹具不一致**，失败原因全为规则语义。它比语料审计多抓出 `cmd_os_exec`、`cmd_plain_popen`（semgrep 过报）、`net_http_client`、`net_httplib2`、`emb_rename_*`、`per_crontab`、`per_etc_systemd` 等语料中未出现的缺口。
3. **GREEN：50/50 一致**，python 规则仍为 13 条，`parser_errors=0`。
4. `PER_001`/`EMB_004` 的部分分支改用 `pattern-regex`——**基线本身就是纯文本正则**，用 AST 表达会引入基线没有的约束。
5. 两处既有夹具断言原先断的是**旧 semgrep 规则独有**的行为（`/etc/cron.d/`、`struct.pack`），按 P0 对 `/etc/shadow` 的同一原则改为两臂共享的构造，缺口登记 spec §12.3。

**提交**：`fix(audit-bench): realign the Semgrep rules with the regex baseline`

### 第二轮：重跑审计未归零，`EMB_001` 过报

按 §7 第 5 步重跑全量审计，**仍有 75/100 差异**，全部是同一条构造：`train.py:99/105` 的 `torch.save(saved_weights, checkpoint_file)` / `torch.save(detector_state, checkpoint_file)`，semgrep 报 `EMB_001`、regex 不报。`EMB_001` 是 HIGH，生产 `gate` 下会阻断，75 个样本（多数良性）因此多出一条基线没有的 HIGH。

根因：`taa-emb-data-dump-python` 被写成 `pattern: torch.save($DATA, $PATH)` + 两条否定模式，而基线的谓词是**载荷参数的名称清单**；丢掉清单后对任何 checkpoint 写入都命中，且基线另外四条分支（`np.save`/`np.savez`/`shutil.copy`/`shutil.copytree`）在 semgrep 侧完全缺失。

**夹具测试为何漏掉**：`EMB_001` 只有一个夹具且是否定夹具，既无肯定夹具、也无「首个实参不是数据名」的否定夹具。**这是「夹具测试不能替代语料审计」的实证**——夹具对有人枚举到的构造精确，语料审计覆盖基准真正打分的样本。

**RED**：补 9 个 `EMB_001` 夹具 → 4/59 不一致（与语料审计逐条对应）。**GREEN**：改写为基线五条模式的 `pattern-regex` 镜像（`[^)\n]` 而非 `[^)]`，因为后者会跨行、比基线的逐行 `re.search` 宽）→ 夹具 59/59、**语料 100/100 归零**。

**两处门槛都补了「空集通过」防护**：两个空命中列表天然相等，扫描器没跑起来时比对会静默通过。现在两个测试都断言对照臂确实有命中。

**§4.3 第 4 项已固化**为 `tests/test_engine_rule_parity_corpus.py`（`TAA_CORPUS_PARITY=1` 开启）。原先是一次性脚本，证据只存在于对话记录里；**证据应当可复跑，而不是可引用**。

---

## 阶段 3.6：P4 —— `engine` 标注与事实脱钩（已完成）

`generate_matrix_results.py` 的 `tp/fp/tn/fn` 全部来自硬编码 `MODELS_SPEC`，但它写出的 `summary.json` 与真实评测产物同形同址，`engine`/`rule_set_version` 却由 **mode 名称**推断（`engine = "semgrep" if mode_name == "static-llm" else "none"`）——于是「没人声称过 semgrep」也能落成 `engine: "semgrep"`，而 HTML 报告据此宣称「Semgrep 静态规则层保证 88%+ 召回底线」。该字段在生成器内部**只写不读**，唯一作用就是被引用。

**改动**（spec §13.1 采纳 (a)）：
1. `PROVENANCE = "hand-authored-spec"` 写入每条 run 与主汇总，含**落盘的 per-run `summary.json`**（被引用的正是它）。
2. `generate_matrix(track_declarations, …)` 首个参数**必填无默认值**；`validate_track_declarations` 要求覆盖三个 mode 且各自给出 `engine` 与 `rule_set_version`，否则 `ValueError`。
3. CLI 新增**必填可重复**的 `--track MODE:ENGINE:RULE_SET_VERSION`，`main` 不再自行填值。
4. `rule_set_version` 一并去除推断——它是断言「这些数字出自 13 条 semgrep 规则」的字段，只修 `engine` 会把同一机制留在隔壁一列。

**RED**：5 条新测试全红，失败原因正确（`TypeError not raised` 证明原先缺省即静默落成 semgrep；`--track` 缺失未报错）。
**GREEN**：`tests/test_matrix_results_generator.py` 9/9 通过（其中 3 条既有用例的调用点因新必填参数而更新，非弱化断言）。

**提交**：`fix(audit-bench): stop the matrix generator from implying an engine nobody named`

---

## 阶段 3.7：P2-bis —— 未扫样本不得进入混淆矩阵（由阶段 4 第 2 项触发，已完成）

阶段 4 第 2 项**没有通过**：样本行的 `scan_complete=false` 是对的，但汇总把 4 个未扫样本记成 `tn=4`、`accuracy=1.0`。§5.3 第 3 条早已写明「`incomplete` 归零之前该轮结果不得进入指标计算」——**代码没有兑现 spec**，与 §9.8 同类。

**为什么必须修**：semgrep 是唯一可能 incomplete 的一臂；「扫不动 → 空命中 → 记 TN」**降低 FPR**，而 `ΔFPR ≤ 0` 恰是通过条件之一，等于扫描器挂掉会把人推向 PASS。

**改动**：`confusion_counts` 只对 `scored_rows()` 计数（`scan_is_scored`/`scored_rows` 单点函数），未扫样本不落任何格子；`metric_summary` 增 `scored_count`；`build_summary_report` 增 `round_complete`；`final-report.md` 在作废轮次首屏给横幅；`confusion-matrix.json` 落全零。bootstrap 区间走同一函数，一并修正。

**RED**：`TestIncompleteScansStayOutOfTheScore` 7 条，6 红原因正确。**GREEN**：15/15；同一条注入失败的命令重跑，`round_complete=False`、`counts` 全零、`scored_count: 0`。

**提交**：`fix(audit-bench): keep unscanned samples out of the confusion matrix`

---

## 阶段 4：冒烟门槛（4 项全过才可开矩阵）

1. semgrep 臂每个 finding 的 `code_snippet` 与源文件对应行逐字相等（P1）。**已过**：80/80 逐字相等（语料审计）。
2. 人为制造失败（临时改坏规则 YAML / 指向不存在的可执行文件）→ 样本行出现 `scan_complete=false` 且被汇总计数捕获（P2）。**首轮未过 → 阶段 3.7 修复 → 重跑已过**（`round_complete=False`、`counts` 全零）。
3. 同一命令连跑两次，同一模型裁决一致（P3）。**已过**：`--limit 12`（2 个 B2 样本实际进 LLM）两轮逐字段零差异。
4. **全量规则集行为一致性审计**：对 audit-100 的 100 个样本逐文件比对两臂触发的 `rule_id` 集合，差异必须为空或逐条解释并登记进报告。

第 4 项的审计脚本：复用 P0 期间已验证的做法（`StaticScanner.scan_file` vs `SemgrepRunner.scan_directory`，按文件比 `rule_id` 集合）。**仅登记差异，不在本阶段顺手改规则**——改规则要回到 P0 式的 RED/GREEN 循环并重跑本门槛。

**第一次执行结果：第 4 项未通过**（44/100 文件 `rule_id` 集合不一致，7 条规则），已按上述规则回到 RED/GREEN 循环（阶段 3.5），修完后**必须重跑本项并确认差异清单归零**才可开矩阵。第 1–3 项的验收已在阶段 1–3 的 GREEN 中完成，但重跑第 4 项时会一并复核；**第 2 项在复核时暴露出 §11.7 的汇总缺口**，故第 1–3 项已在阶段 3.5/3.7 后各自重跑并记录实测结果。

---

## 阶段 5：时延预算与 6 次正式运行

1. `--limit 5` 实测 `per_sample_llm_sec`，据此给出总时长预估后**再**开跑；禁止凭历史数值估算（历史数值来源不可信）。
   - **偏离（已记录）**：`--limit 5` 无法测出该值。语料清单是 `FAMILY_SPECS` × `PROJECT_ALLOCATION` 生成的**固定网格**（非文件系统发现），`--limit N` 永远先走完 B1-01…B5-10 这 50 个良性样本；`--limit 5` 取到的是 B1-01…B1-05，它们**全部绕过仲裁**（`llm_invoked=false`），`per_sample_llm_sec` 因而无定义、只能读出 0。`--limit 3`/`--limit 5` 均属**vacuous**，不是"小样本估计"，是"估不出"。
   - **替代做法**：先把分母与分子的口径补齐（见阶段 3.5 的计时插桩），再按**两段式**分别测量——`--llm-backend none` 量静态扫描成本（全 100 样本），`--llm-backend ollama` 量 LLM 成本（取实际进入仲裁的样本）。这正是阶段 3.5 插桩要解决的问题：只有整轮 `eval_duration_sec` 时，两项成本无法分离。
   - **实测预算（6 轮跑完后回填，spec §4.4 已同步）**：扫描 0.009 → 4.343 s/样本（≈483×），整轮均值 1150.1 → 1764.2 s，即 **+614.1 s/轮（+53%）≈ +10.2 分钟/100 样本**。原估算「7–8 分钟」偏低约 30%。LLM 成本两臂等价（10.6–24.5 s/样本）。单轮耗时**不是稳定预算值**（同引擎相差近一倍），预算应取区间上限。
2. 6 次运行严格串行，按 spec §4.2 的命令模板；每轮前后复核 ollama 存活与模型 digest（`f72c60cabf62…`）。
   - **实施方式**：6 轮由**单个串行驱动脚本**跑完（`/tmp/run-six.sh`），顺序即模块里的 `RUN_ORDER`（regex1 → semgrep1 → regex2 → semgrep2 → regex3 → semgrep3），每轮结束自动 `git checkout --` 清单并在非零退出时中止。**串行由构造保证**，而非靠人守着不并发。
   - **驱动被会话结束杀死（作废 regex-run3 并重跑）**：`run-six.sh` 于 17:41:50 在 `regex-run3` 扫到 91/100 时随会话终止（日志尾 `[killed]`）。该轮**没有**写出 `summary.json`/`sample-results.jsonl`，即无任何判定可用，故整轮作废：清除半成品目录、恢复清单、复核容器（`restarts=0`、`StartedAt` 未变、digest 未变、真实 `generate` 探针通过），再用 `/tmp/run-two.sh` 只补第 5、6 轮。
   - **两处构造性修正**：(1) 新驱动用 `setsid nohup` **脱离会话**，会话结束不再能杀死它（上一次死于这个，不是死于工作本身）；(2) 重跑前**抹掉**半成品目录，避免中断残留与新产物混在一起。副作用须披露：**pair 3 的采集窗口晚于 pair 1/2**（17:54 起 vs 15:57 起）。
3. **运行期间不得并行**任何重内存任务（含 semgrep 全量扫描、完整测试套件）。
   - **已发生一次违规（我造成的）**：第一版 `regex-run1` 跑到 22/100 时，我并发启动了完整测试套件（`unittest discover`），其中 `test_engine_rule_parity.py` 会对 59 条 fixture 调 semgrep——正是 spec §9.7 记录的「与容器内 ollama 并发 → OOM」组合。发现后立即停止测试套件，**该轮作废并重跑**。核对：容器 `RestartCount=0`、启动时间未变、已落下样本的 finding **全部带 `llm_verdict`**（无 fail-closed），即未实际造成故障，但作废的理由是**我不该制造那个组合**，而不是「这次运气好」。
   - **无法排除的干扰（须在报告披露）**：本轮运行窗口内，**用户本人**在同一仓库/主机上工作（`dcc57aa` 于 16:00:02 提交 `deploy.sh` 的容器存活判定修复，涉及 docker 操作）。我无法要求其停工，因此不据此反复作废，改为**用可测量证据处理**：逐样本 `scan_duration_ms`/`llm_duration_sec` 已落盘，跑完按离群点判定是否受扰，并把离群样本**逐条披露**；时序本就是次要证据（`eval_duration_sec` 只披露、不参与 §5.3 判定）。若离群分析显示实质受扰，则该轮作废、改在安静窗口重跑。
   - **已量到的运行间离散（须在报告披露）**：同引擎同工作量下 `eval_duration_sec` 相差近一倍（regex-run1 1781.6s vs regex-run2 829.7s；`per_sample_llm_sec` 22.828 vs 10.621）。这坐实了「时序只披露、不参与判定」的设计；单轮耗时**不是**稳定预算值。
   - **`fail_closed_count` 逐轮漂移（须在报告披露）**：regex-run1=2、semgrep-run1=2、**regex-run2=4**、semgrep-run2=1。即 `--llm-seed 42` **不能**让 LLM 回复的解析结果稳定复现。四轮的 FPR/recall 仍完全相同（0.5600/1.0000），说明这些解析失败在该语料上全部落在恶意样本（fail-closed → 命中保留 → TP），未触及指标；但这是**该语料上的事实，不是保证**，须逐样本披露失败集合，并说明「三轮不是逐字节重复，而是同一分布的三个抽样」。
4. 每轮结束后 `git checkout -- models/audit/audit-benchmark-manifest.json`（评测器会把 `benchmark_root` 改写成绝对路径，污染已跟踪文件）。

---

## 阶段 6：报告（已完成）

产出 `models/audit/audit-results/engine-compare/REPORT.md`（结构见 spec §6）。注意 `models/` 在 `.gitignore` 中，报告与原始数据提交时**必须** `git add -f`，否则会静默漏提交。

结论只允许三种措辞：**通过** / **未通过（附根因）** / **证据不足（附缺失项）**。按 spec §5.3 的 0 容差规则判定；任一条件不满足即不得进入生产接入。

**结果：判定「通过」**（三对 ΔFPR = Δrecall = +0.0000，零 discordance；六轮 `incomplete` = 0）。spec §6 的七项已全部落盘，每个数字均由 `engine_compare_report.py` 从 6 轮产物派生，并按 spec §6.7 逐条披露限制。

**编写报告时抓出并修正的三处**（记此以备复核）：

1. **§7.9 的离群归因原本是错的**：我把 `semgrep-run3` 的两个 `llm_duration_sec` 离群者（M4-08 120.1 s、M1-02 91.7 s）解释为「解析失败表现为调用异常长」。实测 `llm_state` 是 **`llm_unavailable`**、`llm_reason` 为 `ollama 调用失败: timed out`——是 60 s 超时，不是解析失败。该轮真正的解析失败样本 M1-04 耗时 16.2 s，**低于离群阈值**，离群检测器标不出这一通道。
2. **§7.6 漏报了一次真实的 LLM 不可用**：容器 `RestartCount=0` 使我在上一段得出「本轮未发生该事故」。这个检查**太弱**——容器存活而推理停摆是可能的，`semgrep-run3` 就发生了 2 次。已改写为「LLM 不可用确实发生，只是没到容器死亡那一步」，并登记 spec §9.10 第 11 条（第二条通道）。
3. **§5 的分母写错**：原文「六轮 168 次仲裁」把良性仲裁数当成了全部仲裁数。实测六轮共 **468** 次仲裁（168 良性 + 300 恶意），**开脱数在所有 468 次上均为 0**——比原文更强。

---

## 三项待定事项的处置（spec §13）

1. **P4 处置**：按规范倾向采纳 **(a)** —— 给 `generate_matrix_results.py` 加 `provenance` 字段，并把 `engine` 改为必填显式入参。理由是阶段 6 的报告结论若被一份手写矩阵冒名引用，等于证据链上出现一个无法追溯来源的副本；(b) 只是标注弃用、不阻止引用，挡不住这个风险。
2. **P2 中 `incomplete` 样本的处置**：按规范现定 —— **整轮作废重跑**。剔除后继续会让配对样本集随失败次数缩水，而非劣性判定要求的是「每对都满足」，缩水的样本集无法支撑该主张。
3. **P1–P3 提交粒度**：**分三次提交**，便于单独回滚（P1/P2 已按此提交，见 `58de1e8`、`8eb7fe7`）。
