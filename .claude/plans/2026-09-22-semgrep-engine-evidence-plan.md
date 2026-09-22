# Semgrep 引擎非劣性证据 —— 实施计划

- **Date**: 2026-09-22
- **Plan Path**: `.claude/plans/2026-09-22-semgrep-engine-evidence-plan.md`
- **Spec**: `.claude/specs/2026-09-22-semgrep-engine-noninferiority-evidence-design.md`
- **Status**: P0 已完成并提交（`7f131d9`）；P1–P3 未开始
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

## 阶段 3：P3 —— LLM 采样固定种子

**问题**：`code_security_analyzer.py:695` 的 ollama options 为 `{"temperature": 0.1, "num_predict": N}`，**无 seed**，同输入两次运行不可复现；而判定要求「每臂 3 次配对」。

**改动点**：
1. 新增 CLI 参数 `--llm-seed`，默认 `42`；透传到 ollama `options.seed`。
2. 该值写入 summary 运行元数据。
3. **温度保持 `0.1` 不变**（改温度会改变被测量的处理本身）。

**RED**：mock HTTP 层，断言 payload 的 `options.seed == 42`（显式传其它值时等于该值），且 summary 记录了 `llm_seed`。

**GREEN 验收**：新测试通过；`tests/test_code_security_analyzer_v2.py` 全通过。

**提交**：`feat(audit-bench): add a fixed LLM sampling seed for reproducible runs`

---

## 阶段 4：冒烟门槛（4 项全过才可开矩阵）

1. semgrep 臂每个 finding 的 `code_snippet` 与源文件对应行逐字相等（P1）。
2. 人为制造失败（临时改坏规则 YAML / 指向不存在的可执行文件）→ 样本行出现 `scan_complete=false` 且被汇总计数捕获（P2）。
3. 同一命令连跑两次，同一模型裁决一致（P3）。
4. **全量规则集行为一致性审计**：对 audit-100 的 100 个样本逐文件比对两臂触发的 `rule_id` 集合，差异必须为空或逐条解释并登记进报告。

第 4 项的审计脚本：复用 P0 期间已验证的做法（`StaticScanner.scan_file` vs `SemgrepRunner.scan_directory`，按文件比 `rule_id` 集合）。**仅登记差异，不在本阶段顺手改规则**——改规则要回到 P0 式的 RED/GREEN 循环并重跑本门槛。

---

## 阶段 5：时延预算与 6 次正式运行

1. `--limit 5` 实测 `per_sample_llm_sec`，据此给出总时长预估后**再**开跑；禁止凭历史数值估算（历史数值来源不可信）。
2. 6 次运行严格串行，按 spec §4.2 的命令模板；每轮前后复核 ollama 存活与模型 digest（`f72c60cabf62…`）。
3. **运行期间不得并行**任何重内存任务（含 semgrep 全量扫描、完整测试套件）。
4. 每轮结束后 `git checkout -- models/audit/audit-benchmark-manifest.json`（评测器会把 `benchmark_root` 改写成绝对路径，污染已跟踪文件）。

---

## 阶段 6：报告

产出 `models/audit/audit-results/engine-compare/REPORT.md`（结构见 spec §6）。注意 `models/` 在 `.gitignore` 中，报告与原始数据提交时**必须** `git add -f`，否则会静默漏提交。

结论只允许三种措辞：**通过** / **未通过（附根因）** / **证据不足（附缺失项）**。按 spec §5.3 的 0 容差规则判定；任一条件不满足即不得进入生产接入。

---

## 待你拍板的 3 项（spec §13）

1. **P4 处置**：(a) 加 `provenance` 字段并把 `engine` 改为必填显式入参（规范倾向此项）；或 (b) 标记 `generate_matrix_results.py` 为 deprecated。
2. **P2 中 `incomplete` 样本的处置**：整轮作废重跑（规范现定），或从两臂同一对中一并剔除后继续（省时间但配对样本集变小）。
3. **P1–P3 是否分三次提交**（便于单独回滚）还是合并为一次。

未拍板不影响阶段 0–3 的推进：三项都只在阶段 4 之后才产生分叉。**P4 不做则阶段 6 的报告结论有「被手写矩阵冒名引用」的残留风险**，建议至少采纳 (a)。
