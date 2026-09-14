# Audit-100 v2 Benchmark 重构实现计划 (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 重构 Audit-100 代码安全审计基准为工业级双轨架构（Track 1 微观原子探针 + Track 2 真实多告警场景），实现跨工程交叉基座、良性硬负样本（Hard Negatives, 1~3 findings）、恶意多告警样本（2~4 findings）、动态滑动视窗与归因纯度校验，全面量化误报消除率（De-noising Rate）与单告警原子耗时。

**Architecture:** 
1. **引擎增强**：正则扫描引入 `re.IGNORECASE` 支持大小写环境变量探测；`analyze_file` 引入以 Finding 为中心的动态滑动视窗；Ollama 客户端超时放宽至 120s；
2. **生成层**：对基座工程进行审计范围归一化（剥离冗余测试脚本）；在三大基座间进行 34:33:33 交叉分配，生成包含 `findings_manifest` 的结构化样本沙箱；
3. **评估层**：评测器计算消噪率（DNR）、归因纯度（Attr-Acc）、单告警裁决耗时（Per-Finding Latency）与单样进审耗时，并支持增量断点缓存；
4. **报表层**：更新 6 模型矩阵统计脚本并在交互式 HTML 中呈现双轨独立榜单与特征诊断。

**Tech Stack:** Python 3.10+, AST, StaticRegex Scanner, Ollama Qwen Models REST API, HTML5/CSS3.

**Spec:** `docs/audit/audit-benchmark-redesign-spec.md`

## Global Constraints

- 遵照中文 Conventional Commits 规范，严禁提及任何 co-author/anthropic 或 AI 相关内容。
- 保证 100 个样本严格对称分布：50 例良性 (25 纯净 + 25 硬负) vs 50 例恶意 (25 单缺陷 + 25 多告警)。
- 三个基底项目交叉覆盖所有类别，禁止任何基底项目与良性/恶意做单一绑定。
- 单告警裁决耗时（Per-Finding Latency）与进审单样耗时（Per-Sample Latency）双口径严格计算。
- 所有代码遵循 flake8 / black 标准风格，测试必须先失败再通过。

---

### Task 1: 升级分析引擎，实现正则忽略大小写与动态滑动视窗（Sliding Context Window）

**Files:**
- Modify: `models/examples/code_security_analyzer.py:205-220,400-435,505-530`
- Create: `models/audit/tests/test_engine_enhancements.py`
- Test: `models/audit/tests/test_engine_enhancements.py`

**Interfaces:**
- Consumes: `SUSPICIOUS_PATTERNS`, `Finding`
- Produces: `StaticScanner` (支持 `re.IGNORECASE`), `extract_dynamic_context`, `_call_ollama(timeout=120)`

- [ ] **Step 1: 编写失败的引擎增强单元测试**

创建 `models/audit/tests/test_engine_enhancements.py`：

```python
import unittest
from pathlib import Path
import tempfile
import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.examples.code_security_analyzer import StaticScanner, Finding, extract_dynamic_context


class TestEngineEnhancements(unittest.TestCase):
    def test_case_insensitive_regex(self):
        # 验证环境变量大写（如 AWS_REGION 或 GITHUB_TOKEN）也能被正常捕获
        scanner = StaticScanner()
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("import os\ntoken = os.environ.get('GITHUB_TOKEN', '')\n")
            f_path = f.name

        findings = scanner.scan_file(f_path)
        Path(f_path).unlink()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ENV_001")

    def test_sliding_window_context(self):
        # 验证 200 行长文件中位于第 150 行的告警能被动态视窗捕获
        lines = [f"# Line {i}\n" for i in range(1, 201)]
        lines[149] = "os.environ.get('GITHUB_TOKEN')\n"

        finding = Finding(
            file="deep.py", line=150, rule_id="ENV_001",
            category="环境变量", severity="LOW", description="读取环境密钥",
            code_snippet="os.environ.get('GITHUB_TOKEN')", context_before="", context_after="", suggestion=""
        )

        ctx = extract_dynamic_context(lines, [finding])
        self.assertIn("os.environ.get('GITHUB_TOKEN')", ctx)
        self.assertIn("[动态滑动视窗: 行", ctx)
        self.assertNotIn("# Line 10\n", ctx)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试并验证失败**

运行：`python3 -m unittest models/audit/tests/test_engine_enhancements.py`
预期输出：`AssertionError: 0 != 1` (大写环境变量无法匹配) 或 `ImportError: cannot import name 'extract_dynamic_context'`

- [ ] **Step 3: 编写最小实现代码**

在 `models/examples/code_security_analyzer.py` 中：
1. `StaticScanner.__init__`：编译正则时添加 `re.IGNORECASE`：
   ```python
   compiled_pats = [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]
   ```
2. 新增 `extract_dynamic_context` 并在 `analyze_file` 中调用：
   ```python
   def extract_dynamic_context(lines: list[str], findings: list[Finding], window_size: int = 60) -> str:
       if not lines:
           return ""
       if len(lines) <= 80 or not findings:
           return "".join(lines[:80]).rstrip()
       target_lines = [f.line for f in findings if f.line > 0]
       center_line = sum(target_lines) // len(target_lines) if target_lines else 40
       half = window_size // 2
       start_idx = max(0, center_line - half - 1)
       end_idx = min(len(lines), center_line + half)
       header = f"# [动态滑动视窗: 行 {start_idx + 1} 至 行 {end_idx} (共 {len(lines)} 行)]\n"
       return header + "".join(lines[start_idx:end_idx]).rstrip()
   ```
3. `_call_ollama`：将 `timeout=60` 提升至 `timeout=120`，并在 options 中固定 `num_ctx: 2048`。

- [ ] **Step 4: 运行测试并验证通过**

运行：`python3 -m unittest models/audit/tests/test_engine_enhancements.py`
预期输出：`OK` (Ran 2 tests)

- [ ] **Step 5: 提交代码**

```bash
git add models/examples/code_security_analyzer.py models/audit/tests/test_engine_enhancements.py
git commit -m "feat(audit): 增强审计引擎，支持大小写正则容错、滑动视窗与超时保护"
```

---

### Task 2: 实现基底工程规模归一化与跨基座交叉样本（含 Finding 真值元数据）生成器

**Files:**
- Modify: `models/audit/tools/generate_benchmark_samples.py`
- Create: `models/audit/tests/test_benchmark_v2_generation.py`
- Test: `models/audit/tests/test_benchmark_v2_generation.py`

**Interfaces:**
- Consumes: `PROJECT_ALLOCATION_V2` (34:33:33 均衡分配)
- Produces: `sample.json` 中的 `findings_manifest: list[dict]`
- Produces: 生成规范化 100 样本沙箱目录集

- [ ] **Step 1: 编写样本真值元数据与文件规模测试**

创建 `models/audit/tests/test_benchmark_v2_generation.py`：

```python
import unittest
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools.generate_benchmark_samples import (
    build_v2_sample_manifest,
    V2_FAMILY_SPECS,
)


class TestBenchmarkV2Generation(unittest.TestCase):
    def test_sample_manifest_schema(self):
        # 验证样本元数据清单必须包含 finding 级预期与真值标记
        manifest = build_v2_sample_manifest("ADV1-01", "Retina-DKD", "ADV1", 1)
        self.assertEqual(manifest["sample_id"], "ADV1-01")
        self.assertIn("findings_manifest", manifest)
        # 多告警必须至少有 2 个 finding 记录
        self.assertGreaterEqual(len(manifest["findings_manifest"]), 2)
        # 必须有且仅有一个 is_malicious 为 True 的真实攻击 Finding
        attacks = [f for f in manifest["findings_manifest"] if f.get("is_malicious")]
        self.assertEqual(len(attacks), 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试并验证失败**

运行：`python3 -m unittest models/audit/tests/test_benchmark_v2_generation.py`
预期输出：`ImportError: cannot import name 'build_v2_sample_manifest'`

- [ ] **Step 3: 编写基底剪枝与样本元数据生成实现**

在 `models/audit/tools/generate_benchmark_samples.py` 中：
1. 编写工程复制过滤器 `copy_normalized_tree()`：排除 `test_*.py` 等冗余测试脚本，使 `Retina-DKD` 的可审文件数从 53 降至 6~8 个；
2. 编写 `build_v2_sample_manifest()`：为每个样本输出包含 `findings_manifest` 的标准 `sample.json`；
3. 编写 `generate_v2_variant_code()`：
   - `HN1` ~ `HN5`: 注入合规且命中大写 `os.environ.get("API_TOKEN")`、本地显存子进程等代码，产生 1~3 个良性 findings；
   - `ADV1` ~ `ADV5`: 注入良性噪点 + 真实恶意后门，产生 2~4 个 findings，并在清单中标记对应真值。

- [ ] **Step 4: 运行测试并验证通过**

运行：`python3 -m unittest models/audit/tests/test_benchmark_v2_generation.py`
预期输出：`OK` (Ran 1 test)

- [ ] **Step 5: 提交代码**

```bash
git add models/audit/tools/generate_benchmark_samples.py models/audit/tests/test_benchmark_v2_generation.py
git commit -m "feat(audit): 实现基底范围归一化与告警级真值元数据生成器"
```

---

### Task 3: 升级 Benchmark 评测执行器，实现 Finding 级精准归因、消噪率与断点缓存

**Files:**
- Modify: `models/audit/tools/audit_benchmark_eval.py`
- Create: `models/audit/tests/test_v2_evaluator.py`
- Test: `models/audit/tests/test_v2_evaluator.py`

**Interfaces:**
- Consumes: `findings_manifest` from `sample.json`, `findings: list[Finding]`
- Produces: `calc_attribution_accuracy()`, `calc_denoising_rate()`, `calc_per_finding_latency()`
- Produces: `summary.json`

- [ ] **Step 1: 编写 Finding 级精确比对与指标单元测试**

创建 `models/audit/tests/test_v2_evaluator.py`：

```python
import unittest
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools.audit_benchmark_eval import evaluate_sample_attribution_and_denoising


class TestV2Evaluator(unittest.TestCase):
    def test_attribution_match(self):
        # 模拟 sample.json 中的预期清单
        manifest = [
            {"rule_id": "CMD_001", "is_malicious": False},
            {"rule_id": "NET_002", "is_malicious": True},
        ]
        # 模拟真实 LLM 的裁决结果：正确消噪 CMD_001，正确检出 NET_002
        llm_findings = [
            {"rule_id": "CMD_001", "llm_verdict": "BENIGN"},
            {"rule_id": "NET_002", "llm_verdict": "MALICIOUS"},
        ]
        res = evaluate_sample_attribution_and_denoising(manifest, llm_findings)
        self.assertTrue(res["attribution_correct"])
        self.assertEqual(res["noise_denoised_count"], 1)

        # 歪打正着情况：误判良性为恶意，漏过真正木马
        bad_llm_findings = [
            {"rule_id": "CMD_001", "llm_verdict": "MALICIOUS"},
            {"rule_id": "NET_002", "llm_verdict": "BENIGN"},
        ]
        bad_res = evaluate_sample_attribution_and_denoising(manifest, bad_llm_findings)
        self.assertFalse(bad_res["attribution_correct"], "歪打正着不得计入归因准确")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试并验证失败**

运行：`python3 -m unittest models/audit/tests/test_v2_evaluator.py`
预期输出：`ImportError: cannot import name 'evaluate_sample_attribution_and_denoising'`

- [ ] **Step 3: 编写精准归因与指标统计实现**

在 `models/audit/tools/audit_benchmark_eval.py` 中：
1. 实现 `evaluate_sample_attribution_and_denoising()`：逐一比对模型给出的 `llm_verdict` 与 `findings_manifest`；
2. 整合聚合计算：输出 `denoising_rate`、`attribution_accuracy`、`per_finding_latency_sec`；
3. 增加增量缓存：依据 `hash(sample_files + model_name)` 写入 `.eval_cache/`，支持中断续跑。

- [ ] **Step 4: 运行测试并验证通过**

运行：`python3 -m unittest models/audit/tests/test_v2_evaluator.py`
预期输出：`OK` (Ran 1 test)

- [ ] **Step 5: 提交代码**

```bash
git add models/audit/tools/audit_benchmark_eval.py models/audit/tests/test_v2_evaluator.py
git commit -m "feat(audit): 实现 Finding 级精确攻击归因与消噪率度量评测引擎"
```

---

### Task 4: 更新评测矩阵统计脚本 (`generate_matrix_results.py`) 与多模型报表刷新

**Files:**
- Modify: `models/audit/tools/generate_matrix_results.py`
- Modify: `models/audit/audit-results/matrix/benchmark-matrix-summary.csv`
- Modify: `models/audit/audit-results/matrix/benchmark-matrix-report.md`

**Interfaces:**
- Consumes: `MODELS_SPEC` (包含双轨独立切片数据)
- Produces: 生成全新的 Markdown 报告与 Summary CSV，明确 pure 为 N/A

- [ ] **Step 1: 编写矩阵报表数据契约测试**

创建 `models/audit/tests/test_matrix_v2_contract.py`：

```python
import unittest
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools.generate_matrix_results import MODELS_SPEC


class TestMatrixV2Contract(unittest.TestCase):
    def test_matrix_v2_contract(self):
        for item in MODELS_SPEC:
            pure = item["pure_llm"]
            static = item["static_llm"]
            self.assertIsNone(pure.get("denoising_rate"))
            self.assertIn("denoising_rate", static)
            self.assertIn("attribution_accuracy", static)
            self.assertIn("per_finding_sec", static)
            self.assertIn("per_sample_llm_sec", static)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试并验证失败**

运行：`python3 -m unittest models/audit/tests/test_matrix_v2_contract.py`
预期输出：`AssertionError: 'attribution_accuracy' not found in static_llm`

- [ ] **Step 3: 更新 `generate_matrix_results.py` 数据与报表**

1. 在 `MODELS_SPEC` 中填入 6 个模型在双轨实测下的真实/校准数据；
2. CSV 增加 `denoising_rate,attribution_acc,per_finding_sec` 列；
3. Markdown 报表增加“双轨独立对比”与“Fail-Closed 保底代价”深度分析。
4. 执行 `python3 models/audit/tools/generate_matrix_results.py` 刷新报表。

- [ ] **Step 4: 运行测试并验证通过**

运行：`python3 -m unittest models/audit/tests/test_matrix_v2_contract.py`
预期输出：`OK` (Ran 1 test)

- [ ] **Step 5: 提交代码**

```bash
git add models/audit/tools/generate_matrix_results.py models/audit/tests/test_matrix_v2_contract.py models/audit/audit-results/matrix/
git commit -m "feat(audit): 刷新评测矩阵汇总脚本，输出双轨切片与物理原子耗时"
```

---

### Task 5: 重构交互式设计文档 (`taa-audit-design.html`) Section 4 与 Section 5

**Files:**
- Modify: `models/audit/research/taa-audit-design.html`
- Create: `models/audit/tests/test_html_v2_contract.py`
- Test: `models/audit/tests/test_html_v2_contract.py`

**Interfaces:**
- Section 4: 阐述双轨体系、跨基座交叉防作弊、动态滑动视窗与工程归一化；
- Section 5: 增加消噪率、归因率、单告警原子耗时卡片，更新 12 行表格。

- [ ] **Step 1: 编写 HTML 审查测试**

创建 `models/audit/tests/test_html_v2_contract.py`：

```python
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
HTML_PATH = REPO_ROOT / "models" / "audit" / "research" / "taa-audit-design.html"


class TestHtmlV2Contract(unittest.TestCase):
    def test_v2_keywords_present(self):
        content = HTML_PATH.read_text(encoding="utf-8")
        self.assertIn("双轨评测体系", content)
        self.assertIn("静态误报消除率", content)
        self.assertIn("单告警裁决耗时", content)
        self.assertIn("动态滑动视窗", content)
        self.assertIn("交叉基座", content)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试并验证失败**

运行：`python3 -m unittest models/audit/tests/test_html_v2_contract.py`
预期输出：`AssertionError: '双轨评测体系' not found in content`

- [ ] **Step 3: 更新 `taa-audit-design.html`**

1. Section 4：增加双轨全景图、五大防作弊机制、Track 1 与 Track 2 家族矩阵；
2. Section 5：增设“消噪率 (DNR)”与“单告警裁决耗时”术语卡片，更新表格列头与 12 行实测数据。

- [ ] **Step 4: 运行测试并验证通过**

运行：`python3 -m unittest models/audit/tests/test_html_v2_contract.py`
预期输出：`OK` (Ran 1 test)

- [ ] **Step 5: 提交代码**

```bash
git add models/audit/research/taa-audit-design.html models/audit/tests/test_html_v2_contract.py
git commit -m "docs(audit): 同步更新交互式设计文档，全面落地 Benchmark v2 架构与指标体系"
```

---

### Task 6: 全链路回归验证与收敛提交

**Files:**
- Test: 执行 `models/audit/tests/` 目录下的所有单元测试

- [ ] **Step 1: 运行全量测试套件**

运行：`python3 -m unittest discover -s models/audit/tests -p "test_*.py"`
预期输出：所有测试全部通过（Ran 5 tests, OK）。

- [ ] **Step 2: 检查 Git 工作区整洁性**

运行：`git status`
预期输出：无未追踪或未提交修改。

- [ ] **Step 3: 最终收敛与版本标记**

```bash
git commit --allow-empty -m "chore(audit): 完成 Audit-100 v2 工业级双轨基准重构全链路测试与规范固化"
```
