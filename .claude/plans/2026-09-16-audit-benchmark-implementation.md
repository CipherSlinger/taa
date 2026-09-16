# Audit-100 v2 Benchmark 重构实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 基于 `.claude/specs/2026-09-16-audit-benchmark-design.md`，构建 4 大真实自包含工业基座与微缩数据集，重构 Python 审计引擎以对齐 13 条生产规则与 Fail-Closed 决策门禁，升级样本生成器实现 4 基座 × 10 家族 100 样本完全正交平衡物化，并升级三轨公平评测套件与 Bootstrap 置信度度量体系。

**Architecture:** 
- **基座层**：在 `models/audit/benchmarks/base-projects/` 构建 4 个精简工业微工程（金融 XGBoost、医学 Retina、质检 Detection、文本 BERT），微缩资产 < 1MB，内嵌生命周期钩子并严格清洗至 0 Finding。
- **引擎与门禁层**：在 `models/examples/code_security_analyzer.py` 中完整镜像 Go 端 13 条生产规则，升级 400 行 + Finding 锚点动态切片，统一 Gate 门禁决策为 Fail-Closed。
- **物化与生成层**：在 `models/audit/tools/generate_benchmark_samples.py` 中实现 50:50 正交平衡矩阵分配、提示词防越狱探针与 Safe Sink 安全沙箱，生成 Finding 级真值元数据。
- **评测与度量层**：在 `models/audit/tools/audit_benchmark_eval.py` 中支持三轨公平对照（Raw vs Checklist vs 动静协同）、Finding 级归因精准率与 1,000 次 Bootstrap 95% 置信区间。

**Tech Stack:** Python 3.10+ (纯标准库运行), PyTorch/TorchVision/XGBoost/Transformers (轻量抽象与保护性导入), Go 1.22+ (`internal/codeaudit/` 生产对齐), Ollama (本地 Qwen 模型推理)

---

### File Structure & Changes Map

```
models/audit/benchmarks/base-projects/
├── p1_xgboost_finance/          [Create: 金融表格微工程: train.py, dataset.py, model.py, data/creditcard_sample.csv]
├── p2_retina_resnet/            [Create: 医学视觉微工程: train.py, dataset.py, model.py, data/ (5 张图像)]
├── p3_detection_industrial/     [Create: 工业检测微工程: train.py, dataset.py, model.py, data/ (5 张图像+yaml)]
└── p4_bert_sentiment/          [Create: 文本情感微工程: train.py, dataset.py, model.py, data/ (vocab.txt+reviews.jsonl)]

models/examples/
└── code_security_analyzer.py    [Modify: 对齐 13 条生产规则、升级 400 行+锚点切片、重构 Fail-Closed Gate]

models/audit/tools/
├── generate_benchmark_samples.py [Modify: 4 基座 × 10 家族 100 样本正交生成、钩子挂载、Safe Sink]
├── audit_benchmark_eval.py       [Modify: 三轨评测模式、归因精准率度量、Bootstrap 95% 置信区间]
└── generate_matrix_results.py    [Modify: 汇总三轨数据与生成综合报告]

tests/
├── test_benchmark_base_projects.py   [Create: 验证 4 大基座语法编译与 0 Finding 底噪门禁]
├── test_code_security_analyzer_v2.py [Create: 验证 13 规则、切片与 Fail-Closed 决策单元测试]
├── test_benchmark_samples_matrix.py  [Create: 验证 100 样本正交矩阵配比与元数据清单]
└── test_audit_eval_three_track.py    [Create: 验证三轨评测与 Bootstrap 算法逻辑]
```

---

### Task 1: 构建 4 大真实工业基座微工程与微缩数据集

**Files:**
- Create: `models/audit/benchmarks/base-projects/p1_xgboost_finance/train.py`
- Create: `models/audit/benchmarks/base-projects/p1_xgboost_finance/dataset.py`
- Create: `models/audit/benchmarks/base-projects/p1_xgboost_finance/model.py`
- Create: `models/audit/benchmarks/base-projects/p1_xgboost_finance/data/creditcard_sample.csv`
- Create: `models/audit/benchmarks/base-projects/p2_retina_resnet/train.py`
- Create: `models/audit/benchmarks/base-projects/p2_retina_resnet/dataset.py`
- Create: `models/audit/benchmarks/base-projects/p2_retina_resnet/model.py`
- Create: `models/audit/benchmarks/base-projects/p2_retina_resnet/data/`
- Create: `models/audit/benchmarks/base-projects/p3_detection_industrial/train.py`
- Create: `models/audit/benchmarks/base-projects/p3_detection_industrial/dataset.py`
- Create: `models/audit/benchmarks/base-projects/p3_detection_industrial/model.py`
- Create: `models/audit/benchmarks/base-projects/p3_detection_industrial/data/`
- Create: `models/audit/benchmarks/base-projects/p4_bert_sentiment/train.py`
- Create: `models/audit/benchmarks/base-projects/p4_bert_sentiment/dataset.py`
- Create: `models/audit/benchmarks/base-projects/p4_bert_sentiment/model.py`
- Create: `models/audit/benchmarks/base-projects/p4_bert_sentiment/data/`
- Test: `tests/test_benchmark_base_projects.py`

- [ ] **Step 1: 编写基座工程自检单元测试**

在 `tests/test_benchmark_base_projects.py` 中编写测试：
1. 检查 `base-projects` 下存在 `p1_xgboost_finance`, `p2_retina_resnet`, `p3_detection_industrial`, `p4_bert_sentiment` 四个目录；
2. 检查每个基座下均包含 `train.py`, `dataset.py`, `model.py` 及内置 `data/` 目录；
3. 对每个 `.py` 文件执行 `py_compile.compile(..., doraise=True)`，验证语法合法性；
4. 运行现有的静态规则扫描，验证 4 个基座在原始状态下命中 Finding 数严格为 0。

```python
import os
import py_compile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_PROJECTS_DIR = REPO_ROOT / "models" / "audit" / "benchmarks" / "base-projects"

class TestBenchmarkBaseProjects(unittest.TestCase):
    def test_base_projects_exist_and_compile(self):
        expected_bases = ["p1_xgboost_finance", "p2_retina_resnet", "p3_detection_industrial", "p4_bert_sentiment"]
        for base in expected_bases:
            base_dir = BASE_PROJECTS_DIR / base
            self.assertTrue(base_dir.is_dir(), f"Base project directory missing: {base_dir}")
            for py_name in ["train.py", "dataset.py", "model.py"]:
                py_file = base_dir / py_name
                self.assertTrue(py_file.is_file(), f"Core file missing: {py_file}")
                # Must compile cleanly without errors
                py_compile.compile(str(py_file), doraise=True)
            self.assertTrue((base_dir / "data").is_dir(), f"Data directory missing: {base_dir / 'data'}")
```

- [ ] **Step 2: 运行测试以确认基座目录尚未创建 (FAIL)**

运行: `python3 -m unittest tests/test_benchmark_base_projects.py -v`
预期结果: FAIL (Base project directory missing)

- [ ] **Step 3: 构建 P1 XGBoost 金融表格风控基座**

创建 `models/audit/benchmarks/base-projects/p1_xgboost_finance/`:
- `data/creditcard_sample.csv`: 真实微缩抽样 100 条脱敏金融数据 (`Time,V1...V28,Amount,Class`)；
- `dataset.py`: 封装数据读取、空值处理、归一化缩放与特征列提取；
- `model.py`: 封装 XGBoost 分类器超参数配置与模型定义，提供保护性导入降级；
- `train.py`: 执行 2 折交叉验证与模型训练，打印评估 AUC/F1，合规保存权重到输出目录，并在循环末尾插入生命周期钩子：
  ```python
  # --- TAA Audit Variant Lifecycle Hook ---
  try:
      import benchmark_variant
      benchmark_variant.on_epoch_end(epoch=0, metrics={"f1": 0.92, "auc": 0.95})
  except (ImportError, AttributeError):
      pass
  ```

- [ ] **Step 4: 构建 P2 Retina ResNet 医学影像分类基座**

创建 `models/audit/benchmarks/base-projects/p2_retina_resnet/`:
- `data/`: 放置 5 张真实医学眼底切片灰度图（各 ~40KB，总计 < 250KB）；
- `dataset.py`: PyTorch Dataset 封装，医学图像读取与标准化预处理，保护性导入；
- `model.py`: ResNet-50 骨干网络与��类头；
- `train.py`: 训练主循环，计算 CrossEntropyLoss，保存检查点，插入 `benchmark_variant.on_epoch_end` 钩子，**杜绝任何原生 os.system 或 eval 底噪**。

- [ ] **Step 5: 构建 P3 Detection Industrial 工业质检目标检测基座**

创建 `models/audit/benchmarks/base-projects/p3_detection_industrial/`:
- `data/`: 放置 5 张微型工业表面划痕/缺陷切片图与对应的边界框标签 `annotations.yaml`；
- `dataset.py`: 解析缺陷标注与图像张量转换；
- `model.py`: 基于 BSD-3-Clause / Apache-2.0 商业友好许可的精简检测网络（TorchVision Detection / YOLOX 结构），彻底排除 AGPL 协议源码；
- `train.py`: 边界框回归训练主干，合规评估 mAP，插入 `benchmark_variant.on_epoch_end` 钩子。

- [ ] **Step 6: 构建 P4 BERT 现代文本情感分析微调基座**

创建 `models/audit/benchmarks/base-projects/p4_bert_sentiment/`:
- `data/`: 迷你 `vocab.txt` (100 常用词) 与 20 条脱敏短评语料；
- `dataset.py`: 离线 Token 分词映射与 Padding 序列填充；
- `model.py`: Transformer 编码层与序列分类器定义；
- `train.py`: 微调前向计算、梯度累积与评估指标统计，插入 `benchmark_variant.on_epoch_end` 钩子。

- [ ] **Step 7: 运行自检测试并验证 0 Finding 门禁 (PASS)**

运行: `python3 -m unittest tests/test_benchmark_base_projects.py -v`
预期结果: PASS (4 个基座全部存在、全部通过 py_compile、代码结构符合规范)

- [ ] **Step 8: 提交基座工程**

```bash
git add models/audit/benchmarks/base-projects/ tests/test_benchmark_base_projects.py
git commit -m "feat(audit): add four self-contained industrial benchmark base projects"
```

---

### Task 2: Python 评测引擎规则与切片/门禁升级 (Engine Parity)

**Files:**
- Modify: `models/examples/code_security_analyzer.py`
- Test: `tests/test_code_security_analyzer_v2.py`

- [ ] **Step 1: 编写引擎 13 规则、400 行切片与 Fail-Closed 单元测试**

在 `tests/test_code_security_analyzer_v2.py` 中编写测试套件：
1. **规则覆盖测试**：验证 `StaticScanner` 拥有完整的 13 条规则，包含 `EMB_001`~`EMB_004`，对 `torch.save(raw_data)` 命中 `EMB_001`，对 `os.environ.get('AWS_SECRET')` 命中 `ENV_001`，对合规 `torch.save(model.state_dict())` 不产生误报；
2. **切片测试**：输入 500 行长代码并在 350 行植入违规语句，验证分析引擎能生成包含 350 行前后 15 行的局部切片与头部 Import；
3. **Fail-Closed 决策测试**：
   - 验证 `UNCERTAIN` + HIGH finding 时，`compute_conclusion` 返回 `passed = False`；
   - 验证全部告警被判定为 `BENIGN` 时，返回 `passed = True`；
   - 验证 `file_summary` 中包含 `chained = True` 时，强制返回 `passed = False`。

- [ ] **Step 2: 运行测试以确认当前引擎未实现 13 规则与 Fail-Closed (FAIL)**

运行: `python3 -m unittest tests/test_code_security_analyzer_v2.py -v`
预期结果: FAIL

- [ ] **Step 3: 在 `code_security_analyzer.py` 中对齐 13 条生产规则**

同步 Go `internal/codeaudit/rules.go`：
- 在 `StaticScanner.RULES` 中补齐 `EMB_001`（原始数据落盘）、`EMB_002`（数据拷入输出目录）、`EMB_003`（日志打印原始数据）、`EMB_004`（数据隐写嵌入权重）；
- 升级 `ENV_001` 正则，支持忽略大小写（`re.IGNORECASE`）检测 `API_KEY`、`TOKEN` 等全大写环境变量；
- 优化 `CMD_001` 正则，仅在 `shell=True` 或调用 `bash/sh/curl/wget/rm` 等危险外壳时触发，放行常规参数化子进程。

- [ ] **Step 4: 改造长文件感知：400 行全局阈值 + Finding 锚点上下文切片**

在 `code_security_analyzer.py` 的 `analyze_file` 与切片逻辑中：
- 将头部盲目截取行数从 80 行提升至 400 行；
- 当文件总行数超过 400 行时，引入 `extract_finding_centered_context(code_lines, findings)`：
  1. 提取头部 Imports（前 20 行）；
  2. 针对每个 Finding 所在行 `L`，截取 `[max(0, L-15), min(len(lines), L+15)]` 行区间，标注 `[Line X - Line Y Context Window]`；
  3. 保留末尾 `if __name__ == '__main__':` 入口定义；
  4. 组合为结构化上下文提供给大模型整文件研判。

- [ ] **Step 5: 重构 `compute_conclusion` 落实 Fail-Closed 安全底线与攻击链融合**

在 `code_security_analyzer.py` 中重构决策门禁：
```python
def compute_conclusion(stats: dict, file_summaries: list = None, policy: dict = None) -> dict:
    has_high_or_medium = (stats.get("high", 0) > 0) or (stats.get("medium", 0) > 0)
    has_uncertain = stats.get("uncertain", 0) > 0
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0 or suspicious > 0:
        return {"passed": False, "verdict": "MALICIOUS", "reason": "Confirmed security violation present"}

    if has_uncertain and has_high_or_medium:
        return {"passed": False, "verdict": "UNCERTAIN", "reason": "Fail-Closed: LLM uncertain on high/medium risk finding"}

    if has_high_or_medium and not stats.get("has_llm_verdict", False):
        return {"passed": False, "verdict": "SUSPICIOUS", "reason": "High/medium findings not exonerated by LLM"}

    if file_summaries:
        for fs in file_summaries:
            if fs.get("chained", False) or fs.get("exfiltration", False) or fs.get("risk_level") in ("CRITICAL", "HIGH"):
                return {"passed": False, "verdict": "MALICIOUS", "reason": "File-level attack chain detected"}

    return {"passed": True, "verdict": "BENIGN", "reason": "All findings cleared as benign or zero findings"}
```

- [ ] **Step 6: 同步生产级 Prompt 模板与良性白名单指导**

将 Go 端 `verifier.go` 中的 Prompt 判定准则同步至 `LLMSecurityAnalyzer.DEFAULT_PROMPT_TEMPLATE`，明确阐述模型权重保存、Loss 打印、本地配置读取均属于合规操作，必须判定为 `BENIGN`。

- [ ] **Step 7: 运行引擎测试验证对齐效果 (PASS)**

运行: `python3 -m unittest tests/test_code_security_analyzer_v2.py -v`
预期结果: PASS

- [ ] **Step 8: 提交引擎重构代码**

```bash
git add models/examples/code_security_analyzer.py tests/test_code_security_analyzer_v2.py
git commit -m "feat(audit): upgrade python security analyzer with 13 rules and fail-closed gate"
```

---

### Task 3: 样本生成器重构与 100 样本正交物化 (Generator & 100 Samples)

**Files:**
- Modify: `models/audit/tools/generate_benchmark_samples.py`
- Test: `tests/test_benchmark_samples_matrix.py`

- [ ] **Step 1: 编写 100 样本正交物化验证测试**

在 `tests/test_benchmark_samples_matrix.py` 中编写验证脚本：
1. 验证目标目录 `models/audit/benchmarks/audit-100/` 下存在恰好 100 个独立沙箱；
2. 验证基座分布严格对称：4 个基座各包含恰好 25 个样本；
3. 验证标签分布严格对称：50 个样本 `label: "benign"`，50 个样本 `label: "malicious"`；
4. 验证家族分布严格对称：10 个家族（B1~B5, M1~M5）各包含恰好 10 个样本；
5. 验证每个沙箱的 `sample.json` 均包含 `primary_attack_finding` 和 `findings_manifest` 结构；
6. 验证所有生成的 `benchmark_variant.py` 均包含 `def on_epoch_end(epoch, metrics):` 入口。

- [ ] **Step 2: 运行测试以确认当前生成器未支持 4 基座正交生成 (FAIL)**

运行: `python3 -m unittest tests/test_benchmark_samples_matrix.py -v`
预期结果: FAIL

- [ ] **Step 3: 重构 `generate_benchmark_samples.py` 的正交分配与基座读取**

在 `generate_benchmark_samples.py` 中：
1. 废除旧的 3 基座分配字典，升级为 4 基座正交分配：
   ```python
   PROJECT_ALLOCATION = {
       "B1": {"p1_xgboost_finance": 3, "p2_retina_resnet": 2, "p3_detection_industrial": 3, "p4_bert_sentiment": 2},
       "B2": {"p1_xgboost_finance": 2, "p2_retina_resnet": 3, "p3_detection_industrial": 2, "p4_bert_sentiment": 3},
       "B3": {"p1_xgboost_finance": 3, "p2_retina_resnet": 2, "p3_detection_industrial": 3, "p4_bert_sentiment": 2},
       "B4": {"p1_xgboost_finance": 2, "p2_retina_resnet": 3, "p3_detection_industrial": 2, "p4_bert_sentiment": 3},
       "B5": {"p1_xgboost_finance": 3, "p2_retina_resnet": 2, "p3_detection_industrial": 2, "p4_bert_sentiment": 3},
       "M1": {"p1_xgboost_finance": 2, "p2_retina_resnet": 3, "p3_detection_industrial": 2, "p4_bert_sentiment": 3},
       "M2": {"p1_xgboost_finance": 3, "p2_retina_resnet": 2, "p3_detection_industrial": 3, "p4_bert_sentiment": 2},
       "M3": {"p1_xgboost_finance": 2, "p2_retina_resnet": 3, "p3_detection_industrial": 2, "p4_bert_sentiment": 3},
       "M4": {"p1_xgboost_finance": 3, "p2_retina_resnet": 2, "p3_detection_industrial": 3, "p4_bert_sentiment": 2},
       "M5": {"p1_xgboost_finance": 2, "p2_retina_resnet": 3, "p3_detection_industrial": 3, "p4_bert_sentiment": 2},
   }
   ```
2. 将复制源从旧的 `models/examples/` 重定向到 `models/audit/benchmarks/base-projects/`；
3. 放行微缩数据目录 `data/` 及其内部 `.csv`, `.png`, `.yaml`, `.txt` 文件的拷贝，仅过滤 `.git`, `__pycache__`, `*.pyc`。

- [ ] **Step 4: 改造变体代码生成器：标准钩子、提示词防越狱探针与 Safe Sink**

为 10 个家族模板统一添加生命周期接口与安全靶场约束：
- 所有模板统一封装在 `def on_epoch_end(epoch, metrics=None):` 中执行；
- 在 M1~M5 中混入语义欺骗注释与格式伪造探针；
- 所有网络外联强制重定向到 `https://collector.example.invalid`（RFC 2606）；
- 所有文件持久化强制指向 `/tmp/sandbox_test_profile`；
- 在 `sample.json` 中写出 `primary_attack_finding` 与 `findings_manifest`。

- [ ] **Step 5: 执行生成命令原地物化 100 样本测试沙箱**

运行命令:
```bash
python3 models/audit/tools/generate_benchmark_samples.py --clean
```
预期输出: 成功物化 100 个样本沙箱，并在 `docs/audit/audit-benchmark-manifest.json` 更新清单元数据。

- [ ] **Step 6: 运行正交性与语法自检测试 (PASS)**

运行: `python3 -m unittest tests/test_benchmark_samples_matrix.py -v`
预期结果: PASS (100 个样本严格满足 50:50 良恶、4 基座 25 样本、10 家族各 10 样本的完全正交要求，且全部通过 py_compile)

- [ ] **Step 7: 提交样本生成器修改与清单文件**

```bash
git add models/audit/tools/generate_benchmark_samples.py docs/audit/audit-benchmark-manifest.json tests/test_benchmark_samples_matrix.py
git commit -m "feat(audit): rewrite benchmark generator with orthogonal matrix and lifecycle hooks"
```

---

### Task 4: 评测执行套件升级 (Three-Track Evaluation & Bootstrap CI)

**Files:**
- Modify: `models/audit/tools/audit_benchmark_eval.py`
- Test: `tests/test_audit_eval_three_track.py`

- [x] **Step 1: 编写三轨评测与指标计算单元测试**

在 `tests/test_audit_eval_three_track.py` 中编写测试：
1. 测试三种模式命令行参数解析：`pure-llm`, `pure-llm-checklist`, `static-llm`；
2. 测试 `pure-llm-checklist` 能够正确将 13 规则描述注入 Prompt；
3. 测试 Finding 级关键攻击归因率（Attribution Precision）计算逻辑；
4. 测试 Bootstrap 1,000 次重采样 95% 置信区间函数 `compute_bootstrap_ci(scores, n_bootstraps=1000)` 的数学收敛性。

- [x] **Step 2: 运行测试验证缺失的三轨模式与置信区间函数 (FAIL)**

运行: `python3 -m unittest tests/test_audit_eval_three_track.py -v`
预期结果: FAIL

- [x] **Step 3: 升级 `audit_benchmark_eval.py` 评测流水线**

在 `audit_benchmark_eval.py` 中：
1. 扩展 `--audit-mode` 参数，增加 `pure-llm-checklist` 支持；
2. 在 `pure-llm-checklist` 模式下，构建包含 13 条规则详细定义的 System Prompt 头部注入大模型；
3. 在评测结果聚合时，增加 `Attribution Precision` 计算：比对被阻断样本中的触发 Finding 是否与 `sample.json` 中的 `primary_attack_finding` 一致；
4. 实现基于纯标准库（`random`, `math`）的 Bootstrap 1,000 次重采样算法，为 `Accuracy`, `F1`, `FPR`, `Recall` 自动计算 95% 置信区间；
5. 在输出 JSON 中保存包含置信区间与旁路率的完整报表。

- [x] **Step 4: 运行评测套件单元测试 (PASS)**

运行: `python3 -m unittest tests/test_audit_eval_three_track.py -v`
预期结果: PASS

- [x] **Step 5: 提交评测套件代码**

```bash
git add models/audit/tools/audit_benchmark_eval.py tests/test_audit_eval_three_track.py
git commit -m "feat(audit): implement three-track evaluation and bootstrap confidence interval in benchmark runner"
```

---

### Task 5: 综合评测矩阵与 HTML 报告生成脚本升级

**Files:**
- Modify: `models/audit/tools/generate_matrix_results.py`
- Test: 验证脚本执行与数据格式校验

- [x] **Step 1: 升级 `generate_matrix_results.py` 表格生成与报告更新功能**

在 `generate_matrix_results.py` 中：
1. 适配三轨对比（Raw vs Checklist vs Static-LLM）及 4 大新基座的数据聚合；
2. 在报表输出中呈现 `Attribution Precision`、`Bypass Rate` 与 `95% CI`；
3. 提供 `--dry-run` 打印测试结果，提供 `--update-html` 刷新 `models/audit/research/taa-audit-design.html`。

- [x] **Step 2: 执行基准套件整体端到端演练 (Dry-Run / Mock)**

运行：
```bash
python3 models/audit/tools/generate_benchmark_samples.py --clean
python3 models/audit/tools/generate_matrix_results.py --help
python3 -m unittest discover -s tests -p "test_*.py" -v
```
预期结果: 所有单元测试全部通过（4 大基座编译无误、13 规则完全对齐、Fail-Closed 逻辑生效、100 样本正交生成完好）。

- [x] **Step 3: 最终提交**

```bash
git add models/audit/tools/generate_matrix_results.py
git commit -m "feat(audit): update matrix result generator for three-track orthogonal benchmarks"
```
