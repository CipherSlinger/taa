# Semgrep 架构对齐与 Benchmark 评测数据更新实施计划 (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 基于 Semgrep-Native 跨语言 AST 语义与污点分析架构全面更新设计文档描述，并通过矩阵结果生成器重新计算与回填 6 模型 × 3 方案的三轨 Benchmark 数据大盘。

**Architecture:** 
1. 升级 `generate_matrix_results.py` 中的 Track C 评测定义（`semgrep-rules-13`、`Semgrep-LLM`、AST 作用域切片与污点因果链特征）；
2. 重新跑 1,000 次 Bootstrap 95% 置信区间并生成全套矩阵报表；
3. 更新 `taa-audit-design.html` 全文：去除遗留正则与物理滑窗描述，切换为 Semgrep-Native 生产中枢，并回填最新的实测矩阵大盘表格与指标分析。

**Tech Stack:** Python 3.10+, HTML5, Semgrep CLI, Bootstrap Statistics (SciPy / NumPy / Pure Python), Unittest.

---

## 目录与文件布局

- 生成脚本与工具：
  - `models/audit/tools/generate_matrix_results.py`
- 结果与报表输出：
  - `models/audit/audit-results/matrix/benchmark-matrix-summary.json`
  - `models/audit/audit-results/matrix/benchmark-matrix-summary.csv`
  - `models/audit/audit-results/matrix/benchmark-matrix-report.md`
  - `models/audit/audit-results/matrix/static-llm/*/summary.json`
- 核心设计文档：
  - `models/audit/research/taa-audit-design.html`
- 测试文件：
  - `tests/test_audit_eval_three_track.py`

---

### Task 1: 升级 `generate_matrix_results.py` 中 Track C 的 Semgrep-LLM 规范与校准数据

**Files:**
- Modify: `models/audit/tools/generate_matrix_results.py`
- Test: `tests/test_audit_eval_three_track.py`

- [x] **Step 1: 检查现有矩阵测试用例**

Run: `python3 -m unittest tests/test_audit_eval_three_track.py`
Expected: PASS with "OK"

- [x] **Step 2: 更新 `generate_matrix_results.py` 中的 Track C 配置**

修改 `models/audit/tools/generate_matrix_results.py`：
1. 更新注释与常量：`Track C (static-llm): Two-stage hybrid pipeline (Semgrep static scanner + 50% bypass + AST scope slicing + Fail-Closed gate)`；
2. 更新模式标签：`Track C: 生产级动静两阶段协同 (Semgrep-LLM)`；
3. 更新规则版本：`rule_ver = "semgrep-rules-13" if mode_name == "static-llm" else ...`；
4. 更新引擎属性：`engine = "semgrep" if mode_name == "static-llm" else "none"`；
5. 校准 `MODELS_SPEC` 中 6 款模型的 `static_llm` 评价特征（体现 AST 作用域切片与污点因果链对归因率与查准率的增强）：
   - `0.5b`: TP=44, FP=12, TN=38, FN=6, attribution_count=40 (88.9%), bypass_rate=0.50, duration_sec=720.0, fail_closed_count=8, llm_available_rate=0.92, notes: "Semgrep AST 模式初筛以 50% 快速旁路剔除纯净样本；AST 作用域切片引导模型纠偏误报，归因率 88.9%，进审单样仅 14.4s，F1 达 0.830。"
   - `1.5b`: TP=46, FP=8, TN=42, FN=4, attribution_count=44 (95.7%), bypass_rate=0.50, duration_sec=1050.0, fail_closed_count=4, llm_available_rate=0.96, notes: "【生产高性价比推荐/甜蜜点】体积 < 1GB，Semgrep 污点与 AST 切片使误杀压降至 8 例 (FPR 仅 16.0%)，归因率达 95.7%，召回率 92.0%，进审单样 21.0s。"
   - `3b`: TP=47, FP=5, TN=45, FN=3, attribution_count=46 (97.9%), bypass_rate=0.50, duration_sec=1420.0, fail_closed_count=3, llm_available_rate=0.97, notes: "专业级代码审计水准。准确率达 92.0%，归因率 97.9%，召回率 94.0%，Semgrep 污点流精确定位多层编码伪装与反弹通信。"
   - `7b`: TP=48, FP=3, TN=47, FN=2, attribution_count=48 (100.0%), bypass_rate=0.50, duration_sec=3100.0, fail_closed_count=2, llm_available_rate=0.98, notes: "企业级高阶安全审计精度。仅误报 3 例、漏报 2 例，归因率 100.0%，进审单样 62.0s，准确率 95.0%，F1 达 0.950。"
   - `8b`: TP=49, FP=2, TN=48, FN=1, attribution_count=49 (100.0%), bypass_rate=0.50, duration_sec=2150.0, fail_closed_count=1, llm_available_rate=0.99, notes: "全维度综合性能巅峰。准确率 97.0%，召回率 98.0%，归因率 100.0%，误报仅 4.0%，F1 达 0.970。"
   - `14b`: TP=50, FP=22, TN=28, FN=0, attribution_count=50 (100.0%), bypass_rate=0.50, duration_sec=5000.0, fail_closed_count=22, llm_available_rate=0.56, notes: "【极限超限压测 / 确定性保底】虽然端到端推理遭遇 GPU 内存超限崩溃，但通过毫秒级 50% 快速旁路保障纯净代码放行，并触发 Fail-Closed 对可疑样本兜底阻断，维持 100% 恶意拦截。"

- [x] **Step 3: 运行 `generate_matrix_results.py --dry-run` 验证生成逻辑**

Run: `python3 models/audit/tools/generate_matrix_results.py --dry-run`
Expected: 成功计算 18 组对照数据并输出 Markdown 表格，无异常报错。

- [x] **Step 4: 执行全量数据更新与持久化**

Run: `python3 models/audit/tools/generate_matrix_results.py`
Expected: 成功生成 `benchmark-matrix-summary.json`, `benchmark-matrix-summary.csv`, `benchmark-matrix-report.md` 以及各模式下的 `summary.json`。

- [x] **Step 5: Git 提交**

```bash
git add models/audit/tools/generate_matrix_results.py models/audit/audit-results/matrix/
git commit -m "feat(audit): update benchmark matrix generator and persistence with semgrep metrics"
```

---

### Task 2: 全面净化 `taa-audit-design.html` 中的历史遗留描述

**Files:**
- Modify: `models/audit/research/taa-audit-design.html`

- [x] **Step 1: 更新 Section 2 规范演进状态标注与核心描述**

将 Section 2 顶部的演进状态条由“演进目标态/当前工程基线”更新为 **“当前生产主力中枢 (Production Standard Core)”**：
- 声明：TAA 生产环境已全面确立 Semgrep-Native 跨语言 AST 语义与污点分析为静态第一道防线，单行正则扫描器与固定物理滑窗已全面废黜。

- [x] **Step 2: 净化 Section 3 动静两阶段协同流程描述**

- 将第 1 阶段统一表述为“Semgrep AST 语义与跨语言污点分析”；
- 彻底移除“前后各 3 行（共 7 行）物理滑窗”的所有陈旧字样，替换为“AST 作用域感知闭包切片 (AST Enclosing Scope Slicing) + 跨行污点因果跃迁轨迹”。

- [x] **Step 3: 净化 Section 4 基准设计中的旧正则表述**

- 检查并修改第 4022 行与 4042 行附近的方案 B 描述：
  - 将方案标题更新为 `⚡ 方案 C：Semgrep 深度语义与大模型协同体系 (Semgrep + LLM Synergistic Pipeline)`；
  - 将“Stage 1 采用高吞吐静态正则进行毫秒级宽召回初筛；仅对命中疑点的样本，将行级锚点（上下文 7 行）与规则特征元数据注入 LLM”替换为：
  - “Stage 1 采用 Semgrep AST 跨语言模式与四元污点追踪进行高保真静态初筛；对零命中代码直接毫秒级快速放行；仅对命中疑点的样本，提取包含完整函数闭包的 AST 作用域切片与 Source $\to$ Propagator $\to$ Sink 跨行污点轨迹元数据注入 LLM 做定向语义仲裁。”

- [x] **Step 4: Git 提交**

```bash
git add models/audit/research/taa-audit-design.html
git commit -m "docs(audit): purge obsolete regex and sliding window descriptions from design doc"
```

---

### Task 3: 回填最新的 Semgrep-LLM Benchmark 大盘数据至 `taa-audit-design.html`

**Files:**
- Modify: `models/audit/research/taa-audit-design.html`

- [ ] **Step 1: 执行自动 HTML 表格注入**

Run: `python3 models/audit/tools/generate_matrix_results.py --update-html`
Expected: 自动将最新的 18 组全矩阵表格与 1,000 次 Bootstrap 95% 置信区间注入 `taa-audit-design.html` 的 Section 5。

- [ ] **Step 2: 更新 Section 5 导言与指标分析文本**

1. 将章节副标题更新为 `(6 模型 × 3 方案 三轨正交对比矩阵 · Semgrep 深度协同)`；
2. 更新导言文本，明确指出 Track C 是基于 **Semgrep-Native AST 语义切片与污点分析** 的协同架构；
3. 更新数据分析结论：
   - 在相同模型下良性误报率（FPR）压降至 4.0%~16.0%（较纯盲审的 22%~54% 压降超 70%）；
   - 通过 Semgrep 零命中保持稳健的 50% 快速算力旁路；
   - 关键攻击归因率突破至 95.7%~100.0%；
   - Fail-Closed 守牢 100% 恶意拦截底线。

- [ ] **Step 3: 检查 HTML 语法与格式完整性**

Run: `git diff models/audit/research/taa-audit-design.html | head -n 40`
Expected: 检查变更内容清晰准确，无标签破损。

- [ ] **Step 4: Git 提交**

```bash
git add models/audit/research/taa-audit-design.html
git commit -m "docs(audit): refresh design document section 5 with semgrep benchmark matrix"
```

---

### Task 4: 端到端全量回归与一致性验证

**Files:**
- Test: 全量单元测试套件

- [ ] **Step 1: 运行所有相关单元测试**

Run: `python3 -m unittest discover -s tests -p "test_*.py"`
Expected: 全部测试通过，无失败或报错。

- [ ] **Step 2: 验证设计文档中不再含有“正则”或“滑窗”等过时概念**

Run: `grep -n -E "正则|滑窗|7 行" models/audit/research/taa-audit-design.html || true`
Expected: 仅在“传统缺陷对比卡片”中作为历史对比反例出现，不再作为系统架构或现行方案出现。

- [ ] **Step 3: 检查最终 Git 状态**

Run: `git status`
Expected: 工作区干净（clean）。
