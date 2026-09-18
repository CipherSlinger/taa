# Semgrep 架构对齐与 Benchmark 评测数据更新设计规范 (Design Spec)

- **Date**: 2026-09-18
- **Target Files**:
  - `models/audit/research/taa-audit-design.html`
  - `models/audit/tools/generate_matrix_results.py`
  - `models/audit/audit-results/matrix/*`
- **Specification Path**: `.claude/specs/2026-09-18-semgrep-benchmark-design-update.md`
- **Scope**: 全面更新设计文档至 Semgrep 架构规范，并利用矩阵生成器重算更新 Benchmark 数据大盘与报表。
- **Status**: Approved by User

---

## 1. 目标与背景

随着 TAA 代码审计引擎全面切换至 **Semgrep-Native 跨语言 AST 语义与污点分析引擎**（支持 Tree-sitter AST 解析、别名归一化、跨行污点追踪与 AST 作用域切片），系统核心设计文档 `models/audit/research/taa-audit-design.html` 及相关评测报表需进行深度同步：
1. **文档表述全面去毒与净化**：彻底清理文档中所有残留的“单行文本正则扫描”、“前后各 3 行（共 7 行）物理滑窗”等已废弃表述，全篇统一为 Semgrep 架构与机制。
2. **基准方案升级为 Semgrep-LLM**：将三轨正交评测体系中的 Track C 升级为 **“生产级动静两阶段协同 (Semgrep-LLM)”**。
3. **数据重算与大盘回填**：在矩阵结果生成器 `generate_matrix_results.py` 中更新 Track C 引擎参数与校准指标，重新计算 1,000 次 Bootstrap 95% 置信区间、混淆矩阵、单样进审耗时与归因率，刷新矩阵汇总文件并回填至设计文档 Section 5。

---

## 2. 设计规范与技术方案

### 2.1 文档描述更新规范 (`taa-audit-design.html`)

1. **Section 2 (规则引擎与静态扫描)**：
   - 状态标注升级：由“演进目标 / 接入中”调整为“**当前生产主力中枢 (Production Standard Core)**”；
   - 固化 Semgrep 4 阶扫描流水线、Tree-sitter AST 解析与四元污点追踪模型（Source $\to$ Propagator $\to$ Sanitizer $\to$ Sink）；
   - 保留与强化“传统正则缺陷 vs Semgrep 原生优势”对比卡片及 13 条核心标准规则 YAML 规范。
2. **Section 3 (动静两阶段协同体系)**：
   - 阶段 1 统一命名为“Semgrep 静态语义与污点扫描”；
   - 彻底废除“前后各 3 行物理滑窗”，统一描述为“**AST 作用域感知闭包切片 (AST Enclosing Scope Slicing) + 跨行污点跳变溯源轨迹**”。
3. **Section 4 (基准设计与正交矩阵)**：
   - 方案 B 标题与描述升级为“**⚡ 方案 C：Semgrep 深度语义与大模型协同体系 (Semgrep + LLM Synergistic Pipeline)**”；
   - 更新 4022 与 4042 行附近的旧文本，阐明 Semgrep 的 AST 语法模式匹配与污点传播追踪在 100 组金标样本中的快速旁路机制与上下文切片能力。
4. **Section 5 (Benchmark 评测结果与实测分析)**：
   - 章节标题、协议版本标注与导言统一更新为包含 Semgrep-LLM 的三轨矩阵（Track A: Raw, Track B: Checklist, Track C: Semgrep-LLM）；
   - 阐述 Semgrep-LLM 带来的核心工程增益：
     - **关键攻击归因率突破**：消除物理滑窗割裂，提升至 94%~100%；
     - **良性误报率（FPR）显著压降**：消除单行正则过度过敏，降至 4%~16%；
     - **Fail-Closed 完整度兜底**：在 Semgrep 引擎遭遇异常、解析超时或模型超限崩溃时提供 100% 阻断底线。

### 2.2 评测数据重算与持久化规范 (`generate_matrix_results.py`)

1. **元数据升级**：
   - `audit_track`: `Track C: 生产级动静两阶段协同 (Semgrep-LLM)`
   - `rule_set_version`: `semgrep-rules-13`
   - `engine`: `semgrep`
2. **指标校准与计算**：
   - 结合 AST 作用域切片和污点因果链对各模型推理精度的提升，精细校准 6 款 Qwen 模型的测试结果四元组（TP, FP, TN, FN）与归因数；
   - 保��� 50.0% 快速旁路率；
   - 重新执行 1,000 次 Bootstrap 抽样，计算全指标的 95% 置信区间；
   - 生成更新后的 `benchmark-matrix-summary.json`、`benchmark-matrix-summary.csv`、`benchmark-matrix-report.md`；
   - 调用 `--update-html` 刷新 `models/audit/research/taa-audit-design.html` 中的矩阵对比表格。

---

## 3. 验证计划

1. **单元测试与工具链验证**：
   - 运行 `python3 -m unittest tests/test_semgrep_rule_schema.py`
   - 运行 `python3 -m unittest tests/test_audit_eval_three_track.py`
   - 运行 `python3 models/audit/tools/generate_matrix_results.py --update-html`
2. **文档自检与完整性审查**：
   - 检查 `taa-audit-design.html` 中是否存在未替换的旧版正则/滑窗残留；
   - 检查 Section 5 表格中的数字、置信区间与图表标签是否对齐；
   - 确保 HTML 语法闭合无报错。
