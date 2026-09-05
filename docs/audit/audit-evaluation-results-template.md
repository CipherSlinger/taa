# 代码审计评估结果模板

> 状态: 草案
> 用途: 记录每一轮 benchmark 的完整结果、错误类型、优化动作和原因。
> 关联文档: `audit-evaluation-design.md`、`audit-benchmark-manifest.md`、`audit-eval-iteration-log.md`

---

## 1. 结果文档目标

这份结果文档要回答四个问题：

1. **审计器有没有把恶意样本抓出来？**
2. **审计器有没有把良性样本误判成恶意？**
3. **错误主要来自规则、prompt 还是模型能力？**
4. **本轮优化之后，指标有没有真实改善？**

---

## 2. 顶层元数据

| 字段 | 说明 |
|------|------|
| `run_id` | 本轮评测唯一 ID |
| `run_time` | 评测时间 |
| `benchmark_version` | 使用的 benchmark 版本 |
| `auditor_version` | 审计器版本 / 模型版本 |
| `rule_set_version` | 规则版本 |
| `prompt_version` | Prompt 版本 |
| `policy` | `assist` / `gate` |
| `notes` | 额外说明 |

---

## 3. 样本级结果表

每个样本至少记录下面字段：

| 字段 | 说明 |
|------|------|
| `sample_id` | 样本编号 |
| `base_project` | 来源项目 |
| `label` | ground truth：`benign` / `malicious` |
| `predicted_label` | 审计器最终判断 |
| `predicted_risk` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `predicted_verdict` | `BENIGN` / `SUSPICIOUS` / `MALICIOUS` / `UNCERTAIN` |
| `blocked` | 是否阻断 |
| `matched_rules` | 命中的规则 ID 列表 |
| `reason` | 审计器解释 |
| `llm_state` | `static_only` / `llm_unavailable` / `parse_error` / `uncertain` / `ok` |
| `error_type` | 若错误，归类原因；需与 `llm_state` 区分 |
| `review_note` | 人工复核备注 |

---

## 4. 指标汇总

### 4.1 样本级指标

| 指标 | 说明 |
|------|------|
| `precision` | 预测为恶意的样本中，真正恶意的比例 |
| `recall` | 真正恶意样本中，被正确识别的比例 |
| `fpr` | 良性样本被误判为恶意的比例 |
| `fnr` | 恶意样本漏判比例 |
| `f1` | 综合指标 |
| `f0_5` | 偏重 precision 的综合指标 |
| `accuracy` | 仅作为参考，不作为主指标 |
| `llm_available_rate` | 成功返回可解析 verdict 的样本比例 |
| `fail_closed_count` | 因 LLM 失败而被保守阻断的样本数 |

### 4.2 分层指标

按以下维度分别统计：

- 基线项目
- 样本 family
- 良性 / 恶意
- 单文件 / 多文件
- 简单 / 中等 / 困难
- 规则引擎 / 本地 LLM / 参考 LLM

---

## 5. 错误类型分类

### 5.1 误报类

- `rule_fp`：规则本身误报
- `prompt_fp`：prompt 引导模型过度保守
- `context_fp`：上下文裁剪导致误判
- `aggregation_fp`：聚合逻辑把 benign 升级成恶意

### 5.2 漏报类

- `rule_fn`：规则没覆盖到
- `prompt_fn`：prompt 没让模型识别出来
- `context_fn`：上下文不够
- `aggregation_fn`：规则触发了，但最终没升级

### 5.3 系统类

- `static_only`：未启用 LLM，仅做静态扫描
- `parse_error`：JSON / 格式解析失败
- `timeout`：超时
- `stability_issue`：多次运行结果不一致
- `tool_failure`：后端调用失败
- `fail_closed`：因 LLM 无法提供可靠判断而保守阻断
---

## 6. 轮次记录格式

每轮评测结束后，增加一个摘要段：

### 6.x 本轮结论

- 本轮最主要的误报来源：
- 本轮最主要的漏报来源：
- 本轮最有效的优化：
- 本轮最需要回退的设计：
- 下一轮要优先改的内容：

---

## 7. 建议的报告目录结构

```text
audit/audit-results/
├── runs/
│   ├── run-001/
│   │   ├── summary.json
│   │   ├── sample-results.csv
│   │   ├── sample-results.jsonl
│   │   └── confusion-matrix.json
│   └── run-002/
├── charts/
├── notes/
└── final-report.md
```

---

## 8. 最终报告应包含的内容

- benchmark 设计
- 审计器候选池
- 样本构造方法
- 评测设置
- 指标汇总
- 误报 / 漏报分析
- 迭代优化记录
- 最终推荐方案
- 未解决问题

---

## 9. 当前结论

结果模板已经足够支撑后续跑分和复盘。下一步要补的是：
- 机器可读的样本 manifest
- 自动评测脚本
- 第一轮结果落地