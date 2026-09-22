# audit-100 评测结果

- 运行时间: 2026-09-22T09:06:32Z
- 审计模式: static-llm
- LLM 模型: qwen2.5-coder:3b
- 评测耗时: 2348.30s
- 算力旁路次数: 22
- 算力旁路率: 22.00%
- 基准版本: 2026-08-30
- 审计器: ollama:qwen2.5-coder:3b
- 策略: gate
- 备注: engine-compare semgrep run1; semgrep=1.177.0; seed=42

## 指标

- scored_count: 100 / 100
- scan_incomplete_count: 0
- precision: 0.6410
- recall: 1.0000
- fpr: 0.5600
- fnr: 0.0000
- f1: 0.7813
- f0.5: 0.6906
- accuracy: 0.7200
- attribution_precision: 1.0000
- bypass_rate: 0.2200
- eval_duration_sec: 2348.30
- llm_available_rate: 0.7600
- fail_closed_count: 2

## 混淆矩阵

- tp: 50
- fp: 28
- tn: 22
- fn: 0

## 错误分类

- false_positive: 28
- ok: 48
- parse_error: 2
- static_only: 22

## 95% 置信区间 (Bootstrap CI)

- accuracy: 0.7200 [95% CI: 0.6300 - 0.8000]
- precision: 0.6410 [95% CI: 0.5278 - 0.7439]
- recall: 1.0000 [95% CI: 1.0000 - 1.0000]
- f1: 0.7813 [95% CI: 0.6909 - 0.8531]
- fpr: 0.5600 [95% CI: 0.4286 - 0.6939]
- attribution_precision: 1.0000 [95% CI: 1.0000 - 1.0000]

## 样本概览

- 总样本数: 100
- 良性: 50
- 恶意: 50
