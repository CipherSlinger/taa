package codeaudit

import (
	"strings"
	"testing"
)

func TestBuildFindingPromptCarriesEveryField(t *testing.T) {
	f := Finding{
		RuleID:        "EMB_003",
		Category:      "exfiltration",
		Severity:      SeverityHigh,
		Description:   "documented rule text",
		File:          "train.py",
		Line:          42,
		CodeSnippet:   "print(dataset)",
		ContextBefore: "before line",
		ContextAfter:  "after line",
	}
	got := BuildFindingPrompt(f, f.ContextAfter)

	for _, want := range []string{
		"train.py", "第 42 行", "before line", "print(dataset)", "after line",
		"EMB_003", "exfiltration", SeverityHigh, "documented rule text",
		"良性判定规则优先", "请严格按以下 JSON 格式回答",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt is missing %q", want)
		}
	}
}

// TestFindingAnalysisPromptTemplateIsPinned pins the migrated prompt byte for
// byte. Substring assertions cannot catch a one-character edit, and the wording
// and the rubric's leading/trailing positions are load-bearing for the verdicts
// this deployment has been measured on, so the whole rendered prompt is compared
// against a golden literal written out by hand.
func TestFindingAnalysisPromptTemplateIsPinned(t *testing.T) {
	f := Finding{
		RuleID:        "EMB_003",
		Category:      "exfiltration",
		Severity:      SeverityHigh,
		Description:   "writes dataset rows to stdout",
		File:          "train.py",
		Line:          42,
		CodeSnippet:   "print(dataset)",
		ContextBefore: "for dataset in loader:",
	}
	got := BuildFindingPrompt(f, "    val = dataset")

	const golden = "你是一个代码安全审计专家。请分析以下代码片段是否存在窃取数据、外传数据或其他恶意行为。\n\n## 判定优先级与安全边界\n1. 恶意/可疑判定 (MALICIOUS 或 SUSPICIOUS)：\n   - 必须有上下文明确表明代码在窃取或外发凭据（密钥、令牌、密码、证书、私钥、敏感配置文件）；\n   - 或明确在通过未授权网络、隐写载荷、非法持久化通道外传真实的敏感原始数据/特征矩阵；\n   - 只有确凿恶意利用证据时才可判定为 MALICIOUS 或 SUSPICIOUS。\n\n2. 良性判定 (BENIGN)（严格消除训练与日志误报）：\n   - 日志与标准输出（如 EMB_003）：打印数据集名称/路径标识/类别标签/状态分隔线（例如 print(dataset + '--------')、print(dataset)）、打印训练批次统计、模型参数结构、计算进度、评估指标（如 accuracy、loss、AUC、sensitivity、specificity、F1-score、ci 置信区间等），均属完全正常的训练与科研评估日志，绝非敏感数据泄露，必须判为 BENIGN；\n   - 依赖检测与测试打桩（如 DYN_001）：在测试脚本（如 test_*.py）或顶层保护块中使用 __import__ 或 importlib.import_module 探测可选模块、或为缺失依赖（如 torch/numpy/tensorboardX）挂载 MagicMock 模拟对象，属于纯良性的测试用例兼容逻辑，绝非动态恶意执行，必须判为 BENIGN；\n   - 结果保存与导出（如 EMB_001/EMB_002/EMB_004）：正常保存训练生成的模型权重（如 torch.save(model.state_dict(), ...)）、导出评估图表（如 matplotlib/plt 保存 ROC 曲线或分布图）、写入评估结果指标文件，必须判为 BENIGN；\n   - 常规配置读取、环境参数封装、合法子进程参数调用等框架良性用法，必须判为 BENIGN。\n\n3. 不确定判定 (UNCERTAIN)：\n   - 仅在上下文严重缺失、证据不足且语义完全无法确认意图时返回。\n\n## 代码片段\n文件: train.py (第 42 行)\n```python\nfor dataset in loader:\n>>> print(dataset)   ← 触发规则的代码\n    val = dataset\n```\n\n## 触发的规则\n规则ID: EMB_003\n类别: exfiltration\n严重度: HIGH\n规则说明: writes dataset rows to stdout\n\n## 判定提醒\n上述良性判定规则优先：EMB_001/EMB_002/EMB_003/EMB_004 与 DYN_001 均属良性用法，除非有确凿的窃取或外发敏感数据证据，否则必须判为 BENIGN。\n\n## 请回答\n1. verdict: MALICIOUS(恶意) / SUSPICIOUS(可疑) / BENIGN(正常) / UNCERTAIN(不确定)\n2. reason: 一句话说明理由（中文）\n3. risk: 如果恶意，数据会怎样被利用\n\n请严格按以下 JSON 格式回答，不要包含其他内容:\n{\"verdict\": \"...\", \"reason\": \"...\", \"risk\": \"...\"}\n"
	if got != golden {
		t.Fatalf("prompt drifted from the pinned template.\ngot: %q", got)
	}
}

func TestBuildFindingPromptUsesProvidedContextAfter(t *testing.T) {
	f := Finding{File: "a.py", Line: 1, CodeSnippet: "x", ContextBefore: "b", ContextAfter: "original"}
	got := BuildFindingPrompt(f, "cp3 evidence")
	if !strings.Contains(got, "cp3 evidence") || strings.Contains(got, "original") {
		t.Fatalf("prompt must use the provided contextAfter:\n%s", got)
	}
}
