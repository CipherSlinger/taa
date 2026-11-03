package codeaudit

import "fmt"

// findingAnalysisPromptTemplate is the audit rubric handed to the model for one
// finding. It was moved here verbatim from the inference service: the wording,
// the rubric's leading position and its trailing reminder are load-bearing for
// the verdicts this deployment has been measured on, so they must not be
// reworded during the move.
const findingAnalysisPromptTemplate = `你是一个代码安全审计专家。请分析以下代码片段是否存在窃取数据、外传数据或其他恶意行为。

## 判定优先级与安全边界
1. 恶意/可疑判定 (MALICIOUS 或 SUSPICIOUS)：
   - 必须有上下文明确表明代码在窃取或外发凭据（密钥、令牌、密码、证书、私钥、敏感配置文件）；
   - 或明确在通过未授权网络、隐写载荷、非法持久化通道外传真实的敏感原始数据/特征矩阵；
   - 只有确凿恶意利用证据时才可判定为 MALICIOUS 或 SUSPICIOUS。

2. 良性判定 (BENIGN)（严格消除训练与日志误报）：
   - 日志与标准输出（如 EMB_003）：打印数据集名称/路径标识/类别标签/状态分隔线（例如 print(dataset + '--------')、print(dataset)）、打印训练批次统计、模型参数结构、计算进度、评估指标（如 accuracy、loss、AUC、sensitivity、specificity、F1-score、ci 置信区间等），均属完全正常的训练与科研评估日志，绝非敏感数据泄露，必须判为 BENIGN；
   - 依赖检测与测试打桩（如 DYN_001）：在测试脚本（如 test_*.py）或顶层保护块中使用 __import__ 或 importlib.import_module 探测可选模块、或为缺失依赖（如 torch/numpy/tensorboardX）挂载 MagicMock 模拟对象，属于纯良性的测试用例兼容逻辑，绝非动态恶意执行，必须判为 BENIGN；
   - 结果保存与导出（如 EMB_001/EMB_002/EMB_004）：正常保存训练生成的模型权重（如 torch.save(model.state_dict(), ...)）、导出评估图表（如 matplotlib/plt 保存 ROC 曲线或分布图）、写入评估结果指标文件，必须判为 BENIGN；
   - 常规配置读取、环境参数封装、合法子进程参数调用等框架良性用法，必须判为 BENIGN。

3. 不确定判定 (UNCERTAIN)：
   - 仅在上下文严重缺失、证据不足且语义完全无法确认意图时返回。

## 代码片段
文件: %s (第 %d 行)
` + "```python" + `
%s
>>> %s   ← 触发规则的代码
%s
` + "```" + `

## 触发的规则
规则ID: %s
类别: %s
严重度: %s
规则说明: %s

## 判定提醒
上述良性判定规则优先：EMB_001/EMB_002/EMB_003/EMB_004 与 DYN_001 均属良性用法，除非有确凿的窃取或外发敏感数据证据，否则必须判为 BENIGN。

## 请回答
1. verdict: MALICIOUS(恶意) / SUSPICIOUS(可疑) / BENIGN(正常) / UNCERTAIN(不确定)
2. reason: 一句话说明理由（中文）
3. risk: 如果恶意，数据会怎样被利用

请严格按以下 JSON 格式回答，不要包含其他内容:
{"verdict": "...", "reason": "...", "risk": "..."}
`

// BuildFindingPrompt renders the audit prompt for one finding. contextAfter is
// passed explicitly because the caller may replace the source context with CPG
// evidence.
func BuildFindingPrompt(f Finding, contextAfter string) string {
	return fmt.Sprintf(findingAnalysisPromptTemplate,
		f.File, f.Line,
		f.ContextBefore, f.CodeSnippet, contextAfter,
		f.RuleID, f.Category, f.Severity, f.Description,
	)
}
