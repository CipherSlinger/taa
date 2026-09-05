// Package security provides source code security scanning for Python training
// code imported into the TAA trusted execution environment.
package codeaudit

import "regexp"

// Severity levels for security findings.
const (
	SeverityHigh   = "HIGH"
	SeverityMedium = "MEDIUM"
)

// Finding represents a single security issue detected in source code.
type Finding struct {
	File          string `json:"file"`
	Line          int    `json:"line"`
	RuleID        string `json:"rule_id"`
	Category      string `json:"category"`
	Severity      string `json:"severity"`
	Description   string `json:"description"`
	CodeSnippet   string `json:"code_snippet"`
	ContextBefore string `json:"context_before,omitempty"`
	ContextAfter  string `json:"context_after,omitempty"`
	LLMVerdict    string `json:"llm_verdict,omitempty"`
	LLMReason     string `json:"llm_reason,omitempty"`
	LLMRisk       string `json:"llm_risk,omitempty"`
}

// Report is the result of a security scan.
type Report struct {
	ScanTime    string    `json:"scan_time"`
	ScannedDir  string    `json:"scanned_dir"`
	FilesCount  int       `json:"files_count"`
	HighCount   int       `json:"high_count"`
	MediumCount int       `json:"medium_count"`
	Passed      bool      `json:"passed"`
	Findings    []Finding `json:"findings"`
}

// Rule defines a single security check pattern.
type Rule struct {
	ID          string
	Category    string
	Severity    string
	Description string
	Patterns    []*regexp.Regexp
}

// DefaultRules returns the built-in set of security rules for Python code.
func DefaultRules() []Rule {
	return []Rule{
		{
			ID:          "NET_001",
			Category:    "网络请求",
			Severity:    SeverityHigh,
			Description: "HTTP/HTTPS 网络请求 — 可能向外发送数据",
			Patterns: compilePatterns(
				`requests\.(get|post|put|delete|patch|head)\s*\(`,
				`urllib\.request\.(urlopen|urlretrieve)`,
				`http\.client\.HTTPS?Connection`,
				`httpx\.(get|post|put|delete)\s*\(`,
				`aiohttp\.ClientSession`,
				`httplib2\.Http`,
			),
		},
		{
			ID:          "NET_002",
			Category:    "底层网络",
			Severity:    SeverityHigh,
			Description: "原始 Socket 连接 — 可绕过 HTTP 监控外传数据",
			Patterns: compilePatterns(
				`socket\.socket\s*\(`,
				`socket\.create_connection`,
			),
		},
		{
			ID:          "CMD_001",
			Category:    "命令执行",
			Severity:    SeverityHigh,
			Description: "shell 命令执行或危险外部命令 — 可能绕过参数化保护",
			Patterns: compilePatterns(
				`os\.system\s*\(`,
				`os\.popen\s*\(`,
				`os\.exec[a-z]*\s*\(`,
				`commands\.getoutput`,
				`subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True`,
				`subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*\[\s*['\"](?:bash|sh|zsh|fish|curl|wget|rm|cmd\.exe|powershell|pwsh)['\"]`,
				`subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*['\"](?:bash|sh|zsh|fish|curl|wget|rm|cmd\.exe|powershell|pwsh)['\"]`,
			),
		},
		{
			ID:          "OBF_001",
			Category:    "代码混淆",
			Severity:    SeverityHigh,
			Description: "编码/反序列化 — 可能隐藏恶意载荷",
			Patterns: compilePatterns(
				`base64\.(b64decode|b64encode)\s*\(`,
				`pickle\.loads?\s*\(`,
				`marshal\.loads?\s*\(`,
				`zlib\.decompress\s*\(`,
				`codecs\.decode\s*\(`,
				`binascii\.(a2b|b2a)`,
			),
		},
		{
			ID:          "DYN_001",
			Category:    "动态执行",
			Severity:    SeverityMedium,
			Description: "动态代码执行 — 可运行时加载恶意代码",
			Patterns: compilePatterns(
				`(?:^|[^.\w])eval\s*\(`,
				`(?:^|[^.\w])exec\s*\(`,
				`compile\s*\(.*['\"]exec['\"]`,
				`__import__\s*\(`,
				`importlib\.import_module\s*\(`,
			),
		},
		{
			ID:          "FIL_001",
			Category:    "敏感文件读取",
			Severity:    SeverityMedium,
			Description: "读取敏感文件 — 可能窃取密钥/凭证",
			Patterns: compilePatterns(
				`open\s*\(\s*['"].*(?:\.ssh|\.env|password|credential|\.aws|\.kube|id_rsa|authorized_keys)`,
				`Path\s*\(\s*['"].*(?:\.ssh|\.env|password|credential|\.aws|\.kube)[^)]*\)\.(?:read_text|read_bytes|open)\s*\(`,
				`Path\.home\(\)\.joinpath\([^)]*(?:\.ssh|\.env|password|credential|\.aws|\.kube|id_rsa|authorized_keys)[^)]*\)\.(?:read_text|read_bytes|open)\s*\(`,
			),
		},
		{
			ID:          "ENV_001",
			Category:    "环境变量",
			Severity:    SeverityMedium,
			Description: "读取敏感环境变量 — 可能获取密钥/Token",
			Patterns: compilePatterns(
				`os\.environ\s*[.\[]\s*['\"](?:[^'\"]*(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|passwd|pwd|cred|credential|auth|session|cookie|kube|aws|gcp|azure|github|gitlab)[^'\"]*)['\"]`,
				`os\.environ\.get\s*\(\s*['\"](?:[^'\"]*(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|passwd|pwd|cred|credential|auth|session|cookie|kube|aws|gcp|azure|github|gitlab)[^'\"]*)['\"]`,
				`os\.getenv\s*\(\s*['\"](?:[^'\"]*(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|passwd|pwd|cred|credential|auth|session|cookie|kube|aws|gcp|azure|github|gitlab)[^'\"]*)['\"]`,
			),
		},
		{
			ID:          "PER_001",
			Category:    "持久化后门",
			Severity:    SeverityHigh,
			Description: "持久化机制 — 可能在系统中植入后门",
			Patterns: compilePatterns(
				`crontab`,
				`\.bashrc|\.bash_profile|\.zshrc`,
				`systemctl\s+(enable|start)`,
				`/etc/init\.d`,
				`/etc/systemd`,
			),
		},
		{
			ID:          "EXF_001",
			Category:    "数据外传",
			Severity:    SeverityHigh,
			Description: "数据编码后发送 — 典型的数据窃取模式",
			Patterns: compilePatterns(
				`base64.*request|request.*base64`,
				`json\.dumps.*post|post.*json\.dumps`,
				`encode.*send|send.*encode`,
			),
		},

		// ── 计算结果嵌入明文数据检测 ──────────────────────

		{
			ID:          "EMB_001",
			Category:    "结果嵌入数据",
			Severity:    SeverityHigh,
			Description: "将原始数据直接写入输出文件 — 可能通过结果文件泄露原始数据",
			Patterns: compilePatterns(
				`torch\.save\s*\(\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train)\b`,
				`np\.save\s*\(\s*['\"][^'\"]*['\"]\s*,\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train)\b`,
				`np\.savez\s*\(\s*['\"][^'\"]*['\"]\s*,[^)]*(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train)\s*=`,
				`shutil\.copy\s*\([^)]*(?:data|dataset|train|test|image)\b`,
				`shutil\.copytree\s*\([^)]*(?:data|dataset|train|test|image)\b`,
			),
		},
		{
			ID:          "EMB_002",
			Category:    "结果嵌入数据",
			Severity:    SeverityHigh,
			Description: "将原始数据复制到模型输出目录 — 可能在导出时夹带明文数据",
			Patterns: compilePatterns(
				`shutil\.(copy|copytree|move)\s*\(.*output`,
				`shutil\.(copy|copytree|move)\s*\(.*export`,
				`shutil\.(copy|copytree|move)\s*\(.*result`,
				`os\.rename\s*\(.*data.*output`,
				`os\.rename\s*\(.*data.*result`,
			),
		},
		{
			ID:          "EMB_003",
			Category:    "结果嵌入数据",
			Severity:    SeverityMedium,
			Description: "将原始数据直接打印到日志/标准输出 — 可能在日志文件中泄露",
			Patterns: compilePatterns(
				`print\s*\(\s*(?:raw_|train_|test_)?(?:data|images|samples|batch|x_train|y_train)\b`,
				`logging\.(?:info|debug|warning)\s*\(\s*(?:raw_|train_|test_)?(?:data|images|samples|batch|x_train|y_train)\b`,
				`sys\.stdout\.write\s*\(\s*(?:raw_|train_|test_)?(?:data|images|samples|batch|x_train|y_train)\b`,
			),
		},
		{
			ID:          "EMB_004",
			Category:    "结果嵌入数据",
			Severity:    SeverityHigh,
			Description: "将数据编码后嵌入模型权重或输出 — 隐写术数据泄露",
			Patterns: compilePatterns(
				`(?:state_dict|weights|params).*(?:hidden|secret|payload|stego|embed|hide)(?:_?data)?`,
				`base64.*save|save.*base64`,
				`encode.*state_dict|state_dict.*encode`,
				`zlib.*save|save.*zlib`,
				`pickle\.dump\s*\(.*(data|dataset|images|samples)`,
			),
		},
	}
}
func compilePatterns(patterns ...string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		compiled = append(compiled, regexp.MustCompile(p))
	}
	return compiled
}
