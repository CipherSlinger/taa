#!/usr/bin/env python3
"""
Source Code Security Analyzer -- Detect data exfiltration behaviors using small models.
Architecture: Static rules extract suspicious snippets -> Small model semantic evaluation -> Structured audit report.

Applicable Scenarios:
  - Integration into TEE pipeline for automated code auditing before model loading/training
  - CI/CD security quality gate
  - Air-gapped / offline environments (no internet access required)

Recommended Models: Qwen2.5-Coder-0.5B-Instruct (Q4_K_M quantization, smaller footprint)
                    or DeepSeek-Coder-1.3B-Instruct

Dependencies:
  - ollama (local inference) or llama-cpp-python
  - No GPU required, runs on CPU

Usage:
  python3 code_security_analyzer.py <source_dir> [--model qwen2.5-coder:0.5b]
"""

import os
import re
import sys
import json
import time
import argparse
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Union

# ============================================================
# 1. Suspicious pattern rule library (static extraction)
# ============================================================

SUSPICIOUS_PATTERNS = [
    {
        "id": "NET_001",
        "category": "网络请求",
        "severity": "HIGH",
        "description": "HTTP/HTTPS 网络请求 — 可能向外发送数据",
        "patterns": [
            r"requests\.(get|post|put|delete|patch|head)\s*\(",
            r"urllib\.request\.(urlopen|urlretrieve)",
            r"http\.client\.HTTPS?Connection",
            r"httpx\.(get|post|put|delete)\s*\(",
            r"aiohttp\.ClientSession",
            r"httplib2\.Http",
        ],
    },
    {
        "id": "NET_002",
        "category": "底层网络",
        "severity": "HIGH",
        "description": "原始 Socket 连接 — 可绕过 HTTP 监控外传数据",
        "patterns": [
            r"socket\.socket\s*\(",
            r"socket\.create_connection",
        ],
    },
    {
        "id": "CMD_001",
        "category": "命令执行",
        "severity": "HIGH",
        "description": "shell 命令执行或危险外部命令 — 可能绕过参数化保护",
        "patterns": [
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"os\.exec[a-z]*\s*\(",
            r"commands\.getoutput",
            r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
            r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*\[\s*['\"](?:bash|sh|zsh|fish|echo|curl|wget|rm|cmd\.exe|powershell|pwsh)['\"]",
            r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*['\"](?:bash|sh|zsh|fish|echo|curl|wget|rm|cmd\.exe|powershell|pwsh)['\"]",
        ],
    },
    {
        "id": "OBF_001",
        "category": "代码混淆",
        "severity": "HIGH",
        "description": "编码/反序列化 — 可能隐藏恶意载荷",
        "patterns": [
            r"base64\.(b64decode|b64encode)\s*\(",
            r"pickle\.loads?\s*\(",
            r"marshal\.loads?\s*\(",
            r"zlib\.decompress\s*\(",
            r"codecs\.decode\s*\(",
            r"binascii\.(a2b|b2a)",
        ],
    },
    {
        "id": "DYN_001",
        "category": "动态执行",
        "severity": "MEDIUM",
        "description": "动态代码执行 — 可运行时加载恶意代码",
        "patterns": [
            r"(?:^|[^.\w])eval\s*\(",
            r"(?:^|[^.\w])exec\s*\(",
            r"compile\s*\(.*['\"]exec['\"]",
            r"__import__\s*\(",
            r"importlib\.import_module\s*\(",
        ],
    },
    {
        "id": "FIL_001",
        "category": "敏感文件读取",
        "severity": "MEDIUM",
        "description": "读取敏感文件 — 可能窃取密钥/凭证",
        "patterns": [
            r"open\s*\(\s*['\"].*(?:\.ssh|\.env|password|credential|\.aws|\.kube|id_rsa|authorized_keys)",
            r"Path\s*\(\s*['\"].*(?:\.ssh|\.env|password|credential|\.aws|\.kube)[^)]*\)\.(?:read_text|read_bytes|open)\s*\(",
            r"Path\.home\(\)\.joinpath\([^)]*(?:\.ssh|\.env|password|credential|\.aws|\.kube|id_rsa|authorized_keys)[^)]*\)\.(?:read_text|read_bytes|open)\s*\(",
        ],
    },
    {
        "id": "ENV_001",
        "category": "环境变量",
        "severity": "MEDIUM",
        "description": "读取敏感环境变量 — 可能获取密钥/Token",
        "patterns": [
            r"(?i)os\.environ\s*[.\[]\s*['\"](?:[^'\"]*(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|passwd|pwd|cred|credential|auth|session|cookie|kube|aws|gcp|azure|github|gitlab)[^'\"]*)['\"]",
            r"(?i)os\.environ\.get\s*\(\s*['\"](?:[^'\"]*(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|passwd|pwd|cred|credential|auth|session|cookie|kube|aws|gcp|azure|github|gitlab)[^'\"]*)['\"]",
            r"(?i)os\.getenv\s*\(\s*['\"](?:[^'\"]*(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|passwd|pwd|cred|credential|auth|session|cookie|kube|aws|gcp|azure|github|gitlab)[^'\"]*)['\"]",
        ],
    },
    {
        "id": "PER_001",
        "category": "持久化后门",
        "severity": "HIGH",
        "description": "持久化机制 — 可能在系统中植入后门",
        "patterns": [
            r"crontab",
            r"\.bashrc|\.bash_profile|\.zshrc",
            r"systemctl\s+(enable|start)",
            r"/etc/init\.d",
            r"/etc/systemd",
        ],
    },
    {
        "id": "EXF_001",
        "category": "数据外传",
        "severity": "HIGH",
        "description": "数据编码后发送 — 典型的数据窃取模式",
        "patterns": [
            r"base64.*request|request.*base64",
            r"json\.dumps.*post|post.*json\.dumps",
            r"encode.*send|send.*encode",
        ],
    },
    {
        "id": "EMB_001",
        "category": "结果嵌入数据",
        "severity": "HIGH",
        "description": "将原始数据直接写入输出文件 — 可能通过结果文件泄露原始数据",
        "patterns": [
            r"torch\.save\s*\(\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train)\b",
            r"np\.save\s*\(\s*['\"][^'\"]*['\"]\s*,\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train)\b",
            r"np\.savez\s*\(\s*['\"][^'\"]*['\"]\s*,[^)]*(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train)\s*=",
            r"shutil\.copy\s*\([^)]*(?:data|dataset|train|test|image)\b",
            r"shutil\.copytree\s*\([^)]*(?:data|dataset|train|test|image)\b",
        ],
    },
    {
        "id": "EMB_002",
        "category": "结果嵌入数据",
        "severity": "HIGH",
        "description": "将原始数据复制到模型输出目录 — 可能在导出时夹带明文数据",
        "patterns": [
            r"shutil\.(copy|copytree|move)\s*\(.*output",
            r"shutil\.(copy|copytree|move)\s*\(.*export",
            r"shutil\.(copy|copytree|move)\s*\(.*result",
            r"os\.rename\s*\(.*data.*output",
            r"os\.rename\s*\(.*data.*result",
        ],
    },
    {
        "id": "EMB_003",
        "category": "结果嵌入数据",
        "severity": "MEDIUM",
        "description": "将原始数据直接打印到日志/标准输出 — 可能在日志文件中泄露",
        "patterns": [
            r"print\s*\(\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|batch|x_train|y_train)\b",
            r"logging\.(?:info|debug|warning)\s*\(\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|batch|x_train|y_train)\b",
            r"sys\.stdout\.write\s*\(\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|batch|x_train|y_train)\b",
        ],
    },
    {
        "id": "EMB_004",
        "category": "结果嵌入数据",
        "severity": "HIGH",
        "description": "将数据编码后嵌入模型权重或输出 — 隐写术数据泄露",
        "patterns": [
            r"(?:state_dict|weights|params).*(?:hidden|secret|payload|stego|embed|hide)(?:_?data)?",
            r"base64.*save|save.*base64",
            r"encode.*state_dict|state_dict.*encode",
            r"zlib.*save|save.*zlib",
            r"pickle\.dump\s*\(.*(data|dataset|images|samples)",
        ],
    },
]

# Fix suggestion mapping (aligned with Go ruleSuggestionMap)
RULE_SUGGESTION_MAP = {
    "NET_001": "移除网络请求，或限制为仅发送模型指标",
    "NET_002": "移除原始 Socket 连接",
    "CMD_001": "移除子进程调用，使用安全的替代方案",
    "OBF_001": "移除编码/反序列化操作，使用安全的替代方案",
    "DYN_001": "移除 eval/exec，使用安全的替代方案",
    "FIL_001": "移除敏感文件读取",
    "ENV_001": "使用配置文件替代环境变量读取",
    "PER_001": "移除持久化机制",
    "EXF_001": "移除数据编码和发送操作",
    "EMB_001": "不要将原始数据写入输出文件",
    "EMB_002": "不要将数据复制到输出目录",
    "EMB_003": "避免在日志中打印原始数据",
    "EMB_004": "不要将数据编码后嵌入模型权重",
}


def suggestion_for_rule(rule_id: str) -> str:
    """Get fix suggestion for a rule ID."""
    return RULE_SUGGESTION_MAP.get(rule_id, "审查该代码片段并确认其安全性")


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    category: str
    severity: str
    description: str
    code_snippet: str
    context_before: str
    context_after: str
    llm_verdict: Optional[str] = None
    llm_reason: Optional[str] = None
    llm_risk: Optional[str] = None
    suggestion: Optional[str] = None  # Generated by ruleSuggestionMap in Go backend


@dataclass
class FileSummary:
    """Comprehensive LLM analysis for a single file."""
    risk_level: str = "UNCERTAIN"
    summary: str = ""
    chained: bool = False
    exfiltration: bool = False


# ============================================================
# 2. Static Scanning Engine
# ============================================================

class StaticScanner:
    """Scan source code using regex patterns to extract suspicious code snippets."""

    def __init__(self, patterns=SUSPICIOUS_PATTERNS):
        self.patterns = patterns
        self.compiled = []
        for rule in patterns:
            compiled_pats = [re.compile(p) for p in rule["patterns"]]
            self.compiled.append((rule, compiled_pats))

    def scan_file(self, filepath: str) -> List[Finding]:
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for rule, compiled_pats in self.compiled:
                for pat in compiled_pats:
                    if pat.search(line):
                        start = max(0, i - 3)
                        end = min(len(lines), i + 4)
                        ctx_before = "".join(lines[start:i]).strip()
                        ctx_after = "".join(lines[i + 1:end]).strip()

                        findings.append(Finding(
                            file=filepath,
                            line=i + 1,
                            rule_id=rule["id"],
                            category=rule["category"],
                            severity=rule["severity"],
                            description=rule["description"],
                            code_snippet=line.strip(),
                            context_before=ctx_before,
                            context_after=ctx_after,
                            suggestion=suggestion_for_rule(rule["id"]),
                        ))
                        break
        return findings

    def scan_directory(self, dirpath: str, extensions=(".py",)) -> List[Finding]:
        all_findings = []
        for root, dirs, files in os.walk(dirpath):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            for fname in files:
                if any(fname.endswith(ext) for ext in extensions):
                    fpath = os.path.join(root, fname)
                    all_findings.extend(self.scan_file(fpath))
        return all_findings


def extract_json_response(text: str) -> dict:
    """Robustly extract a JSON object from model response text."""
    if not text:
        return {}
    text = text.strip()
    try:
        res = json.loads(text)
        if isinstance(res, dict):
            return res
    except Exception:
        pass
    # Try extracting from markdown code block
    code_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if code_block:
        try:
            res = json.loads(code_block.group(1))
            if isinstance(res, dict):
                return res
        except Exception:
            pass
    # Try extracting outermost curly braces
    brace_match = re.search(r"(\{.*\})", text, re.DOTALL)
    if brace_match:
        try:
            res = json.loads(brace_match.group(1))
            if isinstance(res, dict):
                return res
        except Exception:
            pass
    return {}


def extract_finding_centered_context(
    lines: List[str],
    findings: List[Finding],
    max_lines: int = 400,
    context_window: int = 15,
) -> str:
    """
    Extract finding-centered dynamic context slice for large files:
    - If total lines <= max_lines, return full file content.
    - If total lines > max_lines:
      1. Top imports: first 20 lines.
      2. Finding-centered context windows [L - 1 - context_window, L + context_window].
      3. Bottom entry point (__main__ block near file end).
      Intervals are merged and formatted with section headers indicating lines.
    """
    if len(lines) <= max_lines:
        return "".join(lines).rstrip()

    total_lines = len(lines)
    intervals = []

    # 1. Top imports (first 20 lines)
    import_end = min(20, total_lines)
    intervals.append((0, import_end))

    # 2. Finding context windows
    for f in findings:
        line_no = getattr(f, "line", None)
        if line_no is not None and 1 <= line_no <= total_lines:
            start = max(0, line_no - 1 - context_window)
            end = min(total_lines, line_no + context_window)
            intervals.append((start, end))

    # 3. Bottom entry point (if __main__ block near end)
    main_start = -1
    search_start = max(0, total_lines - 60)
    for idx in range(search_start, total_lines):
        if "__main__" in lines[idx]:
            main_start = idx
            break
    if main_start != -1:
        intervals.append((main_start, total_lines))

    # Merge overlapping or contiguous intervals
    intervals.sort(key=lambda x: (x[0], x[1]))
    merged = []
    for start, end in intervals:
        if not merged:
            merged.append([start, end])
        else:
            prev_start, prev_end = merged[-1]
            if start <= prev_end:
                merged[-1][1] = max(prev_end, end)
            else:
                merged.append([start, end])

    # Build formatted snippet with section headers
    sections = []
    for start, end in merged:
        section_header = f"# --- Lines {start + 1} to {end} ---"
        snippet = "".join(lines[start:end]).rstrip()
        sections.append(f"{section_header}\n{snippet}")

    return "\n\n".join(sections)


# ============================================================
# 3. LLM Semantic Analysis Engine
# ============================================================

class LLMSecurityAnalyzer:
    """
    Perform semantic judgment on suspicious snippets from static scan using small LLMs:
    - Normal functionality vs. malicious behavior
    - Data exfiltration risks
    """

    FINDING_PROMPT = """你是一个代码安全审计专家。分析以下代码片段是否恶意。

文件: {file} (第 {line} 行)
```python
{context_before}
>>> {code_snippet}   ← 触发规则的代码
{context_after}
```

规则: {rule_id} ({category}) — {description}

判定优先级：
1. 只有在上下文表明读取的是密钥、令牌、密码、证书、私钥、敏感文件或外传/持久化载荷时，才判为 MALICIOUS 或 SUSPICIOUS。
2. 如果只是正常配置读取、模型权重保存（如通过 state_dict 保存模型权重）、训练参数、损失统计与日志记录（如 loss 日志打印）、报告导出、路径封装或框架常见 API 的良性用法，判为 BENIGN。
3. 如果证据不足、上下文不完整或语义无法确认，必须返回 UNCERTAIN。

白名单合规准则：
- 允许并通过 state_dict 保存模型权重：如 torch.save(model.state_dict(), ...) 为合规的模型导出，判为 BENIGN。
- 允许训练过程中的 loss、metric、batch 统计打印与日志记录，判为 BENIGN。
- 允许读取本地无敏感凭证的常规配置文件与环境变量，判为 BENIGN。

严格按 JSON 回答:
{{"verdict":"MALICIOUS或SUSPICIOUS或BENIGN或UNCERTAIN","reason":"一句话中文理由","risk":"数据风险说明"}}
"""

    DEFAULT_PROMPT_TEMPLATE = FINDING_PROMPT

    FILE_ANALYSIS_PROMPT = """分析此 Python 文件的安全性。

文件: {file} ({line_count} 行)
发现 {findings_count} 个可疑点: {findings_summary}

```python
{full_code}
```

判断:
1. risk_level: HIGH/MEDIUM/LOW
2. summary: 一句话安全结论(中文)
3. chained: 多个可疑点是否构成攻击链(true/false)
4. exfiltration: 是否有数据外传(true/false)

严格按 JSON 回答:
{{"risk_level":"...","summary":"...","chained":true,"exfiltration":true}}
"""

    PURE_LLM_FILE_PROMPT = """你是一个专业的代码安全审计专家。请对以下 Python 源码文件进行端到端安全审计。

目标环境：TEE (可信执行环境) 安全沙箱。
核心审计任务：检查该文件是否存在数据窃密、凭证泄露、网络外发、命令执行、代码混淆或后门植入行为。

文件: {file} (共 {line_count} 行)
```python
{full_code}
```

判定标准与优先级：
1. MALICIOUS: 明确存在高危攻击行为（如窃取 SSH 密钥/Token/密码/敏感文件、通过 requests/socket 网络外发本地数据、执行 os.system/subprocess 命令、持久化后门等）。
2. SUSPICIOUS: 存在上述危险操作但意图不明确，或经过混淆。
3. BENIGN: 正常的业务逻辑（如模型训练、数据加载、指标评估、日志打印、生成训练报告等常规操作）。
4. UNCERTAIN: 无法确认安全意图或代码不完整。

严格返回 JSON 格式（不要输出任何思考过程或多余文字）：
{{
  "verdict": "MALICIOUS或SUSPICIOUS或BENIGN或UNCERTAIN",
  "risk_level": "HIGH或MEDIUM或LOW或NONE",
  "reason": "一句话中文安全判定理由",
  "exfiltration": true或false
}}
"""

    def __init__(self, model_name="qwen2.5-coder:0.5b", backend="ollama"):
        self.model_name = model_name
        self.backend = backend

    def analyze_finding(self, finding: Finding) -> Finding:
        """Perform LLM semantic judgment on a single finding."""
        prompt = self.FINDING_PROMPT.format(
            file=finding.file,
            line=finding.line,
            code_snippet=finding.code_snippet,
            context_before=finding.context_before,
            context_after=finding.context_after,
            rule_id=finding.rule_id,
            category=finding.category,
            description=finding.description,
        )

        if self.backend == "ollama":
            result = self._call_ollama(prompt, num_predict=200)
        elif self.backend == "llamacpp":
            result = self._call_llamacpp(prompt, num_predict=200)
        else:
            result = {"verdict": "UNCERTAIN", "reason": "未配置推理后端", "risk": ""}

        finding.llm_verdict = result.get("verdict", "UNCERTAIN")
        finding.llm_reason = result.get("reason", "")
        finding.llm_risk = result.get("risk", "")
        return finding

    def analyze_file(self, file_path: str, findings: List[Finding], max_lines: int = 400) -> FileSummary:
        """Perform overall security analysis on a single file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return FileSummary(risk_level="UNCERTAIN", summary="无法读取文件")

        if len(lines) > max_lines:
            full_code = extract_finding_centered_context(lines, findings, max_lines=max_lines)
        else:
            full_code = "".join(lines).rstrip()

        # Build findings summary
        seen = set()
        parts = []
        for f in findings:
            if f.rule_id not in seen:
                seen.add(f.rule_id)
                parts.append(f"{f.rule_id}({f.category},{f.severity})")
        findings_summary = ", ".join(parts) if parts else "无"

        prompt = self.FILE_ANALYSIS_PROMPT.format(
            file=os.path.basename(file_path),
            line_count=len(lines),
            findings_count=len(findings),
            findings_summary=findings_summary,
            full_code=full_code,
        )

        if self.backend == "ollama":
            result = self._call_ollama(prompt, num_predict=300)
        elif self.backend == "llamacpp":
            result = self._call_llamacpp(prompt, num_predict=300)
        else:
            return FileSummary(risk_level="UNCERTAIN", summary="未配置推理后端")

        risk_level = result.get("risk_level", "UNCERTAIN")
        if risk_level not in ("HIGH", "MEDIUM", "LOW", "UNCERTAIN"):
            risk_level = "UNCERTAIN"

        return FileSummary(
            risk_level=risk_level,
            summary=result.get("summary", ""),
            chained=result.get("chained", False),
            exfiltration=result.get("exfiltration", False),
        )

    def audit_file_pure_llm(self, file_path: str, max_lines: int = 400) -> dict:
        """Perform end-to-end security audit on a source file using pure LLM without static rules."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            return {
                "file": os.path.basename(file_path),
                "file_path": file_path,
                "line_count": 0,
                "verdict": "UNCERTAIN",
                "risk_level": "UNCERTAIN",
                "reason": f"无法读取文件: {e}",
                "exfiltration": False,
            }

        if len(lines) > max_lines:
            tail_lines_count = 40
            search_start = max(0, len(lines) - 60)
            for idx in range(search_start, len(lines)):
                if "__main__" in lines[idx]:
                    entry_count = len(lines) - idx
                    if entry_count > tail_lines_count and entry_count <= max_lines // 2:
                        tail_lines_count = entry_count
                    break
            head_lines_count = max(0, max_lines - tail_lines_count)
            head_code = "".join(lines[:head_lines_count]).rstrip()
            tail_code = "".join(lines[-tail_lines_count:]).rstrip()
            full_code = (
                f"{head_code}\n\n"
                f"# ... (Truncated: total {len(lines)} lines, showing top and bottom entrypoint)\n\n"
                f"{tail_code}"
            )
        else:
            full_code = "".join(lines).rstrip()

        prompt = self.PURE_LLM_FILE_PROMPT.format(
            file=os.path.basename(file_path),
            line_count=len(lines),
            full_code=full_code,
        )

        if self.backend == "ollama":
            result = self._call_ollama(prompt, num_predict=200)
        elif self.backend == "llamacpp":
            result = self._call_llamacpp(prompt, num_predict=200)
        else:
            result = {"verdict": "UNCERTAIN", "risk_level": "UNCERTAIN", "reason": "未配置推理后端", "exfiltration": False}

        raw_verdict = str(result.get("verdict", "UNCERTAIN")).upper().strip()
        if raw_verdict not in ("MALICIOUS", "SUSPICIOUS", "BENIGN", "UNCERTAIN"):
            raw_verdict = "UNCERTAIN"

        raw_risk = str(result.get("risk_level", result.get("risk", "UNCERTAIN"))).upper().strip()
        if raw_risk not in ("HIGH", "MEDIUM", "LOW", "NONE", "UNCERTAIN"):
            raw_risk = "UNCERTAIN" if raw_verdict == "UNCERTAIN" else ("HIGH" if raw_verdict == "MALICIOUS" else "LOW")

        reason = result.get("reason", "") or ""
        exfiltration = bool(result.get("exfiltration", False))

        return {
            "file": os.path.basename(file_path),
            "file_path": file_path,
            "line_count": len(lines),
            "verdict": raw_verdict,
            "risk_level": raw_risk,
            "reason": reason,
            "exfiltration": exfiltration,
        }

    # Backward compatibility
    analyze = analyze_finding

    def _call_ollama(self, prompt: str, num_predict: int = 200) -> dict:
        """Invoke local model via Ollama REST API."""
        import urllib.request
        try:
            data = json.dumps({
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": num_predict},
            }).encode()
            req = urllib.request.Request(
                "http://localhost:11434/api/generate",
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read())
                text = result.get("response", "")
                parsed = extract_json_response(text)
                if parsed:
                    return parsed
                return {"verdict": "UNCERTAIN", "reason": f"无法解析模型输出: {text[:100]}", "risk": ""}
        except Exception as e:
            return {"verdict": "UNCERTAIN", "reason": f"ollama 调用失败: {e}", "risk": ""}

    def _call_llamacpp(self, prompt: str, num_predict: int = 200) -> dict:
        """Load and run GGUF model directly via llama-cpp-python."""
        try:
            from llama_cpp import Llama
            if not hasattr(self, '_llm'):
                model_path = os.environ.get("LLM_MODEL_PATH", "models/qwen2.5-coder-1.5b-q4_k_m.gguf")
                self._llm = Llama(model_path=model_path, n_ctx=2048, verbose=False)
            output = self._llm(prompt, max_tokens=num_predict, temperature=0.1)
            text = output["choices"][0]["text"]
            parsed = extract_json_response(text)
            if parsed:
                return parsed
            return {"verdict": "UNCERTAIN", "reason": f"无法解析: {text[:100]}", "risk": ""}
        except Exception as e:
            return {"verdict": "UNCERTAIN", "reason": f"llama.cpp 调用失败: {e}", "risk": ""}


# ============================================================
# 4. Audit Report Generation
# ============================================================

def group_findings_by_file(findings: List[Finding]) -> Dict[str, List[Finding]]:
    """Group findings by file path."""
    groups: Dict[str, List[Finding]] = {}
    for f in findings:
        groups.setdefault(f.file, []).append(f)
    return groups


def infer_risk_level(high_count: int, medium_count: int) -> str:
    """Infer risk level from static scan finding counts."""
    if high_count > 0:
        return "HIGH"
    if medium_count > 0:
        return "MEDIUM"
    return "LOW"


def compute_conclusion(
    stats: dict,
    file_summaries: Optional[Union[List[Union[dict, FileSummary]], Dict[str, FileSummary], str]] = None,
    policy: Optional[Union[dict, str]] = "gate",
) -> dict:
    """Compute audit conclusion (Fail-Closed Security Gate)."""
    # Backwards compatibility: policy passed as 2nd positional argument
    if isinstance(file_summaries, str):
        policy = file_summaries
        file_summaries = None

    policy_str = "gate"
    if isinstance(policy, str):
        policy_str = policy
    elif isinstance(policy, dict):
        policy_str = policy.get("policy", "gate")

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    benign = stats.get("benign", 0)
    uncertain = stats.get("uncertain", 0)
    high = stats.get("high", 0)
    medium = stats.get("medium", 0)
    total = stats.get("total_findings", 0)

    has_high_or_medium = (high > 0) or (medium > 0)
    has_uncertain = uncertain > 0
    has_llm_verdict = bool(stats.get("has_llm_verdict", False)) or (
        malicious + suspicious + benign + uncertain > 0
    )

    # Check file summaries for chained attacks or high-risk indicators
    file_chain_detected = False
    if file_summaries:
        raw_list = (
            list(file_summaries.values())
            if isinstance(file_summaries, dict)
            else file_summaries
        )
        for s in raw_list:
            if isinstance(s, dict):
                chained = s.get("chained", False)
                exfil = s.get("exfiltration", False) or s.get("has_exfiltration_pattern", False)
                s_risk = str(s.get("risk_level", "")).upper()
            else:
                chained = getattr(s, "chained", False)
                exfil = getattr(s, "exfiltration", False)
                s_risk = str(getattr(s, "risk_level", "")).upper()

            if chained or exfil or s_risk in ("CRITICAL", "HIGH"):
                file_chain_detected = True
                break

    # Determine risk_level
    if malicious > 0 or file_chain_detected:
        risk_level = "CRITICAL"
    elif suspicious > 0 or (has_uncertain and has_high_or_medium):
        risk_level = "HIGH"
    elif has_high_or_medium and not has_llm_verdict:
        risk_level = "HIGH" if high > 0 else "MEDIUM"
    elif has_uncertain:
        risk_level = "MEDIUM"
    elif high > 0 or medium > 0:
        risk_level = "LOW"
    else:
        risk_level = "NONE"

    # Evaluate Fail-Closed gate
    if malicious > 0 or suspicious > 0:
        passed = False
        verdict = "MALICIOUS" if malicious > 0 else "SUSPICIOUS"
        reason = "Confirmed attack finding present"
    elif file_chain_detected:
        passed = False
        verdict = "MALICIOUS"
        reason = "File-level attack chain detected"
    elif has_uncertain and has_high_or_medium:
        passed = False
        verdict = "UNCERTAIN"
        reason = "Fail-Closed: LLM uncertain on high/medium finding"
    elif has_high_or_medium and not has_llm_verdict:
        passed = False
        verdict = "SUSPICIOUS"
        reason = "High/medium finding not exonerated by LLM"
    else:
        passed = True
        verdict = "BENIGN"
        reason = "All findings exonerated as benign or zero findings"

    if policy_str == "assist":
        passed = risk_level not in ("CRITICAL", "HIGH")

    # Generate summary
    if total == 0 and not file_chain_detected:
        summary = "未发现安全问题，代码通过审计"
    else:
        parts = []
        if malicious > 0:
            parts.append(f"发现 {malicious} 处恶意代码")
        if suspicious > 0:
            parts.append(f"发现 {suspicious} 处可疑代码")
        if uncertain > 0:
            parts.append(f"发现 {uncertain} 处不确定代码")
        if benign > 0 and parts:
            parts.append(f"{benign} 处已确认为正常")
        if not parts:
            parts.append(f"发现 {total} 处安全问题（静态扫描）")
        if file_chain_detected:
            parts.append("检测到文件级复合攻击链")
        summary = "审计结论: " + "，".join(parts)
        if risk_level == "CRITICAL":
            summary += "。存在数据泄露风险，建议阻断导入"

    return {
        "passed": passed,
        "verdict": verdict,
        "reason": reason,
        "risk_level": risk_level,
        "summary": summary,
        "recommendation": "",
    }


def generate_audit_report(
    findings: List[Finding],
    dir_path: str,
    file_summaries: Dict[str, FileSummary],
    output_path: str,
    policy: str = "gate",
    llm_model: str = "qwen2.5-coder:0.5b",
    llm_enabled: bool = True,
    scan_duration_ms: int = 0,
) -> dict:
    """Generate structured audit report (aligned with Go AuditReport structure)."""
    # Group findings by file
    file_groups = group_findings_by_file(findings)

    # Statistics
    stats = {
        "total_findings": len(findings),
        "high": sum(1 for f in findings if f.severity == "HIGH"),
        "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
        "malicious": sum(1 for f in findings if f.llm_verdict == "MALICIOUS"),
        "suspicious": sum(1 for f in findings if f.llm_verdict == "SUSPICIOUS"),
        "benign": sum(1 for f in findings if f.llm_verdict == "BENIGN"),
        "uncertain": sum(1 for f in findings if f.llm_verdict == "UNCERTAIN"),
    }

    # File reports
    file_reports = []
    for file_path, file_findings in file_groups.items():
        high_count = sum(1 for f in file_findings if f.severity == "HIGH")
        medium_count = sum(1 for f in file_findings if f.severity == "MEDIUM")

        file_summary = file_summaries.get(file_path)
        if file_summary:
            risk_level = file_summary.risk_level
            summary = file_summary.summary
            chained = file_summary.chained
            exfiltration = file_summary.exfiltration
        else:
            risk_level = infer_risk_level(high_count, medium_count)
            summary = "仅静态扫描，未进行语义分析"
            chained = False
            exfiltration = False

        file_reports.append({
            "file": os.path.basename(file_path),
            "file_path": file_path,
            "findings_count": len(file_findings),
            "high_count": high_count,
            "medium_count": medium_count,
            "risk_level": risk_level,
            "summary": summary,
            "has_exfiltration_pattern": exfiltration,
            "chained": chained,
            "findings": [asdict(f) for f in file_findings],
        })

    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    file_reports.sort(key=lambda r: (risk_order.get(r["risk_level"], 5), -r["findings_count"]))

    # Conclusion
    conclusion = compute_conclusion(stats, file_summaries=file_summaries, policy=policy)

    # Generate recommendations
    bad_rule_ids = set()
    for f in findings:
        if f.llm_verdict in ("MALICIOUS", "SUSPICIOUS"):
            bad_rule_ids.add(f.rule_id)
    if not bad_rule_ids:
        for f in findings:
            if f.severity == "HIGH" and not f.llm_verdict:
                bad_rule_ids.add(f.rule_id)
    if bad_rule_ids:
        suggestions = [f"{rid}: {suggestion_for_rule(rid)}" for rid in sorted(bad_rule_ids)]
        conclusion["recommendation"] = "建议修复: " + "; ".join(suggestions)
    else:
        conclusion["recommendation"] = "无需修复"

    # Count scanned files and lines
    scanned_files = set()
    total_lines = 0
    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for fname in files:
            if fname.endswith(".py"):
                fpath = os.path.join(root, fname)
                scanned_files.add(fpath)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        total_lines += sum(1 for _ in f)
                except Exception:
                    pass

    import hashlib
    report_id = f"audit-{time.strftime('%Y%m%d-%H%M%S')}-{hashlib.md5(dir_path.encode()).hexdigest()[:8]}"

    report = {
        "report_id": report_id,
        "audit_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "target": {
            "directory": dir_path,
            "files_scanned": len(scanned_files),
            "total_lines": total_lines,
            "files_with_findings": len(file_reports),
        },
        "conclusion": conclusion,
        "statistics": stats,
        "file_reports": file_reports,
        "scan_metadata": {
            "scanner_version": "1.0.0",
            "rules_count": len(SUSPICIOUS_PATTERNS),
            "llm_model": llm_model,
            "llm_enabled": llm_enabled,
            "policy": policy,
            "scan_duration_ms": scan_duration_ms,
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return report


def print_audit_report(report: dict):
    """Print human-readable audit report to console."""
    c = report["conclusion"]
    s = report["statistics"]
    t = report["target"]
    m = report["scan_metadata"]

    # Risk level icons
    risk_icons = {
        "CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡",
        "LOW": "🟢", "NONE": "✅", "UNCERTAIN": "❓",
    }

    print(f"\n{'='*60}")
    print(f"  源码安全审计报告  ({report['audit_time']})")
    print(f"  Report ID: {report['report_id']}")
    print(f"{'='*60}")

    # Target
    print(f"\n  📁 审计目标: {t['directory']}")
    print(f"     扫描文件: {t['files_scanned']} 个, 总行数: {t['total_lines']}")
    print(f"     有问题文件: {t['files_with_findings']} 个")

    # Conclusion
    icon = risk_icons.get(c["risk_level"], "⚪")
    status = "✅ 通过" if c["passed"] else "❌ 不通过"
    print(f"\n  {icon} 审计结论: {status}")
    print(f"     风险等级: {c['risk_level']}")
    print(f"     {c['summary']}")
    print(f"     建议: {c['recommendation']}")

    # Statistics
    print(f"\n  📊 统计:")
    print(f"     总发现: {s['total_findings']} 个")
    print(f"     HIGH: {s['high']}, MEDIUM: {s['medium']}")
    if m["llm_enabled"]:
        print(f"     LLM 判断: MALICIOUS={s['malicious']}, SUSPICIOUS={s['suspicious']}, "
              f"BENIGN={s['benign']}, UNCERTAIN={s['uncertain']}")

    # File details
    bad_files = [fr for fr in report["file_reports"]
                 if fr["risk_level"] in ("CRITICAL", "HIGH")]
    if bad_files:
        print(f"\n  {'─'*56}")
        print(f"  ⚠️  高风险文件 ({len(bad_files)} 个):")
        print(f"  {'─'*56}")
        for fr in bad_files:
            f_icon = risk_icons.get(fr["risk_level"], "⚪")
            print(f"\n  {f_icon} [{fr['risk_level']}] {fr['file']}")
            print(f"     {fr['summary']}")
            if fr["chained"]:
                print(f"     ⛓️  多个可疑点构成攻击链")
            if fr["has_exfiltration_pattern"]:
                print(f"     📤 存在数据外传模式")
            for finding in fr["findings"]:
                v_icon = {"MALICIOUS": "🚨", "SUSPICIOUS": "⚠️",
                          "BENIGN": "✅", "UNCERTAIN": "❓"}.get(finding.get("llm_verdict", ""), "⏭")
                verdict = finding.get("llm_verdict", "未分析")
                print(f"     {v_icon} L{finding['line']} [{finding['rule_id']}] "
                      f"{finding['code_snippet'][:60]}")
                print(f"        → {verdict}: {finding.get('llm_reason', '-')}")
    else:
        print(f"\n  ✅ 未发现高风险文件")

    # Metadata
    print(f"\n  ⏱️  扫描耗时: {m['scan_duration_ms']}ms")
    print(f"     模型: {m['llm_model']}, 策略: {m['policy']}")
    print(f"\n{'='*60}\n")


# ============================================================
# 5. CLI Entrypoint
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="源码安全分析器 — 静态规则 + 小模型语义判断 + 结构化审计报告")
    parser.add_argument("source_dir", help="要扫描的源码目录")
    parser.add_argument("--model", default="qwen2.5-coder:0.5b", help="ollama 模型名 (默认: qwen2.5-coder:0.5b)")
    parser.add_argument("--backend", default="ollama", choices=["ollama", "llamacpp", "none"],
                        help="推理后端 (none=仅静态扫描)")
    parser.add_argument("--output", default="audit_report.json", help="报告输出路径")
    parser.add_argument("--extensions", default=".py", help="扫描的文件扩展名 (逗号分隔)")
    parser.add_argument("--max-findings", type=int, default=50, help="最多用 LLM 分析的发现数 (防止太慢)")
    parser.add_argument("--policy", default="gate", choices=["gate", "assist"],
                        help="审计策略: gate(可降级放行) 或 assist(仅标注)")
    args = parser.parse_args()

    if not os.path.isdir(args.source_dir):
        print(f"错误: 目录不存在: {args.source_dir}")
        sys.exit(1)

    extensions = tuple(e.strip() for e in args.extensions.split(","))
    start_time = time.time()

    # Step 1: Static scanning
    print(f"[1/4] 静态扫描: {args.source_dir}")
    scanner = StaticScanner()
    findings = scanner.scan_directory(args.source_dir, extensions=extensions)
    print(f"      发现 {len(findings)} 个可疑点")

    if not findings:
        print("      ✅ 无发现，代码安全")
        report = generate_audit_report(
            findings, args.source_dir, {},
            args.output, policy=args.policy,
            llm_model=args.model, llm_enabled=(args.backend != "none"),
            scan_duration_ms=int((time.time() - start_time) * 1000),
        )
        print_audit_report(report)
        sys.exit(0)

    # Step 2: Finding-level LLM analysis
    file_summaries: Dict[str, FileSummary] = {}
    if args.backend != "none":
        analyzer = LLMSecurityAnalyzer(model_name=args.model, backend=args.backend)
        to_analyze = findings[:args.max_findings]
        print(f"[2/4] LLM Finding 分析 ({args.model}): {len(to_analyze)} 个")
        for i, f in enumerate(to_analyze):
            print(f"      [{i+1}/{len(to_analyze)}] {f.rule_id} @ {os.path.basename(f.file)}:{f.line} ...", end=" ")
            analyzer.analyze_finding(f)
            print(f"→ {f.llm_verdict}")

        # Step 3: File-level LLM analysis
        file_groups = group_findings_by_file(findings)
        print(f"[3/4] LLM 文件级分析: {len(file_groups)} 个文件")
        for file_path, file_findings in file_groups.items():
            fname = os.path.basename(file_path)
            print(f"      分析 {fname} ({len(file_findings)} 个发现) ...", end=" ")
            summary = analyzer.analyze_file(file_path, file_findings)
            file_summaries[file_path] = summary
            print(f"→ {summary.risk_level}")
    else:
        print("[2/4] 跳过 LLM Finding 分析 (backend=none)")
        print("[3/4] 跳过 LLM 文件级分析 (backend=none)")

    # Step 4: Generate audit report
    print(f"[4/4] 生成审计报告: {args.output}")
    report = generate_audit_report(
        findings, args.source_dir, file_summaries,
        args.output, policy=args.policy,
        llm_model=args.model, llm_enabled=(args.backend != "none"),
        scan_duration_ms=int((time.time() - start_time) * 1000),
    )
    print_audit_report(report)

    # Exit code: return 1 if audit failed
    sys.exit(0 if report["conclusion"]["passed"] else 1)


if __name__ == "__main__":
    main()
