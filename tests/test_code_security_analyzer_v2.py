"""
Unit tests for Python code security analyzer engine parity upgrade.
Tests rule coverage of 13 static rules, finding-centered context slicing,
and fail-closed gate logic.
"""

import os
import sys
import unittest
import tempfile
from unittest.mock import MagicMock
from pathlib import Path

# Add models/examples to sys.path to import code_security_analyzer
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "models" / "examples"))

import code_security_analyzer
from code_security_analyzer import (
    StaticScanner,
    Finding,
    FileSummary,
    SUSPICIOUS_PATTERNS,
    RULE_SUGGESTION_MAP,
    compute_conclusion,
    generate_audit_report,
    LLMSecurityAnalyzer,
)


class TestCodeSecurityAnalyzerV2(unittest.TestCase):
    """Test suite for engine parity upgrade."""

    def setUp(self):
        self.scanner = StaticScanner()

    def _scan_snippet(self, code_str: str) -> list:
        """Helper to scan an in-memory python code snippet."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code_str)
            tmp_path = f.name
        try:
            return self.scanner.scan_file(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_rule_coverage_13_rules(self):
        """
        Verify StaticScanner has all 13 rules and behaves correctly on:
        - EMB_001 positive and negative cases
        - ENV_001 case-insensitivity
        - CMD_001 shell execution vs benign parameterized subprocess calls
        """
        expected_rules = {
            "NET_001", "NET_002", "CMD_001", "OBF_001", "DYN_001",
            "FIL_001", "ENV_001", "PER_001", "EXF_001",
            "EMB_001", "EMB_002", "EMB_003", "EMB_004",
        }
        actual_rules = {rule["id"] for rule, _ in self.scanner.compiled}
        self.assertEqual(
            expected_rules,
            actual_rules,
            f"Missing or mismatched rules in StaticScanner: {expected_rules - actual_rules}",
        )

        # Verify RULE_SUGGESTION_MAP covers all 13 rules
        for rule_id in expected_rules:
            self.assertIn(rule_id, RULE_SUGGESTION_MAP)

        # EMB_001: torch.save(raw_data, path) triggers EMB_001
        emb_findings = self._scan_snippet("torch.save(raw_data, 'output.pt')\n")
        emb_rule_ids = [f.rule_id for f in emb_findings]
        self.assertIn("EMB_001", emb_rule_ids)

        # EMB_001 negative: torch.save(model.state_dict(), path) does NOT trigger EMB_001
        safe_emb_findings = self._scan_snippet("torch.save(model.state_dict(), 'model.pt')\n")
        safe_emb_rule_ids = [f.rule_id for f in safe_emb_findings]
        self.assertNotIn("EMB_001", safe_emb_rule_ids)

        # ENV_001: case-insensitive detection for AWS_SECRET and API_KEY
        env_findings_1 = self._scan_snippet("secret = os.environ.get('AWS_SECRET')\n")
        env_rule_ids_1 = [f.rule_id for f in env_findings_1]
        self.assertIn("ENV_001", env_rule_ids_1)

        env_findings_2 = self._scan_snippet("api_key = os.environ['API_KEY']\n")
        env_rule_ids_2 = [f.rule_id for f in env_findings_2]
        self.assertIn("ENV_001", env_rule_ids_2)

        # CMD_001: triggers on shell=True, dangerous shells, os.system
        cmd_snippet_shell = 'subprocess.run("rm -rf /", shell=True)\n'
        cmd_findings_shell = self._scan_snippet(cmd_snippet_shell)
        self.assertIn("CMD_001", [f.rule_id for f in cmd_findings_shell])

        cmd_snippet_bash = 'subprocess.run(["bash", "-c", "echo hello"])\n'
        cmd_findings_bash = self._scan_snippet(cmd_snippet_bash)
        self.assertIn("CMD_001", [f.rule_id for f in cmd_findings_bash])

        cmd_snippet_os = 'os.system("ls -la")\n'
        cmd_findings_os = self._scan_snippet(cmd_snippet_os)
        self.assertIn("CMD_001", [f.rule_id for f in cmd_findings_os])

        # CMD_001 negative: benign parameterized subprocess calls without shell=True are NOT flagged
        cmd_snippet_benign = 'subprocess.run(["git", "status"], check=True)\n'
        cmd_findings_benign = self._scan_snippet(cmd_snippet_benign)
        self.assertNotIn("CMD_001", [f.rule_id for f in cmd_findings_benign])

    def test_finding_centered_context_slicing(self):
        """
        Verify extract_finding_centered_context extracts imports, lines around findings,
        and __main__ block without retaining the entire file.
        """
        # Ensure extract_finding_centered_context exists
        self.assertTrue(
            hasattr(code_security_analyzer, "extract_finding_centered_context"),
            "extract_finding_centered_context is not implemented in code_security_analyzer",
        )
        extract_fn = getattr(code_security_analyzer, "extract_finding_centered_context")

        # Build 500-line snippet
        lines = []
        # Lines 1-5: imports
        lines.append("import os\n")
        lines.append("import sys\n")
        lines.append("import torch\n")
        lines.append("import numpy as np\n")
        lines.append("from pathlib import Path\n")

        # Lines 6-349: filler
        for i in range(6, 350):
            lines.append(f"x_{i} = {i}  # filler line\n")

        # Line 350: finding
        lines.append("torch.save(raw_data, 'leaked.pt')  # finding line 350\n")

        # Lines 351-494: filler
        for i in range(351, 495):
            lines.append(f"y_{i} = {i}  # filler line\n")

        # Lines 495-500: entrypoint
        lines.append("if __name__ == '__main__':\n")
        lines.append("    print('running main')\n")
        lines.append("    sys.exit(0)\n")
        for i in range(498, 501):
            lines.append(f"# end line {i}\n")

        self.assertEqual(len(lines), 500)

        finding = Finding(
            file="test_sample.py",
            line=350,
            rule_id="EMB_001",
            category="结果嵌入数据",
            severity="HIGH",
            description="test finding",
            code_snippet="torch.save(raw_data, 'leaked.pt')",
            context_before="",
            context_after="",
        )

        sliced = extract_fn(lines, [finding], max_lines=400, context_window=15)

        # Sliced content must be smaller than the original 500 lines
        sliced_lines = sliced.splitlines()
        self.assertLess(len(sliced_lines), 300)

        # Sliced content must contain imports
        self.assertIn("import torch", sliced)
        self.assertIn("from pathlib import Path", sliced)

        # Sliced content must contain lines around 350
        self.assertIn("torch.save(raw_data, 'leaked.pt')", sliced)
        self.assertIn("x_345", sliced)
        self.assertIn("y_355", sliced)

        # Sliced content must contain __main__ entrypoint
        self.assertIn("if __name__ == '__main__':", sliced)
        self.assertIn("running main", sliced)

        # Verify that distant filler lines are omitted
        self.assertNotIn("x_100", sliced)
        self.assertNotIn("y_420", sliced)

        # Verify that files <= max_lines return full content
        short_lines = ["import math\n", "print(math.pi)\n"]
        short_sliced = extract_fn(short_lines, [], max_lines=400)
        self.assertEqual(short_sliced, "".join(short_lines).rstrip())

    def test_fail_closed_gate(self):
        """
        Verify Fail-Closed Gate rules:
        - stats with high + uncertain -> passed=False, verdict='UNCERTAIN'
        - stats with high + no LLM verdict -> passed=False
        - stats with high + malicious -> passed=False, verdict='MALICIOUS'
        - stats with high + benign + LLM verdict -> passed=True, verdict='BENIGN'
        - file_summaries with chained/exfiltration -> passed=False
        - stats with total_findings=0 -> passed=True
        """
        # 1. High + uncertain -> passed=False, verdict='UNCERTAIN'
        c1 = compute_conclusion({"high": 1, "uncertain": 1, "has_llm_verdict": True})
        self.assertFalse(c1["passed"])
        self.assertEqual(c1["verdict"], "UNCERTAIN")

        # 2. High + no LLM verdict -> passed=False
        c2 = compute_conclusion({"high": 1, "has_llm_verdict": False})
        self.assertFalse(c2["passed"])

        # 3. High + malicious -> passed=False, verdict='MALICIOUS'
        c3 = compute_conclusion({"high": 1, "malicious": 1})
        self.assertFalse(c3["passed"])
        self.assertEqual(c3["verdict"], "MALICIOUS")

        # 4. High + benign + LLM verdict -> passed=True, verdict='BENIGN'
        c4 = compute_conclusion({"high": 1, "benign": 1, "has_llm_verdict": True})
        self.assertTrue(c4["passed"])
        self.assertEqual(c4["verdict"], "BENIGN")

        # 5. file_summaries list with chained=True -> passed=False
        c5_list = compute_conclusion(
            {"high": 0, "total_findings": 0},
            file_summaries=[{"chained": True}],
        )
        self.assertFalse(c5_list["passed"])

        # 5b. file_summaries dict with FileSummary(chained=True) -> passed=False
        c5_dict = compute_conclusion(
            {"high": 0, "total_findings": 0},
            file_summaries={"file.py": FileSummary(chained=True)},
        )
        self.assertFalse(c5_dict["passed"])

        # 6. Zero findings -> passed=True
        c6 = compute_conclusion({"total_findings": 0})
        self.assertTrue(c6["passed"])

    def test_compute_conclusion_backward_compatibility(self):
        """
        Verify backward compatibility for compute_conclusion when policy is passed
        as second argument.
        """
        c_legacy = compute_conclusion({"high": 0, "total_findings": 0}, "gate")
        self.assertTrue(c_legacy["passed"])

        c_assist = compute_conclusion({"high": 1, "total_findings": 1}, "assist")
        self.assertIn("passed", c_assist)
        self.assertIn("risk_level", c_assist)

    def test_llm_prompt_whitelist_guidelines(self):
        """
        Verify that LLMSecurityAnalyzer prompt template includes whitelist guidelines
        for state_dict, metric logging, and config reading.
        """
        prompt = getattr(LLMSecurityAnalyzer, "DEFAULT_PROMPT_TEMPLATE", "")
        if not prompt:
            prompt = getattr(LLMSecurityAnalyzer, "FINDING_PROMPT", "")

        self.assertTrue(len(prompt) > 0)
        self.assertIn("state_dict", prompt)

    def test_audit_file_pure_llm_structured_slicing(self):
        """
        Verify that audit_file_pure_llm applies structured head/tail slicing with
        an English truncation notice when file line count exceeds max_lines.
        """
        analyzer = LLMSecurityAnalyzer(backend="ollama")
        captured_prompts = []
        analyzer._call_ollama = MagicMock(
            side_effect=lambda prompt, **kwargs: (
                captured_prompts.append(prompt),
                {"verdict": "BENIGN", "risk_level": "LOW", "reason": "ok", "exfiltration": False},
            )[1]
        )

        # 1. Test file exceeding max_lines: 500 lines with max_lines=400
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            for i in range(1, 485):
                f.write(f"line_{i} = {i}\n")
            f.write("if __name__ == '__main__':\n")
            for i in range(486, 501):
                f.write(f"    print({i})\n")
            large_file_path = f.name

        try:
            res = analyzer.audit_file_pure_llm(large_file_path, max_lines=400)
            self.assertEqual(res["verdict"], "BENIGN")
            self.assertEqual(len(captured_prompts), 1)
            prompt = captured_prompts[0]

            expected_notice = "# ... (Truncated: total 500 lines, showing top and bottom entrypoint)"
            self.assertIn(expected_notice, prompt)
            self.assertIn("line_1 = 1", prompt)
            self.assertIn("if __name__ == '__main__':", prompt)
            # Intermediate lines should be omitted by slicing
            self.assertNotIn("line_380 = 380", prompt)
        finally:
            if os.path.exists(large_file_path):
                os.unlink(large_file_path)

        # 2. Test file within max_lines limit: no truncation notice
        captured_prompts.clear()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            for i in range(1, 20):
                f.write(f"x_{i} = {i}\n")
            short_file_path = f.name

        try:
            res = analyzer.audit_file_pure_llm(short_file_path, max_lines=400)
            self.assertEqual(res["verdict"], "BENIGN")
            self.assertEqual(len(captured_prompts), 1)
            prompt = captured_prompts[0]
            self.assertNotIn("Truncated:", prompt)
            self.assertIn("x_1 = 1", prompt)
            self.assertIn("x_19 = 19", prompt)
        finally:
            if os.path.exists(short_file_path):
                os.unlink(short_file_path)

    def test_compute_conclusion_defensive_typing(self):
        """
        Verify that compute_conclusion safely handles ill-typed stats and summaries.
        """
        # stats is None or non-dict
        c_none = compute_conclusion(None)
        self.assertFalse(c_none["passed"])
        self.assertEqual(c_none["verdict"], "UNCERTAIN")

        # stats values are strings or None
        c_strings = compute_conclusion({"high": "1", "uncertain": None})
        self.assertFalse(c_strings["passed"])

    def test_semgrep_finding_contract_fields(self):
        """
        Verify that Finding supports multi-language, taint trace, ast scope,
        and engine contract fields.
        """
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
            ast_enclosing_block="def send(): pass",
            engine="semgrep",
        )
        self.assertEqual(f.language, "python")
        self.assertEqual(len(f.taint_trace), 1)
        self.assertIn("def send", f.ast_enclosing_block)
        self.assertEqual(f.engine, "semgrep")

        # file_summaries is invalid type
        c_invalid_summary = compute_conclusion({"high": 0, "total_findings": 0}, file_summaries=123)
        self.assertTrue(c_invalid_summary["passed"])

    def test_extract_finding_centered_context_budget_capping(self):
        """
        Verify that when many findings are scattered across thousands of lines,
        the sliced output adheres to the max_lines budget.
        """
        extract_fn = getattr(code_security_analyzer, "extract_finding_centered_context")
        lines = [f"line_{i} = {i}\n" for i in range(1, 2001)]
        # 30 findings spread out
        findings = [
            Finding(
                file="test.py",
                line=i * 60,
                rule_id="NET_001",
                category="Network",
                severity="HIGH",
                description="desc",
                code_snippet="req",
                context_before="",
                context_after="",
            )
            for i in range(1, 30)
        ]
        sliced = extract_fn(lines, findings, max_lines=400, context_window=15)
        sliced_line_count = len(sliced.splitlines())
        self.assertLessEqual(sliced_line_count, 450)


if __name__ == "__main__":
    unittest.main()
