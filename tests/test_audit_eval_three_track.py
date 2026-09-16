"""Unit tests for three-track evaluation (static-llm, pure-llm, pure-llm-checklist) and bootstrap CI."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools.audit_benchmark_eval import (
    CHECKLIST_RULES_PROMPT,
    SampleSpec,
    analyse_sample,
    bootstrap_metric_ci,
    check_sample_attribution,
    compute_all_bootstrap_ci,
    compute_attribution_precision,
    compute_bootstrap_ci,
    metric_summary,
    parse_args,
)
from models.examples.code_security_analyzer import LLMSecurityAnalyzer

EXPECTED_13_RULES = [
    "NET_001",
    "NET_002",
    "CMD_001",
    "OBF_001",
    "DYN_001",
    "FIL_001",
    "ENV_001",
    "PER_001",
    "EXF_001",
    "EMB_001",
    "EMB_002",
    "EMB_003",
    "EMB_004",
]


class TestAuditEvalThreeTrack(unittest.TestCase):
    """Test suite for three-track evaluation, checklist injection, attribution, and bootstrap CI."""

    def test_audit_mode_cli_parsing(self):
        """Verify --audit-mode CLI argument accepts all three evaluation tracks."""
        args_default = parse_args([])
        self.assertEqual(args_default.audit_mode, "static-llm")

        args_pure = parse_args(["--audit-mode", "pure-llm"])
        self.assertEqual(args_pure.audit_mode, "pure-llm")

        args_checklist = parse_args(["--audit-mode", "pure-llm-checklist"])
        self.assertEqual(args_checklist.audit_mode, "pure-llm-checklist")

        args_static = parse_args(["--audit-mode", "static-llm"])
        self.assertEqual(args_static.audit_mode, "static-llm")

        with self.assertRaises(SystemExit):
            parse_args(["--audit-mode", "invalid-mode"])

    def test_pure_llm_checklist_prompt_injection(self):
        """Verify pure-llm-checklist mode injects all 13 rules into the LLM audit prompt."""
        for rule_id in EXPECTED_13_RULES:
            self.assertIn(
                rule_id,
                CHECKLIST_RULES_PROMPT,
                f"Rule {rule_id} must be present in CHECKLIST_RULES_PROMPT",
            )

        sample = SampleSpec(
            sample_id="M1-01",
            base_project="p1_xgboost_finance",
            family="M1",
            label="malicious",
            transformation="command_execution",
            expected_rules=("CMD_001",),
            expected_severity="HIGH",
            expected_final="MALICIOUS",
            trap_type="cmd_exec",
            notes="Test prompt injection",
            relative_path="p1_xgboost_finance/M1-01",
        )

        sample_dir = REPO_ROOT / "models" / "audit" / "benchmarks" / "audit-100" / sample.relative_path
        results_dir = REPO_ROOT / "models" / "audit" / "audit-results" / "test_run"

        with patch.object(
            LLMSecurityAnalyzer,
            "_call_ollama",
            return_value={
                "verdict": "MALICIOUS",
                "risk_level": "HIGH",
                "reason": "Test detection",
                "exfiltration": False,
            },
        ) as mock_call:
            analyse_sample(
                sample=sample,
                sample_dir=sample_dir,
                results_dir=results_dir,
                audit_mode="pure-llm-checklist",
                policy="gate",
                llm_backend="ollama",
                llm_model="qwen2.5-coder:0.5b",
                extensions=(".py",),
                max_findings=10,
            )

            self.assertTrue(mock_call.called, "LLM backend must be called during file audit")
            first_prompt = mock_call.call_args[0][0]
            for rule_id in EXPECTED_13_RULES:
                self.assertIn(
                    rule_id,
                    first_prompt,
                    f"Injected prompt must contain checklist rule {rule_id}",
                )

        with patch.object(
            LLMSecurityAnalyzer,
            "_call_ollama",
            return_value={
                "verdict": "MALICIOUS",
                "risk_level": "HIGH",
                "reason": "Test detection",
                "exfiltration": False,
            },
        ) as mock_call_pure:
            analyse_sample(
                sample=sample,
                sample_dir=sample_dir,
                results_dir=results_dir,
                audit_mode="pure-llm",
                policy="gate",
                llm_backend="ollama",
                llm_model="qwen2.5-coder:0.5b",
                extensions=(".py",),
                max_findings=10,
            )

            self.assertTrue(mock_call_pure.called)
            pure_prompt = mock_call_pure.call_args[0][0]
            self.assertNotIn(
                "Security Checklist Rules",
                pure_prompt,
                "pure-llm prompt must not have checklist rules injected",
            )

    def test_attribution_precision_calculation(self):
        """Construct synthetic evaluation results and verify attribution precision computation."""
        sample_meta_m1 = {
            "sample_id": "M1-01",
            "label": "malicious",
            "primary_attack_finding": {
                "file": "benchmark_variant.py",
                "rule_id": "CMD_001",
                "line": 15,
            },
        }
        sample_meta_m2 = {
            "sample_id": "M2-01",
            "label": "malicious",
            "primary_attack_finding": {
                "file": "benchmark_variant.py",
                "rule_id": "NET_001",
                "line": 20,
            },
        }
        sample_meta_b1 = {
            "sample_id": "B1-01",
            "label": "benign",
            "primary_attack_finding": None,
        }

        # Case 1: Static-LLM matching primary attack finding (CMD_001 in benchmark_variant.py)
        row_m1_match = {
            "sample_id": "M1-01",
            "label": "malicious",
            "blocked": True,
            "audit_mode": "static-llm",
            "audit_report": {
                "file_reports": [
                    {
                        "file": "benchmark_variant.py",
                        "findings": [
                            {"rule_id": "CMD_001", "llm_verdict": "MALICIOUS", "severity": "HIGH"}
                        ],
                    }
                ]
            },
            "sample_meta": sample_meta_m1,
        }
        self.assertTrue(check_sample_attribution(row_m1_match, sample_meta_m1))

        # Case 2: Static-LLM non-matching finding (blocked on OBF_001 instead of NET_001)
        row_m2_mismatch = {
            "sample_id": "M2-01",
            "label": "malicious",
            "blocked": True,
            "audit_mode": "static-llm",
            "audit_report": {
                "file_reports": [
                    {
                        "file": "benchmark_variant.py",
                        "findings": [
                            {"rule_id": "OBF_001", "llm_verdict": "MALICIOUS", "severity": "HIGH"}
                        ],
                    }
                ]
            },
            "sample_meta": sample_meta_m2,
        }
        self.assertFalse(check_sample_attribution(row_m2_mismatch, sample_meta_m2))

        # Case 3: Malicious sample not blocked (evaded detection)
        row_m1_evaded = {
            "sample_id": "M1-01",
            "label": "malicious",
            "blocked": False,
            "audit_mode": "static-llm",
            "audit_report": {"file_reports": []},
            "sample_meta": sample_meta_m1,
        }
        self.assertFalse(check_sample_attribution(row_m1_evaded, sample_meta_m1))

        # Case 4: Benign sample (attribution is N/A)
        row_b1_benign = {
            "sample_id": "B1-01",
            "label": "benign",
            "blocked": False,
            "audit_mode": "static-llm",
            "audit_report": {"file_reports": []},
            "sample_meta": sample_meta_b1,
        }
        self.assertFalse(check_sample_attribution(row_b1_benign, sample_meta_b1))

        # Case 5: Pure-LLM mode where variant file is judged MALICIOUS
        row_pure_match = {
            "sample_id": "M1-01",
            "label": "malicious",
            "blocked": True,
            "audit_mode": "pure-llm",
            "audit_report": {
                "file_reports": [
                    {"file": "train.py", "verdict": "BENIGN", "risk_level": "NONE"},
                    {"file": "benchmark_variant.py", "verdict": "MALICIOUS", "risk_level": "HIGH"},
                ]
            },
            "sample_meta": sample_meta_m1,
        }
        self.assertTrue(check_sample_attribution(row_pure_match, sample_meta_m1))

        # Case 6: Pure-LLM mode where variant file is BENIGN but another file was flagged
        row_pure_mismatch = {
            "sample_id": "M1-01",
            "label": "malicious",
            "blocked": True,
            "audit_mode": "pure-llm",
            "audit_report": {
                "file_reports": [
                    {"file": "train.py", "verdict": "MALICIOUS", "risk_level": "HIGH"},
                    {"file": "benchmark_variant.py", "verdict": "BENIGN", "risk_level": "NONE"},
                ]
            },
            "sample_meta": sample_meta_m1,
        }
        self.assertFalse(check_sample_attribution(row_pure_mismatch, sample_meta_m1))

        # Test compute_attribution_precision on synthetic batch:
        # 3 blocked malicious samples: row_m1_match (True), row_m2_mismatch (False), row_pure_match (True) -> 2/3
        # Plus 1 unblocked malicious sample (row_m1_evaded) -> not in denominator
        # Plus 1 benign sample (row_b1_benign) -> not in denominator
        synthetic_results = [
            row_m1_match,
            row_m2_mismatch,
            row_m1_evaded,
            row_b1_benign,
            row_pure_match,
        ]

        precision = compute_attribution_precision(synthetic_results)
        self.assertAlmostEqual(precision, 2.0 / 3.0, places=4)

        # Denominator = 0 returns 0.0
        self.assertEqual(compute_attribution_precision([row_b1_benign, row_m1_evaded]), 0.0)
        self.assertEqual(compute_attribution_precision([]), 0.0)

        # Check metric_summary includes attribution_precision
        summary = metric_summary(synthetic_results)
        self.assertIn("attribution_precision", summary)
        self.assertAlmostEqual(summary["attribution_precision"], 2.0 / 3.0, places=4)

    def test_bootstrap_ci_convergence(self):
        """Test bootstrap 95% confidence interval estimation on known distributions."""
        known_distribution = [1.0] * 80 + [0.0] * 20
        ci_result = compute_bootstrap_ci(
            known_distribution,
            n_bootstraps=1000,
            confidence_level=0.95,
            seed=42,
        )

        self.assertIn("mean", ci_result)
        self.assertIn("ci_lower", ci_result)
        self.assertIn("ci_upper", ci_result)

        self.assertAlmostEqual(ci_result["mean"], 0.8, places=4)
        self.assertLess(ci_result["ci_lower"], ci_result["mean"])
        self.assertGreater(ci_result["ci_upper"], ci_result["mean"])
        self.assertGreaterEqual(ci_result["ci_lower"], 0.0)
        self.assertLessEqual(ci_result["ci_upper"], 1.0)

        # Verify deterministic reproducibility with identical seed
        ci_repeat = compute_bootstrap_ci(
            known_distribution,
            n_bootstraps=1000,
            confidence_level=0.95,
            seed=42,
        )
        self.assertEqual(ci_result, ci_repeat)

        # Verify bootstrap_metric_ci tuple API
        mean, lower, upper = bootstrap_metric_ci(
            known_distribution,
            n_bootstraps=1000,
            confidence_level=0.95,
            seed=42,
        )
        self.assertEqual(mean, ci_result["mean"])
        self.assertEqual(lower, ci_result["ci_lower"])
        self.assertEqual(upper, ci_result["ci_upper"])

        # Handles empty list without crashing
        empty_res = compute_bootstrap_ci([], n_bootstraps=1000, seed=42)
        self.assertEqual(empty_res["mean"], 0.0)
        self.assertEqual(empty_res["ci_lower"], 0.0)
        self.assertEqual(empty_res["ci_upper"], 0.0)

        # Handles single value without crashing
        single_res = compute_bootstrap_ci([0.75], n_bootstraps=1000, seed=42)
        self.assertEqual(single_res["mean"], 0.75)
        self.assertEqual(single_res["ci_lower"], 0.75)
        self.assertEqual(single_res["ci_upper"], 0.75)

        # Verify compute_all_bootstrap_ci structure
        sample_results = [
            {"label": "malicious", "blocked": True, "attributed": True},
            {"label": "malicious", "blocked": True, "attributed": False},
            {"label": "benign", "blocked": False, "attributed": False},
            {"label": "benign", "blocked": False, "attributed": False},
        ]
        all_ci = compute_all_bootstrap_ci(sample_results, n_bootstraps=100, seed=42)
        for key in ("accuracy", "precision", "recall", "f1", "fpr", "attribution_precision"):
            self.assertIn(key, all_ci)
            self.assertIn("mean", all_ci[key])
            self.assertIn("ci_lower", all_ci[key])
            self.assertIn("ci_upper", all_ci[key])


if __name__ == "__main__":
    unittest.main()
