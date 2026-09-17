# tests/test_semgrep_fail_closed_gate.py
import unittest
from models.examples.code_security_analyzer import compute_conclusion

class TestFailClosedGateContract(unittest.TestCase):
    """Verifies that incomplete scans or parser defects strictly trigger Fail-Closed blocks."""

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
        self.assertIn("Fail-Closed", res["reason"])

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
        self.assertIn("Fail-Closed", res["reason"])

    def test_zero_findings_with_timeout_blocks(self):
        # Scan timed out -> must NOT pass
        stats = {
            "total_findings": 0,
            "scan_complete": False,
            "timed_out": True
        }
        res = compute_conclusion(stats)
        self.assertFalse(res["passed"])
        self.assertEqual(res["verdict"], "UNCERTAIN")

    def test_zero_findings_clean_pass(self):
        # Pure clean scan -> safely pass
        stats = {
            "total_findings": 0,
            "scan_complete": True,
            "parser_errors": 0,
            "timed_out": False
        }
        res = compute_conclusion(stats)
        self.assertTrue(res["passed"])
        self.assertEqual(res["verdict"], "BENIGN")

if __name__ == "__main__":
    unittest.main()
