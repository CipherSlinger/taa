# tests/test_semgrep_rule_schema.py
import unittest
from pathlib import Path
import yaml

class TestSemgrepRuleSchema(unittest.TestCase):
    """Validates the schema and completeness of canonical Semgrep rule definitions."""

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

    def test_python_rule_severity_matches_baseline(self):
        """Every Python rule must carry the same severity as its baseline mirror.

        The two arms are only comparable if a rule difference cannot show up as
        an engine difference. Severity is part of that: under the gate policy a
        MEDIUM finding always blocks while a HIGH one can be exonerated by the
        LLM, so a mismatched severity silently changes which findings the
        arbitration even sees.
        """
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from models.examples.code_security_analyzer import SUSPICIOUS_PATTERNS

        baseline = {rule["id"]: rule["severity"] for rule in SUSPICIOUS_PATTERNS}
        # Semgrep severities map to the harness vocabulary via this table.
        mapped = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

        compared = set()
        for yf in sorted((self.rules_dir / "python").rglob("*.yaml")):
            with open(yf, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            for rule in data.get("rules", []):
                family = (rule.get("metadata") or {}).get("rule_family")
                if family not in baseline:
                    continue
                compared.add(family)
                actual = mapped.get(str(rule.get("severity", "")).upper())
                self.assertEqual(
                    actual, baseline[family],
                    f"{family}: semgrep severity {rule.get('severity')} maps to "
                    f"{actual}, baseline is {baseline[family]}",
                )

        missing = set(baseline) - compared
        self.assertEqual(missing, set(), f"no Python semgrep rule covers {sorted(missing)}")

if __name__ == "__main__":
    unittest.main()
