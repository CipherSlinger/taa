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

if __name__ == "__main__":
    unittest.main()
