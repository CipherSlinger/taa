"""Unit tests for the 100-sample orthogonal benchmark matrix and materialized sandboxes."""

import ast
import json
import py_compile
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools.audit_benchmark_eval import PROJECT_ALLOCATION  # noqa: E402

MANIFEST_PATH = REPO_ROOT / "docs" / "audit" / "audit-benchmark-manifest.json"
BENCHMARK_ROOT = REPO_ROOT / "models" / "audit" / "benchmarks" / "audit-100"

EXPECTED_BASE_PROJECTS = {
    "p1_xgboost_finance",
    "p2_retina_resnet",
    "p3_detection_industrial",
    "p4_bert_sentiment",
}

EXPECTED_FAMILIES = {
    "B1", "B2", "B3", "B4", "B5",
    "M1", "M2", "M3", "M4", "M5",
}


class TestBenchmarkSamplesMatrix(unittest.TestCase):
    """Verify matrix structure, symmetry, materialized sandboxes, and safe sinks."""

    def test_manifest_structure_and_symmetry(self):
        """Test manifest total counts, symmetry across base projects, and family quotas."""
        self.assertTrue(MANIFEST_PATH.exists(), f"Manifest file missing: {MANIFEST_PATH}")
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

        samples = data.get("samples", [])
        self.assertEqual(len(samples), 100, "Manifest must contain exactly 100 samples")

        benign_samples = [s for s in samples if s["label"] == "benign"]
        malicious_samples = [s for s in samples if s["label"] == "malicious"]
        self.assertEqual(len(benign_samples), 50, "Must have exactly 50 benign samples")
        self.assertEqual(len(malicious_samples), 50, "Must have exactly 50 malicious samples")

        # Verify base project distribution (25 per base project)
        project_counts = {}
        for s in samples:
            project_counts[s["base_project"]] = project_counts.get(s["base_project"], 0) + 1

        self.assertEqual(set(project_counts.keys()), EXPECTED_BASE_PROJECTS)
        for proj, count in project_counts.items():
            self.assertEqual(count, 25, f"Base project {proj} must have exactly 25 samples, got {count}")

        # Verify family distribution (10 per family)
        family_counts = {}
        for s in samples:
            family_counts[s["family"]] = family_counts.get(s["family"], 0) + 1

        self.assertEqual(set(family_counts.keys()), EXPECTED_FAMILIES)
        for fam, count in family_counts.items():
            self.assertEqual(count, 10, f"Family {fam} must have exactly 10 samples, got {count}")

        # Verify exact cell-level quotas matching PROJECT_ALLOCATION
        for fam, alloc in PROJECT_ALLOCATION.items():
            for proj, expected_count in alloc.items():
                actual = sum(1 for s in samples if s["family"] == fam and s["base_project"] == proj)
                self.assertEqual(
                    actual,
                    expected_count,
                    f"Cell ({fam}, {proj}) expected {expected_count} samples, got {actual}",
                )

    def test_materialized_sandboxes_exist(self):
        """Test that all 100 sandboxes exist and contain required files and data assets."""
        self.assertTrue(BENCHMARK_ROOT.exists(), f"Benchmark root missing: {BENCHMARK_ROOT}")
        self.assertTrue(MANIFEST_PATH.exists(), f"Manifest missing: {MANIFEST_PATH}")

        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        samples = data.get("samples", [])

        required_files = {"train.py", "dataset.py", "model.py", "benchmark_variant.py", "sample.json"}

        for s in samples:
            sandbox_dir = BENCHMARK_ROOT / s["base_project"] / s["sample_id"]
            self.assertTrue(sandbox_dir.is_dir(), f"Sandbox directory missing: {sandbox_dir}")

            # Verify required files
            for req_file in required_files:
                file_path = sandbox_dir / req_file
                self.assertTrue(file_path.is_file(), f"Expected file {req_file} missing in {sandbox_dir}")

            # Verify micro-dataset data/ directory exists and has files
            data_dir = sandbox_dir / "data"
            self.assertTrue(data_dir.is_dir(), f"Expected data/ directory missing in {sandbox_dir}")
            data_contents = list(data_dir.iterdir())
            self.assertGreater(len(data_contents), 0, f"Data directory {data_dir} must not be empty")

    def test_sample_json_finding_truth(self):
        """Verify that sample.json in each sandbox has finding-level ground truth."""
        self.assertTrue(MANIFEST_PATH.exists(), f"Manifest missing: {MANIFEST_PATH}")
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        samples = data.get("samples", [])

        for s in samples:
            sample_json_path = BENCHMARK_ROOT / s["base_project"] / s["sample_id"] / "sample.json"
            self.assertTrue(sample_json_path.is_file(), f"sample.json missing: {sample_json_path}")
            meta = json.loads(sample_json_path.read_text(encoding="utf-8"))

            for key in ("sample_id", "label", "base_project", "family", "primary_attack_finding", "findings_manifest"):
                self.assertIn(key, meta, f"Key '{key}' missing from {sample_json_path}")

            self.assertIsInstance(meta["findings_manifest"], list)
            if meta["label"] == "malicious":
                paf = meta["primary_attack_finding"]
                self.assertIsNotNone(paf, f"Malicious sample {meta['sample_id']} has null primary_attack_finding")
                self.assertEqual(paf.get("file"), "benchmark_variant.py")
                self.assertTrue(bool(paf.get("rule_id")), f"rule_id missing in primary_attack_finding: {paf}")
                self.assertIsInstance(paf.get("line"), int, f"line must be an integer: {paf}")
                self.assertGreater(paf.get("line"), 0, f"line must be positive: {paf}")
            else:
                self.assertIsNone(
                    meta["primary_attack_finding"],
                    f"Benign sample {meta['sample_id']} must have null primary_attack_finding",
                )

    def test_variant_lifecycle_hook_and_compilation(self):
        """Verify each variant defines on_epoch_end and all sandbox Python files compile cleanly."""
        self.assertTrue(MANIFEST_PATH.exists(), f"Manifest missing: {MANIFEST_PATH}")
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        samples = data.get("samples", [])

        for s in samples:
            sandbox_dir = BENCHMARK_ROOT / s["base_project"] / s["sample_id"]
            variant_path = sandbox_dir / "benchmark_variant.py"
            self.assertTrue(variant_path.is_file(), f"Variant file missing: {variant_path}")

            variant_content = variant_path.read_text(encoding="utf-8")
            parsed_ast = ast.parse(variant_content, filename=str(variant_path))
            func_names = [node.name for node in ast.walk(parsed_ast) if isinstance(node, ast.FunctionDef)]
            self.assertIn(
                "on_epoch_end",
                func_names,
                f"Lifecycle hook on_epoch_end missing in AST of {variant_path}",
            )

            # Compile all python files in the sandbox
            for py_file in sandbox_dir.glob("**/*.py"):
                try:
                    py_compile.compile(str(py_file), doraise=True)
                except py_compile.PyCompileError as exc:
                    self.fail(f"Compilation failed for {py_file}: {exc}")

    def test_safe_sink_enforcement(self):
        """Verify no variant references ~/.bashrc or real external domains; only safe sinks used."""
        self.assertTrue(MANIFEST_PATH.exists(), f"Manifest missing: {MANIFEST_PATH}")
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        samples = data.get("samples", [])

        forbidden_home_bashrc = re.compile(r"""(?:~/(?:\.bashrc|\.bash_profile|\.zshrc|\.profile)|\.home\(\).*(?:bashrc|profile|zshrc))""")
        domain_pattern = re.compile(r"""["']([a-zA-Z0-9.-]+\.(?:invalid|com|org|net|cn))["']""")

        for s in samples:
            sandbox_dir = BENCHMARK_ROOT / s["base_project"] / s["sample_id"]
            for py_file in sandbox_dir.glob("**/*.py"):
                content = py_file.read_text(encoding="utf-8")

                # Verify home directory shell config is never directly targeted
                self.assertFalse(
                    forbidden_home_bashrc.search(content),
                    f"Dangerous home shell configuration reference found in {py_file}",
                )

                # Verify all network targets use RFC 2606 .invalid
                for domain in domain_pattern.findall(content):
                    self.assertTrue(
                        domain.endswith(".invalid"),
                        f"Non-safe network sink domain '{domain}' found in {py_file}",
                    )


if __name__ == "__main__":
    unittest.main()
