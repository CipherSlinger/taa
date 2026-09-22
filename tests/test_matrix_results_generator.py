"""Unit tests for the benchmark matrix results generator and HTML updater."""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import models.audit.tools.generate_matrix_results as gmr

# The matrix generator's counts are hand-authored (MODELS_SPEC), not measured.
# It used to derive `engine` and `rule_set_version` from the audit mode name, so
# an unstated engine fell back to "semgrep" for the static-llm track; the
# resulting summary.json has the same shape and location as a real evaluator run
# and was cited as a Semgrep measurement. The rule IDs cannot stand in for the
# engine either - the Semgrep rules reuse the baseline's rule_family IDs, so
# matched_rules does not say which arm produced a row.
DECLARATIONS = {
    "pure-llm": {"engine": "none", "rule_set_version": "n/a"},
    "pure-llm-checklist": {"engine": "none", "rule_set_version": "checklist-rules-v1"},
    "static-llm": {"engine": "regex", "rule_set_version": "regex-rules-13"},
}


class TestMatrixProvenance(unittest.TestCase):
    """The matrix must say what produced its numbers, and not imply an engine nobody named."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.results_dir = Path(self.temp_dir) / "matrix"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_the_declaration_is_required(self):
        """Omitting it must raise, not silently fall back to engine="semgrep"."""
        with self.assertRaises(TypeError):
            gmr.generate_matrix(results_dir=self.results_dir, dry_run=True)

    def test_engine_and_rule_set_come_from_the_declaration(self):
        runs, _ = gmr.generate_matrix(DECLARATIONS, results_dir=self.results_dir, dry_run=True)
        by_mode = {r["audit_mode"]: r for r in runs}
        self.assertEqual(by_mode["static-llm"]["engine"], "regex")
        self.assertEqual(by_mode["static-llm"]["rule_set_version"], "regex-rules-13")
        self.assertEqual(by_mode["pure-llm"]["engine"], "none")

    def test_a_declaration_missing_a_track_is_rejected(self):
        partial = {"static-llm": {"engine": "regex", "rule_set_version": "regex-rules-13"}}
        with self.assertRaises(ValueError):
            gmr.generate_matrix(partial, results_dir=self.results_dir, dry_run=True)

    def test_every_row_is_marked_hand_authored(self):
        runs, _ = gmr.generate_matrix(DECLARATIONS, results_dir=self.results_dir, dry_run=False)
        for run in runs:
            self.assertEqual(run["provenance"], "hand-authored-spec")

        master = json.loads(
            (self.results_dir / "benchmark-matrix-summary.json").read_text(encoding="utf-8")
        )
        self.assertEqual(master["provenance"], "hand-authored-spec")
        for run in master["runs"]:
            self.assertEqual(run["provenance"], "hand-authored-spec")

        # The per-run artifact is what gets cited, so it carries the mark too.
        per_run = self.results_dir / "static-llm" / "qwen2_5-coder-3b" / "summary.json"
        self.assertEqual(
            json.loads(per_run.read_text(encoding="utf-8"))["provenance"], "hand-authored-spec"
        )

    def test_cli_refuses_to_run_without_a_declaration(self):
        parser = gmr.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([])
        args = parser.parse_args(["--track", "static-llm:regex:regex-rules-13"])
        self.assertEqual(args.track, ["static-llm:regex:regex-rules-13"])


class TestMatrixResultsGenerator(unittest.TestCase):
    """Test suite for generate_matrix_results CLI, matrix calculations, and HTML updater."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.results_dir = Path(self.temp_dir) / "matrix"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cli_argument_parsing(self):
        """Test argument parser supports --dry-run, --update-html, and directory options."""
        parser = gmr.build_parser()
        args = parser.parse_args(["--dry-run", "--track", "pure-llm:none:n/a"])
        self.assertTrue(args.dry_run)
        self.assertFalse(args.update_html)

        args = parser.parse_args(
            ["--update-html", "--results-dir", str(self.results_dir), "--track", "pure-llm:none:n/a"]
        )
        self.assertTrue(args.update_html)
        self.assertEqual(args.results_dir, str(self.results_dir))

    def test_models_spec_has_all_six_models_and_three_tracks(self):
        """Verify MODELS_SPEC defines 6 models each with pure_llm, pure_llm_checklist, static_llm."""
        self.assertEqual(len(gmr.MODELS_SPEC), 6, "Must define exactly 6 models")
        expected_models = {
            "qwen2.5-coder:0.5b",
            "qwen2.5-coder:1.5b",
            "qwen2.5-coder:3b",
            "qwen2.5-coder:7b",
            "qwen3:8b",
            "qwen3:14b",
        }
        actual_models = {spec["model"] for spec in gmr.MODELS_SPEC}
        self.assertEqual(actual_models, expected_models)

        for spec in gmr.MODELS_SPEC:
            for track_key in ("pure_llm", "pure_llm_checklist", "static_llm"):
                self.assertIn(track_key, spec, f"Track {track_key} missing from model {spec['model']}")
                data = spec[track_key]
                total = data["tp"] + data["fp"] + data["tn"] + data["fn"]
                self.assertEqual(total, 100, f"Total samples for {spec['model']} {track_key} must be 100")
                self.assertIn("attribution_count", data)
                self.assertGreaterEqual(data["attribution_count"], 0)
                self.assertLessEqual(data["attribution_count"], data["tp"])

    def test_generate_matrix_runs_and_writes_files(self):
        """Verify generate_matrix writes all json, csv, and md report files with 95% CIs."""
        runs, summary = gmr.generate_matrix(DECLARATIONS, results_dir=self.results_dir, dry_run=False)
        self.assertEqual(len(runs), 18, "Must generate 6 models * 3 tracks = 18 runs")

        # Check master json
        json_path = self.results_dir / "benchmark-matrix-summary.json"
        self.assertTrue(json_path.exists())
        data = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["runs"]), 18)
        self.assertIn("modes", data)
        self.assertEqual(data["modes"], ["pure-llm", "pure-llm-checklist", "static-llm"])

        # Check master csv
        csv_path = self.results_dir / "benchmark-matrix-summary.csv"
        self.assertTrue(csv_path.exists())
        csv_content = csv_path.read_text(encoding="utf-8")
        self.assertIn("attribution_precision", csv_content)
        self.assertIn("pure-llm-checklist", csv_content)

        # Check master markdown
        md_path = self.results_dir / "benchmark-matrix-report.md"
        self.assertTrue(md_path.exists())
        md_content = md_path.read_text(encoding="utf-8")
        self.assertIn("18 组对照", md_content)
        self.assertIn("Attribution Precision", md_content)

        # Verify run-level artifacts
        for run in runs:
            run_mode = run["audit_mode"]
            run_slug = run["model_specs"]["slug"]
            run_dir = self.results_dir / run_mode / run_slug
            self.assertTrue((run_dir / "summary.json").exists())
            self.assertTrue((run_dir / "confusion-matrix.json").exists())

            # Check CI presence
            metrics = run["metrics"]
            self.assertIn("ci_95", metrics)
            ci = metrics["ci_95"]
            for key in ("accuracy", "recall", "fpr", "f1", "attribution_precision"):
                self.assertIn(key, ci)
                self.assertLessEqual(ci[key]["ci_lower"], ci[key]["ci_upper"])

    def test_update_html_report(self):
        """Verify update_html replaces Section 5 content with the 3-track 18-run table."""
        # Create a mock HTML file with Section 5 markup
        mock_html = Path(self.temp_dir) / "test_report.html"
        original_content = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<div id="before">Before Section</div>
      <section class="section" id="benchmark-results">
        <h2>5. Benchmark 评测结果与实测分析 (6 模型 × 2 方案 对比矩阵)</h2>
        <div class="callout">old callout</div>
        <div class="matrix-table-wrap">
          <table class="matrix-table">
            <tbody>
              <tr><td>old row</td></tr>
            </tbody>
          </table>
        </div>
      </section>
<div id="after">After Section</div>
</body>
</html>"""
        mock_html.write_text(original_content, encoding="utf-8")

        runs, _ = gmr.generate_matrix(DECLARATIONS, results_dir=self.results_dir, dry_run=True)
        updated = gmr.update_html_report(mock_html, runs)
        self.assertTrue(updated)

        new_content = mock_html.read_text(encoding="utf-8")
        self.assertIn("Before Section", new_content)
        self.assertIn("After Section", new_content)
        self.assertIn("6 模型 × 3 方案 三轨正交对比矩阵", new_content)
        self.assertIn("pure-llm-checklist", new_content)
        self.assertIn("qwen2.5-coder:1.5b", new_content)
        self.assertIn("攻击归因率", new_content)
        # Verify removed columns are absent from the core comparison matrix table header
        self.assertNotIn("<th>算力旁路率 (Bypass)</th>", new_content)
        self.assertNotIn("<th>核心特征与工程诊断</th>", new_content)
        # Verify quantitative dashboard section is removed
        self.assertNotIn("三轨全矩阵量化收益看板", new_content)


if __name__ == "__main__":
    unittest.main()
