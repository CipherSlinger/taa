# tests/test_audit_eval_corpus_list.py
"""A corpus has to be introducible as data, not as code.

The evaluator derives its sample list from FAMILY_SPECS and PROJECT_ALLOCATION,
expands it into ids like B1-01, and regenerates that list on every run - the
manifest it writes is output, never input. A held-out corpus therefore has no
way in, and the only alternatives are editing the family tables or hand-placing
files whose ids the evaluator will never look for.

The list is also where a corpus can be wrong in ways nothing downstream will
report. Downstream reads `label == "malicious"` and treats everything else as
benign, and it indexes rows by sample id, so a mistyped label or a repeated id
does not fail - it moves samples between the two columns the comparison is
decided on.
"""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from models.audit.tools import audit_benchmark_eval as ev


def entry(**overrides) -> dict:
    base = {
        "sample_id": "h-01",
        "base_project": "pypi-requests",
        "family": "benign-pypi",
        "label": "benign",
        "relative_path": "pypi-requests/h-01",
    }
    base.update(overrides)
    return base


def write_corpus(path: Path, entries) -> Path:
    path.write_text(json.dumps({"samples": entries}), encoding="utf-8")
    return path


class TestCorpusListLoading(unittest.TestCase):
    def _load(self, entries):
        with tempfile.TemporaryDirectory() as td:
            path = write_corpus(Path(td) / "corpus.json", entries)
            return ev.load_corpus_list(path)

    def test_a_corpus_list_supplies_the_declared_samples(self):
        samples = self._load([
            entry(),
            entry(sample_id="h-02", base_project="dd-packages", family="malicious-datadog",
                  label="malicious", relative_path="dd-packages/h-02"),
        ])
        self.assertEqual([s.sample_id for s in samples], ["h-01", "h-02"])
        self.assertEqual([s.label for s in samples], ["benign", "malicious"])
        self.assertEqual([s.family for s in samples], ["benign-pypi", "malicious-datadog"])
        self.assertEqual(samples[1].relative_path, "dd-packages/h-02")

    def test_the_list_order_is_the_run_order(self):
        """The list is the run plan, so reordering it must not be undone here."""
        samples = self._load([entry(sample_id="h-03"), entry(sample_id="h-01")])
        self.assertEqual([s.sample_id for s in samples], ["h-03", "h-01"])

    def test_metadata_that_does_not_apply_is_left_unset(self):
        """A third-party file has no family spec, and inventing one would be a claim.

        These fields are descriptive - nothing branches on them - but a plausible
        value reads as a statement about how the sample was constructed, and the
        holdout's whole point is that we did not construct it.
        """
        (sample,) = self._load([entry()])
        self.assertEqual(sample.transformation, "external")
        self.assertEqual(sample.expected_rules, ())
        self.assertEqual(sample.expected_severity, "UNSPECIFIED")
        self.assertEqual(sample.expected_final, "UNSPECIFIED")
        self.assertEqual(sample.trap_type, "none")
        self.assertEqual(sample.notes, "")

    def test_declared_metadata_is_carried_through(self):
        (sample,) = self._load([entry(
            transformation="window_extraction",
            expected_rules=["CMD_001", "PER_001"],
            expected_severity="HIGH",
            expected_final="MALICIOUS",
            trap_type="attack_chain",
            notes="semgrep-rules ruleid window",
        )])
        self.assertEqual(sample.transformation, "window_extraction")
        self.assertEqual(sample.expected_rules, ("CMD_001", "PER_001"))
        self.assertEqual(sample.expected_severity, "HIGH")
        self.assertEqual(sample.expected_final, "MALICIOUS")
        self.assertEqual(sample.trap_type, "attack_chain")
        self.assertEqual(sample.notes, "semgrep-rules ruleid window")

    def test_a_label_the_metrics_do_not_recognise_is_rejected(self):
        """Anything but exactly 'malicious' is scored as benign.

        A mistyped label is therefore not an error the run reports - it moves a
        malicious sample into the benign column, so recall loses a sample and the
        false positive rate gains one. Both are the numbers being compared.
        """
        for bad in ("malicous", "MALICIOUS", "Malicious", "malware", "benign ", "unknown"):
            with self.subTest(label=bad):
                with self.assertRaises(ValueError) as ctx:
                    self._load([entry(label=bad)])
                self.assertIn("label", str(ctx.exception))

    def test_a_repeated_sample_id_is_rejected(self):
        """Rows are indexed by sample id, so a repeat silently drops a sample.

        Pairing the two arms is done on dicts keyed by sample id: two entries
        sharing an id collapse into one pair, and which of the two survives is
        decided by dict assignment rather than by anything about the corpus.
        """
        with self.assertRaises(ValueError) as ctx:
            self._load([entry(), entry(base_project="other", relative_path="other/h-01")])
        self.assertIn("h-01", str(ctx.exception))

    def test_each_required_field_is_required(self):
        for field in ("sample_id", "base_project", "family", "label", "relative_path"):
            with self.subTest(field=field):
                bad = entry()
                del bad[field]
                with self.assertRaises(ValueError) as ctx:
                    self._load([bad])
                self.assertIn(field, str(ctx.exception))

    def test_an_empty_required_field_is_rejected(self):
        with self.assertRaises(ValueError):
            self._load([entry(relative_path="")])

    def test_a_misspelled_field_is_rejected(self):
        """Silently ignoring an unknown key would drop whatever it meant to set."""
        with self.assertRaises(ValueError) as ctx:
            self._load([entry(lable="malicious")])
        self.assertIn("lable", str(ctx.exception))

    def test_a_file_that_is_not_a_corpus_list_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "corpus.json"
            path.write_text(json.dumps([entry()]), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                ev.load_corpus_list(path)
            self.assertIn("samples", str(ctx.exception))


class TestTheSyntheticCorpusStillLoads(unittest.TestCase):
    """The declared-list path must not disturb the corpus the evaluator was built on."""

    def test_without_a_corpus_list_the_family_specs_still_expand(self):
        samples = ev.make_sample_specs(Path("/nonexistent"))
        self.assertEqual(len(samples), 100)
        self.assertEqual(samples[0].sample_id, "B1-01")


class TestTheSummaryNamesTheCorpusItMeasured(unittest.TestCase):
    """A run stamps its own name into the bundle it produces.

    The summary identifies the benchmark that was measured, so a held-out corpus
    reported under the synthetic benchmark's name would misdescribe its own
    provenance in the artifact that carries the conclusion.
    """

    def _summary(self, **extra):
        return ev.build_summary_report(
            results=[],
            benchmark_root=Path("/tmp/corpus"),
            audit_mode="static-llm",
            policy="assist",
            llm_backend="ollama",
            llm_model="qwen2.5-coder:3b",
            eval_duration_sec=1.0,
            notes="",
            engine="semgrep",
            **extra,
        )

    def test_a_corpus_run_is_not_stamped_as_the_synthetic_benchmark(self):
        summary = self._summary(benchmark_name="corpus-list",
                                corpus_list="/tmp/corpus/corpus.json")
        self.assertTrue(summary["run_id"].startswith("corpus-list-"),
                        f"run_id misnames the corpus: {summary['run_id']}")
        self.assertEqual(summary["corpus_list"], "/tmp/corpus/corpus.json")
        self.assertIsNone(summary["benchmark_version"],
                          "the synthetic benchmark's version is not this corpus's version")

    def test_the_synthetic_benchmark_keeps_its_name(self):
        summary = self._summary()
        self.assertTrue(summary["run_id"].startswith("audit-100-"))
        self.assertIsNone(summary["corpus_list"])
        self.assertEqual(summary["benchmark_version"], ev.BENCHMARK_VERSION)


class TestTheDumpManifestFollowsTheCorpusList(unittest.TestCase):
    def _dump(self, root: Path, extra_argv) -> dict:
        out = root / "manifest.json"
        argv = [
            "audit_benchmark_eval.py",
            "--benchmark-root", str(root / "audit-holdout"),
            "--manifest-out", str(out),
            "--dump-manifest",
        ] + extra_argv
        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ev.main(), 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_the_manifest_describes_the_corpus_list(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            corpus = write_corpus(root / "corpus.json", [
                entry(),
                entry(sample_id="h-02", base_project="dd-packages", family="malicious-datadog",
                      label="malicious", relative_path="dd-packages/h-02"),
            ])
            manifest = self._dump(root, ["--corpus-list", str(corpus)])

        self.assertEqual({s["sample_id"] for s in manifest["samples"]}, {"h-01", "h-02"})
        self.assertEqual(manifest["totals"], {"samples": 2, "benign": 1, "malicious": 1})
        self.assertEqual(manifest["corpus_list"], str(corpus))
        self.assertNotIn("B1-01", {s["sample_id"] for s in manifest["samples"]})

    def test_the_manifest_without_a_corpus_list_is_unchanged(self):
        """The synthetic path is what every existing comparison was run on."""
        with tempfile.TemporaryDirectory() as td:
            manifest = self._dump(Path(td), [])
        self.assertEqual(manifest["benchmark_name"], "audit-100")
        self.assertEqual(len(manifest["samples"]), 100)
        self.assertNotIn("corpus_list", manifest)


if __name__ == "__main__":
    unittest.main()
