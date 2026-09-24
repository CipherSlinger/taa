# tests/test_gate_rescore.py
"""Gate numbers are derived from the assist run, and only when the derivation replays.

Four things have to hold, and each has a test here that fails if it stops holding:

* the `llm_enabled=False` trap. With the model disabled there are no FileSummary
  objects, so `file_reports[].risk_level` is a static-scan placeholder
  (`infer_risk_level`). Read as a file-level risk it turns a static HIGH into a
  detected attack chain and reports CRITICAL where the run reported MEDIUM.
* the invariant refusal. `compute_conclusion` reads `scan_complete` /
  `parser_errors` / `timed_out` with defaults, so the moment a producer writes
  them into `statistics` the fail-closed branch becomes reachable and re-scoring
  silently stops being exact - in the loosening direction.
* branch coverage the probe could not provide. Every sample in the 12-sample
  probe was either a zero-finding bypass or CRITICAL, so no sample exercised a
  branch where assist and gate disagree. A no-LLM sample with a single MEDIUM
  finding is exactly that case, and it is the reason the derivation is not just
  a restatement of the assist label.
* `--validate` reporting a mismatch as a failure, so a run that does not replay
  cannot be exported as gate.
"""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from models.audit.tools import audit_benchmark_eval as ev
from models.audit.tools import gate_rescore as gr
from models.examples.code_security_analyzer import FileSummary, compute_conclusion


def counters(total_findings=0, high=0, medium=0, malicious=0, suspicious=0,
             benign=0, uncertain=0):
    return {
        "total_findings": total_findings, "high": high, "medium": medium,
        "malicious": malicious, "suspicious": suspicious, "benign": benign,
        "uncertain": uncertain,
    }


def finding(rule_id="CMD_001", severity="MEDIUM", llm_verdict=None, llm_reason=""):
    return {
        "file": "sample.py", "line": 4, "rule_id": rule_id, "severity": severity,
        "category": "命令执行", "description": "d", "code_snippet": "s",
        "llm_verdict": llm_verdict, "llm_reason": llm_reason, "engine": "regex",
    }


def file_report(risk_level="HIGH", *, chained=True, exfil=True, findings=(),
                high_count=0, medium_count=1, file="sample.py"):
    findings = list(findings)
    return {
        "file": file, "file_path": f"/corpus/{file}", "findings_count": len(findings),
        "high_count": high_count, "medium_count": medium_count, "risk_level": risk_level,
        "summary": "存在SQL注入漏洞", "has_exfiltration_pattern": exfil,
        "chained": chained, "findings": findings,
    }


def audit_report(stats, *, file_reports=(), llm_enabled=True, policy="assist",
                 recommendation="无需修复"):
    """A report shaped like the static-llm producer's, without a conclusion yet."""
    return {
        "report_id": "audit-fixture",
        "audit_time": "2026-09-24T00:00:00Z",
        "target": {"directory": "/corpus", "files_scanned": 1, "total_lines": 20,
                   "files_with_findings": len(file_reports)},
        "conclusion": {},
        "statistics": dict(stats),
        "file_reports": list(file_reports),
        "scan_metadata": {
            "scanner_version": "1.0.0", "rules_count": 13, "llm_model": "qwen2.5-coder:3b",
            "llm_enabled": llm_enabled, "llm_seed": 42, "policy": policy,
            "scan_duration_ms": 1,
        },
    }


def concluded(report, policy="assist"):
    """The same report with the conclusion this policy produces, for a replayable fixture."""
    report = copy.deepcopy(report)
    conclusion = gr.rescore(report, policy)
    conclusion["recommendation"] = "无需修复"
    report["conclusion"] = conclusion
    return report


def row(sample_id, label, *, predicted_label, predicted_verdict, predicted_risk, blocked,
        reason, llm_state="ok", error_type="ok", attributed=False, total_findings=1,
        sample_path="/corpus", matched_rules=("CMD_001",), bypass=False):
    """A sample-results row carrying every field the bundle writers read.

    `reason` is required rather than defaulted: the producer writes the
    conclusion's summary there (`audit_benchmark_eval.py:1065`), and a fixture
    that invents its own value is the kind of mismatch the tool exists to catch.
    """
    return {
        "sample_id": sample_id, "base_project": "codeql", "family": "CODEQL-NEARMISS",
        "label": label, "predicted_label": predicted_label,
        "predicted_verdict": predicted_verdict, "predicted_risk": predicted_risk,
        "blocked": blocked, "audit_mode": "static-llm", "bypass": bypass,
        "scan_complete": True, "scan_timed_out": False, "scan_parser_errors": 0,
        "scan_error": None, "slice_error_count": 0, "ast_error_count": 0, "cpg_error": None,
        "incomplete": False, "scan_duration_ms": 1, "matched_rules": list(matched_rules),
        "reason": reason, "error_type": error_type, "llm_state": llm_state,
        "llm_invoked": not bypass, "llm_duration_sec": 1.0, "expected_rules": [],
        "expected_severity": "UNSPECIFIED", "expected_final": "UNSPECIFIED",
        "trap_type": "none", "sample_path": sample_path,
        "report_path": f"/runs/{sample_id}/audit_report.json",
        "files_scanned": 1, "total_findings": total_findings, "llm_available": llm_state == "ok",
        "fail_closed": False, "started_at": "2026-09-24T00:00:00Z",
        "finished_at": "2026-09-24T00:01:00Z", "attributed": attributed,
    }


def write_run(root: Path, run_name: str, samples, *, policy="assist",
              audit_mode="static-llm") -> Path:
    """A run directory shaped like the ones the matrix emits."""
    run_dir = Path(root) / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for sample in samples:
        sample_dir = run_dir / sample["sample_id"]
        sample_dir.mkdir(parents=True, exist_ok=True)
        ev.write_json(sample_dir / "audit_report.json", sample["report"])
        rows.append(sample["row"])
    summary = ev.build_summary_report(
        results=rows, benchmark_root=Path("/corpus"), audit_mode=audit_mode, policy=policy,
        llm_backend="ollama", llm_model="qwen2.5-coder:3b", eval_duration_sec=1.5,
        notes="fixture", engine="regex", llm_seed=42,
    )
    ev.write_results_bundle(run_dir, rows, summary)
    return run_dir


def no_llm_medium_sample(sample_id="s-med", label="benign", *, sample_path="/corpus"):
    """One MEDIUM finding, model disabled: assist passes, gate blocks.

    This is the branch the 12-sample probe never reached - and the reason
    re-scoring is a decision rather than a restatement of the assist label. The
    row is what the producer writes for an assist run: `static_only`, passing,
    so `predicted_verdict` is BENIGN (`infer_predicted_verdict` short-circuits on
    `passed`) and the error type is the static-only one.
    """
    report = audit_report(
        counters(total_findings=1, medium=1),
        file_reports=[file_report(risk_level="MEDIUM", chained=False, exfil=False,
                                  medium_count=1, findings=[finding()])],
        llm_enabled=False,
    )
    report = concluded(report, "assist")
    return {
        "sample_id": sample_id,
        "report": report,
        "row": row(sample_id, label, predicted_label="benign", predicted_verdict="BENIGN",
                   predicted_risk="MEDIUM", blocked=False, llm_state="static_only",
                   error_type="static_only" if label != "malicious" else "false_negative",
                   reason=report["conclusion"]["summary"], sample_path=sample_path,
                   total_findings=1),
    }


class TestReconstruct(unittest.TestCase):
    def test_invariant_refusal_when_statistics_carry_scan_state(self):
        for key, value in (("scan_complete", True), ("parser_errors", 0), ("timed_out", False)):
            with self.subTest(key=key):
                report = audit_report(counters())
                report["statistics"][key] = value
                with self.assertRaises(gr.RescoreInvariantError) as ctx:
                    gr.reconstruct_report(report)
                message = str(ctx.exception)
                self.assertIn("unsound", message)
                self.assertIn("LOOSENING", message)

    def test_invariant_refusal_is_also_a_rescore_error(self):
        # So a validation pass reports it per sample instead of crashing the run.
        self.assertTrue(issubclass(gr.RescoreInvariantError, gr.RescoreError))

    def test_missing_counter_is_refused(self):
        report = audit_report(counters())
        del report["statistics"]["malicious"]
        with self.assertRaises(gr.RescoreError):
            gr.reconstruct_report(report)

    def test_no_model_means_no_file_summaries(self):
        report = audit_report(
            counters(total_findings=1, high=1),
            file_reports=[file_report(risk_level="HIGH", findings=[finding(severity="HIGH")])],
            llm_enabled=False,
        )
        stats, file_summaries = gr.reconstruct_report(report)
        self.assertEqual(file_summaries, {})
        # The trap, stated as the failure it would cause: a static-only HIGH read
        # as a file-level risk makes the chain check fire and reports CRITICAL.
        mistaken = {
            "/corpus/sample.py": FileSummary(risk_level="HIGH", summary="", chained=False,
                                             exfiltration=False),
        }
        self.assertEqual(compute_conclusion(stats, mistaken, "gate")["risk_level"], "CRITICAL")
        self.assertNotEqual(compute_conclusion(stats, file_summaries, "gate")["risk_level"],
                            "CRITICAL")

    def test_model_enabled_makes_a_high_file_risk_a_chain(self):
        report = audit_report(
            counters(total_findings=1, high=1),
            file_reports=[file_report(risk_level="HIGH", findings=[finding(severity="HIGH")])],
            llm_enabled=True,
        )
        _, file_summaries = gr.reconstruct_report(report)
        self.assertIn("/corpus/sample.py", file_summaries)
        conclusion = gr.rescore(report, "gate")
        self.assertEqual(conclusion["risk_level"], "CRITICAL")
        self.assertEqual(conclusion["verdict"], "MALICIOUS")

    def test_real_probe_sample_replays_from_frozen_values(self):
        """Golden values taken from the probe's own dd-0005 artifact.

        Hand-written expectations rather than a value this module computed, so the
        test fails if either the production decision function or the
        reconstruction moves.
        """
        report = audit_report(
            counters(total_findings=1, medium=1, malicious=1),
            file_reports=[file_report(
                risk_level="HIGH", chained=True, exfil=True, medium_count=1,
                findings=[finding(rule_id="DYN_001", severity="MEDIUM",
                                  llm_verdict="MALICIOUS", llm_reason="动态执行")],
            )],
            llm_enabled=True,
        )
        report["conclusion"] = {
            "passed": False, "verdict": "MALICIOUS", "reason": "Confirmed attack finding present",
            "risk_level": "CRITICAL",
            "summary": "审计结论: 发现 1 处恶意代码，检测到文件级复合攻击链。存在数据泄露风险，建议阻断导入",
            "recommendation": "建议修复: DYN_001: 移除 eval/exec",
        }
        for policy in ("assist", "gate"):
            with self.subTest(policy=policy):
                conclusion = gr.rescore(report, policy)
                self.assertEqual(conclusion["passed"], False)
                self.assertEqual(conclusion["verdict"], "MALICIOUS")
                self.assertEqual(conclusion["risk_level"], "CRITICAL")
                self.assertEqual(conclusion["reason"], report["conclusion"]["reason"])
                self.assertEqual(conclusion["summary"], report["conclusion"]["summary"])


class TestBranchCoverage(unittest.TestCase):
    def test_no_llm_medium_finding_assist_passes_and_gate_fails(self):
        sample = no_llm_medium_sample()
        report = sample["report"]

        assist = gr.rescore(report, "assist")
        gate = gr.rescore(report, "gate")
        self.assertTrue(assist["passed"])
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["verdict"], "SUSPICIOUS")
        self.assertEqual(gate["risk_level"], "MEDIUM")

        # The label the criterion reads flips with it, which is the whole point:
        # the assist label is not the gate label, and 12/12 probe samples could
        # not tell the two apart.
        derived = gr.derive_row(sample["row"], report, "gate")
        self.assertEqual(sample["row"]["predicted_label"], "benign")
        self.assertEqual(derived["predicted_label"], "malicious")
        self.assertTrue(derived["blocked"])
        # The static-only error type is overridden by the confusion, in the order
        # the eval applies them (`audit_benchmark_eval.py:1029-1042`).
        self.assertEqual(derived["error_type"], "false_positive")
        self.assertEqual(sample["row"]["error_type"], "static_only")

    def test_derived_row_is_refused_when_a_reproduced_field_disagrees(self):
        sample = no_llm_medium_sample()
        sample["row"]["predicted_label"] = "malicious"  # claims a block it never had
        with self.assertRaises(gr.RescoreError) as ctx:
            gr.derive_row(sample["row"], sample["report"], "assist")
        self.assertIn("predicted_label", str(ctx.exception))

    def test_report_rewrite_keeps_the_recommendation_verbatim(self):
        sample = no_llm_medium_sample()
        report = sample["report"]
        report["conclusion"]["recommendation"] = "建议修复: CMD_001: 移除子进程调用"
        derived = gr.derive_report(report, "gate")
        self.assertEqual(derived["conclusion"]["recommendation"],
                         report["conclusion"]["recommendation"])
        self.assertEqual(derived["scan_metadata"]["policy"], "gate")
        self.assertEqual(report["scan_metadata"]["policy"], "assist")  # source untouched


class TestValidate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "base"

    def tearDown(self):
        self.tmp.cleanup()

    def test_faithful_run_replays_and_reports_no_mismatch(self):
        write_run(self.root, "regex-run1", [no_llm_medium_sample()])
        validation = gr.validate_base_dir(self.root)
        self.assertEqual(validation["samples"], 1)
        self.assertEqual(validation["matches"], 1)
        self.assertEqual(validation["mismatches"], 0)
        self.assertEqual(gr.main(["--validate", "--base-dir", str(self.root)]), 0)

    def test_tampered_conclusion_is_reported_as_a_failure(self):
        run_dir = write_run(self.root, "regex-run1", [no_llm_medium_sample()])
        target = run_dir / "s-med" / "audit_report.json"
        report = json.loads(target.read_text(encoding="utf-8"))
        report["conclusion"]["passed"] = not report["conclusion"]["passed"]
        ev.write_json(target, report)

        validation = gr.validate_run(run_dir)
        self.assertEqual(validation["matches"], 0)
        self.assertEqual(validation["mismatches"], 1)
        self.assertIn("passed", validation["mismatch_details"][0]["differences"])
        self.assertEqual(gr.main(["--validate", "--base-dir", str(self.root)]), 1)

    def test_validate_writes_nothing(self):
        run_dir = write_run(self.root, "regex-run1", [no_llm_medium_sample()])
        before = {path: path.read_bytes() for path in sorted(run_dir.rglob("*")) if path.is_file()}
        gr.main(["--validate", "--base-dir", str(self.root)])
        after = {path: path.read_bytes() for path in sorted(run_dir.rglob("*")) if path.is_file()}
        self.assertEqual(sorted(before), sorted(after))
        for path, payload in before.items():
            self.assertEqual(payload, after[path])

    def test_non_static_llm_run_is_refused_by_name(self):
        run_dir = write_run(self.root, "regex-run1", [no_llm_medium_sample()],
                            audit_mode="pure-llm")
        with self.assertRaises(gr.RescoreError) as ctx:
            gr.validate_run(run_dir)
        self.assertIn("static-llm", str(ctx.exception))


class TestMaterialise(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.base = self.root / "base"
        self.out = self.root / "gate"
        # A corpus the samples' metadata can resolve against: a sample the gate
        # newly blocks has its attribution re-checked, which reads sample.json.
        self.corpus = self.root / "corpus"
        for sample_id in ("s-flip", "s-steady"):
            sample_dir = self.corpus / sample_id
            sample_dir.mkdir(parents=True)
            ev.write_json(sample_dir / "sample.json", {
                "primary_attack_finding": {"file": "sample.py", "rule_id": "CMD_001"},
            })

    def tearDown(self):
        self.tmp.cleanup()

    def flipped(self, *, sample_path=None):
        """A malicious sample the gate newly blocks: assist passes, gate does not."""
        return no_llm_medium_sample(
            "s-flip", label="malicious",
            sample_path=sample_path or str(self.corpus / "s-flip"),
        )

    def steady(self):
        """A malicious sample both policies block, so nothing about it should move."""
        report = audit_report(
            counters(total_findings=1, medium=1, malicious=1),
            file_reports=[file_report(risk_level="HIGH", chained=True, exfil=True,
                                      findings=[finding(llm_verdict="MALICIOUS")])],
            llm_enabled=True,
        )
        report = concluded(report, "assist")
        return {
            "sample_id": "s-steady",
            "report": report,
            "row": row("s-steady", "malicious", predicted_label="malicious",
                       predicted_verdict="MALICIOUS", predicted_risk="CRITICAL", blocked=True,
                       reason=report["conclusion"]["summary"],
                       sample_path=str(self.corpus / "s-steady")),
        }

    def flipped_and_steady(self):
        """One sample the gate newly blocks, one it leaves alone."""
        return [self.flipped(), self.steady()]

    def test_materialise_writes_a_gate_bundle_and_provenance(self):
        write_run(self.base, "regex-run1", self.flipped_and_steady())
        source_summary = json.loads((self.base / "regex-run1" / "summary.json").read_text())

        provenance = gr.materialise(self.base, self.out)

        target = self.out / "regex-run1"
        for name in ("summary.json", "sample-results.jsonl", "confusion-matrix.json",
                     "sample-results.csv", "final-report.md"):
            self.assertTrue((target / name).exists(), name)

        summary = json.loads((target / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(set(summary), set(source_summary))
        self.assertEqual(summary["policy"], "gate")
        self.assertIn("gate derived by re-scoring", summary["notes"])

        rows = {json.loads(line)["sample_id"]: json.loads(line)
                for line in (target / "sample-results.jsonl").read_text().splitlines() if line}
        self.assertEqual(rows["s-flip"]["predicted_label"], "malicious")
        self.assertTrue(rows["s-flip"]["blocked"])
        self.assertEqual(rows["s-flip"]["error_type"], "static_only")
        self.assertEqual(rows["s-steady"]["predicted_label"], "malicious")
        self.assertTrue(rows["s-steady"]["blocked"])

        # The decision is recomputed against the same counts, not inherited.
        self.assertEqual(summary["counts"], ev.confusion_counts(list(rows.values())))
        self.assertEqual(json.loads((target / "confusion-matrix.json").read_text()),
                         summary["counts"])

        derived_report = json.loads(
            (target / "s-flip" / "audit_report.json").read_text(encoding="utf-8"))
        self.assertEqual(derived_report["scan_metadata"]["policy"], "gate")
        self.assertFalse(derived_report["conclusion"]["passed"])

        self.assertEqual(provenance["derived_policy"], "gate")
        self.assertEqual(provenance["invariant"]["result"], "pass")
        self.assertEqual(provenance["validation"]["matches"], 2)
        self.assertEqual(provenance["validation"]["mismatches"], 0)
        self.assertEqual(provenance["tool_sha256"], gr.tool_digest())
        self.assertIn("was NOT run", provenance["derivation"])

    def test_source_run_is_left_untouched(self):
        write_run(self.base, "regex-run1", self.flipped_and_steady())
        before = {path: path.read_bytes()
                  for path in sorted((self.base / "regex-run1").rglob("*")) if path.is_file()}
        gr.materialise(self.base, self.out)
        after = {path: path.read_bytes()
                 for path in sorted((self.base / "regex-run1").rglob("*")) if path.is_file()}
        self.assertEqual(sorted(before), sorted(after))
        for path, payload in before.items():
            self.assertEqual(payload, after[path])

    def test_materialise_refuses_when_a_run_does_not_replay(self):
        run_dir = write_run(self.base, "regex-run1", self.flipped_and_steady())
        target = run_dir / "s-steady" / "audit_report.json"
        report = json.loads(target.read_text(encoding="utf-8"))
        report["conclusion"]["risk_level"] = "NONE"
        ev.write_json(target, report)
        with self.assertRaises(gr.RescoreError) as ctx:
            gr.materialise(self.base, self.out)
        self.assertIn("refusing to derive gate", str(ctx.exception))
        self.assertFalse(self.out.exists())

    def test_materialise_refuses_a_source_run_already_under_gate(self):
        write_run(self.base, "regex-run1", [self.flipped()], policy="gate")
        with self.assertRaises(gr.RescoreError) as ctx:
            gr.materialise(self.base, self.out)
        self.assertIn("assist", str(ctx.exception))

    def test_materialise_refuses_a_run_outside_the_engine_compare_layout(self):
        """A run the criterion's report would skip must not be exported silently.

        `run-a` is not in the layout, so it is not a run at all and the base has
        none; exporting nothing while reporting success is the failure to avoid.
        """
        write_run(self.base, "regex-run1", [self.flipped()])
        for run_dir in self.base.iterdir():
            run_dir.rename(self.base / "run-a")
        with self.assertRaises(gr.RescoreError) as ctx:
            gr.materialise(self.base, self.out)
        self.assertIn("no run directories", str(ctx.exception))

    def test_validate_refuses_an_interrupted_run(self):
        """A layout-named run with no summary.json is an unfinished run, not an absent one.

        The first holdout matrix left exactly this shape, and reading it as "no run
        here" would report a clean pass over zero samples.
        """
        run_dir = write_run(self.base, "regex-run1", [self.flipped()])
        (run_dir / "summary.json").unlink()

        with self.assertRaises(gr.RescoreError) as ctx:
            gr.validate_base_dir(self.base)
        self.assertIn("summary.json", str(ctx.exception))
        self.assertEqual(gr.main(["--base-dir", str(self.base), "--validate"]), 2)

    def test_newly_blocked_sample_needs_its_metadata_to_recheck_attribution(self):
        write_run(self.base, "regex-run1", [self.flipped(sample_path="/does/not/exist")])
        with self.assertRaises(gr.RescoreError) as ctx:
            gr.materialise(self.base, self.out)
        self.assertIn("sample.json", str(ctx.exception))

    def test_newly_blocked_sample_rechecks_attribution_when_metadata_resolves(self):
        """A newly blocked sample must go through the eval's own attribution check.

        That the check is *run* is what the missing-metadata test above proves; this
        one pins what it returns. For the only sample class the gate newly blocks -
        a static-only run whose high/medium findings carry no verdict - the answer is
        False: `check_sample_attribution` reads the finding's `llm_verdict`, and the
        producer serializes an unreviewed finding's verdict as null
        (`"findings": [asdict(f) ...]`, code_security_analyzer.py:990), which the check
        coerces to the string "NONE" rather than the empty one it treats as unreviewed.
        So every sample the gate adds to the block set is unattributed, and gate's
        attribution_precision is lower than assist's by that construction, not by
        a modelling difference.
        """
        # setUp already wrote corpus/s-flip/sample.json naming the finding below.
        corpus = self.root / "corpus" / "s-flip"
        write_run(self.base, "regex-run1", [self.flipped(sample_path=str(corpus))])
        gr.materialise(self.base, self.out)
        rows = [json.loads(line) for line in
                (self.out / "regex-run1" / "sample-results.jsonl").read_text().splitlines() if line]
        self.assertTrue(rows[0]["blocked"])
        self.assertFalse(rows[0]["attributed"])

    def test_newly_blocked_sample_with_a_reviewed_finding_is_attributed(self):
        """The recheck is not a constant: a verdict that names the attack attributes it.

        This is the branch `derive_attributed` exists for. It cannot be reached from a
        gate/assist divergence in this benchmark (see the test above), so it is driven
        directly, through the eval's own `check_sample_attribution`.
        """
        sample = self.flipped(sample_path=str(self.corpus / "s-flip"))
        sample["report"]["file_reports"][0]["findings"][0]["llm_verdict"] = "SUSPICIOUS"
        row = dict(sample["row"])
        row["blocked"] = False

        attributed = gr.derive_attributed(
            row, sample["report"], True, None, {}
        )

        self.assertTrue(attributed)


if __name__ == "__main__":
    unittest.main()
