# tests/test_h2_loaded_rounds_resume.py
"""The resume path is the one that can silently corrupt a matrix, so it is tested.

The driver runs six scored runs over hours, and a machine can go down in the middle
(one did: a host reboot cut run 2 off four days in). Recovering without a resume costs
the whole matrix; recovering with a careless one is worse, because a run that is
skipped while it is still incomplete leaves a matrix scored on fewer samples than the
corpus, with nothing anywhere reporting an error.

So the property under test is not "resume works" but "resume never trusts a partial
run". A run counts as finished only when its own artifacts say so -- the confusion
matrix exists AND the report count equals the corpus size -- and the tests below break
one half of that conjunction at a time to check the other half is not enough:

* a run with both halves is kept,
* a run with the matrix but too few reports is re-run,
* a run with the reports but no matrix is re-run,
* with resume off, a complete run is re-run like any other,
* and a run that fails still stops the matrix.

Each test drives the real script in a sandbox: the script is copied in beside a stub
evaluator, a stub `curl` (the driver refuses to measure against a cold runner), and a
two-sample corpus list. The stub appends "<engine> <run dir>" to a file for every
invocation, which is what lets these tests tell "kept" from "re-run" by name instead
of by reading the driver's prose.
"""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DRIVER = REPO_ROOT / "models" / "audit" / "tools" / "h2_loaded_rounds.sh"

STUB_EVALUATOR = '''\
import argparse, json, os, pathlib

p = argparse.ArgumentParser()
p.add_argument("--corpus-list")
p.add_argument("--results-dir")
p.add_argument("--engine")
a, _ = p.parse_known_args()

with open(os.environ["STUB_INVOCATIONS"], "a") as fh:
    fh.write("%s %s\\n" % (a.engine, os.path.basename(a.results_dir.rstrip("/"))))

n = len(json.load(open(a.corpus_list))["samples"])
d = pathlib.Path(a.results_dir)
d.mkdir(parents=True, exist_ok=True)
for i in range(n):
    sd = d / ("s%d" % i)
    sd.mkdir(exist_ok=True)
    (sd / "audit_report.json").write_text("{}")
(d / "confusion-matrix.json").write_text(json.dumps({"tp": 1, "fp": 0, "tn": 1, "fn": 0}))
'''

STUB_FAILING = '''\
import argparse, os, sys

p = argparse.ArgumentParser()
p.add_argument("--engine")
p.add_argument("--results-dir")
a, _ = p.parse_known_args()

with open(os.environ["STUB_INVOCATIONS"], "a") as fh:
    fh.write("%s %s\\n" % (a.engine, os.path.basename(a.results_dir.rstrip("/"))))
if a.engine == "regex":
    sys.exit(3)
'''

MATRIX = {"tp": 1, "fp": 0, "tn": 1, "fn": 0}


def write_exec(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class ResumeTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.sandbox = root / "tools"
        self.sandbox.mkdir()
        shutil.copy(DRIVER, self.sandbox / "h2_loaded_rounds.sh")
        self.evaluator = self.sandbox / "audit_benchmark_eval.py"
        self.evaluator.write_text(STUB_EVALUATOR)

        # The driver calls `warm_model` before measuring and refuses to continue if it
        # fails, so the sandbox needs a curl that succeeds. Stubbing it is deliberate:
        # these tests are about which runs execute, not about the model.
        bindir = root / "bin"
        bindir.mkdir()
        write_exec(bindir / "curl", "#!/bin/sh\nexit 0\n")

        self.out = root / "out"
        self.out.mkdir()
        self.corpus_list = root / "corpus-list.json"
        self.corpus_list.write_text(
            json.dumps({"samples": [{"sample_id": "s0"}, {"sample_id": "s1"}]})
        )
        self.invocations = root / "invocations.txt"
        self.invocations.write_text("")

        self.env = dict(os.environ)
        self.env["PATH"] = str(bindir) + os.pathsep + self.env["PATH"]
        self.env["STUB_INVOCATIONS"] = str(self.invocations)
        self.env["LOAD"] = "0"
        self.env["OUT"] = str(self.out)
        self.env["CORPUS_LIST"] = str(self.corpus_list)
        self.env["CORPUS_ROOT"] = str(root)

    def tearDown(self):
        self.tmp.cleanup()

    def drive(self, resume=True, expect_ok=True):
        self.env["RESUME"] = "1" if resume else "0"
        done = subprocess.run(
            ["bash", str(self.sandbox / "h2_loaded_rounds.sh")],
            env=self.env, cwd=str(self.sandbox),
            capture_output=True, text=True,
        )
        if expect_ok:
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return done.stdout + done.stderr

    def ran(self):
        return [line for line in self.invocations.read_text().splitlines() if line]

    def seed_complete(self, run):
        d = self.out / run
        d.mkdir(parents=True)
        (d / "confusion-matrix.json").write_text(json.dumps(MATRIX))
        for i in range(2):
            sd = d / ("s%d" % i)
            sd.mkdir()
            (sd / "audit_report.json").write_text("{}")
        (d / "PREEXISTING").write_text("kept iff not re-run")
        return d

    def seed_partial(self, run, matrix, reports):
        d = self.out / run
        d.mkdir(parents=True)
        if matrix:
            (d / "confusion-matrix.json").write_text(json.dumps(MATRIX))
        for i in range(reports):
            sd = d / ("s%d" % i)
            sd.mkdir()
            (sd / "audit_report.json").write_text("{}")
        (d / "PREEXISTING").write_text("must be wiped")
        return d


class KeepCompleteTest(ResumeTestBase):
    def test_a_complete_run_is_kept_and_the_others_still_run(self):
        self.seed_complete("regex-run1")
        log = self.drive(resume=True)
        self.assertNotIn("regex regex-run1", self.ran(), "a complete run must not be re-measured")
        self.assertEqual(
            self.ran(),
            ["semgrep semgrep-run1", "regex regex-run2", "semgrep semgrep-run2",
             "regex regex-run3", "semgrep semgrep-run3"],
        )
        self.assertIn("already complete, kept", log)

    def test_a_kept_run_is_untouched_and_still_reported(self):
        d = self.seed_complete("regex-run1")
        log = self.drive(resume=True)
        self.assertTrue((d / "PREEXISTING").exists(), "kept means untouched")
        # Its matrix is printed too, so the log reads the same whether a run was kept
        # or measured -- a reader should never have to know which.
        self.assertIn("tp=1 fp=0 tn=1 fn=0", log)


class RerunPartialTest(ResumeTestBase):
    def test_a_matrix_without_all_the_reports_is_rerun(self):
        # The dangerous half: a run killed after writing its summary but before
        # finishing its samples would score a partial corpus if this were trusted.
        d = self.seed_partial("regex-run1", matrix=True, reports=1)
        self.drive(resume=True)
        self.assertIn("regex regex-run1", self.ran(), "a partial run must be re-measured")
        self.assertFalse((d / "PREEXISTING").exists(), "a partial run is wiped, not merged into")

    def test_reports_without_a_matrix_are_rerun(self):
        d = self.seed_partial("regex-run1", matrix=False, reports=2)
        self.drive(resume=True)
        self.assertIn("regex regex-run1", self.ran())
        self.assertFalse((d / "PREEXISTING").exists())

    def test_an_empty_run_dir_is_rerun(self):
        (self.out / "regex-run1").mkdir()
        self.drive(resume=True)
        self.assertIn("regex regex-run1", self.ran())


class ResumeOffTest(ResumeTestBase):
    def test_without_resume_a_complete_run_is_rerun(self):
        # The default must stay exactly what it was before resume existed: the
        # pre-registered protocol re-measures every run, so no verdict can depend on
        # artifacts that a previous matrix happened to leave behind.
        d = self.seed_complete("regex-run1")
        self.drive(resume=False)
        self.assertIn("regex regex-run1", self.ran())
        self.assertFalse((d / "PREEXISTING").exists())
        self.assertEqual(len(self.ran()), 6)


class BannerTest(ResumeTestBase):
    def test_the_banner_and_the_completeness_test_agree_on_the_sample_count(self):
        # Both read EXPECTED. If they diverged, "complete" would be judged against a
        # different number than the one printed, and the printed one is what a reader
        # would check it against.
        log = self.drive(resume=False)
        self.assertIn("samples=2", log)


class FailureStillStopsTest(ResumeTestBase):
    def test_a_failing_run_stops_the_matrix(self):
        # Pinned here because resume now sits inside the same loop.
        self.evaluator.write_text(STUB_FAILING)
        self.drive(resume=True, expect_ok=True)
        self.assertEqual(self.ran(), ["regex regex-run1"],
                         "the matrix must stop at the first failed run")


if __name__ == "__main__":
    unittest.main()
