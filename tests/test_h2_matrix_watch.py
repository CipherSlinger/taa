# tests/test_h2_matrix_watch.py
"""The watch is an instrument, and its failure mode is silence, so it is tested.

An OOM kill of the model runner is the one event that can move the holdout
verdict without leaving a trace in the artifacts: the request in flight gets a
connection failure, and the killed server cannot write its own error line. The
watch exists to make that event loud, which means a branch of the watch that
fails quietly is worse than no watch at all.

Two such branches were found by reading it and are pinned here:

* The gather probe emitted the runner's pid field only when the runner was
  present. Absent, every later field shifted one place left, so the run count
  landed in `pid`, the GONE alert compared two numbers and never fired, and the
  heartbeat reported the memory figure as the run count. The fix emits the
  literal "none" when absent; the alignment tests below fail against the old
  behaviour because `runs=` comes back carrying the memory figure.

* The heartbeat reported memory as `current/max`, which reads as proximity to
  the limit. `current` is anon plus reclaimable page cache, so the reading was
  misleading in the direction of alarm. It is now decomposed, and the test pins
  the four labels so a future edit cannot quietly drop back to one number.

* The failed-arbitration count read `conclusion.verdict == "UNCERTAIN"`. That is
  what a failure is lifted *into*, not what it leaves behind: measured on the two
  complete runs, `statistics.uncertain > 0` marks exactly the samples whose
  llm_state is llm_unavailable or parse_error (8 of 8 and 6 of 6, identical by
  sample id), while the verdict marks 1 and 2 of those same failures. A wave of
  failures -- the event this branch exists to make loud -- would have been mostly
  invisible. `FailedArbitrationCountTest` pins both directions.

The watch drives `docker exec`, `ps` and the cgroup files, so the test supplies
all three: a fake docker that runs the probe locally instead of in the
container, a fake ps whose runner line follows a scripted sequence, and a
fixture cgroup directory. The cadence and the cgroup path are parameters on the
script for this reason -- a test cannot wait thirty minutes for a heartbeat.
"""
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# Overridable so the fix can be mutation-checked: point it at a copy with the
# old gather line restored and the alignment test must fail. Without that, the
# assertions below are only claims about the current file.
WATCH = Path(
    os.environ.get("H2_WATCH_SCRIPT", REPO_ROOT / "models" / "audit" / "tools" / "h2_matrix_watch.sh")
)

MiB = 1048576

# Runs the probe locally instead of in the container, and ends the log-following
# stream immediately. `docker exec <c> sh -c <script>` is the only call whose
# output the watch parses; `docker exec <c> tail -F` only feeds the background
# grep, which is not under test.
FAKE_DOCKER = """#!/bin/sh
[ "$1" = "exec" ] || exit 0
shift           # exec
shift           # container
case "$1" in
  tail) exit 0 ;;
  sh)
    shift       # sh
    shift       # -c
    exec sh -c "$1"
    ;;
esac
exit 0
"""

# Reproduces the shape of `ps -eo pid,args` with only the runner line varying.
# FAKE_PS_SEQUENCE is consumed one value per invocation and its last value then
# repeats, so a scenario can say "present, present, gone from here on".
FAKE_PS = """#!/bin/sh
counter=$FAKE_PS_COUNTER
n=$(cat "$counter" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$counter"
value=$(echo "$FAKE_PS_SEQUENCE" | cut -d, -f"$n")
[ -z "$value" ] && value=$(echo "$FAKE_PS_SEQUENCE" | awk -F, '{print $NF}')
echo "    PID ARGS"
[ "$value" = "none" ] || echo "$value /usr/bin/llama-server --port 8080"
"""


def write_exec(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class WatchTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)

        bindir = root / "bin"
        bindir.mkdir()
        write_exec(bindir / "docker", FAKE_DOCKER)
        write_exec(bindir / "ps", FAKE_PS)

        self.cgroup = root / "cgroup"
        self.cgroup.mkdir()
        (self.cgroup / "memory.events").write_text("oom_kill 0\n")
        (self.cgroup / "memory.stat").write_text(
            "anon %d\nfile %d\n" % (2154 * MiB, 1954 * MiB)
        )
        (self.cgroup / "memory.current").write_text("%d\n" % (4133 * MiB))
        (self.cgroup / "memory.max").write_text("%d\n" % (7168 * MiB))

        self.out = root / "out"
        self.out.mkdir()
        for run in ("regex-run1", "semgrep-run1", "regex-run2"):
            (self.out / run).mkdir()

        self.env = dict(os.environ)
        self.env["PATH"] = str(bindir) + os.pathsep + self.env["PATH"]
        self.env["CGROUP"] = str(self.cgroup)
        self.env["OUT"] = str(self.out)
        self.env["LOG"] = str(root / "driver.log")
        self.env["POLL_INTERVAL"] = "0.5"
        self.env["HEARTBEAT_EVERY"] = "1"
        self.env["FAKE_PS_COUNTER"] = str(root / "ps-counter")

    def tearDown(self):
        self.tmp.cleanup()

    def watch(self, ps_sequence, seconds=5):
        self.env["FAKE_PS_SEQUENCE"] = ps_sequence
        # `timeout` is expected to kill it: the watch loops until interrupted.
        done = subprocess.run(
            ["timeout", str(seconds), "bash", str(WATCH)],
            env=self.env, capture_output=True, text=True,
        )
        return done.stdout + done.stderr


class HeartbeatTest(WatchTestBase):
    def test_the_heartbeat_reports_memory_decomposed(self):
        log = self.watch("402")
        self.assertIn("mem_anon=2154MiB", log)
        self.assertIn("mem_file=1954MiB", log)
        self.assertIn("mem_current=4133MiB", log)
        self.assertIn("mem_max=7168MiB", log)


class FieldAlignmentTest(WatchTestBase):
    def test_a_missing_runner_does_not_shift_the_later_fields(self):
        # The regression: with the pid field skipped, `nrun` received the anon
        # figure, so this asserted pair comes back as "runs=2154
        # uncertain_total=3" and the four memory labels are all off by one.
        log = self.watch("none")
        self.assertIn("runs=3 failed_samples_all_runs=0 failed_findings_all_runs=0", log)
        self.assertIn(
            "mem_anon=2154MiB mem_file=1954MiB mem_current=4133MiB mem_max=7168MiB",
            log,
        )

    def test_the_same_fields_hold_when_the_runner_is_present(self):
        # The negative control for the test above: the alignment must not depend
        # on which branch the runner happens to be in.
        log = self.watch("402")
        self.assertIn("runs=3 failed_samples_all_runs=0 failed_findings_all_runs=0", log)
        self.assertIn("llama_pid=402", log)


class FailedArbitrationCountTest(WatchTestBase):
    """The count must come from statistics.uncertain, not from the verdict."""

    def sample(self, run, sample_id, report):
        d = self.out / run / sample_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "audit_report.json").write_text(json.dumps(report))

    def test_a_failed_call_is_counted_even_though_the_verdict_is_malicious(self):
        # The shape a real failure takes: the UNCERTAIN is lifted to CRITICAL and
        # the verdict reads MALICIOUS, so the verdict carries no trace of it.
        # Against the old verdict-based count this asserts "failed_samples_all_runs=0" and
        # fails, which is the point of the fixture.
        self.sample(
            "regex-run2", "dd-0019",
            {"conclusion": {"verdict": "MALICIOUS"},
             "statistics": {"uncertain": 2}},
        )
        log = self.watch("402")
        self.assertIn("failed_samples_all_runs=1 failed_findings_all_runs=2", log)

    def test_an_uncertain_verdict_alone_is_not_a_failed_call(self):
        # The other direction, so the fix cannot be "count either signal": a
        # sample reported UNCERTAIN with no failed finding is not a failure.
        self.sample(
            "regex-run2", "cq-0001",
            {"conclusion": {"verdict": "UNCERTAIN"},
             "statistics": {"uncertain": 0}},
        )
        log = self.watch("402")
        self.assertIn("failed_samples_all_runs=0 failed_findings_all_runs=0", log)


class RunnerLivenessTest(WatchTestBase):
    def test_the_gone_alert_fires_when_the_runner_disappears(self):
        log = self.watch("402,402,none")
        self.assertIn("llama-server GONE", log)

    def test_no_gone_alert_while_the_runner_stays_up(self):
        log = self.watch("402")
        self.assertNotIn("GONE", log)


if __name__ == "__main__":
    unittest.main()
