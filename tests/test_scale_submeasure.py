# tests/test_scale_submeasure.py
"""The H2.5 scale instrument: its parsing, its process-tree walk, its maxima.

The readings this produces are quoted as measured facts about what a real
package costs, and a misread here would be indistinguishable from a finding, so
the parts that can be wrong silently are tested directly:

* the `/proc/<pid>/stat` split, which must survive a command name containing
  spaces and parentheses (a naive tokenize shifts every field and would report
  the wrong parent, silently truncating the process tree);
* the descendant walk, which must terminate even if a pid is reused mid-walk;
* the maxima, which must not depend on sampling order, since that is what makes
  two runs comparable.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools import scale_submeasure as ss  # noqa: E402


def stat_line(ppid: int, rss_pages: int, comm: str = "python3") -> str:
    """One `/proc/<pid>/stat`, with the field count a real one has."""
    after_comm = ["S", str(ppid)] + ["0"] * 19 + [str(rss_pages)]
    assert len(after_comm) == 22
    return f"1234 ({comm}) " + " ".join(after_comm) + "\n"


def write_fake_proc(root: Path, procs: dict) -> None:
    """`procs` maps pid to (ppid, rss_pages, comm)."""
    for pid, (ppid, rss_pages, comm) in procs.items():
        entry = root / str(pid)
        entry.mkdir(parents=True, exist_ok=True)
        (entry / "stat").write_text(stat_line(ppid, rss_pages, comm))
        (entry / "statm").write_text(f"1000 {rss_pages} 0 0 0 0 0\n")


class TestParsing(unittest.TestCase):
    def test_mem_available_is_read_in_kb(self):
        text = "MemTotal:  9935000 kB\nMemAvailable:   7519000 kB\n"
        self.assertEqual(ss.parse_meminfo_available(text), 7519000)

    def test_a_missing_mem_available_is_none_not_zero(self):
        # Zero would read as "no memory left" and halt a sweep that was never
        # actually constrained.
        self.assertIsNone(ss.parse_meminfo_available("MemTotal: 100 kB\n"))

    def test_cgroup_anon_is_read_and_absence_is_none(self):
        text = "anon 2147483648\nfile 1234\n"
        self.assertEqual(ss.parse_cgroup_anon(text), 2147483648)
        self.assertIsNone(ss.parse_cgroup_anon("file 1234\n"))

    def test_a_command_with_spaces_and_parentheses_does_not_shift_the_fields(self):
        # `bwrap --args (x)` style names are real, and tokenizing from the left
        # would read the wrong field as the parent.
        line = stat_line(ppid=7, rss_pages=42, comm="bwrap --dev (x) y")
        self.assertEqual(ss.parse_proc_stat(line), (7, 42))

    def test_a_truncated_stat_line_is_refused(self):
        self.assertIsNone(ss.parse_proc_stat("1234 (python3) S 1 2 3\n"))
        self.assertIsNone(ss.parse_proc_stat("no parens at all\n"))


class TestProcessTree(unittest.TestCase):
    def test_descendants_include_the_root(self):
        children = {1: [2, 3], 2: [4]}
        self.assertEqual(ss.descendants(1, children), [1, 2, 3, 4])

    def test_a_cycle_terminates(self):
        # A reused pid can make a process appear to be its own ancestor.
        children = {1: [2], 2: [1]}
        self.assertEqual(ss.descendants(1, children), [1, 2])

    def test_a_leaf_is_its_own_only_member(self):
        self.assertEqual(ss.descendants(9, {1: [2]}), [9])

    def test_the_tree_sum_does_not_stop_at_the_parent(self):
        # Semgrep's work happens in semgrep-core children, so a parent-only
        # reading would miss nearly all of it.
        table = ss.ProcTable(children={10: [11, 12], 11: [13]}, rss_kb={10: 100, 11: 200,
                                                                      12: 300, 13: 400})
        self.assertEqual(ss.sum_tree_rss_kb(10, table), 1000)

    def test_an_absent_process_contributes_nothing(self):
        self.assertEqual(ss.sum_tree_rss_kb(99, ss.ProcTable()), 0)

    def test_a_fake_proc_tree_is_walked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fake_proc(root, {
                1: (0, 10, "init"),
                2: (1, 20, "semgrep"),
                3: (2, 30, "semgrep-core"),
                4: (1, 40, "unrelated"),
            })
            table = ss.read_proc_table(str(root))
            self.assertEqual(sorted(table.rss_kb), [1, 2, 3, 4])
            expected = (20 + 30) * ss.PAGE_SIZE_KB
            self.assertEqual(ss.sum_tree_rss_kb(2, table), expected)

    def test_a_non_process_entry_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fake_proc(root, {1: (0, 10, "init")})
            (root / "self").mkdir()          # /proc really does contain these
            (root / "meminfo").write_text("MemTotal: 1 kB\n")
            table = ss.read_proc_table(str(root))
            self.assertEqual(sorted(table.rss_kb), [1])


class TestSample(unittest.TestCase):
    def test_the_maxima_are_order_independent(self):
        instants = [(100, 200, 50, 900), (300, 150, 10, 800), (200, 250, 70, 1000)]
        forward, backward = ss.Sample(), ss.Sample()
        for instant in instants:
            forward.observe(*instant)
        for instant in reversed(instants):
            backward.observe(*instant)
        self.assertEqual(forward.as_dict(), backward.as_dict())
        self.assertEqual(forward.anon_bytes, 300)
        self.assertEqual(forward.current_bytes, 250)
        self.assertEqual(forward.tree_rss_kb, 70)

    def test_min_available_keeps_the_lowest_reading(self):
        sample = ss.Sample()
        sample.observe(0, 0, 0, 5000)
        sample.observe(0, 0, 0, 3000)
        sample.observe(0, 0, 0, 4000)
        self.assertEqual(sample.min_available_kb, 3000)

    def test_an_unreadable_field_does_not_zero_a_maximum(self):
        # None means "could not read", not "zero": folding it in as zero would
        # erase a peak that had already been observed.
        sample = ss.Sample()
        sample.observe(500, 600, 10, 700)
        sample.observe(None, None, 0, None)
        self.assertEqual(sample.anon_bytes, 500)
        self.assertEqual(sample.current_bytes, 600)
        self.assertEqual(sample.min_available_kb, 700)
        self.assertEqual(sample.samples, 2)

    def test_mib_conversion(self):
        sample = ss.Sample()
        sample.observe(2 * 1048576, 3 * 1048576, 1024 * 4, 1024 * 8)
        self.assertEqual(sample.as_dict()["peak_anon_mib"], 2.0)
        self.assertEqual(sample.as_dict()["peak_current_mib"], 3.0)
        self.assertEqual(sample.as_dict()["peak_tree_rss_mib"], 4.0)
        self.assertEqual(sample.as_dict()["min_available_mib"], 8.0)


class TestAbortGuard(unittest.TestCase):
    def test_a_run_is_stopped_once_available_memory_falls_below_the_floor(self):
        self.assertTrue(ss.should_abort(500 * 1024, 1024 * 1024))
        self.assertFalse(ss.should_abort(2000 * 1024, 1024 * 1024))

    def test_an_unreadable_available_is_not_a_shortage(self):
        # Reading it as a shortage would stop runs that were never constrained.
        self.assertFalse(ss.should_abort(None, 1024 * 1024))

    def test_no_floor_means_no_guard(self):
        self.assertFalse(ss.should_abort(1, None))


class TestSummaries(unittest.TestCase):
    def test_semgrep_findings_are_counted_by_family(self):
        text = json.dumps({"results": [
            {"path": "a.py", "check_id": "taa-cmd-exec-python",
             "extra": {"metadata": {"rule_family": "CMD_001"}}},
            {"path": "a.py", "check_id": "taa-net-general-python",
             "extra": {"metadata": {"rule_family": "NET_001"}}},
            {"path": "b.py", "check_id": "taa-net-general-python",
             "extra": {"metadata": {"rule_family": "NET_001"}}},
        ], "errors": []})
        summary = ss.summarize_semgrep_json(text)
        self.assertEqual(summary["findings"], 3)
        self.assertEqual(summary["per_rule"], {"CMD_001": 1, "NET_001": 2})
        self.assertEqual(summary["files_with_findings"], 2)

    def test_a_rule_without_a_family_falls_back_to_its_id(self):
        text = json.dumps({"results": [{"path": "a.py", "check_id": "some-rule"}]})
        self.assertEqual(ss.summarize_semgrep_json(text)["per_rule"], {"some-rule": 1})

    def test_unparseable_semgrep_output_is_an_error_not_zero_findings(self):
        # A scan that produced no JSON is not a scan that found nothing.
        summary = ss.summarize_semgrep_json("<html>proxy error</html>")
        self.assertIn("summary_error", summary)
        self.assertNotIn("findings", summary)

    def test_semgrep_errors_are_counted(self):
        text = json.dumps({"results": [], "errors": [{"type": "ParseError"}]})
        self.assertEqual(ss.summarize_semgrep_json(text)["semgrep_errors"], 1)

    def test_the_adapter_summary_reads_the_last_json_line(self):
        text = 'some warning\n{"engine": "regex", "findings": 7}\n'
        summary = ss.summarize_adapter_json(text)
        self.assertEqual(summary["findings"], 7)

    def test_an_adapter_summary_that_is_not_json_is_an_error(self):
        self.assertIn("summary_error", ss.summarize_adapter_json("Traceback...\n"))
        self.assertIn("summary_error", ss.summarize_adapter_json(""))


class TestTimeoutGuard(unittest.TestCase):
    """The per-run bound, which is what keeps a slow tree a reading, not a hang."""

    def test_a_run_past_its_bound_is_stopped_and_reported_as_timed_out(self):
        argv = [sys.executable, "-c", "import time; time.sleep(30)"]
        result = ss.run_measured(argv, interval=0.05, timeout_seconds=0.5,
                                 summarize=ss.summarize_adapter_json)
        self.assertTrue(result["timed_out"])
        self.assertLess(result["seconds"], 10)
        self.assertEqual(result["timeout_seconds"], 0.5)

    def test_a_stopped_run_takes_its_descendants_with_it(self):
        # The regression this guards: the child spawns a grandchild that keeps
        # the output handles open, so waiting on the child alone never returns
        # and the next measurement would run alongside the previous one.
        argv = [sys.executable, "-c",
                "import subprocess, sys, time\n"
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                "time.sleep(60)\n"]
        result = ss.run_measured(argv, interval=0.05, timeout_seconds=0.5)
        self.assertTrue(result["timed_out"])
        self.assertLess(result["seconds"], 20)

    def test_large_output_does_not_deadlock_the_run(self):
        # With stdout on a pipe, a child that writes more than a pipe buffer
        # blocks forever and the poll loop waits on a process that cannot exit.
        argv = [sys.executable, "-c",
                "import sys; sys.stdout.write('x' * (4 << 20)); sys.stdout.flush()"]
        result = ss.run_measured(argv, interval=0.05, timeout_seconds=60)
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["exit_code"], 0)
        self.assertGreaterEqual(result["stdout_bytes"], 4 << 20)

    def test_a_run_inside_its_bound_is_not_marked_timed_out(self):
        argv = [sys.executable, "-c", "print('{\"findings\": 0}')"]
        result = ss.run_measured(argv, interval=0.05, timeout_seconds=30)
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["exit_code"], 0)

    def test_no_bound_means_no_timeout_field_value(self):
        result = ss.run_measured([sys.executable, "-c", "pass"], interval=0.05,
                                 timeout_seconds=None)
        self.assertFalse(result["timed_out"])
        self.assertIsNone(result["timeout_seconds"])

    def test_the_summary_still_reads_from_the_file_backed_output(self):
        argv = [sys.executable, "-c", "print('{\"findings\": 5}')"]
        result = ss.run_measured(argv, interval=0.05, timeout_seconds=30,
                                 summarize=ss.summarize_adapter_json)
        self.assertEqual(result["findings"], 5)


class TestBurst(unittest.TestCase):
    """The concurrent peak, which is not the sum of single-run readings."""

    def test_the_burst_reports_every_run_and_its_own_level(self):
        result = ss.run_burst(
            level=3,
            argv_factory=lambda i: [sys.executable, "-c", "print('{\"findings\": 5}')"],
            interval=0.05, timeout_seconds=30, summarize=ss.summarize_adapter_json,
        )
        self.assertEqual(result["level"], 3)
        self.assertEqual(result["exit_codes"], [0, 0, 0])
        # Reported per scan, never summed: three scans of one corpus would
        # otherwise read as a corpus holding fifteen findings.
        self.assertEqual([s["findings"] for s in result["summaries"]], [5, 5, 5])
        self.assertFalse(result["timed_out"])

    def test_each_run_gets_its_own_invocation(self):
        seen = []
        ss.run_burst(level=4, argv_factory=lambda i: (seen.append(i), [
            sys.executable, "-c", "pass"])[1], interval=0.05, timeout_seconds=30)
        self.assertEqual(seen, [0, 1, 2, 3])

    def test_the_tree_reading_covers_every_run_not_just_the_first(self):
        # With runs staggered so that at least two overlap, a reader that
        # sampled only the first process would report a footprint smaller than
        # the set's - and the limit would be set from it.
        argv = [sys.executable, "-c", "import time; time.sleep(1.2)"]
        result = ss.run_burst(level=3, argv_factory=lambda i: argv, interval=0.1,
                              timeout_seconds=30)
        # Three idle interpreters: a few MiB each, so the tree sum must exceed
        # what any one of them holds on its own by a clear margin.
        self.assertGreater(result["memory"]["peak_tree_rss_mib"], 0)

    def test_a_burst_past_its_bound_stops_all_of_its_runs(self):
        argv = [sys.executable, "-c", "import time; time.sleep(60)"]
        result = ss.run_burst(level=3, argv_factory=lambda i: argv, interval=0.05,
                              timeout_seconds=0.5)
        self.assertTrue(result["timed_out"])
        self.assertLess(result["seconds"], 20)

    def test_a_burst_over_a_memory_floor_is_aborted_and_says_so(self):
        argv = [sys.executable, "-c", "import time; time.sleep(60)"]
        result = ss.run_burst(level=2, argv_factory=lambda i: argv, interval=0.05,
                              timeout_seconds=30, abort_below_kb=10 ** 12)
        self.assertTrue(result["aborted"])
        self.assertIsNotNone(result["aborted_at_available_mib"])
        self.assertLess(result["seconds"], 20)


class TestInvocations(unittest.TestCase):
    def test_the_semgrep_invocation_pins_jobs_and_the_per_file_cap(self):
        # Both are pinned deliberately: --max-memory bounds one file, not how
        # many are in flight, so the aggregate ceiling is jobs * max_memory.
        argv = ss.semgrep_argv("/tree", "/rules", jobs=4, max_memory_mb=1024)
        self.assertIn("--jobs", argv)
        self.assertEqual(argv[argv.index("--jobs") + 1], "4")
        self.assertEqual(argv[argv.index("--max-memory") + 1], "1024")
        self.assertEqual(argv[-1], "/tree")

    def test_the_scan_runs_through_the_evaluations_own_adapter(self):
        # A re-implementation would measure a different code path than the one
        # the criterion takes.
        argv = ss.python_scan_argv("/tree", "/staged", "semgrep", "/rules")
        self.assertEqual(argv[:2], [sys.executable, "-c"])
        self.assertIn("SemgrepScannerAdapter", ss.PYTHON_SCAN_SNIPPET)
        # The snippet reads these positionally, so their order is part of the
        # contract between it and this function.
        self.assertEqual(argv[3:7], ["/staged", "semgrep", "/tree", "/rules"])

    def test_the_rules_argument_is_optional(self):
        argv = ss.python_scan_argv("/tree", "/staged", "regex")
        self.assertEqual(argv[3:6], ["/staged", "regex", "/tree"])

    def test_counting_python_files_ignores_other_extensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("")
            (root / "sub").mkdir()
            (root / "sub" / "b.py").write_text("")
            (root / "sub" / "c.txt").write_text("")
            self.assertEqual(ss.count_python_files(tmp), 2)


if __name__ == "__main__":
    unittest.main()
