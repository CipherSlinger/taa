# models/audit/tools/scale_submeasure.py
"""Time and memory of one scan, measured on a real package tree.

Stage H2.5 exists because the single-file samples cannot answer two questions
that decide whether the Semgrep arm can be deployed at all: what a scan of a
real package costs in wall time and memory, and whether the per-file scan path
reaches the finding caps that are registered as one-sided asymmetries. This
module is the instrument for that measurement, kept apart from the judgement so
that a scale reading is never mistaken for a detection difference.

Two properties of the reading matter enough to state plainly:

* **The memory figures are sampled maxima, not the kernel's high-water mark.**
  `memory.peak` is monotonic over the container's lifetime and the cgroup
  filesystem is mounted read-only, so it cannot be reset per run; a per-run peak
  therefore has to be sampled. A sampled maximum can only *understate* the true
  peak, by at most one sampling interval. `VmHWM` would be exact, but it is
  per-process and short-lived Semgrep workers exit between reads.
* **The anonymous figure is the one to compare against a limit.** The cgroup's
  `current` includes page cache, which is reclaimable and is not pressure; a
  budget sized on `current` would overstate the footprint, and one sized on
  `anon` alone would ignore that page cache still competes for the host when no
  limit is set. Both are reported.

Nothing here decides anything: it prints numbers, and the plan's section 7
requires the scale readings to be reported separately from the single-file
criterion.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SAMPLE_INTERVAL_SECONDS = 0.2
PAGE_SIZE_KB = os.sysconf("SC_PAGE_SIZE") // 1024

CGROUP_CURRENT = "/sys/fs/cgroup/memory.current"
CGROUP_STAT = "/sys/fs/cgroup/memory.stat"
MEMINFO = "/proc/meminfo"


def parse_meminfo_available(text: str) -> Optional[int]:
    """`MemAvailable` in kB, or None when the field is absent.

    Absent rather than zero: a zero would read as "no memory left" and stop an
    escalation that was never actually constrained.
    """
    for line in text.splitlines():
        if line.startswith("MemAvailable:"):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1])
    return None


def parse_cgroup_anon(text: str) -> Optional[int]:
    """The `anon` field of `memory.stat`, in bytes."""
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        if key == "anon":
            return int(value)
    return None


def parse_proc_stat(text: str) -> Optional[Tuple[int, int]]:
    """`(ppid, rss_pages)` from one `/proc/<pid>/stat`.

    The second field is the command in parentheses and may itself contain
    spaces and parentheses, so the split is anchored on the *last* ')' rather
    than tokenized from the left.
    """
    _, sep, tail = text.rpartition(") ")
    if not sep:
        return None
    fields = tail.split()
    if len(fields) < 22:
        return None
    try:
        return int(fields[1]), int(fields[21])
    except ValueError:
        return None


@dataclass
class ProcTable:
    """A snapshot of the process table, in the two shapes the walk needs."""

    children: Dict[int, List[int]] = field(default_factory=dict)
    rss_kb: Dict[int, int] = field(default_factory=dict)


def read_proc_table(proc_root: str = "/proc") -> ProcTable:
    """Read every process's parent and resident size.

    `statm`'s resident field is preferred over `stat`'s rss: the two agree, and
    `statm` is the one that does not need the parenthesized-command dance.
    """
    table = ProcTable()
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return table
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            stat_text = Path(proc_root, entry, "stat").read_text()
            statm_text = Path(proc_root, entry, "statm").read_text()
        except OSError:
            continue  # The process exited between listdir and read.
        parsed = parse_proc_stat(stat_text)
        if parsed is None:
            continue
        ppid, _ = parsed
        try:
            resident_pages = int(statm_text.split()[1])
        except (IndexError, ValueError):
            continue
        table.rss_kb[pid] = resident_pages * PAGE_SIZE_KB
        table.children.setdefault(ppid, []).append(pid)
    return table


def descendants(root_pid: int, children: Dict[int, List[int]]) -> List[int]:
    """Every pid reachable from `root_pid` through the parent links, itself included.

    Iterative and cycle-guarded: a pid reused while the walk runs can make a
    process appear to be its own ancestor, and a recursive walk would then not
    terminate.
    """
    seen = set()
    stack = [root_pid]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        stack.extend(children.get(pid, ()))
    return sorted(seen)


def sum_tree_rss_kb(root_pid: int, table: ProcTable) -> int:
    """The resident size of a process tree at one instant.

    Semgrep's work happens in `semgrep-core` children, so a reading taken from
    the parent alone would miss nearly all of it.
    """
    return sum(table.rss_kb.get(pid, 0) for pid in descendants(root_pid, table.children))


@dataclass
class Sample:
    """The maxima observed while one scan ran."""

    anon_bytes: int = 0
    current_bytes: int = 0
    tree_rss_kb: int = 0
    min_available_kb: Optional[int] = None
    samples: int = 0

    def observe(self, anon: Optional[int], current: Optional[int],
                tree_rss_kb: int, available_kb: Optional[int]) -> None:
        """Fold one instant into the maxima.

        Maxima are order-independent, which is what makes the reading
        reproducible: two runs that see the same set of instants report the same
        peak regardless of when the sampler happened to be scheduled.
        """
        self.samples += 1
        if anon is not None:
            self.anon_bytes = max(self.anon_bytes, anon)
        if current is not None:
            self.current_bytes = max(self.current_bytes, current)
        self.tree_rss_kb = max(self.tree_rss_kb, tree_rss_kb)
        if available_kb is not None:
            self.min_available_kb = (
                available_kb if self.min_available_kb is None
                else min(self.min_available_kb, available_kb)
            )

    def as_dict(self) -> Dict[str, Optional[float]]:
        return {
            "peak_anon_mib": round(self.anon_bytes / 1048576, 1),
            "peak_current_mib": round(self.current_bytes / 1048576, 1),
            "peak_tree_rss_mib": round(self.tree_rss_kb / 1024, 1),
            "min_available_mib": (
                None if self.min_available_kb is None
                else round(self.min_available_kb / 1024, 1)
            ),
            "samples": self.samples,
        }


def read_cgroup() -> Tuple[Optional[int], Optional[int]]:
    """`(anon_bytes, current_bytes)`, either of which may be unreadable."""
    anon = current = None
    try:
        current = int(Path(CGROUP_CURRENT).read_text())
        anon = parse_cgroup_anon(Path(CGROUP_STAT).read_text())
    except OSError:
        pass
    return anon, current


def read_available_kb() -> Optional[int]:
    try:
        return parse_meminfo_available(Path(MEMINFO).read_text())
    except OSError:
        return None


def should_abort(available_kb: Optional[int], floor_kb: Optional[int]) -> bool:
    """Whether the host is short enough of memory that a run must be stopped.

    The condition this exists for is the one that has already happened on this
    host: a Semgrep scan with unpinned concurrency taking the machine into OOM,
    where the kernel's victim is whichever process has the largest resident
    size. A reading taken after the fact would be the OOM, not the measurement,
    so the sampler stops the run while there is still memory left.

    An unreadable `MemAvailable` is not a reason to abort: it means the field
    could not be read, and treating that as a shortage would stop runs that were
    never constrained.
    """
    return (floor_kb is not None and available_kb is not None
            and available_kb < floor_kb)


def summarize_semgrep_json(text: str) -> Dict[str, object]:
    """Finding counts from one `semgrep --json` stdout.

    Counted by rule *family* where the rule carries one, because the number the
    registries compare against their caps is a count of findings, while the
    family is what makes a count comparable to the baseline's rules.

    Unparseable output is reported as such rather than as zero findings: a scan
    that produced no JSON at all is not a scan that found nothing, and the two
    have to stay distinguishable for the same reason `ScanOutcome` exists.
    """
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {"summary_error": "stdout was not JSON", "stdout_prefix": text[:200]}
    results = doc.get("results", []) if isinstance(doc, dict) else []
    per_family: Dict[str, int] = {}
    files = set()
    for result in results:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        key = metadata.get("rule_family") or result.get("check_id") or "unknown"
        per_family[key] = per_family.get(key, 0) + 1
        if result.get("path"):
            files.add(result["path"])
    return {
        "findings": len(results),
        "per_rule": dict(sorted(per_family.items())),
        "files_with_findings": len(files),
        "semgrep_errors": len(doc.get("errors", []) or []),
    }


def summarize_adapter_json(text: str) -> Dict[str, object]:
    """Pass through the JSON the in-container adapter snippet printed."""
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return {"summary_error": "last non-empty stdout line was not JSON",
                    "stdout_prefix": text[:200]}
    return {"summary_error": "stdout was empty"}


def run_measured(argv: Sequence[str], interval: float = SAMPLE_INTERVAL_SECONDS,
                 env: Optional[Dict[str, str]] = None,
                 abort_below_kb: Optional[int] = None,
                 summarize: Optional[object] = None,
                 timeout_seconds: Optional[float] = None) -> Dict[str, object]:
    """Run one command, sampling its footprint, and report both.

    `abort_below_kb` is a live guard: the run is terminated as soon as
    `MemAvailable` samples below it, and the reading says so rather than
    reporting a partial footprint as if it were the whole cost.

    `timeout_seconds` reproduces the bound the production path applies
    (`SemgrepRunner.scan_directory` passes `timeout=120`). Measuring under the
    same bound is what makes "this tree does not finish in time" a reading
    instead of a hung sweep, and it is the difference between a sample the
    pipeline can score and one it must drop.

    `summarize` maps the command's stdout to extra fields. It is a parameter
    rather than a branch on the command name so that the same sampler serves
    both engines, and so that a scan whose output cannot be read says so
    instead of scoring as a clean scan.
    """
    started = time.monotonic()
    deadline = None if timeout_seconds is None else started + timeout_seconds
    with tempfile.TemporaryDirectory() as tmp:
        out_path, err_path = Path(tmp, "stdout"), Path(tmp, "stderr")
        # Output goes to files, not pipes. With `stdout=PIPE` the child blocks
        # once it has written a pipe buffer's worth (64 KiB) and nothing has read
        # it, and a Semgrep scan of a real tree produces far more JSON than that:
        # the run would then sit at 100% forever while the poll loop watched a
        # process that was never going to exit.
        with out_path.open("wb") as out_handle, err_path.open("wb") as err_handle:
            proc = subprocess.Popen(list(argv), stdout=out_handle, stderr=err_handle,
                                    env=env, start_new_session=True)
            sample = Sample()
            aborted_at_kb: Optional[int] = None
            timed_out = False
            while proc.poll() is None:
                anon, current = read_cgroup()
                available = read_available_kb()
                sample.observe(anon, current,
                               sum_tree_rss_kb(proc.pid, read_proc_table()), available)
                if should_abort(available, abort_below_kb):
                    aborted_at_kb = available
                    _terminate(proc)
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    timed_out = True
                    _terminate(proc)
                    break
                time.sleep(interval)
            # One last reading: a scan that finished inside one interval would
            # otherwise report an empty sample set and look weightless.
            anon, current = read_cgroup()
            sample.observe(anon, current, 0, read_available_kb())
            proc.wait(timeout=30)
        stdout = out_path.read_text(errors="replace")
        stderr = err_path.read_text(errors="replace")
    result: Dict[str, object] = {
        "argv": list(argv),
        "exit_code": proc.returncode,
        "aborted": aborted_at_kb is not None,
        "aborted_at_available_mib": (
            None if aborted_at_kb is None else round(aborted_at_kb / 1024, 1)
        ),
        "timed_out": timed_out,
        "timeout_seconds": timeout_seconds,
        "seconds": round(time.monotonic() - started, 2),
        "memory": sample.as_dict(),
        "stdout_bytes": len(stdout),
        "stderr_tail": stderr[-2000:],
    }
    if summarize is not None:
        result.update(summarize(stdout))
    return result


def run_burst(level: int, argv_factory, interval: float = SAMPLE_INTERVAL_SECONDS,
              timeout_seconds: Optional[float] = None,
              abort_below_kb: Optional[int] = None,
              summarize: Optional[object] = None,
              env: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    """Run `level` copies of one command at once and sample the whole set.

    This is the shape the load test applies (`semgrep_press_test.sh` runs
    `level` concurrent scans), and it is **not** the sum of `level` single-run
    readings: the peak that decides a container limit is the peak of the set,
    which no single-run sweep can show. `argv_factory(i)` returns the argument
    vector for run `i`, because the load test gives each run its own output file.

    The per-scan summaries are reported as a list, not aggregated. Every run
    scans the same corpus, so a sum over them would be a multiple of one scan's
    finding count - a number with no interpretation, and one that would read as
    if the corpus contained that many findings.

    `timeout_seconds` bounds the whole burst; the first run past it stops all of
    them, since a set that is still running is not a set whose peak has been
    reached.
    """
    started = time.monotonic()
    deadline = None if timeout_seconds is None else started + timeout_seconds
    procs: List[subprocess.Popen] = []
    handles: List[object] = []
    paths: List[Tuple[Path, Path]] = []
    summaries: List[Dict[str, object]] = []
    aborted_at_kb: Optional[int] = None
    timed_out = False
    tmp = tempfile.TemporaryDirectory()
    try:
        for i in range(level):
            out_path = Path(tmp.name, f"stdout-{i}")
            err_path = Path(tmp.name, f"stderr-{i}")
            paths.append((out_path, err_path))
            # File-backed output for the same reason as `run_measured`: a pipe
            # would stall a scan that writes more than a pipe buffer.
            out_handle = out_path.open("wb")
            err_handle = err_path.open("wb")
            handles.extend([out_handle, err_handle])
            procs.append(subprocess.Popen(list(argv_factory(i)), stdout=out_handle,
                                          stderr=err_handle, env=env,
                                          start_new_session=True))
        sample = Sample()
        while any(proc.poll() is None for proc in procs):
            anon, current = read_cgroup()
            available = read_available_kb()
            table = read_proc_table()
            # Every run's tree counts, not just the first: the peak of a burst is
            # the sum over the set, which is the quantity a limit must cover.
            tree_kb = sum(sum_tree_rss_kb(proc.pid, table) for proc in procs
                          if proc.poll() is None)
            sample.observe(anon, current, tree_kb, available)
            if should_abort(available, abort_below_kb):
                aborted_at_kb = available
                for proc in procs:
                    _terminate(proc)
                break
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                for proc in procs:
                    _terminate(proc)
                break
            time.sleep(interval)
        # One last reading, so a burst that finishes inside one interval is not
        # reported as weightless.
        anon, current = read_cgroup()
        sample.observe(anon, current, 0, read_available_kb())
        for proc in procs:
            proc.wait(timeout=30)
    finally:
        for handle in handles:
            try:
                handle.close()
            except Exception:      # noqa: BLE001 - a failed close must not mask the reading
                pass
        if summarize is not None:
            for out_path, _ in paths:
                summaries.append(summarize(out_path.read_text(errors="replace")))
        tmp.cleanup()
    return {
        "level": level,
        "seconds": round(time.monotonic() - started, 2),
        "timed_out": timed_out,
        "timeout_seconds": timeout_seconds,
        "aborted": aborted_at_kb is not None,
        "aborted_at_available_mib": (
            None if aborted_at_kb is None else round(aborted_at_kb / 1024, 1)
        ),
        "memory": sample.as_dict(),
        "exit_codes": [proc.returncode for proc in procs],
        "summaries": summaries,
    }


def _terminate(proc: subprocess.Popen) -> None:
    """Stop a child *and its descendants*, escalating to a kill if needed.

    The child is started in its own session, so its process group is its own and
    signalling that group cannot reach anything of ours. Signalling the parent
    alone is not enough: Semgrep's work happens in `semgrep-core` and
    `pysemgrep` descendants, and if they survive a killed run then the next level
    of a sweep measures the leftovers of the previous one.
    """
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            continue


# The engines the plan compares, and how each is invoked on a directory. Kept
# here rather than inline so that the invocation is visible next to the reading
# it produces.
SEMGREP_BASE = [
    "semgrep", "scan", "--json", "--quiet", "--disable-version-check", "--no-git-ignore",
]


def semgrep_argv(target: str, rules: str, jobs: int, max_memory_mb: int) -> List[str]:
    """One Semgrep scan with its concurrency and per-file memory cap pinned.

    Both are pinned on purpose. `--max-memory` alone bounds one file, not how
    many are in flight, so the aggregate ceiling is `jobs * max_memory`; leaving
    `--jobs` to the default on a 16-CPU host is what made the earlier OOM
    reachable by construction (plan section 9.1).
    """
    return SEMGREP_BASE + [
        "--config", rules, "--jobs", str(jobs),
        "--max-memory", str(max_memory_mb), target,
    ]


def python_scan_argv(target: str, tools_root: str, engine: str,
                     rules: Optional[str] = None) -> List[str]:
    """One scan through the evaluation's own adapter, as the criterion runs it.

    The adapter is used rather than a re-implementation so that the reading
    describes the path the criterion actually takes.
    """
    args = [sys.executable, "-c", PYTHON_SCAN_SNIPPET, tools_root, engine, target]
    if rules:
        args.append(rules)
    return args


# Runs inside the container: import the staged adapter, scan one directory, emit
# the finding counts as JSON. Inline because the staged tree is not importable
# from the host and the point is to exercise the staged copy.
PYTHON_SCAN_SNIPPET = r"""
import json, sys, time
sys.path.insert(0, sys.argv[1])
from collections import Counter
from models.audit.tools.audit_benchmark_eval import (
    RegexScannerAdapter, SemgrepScannerAdapter,
)
engine, target = sys.argv[2], sys.argv[3]
rules = sys.argv[4] if len(sys.argv) > 4 else None
adapter = (RegexScannerAdapter(rules_path=rules) if engine == "regex"
           else SemgrepScannerAdapter(rules_path=rules))
started = time.monotonic()
outcome = adapter.scan_directory(target)
elapsed = time.monotonic() - started
counts = Counter(f.rule_id for f in outcome.findings)
files = sorted({f.file for f in outcome.findings})
print(json.dumps({
    "engine": engine,
    "findings": len(outcome.findings),
    "per_rule": dict(sorted(counts.items())),
    "files_with_findings": len(files),
    "scan_complete": outcome.scan_complete,
    "timed_out": outcome.timed_out,
    "parser_errors": outcome.parser_errors,
    "error_message": outcome.error_message,
    "scan_seconds": round(elapsed, 2),
}))
"""


def count_python_files(target: str) -> int:
    return sum(1 for _ in Path(target).rglob("*.py"))


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", type=Path, required=True,
                        help="JSON file to append every reading to")
    parser.add_argument("--semgrep-target", default=None)
    parser.add_argument("--python-target", default=None)
    parser.add_argument("--rules", default=None)
    parser.add_argument("--tools-root", default=None,
                        help="Directory whose parent is the repo root importable as "
                             "models.audit.tools (the staged tree inside the container)")
    parser.add_argument("--jobs", type=int, nargs="+", default=[1, 2, 4])
    parser.add_argument("--max-memory-mb", type=int, default=1024)
    parser.add_argument("--engines", nargs="+", default=["regex", "semgrep"])
    parser.add_argument("--interval", type=float, default=SAMPLE_INTERVAL_SECONDS)
    parser.add_argument("--available-floor-mb", type=int, default=2048,
                        help="Stop escalating --jobs once MemAvailable drops below this")
    parser.add_argument("--abort-below-mb", type=int, default=1024,
                        help="Terminate a run in flight once MemAvailable drops below this")
    parser.add_argument("--timeout-seconds", type=float, default=120.0,
                        help="Per-run bound, matching SemgrepRunner's default of 120 s")
    parser.add_argument("--burst-levels", type=int, nargs="*", default=[],
                        help="Concurrent-scan levels to burst, matching the load "
                             "test's LEVELS. Needs --semgrep-target and --rules.")
    args = parser.parse_args(argv)

    abort_below_kb = args.abort_below_mb * 1024
    timeout_seconds = args.timeout_seconds if args.timeout_seconds > 0 else None
    readings: List[Dict[str, object]] = []

    def record(entry: Dict[str, object]) -> None:
        readings.append(entry)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(readings, indent=2, ensure_ascii=False) + "\n")
        print(json.dumps(entry, ensure_ascii=False), flush=True)

    for jobs in args.jobs:
        if args.semgrep_target:
            result = run_measured(
                semgrep_argv(args.semgrep_target, args.rules, jobs, args.max_memory_mb),
                interval=args.interval, abort_below_kb=abort_below_kb,
                summarize=summarize_semgrep_json, timeout_seconds=timeout_seconds,
            )
            result["label"] = f"semgrep jobs={jobs} max-memory={args.max_memory_mb}MB"
            result["jobs"] = jobs
            record(result)
            if result["timed_out"]:
                # A level that cannot finish inside production's own bound is a
                # reading about that level; escalating concurrency on top of it
                # would measure a configuration the pipeline never runs.
                record({"label": "sweep stopped", "at_jobs": jobs, "reason": (
                    f"run did not finish within {timeout_seconds}s, so the higher "
                    "concurrency levels were not attempted")})
                break
            floor = result["memory"].get("min_available_mib")
            if result["aborted"]:
                record({"label": "sweep stopped", "at_jobs": jobs, "reason": (
                    f"run was aborted at {result['aborted_at_available_mib']} MiB "
                    "available, so the next level was never attempted")})
                break
            if floor is not None and floor < args.available_floor_mb:
                # Escalating past a host that is already short of memory is how
                # the earlier OOM happened; the sweep stops instead.
                record({"label": "sweep stopped", "at_jobs": jobs, "reason": (
                    f"MemAvailable fell to {floor} MiB, below the "
                    f"{args.available_floor_mb} MiB floor")})
                break

    for level in args.burst_levels:
        if not (args.semgrep_target and args.rules):
            raise SystemExit("--burst-levels needs --semgrep-target and --rules")
        result = run_burst(
            level,
            lambda i: semgrep_argv(args.semgrep_target, args.rules, args.jobs[-1],
                                   args.max_memory_mb),
            interval=args.interval, abort_below_kb=abort_below_kb,
            summarize=summarize_semgrep_json, timeout_seconds=timeout_seconds,
        )
        result["label"] = (f"burst level={level} jobs={args.jobs[-1]} "
                           f"max-memory={args.max_memory_mb}MB")
        record(result)
        floor = result["memory"].get("min_available_mib")
        if result["timed_out"] or result["aborted"]:
            record({"label": "burst sweep stopped", "at_level": level, "reason": (
                "the burst did not complete inside its bound, so the higher "
                "concurrency levels were not attempted")})
            break
        if floor is not None and floor < args.available_floor_mb:
            record({"label": "burst sweep stopped", "at_level": level, "reason": (
                f"MemAvailable fell to {floor} MiB, below the "
                f"{args.available_floor_mb} MiB floor")})
            break

    for engine in args.engines:
        if not args.python_target:
            continue
        result = run_measured(
            python_scan_argv(args.python_target, args.tools_root, engine, args.rules),
            interval=args.interval, abort_below_kb=abort_below_kb,
            summarize=summarize_adapter_json, timeout_seconds=timeout_seconds,
        )
        result["label"] = f"{engine} adapter"
        result["engine"] = engine
        result["files"] = count_python_files(args.python_target)
        record(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
