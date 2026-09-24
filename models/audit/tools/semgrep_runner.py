import os
import sys
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional

@dataclass
class SemgrepScanResult:
    """Represents the outcome of a Semgrep static scan."""
    scan_complete: bool = False
    passed: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)
    parser_errors: int = 0
    timed_out: bool = False
    exit_code: int = 0
    error_message: Optional[str] = None
    scanned_files_count: int = 0

class SemgrepRunner:
    """Executes Semgrep CLI, handles process execution, and normalizes findings."""

    SEVERITY_MAP = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        "CRITICAL": "CRITICAL"
    }

    # Semgrep CE replaces extra.lines (and fingerprint/metavars/is_ignored) with
    # this literal string unless the CLI is logged in to the AppSec Platform.
    # The field maps to code_snippet, which is handed to the LLM as "the code
    # that triggered the rule", so it must never be forwarded as evidence.
    SNIPPET_PLACEHOLDER = "requires login"

    def __init__(self, executable: str = "semgrep", rules_path: Optional[str] = None,
                 jobs: int = 4):
        self.executable = executable
        # Pinned, not left to the engine's default of "one worker per core". The
        # host has 16 cores and Semgrep's per-file cap does not bound how many
        # files are in flight, so an unpinned --jobs is the one knob with no
        # ceiling on it. Proven not to change the verdict: over the 311-sample
        # holdout corpus, --jobs 1 and --jobs 16 both yield 178 findings across
        # 311 scanned files, with identical (rule, sample, line) triples.
        #
        # --max-memory is deliberately NOT pinned here, although the load-test
        # script pins it. It is a per-file cap that makes Semgrep *skip* a file
        # that exceeds it, so adding it could remove findings; that is a change
        # in semantics, not in scheduling, and it does not belong in the path
        # the criterion is measured on.
        self.jobs = jobs
        if rules_path:
            self.rules_path = Path(rules_path)
        else:
            self.rules_path = Path(__file__).resolve().parents[1] / "semgrep" / "rules"

    def is_available(self) -> bool:
        """Checks if the Semgrep executable is available on the system."""
        if shutil.which(self.executable):
            return True
        user_local = Path.home() / ".local" / "bin" / self.executable
        if user_local.is_file() and os.access(user_local, os.X_OK):
            self.executable = str(user_local)
            return True
        return False

    def parse_output(self, raw_data: Dict[str, Any], exit_code: int = 0,
                     scan_root: Optional[str] = None) -> SemgrepScanResult:
        """Parses Semgrep raw JSON output into structured findings and scan metadata."""
        findings = []
        raw_results = raw_data.get("results", [])
        raw_errors = raw_data.get("errors", [])
        parser_errors = len(raw_errors)
        # Line cache scoped to this parse: one scan usually hits a file several
        # times, and re-reading it per match would dominate the parse cost.
        source_cache: Dict[str, List[str]] = {}

        for match in raw_results:
            extra = match.get("extra", {})
            metadata = extra.get("metadata", {})
            rule_id = metadata.get("rule_family") or match.get("check_id", "UNKNOWN")
            raw_sev = extra.get("severity", "WARNING").upper()
            severity = self.SEVERITY_MAP.get(raw_sev, "MEDIUM")

            # Extract taint dataflow trace if available
            taint_trace = []
            df_trace = extra.get("dataflow_trace", {})
            step_counter = 1

            # Taint source
            for node in df_trace.get("taint_source", []):
                taint_trace.append({
                    "step": step_counter,
                    "type": "SOURCE",
                    "file": node.get("path", match.get("path")),
                    "line": node.get("start", {}).get("line", 0),
                    "code": node.get("content", "").strip()
                })
                step_counter += 1

            # Intermediate nodes (propagators)
            for node in df_trace.get("intermediate_vars", []):
                taint_trace.append({
                    "step": step_counter,
                    "type": "PROPAGATOR",
                    "file": node.get("path", match.get("path")),
                    "line": node.get("start", {}).get("line", 0),
                    "code": node.get("content", "").strip()
                })
                step_counter += 1

            code_snippet, slice_error = self._resolve_snippet(
                match, extra, source_cache, scan_root=scan_root
            )

            finding = {
                "file": match.get("path", ""),
                "line": match.get("start", {}).get("line", 0),
                "col": match.get("start", {}).get("col", 0),
                "end_line": match.get("end", {}).get("line", 0),
                "rule_id": rule_id,
                "check_id": match.get("check_id", ""),
                "category": metadata.get("category", "General"),
                "severity": severity,
                "description": extra.get("message", ""),
                "code_snippet": code_snippet,
                "slice_error": slice_error,
                "taint_trace": taint_trace,
                "engine": "semgrep"
            }
            findings.append(finding)

        # Semgrep returns 0 if clean, 1 if findings are found (with --error / default behavior), or 0 on quiet
        scan_complete = (exit_code in (0, 1)) and parser_errors == 0
        passed = scan_complete and len(findings) == 0

        return SemgrepScanResult(
            scan_complete=scan_complete,
            passed=passed,
            findings=findings,
            parser_errors=parser_errors,
            timed_out=False,
            exit_code=exit_code
        )

    def _resolve_snippet(self, match: Dict[str, Any], extra: Dict[str, Any],
                         cache: Dict[str, List[str]],
                         scan_root: Optional[str] = None) -> tuple:
        """Returns (code_snippet, slice_error) for one Semgrep match.

        Semgrep's own line text is used when it is real, since it reflects what
        the engine actually matched. Otherwise the line range is sliced out of
        the file: start.line and end.line stay correct in the community edition
        even though extra.lines does not.
        """
        raw_lines = extra.get("lines")
        if isinstance(raw_lines, str):
            text = raw_lines.strip()
            if text and text != self.SNIPPET_PLACEHOLDER:
                return text, None

        path = match.get("path", "")
        start = match.get("start", {}).get("line", 0) or 0
        end = match.get("end", {}).get("line", 0) or start

        # Semgrep echoes the path it was given, but a relative one is only
        # meaningful against the scan root.
        if path and scan_root and not os.path.isabs(path):
            joined = os.path.join(str(scan_root), path)
            if os.path.exists(joined):
                path = joined

        if not path:
            return "", "match carries no file path"
        if start < 1:
            return "", f"match carries no usable start line in {path}"

        if path not in cache:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    cache[path] = f.readlines()
            except OSError as exc:
                return "", f"cannot read {path}: {exc}"

        snippet = "".join(cache[path][start - 1:max(end, start)]).strip()
        if not snippet:
            return "", f"line range {start}-{end} yields no text in {path}"
        return snippet, None

    def scan_directory(self, target_dir: str, timeout: int = 120, extensions: Optional[List[str]] = None) -> SemgrepScanResult:
        """Executes Semgrep scan against target directory with timeout protection."""
        if not self.is_available():
            return SemgrepScanResult(
                scan_complete=False,
                passed=False,
                error_message=f"Semgrep executable '{self.executable}' not found in PATH"
            )

        cmd = [
            self.executable,
            "scan",
            "--config", str(self.rules_path),
            "--json",
            "--quiet",
            "--disable-version-check",
            "--no-git-ignore",
            "--jobs", str(self.jobs)
        ]

        if extensions:
            for ext in extensions:
                ext_pattern = f"*{ext}" if ext.startswith(".") else f"*.{ext}"
                cmd.extend(["--include", ext_pattern])

        cmd.append(str(target_dir))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            try:
                raw_data = json.loads(proc.stdout) if proc.stdout.strip() else {"results": [], "errors": []}
            except json.JSONDecodeError:
                return SemgrepScanResult(
                    scan_complete=False,
                    passed=False,
                    exit_code=proc.returncode,
                    error_message=f"Failed to parse Semgrep JSON output: {proc.stderr}"
                )
            return self.parse_output(raw_data, exit_code=proc.returncode,
                                     scan_root=str(target_dir))

        except subprocess.TimeoutExpired:
            return SemgrepScanResult(
                scan_complete=False,
                passed=False,
                timed_out=True,
                error_message=f"Semgrep scan timed out after {timeout} seconds"
            )
        except Exception as e:
            return SemgrepScanResult(
                scan_complete=False,
                passed=False,
                error_message=f"Execution failed: {str(e)}"
            )
