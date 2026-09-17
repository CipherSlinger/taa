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

    def __init__(self, executable: str = "semgrep", rules_path: Optional[str] = None):
        self.executable = executable
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

    def parse_output(self, raw_data: Dict[str, Any], exit_code: int = 0) -> SemgrepScanResult:
        """Parses Semgrep raw JSON output into structured findings and scan metadata."""
        findings = []
        raw_results = raw_data.get("results", [])
        raw_errors = raw_data.get("errors", [])
        parser_errors = len(raw_errors)

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
                "code_snippet": extra.get("lines", "").strip(),
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
            "--no-git-ignore"
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
            return self.parse_output(raw_data, exit_code=proc.returncode)

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
