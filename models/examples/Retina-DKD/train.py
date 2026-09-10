#!/usr/bin/env python3
"""Quick training wrapper for Retina-DKD.

Usage:
  train.py --data-dir <data_dir> --output <output_dir>

--data-dir and --input are aliases for the same data directory (TAA passes
--data-dir when invoking training scripts).
"""

from __future__ import annotations

import argparse
import os
import runpy
import signal
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CODE_DIR = SCRIPT_DIR / "Retina-DKD"
TRAINING_SCRIPT = CODE_DIR / "train_fusion.py"
TIMEOUT_SECONDS = 600


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_path(path_text: str) -> Path:
    return Path(path_text).expanduser().resolve(strict=False)


def run_python_entrypoint(script_path: Path, argv: list[str], timeout_seconds: int | None = None) -> int:
    original_argv = sys.argv[:]
    original_sys_path = sys.path[:]
    previous_handler = None

    def handle_timeout(signum, frame):  # noqa: ARG001 - required signal handler signature
        raise TimeoutError

    try:
        if timeout_seconds is not None and hasattr(signal, "SIGALRM"):
            previous_handler = signal.signal(signal.SIGALRM, handle_timeout)
            signal.alarm(timeout_seconds)

        sys.path.insert(0, str(script_path.parent))
        sys.argv = [str(script_path), *argv]
        runpy.run_path(str(script_path), run_name="__main__")
        return 0
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        print(code, file=sys.stderr)
        return 1
    except TimeoutError:
        print(f"{script_path.name} timed out after {timeout_seconds}s", file=sys.stderr)
        return 124
    except Exception:  # pragma: no cover - surfaced in shell output
        traceback.print_exc()
        return 1
    finally:
        sys.argv = original_argv
        sys.path = original_sys_path
        if timeout_seconds is not None and hasattr(signal, "SIGALRM"):
            signal.alarm(0)
            if previous_handler is not None:
                signal.signal(signal.SIGALRM, previous_handler)


def ensure_symlink(link_path: Path, target_path: Path) -> None:
    if link_path.is_symlink() or link_path.exists():
        if link_path.is_dir() and not link_path.is_symlink():
            import shutil

            shutil.rmtree(link_path)
        else:
            link_path.unlink()
    link_path.symlink_to(target_path)


def run_training(input_dir: Path, output_dir: Path) -> int:
    original_cwd = Path.cwd()
    started_at = utc_timestamp()
    started_epoch = time.time()

    print(f"Running Retina-DKD quick training from {CODE_DIR}")
    print(
        "Command: python3 train_fusion.py -b TransMUF -g cpu -bc 4 -e 1 -d _dkd -s 64 -lr 1 -nw 0"
    )
    print(f"Timeout: {TIMEOUT_SECONDS}s")

    try:
        os.chdir(CODE_DIR)
        actual_input_dir = input_dir / "data" if (input_dir / "data").is_dir() else input_dir
        try:
            ensure_symlink(CODE_DIR / "data", actual_input_dir)
            ensure_symlink(CODE_DIR / "model", output_dir)
        except OSError:
            pass

        exit_code = run_python_entrypoint(
            TRAINING_SCRIPT,
            [
                "--data-root",
                str(actual_input_dir),
                "--output-dir",
                str(output_dir),
                "-b",
                "TransMUF",
                "-g",
                "cpu",
                "-bc",
                "4",
                "-e",
                "1",
                "-d",
                "_dkd",
                "-s",
                "64",
                "-lr",
                "1",
                "-nw",
                "0",
            ],
            timeout_seconds=TIMEOUT_SECONDS,
        )
    finally:
        os.chdir(original_cwd)

    finished_at = utc_timestamp()
    duration = int(time.time() - started_epoch)
    status = (
        "succeeded"
        if exit_code == 0
        else "timeout"
        if exit_code == 124
        else "failed"
    )

    print(
        f"Training finished: status={status}, exit_code={exit_code}, "
        f"duration={duration}s, started_at={started_at}, finished_at={finished_at}"
    )
    print("Training result is written by train_fusion.py; TAA will generate the final report.")
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--data-dir", "--input", "-i", dest="input_dir", default="/opt/taa/input/data")
    parser.add_argument("--output", "--output-dir", "-o", dest="output_dir", default="/opt/taa/output")
    args, unknown = parser.parse_known_args()
    if unknown:
        raise SystemExit(f"unrecognized arguments: {' '.join(unknown)}")

    input_dir = resolve_path(args.input_dir)
    output_dir = resolve_path(args.output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    exit_code = run_training(input_dir, output_dir)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
