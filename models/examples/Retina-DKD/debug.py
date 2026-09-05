#!/usr/bin/env python3
"""Phase-1 quick training wrapper for Retina-DKD.

Usage:
  debug.py --output <output_dir>
"""

from __future__ import annotations

import argparse
from pathlib import Path

from train import run_training

SCRIPT_DIR = Path(__file__).resolve().parent
PHASE1_DATA_DIR = SCRIPT_DIR / "data"


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--output", "-o", dest="output_dir")
    args, _ = parser.parse_known_args()

    if not args.output_dir:
        print("Error: --output directory is required")
        print(f"Usage: {Path(__file__).name} --output <output_dir>")
        return 1

    output_path = Path(args.output_dir).expanduser().resolve(strict=False)
    output_path.mkdir(parents=True, exist_ok=True)
    return run_training(PHASE1_DATA_DIR, output_path)


if __name__ == "__main__":
    raise SystemExit(main())
