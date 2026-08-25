"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence, TextIO

from .report import analyze_source, dumps_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze a source-pinned GenLayer contract against the EquivLab Phase 1 baseline."
    )
    parser.add_argument("source", type=Path, help="Python Intelligent Contract source file")
    parser.add_argument("--url", required=True, help="Commit-pinned public source URL")
    parser.add_argument("--sha256", required=True, help="Expected canonical SHA-256")
    return parser


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = analyze_source(args.source.read_bytes(), args.url, args.sha256)
    (stdout or sys.stdout).write(dumps_report(report))
    return 0 if report["status"] in {"MEETS_BASELINE", "WARN"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
