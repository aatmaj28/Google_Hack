"""CLI entry point: `python -m triage <logfile> [--out results.jsonl]`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pipeline import run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="triage",
        description="Stream a log file through Gemma and emit anomaly JSONL.",
    )
    parser.add_argument("log", type=Path, help="path to the log file")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("results.jsonl"),
        help="results JSONL file (appended, default: results.jsonl)",
    )
    args = parser.parse_args(argv)

    if not args.log.exists():
        print(f"error: {args.log} does not exist", file=sys.stderr)
        return 1

    run(args.log, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
