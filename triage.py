#!/usr/bin/env python3
"""
Universal log-triage CLI.

    python triage.py <logfile> [--top-k N] [--out result.json] [--no-model]

Reads ANY raw log file, discovers its structure, finds the most suspicious
events, and prints validated JSON incident cards. The same command works on
HDFS, Linux, Apache, BGL, Windows, ... with zero per-format configuration.
"""
from __future__ import annotations

import argparse
import json
import sys

from logtriage.pipeline import run


def main() -> int:
    ap = argparse.ArgumentParser(description="Universal log -> JSON incident triage")
    ap.add_argument("logfile", help="path to a raw .log/.txt file")
    ap.add_argument("--top-k", type=int, default=5, help="max incidents to emit (default 5)")
    ap.add_argument("--out", help="write JSON here instead of stdout")
    ap.add_argument("--no-model", action="store_true",
                    help="skip the LLM and use deterministic fallback cards only")
    args = ap.parse_args()

    result = run(args.logfile, top_k=args.top_k, use_model=not args.no_model)
    payload = json.dumps(result, indent=2)

    if args.out:
        with open(args.out, "w") as fh:
            fh.write(payload)
        stats = result["stats"]
        print(f"Wrote {len(result['incidents'])} incidents to {args.out} "
              f"({stats['lines_parsed']} lines, {stats['event_templates']} templates, "
              f"session_key={stats['session_key']}, {stats['elapsed_sec']}s)",
              file=sys.stderr)
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
