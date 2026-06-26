#!/usr/bin/env python3
"""
Log Triage Pipeline — reads any raw log file, uses Gemma via BAML to identify
anomalies, and outputs validated JSON ready for webhook/database injection.

Usage:
    python triage.py --input <log_file> [--output <out.json>] [--chunk-size 25] [--context 3]
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from baml_client import b
from baml_client.types import LogAnomaly

# Regex that catches any log line worth looking at
ANOMALY_RE = re.compile(
    r"ERROR|FATAL|CRITICAL|WARN(?:ING)?|[Ee]xception|[Ff]ailure|[Cc]rash|"
    r"[Tt]raceback|[Kk]illed|OOM|[Tt]imeout|[Rr]efused|[Dd]enied|"
    r"authentication failure|error state|in error",
    re.IGNORECASE,
)


def load_lines(path: str) -> list[str]:
    with open(path, "r", errors="replace") as f:
        return f.readlines()


def find_candidate_indices(lines: list[str]) -> list[int]:
    """Return indices of lines that match the anomaly pattern."""
    return [i for i, line in enumerate(lines) if ANOMALY_RE.search(line)]


def build_chunks(
    lines: list[str],
    candidate_indices: list[int],
    context: int,
    chunk_size: int,
) -> list[str]:
    """
    Expand each candidate index with ±context lines, merge overlapping windows,
    then group into chunks of at most chunk_size lines.
    """
    n = len(lines)
    # Collect all line indices that should be included
    included: set[int] = set()
    for idx in candidate_indices:
        for j in range(max(0, idx - context), min(n, idx + context + 1)):
            included.add(j)

    if not included:
        return []

    sorted_indices = sorted(included)

    # Group contiguous indices into windows, then split windows into chunks
    chunks: list[str] = []
    window: list[int] = [sorted_indices[0]]

    for idx in sorted_indices[1:]:
        if idx == window[-1] + 1:
            window.append(idx)
        else:
            # flush current window into chunks
            _flush_window(lines, window, chunk_size, chunks)
            window = [idx]

    _flush_window(lines, window, chunk_size, chunks)
    return chunks


def _flush_window(
    lines: list[str], window: list[int], chunk_size: int, chunks: list[str]
) -> None:
    for start in range(0, len(window), chunk_size):
        batch = window[start : start + chunk_size]
        text = "".join(lines[i] for i in batch)
        chunks.append(text)


def anomaly_key(a: LogAnomaly) -> str:
    """Dedup key: service + first 80 chars of raw line."""
    raw = (a.raw_log_line or "")[:80]
    return hashlib.md5(f"{a.service_name}|{raw}".encode()).hexdigest()


def triage_file(
    log_path: str,
    chunk_size: int = 25,
    context: int = 3,
) -> list[dict]:
    lines = load_lines(log_path)
    candidate_indices = find_candidate_indices(lines)

    if not candidate_indices:
        print(
            f"[INFO] No anomaly keywords found in {log_path}. File appears clean.",
            file=sys.stderr,
        )
        return []

    chunks = build_chunks(lines, candidate_indices, context, chunk_size)
    total = len(chunks)
    print(
        f"[INFO] {len(lines)} lines → {len(candidate_indices)} candidates → {total} chunks",
        file=sys.stderr,
    )

    all_anomalies: list[dict] = []
    seen_keys: set[str] = set()

    for i, chunk in enumerate(chunks, 1):
        print(f"[INFO] Chunk {i}/{total} ...", file=sys.stderr)
        try:
            result = b.TriageLogs(chunk)
        except Exception as exc:
            print(f"[WARN] Chunk {i} failed: {exc}", file=sys.stderr)
            continue

        for anomaly in result.anomalies:
            key = anomaly_key(anomaly)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            all_anomalies.append(
                {
                    "service_name": anomaly.service_name,
                    "timestamp": anomaly.timestamp,
                    "error_severity": anomaly.error_severity.value
                    if hasattr(anomaly.error_severity, "value")
                    else str(anomaly.error_severity),
                    "raw_log_line": anomaly.raw_log_line,
                    "suggested_remediation": anomaly.suggested_remediation,
                }
            )

        # Fallback: if Gemma found nothing but there were error keywords in this chunk
        if not result.anomalies and ANOMALY_RE.search(chunk):
            key = hashlib.md5(chunk[:80].encode()).hexdigest()
            if key not in seen_keys:
                seen_keys.add(key)
                all_anomalies.append(
                    {
                        "service_name": "unknown",
                        "timestamp": "unknown",
                        "error_severity": "LOW",
                        "raw_log_line": chunk.strip()[:500],
                        "suggested_remediation": "Manual review required — model could not extract structured data from this log segment.",
                    }
                )

    # Sort by severity priority
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_anomalies.sort(key=lambda a: severity_order.get(a["error_severity"], 99))

    return all_anomalies


def main() -> None:
    parser = argparse.ArgumentParser(description="Log Triage Pipeline using Gemma + BAML")
    parser.add_argument("--input", required=True, help="Path to the log file")
    parser.add_argument(
        "--output", default=None, help="Output JSON file (defaults to stdout)"
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=25,
        help="Candidate lines per BAML call (default: 25)",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=3,
        help="Context lines around each anomaly hit (default: 3)",
    )
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"[ERROR] File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    anomalies = triage_file(args.input, args.chunk_size, args.context)

    output = json.dumps(anomalies, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(
            f"[INFO] {len(anomalies)} anomalies written to {args.output}",
            file=sys.stderr,
        )
    else:
        print(output)


if __name__ == "__main__":
    main()
