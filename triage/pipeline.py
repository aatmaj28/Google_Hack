"""End-to-end pipeline: file -> sniff -> stream -> bursts -> prefilter -> Gemma -> JSONL.

Output is streamed: each anomaly is written to stdout AND appended to the
results file the moment it is produced, with explicit flushing so the
viewer sees results while the file is still being processed.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import sys
from pathlib import Path
from typing import Iterator, TextIO

from baml_client import b

from .prefilter import is_interesting
from .profiles import GENERIC, Profile, sniff
from .windowing import Burst, bursts


def _sniff_head(path: Path, n: int = 20) -> Profile:
    with path.open() as f:
        head = list(itertools.islice(f, n))
    return sniff(head)


def _dedupe_key(timestamp: str, evidence_line: str) -> str:
    return hashlib.sha1(f"{timestamp}|{evidence_line}".encode()).hexdigest()


def _iter_anomalies(
    path: Path, profile: Profile
) -> Iterator[tuple[Burst, object]]:
    """Yield (burst, anomaly_or_None) for every burst the prefilter passes."""
    with path.open() as f:
        for burst in bursts(f, profile):
            if not is_interesting(burst):
                continue
            try:
                anomaly = b.TriageBurst(
                    burst=burst.as_text(), format_hint=profile.name
                )
            except Exception as e:
                print(f"[warn] LLM call failed: {e}", file=sys.stderr, flush=True)
                continue
            yield burst, anomaly


def run(
    log_path: Path,
    out_path: Path,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Process a log file end-to-end. Returns the number of anomalies emitted."""
    profile = _sniff_head(log_path)
    print(
        f"[info] {log_path.name}: detected profile={profile.name}",
        file=stderr,
        flush=True,
    )
    if profile is GENERIC:
        print(
            "[warn] generic profile: timestamps unparsed, bursts may be coarse",
            file=stderr,
            flush=True,
        )

    seen: set[str] = set()
    emitted = 0

    with out_path.open("a") as out:
        for burst, anomaly in _iter_anomalies(log_path, profile):
            if anomaly is None:
                continue
            key = _dedupe_key(anomaly.timestamp, anomaly.evidence_line)
            if key in seen:
                continue
            seen.add(key)

            payload = anomaly.model_dump_json()
            stdout.write(payload + "\n")
            stdout.flush()
            out.write(payload + "\n")
            out.flush()
            emitted += 1

    print(
        f"[info] {log_path.name}: emitted {emitted} unique anomalies",
        file=stderr,
        flush=True,
    )
    return emitted
