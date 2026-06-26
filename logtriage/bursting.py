"""
Temporal burst context (idea borrowed from the `shivu` branch, adapted to our
LogRecord model).

Our anomaly detector picks a single representative line per suspicious event.
For logs *with* a correlation id we already hand the LLM the full session
timeline. For logs *without* one (Apache, BGL, Windows, Spark...) a lone line
loses the lead-up and any multi-line continuation (stack traces). This module
reconstructs the local burst around a line so the LLM sees what led to the
failure — without sending the whole file.

A burst = the target line, its immediate time-clustered neighbours (cut at a
real time gap), and the untimed continuation lines that follow it.
"""
from __future__ import annotations

from .discover import LogRecord


def _gap_ok(a: LogRecord, b: LogRecord, gap_seconds: float) -> bool:
    """True if a and b are close in time. Falls back to True when either line
    is untimed (we keep continuation lines like stack traces)."""
    if a.timestamp is None or b.timestamp is None:
        return True
    return abs(b.sort_key - a.sort_key) <= gap_seconds


def burst_around(records: list[LogRecord], center_idx: int, *,
                 gap_seconds: float = 5.0, max_before: int = 12,
                 max_after: int = 12) -> list[str]:
    """Return the raw lines forming the burst around records[center_idx]."""
    n = len(records)
    before: list[str] = []
    i = center_idx - 1
    while i >= 0 and len(before) < max_before and _gap_ok(records[i], records[i + 1], gap_seconds):
        before.append(records[i].raw)
        i -= 1
    before.reverse()

    after: list[str] = []
    j = center_idx + 1
    while j < n and len(after) < max_after and _gap_ok(records[j - 1], records[j], gap_seconds):
        after.append(records[j].raw)
        j += 1

    return before + [records[center_idx].raw] + after
