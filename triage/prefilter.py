"""Cheap regex prefilter: skip benign bursts before any LLM call."""

from __future__ import annotations

import re

from .windowing import Burst

# Case-insensitive: word-bounded severity tokens + common failure verbs.
_INTEREST = re.compile(
    r"\b(?:ERROR|FATAL|SEVERE|CRITICAL|PANIC|EMERG|ALERT|"
    r"Exception|Traceback|Stacktrace|"
    r"failed|failure|denied|refused|unreachable|"
    r"timeout|timed out|"
    r"OOM|out of memory|core dumped|segfault|"
    r"corrupt|invalid|unauthorized)\b",
    re.IGNORECASE,
)


def is_interesting(burst: Burst) -> bool:
    """True iff any line in the burst hits a failure-keyword pattern."""
    for ln in burst.lines:
        if ln.level and ln.level.upper() in {
            "ERROR",
            "FATAL",
            "SEVERE",
            "CRITICAL",
        }:
            return True
        if _INTEREST.search(ln.raw):
            return True
    return False
