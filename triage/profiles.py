"""Format detection and per-format line parsing for known loghub formats."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable


@dataclass
class ParsedLine:
    raw: str
    timestamp: datetime | None
    level: str | None
    service: str | None


@dataclass
class Profile:
    name: str
    parse: Callable[[str], ParsedLine]


_HDFS_RE = re.compile(
    r"^(?P<ts>\d{6} \d{6})\s+\d+\s+(?P<lvl>[A-Z]+)\s+(?P<svc>[^:]+):\s*(?P<msg>.*)$"
)

_ZK_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}),(?P<ms>\d{3})"
    r"\s+-\s+(?P<lvl>[A-Z]+)\s+\[(?P<svc>.+)\]\s+-\s+(?P<msg>.*)$"
)

_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"(?P<svc>[^\s\[:]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)


def _hdfs_parse(line: str) -> ParsedLine:
    m = _HDFS_RE.match(line)
    if not m:
        return ParsedLine(raw=line, timestamp=None, level=None, service=None)
    try:
        ts = datetime.strptime(m.group("ts"), "%y%m%d %H%M%S")
    except ValueError:
        ts = None
    return ParsedLine(
        raw=line,
        timestamp=ts,
        level=m.group("lvl"),
        service=m.group("svc").strip(),
    )


def _zk_parse(line: str) -> ParsedLine:
    m = _ZK_RE.match(line)
    if not m:
        return ParsedLine(raw=line, timestamp=None, level=None, service=None)
    try:
        ts = datetime.strptime(
            f"{m.group('date')} {m.group('time')}.{m.group('ms')}",
            "%Y-%m-%d %H:%M:%S.%f",
        )
    except ValueError:
        ts = None
    return ParsedLine(
        raw=line,
        timestamp=ts,
        level=m.group("lvl"),
        service=m.group("svc").strip(),
    )


# Syslog lines have no year; use a fixed placeholder so gap math is consistent.
_SYSLOG_YEAR = 2000


def _syslog_parse(line: str) -> ParsedLine:
    m = _SYSLOG_RE.match(line)
    if not m:
        return ParsedLine(raw=line, timestamp=None, level=None, service=None)
    try:
        ts = datetime.strptime(
            f"{_SYSLOG_YEAR} {m.group('ts')}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        ts = None
    return ParsedLine(
        raw=line, timestamp=ts, level=None, service=m.group("svc")
    )


def _generic_parse(line: str) -> ParsedLine:
    return ParsedLine(raw=line, timestamp=None, level=None, service=None)


HDFS = Profile(name="hdfs", parse=_hdfs_parse)
ZOOKEEPER = Profile(name="zookeeper", parse=_zk_parse)
SYSLOG = Profile(name="syslog", parse=_syslog_parse)
GENERIC = Profile(name="generic", parse=_generic_parse)

_CANDIDATES = (HDFS, ZOOKEEPER, SYSLOG)


def sniff(sample_lines: Iterable[str], min_hit_rate: float = 0.6) -> Profile:
    """Pick the profile whose parser succeeds on the largest share of sample lines.

    Falls back to GENERIC when no candidate clears `min_hit_rate`.
    """
    samples = [ln for ln in sample_lines if ln.strip()]
    if not samples:
        return GENERIC

    best = GENERIC
    best_score = 0.0
    for prof in _CANDIDATES:
        hits = sum(1 for ln in samples if prof.parse(ln).timestamp is not None)
        score = hits / len(samples)
        if score > best_score:
            best, best_score = prof, score

    return best if best_score >= min_hit_rate else GENERIC
