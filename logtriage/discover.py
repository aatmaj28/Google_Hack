"""
Stage 1 — Adaptive structure discovery.

Given ANY log line from ANY system, discover its structure at runtime:
    timestamp, severity level, component/source, and the message body.

Design principle: NOTHING is hardcoded per dataset. We apply a *universal
library* of timestamp shapes and severity keywords (the same way Splunk /
Logstash / Datadog auto-detect log structure) and a small set of generic
field-boundary heuristics. The exact same code parses HDFS, Linux, Apache,
Windows, BGL, etc. with zero per-format configuration.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from dateutil import parser as dateparser


# ---------------------------------------------------------------------------
# Severity vocabulary — universal across systems, mapped to a normalized scale.
# ---------------------------------------------------------------------------
_SEVERITY_RANK = {
    "TRACE": 1, "DEBUG": 1, "FINE": 1, "VERBOSE": 1,
    "INFO": 2, "NOTICE": 2, "INFORMATION": 2, "AUDIT": 2,
    "WARN": 3, "WARNING": 3,
    "ERROR": 4, "ERR": 4, "FAIL": 4, "FAILURE": 4, "FAILED": 4, "SEVERE": 4,
    "FATAL": 5, "CRITICAL": 5, "CRIT": 5, "ALERT": 5, "EMERG": 5,
    "EMERGENCY": 5, "PANIC": 5,
}
# Normalized output buckets so downstream code never sees raw vendor labels.
_RANK_TO_SEVERITY = {1: "DEBUG", 2: "INFO", 3: "WARNING", 4: "ERROR", 5: "CRITICAL"}

_LEVEL_RE = re.compile(
    r"\b(" + "|".join(sorted(_SEVERITY_RANK, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Timestamp shape library. Each entry: (compiled regex, normalizer).
# Tried in order, most-specific first. This is a *format-agnostic* catalogue —
# applied uniformly to every file, never branched on the dataset.
# ---------------------------------------------------------------------------
def _norm_dateutil(s: str) -> Optional[datetime]:
    try:
        return dateparser.parse(s.replace(",", ".").strip("[]"), fuzzy=True)
    except (ValueError, OverflowError):
        return None


def _norm_compact(s: str) -> Optional[datetime]:
    # HDFS: "081109 203615"  -> YYMMDD HHMMSS
    try:
        return datetime.strptime(s, "%y%m%d %H%M%S")
    except ValueError:
        return None


def _norm_slash(s: str) -> Optional[datetime]:
    # Spark: "17/06/09 20:10:40" -> YY/MM/DD HH:MM:SS
    try:
        return datetime.strptime(s, "%y/%m/%d %H:%M:%S")
    except ValueError:
        return None


def _norm_healthapp(s: str) -> Optional[datetime]:
    # HealthApp: "20171223-22:15:29:606" (time fields may be non-zero-padded)
    try:
        return datetime.strptime(s, "%Y%m%d-%H:%M:%S:%f")
    except ValueError:
        return None


def _norm_android(s: str) -> Optional[datetime]:
    # Android: "03-17 16:13:38.811" (no year)
    try:
        return datetime.strptime(s, "%m-%d %H:%M:%S.%f")
    except ValueError:
        return None


def _norm_proxifier(s: str) -> Optional[datetime]:
    # Proxifier: "[10.30 16:49:06]" (MM.DD, no year)
    try:
        return datetime.strptime(s.strip("[]"), "%m.%d %H:%M:%S")
    except ValueError:
        return None


def _norm_bgl(s: str) -> Optional[datetime]:
    # BGL: "2005-06-03-15.42.50.675872"
    try:
        return datetime.strptime(s, "%Y-%m-%d-%H.%M.%S.%f")
    except ValueError:
        return None


def _norm_epoch(s: str) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(int(s), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


_TIMESTAMP_PATTERNS = [
    # ISO-ish: 2016-09-28 04:30:30(,455 / .455)
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), _norm_dateutil),
    # BGL: 2005-06-03-15.42.50.675872
    (re.compile(r"\b\d{4}-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}\.\d+\b"), _norm_bgl),
    # Apache full: [Sun Dec 04 04:47:44 2005]
    (re.compile(r"\[?[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\]?"), _norm_dateutil),
    # HealthApp: 20171223-22:15:29:606  (time fields may be non-zero-padded)
    (re.compile(r"\b\d{8}-\d{1,2}:\d{1,2}:\d{1,2}:\d{1,3}\b"), _norm_healthapp),
    # HDFS compact: 081109 203615
    (re.compile(r"\b\d{6}\s+\d{6}\b"), _norm_compact),
    # Spark: 17/06/09 20:10:40
    (re.compile(r"\b\d{2}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\b"), _norm_slash),
    # Android: 03-17 16:13:38.811
    (re.compile(r"\b\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\b"), _norm_android),
    # Proxifier: [10.30 16:49:06]
    (re.compile(r"\[\d{2}\.\d{2}\s+\d{2}:\d{2}:\d{2}\]"), _norm_proxifier),
    # Syslog: Jun 14 15:16:01  /  Jul  1 09:00:55  (no year)
    (re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"), _norm_dateutil),
    # Bare epoch seconds (BGL/Thunderbird/HPC). Lowest priority — most ambiguous.
    (re.compile(r"\b1\d{9}\b"), _norm_epoch),
]


# ---------------------------------------------------------------------------
# Component / source heuristics. Best-effort and never blocking: the message
# body + event template carry the anomaly signal, so a miss here is harmless.
#
# All component patterns are ANCHORED to the start of the metadata-stripped
# body, so a mid-message colon (e.g. "...time out: 3200") can never be
# mistaken for a component delimiter and truncate the message.
# ---------------------------------------------------------------------------
_COMPONENT_PATTERNS = [
    # syslog: [<host/location>] <component>[pid]:  e.g. "combo sshd(pam_unix)[19939]:"
    # The required "[pid]:" shape makes this safe from sentence colons.
    (re.compile(r"^(?:\S+\s+){0,2}?([A-Za-z][\w.\-]*(?:\([\w.\-]+\))?)\[\d+\]\s*:\s*"), True),
    # dotted java/module identifier + colon (optional leading [thread]):
    #   "[main] org.apache.hadoop...MRAppMaster:"  /  "dfs.DataNode$PacketResponder:"
    # Requires a dot or $ segment so plain sentence words can't false-match.
    (re.compile(r"^(?:\[[^\]]*\]\s+)?([A-Za-z][\w]*(?:[.$][\w]+)+)\s*:\s+"), True),
    # dotted module name followed by a bracket/content (OpenStack java):
    #   "nova.osapi_compute.wsgi.server [req-...]"
    (re.compile(r"^([a-zA-Z][\w]*(?:\.[\w]+)+)\s+(?=[\[\"])"), False),
]

# Leading metadata that precedes the component/message across formats:
# stray separators, process-id integers, and a severity keyword.
_LEADING_NOISE_RE = re.compile(
    r"^(?:[\-,|:#]+|\s+|\d+\b|"
    + r"\b(?:" + "|".join(_SEVERITY_RANK) + r")\b)\s*",
    re.IGNORECASE,
)
_BLOCKID_RE = re.compile(r"blk_-?\d+")


@dataclass
class LogRecord:
    line_no: int
    raw: str
    timestamp: Optional[str] = None          # normalized ISO string
    sort_key: float = 0.0                     # epoch seconds if known, else line_no
    severity: Optional[str] = None            # normalized: DEBUG/INFO/WARNING/ERROR/CRITICAL
    severity_rank: int = 0                    # 0 = unknown
    component: Optional[str] = None
    message: str = ""
    template_id: Optional[str] = None         # filled by Stage 2
    template: Optional[str] = None
    session_key: Optional[str] = None         # filled by Stage 3
    extras: dict = field(default_factory=dict)


def _find_timestamp(line: str):
    """Return (iso_string, sort_key, match_end) or (None, None, 0)."""
    for rx, norm in _TIMESTAMP_PATTERNS:
        m = rx.search(line)
        if not m:
            continue
        dt = norm(m.group(0))
        if dt is None:
            continue
        sort_key = dt.timestamp() if dt.tzinfo else dt.replace(tzinfo=timezone.utc).timestamp()
        return dt.isoformat(), sort_key, m.end()
    return None, None, 0


def _find_severity(line: str):
    """Return (normalized_severity, rank) using the highest-ranked keyword found."""
    best_rank = 0
    for m in _LEVEL_RE.finditer(line):
        rank = _SEVERITY_RANK[m.group(1).upper()]
        if rank > best_rank:
            best_rank = rank
    if best_rank == 0:
        return None, 0
    return _RANK_TO_SEVERITY[best_rank], best_rank


def _strip_leading_noise(body: str) -> str:
    """Remove leading separators / pids / a severity keyword to expose the core."""
    prev = None
    core = body
    while core and core != prev:
        prev = core
        core = _LEADING_NOISE_RE.sub("", core, count=1)
    return core.strip()


def _split_component_message(core: str):
    """Return (component, message). Component anchored at start; message never
    truncated by a mid-line colon."""
    for rx, consume_colon in _COMPONENT_PATTERNS:
        m = rx.match(core)
        if m and len(m.group(1)) <= 64:
            component = m.group(1)
            message = core[m.end():].strip() if consume_colon else core[m.start(1) + len(component):].strip()
            return component, (message or core)
    return None, core


def parse_line(line: str, line_no: int) -> Optional[LogRecord]:
    raw = line.rstrip("\n")
    if not raw.strip():
        return None

    ts_iso, sort_key, ts_end = _find_timestamp(raw)
    severity, rank = _find_severity(raw)
    # Body = everything after the timestamp region (where the component+message live).
    body = raw[ts_end:].strip() if ts_end else raw
    core = _strip_leading_noise(body)
    component, message = _split_component_message(core)

    rec = LogRecord(
        line_no=line_no,
        raw=raw,
        timestamp=ts_iso,
        sort_key=sort_key if sort_key is not None else float(line_no),
        severity=severity,
        severity_rank=rank,
        component=component,
        message=message or body,
    )
    blk = _BLOCKID_RE.search(raw)
    if blk:
        rec.extras["block_id"] = blk.group(0)
    return rec


def parse_file(path: str) -> list[LogRecord]:
    records: list[LogRecord] = []
    with open(path, "r", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            rec = parse_line(line, i)
            if rec:
                records.append(rec)
    return records
