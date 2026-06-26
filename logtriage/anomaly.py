"""
Stage 3 — Multi-signal anomaly scoring (deterministic, no LLM).

This is what makes the pipeline work on *any* log, even ones with no error
keyword and no session id. We combine several format-agnostic signals:

  * severity   — explicit ERROR/FATAL/CRITICAL levels (when the log has them)
  * keyword    — failure words in the message (for logs with no level field)
  * rarity     — templates that almost never occur (idf): an unusual event is
                 suspicious even when every line says "INFO" -> this is the
                 "grep can't catch it" signal, generalized
  * session    — BONUS: auto-detect a correlation id (block id / request id /
                 pid / ip), group by it, and surface the event sequence so the
                 LLM can reason about *what led to what*

Only the top-K distinct anomalous event types are forwarded to the LLM, so the
bulk of the log never costs a token.
"""
from __future__ import annotations

import math
import re
from collections import defaultdict

from .bursting import burst_around
from .discover import LogRecord

# Failure words — catch anomalies in logs that carry no severity field at all.
_KEYWORD_RE = re.compile(
    r"\b(exception|error|errors|failed|failure|fatal|panic|segfault|crash(?:ed)?|"
    r"timed?\s?out|timeout|refused|denied|unreachable|unavailable|cannot|"
    r"could\s?not|unable|abort(?:ed)?|corrupt(?:ed)?|deadlock|oom|killed|"
    r"rejected|invalid|broken|lost|down)\b",
    re.IGNORECASE,
)

# Candidate session-key shapes. Tier 1 = explicit transaction/correlation ids
# (semantically the real "unit of work"); tier 2 = infrastructure ids used only
# when no transaction id partitions the file. Within a tier we pick whichever
# shape actually partitions THIS file best (see detect_session_key).
_SESSION_PATTERNS = [
    (1, "block_id", re.compile(r"blk_-?\d+")),
    (1, "request_id", re.compile(r"req-[0-9a-fA-F\-]{8,}")),
    (1, "uuid", re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")),
    (1, "instance_id", re.compile(r"\b(?:instance|container|app(?:lication)?|job|task)[_\-][\w\-]+", re.I)),
    (2, "ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    (2, "pid", re.compile(r"\[(\d{2,})\]")),
]


def _severity_points(rank: int) -> float:
    return {5: 3.0, 4: 2.0, 3: 0.6}.get(rank, 0.0)


def grep_comparison(candidates: list[dict]) -> dict:
    """How many flagged anomalies a naive keyword `grep` would catch vs miss.

    A candidate is "grep-visible" if it carries a severity or keyword signal;
    if it was flagged by rarity ALONE, a keyword search would never find it.
    This quantifies our core edge (e.g. HDFS, where anomalies are all INFO).
    """
    visible = sum(
        1 for c in candidates
        if any(s == "keyword" or s.startswith("severity:") for s in c["signals"])
    )
    return {
        "engine_found": len(candidates),
        "grep_would_find": visible,
        "grep_would_miss": len(candidates) - visible,
    }


def score_records(records: list[LogRecord], vocab: dict[str, dict]) -> None:
    """Annotate each record with extras['score'] and extras['signals']."""
    total = max(len(records), 1)
    for rec in records:
        signals = []
        score = 0.0

        pts = _severity_points(rec.severity_rank)
        if pts:
            score += pts
            signals.append(f"severity:{rec.severity}")

        if _KEYWORD_RE.search(rec.message):
            score += 1.5
            signals.append("keyword")

        # Rarity (idf): rare templates score higher. Gated so it only fires for
        # genuinely rare events, not every one-off INFO line.
        count = vocab.get(rec.template_id, {}).get("count", total)
        if count <= max(3, total * 0.005):
            idf = math.log(total / count)
            score += min(idf, 3.0)
            signals.append(f"rare:{count}")

        rec.extras["score"] = round(score, 3)
        rec.extras["signals"] = signals


def detect_session_key(records: list[LogRecord]):
    """Auto-pick the id shape that best partitions this file.

    Returns (key_type, regex) or None. A good key covers many lines with
    moderate cardinality (not one group per line, not one giant group).
    """
    n = len(records)
    best_by_tier: dict[int, tuple] = {}
    for tier, key_type, rx in _SESSION_PATTERNS:
        groups = defaultdict(int)
        covered = 0
        for rec in records:
            m = rx.search(rec.raw)
            if m:
                covered += 1
                groups[m.group(0)] += 1
        if covered == 0 or len(groups) < 2:
            continue
        coverage = covered / n
        avg_group = covered / len(groups)
        # want high coverage, >1 group, avoid ~1-line-per-group degenerate keys
        if coverage < 0.30 or avg_group < 1.5:
            continue
        quality = coverage * min(avg_group, 50)
        cur = best_by_tier.get(tier)
        if cur is None or quality > cur[0]:
            best_by_tier[tier] = (quality, key_type, rx)
    # Prefer the best key from the strongest (lowest-numbered) tier available.
    for tier in sorted(best_by_tier):
        _, key_type, rx = best_by_tier[tier]
        return key_type, rx
    return None


def assemble_candidates(records: list[LogRecord], vocab: dict[str, dict],
                        top_k: int = 5) -> list[dict]:
    """Rank distinct anomalous event types and attach session context."""
    score_records(records, vocab)

    session = detect_session_key(records)
    session_key_type = session[0] if session else None
    by_session: dict[str, list[LogRecord]] = defaultdict(list)
    if session:
        _, rx = session
        for rec in records:
            m = rx.search(rec.raw)
            if m:
                rec.session_key = m.group(0)
                by_session[rec.session_key].append(rec)

    # Best (highest-scoring) representative per template.
    idx_of: dict[int, int] = {id(r): i for i, r in enumerate(records)}
    best_per_template: dict[str, LogRecord] = {}
    for rec in records:
        cur = best_per_template.get(rec.template_id)
        if cur is None or rec.extras["score"] > cur.extras["score"]:
            best_per_template[rec.template_id] = rec

    ranked = sorted(
        (r for r in best_per_template.values() if r.extras["score"] > 0),
        key=lambda r: r.extras["score"],
        reverse=True,
    )[:top_k]

    candidates = []
    for rec in ranked:
        cand = {
            "template_id": rec.template_id,
            "template": rec.template,
            "occurrences": vocab.get(rec.template_id, {}).get("count", 1),
            "score": rec.extras["score"],
            "signals": rec.extras["signals"],
            "representative": {
                "timestamp": rec.timestamp,
                "severity": rec.severity,
                "component": rec.component,
                "raw": rec.raw,
                "message": rec.message,
            },
            # temporal burst around the line: lead-up + continuation (stack traces)
            "context_lines": burst_around(records, idx_of[id(rec)]),
            "session": None,
        }
        if rec.session_key and rec.session_key in by_session:
            seq = by_session[rec.session_key]
            cand["session"] = {
                "key_type": session_key_type,
                "key_value": rec.session_key,
                "event_sequence": [r.template_id for r in seq][:40],
                # bounded + truncated so the LLM prompt stays under the 8192-token cap
                "timeline": [
                    {"timestamp": r.timestamp, "severity": r.severity,
                     "message": r.message[:150]}
                    for r in seq
                ][:12],
            }
        candidates.append(cand)
    return candidates
