"""End-to-end pipeline: raw log file -> validated incident cards (JSON)."""
from __future__ import annotations

import time

from .anomaly import assemble_candidates, detect_session_key
from .discover import parse_file
from .templatize import templatize
from .triage import triage_candidates

# Highest severity first in the output (idea borrowed from the `main` branch).
_SEVERITY_ORDER = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3}


def _summarize(incidents: list[dict]) -> tuple[bool, str]:
    """Run-level rollup (from the `main` branch): a critical flag + one line."""
    if not incidents:
        return False, "No anomalies detected."
    has_critical = any(c.get("error_severity") == "CRITICAL" for c in incidents)
    top = incidents[0]
    summary = (f"{len(incidents)} incident(s); most significant: "
               f"{top.get('error_severity')} in {top.get('service_name')} - "
               f"{top.get('root_cause', '')}")
    return has_critical, summary


def run(path: str, top_k: int = 5, use_model: bool = True, on_incident=None) -> dict:
    t0 = time.time()
    records = parse_file(path)
    vocab = templatize(records)
    session = detect_session_key(records)
    candidates = assemble_candidates(records, vocab, top_k=top_k)
    incidents = triage_candidates(candidates, use_model=use_model, on_incident=on_incident)

    # Sort: highest severity first, then by anomaly score.
    incidents.sort(key=lambda c: (
        _SEVERITY_ORDER.get(c.get("error_severity"), 9),
        -c.get("evidence", {}).get("anomaly_score", 0),
    ))
    has_critical, summary = _summarize(incidents)

    return {
        "source_file": path,
        "summary": summary,
        "stats": {
            "lines_parsed": len(records),
            "event_templates": len(vocab),
            "session_key": session[0] if session else None,
            "candidates_triaged": len(incidents),
            "has_critical_issues": has_critical,
            "elapsed_sec": round(time.time() - t0, 2),
        },
        "incidents": incidents,
    }
