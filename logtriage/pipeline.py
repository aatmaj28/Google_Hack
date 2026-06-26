"""End-to-end pipeline: raw log file -> validated incident cards (JSON)."""
from __future__ import annotations

import time

from .anomaly import assemble_candidates, detect_session_key
from .discover import parse_file
from .templatize import templatize
from .triage import triage_candidates


def run(path: str, top_k: int = 5, use_model: bool = True) -> dict:
    t0 = time.time()
    records = parse_file(path)
    vocab = templatize(records)
    session = detect_session_key(records)
    candidates = assemble_candidates(records, vocab, top_k=top_k)
    incidents = triage_candidates(candidates, use_model=use_model)

    return {
        "source_file": path,
        "stats": {
            "lines_parsed": len(records),
            "event_templates": len(vocab),
            "session_key": session[0] if session else None,
            "candidates_triaged": len(incidents),
            "elapsed_sec": round(time.time() - t0, 2),
        },
        "incidents": incidents,
    }
