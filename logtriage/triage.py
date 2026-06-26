"""
Stage 4 + 5 — LLM triage with validation and graceful fallback.

Each pre-detected anomalous event is sent to local Gemma via BAML, which does
schema-aligned parsing into the validated IncidentCard type. If the model is
unreachable or its output can't be coerced, we fall back to a deterministic
card built from the signals we already extracted — so the remediation field is
never empty and the demo never hard-fails.
"""
from __future__ import annotations

import json
import os
import re

# Two interchangeable Gemma backends, chosen with LLM_BACKEND (ollama | vllm).
#   ollama -> teammate's local/LAN box   (GemmaOllama client)
#   vllm   -> OpenAI-compatible vLLM      (GemmaVLLM client, google/gemma-3-12b-it)
# Defaults are placeholders; override the relevant env vars for your endpoint.
os.environ.setdefault("OLLAMA_BASE_URL", "http://localhost:11434/v1")
os.environ.setdefault("GEMMA_MODEL", "gemma2:2b")
os.environ.setdefault("VLLM_BASE_URL", "http://vllm-gemma3-12b:8001/v1")
os.environ.setdefault("VLLM_MODEL", "google/gemma-3-12b-it")
# Keep BAML logs off stdout so JSON output stays clean (set BAML_LOG=info to debug).
os.environ.setdefault("BAML_LOG", "off")

_BACKEND_TO_CLIENT = {"ollama": "GemmaOllama", "vllm": "GemmaVLLM"}


def _client_registry():
    """Pick the BAML client matching LLM_BACKEND. Returns None for the default."""
    backend = os.environ.get("LLM_BACKEND", "ollama").lower()
    client_name = _BACKEND_TO_CLIENT.get(backend)
    if not client_name:
        return None
    from baml_py import ClientRegistry
    cr = ClientRegistry()
    cr.set_primary(client_name)
    return cr


# Keyword -> concrete remediation. Used both as the fallback and to guarantee
# the field is never garbage. Generic across systems (no per-dataset values).
_REMEDIATION_MAP = [
    (r"auth|password|login|credential|permission|denied|unauthor",
     "Investigate repeated auth failures for brute-force; rate-limit or block the source, rotate credentials, and prefer key-based auth."),
    (r"connection reset|refused|unreachable|no route|timed?\s?out|timeout",
     "Check network/firewall reachability and confirm the downstream service is healthy and accepting connections."),
    (r"disk|no space|quota|full|under-?replicat|replica",
     "Free or expand storage on the affected node and verify replication/quotas; rebalance if a node is degraded."),
    (r"out of memory|oom|memory|killed",
     "Raise the memory limit or fix the leak; inspect container/cgroup limits and recent allocation growth."),
    (r"panic|fatal|segfault|core dump|abort",
     "Capture the crash/core dump and correlate with the most recent deploy or config change to the failing component."),
    (r"corrupt|checksum|parity|bad block",
     "Run an integrity check on the affected resource and restore/replace the corrupted unit; inspect the underlying hardware."),
    (r"exception|stack ?trace|nullpointer|null pointer",
     "Open the stack trace at the topmost application frame and add a guard/null-check at the failing call site."),
]
_DEFAULT_REMEDIATION = (
    "Inspect surrounding log context for this component and review recent "
    "deploys/config changes that could have triggered the event."
)


def _remediation_for(text: str) -> str:
    for pat, fix in _REMEDIATION_MAP:
        if re.search(pat, text, re.IGNORECASE):
            return fix
    return _DEFAULT_REMEDIATION


def _anomaly_type(signals: list[str]) -> str:
    joined = ",".join(signals)
    if "severity:CRITICAL" in joined or "severity:ERROR" in joined:
        return "SeverityError"
    if "keyword" in joined:
        return "FailureKeyword"
    if "rare" in joined:
        return "RareEvent"
    return "RareEvent"


def _infer_severity(rep: dict, signals: list[str]) -> str:
    if rep.get("severity"):
        return rep["severity"]
    if "keyword" in ",".join(signals):
        return "ERROR"
    return "WARNING"


def fallback_card(cand: dict) -> dict:
    rep = cand["representative"]
    text = rep.get("message", "") or rep.get("raw", "")
    chain = []
    if cand.get("session"):
        for i, ev in enumerate(cand["session"].get("timeline", [])[:8], 1):
            chain.append({"step": i, "event": ev.get("message", "")[:120]})
    return {
        "service_name": rep.get("component") or "unknown",
        "timestamp": rep.get("timestamp") or "",
        "error_severity": _infer_severity(rep, cand["signals"]),
        "anomaly_type": _anomaly_type(cand["signals"]),
        "root_cause": (text[:160] if text else "unclassified anomalous event"),
        "causal_chain": chain,
        "suggested_remediation": _remediation_for(text),
        "confidence": 0.4,
        "_source": "fallback",
    }


def triage_candidates(candidates: list[dict], use_model: bool = True,
                      on_incident=None) -> list[dict]:
    """on_incident(card): optional callback fired as each card is produced
    (used for streaming output, idea from the `shivu` branch)."""
    cards: list[dict] = []
    b = None
    registry = None
    if use_model:
        try:
            from baml_client import b as _b
            b = _b
            registry = _client_registry()
        except Exception:
            b = None

    for cand in candidates:
        card = None
        if b is not None:
            try:
                opts = {"client_registry": registry} if registry else {}
                result = b.TriageIncident(json.dumps(cand), baml_options=opts)
                if result is None:
                    # model judged this rare-but-routine event benign -> drop it
                    continue
                card = result.model_dump()
                # normalize enums to plain strings for JSON output
                card["error_severity"] = getattr(card["error_severity"], "value", card["error_severity"])
                card["anomaly_type"] = getattr(card["anomaly_type"], "value", card["anomaly_type"])
                if not card.get("suggested_remediation"):
                    card["suggested_remediation"] = _remediation_for(cand["representative"].get("message", ""))
                card["_source"] = "model"
            except Exception as exc:
                card = fallback_card(cand)
                card["_note"] = f"model unavailable: {type(exc).__name__}"
        else:
            card = fallback_card(cand)

        # always attach the deterministic provenance so the card is auditable
        card["evidence"] = {
            "template_id": cand["template_id"],
            "template": cand["template"],
            "occurrences": cand["occurrences"],
            "anomaly_score": cand["score"],
            "signals": cand["signals"],
            "raw_line": cand["representative"].get("raw", ""),
        }
        cards.append(card)
        if on_incident is not None:
            on_incident(card)
    return cards
