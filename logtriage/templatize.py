"""
Stage 2 — Event templating (format-agnostic).

Collapses millions of distinct log lines into a small vocabulary of event
*templates* using Drain (the industry-standard online log-parsing algorithm,
the same one loghub benchmarks). Variables (ids, IPs, numbers, paths...) are
masked so that "Receiving block blk_123" and "Receiving block blk_456" become
one event type. No per-format configuration and no training pass.
"""
from __future__ import annotations

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

from .discover import LogRecord


# Universal variable masks, applied to every dataset. Ordered most-specific
# first so e.g. an IP:port is masked before its bare numbers are.
_MASKS = [
    (r"blk_-?\d+", "BLOCKID"),
    (r"(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})", "UUID"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", "IP"),
    (r"0x[0-9a-fA-F]+", "HEX"),
    (r"(?:/[\w.\-]+)+/?", "PATH"),
    (r"\b[0-9a-fA-F]{16,}\b", "ID"),
    (r"\b\d+\b", "NUM"),
]


def build_miner() -> TemplateMiner:
    config = TemplateMinerConfig()
    config.profiling_enabled = False
    config.drain_sim_th = 0.4
    config.drain_depth = 4
    config.parametrize_numeric_tokens = True
    config.masking_instructions = [MaskingInstruction(p, m) for p, m in _MASKS]
    return TemplateMiner(config=config)


def templatize(records: list[LogRecord]) -> dict[str, dict]:
    """Assign template_id + template to each record in place.

    Returns a vocabulary: {template_id: {"template": str, "count": int}}.
    """
    miner = build_miner()
    for rec in records:
        result = miner.add_log_message(rec.message)
        rec.template_id = f"E{result['cluster_id']}"
        rec.template = result["template_mined"]

    vocab: dict[str, dict] = {}
    for cluster in miner.drain.clusters:
        vocab[f"E{cluster.cluster_id}"] = {
            "template": cluster.get_template(),
            "count": cluster.size,
        }
    return vocab
