"""End-to-end tests: the pipeline must handle every loghub format without
per-format config, and always emit schema-valid incident cards."""
import glob
import os

import pytest

from baml_client.types import IncidentCard
from logtriage.anomaly import assemble_candidates, detect_session_key, grep_comparison
from logtriage.discover import parse_file
from logtriage.pipeline import run
from logtriage.templatize import templatize

DATASETS = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "datasets", "*_2k.log")))
NAMES = [os.path.basename(p).replace("_2k.log", "") for p in DATASETS]

REQUIRED_FIELDS = {
    "service_name", "timestamp", "error_severity", "anomaly_type",
    "root_cause", "causal_chain", "suggested_remediation", "confidence",
}


@pytest.mark.parametrize("path", DATASETS, ids=NAMES)
def test_stage1_discovers_timestamps(path):
    """Stage 1 must detect a timestamp on (almost) every line of any format."""
    recs = parse_file(path)
    assert recs, "parser returned no records"
    ts_rate = sum(1 for r in recs if r.timestamp) / len(recs)
    assert ts_rate >= 0.95, f"timestamp detection too low: {ts_rate:.0%}"


@pytest.mark.parametrize("path", DATASETS, ids=NAMES)
def test_stage2_templating_collapses(path):
    """Templating must collapse lines into far fewer event types."""
    recs = parse_file(path)
    vocab = templatize(recs)
    assert 0 < len(vocab) < len(recs), "templating did not collapse the log"
    assert all(r.template_id for r in recs), "some records were not templatized"


@pytest.mark.parametrize("path", DATASETS, ids=NAMES)
def test_stage3_finds_candidates(path):
    """Anomaly scoring must surface at least one candidate on every dataset."""
    recs = parse_file(path)
    vocab = templatize(recs)
    cands = assemble_candidates(recs, vocab, top_k=5)
    assert cands, "no anomaly candidates found"
    assert all(c["score"] > 0 for c in cands)


@pytest.mark.parametrize("path", DATASETS, ids=NAMES)
def test_end_to_end_emits_valid_cards(path):
    """Full pipeline (offline) must emit cards that satisfy the schema."""
    result = run(path, top_k=3, use_model=False)
    assert result["incidents"], "no incidents emitted"
    for card in result["incidents"]:
        assert REQUIRED_FIELDS <= set(card), "card missing required fields"
        assert card["suggested_remediation"].strip(), "empty remediation"
        # the card body (minus our provenance extras) must validate as IncidentCard
        body = {k: v for k, v in card.items() if k in REQUIRED_FIELDS}
        IncidentCard.model_validate(body)


def test_session_key_autodetected_where_expected():
    """A correlation key must be auto-detected for session-bearing logs."""
    base = os.path.join(os.path.dirname(__file__), "..", "datasets")
    for name in ["OpenSSH", "Linux", "OpenStack"]:
        sk = detect_session_key(parse_file(os.path.join(base, f"{name}_2k.log")))
        assert sk is not None, f"{name}: expected a session key"


# --- synthesis features (best of main + shivu folded into ours) -------------

@pytest.mark.parametrize("path", DATASETS, ids=NAMES)
def test_candidates_carry_burst_context(path):
    """Every candidate must carry a temporal burst context (shivu's idea)."""
    recs = parse_file(path)
    vocab = templatize(recs)
    for c in assemble_candidates(recs, vocab, top_k=3):
        ctx = c["context_lines"]
        assert isinstance(ctx, list) and ctx, "missing burst context"
        # the representative raw line must be inside its own burst
        assert c["representative"]["raw"] in ctx


def test_run_summary_and_severity_sort():
    """Output carries a run summary + critical flag and is severity-sorted (main's idea)."""
    base = os.path.join(os.path.dirname(__file__), "..", "datasets")
    result = run(os.path.join(base, "BGL_2k.log"), top_k=5, use_model=False)
    assert result["summary"]
    assert "has_critical_issues" in result["stats"]
    order = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3}
    ranks = [order.get(c["error_severity"], 9) for c in result["incidents"]]
    assert ranks == sorted(ranks), "incidents not severity-sorted"


def test_streaming_callback_fires_per_incident():
    """on_incident must fire once per emitted card (shivu's streaming idea)."""
    base = os.path.join(os.path.dirname(__file__), "..", "datasets")
    seen = []
    result = run(os.path.join(base, "OpenSSH_2k.log"), top_k=3,
                 use_model=False, on_incident=seen.append)
    assert len(seen) == len(result["incidents"])


def test_grep_blindspot_on_hdfs():
    """Our differentiator: keyword grep misses HDFS anomalies; we catch them."""
    base = os.path.join(os.path.dirname(__file__), "..", "datasets")
    recs = parse_file(os.path.join(base, "HDFS_2k.log"))
    vocab = templatize(recs)
    g = grep_comparison(assemble_candidates(recs, vocab, top_k=10))
    assert g["grep_would_miss"] > 0, "expected rarity-only anomalies grep can't see"
    assert g["engine_found"] >= g["grep_would_find"]
