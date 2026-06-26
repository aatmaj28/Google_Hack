"""End-to-end tests: the pipeline must handle every loghub format without
per-format config, and always emit schema-valid incident cards."""
import glob
import os

import pytest

from baml_client.types import IncidentCard
from logtriage.anomaly import assemble_candidates, detect_session_key
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
