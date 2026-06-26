# Universal Log Triage Pipeline

**One command turns ANY raw log file into validated JSON incident cards — no per-format configuration.**

```bash
python triage.py datasets/HDFS_2k.log      # Hadoop block logs
python triage.py datasets/Linux_2k.log     # syslog
python triage.py datasets/Apache_2k.log    # web server errors
python triage.py datasets/BGL_2k.log       # supercomputer RAS logs
```

Same code, 16 wildly different log formats, zero hardcoded fields. Drop in a log it has never seen and it discovers the structure at runtime, finds the events that actually matter, and emits a clean, schema-validated incident card.

## Why this is hard (and why hardcoding fails)

We inspected all 16 [loghub](https://github.com/logpai/loghub) datasets. **No two share a field schema** — Apache parses into 3 fields, Thunderbird into 14, and three datasets (Proxifier, HealthApp, HPC) have no severity field at all. The standard approach writes a regex *per format*. That is exactly what a generic tool cannot do. So instead of assuming structure, this pipeline **discovers** it.

> Design principle: anything that varies per format is *discovered, not coded*.

## Architecture

```
ANY .log → [1 Discover] → [2 Templatize] → [3 Score] → [4 Triage] → [5 Validate] → JSON cards
            deterministic   deterministic    deterministic   Gemma (top-K)   BAML
```

| Stage | What it does | How it generalizes |
|-------|--------------|--------------------|
| **1. Discover** (`discover.py`) | Pulls timestamp, severity, component, message from each line | A *universal library* of timestamp shapes + severity keywords, applied uniformly (like Splunk/Logstash auto-detection). 100% timestamp detection across all 16 datasets. |
| **2. Templatize** (`templatize.py`) | Collapses millions of lines into a few dozen event templates | [Drain](https://github.com/logpai/Drain3), the industry-standard online log parser — masks variables, needs no format spec or training. |
| **3. Score** (`anomaly.py`) | Ranks the most suspicious events | Multi-signal: **severity** + failure **keyword** + statistical **rarity** (catches anomalies with no error keyword — the HDFS case) + auto-detected **session** correlation. |
| **4. Triage** (`triage.py` + `baml_src/`) | LLM reasons over each candidate → root cause, causal chain, remediation | Local Gemma via [BAML](https://docs.boundaryml.com); only the top-K candidates ever reach the model, so the bulk of the log costs zero tokens. |
| **5. Validate** | Guarantees webhook-ready JSON | BAML schema-aligned parsing + `@@assert`; deterministic fallback card if the model is unreachable, so the remediation field is never empty. |

### The "grep can't catch it" signal

In HDFS, failures like under-replication contain **no error keyword** — every line is `INFO`. Keyword search finds nothing. The **rarity** signal in stage 3 flags the unusual event sequence anyway. That's the differentiator: we detect what `grep ERROR` structurally cannot.

### Auto-detected session keys

When a log carries a correlation id, the pipeline finds it automatically (preferring transaction ids over infrastructure ids) and reconstructs the event sequence into a causal chain:

| Log | Detected session key |
|-----|----------------------|
| HDFS / OpenStack | block id / request uuid |
| Linux / OpenSSH / Zookeeper | source IP |
| Mac / Thunderbird | process id |

## Setup

```bash
uv sync                       # install deps
uv run baml-cli generate      # (re)generate the BAML client from baml_src/
```

Point at your local/remote Gemma:

```bash
export OLLAMA_BASE_URL=http://localhost:11434/v1   # or http://<lan-ip>:11434/v1
export GEMMA_MODEL=gemma2:9b                        # any Ollama tag
```

## Usage

```bash
python triage.py <logfile> [--top-k N] [--out result.json] [--no-model]
```

- `--no-model` — skip the LLM and emit deterministic fallback cards (fast, offline, demo-safe).
- `--out` — write JSON to a file instead of stdout.

## Output

```json
{
  "service_name": "sshd",
  "timestamp": "2023-12-10T06:55:48",
  "error_severity": "CRITICAL",
  "anomaly_type": "SeverityError",
  "root_cause": "...",
  "causal_chain": [ { "step": 1, "event": "..." } ],
  "suggested_remediation": "...",
  "confidence": 0.0,
  "evidence": { "template": "...", "anomaly_score": 7.5, "signals": ["..."], "raw_line": "..." }
}
```
