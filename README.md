# Universal Log Triage Pipeline

**One command turns ANY raw log file into validated JSON incident cards — no per-format configuration.**

```bash
python triage.py datasets/HDFS_2k.log      # Hadoop block logs
python triage.py datasets/Linux_2k.log     # syslog
python triage.py datasets/Apache_2k.log    # web server errors
python triage.py datasets/BGL_2k.log       # supercomputer RAS logs
```

Same code, 16 wildly different log formats, zero hardcoded fields. Drop in a log it has never seen and it discovers the structure at runtime, finds the events that actually matter, and emits a clean, schema-validated incident card.

> **Best-of-three synthesis.** This branch combines the strongest ideas from all three team approaches: the universal discovery + rarity detection + dual backends (base), **temporal burst context** + **benign-skip** + **streaming output** (from `shivu`), and a **run-level summary** + **severity-sorted output** (from `main`).

## What makes it unique

1. **Catches what `grep` can't.** Most log tools keyword-search for `ERROR`/`FATAL`. Our **rarity** signal flags abnormal events even when every line says `INFO` (e.g. HDFS under-replication). `--compare-grep` quantifies it live — on HDFS, keyword search finds **1** problem, we find **7**.
2. **Truly format-agnostic.** One pipeline auto-discovers the structure of all 16 loghub formats — 100% timestamp detection, zero per-format config. No hardcoded fields.
3. **Hybrid cost model.** Cheap deterministic code triages thousands of lines down to a handful; Gemma only ever explains the top few — so it scales and stays token-light.
4. **Auto causal chains.** It auto-detects the correlation id (block/request/ip) and reconstructs *what led to what* — not just the single failing line.

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

In HDFS, failures like under-replication contain **no error keyword** — every line is `INFO`. Keyword search finds nothing. The **rarity** signal in stage 3 flags the unusual event anyway. Prove it live:

```bash
python triage.py datasets/HDFS_2k.log --top-k 10 --compare-grep --no-model
#   Keyword grep would find : 1 anomaly types
#   This engine found       : 7 anomaly types
#   >>> grep would MISS      : 6 (rarity-flagged, no error keyword)
```

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

Point at Gemma — two interchangeable backends, chosen with `LLM_BACKEND`:

```bash
# Ollama (local / LAN)
export LLM_BACKEND=ollama OLLAMA_BASE_URL=http://localhost:11434/v1 GEMMA_MODEL=gemma4:e4b

# vLLM (OpenAI-compatible, e.g. gemma-3-12b-it)
export LLM_BACKEND=vllm VLLM_BASE_URL=http://localhost:8001/v1 VLLM_MODEL=google/gemma-3-12b-it
```

## Usage

```bash
python triage.py <logfile> [--top-k N] [--out result.json] [--no-model] [--stream] [--compare-grep]
```

- `--top-k N` — max distinct anomaly types to emit (default 5; raise to show all).
- `--no-model` — skip the LLM, emit deterministic fallback cards (offline break-glass only).
- `--stream` — emit each incident as a JSONL line as it's produced, summary to stderr.
- `--compare-grep` — show how many anomalies a naive keyword grep would miss vs this engine.
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
