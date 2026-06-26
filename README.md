# Log Triage Pipeline

A generalized log-to-JSON pipeline that uses **Gemma 4 12B** (via Ollama) and **BAML** to automatically detect anomalies in any raw system log file and output structured, validated JSON ready for webhook or database injection.

## What It Does

1. **Pre-filters** the log file using regex to isolate error/warning/failure lines (with surrounding context), stripping out benign INFO noise without touching the model.
2. **Sends candidate chunks** to Gemma 4 12B via BAML, which enforces a strict output schema and handles JSON validation automatically.
3. **Outputs a clean JSON array** of anomalies, each with:
   - `service_name` — the component that produced the error
   - `timestamp` — normalized to ISO 8601 where possible
   - `error_severity` — `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`
   - `raw_log_line` — the exact offending log line(s)
   - `suggested_remediation` — actionable SRE steps to resolve the issue

Works out of the box on HDFS, Linux syslog, Apache, Spark, Hadoop, OpenStack, Zookeeper, BGL hardware logs, and any other format — no hard-coded parsers.

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) running locally with `gemma4:12b` pulled
- `baml-py==0.223.0`

## Setup

```bash
# 1. Install dependencies
pip install baml-py==0.223.0

# 2. Pull the model (if not already done)
ollama pull gemma4:12b

# 3. The BAML client is pre-generated — no need to regenerate unless you edit .baml files
#    If you do edit them:
#    baml-cli generate
```

## Usage

```bash
# Output to stdout
python3 triage.py --input logs/loghub/HDFS/HDFS_2k.log

# Save to a file
python3 triage.py --input logs/loghub/Apache/Apache_2k.log --output results.json

# Tune chunk size and context window
python3 triage.py --input logs/loghub/Linux/Linux_2k.log --chunk-size 30 --context 5
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | required | Path to the log file |
| `--output` | stdout | Output JSON file path |
| `--chunk-size` | 25 | Candidate lines per model call |
| `--context` | 3 | Lines of context around each anomaly hit |

## Output Format

```json
[
  {
    "service_name": "mod_jk",
    "timestamp": "2005-12-04T04:47:44",
    "error_severity": "HIGH",
    "raw_log_line": "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6",
    "suggested_remediation": "Restart the mod_jk worker process. Check /etc/httpd/conf/workers2.properties for misconfigured worker settings and inspect the JVM backend for crashes."
  }
]
```

Results are sorted by severity (CRITICAL first).

## Project Structure

```
.
├── baml_src/
│   ├── generators.baml     # BAML code generation config
│   ├── clients.baml        # Gemma 4 12B client via Ollama
│   └── log_triage.baml     # LogAnomaly types + TriageLogs function + prompts
├── baml_client/            # Auto-generated BAML client (do not edit)
├── triage.py               # Main CLI script
├── requirements.txt
└── logs/                   # Sample log files (Loghub dataset)
```

## How Generalization Works

The pipeline avoids hard-coded format parsers entirely:

- **Stage 1 (Python regex)**: catches error keywords across all log formats — the same `ERROR|FATAL|CRITICAL|WARN|exception|failure` pattern works regardless of timestamp format or log structure.
- **Stage 2 (Gemma + BAML)**: the model reads the log semantically and extracts the service name, timestamp, and severity from context — it understands Apache bracket timestamps, HDFS compact timestamps, syslog format, and Java stack traces the same way.
- **BAML schema enforcement**: if Gemma returns malformed JSON, BAML retries automatically. You always get a valid Pydantic object.
