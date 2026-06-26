#!/usr/bin/env bash
# Demo: run the SAME command across wildly different log formats.
# "One pipeline, every format, zero config."
set -e
cd "$(dirname "$0")"

DATASETS=(${DEMO_DATASETS:-HDFS Linux Apache BGL OpenSSH})
FLAG="${DEMO_FLAG:---no-model}"   # set DEMO_FLAG="" once Gemma is wired

for ds in "${DATASETS[@]}"; do
  echo ""
  echo "=================================================================="
  echo "  python triage.py datasets/${ds}_2k.log   ($ds format)"
  echo "=================================================================="
  uv run python triage.py "datasets/${ds}_2k.log" --top-k 2 $FLAG
done
