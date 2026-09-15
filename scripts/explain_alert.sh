#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <SID>"
  exit 2
fi

PYTHONPATH=src python3 -m as_engine.explain \
  --scores runs/improved/scores.jsonl \
  --sid "$1"
