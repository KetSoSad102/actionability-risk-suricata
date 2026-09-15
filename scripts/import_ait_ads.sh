#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 <scenario> <scenario_wazuh.json> [scenario_alerts.txt]"
  exit 2
fi

scenario="$1"
input_file="$2"
labels_file="${3:-}"
sample_fraction="${AIT_SAMPLE_FRACTION:-0.25}"
output_dir="runs/external/ait_ads/${scenario}"

mkdir -p "$output_dir"

label_args=()
if [ -n "$labels_file" ]; then
  label_args=(--labels-csv "$labels_file")
fi

PYTHONPATH=src python3 -m as_engine.ait_ads \
  --input "$input_file" \
  --scenario "$scenario" \
  --out-eve "$output_dir/eve.json" \
  --out-summary "$output_dir/adapter_summary.json" \
  "${label_args[@]}"

PYTHONPATH=src python3 -m as_engine.cli \
  --eve "$output_dir/eve.json" \
  --rules rules/rule_metadata.yaml \
  --scoring config/scoring-v2.yaml \
  --out-jsonl "$output_dir/scores.jsonl" \
  --out-csv "$output_dir/scores.csv" \
  --out-summary "$output_dir/score_summary.json"

PYTHONPATH=src python3 -m as_engine.archetypes \
  --scores "$output_dir/scores.jsonl" \
  --output-dir "$output_dir/archetypes" \
  --sample-fraction "$sample_fraction" \
  --seed 2026

echo "[+] AIT-ADS scenario output: $output_dir"
echo "[+] Archetype sampling fraction: $sample_fraction"
echo "[!] Unknown SID metadata is retained as missing evidence; no metadata is fabricated."
