#!/usr/bin/env bash
set -euo pipefail

export LOCAL_UID="${LOCAL_UID:-$(id -u)}"
export LOCAL_GID="${LOCAL_GID:-$(id -g)}"

mkdir -p runs/experiments/controlled

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  docker compose build experiment
  docker compose run --rm experiment
else
  echo "Docker Compose not available; running with the current Python environment."
  PYTHONPATH=src python3 -m as_engine.experiment \
    --eve logs/suricata/eve.json \
    --rules rules/rule_metadata.yaml \
    --scoring config/scoring-v2.yaml \
    --variants config/controlled_variants.yaml \
    --contexts config/context_variants.yaml \
    --output-dir runs/experiments/controlled
fi

echo "[+] Controlled experiment summary"
python3 - <<'PY'
import json
from pathlib import Path

path = Path("runs/experiments/controlled/experiment_summary.json")
summary = json.loads(path.read_text(encoding="utf-8"))
print(json.dumps({
    "design": summary["design"],
    "overall": summary["overall"],
    "comparator_results": summary["comparator_results"],
    "ablation": summary["ablation"],
    "sensitivity": summary["sensitivity"],
    "annotation_protocol": summary["annotation_protocol"],
}, indent=2))
PY
