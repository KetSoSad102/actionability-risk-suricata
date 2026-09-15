#!/usr/bin/env bash
set -euo pipefail
export LOCAL_UID="${LOCAL_UID:-$(id -u)}"
export LOCAL_GID="${LOCAL_GID:-$(id -g)}"
docker compose run --rm as-engine python -m as_engine.validation \
  --scores /app/runs/improved/scores.csv \
  --truth /app/config/ground_truth.yaml
