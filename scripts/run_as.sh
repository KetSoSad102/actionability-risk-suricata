#!/usr/bin/env bash
set -euo pipefail
export LOCAL_UID="${LOCAL_UID:-$(id -u)}"
export LOCAL_GID="${LOCAL_GID:-$(id -g)}"
mkdir -p runs/improved
docker compose build as-engine
docker compose run --rm as-engine
