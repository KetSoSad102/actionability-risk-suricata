#!/usr/bin/env bash
set -euo pipefail
export LOCAL_UID="${LOCAL_UID:-$(id -u)}"
export LOCAL_GID="${LOCAL_GID:-$(id -g)}"
mkdir -p logs/suricata
rm -f logs/suricata/*
docker compose run --rm suricata-offline
ls -lh logs/suricata/
