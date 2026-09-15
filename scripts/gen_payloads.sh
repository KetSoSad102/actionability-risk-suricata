#!/usr/bin/env bash
set -euo pipefail
export LOCAL_UID="${LOCAL_UID:-$(id -u)}"
export LOCAL_GID="${LOCAL_GID:-$(id -g)}"
mkdir -p pcaps
docker compose build pcap-gen
docker compose run --rm pcap-gen
ls -lh pcaps/generated_official_payloads.pcap
