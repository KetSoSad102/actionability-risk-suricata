#!/usr/bin/env bash
set -euo pipefail
export LOCAL_UID="${LOCAL_UID:-$(id -u)}"
export LOCAL_GID="${LOCAL_GID:-$(id -g)}"
mkdir -p logs/suricata runs/improved pcaps
rm -f logs/suricata/* runs/improved/* pcaps/generated_official_payloads.pcap

echo "[1/6] Build images"
docker compose build

echo "[2/6] Generate official-rule payload PCAP"
docker compose run --rm pcap-gen

echo "[3/6] Run Suricata offline with rules/improved.rules"
docker compose run --rm suricata-offline

echo "[4/6] Parse eve.json and compute Actionability + Risk scores"
docker compose run --rm as-engine

echo "[5/6] Validate results against ground truth"
./scripts/validate_results.sh

echo "[6/6] Generate 500 post-alert presentations, figures, and annotation pack"
docker compose run --rm experiment

echo
echo "[+] Alerts:"
jq 'select(.event_type=="alert") | {sid:.alert.signature_id, rev:.alert.rev, signature:.alert.signature, src:.src_ip, dst:.dest_ip, status:.http.status, url:.http.url}' logs/suricata/eve.json || true

echo
echo "[+] Scores:"
./scripts/show_results.sh
