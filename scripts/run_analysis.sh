#!/usr/bin/env bash
#
# run_analysis.sh
# Runs the full pcap -> Zeek -> Suricata -> timeline pipeline.
#
# Usage: ./scripts/run_analysis.sh evidence/capture.pcap
#
set -euo pipefail

PCAP="${1:?Usage: $0 <path-to-pcap>}"
OUT_DIR="evidence/logs"

mkdir -p "$OUT_DIR"

echo "[+] Running Zeek against $PCAP"
( cd "$OUT_DIR" && zeek -r "../../$PCAP" )

echo "[+] Running Suricata against $PCAP"
suricata -r "$PCAP" -l "$OUT_DIR" -c /etc/suricata/suricata.yaml

echo "[+] Building consolidated timeline"
python3 src/build_timeline.py \
    --pcap "$PCAP" \
    --zeek-dir "$OUT_DIR" \
    --suricata-eve "$OUT_DIR/eve.json" \
    --out "$OUT_DIR/attack_timeline.csv"

echo "[+] Done. Timeline written to $OUT_DIR/attack_timeline.csv"
