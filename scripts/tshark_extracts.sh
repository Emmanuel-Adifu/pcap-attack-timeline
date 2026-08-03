#!/usr/bin/env bash
#
# tshark_extracts.sh
# Quick manual-inspection extracts used while building the report's
# Results and Findings section. Run individually as needed.
#
set -euo pipefail
PCAP="${1:?Usage: $0 <path-to-pcap>}"

echo "== Conversation summary (who talked to whom) =="
tshark -r "$PCAP" -q -z conv,tcp

echo "== HTTP requests =="
tshark -r "$PCAP" -Y http.request \
    -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri

echo "== DNS queries =="
tshark -r "$PCAP" -Y dns.flags.response==0 \
    -T fields -e frame.time -e ip.src -e dns.qry.name

echo "== Possible port scan (SYN without ACK, high fan-out) =="
tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport

echo "== Credentials in cleartext protocols (FTP/HTTP Basic/Telnet) — lab data only =="
tshark -r "$PCAP" -Y "ftp.request.command==USER or ftp.request.command==PASS or http.authbasic or telnet" \
    -T fields -e frame.time -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg
