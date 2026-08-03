#!/usr/bin/env python3
"""
build_timeline.py

Consolidates Zeek logs, Suricata eve.json alerts, and (optionally) raw
tshark field extractions into a single chronological, MITRE ATT&CK-tagged
attack timeline CSV.

Usage:
    python3 build_timeline.py --pcap capture.pcap \
        --zeek-dir evidence/logs --suricata-eve evidence/logs/eve.json \
        --out evidence/logs/attack_timeline.csv

Notes:
    - This script expects Zeek's default TSV log format (conn.log, dns.log,
      http.log, files.log, notice.log if present).
    - The MITRE_MAP dictionary below is a starting point; extend it with
      the techniques you actually observe in your capture (see the
      technique reference table in docs/mitre_mapping.md).
    - Designed to run against LAB / SIMULATED captures only.
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# A small starting map from observable event types -> MITRE ATT&CK technique.
# Extend this as you identify more behaviours in your own capture.
# ---------------------------------------------------------------------------
MITRE_MAP = {
    "dns_query_flood": ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    "port_scan": ("T1046", "Network Service Discovery"),
    "http_login_attempt": ("T1110", "Brute Force"),
    "suspicious_download": ("T1105", "Ingress Tool Transfer"),
    "reverse_shell_conn": ("T1059", "Command and Scripting Interpreter"),
    "data_exfil_large_upload": ("T1041", "Exfiltration Over C2 Channel"),
    "suricata_alert": ("T1190", "Exploit Public-Facing Application"),  # default; override per-signature
}


def parse_zeek_log(path):
    """Parse a Zeek TSV log file into a list of dict rows, skipping headers."""
    rows = []
    if not os.path.exists(path):
        return rows

    with open(path, "r", errors="ignore") as f:
        fields = []
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            values = line.split("\t")
            row = dict(zip(fields, values))
            rows.append(row)
    return rows


def zeek_ts_to_iso(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (ValueError, TypeError):
        return ts


def load_conn_log(zeek_dir):
    events = []
    for row in parse_zeek_log(os.path.join(zeek_dir, "conn.log")):
        events.append({
            "timestamp": zeek_ts_to_iso(row.get("ts")),
            "source": "zeek:conn",
            "src_ip": row.get("id.orig_h"),
            "dst_ip": row.get("id.resp_h"),
            "dst_port": row.get("id.resp_p"),
            "proto": row.get("proto"),
            "event": f"connection {row.get('id.orig_h')} -> "
                     f"{row.get('id.resp_h')}:{row.get('id.resp_p')} "
                     f"({row.get('proto')})",
            "mitre_id": "",
            "mitre_name": "",
        })
    return events


def load_dns_log(zeek_dir):
    events = []
    for row in parse_zeek_log(os.path.join(zeek_dir, "dns.log")):
        events.append({
            "timestamp": zeek_ts_to_iso(row.get("ts")),
            "source": "zeek:dns",
            "src_ip": row.get("id.orig_h"),
            "dst_ip": row.get("id.resp_h"),
            "dst_port": row.get("id.resp_p"),
            "proto": "dns",
            "event": f"DNS query for {row.get('query')}",
            "mitre_id": "",
            "mitre_name": "",
        })
    return events


def load_http_log(zeek_dir):
    events = []
    for row in parse_zeek_log(os.path.join(zeek_dir, "http.log")):
        events.append({
            "timestamp": zeek_ts_to_iso(row.get("ts")),
            "source": "zeek:http",
            "src_ip": row.get("id.orig_h"),
            "dst_ip": row.get("id.resp_h"),
            "dst_port": row.get("id.resp_p"),
            "proto": "http",
            "event": f"{row.get('method')} {row.get('host')}{row.get('uri')} "
                     f"-> {row.get('status_code')}",
            "mitre_id": "",
            "mitre_name": "",
        })
    return events


def load_suricata_eve(path):
    events = []
    if not path or not os.path.exists(path):
        return events

    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event_type") != "alert":
                continue
            alert = rec.get("alert", {})
            events.append({
                "timestamp": rec.get("timestamp"),
                "source": "suricata",
                "src_ip": rec.get("src_ip"),
                "dst_ip": rec.get("dest_ip"),
                "dst_port": rec.get("dest_port"),
                "proto": rec.get("proto"),
                "event": f"ALERT: {alert.get('signature')} "
                         f"(sid {alert.get('signature_id')}, "
                         f"severity {alert.get('severity')})",
                "mitre_id": MITRE_MAP["suricata_alert"][0],
                "mitre_name": MITRE_MAP["suricata_alert"][1],
            })
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", help="Original pcap file (for reference only)")
    parser.add_argument("--zeek-dir", required=True, help="Directory containing Zeek logs")
    parser.add_argument("--suricata-eve", help="Path to Suricata eve.json")
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()

    all_events = []
    all_events += load_conn_log(args.zeek_dir)
    all_events += load_dns_log(args.zeek_dir)
    all_events += load_http_log(args.zeek_dir)
    all_events += load_suricata_eve(args.suricata_eve)

    # Sort chronologically; entries with unparsable timestamps sink to the end
    def sort_key(e):
        ts = e["timestamp"]
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.max.replace(tzinfo=timezone.utc)

    all_events.sort(key=sort_key)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    fieldnames = ["timestamp", "source", "src_ip", "dst_ip", "dst_port",
                  "proto", "event", "mitre_id", "mitre_name"]
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_events)

    print(f"Wrote {len(all_events)} timeline events to {args.out}")


if __name__ == "__main__":
    sys.exit(main())
