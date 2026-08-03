# Network Packet Capture Analysis — Attack Timeline Reconstruction

**Author:** [Your Full Name]
**Index Number:** [Your Index Number]
**Track:** Blue Team
**Course:** [Course Code]

## Summary

This project reconstructs the timeline of a simulated network intrusion using
packet capture (pcap) analysis. Traffic was generated in an isolated lab
environment (attacker + victim VMs) and captured with `tcpdump`/Wireshark.
The capture was then processed with Zeek (log generation), Suricata
(signature-based alerting), and custom Python/tshark scripts to produce a
consolidated, timestamped attack timeline mapped against the MITRE ATT&CK
framework — covering reconnaissance, initial access, and post-exploitation
activity observed on the wire.

## Tools Used

| Tool | Purpose |
|---|---|
| Wireshark / tshark | Manual and scripted packet inspection |
| tcpdump | Traffic capture |
| Zeek | Structured log generation (conn.log, http.log, dns.log, files.log) |
| Suricata | Signature-based IDS alerting on the capture |
| NetworkMiner | Session/file/credential extraction (validation pass) |
| Python 3 (Scapy, PyShark, pandas) | Timeline extraction and correlation |
| MITRE ATT&CK Navigator | Technique mapping and visualization |

## Repository Structure

```
.
├── src/            # Python analysis scripts (timeline builder, parsers)
├── scripts/         # Shell wrappers for tshark/Zeek/Suricata runs
├── configs/          # Zeek/Suricata config snippets used (sanitized)
├── docs/             # Report, diagrams, MITRE mapping tables
├── evidence/
│   ├── logs/         # Zeek/Suricata output logs (sanitized, no real target data)
│   └── screenshots/  # Captioned screenshots referenced in the report
└── appendices/       # Full raw logs / extended code referenced in the report
```

## How to Run

1. **Capture traffic** (in an isolated lab only):
   ```bash
   sudo tcpdump -i <interface> -w evidence/capture.pcap
   ```
2. **Generate Zeek logs**:
   ```bash
   zeek -r evidence/capture.pcap
   mv *.log evidence/logs/
   ```
3. **Run Suricata against the capture**:
   ```bash
   suricata -r evidence/capture.pcap -l evidence/logs/
   ```
4. **Build the consolidated timeline**:
   ```bash
   python3 src/build_timeline.py --pcap evidence/capture.pcap \
       --zeek-dir evidence/logs --suricata-eve evidence/logs/eve.json \
       --out evidence/logs/attack_timeline.csv
   ```
5. Open `evidence/logs/attack_timeline.csv` for the final chronological,
   MITRE-mapped event list used in the report.

## Screenshots

Key screenshots are in `evidence/screenshots/` and referenced by figure
number in `docs/report.pdf` (see Section: Results and Findings).

## Notes on Data

All IP addresses, hostnames, and credentials in this repository are
lab/simulated values. No live target information, real credentials, or
personal data is included in this repository or its commit history.

## Attribution

Zeek and Suricata are third-party open-source tools used as-is per their
respective licenses; only configuration and parsing scripts here are
original work. See `docs/report.pdf`, References section, for full citations.
