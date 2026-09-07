# X9 — MITM and Spoofing Detectors

Defensive daemon trio: ARP-cache watcher, DHCP pool gauge, and DNS consistency checker that detect network spoofing attacks and emit SIEM-format JSON alerts from parsed event and PCAP-ish input data.

## Overview

This project is the defensive counterpart to X5 — detects MITM and spoofing attacks:
- **ARP-Cache Watcher**: Monitors gateway MAC address for drift/arbitration table changes
- **DHCP Pool Gauge**: Detects DHCP pool exhaustion from lease counter heuristics
- **DNS Consistency Checker**: Compares canary-domain resolution across multiple resolvers
- **Real ARP frame parser**: decodes raw ethernet+L2 frames (RFC 826) and flags gratuitous
  announcements and IP/MAC conflicts
- **Real DNS packet parser**: builds/decodes actual DNS query/response wire format and
  detects query↔response mismatch (transaction-id, question-name, spoofed answer)
- **TLS certificate hostname check**: pure-stdlib X.509 DER parser extracts the subject CN
  and SAN extension (OID 2.5.29.17) and flags hostname mismatches
- **SIEM Output**: All detectors emit normalized JSON events for ingestion into SIEM pipelines
- **Offline Demo**: Runs against embedded sample ARP/DNS/DHCP data without live traffic

## Features

- **ARP Drift Alarm**: Detects gateway MAC address changes indicating ARP spoofing
- **ARP Frame Analysis**: byte-exact ethernet/ARP parser; builds and parses frames for tests
- **DHCP Exhaustion Detection**: Flags DHCP pool starvation from lease/offer ratios
- **DNS Canary Comparison**: Resolves canary domains across resolvers to detect DNS spoofing
- **DNS Wire-Format Matching**: real query/response packets checked for id/name/answer mismatches
- **X.509 Hostname Verification**: pure-Python DER reader with wildcard SAN matching
- **JSON Event Emission**: SIEM-compatible structured event output
- **Configurable Thresholds**: Tunable sensitivity for each detector
- **Offline Processing**: Parses embedded sample data for demonstration

## Installation

```bash
# No external dependencies required — pure Python stdlib
python3 firmware/mitm_detectors.py
```

## Usage

```bash
# Run full demo with embedded sample data + real capture parsers
python3 firmware/mitm_detectors.py

# Report mode writes reports/mitm_report.json
python3 firmware/mitm_detectors.py --demo-report

# Plan only
python3 firmware/mitm_detectors.py --dry-run

# Programmatic usage
from mitm_detectors import ARPCacheWatcher, ARPFrameAnalyzer, \
    DNSPacketPairChecker, TLSHostnameChecker, build_dns_query, \
    build_dns_response, build_arp_frame, FIXTURE_CERT_DER_B64

arp = ARPCacheWatcher(threshold=3)
alerts = arp.process_events(sample_arp_events)

frame = build_arp_frame("aa:bb:cc:dd:ee:01", "192.168.1.1",
                        "ff:ff:ff:ff:ff:ff", "192.168.1.50")
mitm = ARPFrameAnalyzer()
print(mitm.process_frame(frame))
```

## Example Output

```
============================================================
  X9 — MITM & Spoofing Detectors
============================================================

[*] Loading embedded sample data...
[*] 3 detector modules initialized

--- ARP Cache Watcher ---
  [!] ARP DRIFT DETECTED: Gateway 192.168.1.1 MAC changed
      Old: aa:bb:cc:dd:ee:01 → New: aa:bb:cc:dd:ee:99
      5 gratuitous ARP replies in 2s window
      Severity: HIGH | Technique: T1557.002 (ARP Cache Poisoning)

--- DHCP Pool Gauge ---
  [!] DHCP EXHAUSTION WARNING: Pool utilization at 97%
      Active leases: 243/250 | Offer rate: 0
      Starvation pattern: 180 unique MACs in 60s
      Severity: HIGH | Technique: T1557.001 (LLMNR/NBT-NS)

--- DNS Consistency Checker ---
  [!] DNS SPOOF DETECTED: canary.example.com
      Resolver 10.0.0.1 → 10.0.0.99 (attacker)
      Resolver 10.0.0.2 → 93.184.216.34 (legitimate)
      3/5 canary queries returned forged answers
      Severity: CRITICAL | Technique: T1557.003 (DHCP)

=== Summary ===
  Total alerts: 3 (1 CRITICAL, 2 HIGH)
  Detectors active: ARP=1, DHCP=1, DNS=1

=== SIEM Events (JSON) ===
{"timestamp":"2026-09-04T12:00:00Z","detector":"arp_watcher","severity":"HIGH","detail":"Gateway MAC drift aa:bb:cc:dd:ee:01→aa:bb:cc:dd:ee:99","technique":"T1557.002"}
{"timestamp":"2026-09-04T12:00:00Z","detector":"dhcp_gauge","severity":"HIGH","detail":"Pool exhaustion 97% utilization 243/250","technique":"T1557.001"}
{"timestamp":"2026-09-04T12:00:00Z","detector":"dns_checker","severity":"CRITICAL","detail":"DNS spoof canary.example.com forged 3/5","technique":"T1557.003"}
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission before deploying these detectors on monitored networks
- Monitoring network traffic and ARP/DHCP/DNS behavior may require authorization from network owners
- These tools should ONLY be used on networks you own or have written authorization to monitor
- Alert data must be handled in accordance with organizational data retention policies

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **ECPA/Wiretap Act**: Intercepting network traffic may require authorization
- **GDPR/CCPA**: Network monitoring data may contain personal data subject to privacy regulations
- **State Laws**: Many states have additional computer crime and privacy statutes

### Acceptable Use
- Monitoring your own network infrastructure for spoofing attacks
- Authorized security operations center (SOC) deployments with proper authorization
- Academic research in controlled lab environments
- Security education and training demonstrations

### Prohibited Use
- Deploying these detectors on networks without proper authorization
- Using detection results to target individuals without legal basis
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you detect real spoofing attacks using these tools, follow responsible disclosure practices:
1. Report to the network owner/administrator immediately
2. Contain the attack if within your authorized scope
3. Preserve forensic evidence for investigation
4. Follow your organization's incident response procedures
5. Do not attempt to counter-attack the spoofing source

## Live Lab Test Plan

1. `python3 firmware/mitm_detectors.py` — runs all six detectors: ARP drift, DHCP
   exhaustion, DNS canary check, plus the real frame/packet/cert parsers; prints
   `ARP CONFLICT`, `DNS MISMATCH` and `TLS HOSTNAME MISMATCH` alerts and JSON SIEM
   events; exits 0.
2. `python3 firmware/mitm_detectors.py --dry-run` — prints plan, exit 0.
3. `python3 firmware/mitm_detectors.py --demo-report` — writes
   `reports/mitm_report.json` containing all alerts plus the parsed capture details.
4. `python3 -m unittest discover -s tests` — 26 assertions covering raw ARP frame
   round-trips, DNS wire parsing, spoofed-answer and transaction-id detection, and
   X.509 CN/SAN extraction with wildcard matching (all offline).

## Metrics

- 6 detection paths: `arp_watcher`, `dhcp_gauge`, `dns_checker` + real `arp_frame`,
  `dns_pair`, `tls_cert`
- ARP: byte-exact RFC 826 parser; IP/MAC conflict and gratuitous-reply alerts
- DNS: real wire-format query builder (`build_dns_query`) and response builder
  (`build_dns_response`); transaction-id, question-name and answer spoof checks
- TLS: pure-stdlib ASN.1/DER reader extracts CN and SAN (2.5.29.17) with `*.domain`
  wildcard matching; self-signed fixture (CN=SAN=legit.example.com) verifies both
  match and mismatch paths
- 26 unittest assertions, all offline; no packets sent, no network namespace needed
- `reports/mitm_report.json` (gitignored) captures full alert set

## License

MIT
