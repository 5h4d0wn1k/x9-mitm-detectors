# X9 — MITM and Spoofing Detectors

Defensive daemon trio: ARP-cache watcher, DHCP pool gauge, and DNS consistency checker that detect network spoofing attacks and emit SIEM-format JSON alerts from parsed event and PCAP-ish input data.

## Overview

This project is the defensive counterpart to X5 — detects MITM and spoofing attacks:
- **ARP-Cache Watcher**: Monitors gateway MAC address for drift/arbitration table changes
- **DHCP Pool Gauge**: Detects DHCP pool exhaustion from lease counter heuristics
- **DNS Consistency Checker**: Compares canary-domain resolution across multiple resolvers
- **SIEM Output**: All detectors emit normalized JSON events for ingestion into SIEM pipelines
- **Offline Demo**: Runs against embedded sample ARP/DNS/DHCP data without live traffic

## Features

- **ARP Drift Alarm**: Detects gateway MAC address changes indicating ARP spoofing
- **DHCP Exhaustion Detection**: Flags DHCP pool starvation from lease/offer ratios
- **DNS Canary Comparison**: Resolves canary domains across resolvers to detect DNS spoofing
- **JSON Event Emission**: SIEM-compatible structured event output
- **Configurable Thresholds**: Tunable sensitivity for each detector
- **Offline Processing**: Parses embedded sample data for demonstration

## Installation

```bash
# No external dependencies required — pure Python stdlib
python3 mitm_detectors.py
```

## Usage

```bash
# Run full demo with embedded sample data
python3 mitm_detectors.py

# Programmatic usage
from mitm_detectors import ARPCacheWatcher, DHCPPoolGauge, DNSConsistencyChecker

arp = ARPCacheWatcher(threshold=3)
alerts = arp.process_events(sample_arp_events)
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

## License

MIT
