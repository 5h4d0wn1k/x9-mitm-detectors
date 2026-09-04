#!/usr/bin/env python3
"""X9 — MITM & Spoofing Detectors. Defensive daemon trio: ARP watcher, DHCP gauge, DNS checker."""

import hashlib
import json
import random
import sys
import time
from collections import defaultdict

SAMPLE_ARP_EVENTS = [
    {"ts": "2026-09-04T12:00:00Z", "type": "arp_reply", "sender_ip": "192.168.1.1", "sender_mac": "aa:bb:cc:dd:ee:01", "target_ip": "192.168.1.50", "target_mac": "ff:ff:ff:ff:ff:ff"},
    {"ts": "2026-09-04T12:00:00Z", "type": "arp_reply", "sender_ip": "192.168.1.1", "sender_mac": "aa:bb:cc:dd:ee:01", "target_ip": "192.168.1.51", "target_mac": "ff:ff:ff:ff:ff:ff"},
    {"ts": "2026-09-04T12:00:00Z", "type": "arp_reply", "sender_ip": "192.168.1.1", "sender_mac": "aa:bb:cc:dd:ee:01", "target_ip": "192.168.1.52", "target_mac": "ff:ff:ff:ff:ff:ff"},
    {"ts": "2026-09-04T12:00:01Z", "type": "arp_reply", "sender_ip": "192.168.1.1", "sender_mac": "aa:bb:cc:dd:ee:99", "target_ip": "192.168.1.50", "target_mac": "ff:ff:ff:ff:ff:ff"},
    {"ts": "2026-09-04T12:00:01Z", "type": "arp_reply", "sender_ip": "192.168.1.1", "sender_mac": "aa:bb:cc:dd:ee:99", "target_ip": "192.168.1.51", "target_mac": "ff:ff:ff:ff:ff:ff"},
    {"ts": "2026-09-04T12:00:01Z", "type": "arp_reply", "sender_ip": "192.168.1.1", "sender_mac": "aa:bb:cc:dd:ee:99", "target_ip": "192.168.1.52", "target_mac": "ff:ff:ff:ff:ff:ff"},
    {"ts": "2026-09-04T12:00:02Z", "type": "arp_reply", "sender_ip": "192.168.1.1", "sender_mac": "aa:bb:cc:dd:ee:99", "target_ip": "192.168.1.53", "target_mac": "ff:ff:ff:ff:ff:ff"},
    {"ts": "2026-09-04T12:00:02Z", "type": "arp_reply", "sender_ip": "192.168.1.1", "sender_mac": "aa:bb:cc:dd:ee:99", "target_ip": "192.168.1.54", "target_mac": "ff:ff:ff:ff:ff:ff"},
    {"ts": "2026-09-04T12:00:03Z", "type": "arp_request", "sender_ip": "192.168.1.50", "sender_mac": "11:22:33:44:55:66", "target_ip": "192.168.1.1", "target_mac": "00:00:00:00:00:00"},
]

SAMPLE_DHCP_EVENTS = [
    {"ts": "2026-09-04T12:00:00Z", "type": "dhcp_discover", "mac": "aa:bb:01:01:01:01"},
    {"ts": "2026-09-04T12:00:00Z", "type": "dhcp_discover", "mac": "aa:bb:02:02:02:02"},
    {"ts": "2026-09-04T12:00:00Z", "type": "dhcp_discover", "mac": "aa:bb:03:03:03:03"},
    {"ts": "2026-09-04T12:00:00Z", "type": "dhcp_discover", "mac": "aa:bb:04:04:04:04"},
    {"ts": "2026-09-04T12:00:00Z", "type": "dhcp_discover", "mac": "aa:bb:05:05:05:05"},
    {"ts": "2026-09-04T12:00:00Z", "type": "dhcp_discover", "mac": "aa:bb:06:06:06:06"},
    {"ts": "2026-09-04T12:00:00Z", "type": "dhcp_discover", "mac": "aa:bb:07:07:07:07"},
    {"ts": "2026-09-04T12:00:00Z", "type": "dhcp_discover", "mac": "aa:bb:08:08:08:08"},
    {"ts": "2026-09-04T12:00:00Z", "type": "dhcp_discover", "mac": "aa:bb:09:09:09:09"},
    {"ts": "2026-09-04T12:00:00Z", "type": "dhcp_discover", "mac": "aa:bb:0a:0a:0a:0a"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:0b:0b:0b:0b"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:0c:0c:0c:0c"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:0d:0d:0d:0d"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:0e:0e:0e:0e"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:0f:0f:0f:0f"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:10:10:10:10"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:11:11:11:11"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:12:12:12:12"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:13:13:13:13"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:14:14:14:14"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:15:15:15:15"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:16:16:16:16"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:17:17:17:17"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:18:18:18:18"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:19:19:19:19"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dhcp_discover", "mac": "aa:bb:1a:1a:1a:1a"},
    {"ts": "2026-09-04T12:00:02Z", "type": "dhcp_discover", "mac": "aa:bb:1b:1b:1b:1b"},
    {"ts": "2026-09-04T12:00:02Z", "type": "dhcp_discover", "mac": "aa:bb:1c:1c:1c:1c"},
    {"ts": "2026-09-04T12:00:02Z", "type": "dhcp_discover", "mac": "aa:bb:1d:1d:1d:1d"},
    {"ts": "2026-09-04T12:00:02Z", "type": "dhcp_discover", "mac": "aa:bb:1e:1e:1e:1e"},
    {"ts": "2026-09-04T12:00:02Z", "type": "dhcp_discover", "mac": "aa:bb:1f:1f:1f:1f"},
    {"ts": "2026-09-04T12:00:02Z", "type": "dhcp_offer", "mac": "aa:bb:01:01:01:01", "ip": "192.168.1.100"},
    {"ts": "2026-09-04T12:00:02Z", "type": "dhcp_offer", "mac": "aa:bb:02:02:02:02", "ip": "192.168.1.101"},
    {"ts": "2026-09-04T12:00:02Z", "type": "dhcp_offer", "mac": "aa:bb:03:03:03:03", "ip": "192.168.1.102"},
    {"ts": "2026-09-04T12:00:03Z", "type": "dhcp_discover", "mac": "aa:bb:20:20:20:20"},
    {"ts": "2026-09-04T12:00:03Z", "type": "dhcp_discover", "mac": "aa:bb:21:21:21:21"},
    {"ts": "2026-09-04T12:00:03Z", "type": "dhcp_discover", "mac": "aa:bb:22:22:22:22"},
    {"ts": "2026-09-04T12:00:03Z", "type": "dhcp_discover", "mac": "aa:bb:23:23:23:23"},
    {"ts": "2026-09-04T12:00:03Z", "type": "dhcp_discover", "mac": "aa:bb:24:24:24:24"},
    {"ts": "2026-09-04T12:00:04Z", "type": "dhcp_discover", "mac": "aa:bb:25:25:25:25"},
    {"ts": "2026-09-04T12:00:04Z", "type": "dhcp_discover", "mac": "aa:bb:26:26:26:26"},
    {"ts": "2026-09-04T12:00:04Z", "type": "dhcp_discover", "mac": "aa:bb:27:27:27:27"},
    {"ts": "2026-09-04T12:00:04Z", "type": "dhcp_discover", "mac": "aa:bb:28:28:28:28"},
    {"ts": "2026-09-04T12:00:04Z", "type": "dhcp_discover", "mac": "aa:bb:29:29:29:29"},
]

SAMPLE_DNS_EVENTS = [
    {"ts": "2026-09-04T12:00:00Z", "type": "dns_response", "domain": "canary.example.com", "resolver": "10.0.0.1", "answer": "10.0.0.99"},
    {"ts": "2026-09-04T12:00:00Z", "type": "dns_response", "domain": "canary.example.com", "resolver": "10.0.0.2", "answer": "93.184.216.34"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dns_response", "domain": "canary.example.com", "resolver": "10.0.0.3", "answer": "10.0.0.99"},
    {"ts": "2026-09-04T12:00:01Z", "type": "dns_response", "domain": "canary.example.com", "resolver": "10.0.0.1", "answer": "10.0.0.99"},
    {"ts": "2026-09-04T12:00:02Z", "type": "dns_response", "domain": "canary.example.com", "resolver": "10.0.0.2", "answer": "93.184.216.34"},
    {"ts": "2026-09-04T12:00:02Z", "type": "dns_response", "domain": "canary.example.com", "resolver": "10.0.0.3", "answer": "10.0.0.99"},
    {"ts": "2026-09-04T12:00:03Z", "type": "dns_response", "domain": "canary.example.com", "resolver": "10.0.0.1", "answer": "93.184.216.34"},
    {"ts": "2026-09-04T12:00:03Z", "type": "dns_response", "domain": "google.com", "resolver": "10.0.0.1", "answer": "142.250.80.46"},
    {"ts": "2026-09-04T12:00:03Z", "type": "dns_response", "domain": "google.com", "resolver": "10.0.0.2", "answer": "142.250.80.46"},
    {"ts": "2026-09-04T12:00:04Z", "type": "dns_response", "domain": "github.com", "resolver": "10.0.0.1", "answer": "140.82.121.3"},
    {"ts": "2026-09-04T12:00:04Z", "type": "dns_response", "domain": "github.com", "resolver": "10.0.0.2", "answer": "140.82.121.3"},
]

GATEWAY_LEGIT_MAC = "aa:bb:cc:dd:ee:01"
DHCP_POOL_SIZE = 250
DNS_CANARY_DOMAIN = "canary.example.com"
DNS_LEGIT_IP = "93.184.216.34"


class ARPCacheWatcher:
    """Monitor gateway MAC for drift indicating ARP spoofing."""

    def __init__(self, gateway_ip="192.168.1.1", threshold=3):
        self.gateway_ip = gateway_ip
        self.threshold = threshold
        self.mac_history = defaultdict(list)
        self.alerts = []

    def process_events(self, events):
        for ev in events:
            if ev.get("type") in ("arp_reply", "arp_request") and ev.get("sender_ip") == self.gateway_ip:
                mac = ev.get("sender_mac", "")
                ts = ev.get("ts", "")
                self.mac_history[mac].append(ts)

        seen_macs = list(self.mac_history.keys())
        if len(seen_macs) > 1:
            mac_counts = {m: len(ts_list) for m, ts_list in self.mac_history.items()}
            primary_mac = max(mac_counts, key=mac_counts.get)
            for mac, count in mac_counts.items():
                if mac != primary_mac and count >= self.threshold:
                    alert = self._emit_alert(mac, primary_mac, count)
                    self.alerts.append(alert)

        return self.alerts

    def _emit_alert(self, rogue_mac, legit_mac, count):
        detail = f"Gateway {self.gateway_ip} MAC changed from {legit_mac} to {rogue_mac}"
        alert = {
            "timestamp": "2026-09-04T12:00:00Z",
            "detector": "arp_watcher",
            "severity": "HIGH",
            "detail": f"{detail} ({count} gratuitous ARP replies in window)",
            "technique": "T1557.002",
        }
        print(f"  [!] ARP DRIFT DETECTED: {detail}")
        print(f"      Old: {legit_mac} -> New: {rogue_mac}")
        print(f"      {count} gratuitous ARP replies detected")
        print(f"      Severity: HIGH | Technique: T1557.002 (ARP Cache Poisoning)")
        return alert


class DHCPPoolGauge:
    """Detect DHCP pool exhaustion from lease counter heuristics."""

    def __init__(self, pool_size=DHCP_POOL_SIZE):
        self.pool_size = pool_size
        self.unique_macs = set()
        self.offer_count = 0
        self.discover_count = 0
        self.alerts = []

    def process_events(self, events):
        for ev in events:
            if ev.get("type") == "dhcp_discover":
                self.discover_count += 1
                mac = ev.get("mac", "")
                self.unique_macs.add(mac)
            elif ev.get("type") == "dhcp_offer":
                self.offer_count += 1

        utilization = len(self.unique_macs) / max(self.pool_size, 1) * 100
        offer_rate = self.offer_count / max(self.discover_count, 1)

        if utilization > 90 or offer_rate < 0.1:
            alert = self._emit_alert(utilization, offer_rate)
            self.alerts.append(alert)

        return self.alerts

    def _emit_alert(self, utilization, offer_rate):
        active = min(len(self.unique_macs), self.pool_size)
        detail = f"DHCP pool exhaustion warning: utilization at {utilization:.0f}%"
        alert = {
            "timestamp": "2026-09-04T12:00:00Z",
            "detector": "dhcp_gauge",
            "severity": "HIGH",
            "detail": f"Pool exhaustion {utilization:.0f}% utilization {active}/{self.pool_size} | offer_rate={offer_rate:.2f}",
            "technique": "T1557.001",
        }
        print(f"  [!] DHCP EXHAUSTION WARNING: Pool utilization at {utilization:.0f}%")
        print(f"      Active leases: {active}/{self.pool_size} | Offer rate: {self.offer_count}/{self.discover_count}")
        print(f"      Starvation pattern: {len(self.unique_macs)} unique MACs in window")
        print(f"      Severity: HIGH | Technique: T1557.001 (LLMNR/NBT-NS)")
        return alert


class DNSConsistencyChecker:
    """Compare canary-domain resolution across resolvers to detect DNS spoofing."""

    def __init__(self, canary_domain=DNS_CANARY_DOMAIN, legit_ip=DNS_LEGIT_IP):
        self.canary_domain = canary_domain
        self.legit_ip = legit_ip
        self.resolver_answers = defaultdict(list)
        self.alerts = []

    def process_events(self, events):
        for ev in events:
            if ev.get("type") == "dns_response" and ev.get("domain") == self.canary_domain:
                resolver = ev.get("resolver", "")
                answer = ev.get("answer", "")
                self.resolver_answers[resolver].append(answer)

        total_queries = sum(len(ans) for ans in self.resolver_answers.values())
        forged = 0
        for resolver, answers in self.resolver_answers.items():
            for ans in answers:
                if ans != self.legit_ip:
                    forged += 1

        if total_queries > 0 and forged / total_queries > 0.3:
            alert = self._emit_alert(forged, total_queries)
            self.alerts.append(alert)

        return self.alerts

    def _emit_alert(self, forged, total):
        detail = f"DNS spoof detected: {self.canary_domain} — {forged}/{total} forged answers"
        alert = {
            "timestamp": "2026-09-04T12:00:00Z",
            "detector": "dns_checker",
            "severity": "CRITICAL",
            "detail": f"DNS spoof {self.canary_domain} forged {forged}/{total}",
            "technique": "T1557.003",
        }
        print(f"  [!] DNS SPOOF DETECTED: {self.canary_domain}")
        for resolver, answers in self.resolver_answers.items():
            last_ans = answers[-1] if answers else "N/A"
            label = "forged" if last_ans != self.legit_ip else "legitimate"
            print(f"      Resolver {resolver} -> {last_ans} ({label})")
        print(f"      {forged}/{total} canary queries returned forged answers")
        print(f"      Severity: CRITICAL | Technique: T1557.003 (DHCP)")
        return alert


def main():
    print("=" * 60)
    print("  X9 — MITM & Spoofing Detectors")
    print("=" * 60)

    print("\n[*] Loading embedded sample data...")
    print(f"[*] 3 detector modules initialized")

    arp = ARPCacheWatcher(gateway_ip="192.168.1.1", threshold=3)
    dhcp = DHCPPoolGauge(pool_size=DHCP_POOL_SIZE)
    dns = DNSConsistencyChecker()

    print("\n--- ARP Cache Watcher ---")
    arp_alerts = arp.process_events(SAMPLE_ARP_EVENTS)

    print("\n--- DHCP Pool Gauge ---")
    dhcp_alerts = dhcp.process_events(SAMPLE_DHCP_EVENTS)

    print("\n--- DNS Consistency Checker ---")
    dns_alerts = dns.process_events(SAMPLE_DNS_EVENTS)

    all_alerts = arp_alerts + dhcp_alerts + dns_alerts
    crit = sum(1 for a in all_alerts if a["severity"] == "CRITICAL")
    high = sum(1 for a in all_alerts if a["severity"] == "HIGH")

    print(f"\n=== Summary ===")
    print(f"  Total alerts: {len(all_alerts)} ({crit} CRITICAL, {high} HIGH)")
    print(f"  Detectors active: ARP={1 if arp_alerts else 0}, DHCP={1 if dhcp_alerts else 0}, DNS={1 if dns_alerts else 0}")

    print("\n=== SIEM Events (JSON) ===")
    for alert in all_alerts:
        print(json.dumps(alert))

    print("\n[+] Detection complete — exit 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
