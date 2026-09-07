#!/usr/bin/env python3
"""X9 - MITM & Spoofing Detectors. Defensive daemon trio: ARP watcher, DHCP gauge, DNS checker."""

import argparse
import base64
import hashlib
import json
import os
import random
import struct
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


# ---------------------------------------------------------------------------
# Real-parsing layer: raw ethernet ARP frames, DNS packets, X.509 certificates
# ---------------------------------------------------------------------------

def mac_to_str(b):
    return ":".join("%02x" % x for x in b)


def ipv4_to_str(b):
    return ".".join(str(x) for x in b)


def parse_arp_frame(frame):
    """Parse a raw ethernet frame (14-byte header + ARP payload) into a dict.

    Returns None when the ethertype is not ARP (0x0806). Raises ValueError on
    truncated or malformed payloads.
    """
    if len(frame) < 14 + 28:
        raise ValueError("truncated frame (%d bytes)" % len(frame))
    eth_type = int.from_bytes(frame[12:14], "big")
    if eth_type != 0x0806:
        return None
    arp = frame[14:]
    htype, ptype, hlen, plen, oper = struct.unpack(">HHBBH", arp[:8])
    if hlen == 0 or plen == 0 or 8 + 2 * hlen + 2 * plen > len(arp):
        raise ValueError("malformed ARP fields")
    off = 8
    sha = arp[off:off + hlen]
    off += hlen
    spa = arp[off:off + plen]
    off += plen
    tha = arp[off:off + hlen]
    off += hlen
    tpa = arp[off:off + plen]
    return {
        "eth_type": eth_type,
        "hw_type": htype,
        "proto_type": ptype,
        "hw_len": hlen,
        "proto_len": plen,
        "oper": oper,          # 1 = request, 2 = reply
        "src_mac": mac_to_str(sha),
        "src_ip": ipv4_to_str(spa),
        "dst_mac": mac_to_str(tha),
        "dst_ip": ipv4_to_str(tpa),
    }


def build_arp_frame(src_mac, src_ip, dst_mac, dst_ip, oper=2,
                    eth_src=None, eth_dst=b"\xff" * 6, htype=1, ptype=0x0800):
    """Build a raw ethernet+ARP frame. oper: 1 = request, 2 = reply."""
    sha = bytes.fromhex(src_mac.replace(":", ""))
    tha = bytes.fromhex(dst_mac.replace(":", ""))
    spa = bytes(map(int, src_ip.split(".")))
    tpa = bytes(map(int, dst_ip.split(".")))
    arp = struct.pack(">HHBBH", htype, ptype, len(sha), len(spa), oper)
    arp += sha + spa + tha + tpa
    eth_src = bytes.fromhex((eth_src or src_mac).replace(":", ""))
    return eth_dst + eth_src + b"\x08\x06" + arp


class ARPFrameAnalyzer:
    """Analyze raw ARP frames: gratuitous announcements and IP/MAC conflicts."""

    def __init__(self, trusted_ip="192.168.1.1",
                 trusted_macs=("aa:bb:cc:dd:ee:01",)):
        self.trusted_ip = trusted_ip
        self.trusted_macs = set(m.lower() for m in trusted_macs)
        self.ip_mac_map = {}
        self.alerts = []

    def process_frames(self, frames):
        for frame in frames:
            self.process_frame(frame)
        return self.alerts

    def process_frame(self, frame):
        try:
            pkt = parse_arp_frame(frame)
        except ValueError:
            return
        if pkt is None:
            return
        mac = pkt["src_mac"].lower()
        ip = pkt["src_ip"]
        if pkt["oper"] == 2 and pkt["src_ip"] == pkt["dst_ip"]:
            alert = {
                "timestamp": "2026-09-04T12:00:00Z",
                "detector": "arp_frame",
                "severity": "MEDIUM",
                "detail": "gratuitous ARP reply: %s claims %s" % (mac, ip),
                "technique": "T1557.002",
            }
            self.alerts.append(alert)
            print(f"  [!] GRATUITOUS ARP: {mac} announces {ip}")
        if ip == self.trusted_ip and mac not in self.trusted_macs:
            prev = self.ip_mac_map.get(ip)
            if prev is not None and prev != mac:
                alert = {
                    "timestamp": "2026-09-04T12:00:00Z",
                    "detector": "arp_frame",
                    "severity": "HIGH",
                    "detail": "IP/MAC conflict: %s claimed by %s and %s" % (ip, prev, mac),
                    "technique": "T1557.002",
                }
                self.alerts.append(alert)
                print(f"  [!] ARP CONFLICT: {ip} seen on {prev} then {mac}")
        self.ip_mac_map[ip] = mac


def _read_dns_name(pkt, off):
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels = []
    jumped = None
    pos = off
    while True:
        length = pkt[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(pkt):
                raise ValueError("truncated DNS pointer")
            ptr = ((length & 0x3F) << 8) | pkt[pos + 1]
            if jumped is None:
                jumped = pos + 2
            pos = ptr
            continue
        if length == 0:
            pos += 1
            break
        if pos + 1 + length > len(pkt):
            raise ValueError("truncated DNS label")
        labels.append(pkt[pos + 1:pos + 1 + length].decode("latin-1"))
        pos += 1 + length
    end = jumped if jumped is not None else pos
    return ".".join(labels), end


def parse_dns_packet(pkt):
    """Parse a DNS message (query or response) into a dict."""
    if len(pkt) < 12:
        raise ValueError("DNS packet too short")
    dns_id = int.from_bytes(pkt[0:2], "big")
    flags = int.from_bytes(pkt[2:4], "big")
    qd = int.from_bytes(pkt[4:6], "big")
    an = int.from_bytes(pkt[6:8], "big")
    off = 12
    questions = []
    for _ in range(qd):
        name, off = _read_dns_name(pkt, off)
        qtype = int.from_bytes(pkt[off:off + 2], "big")
        off += 2
        qclass = int.from_bytes(pkt[off:off + 2], "big")
        off += 2
        questions.append({"name": name, "type": qtype, "class": qclass})
    answers = []
    for _ in range(an):
        name, off = _read_dns_name(pkt, off)
        rtype = int.from_bytes(pkt[off:off + 2], "big")
        off += 2
        rclass = int.from_bytes(pkt[off:off + 2], "big")
        off += 2
        ttl = int.from_bytes(pkt[off:off + 4], "big")
        off += 4
        rdlen = int.from_bytes(pkt[off:off + 2], "big")
        off += 2
        rdata = pkt[off:off + rdlen]
        if rtype == 1 and len(rdata) == 4:
            rr = ipv4_to_str(rdata)
        else:
            rr = rdata.hex()
        answers.append({"name": name, "type": rtype, "ttl": ttl, "rdata": rr})
        off += rdlen
    return {
        "id": dns_id,
        "flags": flags,
        "qr": bool(flags & 0x8000),
        "rcode": flags & 0x000F,
        "questions": questions,
        "answers": answers,
    }


def build_dns_query(name, qid=0xBEEF):
    """Build a real A-type DNS query packet."""
    pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        pkt += struct.pack("B", len(label)) + label.encode()
    pkt += b"\x00" + struct.pack(">HH", 1, 1)
    return pkt


def build_dns_response(query_pkt, answer_ip, qid=None, rcode_ok=True):
    """Build a real A-type DNS response packet for a given query."""
    q = parse_dns_packet(query_pkt)
    qid = qid if qid is not None else q["id"]
    flags = 0x8180 if rcode_ok else 0x8183
    pkt = struct.pack(">HHHHHH", qid, flags, 1, 1, 0, 0)
    name = q["questions"][0]["name"]
    for label in name.split("."):
        pkt += struct.pack("B", len(label)) + label.encode()
    pkt += b"\x00" + struct.pack(">HH", 1, 1)
    pkt += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
    pkt += bytes(map(int, answer_ip.split(".")))
    return pkt


class DNSPacketPairChecker:
    """Check a real DNS response against its query and a trust expectation."""

    def __init__(self, legit_answers=None):
        self.legit_answers = legit_answers or {DNS_CANARY_DOMAIN: DNS_LEGIT_IP}
        self.alerts = []

    def check_pair(self, query_pkt, response_pkt):
        try:
            q = parse_dns_packet(query_pkt)
            r = parse_dns_packet(response_pkt)
        except ValueError:
            return None
        problems = []
        if r["id"] != q["id"]:
            problems.append("transaction id mismatch (%#x vs %#x)" % (r["id"], q["id"]))
        if not r["qr"]:
            problems.append("no QR flag — not a response")
        if not q["questions"] or not r["questions"]:
            problems.append("missing question section")
        elif r["questions"][0]["name"] != q["questions"][0]["name"]:
            problems.append("question name %s != %s" % (q["questions"][0]["name"], r["questions"][0]["name"]))
        name = q["questions"][0]["name"] if q["questions"] else ""
        if name in self.legit_answers:
            rdata = r["answers"][0]["rdata"] if r["answers"] else ""
            if rdata != self.legit_answers[name]:
                problems.append("answer %s for %s expected %s (spoofed)" % (
                    rdata, name, self.legit_answers[name]))
        if not problems:
            return None
        alert = {
            "timestamp": "2026-09-04T12:00:00Z",
            "detector": "dns_pair",
            "severity": "CRITICAL" if any("spoofed" in p for p in problems) else "HIGH",
            "detail": "; ".join(problems),
            "technique": "T1557.003",
        }
        self.alerts.append(alert)
        print(f"  [!] DNS MISMATCH: {'; '.join(problems)}")
        return alert


# --- Minimal ASN.1 DER reader (no external crypto library) -----------------

def _der_tag_length(buf, off):
    """Return (tag, tag_len_index, value_length) at offsets within buf."""
    tag = buf[off]
    off += 1
    lb = buf[off]
    off += 1
    if lb & 0x80:
        n = lb & 0x7f
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    else:
        ln = lb
    return tag, off, ln


def _der_tlv(buf, off):
    """Read one DER TLV. Returns (tag, value_bytes, value_start, tlv_end)."""
    tag, after_len, ln = _der_tag_length(buf, off)
    vstart = after_len
    if vstart + ln > len(buf):
        raise ValueError("DER value runs past buffer end")
    return tag, buf[vstart:vstart + ln], vstart, vstart + ln


def _walk_sequence(buf, start, end):
    out = []
    while start < end:
        tag, val, vstart, vlen_end = _der_tlv(buf, start)
        out.append((tag, val))
        start = vlen_end
    return out


def parse_cert_der(der):
    """Split a DER X.509 certificate into its top-level structures."""
    tag, cert, cstart, cend = _der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("expected SEQUENCE, got tag %#x" % tag)
    tbuf = cert
    tag, tbs, tstart, tend = _der_tlv(tbuf, 0)
    if tag != 0x30:
        raise ValueError("expected tbsCertificate SEQUENCE")
    parts = _walk_sequence(tbuf, tstart, tend)
    subject = parts[5][1] if len(parts) > 5 else None
    extensions = None
    for ptag, pval in parts:
        if ptag == 0xA3:
            extensions = pval
    return {"subject": subject, "extensions": extensions}


CN_OID = bytes([0x55, 0x04, 0x03])
SAN_OID = bytes([0x55, 0x1D, 0x11])


def extract_subject_cn(subject_val):
    """Return the commonName list from an X.509 subject field value."""
    cns = []
    for rtag, rval in _walk_sequence(subject_val, 0, len(subject_val)):
        for atag, aval in _walk_sequence(rval, 0, len(rval)):
            tag, oid, vstart, vend = _der_tlv(aval, 0)
            if oid == CN_OID:
                straq, str_val, _, _ = _der_tlv(aval, vend)
                cns.append(str_val.decode("utf-8", errors="replace"))
    return cns


def extract_subject_alt_names(extensions_val):
    """Return [(kind, value)] SAN list from the [3] extensions field value."""
    tag, seq, sstart, send = _der_tlv(extensions_val, 0)
    if tag != 0x30:
        return []
    sans = []
    for etag, ev in _walk_sequence(extensions_val, sstart, send):
        elems = _walk_sequence(ev, 0, len(ev))
        oid = elems[0][1]
        idx = 2 if elems[1][0] == 0x01 else 1
        octet = elems[idx][1]
        if oid == SAN_OID:
            inner_tag, gname, gstart, gend = _der_tlv(octet, 0)
            for gt, gv in _walk_sequence(octet, gstart, gend):
                if gt == 0x82:
                    sans.append(("DNS", gv.decode("utf-8", errors="replace")))
                elif gt == 0x87:
                    sans.append(("IP", ".".join(str(x) for x in gv)))
    return sans


def _hostname_matches(pattern, hostname):
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname.count(".") == suffix.count(".")
    return False


# Self-signed fixture certificate: CN=legit.example.com,
# SAN DNS:legit.example.com + DNS:api.legit.example.com (DER base64)
FIXTURE_CERT_DER_B64 = (
    "MIIDUDCCAjigAwIBAgIUVAJOUs2s96fvddzNvFomOvwW9VEwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UEAwwRbGVnaXQuZXhhbXBsZS5jb20wHhcNMjYwOTA3MDcxMTQ3WhcNMzYwOTA0MDcxMTQ3WjAcMRowGAYDVQQDDBFsZWdpdC5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALh9k1/FEfLCqrUQJyiC/HCUrMYhaNm8dD5kqQhuqifcPhCEqGQMgUrjN6nKc9YquFjanHBl/QkEjFt9T7NKWpp4isuuh3Wo9pjJase/RooRlZlwcL0iqezof0v7Fl4Y92UfQ+lWCODnmzoYTQ6PAPNdg8FhJovTOCEy2gfiWoYDO9IBV+9E/D2/dwdhD0jSGbBui9JjUldo2SHmNtb3H/LqVYGyEW7JBxzwiH3SljvlCzoxasFaGnNVgJtZbJpvANM6J/0HcDm9LUGb4b/kdH3dodIGJJo88fR8HHQ6oJ/jAuEYBxFNfYIArIbEQb3lRtHFEh8Kg5B05NnVyyGLryECAwEAAaOBiTCBhjAdBgNVHQ4EFgQU+IZVtu/8ULitpMFJQSc3bx71CkUwHwYDVR0jBBgwFoAU+IZVtu/8ULitpMFJQSc3bx71CkUwDwYDVR0TAQH/BAUwAwEB/zAzBgNVHREELDAqghFsZWdpdC5leGFtcGxlLmNvbYIVYXBpLmxlZ2l0LmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAND9cDHRQtoZynX6yhA3qfty1OhjrtpSXG9QPp8XlRtUPMmz9efuYCtaTyOjlbkcp/zD3g3FIM96YZ+JtbPGpQpRI5NbNy1mCQMDRo9ueIjktuQRtMA+1zqnIKcuBJq7Kci3sgO6FP6kDoTeEv1l4x5lQJSakDMLOl5LORs2/NLj4A+LPzzqj7rcuSiWdWicQHRmfwiiYBeimhkbbWZLvUgleL3OB8ImIWCNmo1bzxvJyTN/mVKbNcyLPIGczhbBASQ3Dq916ZiLXpA5TcugOkfs2Ij6ZOml5RnSChYs+lq9I+hKJ+5WbvmaniWojWxw6pi689mI70xwJvfERgIIGr")


class TLSHostnameChecker:
    """Verify a certificate's SAN/CN against an expected hostname."""

    def __init__(self):
        self.alerts = []

    def verify_hostname(self, der_b64, hostname):
        der = base64.b64decode(der_b64)
        info = parse_cert_der(der)
        sans = extract_subject_alt_names(info["extensions"])
        cns = extract_subject_cn(info["subject"])
        san_dns = [v for (k, v) in sans if k == "DNS"]
        ok = any(_hostname_matches(p, hostname) for p in san_dns)
        matched_by = "SAN"
        if not ok:
            ok = any(_hostname_matches(c, hostname) for c in cns)
            matched_by = "CN" if ok else None
        return {
            "hostname": hostname,
            "matches": ok,
            "matched_by": matched_by,
            "san": san_dns,
            "cn": cns,
        }

    def check(self, der_b64, hostname):
        res = self.verify_hostname(der_b64, hostname)
        if not res["matches"]:
            alert = {
                "timestamp": "2026-09-04T12:00:00Z",
                "detector": "tls_cert",
                "severity": "CRITICAL",
                "detail": ("certificate for %s does not match SAN %s nor CN %s" % (
                    hostname, res["san"] or "-", res["cn"] or "-")),
                "technique": "T1557.003",
            }
            self.alerts.append(alert)
            print(f"  [!] TLS HOSTNAME MISMATCH: {hostname} not covered by cert "
                  f"(SAN={res['san'] or '-'} CN={res['cn'] or '-'})")
        return res


def demo_real_capture():
    """Run the real-parsing detectors (ARP frames, DNS packets, TLS certs)."""
    print("  (raw ethernet ARP frames, DNS packets, X.509 certs — no network)")
    arp = ARPFrameAnalyzer(trusted_ip="192.168.1.1")
    frames = [
        build_arp_frame("aa:bb:cc:dd:ee:01", "192.168.1.1",
                        "ff:ff:ff:ff:ff:ff", "192.168.1.50", oper=2),
        build_arp_frame("aa:bb:cc:dd:ee:99", "192.168.1.1",
                        "ff:ff:ff:ff:ff:ff", "192.168.1.50", oper=2),
    ]
    parsed = parse_arp_frame(frames[0])
    print(f"    frame: ethertype=0x{parsed['eth_type']:04x} oper={parsed['oper']} "
          f"{parsed['src_mac']}/{parsed['src_ip']} -> {parsed['dst_mac']}/{parsed['dst_ip']}")
    arp_alerts = arp.process_frames(frames)

    q = build_dns_query(DNS_CANARY_DOMAIN, qid=0xBEEF)
    forged = build_dns_response(q, "10.0.0.99")
    checker = DNSPacketPairChecker()
    dns_query = parse_dns_packet(q)
    dns_resp = parse_dns_packet(forged)
    print(f"    query {dns_query['id']:#06x} {dns_query['questions'][0]['name']} A")
    print(f"    response {dns_resp['id']:#06x} answers=%s" % dns_resp["answers"][0]["rdata"])
    dns_alerts = [checker.check_pair(q, forged)]

    tls = TLSHostnameChecker()
    tls_check_ok = tls.check(FIXTURE_CERT_DER_B64, "legit.example.com")
    tls_check_bad = tls.check(FIXTURE_CERT_DER_B64, "fake.example.net")
    print(f"    cert SAN={tls_check_ok['san']} CN={tls_check_ok['cn']}")

    alerts = list(arp_alerts) + [a for a in dns_alerts if a] + list(tls.alerts)
    return {
        "arp_frame": list(arp_alerts),
        "dns_pair": [a for a in dns_alerts if a],
        "tls_cert": list(tls.alerts),
        "capture": {
            "arp": parsed,
            "dns_query": {"id": dns_query["id"], "name": dns_query["questions"][0]["name"]},
            "dns_response": {"id": dns_resp["id"], "rdata": dns_resp["answers"][0]["rdata"]},
            "tls": tls_check_ok,
        },
        "total_alerts": len(alerts),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="mitm_detectors",
        description="X9 - MITM & Spoofing Detectors: ARP-cache watch, DHCP pool "
                    "gauge, DNS consistency check. Detects ARP/DHCP/DNS spoofing "
                    "from parsed event streams.",
        epilog="Authorized lab/network-owner use only.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print plan and exit without analysis")
    ap.add_argument("--demo-report", action="store_true",
                    help="run analysis and write JSON report to reports/")
    args = ap.parse_args(argv)

    if args.dry_run:
        print("dry-run: detectors=arp,dhcp,dns (no execution)")
        return 0

    if args.demo_report:
        return run_demo_report()

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

    print("\n--- Real Capture Parsers (ARP frames / DNS packets / X.509) ---")
    real = demo_real_capture()
    arp_alerts += real["arp_frame"]
    dns_alerts += real["dns_pair"]
    tls_alerts = real["tls_cert"]

    all_alerts = arp_alerts + dhcp_alerts + dns_alerts + tls_alerts
    crit = sum(1 for a in all_alerts if a["severity"] == "CRITICAL")
    high = sum(1 for a in all_alerts if a["severity"] == "HIGH")
    med = sum(1 for a in all_alerts if a["severity"] == "MEDIUM")

    print(f"\n=== Summary ===")
    print(f"  Total alerts: {len(all_alerts)} ({crit} CRITICAL, {high} HIGH, {med} MEDIUM)")
    print(f"  Detectors active: ARP={1 if arp_alerts else 0}, DHCP={1 if dhcp_alerts else 0}, "
          f"DNS={1 if dns_alerts else 0}, ARP-frame={1 if real['arp_frame'] else 0}, "
          f"DNS-pair={1 if real['dns_pair'] else 0}, TLS-cert={1 if real['tls_cert'] else 0}")

    print("\n=== SIEM Events (JSON) ===")
    for alert in all_alerts:
        print(json.dumps(alert))

    print("\n[+] Detection complete — exit 0")
    return 0


def run_demo_report():
    """Run analysis and write JSON report to reports/."""
    print("=== X9 - MITM & Spoofing Detectors (report mode) ===")
    reports = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports")
    os.makedirs(reports, exist_ok=True)
    arp = ARPCacheWatcher(gateway_ip="192.168.1.1", threshold=3)
    dhcp = DHCPPoolGauge(pool_size=DHCP_POOL_SIZE)
    dns = DNSConsistencyChecker()
    arp_alerts = arp.process_events(SAMPLE_ARP_EVENTS)
    dhcp_alerts = dhcp.process_events(SAMPLE_DHCP_EVENTS)
    dns_alerts = dns.process_events(SAMPLE_DNS_EVENTS)
    real = demo_real_capture()
    report = {
        "tool": "mitm-detectors-x9",
        "arp_alerts": arp_alerts,
        "dhcp_alerts": dhcp_alerts,
        "dns_alerts": dns_alerts,
        "real_capture": real,
        "total_alerts": (len(arp_alerts + dhcp_alerts + dns_alerts)
                         + real["total_alerts"]),
    }
    out = os.path.join(reports, "mitm_report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Report written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
