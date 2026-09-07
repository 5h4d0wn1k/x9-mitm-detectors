#!/usr/bin/env python3
"""Tests for X9 - MITM & Spoofing Detectors."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

FIRMWARE = os.path.join(os.path.dirname(__file__), os.pardir, "firmware")
ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
if FIRMWARE not in sys.path:
    sys.path.insert(0, FIRMWARE)

from mitm_detectors import (
    ARPCacheWatcher, ARPFrameAnalyzer, DHCPPoolGauge, DNSConsistencyChecker,
    DNSPacketPairChecker, TLSHostnameChecker, build_arp_frame, build_dns_query,
    build_dns_response, parse_arp_frame, parse_dns_packet,
    _hostname_matches,
    SAMPLE_ARP_EVENTS, SAMPLE_DHCP_EVENTS, SAMPLE_DNS_EVENTS,
    GATEWAY_LEGIT_MAC, DNS_CANARY_DOMAIN, DNS_LEGIT_IP, FIXTURE_CERT_DER_B64,
)


class TestARPCacheWatcher(unittest.TestCase):
    def test_no_alert_normal(self):
        watcher = ARPCacheWatcher(gateway_ip="192.168.1.1")
        events = [e for e in SAMPLE_ARP_EVENTS if e.get("sender_mac") == GATEWAY_LEGIT_MAC]
        alerts = watcher.process_events(events)
        self.assertEqual(len(alerts), 0)

    def test_detects_mac_drift(self):
        watcher = ARPCacheWatcher(gateway_ip="192.168.1.1", threshold=2)
        alerts = watcher.process_events(SAMPLE_ARP_EVENTS)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertIn("T1557.002", alerts[0]["technique"])

    def test_gateway_ip_filter(self):
        watcher = ARPCacheWatcher(gateway_ip="10.0.0.1", threshold=1)
        alerts = watcher.process_events(SAMPLE_ARP_EVENTS)
        self.assertEqual(len(alerts), 0)


class TestDHCPPoolGauge(unittest.TestCase):
    def test_detects_exhaustion(self):
        gauge = DHCPPoolGauge(pool_size=250)
        alerts = gauge.process_events(SAMPLE_DHCP_EVENTS)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_no_alert_low_utilization(self):
        gauge = DHCPPoolGauge(pool_size=10000)
        events = [{"type": "dhcp_discover", "mac": "aa:bb:00:00:00:01"},
                  {"type": "dhcp_offer", "mac": "aa:bb:00:00:00:01", "ip": "10.0.0.1"}]
        alerts = gauge.process_events(events)
        self.assertEqual(len(alerts), 0)

    def test_offer_rate_tracking(self):
        gauge = DHCPPoolGauge(pool_size=250)
        gauge.process_events(SAMPLE_DHCP_EVENTS)
        self.assertGreater(gauge.discover_count, 0)


class TestDNSConsistencyChecker(unittest.TestCase):
    def test_detects_spoof(self):
        checker = DNSConsistencyChecker()
        alerts = checker.process_events(SAMPLE_DNS_EVENTS)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_no_alert_consistent(self):
        checker = DNSConsistencyChecker()
        events = [
            {"type": "dns_response", "domain": "canary.example.com",
             "resolver": "10.0.0.1", "answer": "93.184.216.34"},
            {"type": "dns_response", "domain": "canary.example.com",
             "resolver": "10.0.0.2", "answer": "93.184.216.34"},
        ]
        alerts = checker.process_events(events)
        self.assertEqual(len(alerts), 0)


class TestARPFrameParser(unittest.TestCase):
    def test_build_and_parse_roundtrip(self):
        frame = build_arp_frame("aa:bb:cc:dd:ee:01", "192.168.1.1",
                                "ff:ff:ff:ff:ff:ff", "192.168.1.50", oper=2)
        self.assertEqual(len(frame), 42)  # 14 eth + 28 arp
        pkt = parse_arp_frame(frame)
        self.assertEqual(pkt["eth_type"], 0x0806)
        self.assertEqual(pkt["oper"], 2)
        self.assertEqual(pkt["src_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(pkt["src_ip"], "192.168.1.1")
        self.assertEqual(pkt["dst_mac"], "ff:ff:ff:ff:ff:ff")
        self.assertEqual(pkt["dst_ip"], "192.168.1.50")

    def test_non_arp_ethertype(self):
        frame = b"\x00" * 14 + b"\x08\x00" + b"\x00" * 28  # IP ethertype, no ARP
        self.assertIsNone(parse_arp_frame(frame))

    def test_truncated_frame_raises(self):
        with self.assertRaises(ValueError):
            parse_arp_frame(b"\x00" * 20)


class TestARPFrameAnalyzer(unittest.TestCase):
    def test_detects_ip_mac_conflict(self):
        analyzer = ARPFrameAnalyzer(trusted_ip="192.168.1.1")
        frames = [
            build_arp_frame("aa:bb:cc:dd:ee:01", "192.168.1.1",
                            "ff:ff:ff:ff:ff:ff", "192.168.1.50", oper=2),
            build_arp_frame("aa:bb:cc:dd:ee:99", "192.168.1.1",
                            "ff:ff:ff:ff:ff:ff", "192.168.1.51", oper=2),
        ]
        alerts = analyzer.process_frames(frames)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["detector"], "arp_frame")

    def test_no_alert_single_mac(self):
        analyzer = ARPFrameAnalyzer(trusted_ip="192.168.1.1")
        frames = [
            build_arp_frame("aa:bb:cc:dd:ee:01", "192.168.1.1",
                            "ff:ff:ff:ff:ff:ff", "192.168.1.50", oper=2),
            build_arp_frame("aa:bb:cc:dd:ee:01", "192.168.1.50",
                            "ff:ff:ff:ff:ff:ff", "192.168.1.1", oper=1),
        ]
        alerts = analyzer.process_frames(frames)
        self.assertEqual(alerts, [])


class TestDNSPacketPairChecker(unittest.TestCase):
    def test_build_and_parse_query(self):
        q = build_dns_query("canary.example.com", qid=0xBEEF)
        pkt = parse_dns_packet(q)
        self.assertFalse(pkt["qr"])
        self.assertEqual(pkt["id"], 0xBEEF)
        self.assertEqual(pkt["questions"][0]["name"], "canary.example.com")

    def test_detects_spoofed_answer(self):
        q = build_dns_query(DNS_CANARY_DOMAIN, qid=0x3333)
        forged = build_dns_response(q, "10.0.0.99")
        alert = DNSPacketPairChecker().check_pair(q, forged)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertIn("spoofed", alert["detail"])
        self.assertEqual(alert["detector"], "dns_pair")

    def test_no_alert_consistent_pair(self):
        q = build_dns_query(DNS_CANARY_DOMAIN, qid=0x4444)
        good = build_dns_response(q, DNS_LEGIT_IP)
        self.assertIsNone(DNSPacketPairChecker().check_pair(q, good))

    def test_detects_id_mismatch(self):
        q = build_dns_query(DNS_CANARY_DOMAIN, qid=0x1111)
        good = build_dns_response(q, DNS_LEGIT_IP, qid=0xAAAA)
        alert = DNSPacketPairChecker().check_pair(q, good)
        self.assertIsNotNone(alert)
        self.assertIn("transaction id", alert["detail"])


class TestTLSHostnameChecker(unittest.TestCase):
    def test_fixture_san_parsed(self):
        checker = TLSHostnameChecker()
        res = checker.verify_hostname(FIXTURE_CERT_DER_B64, "legit.example.com")
        self.assertTrue(res["matches"])
        self.assertIn("legit.example.com", res["san"])
        self.assertIn("api.legit.example.com", res["san"])
        self.assertEqual(res["matched_by"], "SAN")

    def test_detects_wrong_hostname(self):
        checker = TLSHostnameChecker()
        res = checker.verify_hostname(FIXTURE_CERT_DER_B64, "fake.example.net")
        self.assertFalse(res["matches"])
        alerts = checker.check(FIXTURE_CERT_DER_B64, "fake.example.net")
        self.assertEqual(checker.alerts[0]["severity"], "CRITICAL")
        self.assertEqual(checker.alerts[0]["detector"], "tls_cert")

    def test_wildcard_san(self):
        self.assertTrue(_hostname_matches("*.example.com", "api.example.com"))
        self.assertFalse(_hostname_matches("*.example.com", "deep.api.example.com"))
        self.assertFalse(_hostname_matches("*.example.com", "example.com"))


class TestDemo(unittest.TestCase):
    def test_demo_exit_zero(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "mitm_detectors.py")],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Detection complete", r.stdout)
        self.assertIn("ARP CONFLICT", r.stdout)
        self.assertIn("TLS HOSTNAME MISMATCH", r.stdout)

    def test_json_output(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "mitm_detectors.py")],
            capture_output=True, text=True, cwd=ROOT)
        json_lines = [l for l in r.stdout.splitlines() if l.strip().startswith("{")]
        self.assertGreater(len(json_lines), 0)
        for line in json_lines[:3]:
            obj = json.loads(line)
            self.assertIn("detector", obj)
            self.assertIn("severity", obj)


class TestCLI(unittest.TestCase):
    def test_help(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "mitm_detectors.py"), "--help"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("MITM", r.stdout)

    def test_dry_run(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "mitm_detectors.py"), "--dry-run"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0)

    def test_demo_report_json(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "mitm_detectors.py"), "--demo-report"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0)


class TestPyCompile(unittest.TestCase):
    def test_compile(self):
        r = subprocess.run(
            [sys.executable, "-m", "py_compile",
             os.path.join(FIRMWARE, "mitm_detectors.py")],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
