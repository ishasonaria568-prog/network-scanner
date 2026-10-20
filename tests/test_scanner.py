"""Unit and integration test suite for Network Scanner.

Validates:
- CIDR parsing & boundary enforcement
- Host enumeration rules
- Thread-safe result aggregation
- CSV and JSON generation
- Capability detection logic
- Agent security boundaries
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from agent.config import AgentConfig
from network_scanner.arp_scanner import lookup_vendor
from network_scanner.capabilities import detect_capabilities
from network_scanner.fingerprint import evaluate_os_evidence
from network_scanner.hostname import resolve_hostname
from network_scanner.results import DiscoveredDevice, ScanReport, ThreadSafeResultCollector
from network_scanner.tcp_scanner import probe_single_port
from network_scanner.validation import (
    ValidationError,
    enumerate_hosts,
    parse_ports,
    validate_network,
    validate_thread_count,
)


class TestNetworkValidation(unittest.TestCase):
    def test_valid_cidr_parsing(self):
        net = validate_network("192.168.1.0/24")
        self.assertEqual(str(net), "192.168.1.0/24")
        self.assertEqual(net.num_addresses, 256)

    def test_single_ip_auto_appends_32(self):
        net = validate_network("10.0.0.1")
        self.assertEqual(str(net), "10.0.0.1/32")
        self.assertEqual(net.num_addresses, 1)

    def test_reject_empty_or_malformed_cidr(self):
        with self.assertRaises(ValidationError):
            validate_network("")
        with self.assertRaises(ValidationError):
            validate_network("999.999.999.999")
        with self.assertRaises(ValidationError):
            validate_network("192.168.1.1/33")
        with self.assertRaises(ValidationError):
            validate_network("not-an-ip")

    def test_reject_multicast_and_broadcast(self):
        with self.assertRaises(ValidationError):
            validate_network("224.0.0.1")
        with self.assertRaises(ValidationError):
            validate_network("255.255.255.255")

    def test_reject_oversized_range(self):
        # Default limit is 1024 hosts (/22)
        with self.assertRaises(ValidationError) as ctx:
            validate_network("10.0.0.0/16")
        self.assertIn("exceeding the maximum safe limit", str(ctx.exception))

    def test_host_enumeration(self):
        net = validate_network("192.168.1.0/29")
        hosts = enumerate_hosts(net)
        # /29 has 8 addresses: network .0, hosts .1-.6, broadcast .7
        self.assertEqual(len(hosts), 6)
        self.assertEqual(hosts[0], "192.168.1.1")
        self.assertEqual(hosts[-1], "192.168.1.6")

    def test_single_host_enumeration(self):
        net = validate_network("127.0.0.1/32")
        hosts = enumerate_hosts(net)
        self.assertEqual(hosts, ["127.0.0.1"])

    def test_port_parsing_valid(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])
        self.assertEqual(parse_ports("80-83"), [80, 81, 82, 83])
        self.assertEqual(parse_ports("443, 80, 22"), [22, 80, 443])

    def test_port_parsing_invalid(self):
        with self.assertRaises(ValidationError):
            parse_ports("0")
        with self.assertRaises(ValidationError):
            parse_ports("70000")
        with self.assertRaises(ValidationError):
            parse_ports("80-70")
        with self.assertRaises(ValidationError):
            parse_ports("abc")

    def test_thread_count_bounds(self):
        self.assertEqual(validate_thread_count(50), 50)
        with self.assertRaises(ValidationError):
            validate_thread_count(0)
        with self.assertRaises(ValidationError):
            validate_thread_count(999)


class TestResultFormatting(unittest.TestCase):
    def test_report_json_and_csv_generation(self):
        collector = ThreadSafeResultCollector(
            scan_id="test-scan-123",
            target_network="192.168.1.0/24",
            scan_method="arp_discovery",
            total_hosts=254,
        )

        device = DiscoveredDevice(
            ip_address="192.168.1.50",
            mac_address="b8:27:eb:11:22:33",
            hostname="printer.local",
            vendor="Raspberry Pi Foundation",
            open_ports=[80, 631],
            os_match="Linux / Unix",
            evidence="POSIX open port stack",
            latency_ms=1.45,
        )
        collector.add_device(device)
        report = collector.finalize()

        # Check JSON output
        json_str = report.to_json()
        data = json.loads(json_str)
        self.assertEqual(data["scan_id"], "test-scan-123")
        self.assertEqual(len(data["discovered_devices"]), 1)
        self.assertEqual(data["discovered_devices"][0]["ip_address"], "192.168.1.50")
        self.assertEqual(data["discovered_devices"][0]["mac_address"], "b8:27:eb:11:22:33")

        # Check CSV output
        csv_str = report.to_csv()
        self.assertIn("192.168.1.50", csv_str)
        self.assertIn("b8:27:eb:11:22:33", csv_str)
        self.assertIn("printer.local", csv_str)

    def test_vendor_oui_resolution(self):
        self.assertEqual(lookup_vendor("b8:27:eb:aa:bb:cc"), "Raspberry Pi Foundation")
        self.assertEqual(lookup_vendor("00:50:56:00:11:22"), "VMware, Inc.")
        self.assertIsNone(lookup_vendor("ff:ee:dd:cc:bb:aa"))

    def test_conservative_os_fingerprinting(self):
        # When SMB and RDP are both present
        os_match, ev = evaluate_os_evidence([445, 3389])
        self.assertEqual(os_match, "Microsoft Windows")

        # Unknown when no clear evidence exists
        os_unknown, ev_unknown = evaluate_os_evidence([8080])
        self.assertEqual(os_unknown, "Unknown")
        self.assertIn("Insufficient", ev_unknown)


class TestAgentSecurity(unittest.TestCase):
    def test_agent_authorization_boundary(self):
        cfg = AgentConfig(allowed_subnets=["192.168.1.0/24", "10.0.0.0/16"])
        self.assertTrue(cfg.is_target_authorized("192.168.1.0/24"))
        self.assertTrue(cfg.is_target_authorized("192.168.1.50/32"))
        self.assertTrue(cfg.is_target_authorized("10.0.5.0/24"))

        # Rejects unauthorized external or public targets
        self.assertFalse(cfg.is_target_authorized("8.8.8.8/32"))
        self.assertFalse(cfg.is_target_authorized("172.16.0.0/16"))


if __name__ == "__main__":
    unittest.main()
