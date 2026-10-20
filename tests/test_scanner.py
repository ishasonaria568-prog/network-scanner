"""Unit and integration test suite for Network Discovery & Security Inventory.

Validates:
- CIDR parsing & boundary enforcement
- Host enumeration rules
- Thread-safe result aggregation & deduplication
- Accurate per-port state tracking (open, closed, timeout, error)
- Connection refused and timeout socket behavior
- Preservation of ARP-discovered devices when no TCP ports are open
- CSV and JSON generation with port status summaries
- Capability detection logic
- Agent security boundaries
"""

import errno
import json
import socket
import unittest
from unittest.mock import MagicMock, patch

from agent.config import AgentConfig
from network_scanner.arp_scanner import lookup_vendor
from network_scanner.capabilities import detect_capabilities
from network_scanner.fingerprint import evaluate_os_evidence
from network_scanner.hostname import resolve_hostname
from network_scanner.results import (
    DiscoveredDevice,
    PortFinding,
    ScanReport,
    ThreadSafeResultCollector,
)
from network_scanner.tcp_scanner import (
    COMMON_SERVICES,
    probe_single_port,
    run_tcp_scan,
    scan_host_tcp,
)
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


class TestTcpPortScanningAccuracy(unittest.TestCase):
    @patch("socket.socket")
    def test_probe_single_port_open(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        finding = probe_single_port("192.168.1.10", 80, timeout_sec=0.5, grab_banner=False)
        self.assertEqual(finding.port, 80)
        self.assertEqual(finding.service, "HTTP")
        self.assertEqual(finding.state, "open")
        self.assertIsNotNone(finding.response_time_ms)
        self.assertIsNone(finding.error_message)
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_probe_single_port_connection_refused(self, mock_socket_class):
        mock_sock = MagicMock()
        # Connection refused errno
        mock_sock.connect_ex.return_value = errno.ECONNREFUSED
        mock_socket_class.return_value = mock_sock

        finding = probe_single_port("192.168.1.10", 22, timeout_sec=0.5)
        self.assertEqual(finding.port, 22)
        self.assertEqual(finding.service, "SSH")
        self.assertEqual(finding.state, "closed")
        self.assertIsNotNone(finding.response_time_ms)
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_probe_single_port_timeout_errno(self, mock_socket_class):
        mock_sock = MagicMock()
        # Timeout errno
        mock_sock.connect_ex.return_value = errno.ETIMEDOUT
        mock_socket_class.return_value = mock_sock

        finding = probe_single_port("192.168.1.10", 443, timeout_sec=0.5)
        self.assertEqual(finding.port, 443)
        self.assertEqual(finding.state, "timeout")
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_probe_single_port_timeout_exception(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout("Timed out")
        mock_socket_class.return_value = mock_sock

        finding = probe_single_port("192.168.1.10", 8080, timeout_sec=0.5)
        self.assertEqual(finding.port, 8080)
        self.assertEqual(finding.state, "timeout")
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_probe_single_port_socket_error(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = errno.EHOSTUNREACH
        mock_socket_class.return_value = mock_sock

        finding = probe_single_port("192.168.1.10", 53, timeout_sec=0.5)
        self.assertEqual(finding.port, 53)
        self.assertEqual(finding.state, "error")
        self.assertIn("unreachable", finding.error_message.lower())
        mock_sock.close.assert_called_once()

    @patch("network_scanner.tcp_scanner.probe_single_port")
    def test_scan_host_tcp_preserves_arp_device_with_no_open_ports(self, mock_probe):
        # Port 22 is closed, Port 80 timed out
        def mock_side_effect(ip, port, timeout_sec=1.0, grab_banner=False):
            if port == 22:
                return PortFinding(port=22, service="SSH", state="closed", response_time_ms=5.0)
            return PortFinding(port=80, service="HTTP", state="timeout")

        mock_probe.side_effect = mock_side_effect

        # When is_enrichment=True (as used after ARP discovery):
        device = scan_host_tcp(
            "192.168.1.50",
            ports=[22, 80],
            timeout_sec=0.5,
            resolve_dns=False,
            is_enrichment=True,
        )

        self.assertIsNotNone(device)
        self.assertEqual(device.ip_address, "192.168.1.50")
        self.assertEqual(device.open_ports, [])
        self.assertEqual(len(device.port_details), 2)
        self.assertEqual(device.port_details[0].state, "closed")
        self.assertEqual(device.port_details[1].state, "timeout")
        self.assertEqual(device.port_scan_status, "completed")
        self.assertEqual(device.get_open_ports_summary(), "None detected")
        self.assertEqual(device.get_port_status_summary(), "22:closed, 80:timeout")

    @patch("network_scanner.tcp_scanner.probe_single_port")
    def test_scan_host_tcp_discovery_mode_filters_silent_hosts(self, mock_probe):
        # All ports timed out in discovery mode
        mock_probe.return_value = PortFinding(port=80, service="HTTP", state="timeout")

        # When is_enrichment=False:
        device = scan_host_tcp(
            "192.168.1.99",
            ports=[80],
            timeout_sec=0.5,
            resolve_dns=False,
            is_enrichment=False,
        )
        self.assertIsNone(device)

    def test_port_finding_model_and_is_open(self):
        f_open = PortFinding(port=80, service="HTTP", state="open", response_time_ms=1.2)
        f_closed = PortFinding(port=22, service="SSH", state="closed", response_time_ms=0.8)
        f_timeout = PortFinding(port=443, service="HTTPS", state="timeout")
        f_error = PortFinding(port=53, service="DNS", state="error", error_message="Network unreachable")

        self.assertTrue(f_open.is_open)
        self.assertFalse(f_closed.is_open)
        self.assertFalse(f_timeout.is_open)
        self.assertFalse(f_error.is_open)

        d = f_open.to_dict()
        self.assertEqual(d["port"], 80)
        self.assertEqual(d["state"], "open")
        self.assertEqual(d["response_time_ms"], 1.2)

    def test_discovered_device_port_status_distinction(self):
        # Unscanned device
        dev_unscanned = DiscoveredDevice(ip_address="192.168.1.1", mac_address="00:11:22:33:44:55")
        self.assertEqual(dev_unscanned.port_scan_status, "not_performed")
        self.assertEqual(dev_unscanned.get_open_ports_summary(), "Not scanned")
        self.assertEqual(dev_unscanned.get_port_status_summary(), "Not scanned")

        # Scanned device with NO open ports
        dev_no_open = DiscoveredDevice(
            ip_address="192.168.1.2",
            port_scan_status="completed",
            open_ports=[],
            port_details=[
                PortFinding(port=22, state="closed"),
                PortFinding(port=80, state="timeout"),
            ],
        )
        self.assertEqual(dev_no_open.get_open_ports_summary(), "None detected")
        self.assertEqual(dev_no_open.get_port_status_summary(), "22:closed, 80:timeout")

        # Scanned device with confirmed open ports
        dev_with_open = DiscoveredDevice(
            ip_address="192.168.1.3",
            port_scan_status="completed",
            open_ports=[80, 443],
            port_details=[
                PortFinding(port=80, state="open"),
                PortFinding(port=443, state="open"),
                PortFinding(port=22, state="closed"),
            ],
        )
        self.assertEqual(dev_with_open.get_open_ports_summary(), "80,443")
        self.assertEqual(dev_with_open.get_port_status_summary(), "22:closed, 80:open, 443:open")

    @patch("socket.socket")
    def test_banner_grab_failure_preserves_open_state(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.side_effect = socket.timeout("Banner recv timed out")
        mock_socket_class.return_value = mock_sock

        finding = probe_single_port("192.168.1.10", 80, timeout_sec=0.5, grab_banner=True)
        self.assertEqual(finding.state, "open")
        self.assertIsNone(finding.banner)
        mock_sock.close.assert_called_once()


class TestResultFormattingAndDeduplication(unittest.TestCase):
    def test_report_json_and_csv_generation(self):
        collector = ThreadSafeResultCollector(
            scan_id="test-scan-123",
            target_network="192.168.1.0/24",
            scan_method="arp_discovery",
            total_hosts=254,
            requested_ports=[80, 443],
        )

        device = DiscoveredDevice(
            ip_address="192.168.1.50",
            mac_address="b8:27:eb:11:22:33",
            hostname="printer.local",
            vendor="Raspberry Pi Foundation",
            open_ports=[80],
            port_details=[
                PortFinding(port=80, service="HTTP", state="open", response_time_ms=2.5),
                PortFinding(port=443, service="HTTPS", state="closed", response_time_ms=2.1),
            ],
            os_match="Linux / Unix",
            evidence="POSIX open port stack",
            latency_ms=2.3,
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
        self.assertEqual(data["discovered_devices"][0]["open_ports"], [80])
        self.assertEqual(data["discovered_devices"][0]["port_status_summary"], "80:open, 443:closed")

        # Check CSV output
        csv_str = report.to_csv()
        self.assertIn("192.168.1.50", csv_str)
        self.assertIn("b8:27:eb:11:22:33", csv_str)
        self.assertIn("printer.local", csv_str)
        self.assertIn("80:open, 443:closed", csv_str)

    def test_duplicate_port_finding_deduplication(self):
        collector = ThreadSafeResultCollector(
            scan_id="test-dedup",
            target_network="192.168.1.0/24",
            scan_method="arp_discovery",
            total_hosts=1,
        )

        # Initial ARP device with no port details
        dev_initial = DiscoveredDevice(
            ip_address="192.168.1.100",
            mac_address="00:1a:2b:3c:4d:5e",
            hostname="router.lan",
        )
        collector.add_device(dev_initial)

        # Enrichment phase adds port findings
        dev_enriched = DiscoveredDevice(
            ip_address="192.168.1.100",
            open_ports=[80],
            port_details=[
                PortFinding(port=80, service="HTTP", state="open"),
                PortFinding(port=443, service="HTTPS", state="closed"),
            ],
        )
        collector.add_device(dev_enriched)

        # A second duplicate probe should merge cleanly without duplicating port details
        dev_duplicate_probe = DiscoveredDevice(
            ip_address="192.168.1.100",
            open_ports=[80],
            port_details=[
                PortFinding(port=80, service="HTTP", state="open", banner="Apache/2.4"),
            ],
        )
        collector.add_device(dev_duplicate_probe)

        report = collector.finalize()
        self.assertEqual(len(report.discovered_devices), 1)
        final_dev = report.discovered_devices[0]
        self.assertEqual(final_dev.mac_address, "00:1a:2b:3c:4d:5e")
        self.assertEqual(final_dev.hostname, "router.lan")
        # Exactly 2 unique ports: 80 and 443
        self.assertEqual(len(final_dev.port_details), 2)
        ports = [p.port for p in final_dev.port_details]
        self.assertEqual(ports, [80, 443])

    def test_vendor_oui_resolution(self):
        self.assertEqual(lookup_vendor("b8:27:eb:aa:bb:cc"), "Raspberry Pi Foundation")
        self.assertEqual(lookup_vendor("00:50:56:00:11:22"), "VMware, Inc.")
        self.assertIsNone(lookup_vendor("ff:ee:dd:cc:bb:aa"))

    def test_conservative_os_fingerprinting(self):
        os_match, ev = evaluate_os_evidence([445, 3389])
        self.assertEqual(os_match, "Microsoft Windows")

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
