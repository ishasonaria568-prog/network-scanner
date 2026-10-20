"""ARP Discovery module for local Layer-2 networks.

Uses Scapy to broadcast ARP requests (who-has) and capture IP/MAC mappings.
Performs honest privilege verification, vendor resolution, and hostname lookups.
"""

from __future__ import annotations

import concurrent.futures
import sys
from typing import Callable, Dict, List, Optional

from network_scanner.capabilities import is_root_or_admin, is_scapy_available
from network_scanner.hostname import resolve_hostname
from network_scanner.results import DiscoveredDevice, ThreadSafeResultCollector


# Common MAC OUI vendor prefix database
OUI_VENDORS = {
    "00:0c:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "Oracle VirtualBox",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading",
    "00:1a:11": "Google, Inc.",
    "3c:5a:b4": "Google, Inc.",
    "f4:f5:d8": "Google, Inc.",
    "00:17:88": "Philips Lighting",
    "00:1f:f3": "Apple, Inc.",
    "3c:07:54": "Apple, Inc.",
    "ac:bc:32": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.",
    "00:1a:2b": "Cisco Systems",
    "00:1b:2a": "Cisco Systems",
    "00:26:0b": "Cisco Systems",
    "00:15:5d": "Microsoft Hyper-V",
    "00:1e:67": "Intel Corporation",
    "00:21:6a": "Intel Corporation",
    "5c:b9:01": "Intel Corporation",
    "00:14:22": "Dell Inc.",
    "18:66:da": "Dell Inc.",
    "00:25:b3": "Hewlett-Packard",
    "70:5a:0f": "Hewlett-Packard",
    "ec:08:6b": "TP-Link Technologies",
    "50:c7:bf": "TP-Link Technologies",
    "00:26:37": "Samsung Electronics",
    "50:01:d9": "Samsung Electronics",
    "00:04:4b": "NVIDIA Corporation",
    "48:b0:2d": "NVIDIA Corporation",
}


def lookup_vendor(mac: str) -> Optional[str]:
    """Lookup hardware vendor using MAC OUI prefix (first 3 octets)."""
    if not mac:
        return None
    cleaned = mac.lower().replace("-", ":").strip()
    parts = cleaned.split(":")
    if len(parts) >= 3:
        prefix = ":".join(parts[:3])
        return OUI_VENDORS.get(prefix)
    return None


class PrivilegeError(PermissionError):
    """Raised when ARP scanning is attempted without root/administrator privileges."""
    pass


class DependencyError(ImportError):
    """Raised when Scapy is missing."""
    pass


def run_arp_scan(
    target_cidr: str,
    timeout_sec: float = 2.0,
    resolve_dns: bool = True,
    threads: int = 20,
    collector: Optional[ThreadSafeResultCollector] = None,
    progress_callback: Optional[Callable[[int, int, Optional[DiscoveredDevice]], None]] = None,
) -> List[DiscoveredDevice]:
    """Perform real ARP discovery on the local network segment using Scapy.

    Args:
        target_cidr: Subnet in CIDR format (e.g. '192.168.1.0/24')
        timeout_sec: ARP response wait timeout in seconds
        resolve_dns: Whether to perform reverse DNS lookups on discovered hosts
        threads: Concurrency for parallel reverse DNS lookups
        collector: Optional ThreadSafeResultCollector instance
        progress_callback: Optional progress reporter callback

    Returns:
        List of DiscoveredDevice instances with real IP and MAC addresses.

    Raises:
        PrivilegeError: If executed without superuser permissions.
        DependencyError: If Scapy is not installed.
    """
    if not is_scapy_available():
        raise DependencyError(
            "Scapy is required for ARP discovery. Install with: pip install scapy"
        )

    if not is_root_or_admin():
        raise PrivilegeError(
            "Raw socket ARP discovery requires elevated privileges (root/sudo on Linux). "
            "Re-run with: sudo python -m network_scanner scan ..."
        )

    # Scapy import deferred until runtime check passes
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
    except ImportError as exc:
        raise DependencyError(f"Failed to import Scapy components: {exc}") from exc

    # Create Ethernet broadcast frame containing ARP request
    # 'who-has' request pdst=target_cidr, broadcast to ff:ff:ff:ff:ff:ff
    arp_req = ARP(pdst=target_cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req

    try:
        # Send at Layer 2 and receive answers
        answered_list, _ = srp(packet, timeout=timeout_sec, verbose=0, retry=1)
    except PermissionError as exc:
        raise PrivilegeError(f"Permission denied during raw packet transmission: {exc}") from exc
    except Exception as exc:
        if collector:
            collector.add_error(f"ARP transmission error: {exc}")
        raise RuntimeError(f"ARP scan failed: {exc}") from exc

    discovered_raw = []
    for sent, received in answered_list:
        ip = received.psrc
        mac = received.hwsrc
        discovered_raw.append((ip, mac))

    # Resolve hostnames and vendors concurrently
    results: List[DiscoveredDevice] = []

    def process_host(ip: str, mac: str) -> DiscoveredDevice:
        hostname = resolve_hostname(ip, timeout_sec=1.0) if resolve_dns else None
        vendor = lookup_vendor(mac)
        return DiscoveredDevice(
            ip_address=ip,
            mac_address=mac,
            hostname=hostname,
            vendor=vendor,
            open_ports=[],
            port_details=[],
            os_match="Unknown",
            evidence=f"Active Layer 2 ARP response from MAC {mac}",
            latency_ms=None,
        )

    total = len(discovered_raw)
    completed = 0

    if discovered_raw:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_item = {
                executor.submit(process_host, ip, mac): (ip, mac)
                for ip, mac in discovered_raw
            }
            for future in concurrent.futures.as_completed(future_to_item):
                completed += 1
                try:
                    dev = future.result()
                    results.append(dev)
                    if collector:
                        collector.add_device(dev)
                    if progress_callback:
                        progress_callback(completed, total, dev)
                except Exception as exc:
                    if collector:
                        collector.add_error(f"Host processing error: {exc}")

    return results
