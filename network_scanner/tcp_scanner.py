"""Multithreaded TCP Connect scanning and host discovery module.

Supports safe TCP connect probing for authorized hosts without requiring raw socket privileges.
Includes bounded concurrency, thread-safe result collection, and banner grasping.
"""

from __future__ import annotations

import concurrent.futures
import socket
import time
from typing import Callable, List, Optional, Tuple

from network_scanner.fingerprint import evaluate_os_evidence
from network_scanner.hostname import resolve_hostname
from network_scanner.results import DiscoveredDevice, PortFinding, ThreadSafeResultCollector


# Common service name lookup for standard ports
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "IMAP",
    443: "HTTPS",
    445: "microsoft-ds (SMB)",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def probe_single_port(
    ip: str,
    port: int,
    timeout_sec: float = 1.0,
    grab_banner: bool = True,
) -> Tuple[bool, Optional[float], Optional[str]]:
    """Test TCP connection to a single IP and port.

    Returns:
        (is_open, latency_ms, banner_string)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    start_t = time.perf_counter()

    try:
        res = s.connect_ex((ip, port))
        latency = (time.perf_counter() - start_t) * 1000.0

        if res == 0:
            banner = None
            if grab_banner:
                try:
                    s.settimeout(0.6)
                    # For HTTP ports, send HEAD request; for SSH/FTP/etc, read server greeting
                    if port in (80, 8080, 8000):
                        s.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                    data = s.recv(512)
                    if data:
                        # Decode printable ascii/utf-8 safely
                        cleaned = data.decode("utf-8", errors="replace").strip()
                        # Extract first meaningful line
                        first_line = cleaned.splitlines()[0] if cleaned.splitlines() else cleaned
                        banner = first_line[:120]
                except Exception:
                    pass
            return True, latency, banner
        return False, None, None
    except (socket.timeout, OSError):
        return False, None, None
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_host_tcp(
    ip: str,
    ports: List[int],
    timeout_sec: float = 1.0,
    resolve_dns: bool = True,
) -> Optional[DiscoveredDevice]:
    """Scan specified ports on a single host.

    Returns:
        DiscoveredDevice if any port is open or host is responding, else None.
    """
    open_port_findings: List[PortFinding] = []
    latencies: List[float] = []
    banners: List[str] = []

    for port in ports:
        is_open, latency, banner = probe_single_port(ip, port, timeout_sec=timeout_sec)
        if is_open:
            if latency is not None:
                latencies.append(latency)
            if banner:
                banners.append(banner)
            service = COMMON_SERVICES.get(port, "unknown")
            open_port_findings.append(
                PortFinding(
                    port=port,
                    service=service,
                    state="open",
                    banner=banner,
                    response_time_ms=round(latency, 2) if latency is not None else None,
                )
            )

    if not open_port_findings:
        return None

    hostname = resolve_hostname(ip, timeout_sec=1.0) if resolve_dns else None
    avg_latency = sum(latencies) / len(latencies) if latencies else None
    open_port_nums = [p.port for p in open_port_findings]

    os_match, evidence = evaluate_os_evidence(open_port_nums, banners)

    return DiscoveredDevice(
        ip_address=ip,
        mac_address=None,  # Layer 3 TCP connect cannot discover remote MAC addresses
        hostname=hostname,
        vendor=None,
        open_ports=open_port_nums,
        port_details=open_port_findings,
        os_match=os_match,
        evidence=evidence,
        latency_ms=avg_latency,
    )


def run_tcp_scan(
    host_list: List[str],
    ports: List[int],
    threads: int = 30,
    timeout_sec: float = 1.0,
    resolve_dns: bool = True,
    collector: Optional[ThreadSafeResultCollector] = None,
    progress_callback: Optional[Callable[[int, int, Optional[DiscoveredDevice]], None]] = None,
) -> List[DiscoveredDevice]:
    """Run concurrent TCP connect scan against a list of hosts."""
    discovered: List[DiscoveredDevice] = []
    total = len(host_list)
    completed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {
            executor.submit(scan_host_tcp, ip, ports, timeout_sec, resolve_dns): ip
            for ip in host_list
        }

        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            completed += 1
            try:
                device = future.result()
                if device:
                    discovered.append(device)
                    if collector:
                        collector.add_device(device)
                if progress_callback:
                    progress_callback(completed, total, device)
            except Exception as exc:
                if collector:
                    collector.add_error(f"Error scanning host {ip}: {exc}")

    return discovered
