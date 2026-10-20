"""Multithreaded TCP Connect scanning and host discovery module.

Supports safe TCP connect probing with precise, per-port state tracking:
- 'open': Connection successfully established.
- 'closed': Connection explicitly refused (RST received).
- 'timeout': No response within timeout window (never assumed closed).
- 'error': Socket error or unreachable host.
- 'not_scanned': Port not probed.

Includes bounded concurrency, thread-safe result collection, and safe optional banner grasping.
"""

from __future__ import annotations

import concurrent.futures
import errno
import os
import socket
import time
from typing import Callable, List, Optional, Tuple

from network_scanner.fingerprint import evaluate_os_evidence
from network_scanner.hostname import resolve_hostname
from network_scanner.results import DiscoveredDevice, PortFinding, ThreadSafeResultCollector


# Portable errno sets for robust cross-platform socket error identification
REFUSED_ERRNOS = {
    getattr(errno, "ECONNREFUSED", 111),
    getattr(errno, "WSAECONNREFUSED", 10061),
}

TIMEOUT_ERRNOS = {
    getattr(errno, "ETIMEDOUT", 110),
    getattr(errno, "WSAETIMEDOUT", 10060),
}

UNREACHABLE_ERRNOS = {
    getattr(errno, "EHOSTUNREACH", 113),
    getattr(errno, "ENETUNREACH", 101),
    getattr(errno, "EHOSTDOWN", 112),
}

# Common service name lookup for standard ports
COMMON_SERVICES = {
    20: "FTP-Data",
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
    grab_banner: bool = False,
) -> PortFinding:
    """Test TCP connection to a single IP and port with explicit state tracking.

    Returns:
        PortFinding recording state as 'open', 'closed', 'timeout', or 'error'.
    """
    service = COMMON_SERVICES.get(port, "unknown")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    start_t = time.perf_counter()

    state = "error"
    banner: Optional[str] = None
    error_msg: Optional[str] = None
    latency_ms: Optional[float] = None

    try:
        res = s.connect_ex((ip, port))
        elapsed = (time.perf_counter() - start_t) * 1000.0

        if res == 0:
            state = "open"
            latency_ms = elapsed
            if grab_banner:
                try:
                    s.settimeout(0.5)
                    if port in (80, 8080, 8000):
                        s.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                    data = s.recv(512)
                    if data:
                        cleaned = data.decode("utf-8", errors="replace").strip()
                        banner = cleaned.splitlines()[0][:120] if cleaned.splitlines() else cleaned[:120]
                except Exception:
                    # Banner grabbing failure must never invalidate an open port state
                    pass
        elif res in REFUSED_ERRNOS:
            state = "closed"
            latency_ms = elapsed
        elif res in TIMEOUT_ERRNOS:
            state = "timeout"
        elif res in UNREACHABLE_ERRNOS:
            state = "error"
            error_msg = f"Host/network unreachable (errno {res})"
        else:
            state = "error"
            error_msg = f"Socket error (errno {res})"

    except socket.timeout:
        state = "timeout"
    except OSError as exc:
        err_code = getattr(exc, "errno", None)
        if err_code in REFUSED_ERRNOS:
            state = "closed"
        elif isinstance(exc, socket.timeout) or err_code in TIMEOUT_ERRNOS:
            state = "timeout"
        elif err_code in UNREACHABLE_ERRNOS:
            state = "error"
            error_msg = f"Host unreachable: {exc}"
        else:
            state = "error"
            error_msg = str(exc)
    finally:
        try:
            s.close()
        except Exception:
            pass

    return PortFinding(
        port=port,
        service=service,
        state=state,
        banner=banner,
        response_time_ms=round(latency_ms, 2) if latency_ms is not None else None,
        error_message=error_msg,
    )


def scan_host_tcp(
    ip: str,
    ports: List[int],
    timeout_sec: float = 1.0,
    resolve_dns: bool = True,
    grab_banner: bool = False,
    is_enrichment: bool = False,
) -> Optional[DiscoveredDevice]:
    """Scan requested ports on a single host.

    Args:
        ip: IPv4 address string
        ports: List of integer port numbers to probe
        timeout_sec: Timeout per socket attempt
        resolve_dns: Whether to perform reverse DNS
        grab_banner: Whether to attempt safe banner grasping on open ports
        is_enrichment: If True, always returns a DiscoveredDevice preserving all port findings
                       even if no ports are open (crucial for ARP enrichment).

    Returns:
        DiscoveredDevice if active (or if is_enrichment=True), else None.
    """
    port_findings: List[PortFinding] = []
    open_port_nums: List[int] = []
    latencies: List[float] = []
    banners: List[str] = []

    for port in ports:
        finding = probe_single_port(ip, port, timeout_sec=timeout_sec, grab_banner=grab_banner)
        port_findings.append(finding)

        if finding.state == "open":
            open_port_nums.append(port)
            if finding.response_time_ms is not None:
                latencies.append(finding.response_time_ms)
            if finding.banner:
                banners.append(finding.banner)
        elif finding.state == "closed" and finding.response_time_ms is not None:
            # An active RST response also measures latency
            latencies.append(finding.response_time_ms)

    # In pure discovery mode, return None if no open ports were detected
    if not is_enrichment and not open_port_nums:
        return None

    hostname = resolve_hostname(ip, timeout_sec=1.0) if resolve_dns else None
    avg_latency = sum(latencies) / len(latencies) if latencies else None

    os_match, evidence = evaluate_os_evidence(open_port_nums, banners)
    port_scan_status = "error" if (port_findings and all(p.state == "error" for p in port_findings)) else "completed"

    return DiscoveredDevice(
        ip_address=ip,
        mac_address=None,  # Layer 3 TCP connect cannot discover remote physical MAC addresses
        hostname=hostname,
        vendor=None,
        open_ports=sorted(open_port_nums),
        port_details=port_findings,
        port_scan_status=port_scan_status,
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
    grab_banner: bool = False,
    collector: Optional[ThreadSafeResultCollector] = None,
    progress_callback: Optional[Callable[[int, int, Optional[DiscoveredDevice]], None]] = None,
) -> List[DiscoveredDevice]:
    """Run concurrent TCP connect scan against a list of hosts."""
    discovered: List[DiscoveredDevice] = []
    total = len(host_list)
    completed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {
            executor.submit(scan_host_tcp, ip, ports, timeout_sec, resolve_dns, grab_banner, False): ip
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
