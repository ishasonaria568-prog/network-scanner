"""Command-Line Interface for Network Discovery & Security Inventory.

Engineered for Kali Linux and Linux terminal environments.
Supports real ARP discovery, TCP connect probing, reverse DNS, and formatted exports.
Built by Isha Sonaria.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from typing import List, Optional

from network_scanner.arp_scanner import DependencyError, PrivilegeError, run_arp_scan
from network_scanner.capabilities import detect_capabilities
from network_scanner.results import (
    DiscoveredDevice,
    ScanReport,
    ThreadSafeResultCollector,
)
from network_scanner.tcp_scanner import run_tcp_scan, scan_host_tcp
from network_scanner.validation import (
    ValidationError,
    enumerate_hosts,
    parse_ports,
    validate_network,
    validate_thread_count,
)


# Terminal color constants
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GRAY = "\033[90m"


def print_banner() -> None:
    banner = f"""
{RED}{BOLD}███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{RESET}
{BOLD}Network Discovery & Security Inventory{RESET} · Built by {BOLD}Isha Sonaria{RESET}
{GRAY}GitHub: https://github.com/ishasonaria568-prog · Portfolio: https://isha-sonaria-cybersecurity-portfoli.vercel.app/{RESET}
"""
    sys.stderr.write(banner)


def format_port_status_colored(device: DiscoveredDevice) -> str:
    """Format individual port states with readable terminal colors."""
    if not device.port_details:
        return f"{GRAY}Not scanned{RESET}"

    parts = []
    for p in sorted(device.port_details, key=lambda x: x.port):
        if p.state == "open":
            parts.append(f"{GREEN}{p.port}:open{RESET}")
        elif p.state == "closed":
            parts.append(f"{GRAY}{p.port}:closed{RESET}")
        elif p.state == "timeout":
            parts.append(f"{YELLOW}{p.port}:timeout{RESET}")
        else:
            parts.append(f"{RED}{p.port}:error{RESET}")

    return ", ".join(parts)


def render_table(report: ScanReport) -> None:
    """Print results in a clean, structured console table with per-port status tracking."""
    devices = report.discovered_devices

    print(f"\n{BOLD}{CYAN}=== SCAN RESULTS [{report.target_network}] ==={RESET}")
    print(
        f"Method: {report.scan_method.upper()} | Elapsed: {report.duration_seconds:.2f}s | Status: {report.status.upper()}"
    )
    if report.requested_ports:
        print(f"Requested Ports: {','.join(map(str, report.requested_ports))} (Timeout: {report.timeout_sec}s)")
    print(f"Discovered Hosts: {len(devices)} active / {report.total_hosts} probed\n")

    if not devices:
        print(f"{YELLOW}No active responsive devices discovered on {report.target_network}.{RESET}")
        return

    # Calculate readable column widths
    ip_w = max(15, max((len(d.ip_address) for d in devices), default=15))
    mac_w = max(17, max((len(d.mac_address or "N/A (L3 only)") for d in devices), default=17))
    host_w = max(18, max((len(d.hostname or "Unresolved") for d in devices), default=18))
    vendor_w = max(15, max((len(d.vendor or "Unknown") for d in devices), default=15))

    # Open ports display
    open_ports_strings = [d.get_open_ports_summary() for d in devices]
    open_w = max(18, max((len(s) for s in open_ports_strings), default=18))

    # Port status display width
    port_status_raw_strings = [d.get_port_status_summary() for d in devices]
    status_w = max(24, max((len(s) for s in port_status_raw_strings), default=24))

    header = (
        f"{BOLD}{'IP ADDRESS':<{ip_w}}  "
        f"{'MAC ADDRESS':<{mac_w}}  "
        f"{'VENDOR':<{vendor_w}}  "
        f"{'HOSTNAME':<{host_w}}  "
        f"{'OPEN PORTS':<{open_w}}  "
        f"{'PORT STATUS':<{status_w}}  "
        f"{'EST. OS':<18}{RESET}"
    )
    divider = "-" * len(header.replace(BOLD, "").replace(RESET, ""))

    print(header)
    print(divider)

    for d in devices:
        mac_str = d.mac_address or f"{GRAY}N/A (L3 only){RESET}"
        vendor_str = (d.vendor or "Unknown")[:vendor_w]
        host_str = (d.hostname or "Unresolved")[:host_w]

        # Open ports label
        if not d.port_details and not d.open_ports:
            open_ports_label = f"{GRAY}Not scanned{RESET}"
        elif d.open_ports:
            open_ports_label = f"{GREEN}{','.join(map(str, d.open_ports))}{RESET}"
        else:
            open_ports_label = f"{YELLOW}None detected{RESET}"

        status_colored = format_port_status_colored(d)
        os_str = (d.os_match or "Unknown")[:18]

        # Calculate padding accounting for ANSI escapes
        raw_open_len = len(d.get_open_ports_summary())
        raw_status_len = len(d.get_port_status_summary())
        open_pad = " " * max(0, open_w - raw_open_len)
        status_pad = " " * max(0, status_w - raw_status_len)

        row = (
            f"{GREEN}{d.ip_address:<{ip_w}}{RESET}  "
            f"{mac_str:<{mac_w}}  "
            f"{vendor_str:<{vendor_w}}  "
            f"{host_str:<{host_w}}  "
            f"{open_ports_label}{open_pad}  "
            f"{status_colored}{status_pad}  "
            f"{os_str:<18}"
        )
        print(row)

    print(divider)

    if report.errors:
        print(f"\n{YELLOW}Warnings / Partial Errors encountered:{RESET}")
        for err in report.errors:
            print(f" - {err}")


def cmd_capabilities() -> int:
    """Print current environment diagnosis and execution capabilities."""
    caps = detect_capabilities()
    print(f"\n{BOLD}{CYAN}--- Environment Capabilities ---{RESET}")
    print(f"Platform:              {caps['platform']}")
    print(f"Python Version:        {caps['python_version']}")
    print(f"Runtime Environment:   {caps['deployment']}")
    print(f"Elevated Privileges:   {'YES (root/admin)' if caps['is_root'] else 'NO (unprivileged)'}")
    print(f"Scapy Installed:       {'YES' if caps['scapy_installed'] else 'NO'}")
    print(f"Raw Socket Access:     {'YES' if caps['raw_packet_access'] else 'NO'}")
    print(f"Layer 2 ARP Discovery: {'SUPPORTED' if caps['arp_discovery'] else 'UNSUPPORTED'}")
    print(f"Supported Methods:     {', '.join(caps['supported_methods'])}")
    print(f"Overall Status:        {caps['status'].upper()}")

    if caps["limitations"]:
        print(f"\n{YELLOW}Limitations & Recommendations:{RESET}")
        for lim in caps["limitations"]:
            print(f"  • {lim}")

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute network scan based on validated command-line arguments."""
    target_str = args.network
    threads = args.threads
    timeout = args.timeout
    output_path = args.output
    fmt = args.format
    ports_str = args.ports
    scan_mode = args.method
    grab_banner = getattr(args, "banner", False)

    # 1. Validate inputs
    try:
        network = validate_network(target_str)
        threads = validate_thread_count(threads)
        ports = parse_ports(ports_str)
    except ValidationError as err:
        sys.stderr.write(f"{RED}[ERROR] Input validation failed:{RESET} {err}\n")
        return 1

    host_list = enumerate_hosts(network)
    scan_id = str(uuid.uuid4())
    total_hosts = len(host_list)

    print_banner()
    print(f"{BOLD}[*] Initiating scan against {network} ({total_hosts} hosts)...{RESET}")
    print(
        f"[*] Concurrency: {threads} threads | Timeout: {timeout}s | Requested Ports: {ports if ports else 'None (Discovery only)'}"
    )

    caps = detect_capabilities()
    collector: Optional[ThreadSafeResultCollector] = None

    if scan_mode == "arp" or (scan_mode == "auto" and caps["arp_discovery"]):
        print(f"[*] Using Layer 2 ARP Discovery engine (Scapy broadcast)...")
        collector = ThreadSafeResultCollector(
            scan_id=scan_id,
            target_network=str(network),
            scan_method="arp_discovery",
            total_hosts=total_hosts,
            requested_ports=ports,
            timeout_sec=timeout,
        )

        try:
            discovered = run_arp_scan(
                target_cidr=str(network),
                timeout_sec=timeout,
                resolve_dns=not args.no_dns,
                threads=threads,
                collector=collector,
            )

            # If user also requested port scanning on ARP-discovered devices:
            if ports and discovered:
                print(f"[*] Probing {len(ports)} ports on {len(discovered)} active hosts...")
                for dev in discovered:
                    enriched = scan_host_tcp(
                        dev.ip_address,
                        ports,
                        timeout_sec=min(timeout, 1.0),
                        resolve_dns=False,
                        grab_banner=grab_banner,
                        is_enrichment=True,
                    )
                    if enriched:
                        dev.open_ports = enriched.open_ports
                        dev.port_details = enriched.port_details
                        dev.port_scan_status = enriched.port_scan_status
                        if enriched.os_match and enriched.os_match != "Unknown":
                            dev.os_match = enriched.os_match
                            dev.evidence = enriched.evidence
                        if enriched.latency_ms is not None and dev.latency_ms is None:
                            dev.latency_ms = enriched.latency_ms

        except PrivilegeError as exc:
            sys.stderr.write(f"\n{RED}[PERMISSION ERROR]{RESET} {exc}\n")
            return 2
        except DependencyError as exc:
            sys.stderr.write(f"\n{RED}[DEPENDENCY ERROR]{RESET} {exc}\n")
            return 2
        except Exception as exc:
            sys.stderr.write(f"\n{RED}[SCAN ERROR]{RESET} Scan failed: {exc}\n")
            return 3

    elif scan_mode == "tcp" or (scan_mode == "auto" and not caps["arp_discovery"]):
        if scan_mode == "auto":
            print(f"{YELLOW}[!] Note: Unprivileged mode detected; falling back to Layer 3 TCP connect discovery.{RESET}")
            print(f"{GRAY}[!] Note: L3 scanning cannot determine physical MAC addresses. Run with 'sudo' for full ARP.{RESET}")

        effective_ports = ports if ports else [80, 443, 22, 445, 8080, 53]
        collector = ThreadSafeResultCollector(
            scan_id=scan_id,
            target_network=str(network),
            scan_method="tcp_connect",
            total_hosts=total_hosts,
            requested_ports=effective_ports,
            timeout_sec=timeout,
        )

        try:
            run_tcp_scan(
                host_list=host_list,
                ports=effective_ports,
                threads=threads,
                timeout_sec=timeout,
                resolve_dns=not args.no_dns,
                grab_banner=grab_banner,
                collector=collector,
            )
        except Exception as exc:
            sys.stderr.write(f"\n{RED}[SCAN ERROR]{RESET} TCP scan failed: {exc}\n")
            return 3

    report = collector.finalize()

    # Output presentation
    if fmt == "json":
        json_out = report.to_json(indent=2)
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_out)
            print(f"[*] JSON results saved to: {output_path}")
        else:
            print(json_out)
    elif fmt == "csv":
        csv_out = report.to_csv()
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(csv_out)
            print(f"[*] CSV results saved to: {output_path}")
        else:
            print(csv_out)
    else:  # Table
        render_table(report)
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                if output_path.endswith(".json"):
                    f.write(report.to_json())
                else:
                    f.write(report.to_csv())
            print(f"[*] Export saved to: {output_path}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="network_scanner",
        description="Network Discovery & Security Inventory · Built by Isha Sonaria",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Real ARP discovery on local subnet (requires root / sudo on Linux):
  sudo python -m network_scanner scan --network 192.168.1.0/24

  # High-speed scan with 50 worker threads and common ports:
  sudo python -m network_scanner scan --network 192.168.1.0/24 --threads 50 --ports 22,80,443

  # Export results directly to CSV:
  python -m network_scanner scan --network 10.0.0.0/24 --output scan_report.csv --format csv

  # Inspect host platform capabilities:
  python -m network_scanner capabilities

Branding:
  Network Discovery & Security Inventory · Built by Isha Sonaria
  GitHub: https://github.com/ishasonaria568-prog
  Portfolio: https://isha-sonaria-cybersecurity-portfoli.vercel.app/
        """,
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Operational mode")

    # 'scan' command
    scan_parser = subparsers.add_parser("scan", help="Scan a target IP or CIDR subnet")
    scan_parser.add_argument(
        "--network",
        "-n",
        required=True,
        help="Target IPv4 address or CIDR range (e.g. 192.168.1.0/24)",
    )
    scan_parser.add_argument(
        "--threads",
        "-t",
        type=int,
        default=30,
        help="Number of concurrent worker threads (default: 30, max: 200)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Response timeout in seconds (default: 1.5)",
    )
    scan_parser.add_argument(
        "--ports",
        "-p",
        type=str,
        default=None,
        help="Optional comma-separated list or range of ports to probe (e.g. 22,80,443 or 80-88)",
    )
    scan_parser.add_argument(
        "--method",
        "-m",
        choices=["auto", "arp", "tcp"],
        default="auto",
        help="Scanning method (auto: prefers ARP if elevated, else TCP connect)",
    )
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["table", "json", "csv"],
        default="table",
        help="Output presentation format (default: table)",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="File path to save scan results",
    )
    scan_parser.add_argument(
        "--no-dns",
        action="store_true",
        help="Disable reverse DNS hostname resolution",
    )
    scan_parser.add_argument(
        "--banner",
        action="store_true",
        help="Attempt optional non-destructive service banner grab on open ports",
    )

    # 'capabilities' command
    subparsers.add_parser("capabilities", help="Inspect platform network capabilities and privileges")

    return parser


def main() -> None:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.subcommand == "capabilities":
        sys.exit(cmd_capabilities())
    elif args.subcommand == "scan":
        sys.exit(cmd_scan(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
