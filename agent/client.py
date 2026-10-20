"""External Scanner Agent Client.

Runs as a standalone process on an authorized local machine (e.g. Kali Linux, Raspberry Pi, local PC).
Registers with the central web platform, reports Layer 2 ARP capabilities, polls for authorized
scan jobs, executes actual ARP discovery, and pushes real scan reports securely.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, Optional

from agent.config import AgentConfig
from network_scanner.arp_scanner import DependencyError, PrivilegeError, run_arp_scan
from network_scanner.capabilities import detect_capabilities
from network_scanner.results import ScanReport, ThreadSafeResultCollector
from network_scanner.tcp_scanner import run_tcp_scan, scan_host_tcp
from network_scanner.validation import ValidationError, enumerate_hosts, parse_ports, validate_network


# ANSI styling
BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GRAY = "\033[90m"
RESET = "\033[0m"


def get_local_ip() -> str:
    """Determine local primary IPv4 address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually connect but picks the routing interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        return ip
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


class ScannerAgent:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.agent_id = config.agent_id or f"agent-{uuid.uuid4().hex[:8]}"
        self.local_ip = get_local_ip()
        self.running = True

    def _http_request(self, endpoint: str, data: Optional[Dict[str, Any]] = None, method: str = "GET") -> Dict[str, Any]:
        url = f"{self.config.server_url}{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"NetworkScannerAgent/{self.agent_id}",
        }
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"

        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_sec) as resp:
                resp_data = resp.read().decode("utf-8")
                if resp_data:
                    return json.loads(resp_data)
                return {}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"HTTP {exc.code} from server: {err_body or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise ConnectionError(f"Failed to connect to scanner server at {self.config.server_url}: {exc.reason}") from exc

    def register(self) -> Dict[str, Any]:
        """Register agent capabilities with the web server."""
        caps = detect_capabilities()
        payload = {
            "agent_id": self.agent_id,
            "agent_name": self.config.agent_name,
            "local_ip": self.local_ip,
            "hostname": socket.gethostname(),
            "platform": f"{platform.system()} {platform.release()}",
            "arp_supported": caps["arp_discovery"],
            "raw_packet_access": caps["raw_packet_access"],
            "is_root": caps["is_root"],
            "allowed_subnets": self.config.allowed_subnets,
        }

        print(f"{CYAN}[*] Registering agent '{self.agent_id}' with server {self.config.server_url}...{RESET}")
        res = self._http_request("/api/agent/register", data=payload, method="POST")
        print(f"{GREEN}[+] Registration successful! Server status: {res.get('status', 'connected')}{RESET}")
        return res

    def poll_for_job(self) -> Optional[Dict[str, Any]]:
        """Query server for pending scan jobs."""
        endpoint = f"/api/agent/poll?agent_id={self.agent_id}"
        try:
            res = self._http_request(endpoint, method="GET")
            if res and res.get("job"):
                return res["job"]
        except Exception as exc:
            print(f"{YELLOW}[!] Poll heartbeat warning: {exc}{RESET}")
        return None

    def execute_job(self, job: Dict[str, Any]) -> None:
        """Execute assigned scan job with strict validation and submit results."""
        job_id = job.get("job_id", str(uuid.uuid4()))
        target = job.get("target")
        method = job.get("method", "arp_discovery")
        ports_val = job.get("ports", [])
        timeout = float(job.get("timeout", 1.5))

        print(f"\n{BOLD}[+] Executing assigned scan job [{job_id}]{RESET}")
        print(f"    Target: {target} | Method: {method} | Ports: {ports_val}")

        # 1. Independent security boundary check
        if not self.config.is_target_authorized(target):
            err_msg = f"Target '{target}' is rejected: outside of agent configured allowlist {self.config.allowed_subnets}."
            print(f"{RED}[!] Security rejection: {err_msg}{RESET}")
            self.submit_results(job_id, target, method, error=err_msg)
            return

        # 2. Input validation
        try:
            network = validate_network(target)
            host_list = enumerate_hosts(network)
        except ValidationError as err:
            err_msg = f"Target validation failed: {err}"
            print(f"{RED}[!] {err_msg}{RESET}")
            self.submit_results(job_id, target, method, error=err_msg)
            return

        collector = ThreadSafeResultCollector(
            scan_id=job_id,
            target_network=str(network),
            scan_method=method,
            total_hosts=len(host_list),
        )

        try:
            if method == "arp_discovery":
                caps = detect_capabilities()
                if not caps["arp_discovery"]:
                    raise PrivilegeError("Agent host lacks root or Scapy privileges required for ARP discovery.")

                discovered = run_arp_scan(
                    target_cidr=str(network),
                    timeout_sec=timeout,
                    resolve_dns=True,
                    threads=20,
                    collector=collector,
                )

                if ports_val and discovered:
                    ports = parse_ports(",".join(map(str, ports_val)) if isinstance(ports_val, list) else str(ports_val))
                    for dev in discovered:
                        enriched = scan_host_tcp(dev.ip_address, ports, timeout_sec=min(timeout, 1.0), resolve_dns=False)
                        if enriched:
                            dev.open_ports = enriched.open_ports
                            dev.port_details = enriched.port_details
                            dev.os_match = enriched.os_match
                            dev.evidence = enriched.evidence
            else:
                ports = parse_ports(",".join(map(str, ports_val)) if isinstance(ports_val, list) else str(ports_val))
                if not ports:
                    ports = [80, 443, 22, 445, 8080]
                run_tcp_scan(
                    host_list=host_list,
                    ports=ports,
                    threads=30,
                    timeout_sec=timeout,
                    resolve_dns=True,
                    collector=collector,
                )

            report = collector.finalize()
            self.submit_results(job_id, target, method, report=report)

        except Exception as exc:
            collector.add_error(str(exc))
            report = collector.finalize(status="failed")
            self.submit_results(job_id, target, method, report=report, error=str(exc))

    def submit_results(
        self,
        job_id: str,
        target: str,
        method: str,
        report: Optional[ScanReport] = None,
        error: Optional[str] = None,
    ) -> None:
        """Submit completed scan report back to the central server."""
        payload = {
            "agent_id": self.agent_id,
            "job_id": job_id,
            "target": target,
            "method": method,
            "status": "failed" if error and not report else (report.status if report else "failed"),
            "report": report.to_dict() if report else None,
            "error": error,
        }

        try:
            res = self._http_request("/api/agent/submit", data=payload, method="POST")
            print(f"{GREEN}[+] Scan results for job [{job_id}] pushed successfully to server!{RESET}")
        except Exception as exc:
            print(f"{RED}[!] Error submitting results to server: {exc}{RESET}")

    def run_worker_loop(self) -> None:
        """Continuous polling loop."""
        print(f"\n{GREEN}{BOLD}[*] Scanner Agent is active and listening for authorized jobs.{RESET}")
        print(f"    Server: {self.config.server_url}")
        print(f"    Agent ID: {self.agent_id}")
        print(f"    Allowed Subnets: {self.config.allowed_subnets}")
        print(f"    Press Ctrl+C to terminate agent.\n")

        while self.running:
            try:
                job = self.poll_for_job()
                if job:
                    self.execute_job(job)
            except KeyboardInterrupt:
                print(f"\n{YELLOW}[*] Shutting down agent gracefully...{RESET}")
                self.running = False
                break
            except Exception as exc:
                print(f"{RED}[!] Unexpected error in agent worker: {exc}{RESET}")

            time.sleep(self.config.poll_interval)


def parse_agent_args() -> AgentConfig:
    parser = argparse.ArgumentParser(
        prog="scanner-agent",
        description="External Network Scanner Agent for Kali Linux / Local LAN Discovery",
    )
    parser.add_argument(
        "--server-url",
        default=os.environ.get("SCANNER_SERVER_URL", "http://localhost:3000"),
        help="URL of the central Network Scanner web dashboard (default: http://localhost:3000)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("SCANNER_AGENT_TOKEN", ""),
        help="Secret agent authentication token",
    )
    parser.add_argument(
        "--name",
        default="Kali-Edge-Agent-01",
        help="Descriptive name for this agent node",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=3.0,
        help="Polling interval in seconds (default: 3.0)",
    )
    parser.add_argument(
        "--allow-subnet",
        action="append",
        dest="allowed_subnets",
        help="Permitted subnet CIDR (can be specified multiple times; default allows RFC1918)",
    )
    parser.add_argument(
        "--scan-now",
        help="Perform an immediate scan of specified CIDR and push results directly",
    )

    args = parser.parse_args()

    cfg = AgentConfig.from_env()
    cfg.server_url = args.server_url.rstrip("/")
    if args.token:
        cfg.token = args.token
    if args.name:
        cfg.agent_name = args.name
    cfg.poll_interval = args.poll_interval
    if args.allowed_subnets:
        cfg.allowed_subnets = args.allowed_subnets

    return cfg


def main() -> None:
    cfg = parse_agent_args()
    agent = ScannerAgent(cfg)

    try:
        agent.register()
    except Exception as exc:
        print(f"{RED}[ERROR] Agent could not register with server: {exc}{RESET}")
        print(f"{GRAY}Ensure the web server is running and accessible at {cfg.server_url}{RESET}")
        sys.exit(1)

    agent.run_worker_loop()


if __name__ == "__main__":
    main()
