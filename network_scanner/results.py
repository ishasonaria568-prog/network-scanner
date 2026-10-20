"""Result structures, thread-safe aggregation, and CSV/JSON exporters.

Adheres strictly to the data contract specified in the project requirements.
Unavailable attributes are represented as None or explicit 'Unknown', never fabricated.
"""

from __future__ import annotations

import csv
import io
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class PortFinding:
    port: int
    service: str = "unknown"
    state: str = "open"
    banner: Optional[str] = None
    response_time_ms: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "service": self.service,
            "state": self.state,
            "banner": self.banner,
            "response_time_ms": self.response_time_ms,
        }


@dataclass
class DiscoveredDevice:
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    port_details: List[PortFinding] = field(default_factory=list)
    os_match: Optional[str] = None
    evidence: Optional[str] = None
    latency_ms: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "open_ports": sorted(self.open_ports),
            "port_details": [p.to_dict() if isinstance(p, PortFinding) else p for p in self.port_details],
            "os_match": self.os_match or "Unknown",
            "evidence": self.evidence,
            "latency_ms": round(self.latency_ms, 2) if self.latency_ms is not None else None,
        }


@dataclass
class ScanReport:
    scan_id: str
    target_network: str
    scan_method: str  # 'arp_discovery' | 'tcp_connect' | 'hybrid'
    started_at: str
    completed_at: Optional[str] = None
    status: str = "running"  # 'running' | 'completed' | 'partial' | 'failed'
    duration_seconds: float = 0.0
    total_hosts: int = 0
    discovered_devices: List[DiscoveredDevice] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_network": self.target_network,
            "scan_method": self.scan_method,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "duration_seconds": round(self.duration_seconds, 3),
            "total_hosts": self.total_hosts,
            "discovered_devices": [d.to_dict() for d in self.discovered_devices],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        # Header row
        writer.writerow([
            "IP Address",
            "MAC Address",
            "Vendor",
            "Hostname",
            "Open Ports",
            "Estimated OS",
            "Evidence",
            "Latency (ms)",
        ])

        for device in self.discovered_devices:
            writer.writerow([
                device.ip_address,
                device.mac_address or "N/A (L3 only)",
                device.vendor or "Unknown",
                device.hostname or "Unresolved",
                ",".join(map(str, sorted(device.open_ports))) if device.open_ports else "None detected",
                device.os_match or "Unknown",
                device.evidence or "",
                f"{round(device.latency_ms, 2)}" if device.latency_ms is not None else "",
            ])

        return output.getvalue()


class ThreadSafeResultCollector:
    """Thread-safe collector for streaming scan results from bounded worker pools."""

    def __init__(self, scan_id: str, target_network: str, scan_method: str, total_hosts: int):
        self.lock = threading.Lock()
        self.started_dt = datetime.now(timezone.utc)
        self.report = ScanReport(
            scan_id=scan_id,
            target_network=target_network,
            scan_method=scan_method,
            started_at=self.started_dt.isoformat(),
            total_hosts=total_hosts,
        )
        self._devices_by_ip: Dict[str, DiscoveredDevice] = {}

    def add_device(self, device: DiscoveredDevice) -> None:
        with self.lock:
            if device.ip_address in self._devices_by_ip:
                existing = self._devices_by_ip[device.ip_address]
                if device.mac_address and not existing.mac_address:
                    existing.mac_address = device.mac_address
                if device.vendor and not existing.vendor:
                    existing.vendor = device.vendor
                if device.hostname and not existing.hostname:
                    existing.hostname = device.hostname
                if device.os_match and existing.os_match == "Unknown":
                    existing.os_match = device.os_match
                if device.evidence and not existing.evidence:
                    existing.evidence = device.evidence
                if device.open_ports:
                    merged_ports = set(existing.open_ports).union(set(device.open_ports))
                    existing.open_ports = sorted(list(merged_ports))
                if device.port_details:
                    existing.port_details.extend(device.port_details)
                if device.latency_ms is not None and existing.latency_ms is None:
                    existing.latency_ms = device.latency_ms
            else:
                self._devices_by_ip[device.ip_address] = device
                self.report.discovered_devices.append(device)

    def add_error(self, err: str) -> None:
        with self.lock:
            self.report.errors.append(err)

    def finalize(self, status: Optional[str] = None) -> ScanReport:
        with self.lock:
            end_dt = datetime.now(timezone.utc)
            self.report.completed_at = end_dt.isoformat()
            self.report.duration_seconds = (end_dt - self.started_dt).total_seconds()
            if status:
                self.report.status = status
            elif self.report.errors and not self.report.discovered_devices:
                self.report.status = "failed"
            elif self.report.errors:
                self.report.status = "partial"
            else:
                self.report.status = "completed"

            # Sort discovered devices by IP address for structured presentation
            try:
                import ipaddress
                self.report.discovered_devices.sort(
                    key=lambda d: ipaddress.IPv4Address(d.ip_address)
                )
            except Exception:
                self.report.discovered_devices.sort(key=lambda d: d.ip_address)

            return self.report
