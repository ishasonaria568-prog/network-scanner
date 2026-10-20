"""Configuration loader and security boundary validator for the Scanner Agent."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AgentConfig:
    server_url: str = "http://localhost:3000"
    token: str = ""
    agent_id: str = ""
    agent_name: str = "Kali-Edge-Agent-01"
    poll_interval: float = 3.0
    timeout_sec: float = 10.0
    # Security boundary: Only subnets in this list can be scanned by this agent.
    # Empty list means only RFC1918 private subnets are permitted.
    allowed_subnets: List[str] = field(default_factory=lambda: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.1/32"])

    @classmethod
    def from_env(cls) -> "AgentConfig":
        server_url = os.environ.get("SCANNER_SERVER_URL", "http://localhost:3000")
        token = os.environ.get("SCANNER_AGENT_TOKEN", "")
        agent_id = os.environ.get("SCANNER_AGENT_ID", "")
        agent_name = os.environ.get("SCANNER_AGENT_NAME", "Kali-Edge-Agent-01")
        poll_str = os.environ.get("SCANNER_POLL_INTERVAL", "3.0")
        allowed = os.environ.get("SCANNER_ALLOWED_SUBNETS", "")

        subnets = [s.strip() for s in allowed.split(",") if s.strip()] if allowed else [
            "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.1/32"
        ]

        try:
            poll_interval = float(poll_str)
        except ValueError:
            poll_interval = 3.0

        return cls(
            server_url=server_url.rstrip("/"),
            token=token,
            agent_id=agent_id,
            agent_name=agent_name,
            poll_interval=poll_interval,
            allowed_subnets=subnets,
        )

    def is_target_authorized(self, target_network_str: str) -> bool:
        """Validate whether a scan target is permitted within this agent's security boundary."""
        try:
            target_net = ipaddress.IPv4Network(target_network_str, strict=False)
        except Exception:
            return False

        for allowed_str in self.allowed_subnets:
            try:
                allowed_net = ipaddress.IPv4Network(allowed_str, strict=False)
                # Subnet containment check: target must be equal to or a sub-network of allowed
                if target_net.subnet_of(allowed_net):
                    return True
            except Exception:
                continue

        return False
