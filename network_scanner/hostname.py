"""Hostname resolution module using reverse DNS with bounded timeouts.

Handles lookup failures honestly and safely across diverse network environments.
"""

from __future__ import annotations

import socket
from typing import Optional


def resolve_hostname(ip: str, timeout_sec: float = 1.0) -> Optional[str]:
    """Attempt reverse DNS lookup for an IPv4 address.

    Args:
        ip: IPv4 address string
        timeout_sec: Socket default timeout during lookup

    Returns:
        Resolved FQDN/hostname or None if resolution failed or timed out.
    """
    if not ip or not isinstance(ip, str):
        return None

    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_sec)
        hostname, _, _ = socket.gethostbyaddr(ip.strip())
        return hostname.strip() if hostname else None
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(orig_timeout)
