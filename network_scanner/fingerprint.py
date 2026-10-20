"""Evidence-based OS fingerprinting module.

Strictly follows project requirement:
- Never fabricate or guess operating systems.
- Returns 'Unknown' unless backed by concrete open port signatures or banner strings.
"""

from __future__ import annotations

from typing import List, Optional, Tuple


def evaluate_os_evidence(
    open_ports: List[int],
    banners: List[str] | None = None,
    ttl: Optional[int] = None,
) -> Tuple[str, str]:
    """Evaluate operating system match solely based on observable technical evidence.

    Returns:
        (os_match, evidence_description)
    """
    ports_set = set(open_ports or [])
    banners = banners or []

    # 1. Direct Banner Inspection (highest confidence)
    for banner in banners:
        if not banner:
            continue
        banner_lower = banner.lower()
        if "ubuntu" in banner_lower:
            return "Linux (Ubuntu)", f"Banner evidence: '{banner.strip()[:80]}'"
        if "debian" in banner_lower:
            return "Linux (Debian)", f"Banner evidence: '{banner.strip()[:80]}'"
        if "centos" in banner_lower or "red hat" in banner_lower or "rhel" in banner_lower:
            return "Linux (RHEL/CentOS)", f"Banner evidence: '{banner.strip()[:80]}'"
        if "freebsd" in banner_lower:
            return "FreeBSD", f"Banner evidence: '{banner.strip()[:80]}'"
        if "microsoft-iis" in banner_lower or "microsoft-httpapi" in banner_lower or "windows" in banner_lower:
            return "Microsoft Windows", f"Banner evidence: '{banner.strip()[:80]}'"
        if "mikrotik" in banner_lower or "routeros" in banner_lower:
            return "RouterOS (MikroTik)", f"Banner evidence: '{banner.strip()[:80]}'"
        if "cisco" in banner_lower:
            return "Cisco IOS", f"Banner evidence: '{banner.strip()[:80]}'"
        if "openwrt" in banner_lower or "dropbear" in banner_lower:
            return "Embedded Linux (OpenWrt/Dropbear)", f"Banner evidence: '{banner.strip()[:80]}'"

    # 2. Port combination signatures (moderate confidence)
    if {135, 139, 445}.issubset(ports_set) or (445 in ports_set and 3389 in ports_set):
        return "Microsoft Windows", "Active SMB (445/139), MSRPC (135), and/or RDP (3389) signature"

    if 3389 in ports_set and 445 not in ports_set and 22 in ports_set:
        return "Linux (xrdp) or Windows", "Port 3389 (RDP) and 22 (SSH) open; requires deeper inspection"

    if {22, 80, 443}.issubset(ports_set) and 445 not in ports_set and 135 not in ports_set:
        return "Linux / Unix", "Standard POSIX stack with SSH (22) and Web (80/443); Windows RPC absent"

    # 3. Known appliance signatures
    if 5353 in ports_set and (7000 in ports_set or 5000 in ports_set):
        return "Apple macOS / iOS / tvOS", "AirPlay / Bonjour service signature (5353, 5000/7000)"

    # If no conclusive proof:
    return "Unknown", "Insufficient port or banner signatures to determine OS reliably"
