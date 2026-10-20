"""Environment capability detection module.

Accurately detects whether current runtime has permissions for Layer 2 ARP broadcast,
raw socket access, or is constrained by serverless/cloud container sandboxes.
"""

from __future__ import annotations

import os
import platform
import socket
import sys
from typing import Any, Dict, List


def is_root_or_admin() -> bool:
    """Check whether process has superuser / administrative privileges."""
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return False


def is_scapy_available() -> bool:
    """Check if Scapy library is installed and importable."""
    try:
        import scapy.all  # noqa: F401
        return True
    except ImportError:
        return False


def can_open_raw_socket() -> bool:
    """Test whether raw socket creation is permitted by the kernel."""
    if sys.platform.startswith("linux"):
        try:
            # AF_PACKET requires CAP_NET_RAW or root on Linux
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            s.close()
            return True
        except (PermissionError, OSError):
            return False
    return False


def detect_capabilities() -> Dict[str, Any]:
    """Detect real, non-fabricated platform capabilities."""
    is_vercel = bool(os.environ.get("VERCEL") or os.environ.get("NOW_REGION"))
    is_cloud_container = bool(
        os.environ.get("K_SERVICE")  # Google Cloud Run
        or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        or os.environ.get("RAILWAY_ENVIRONMENT")
    )

    root = is_root_or_admin()
    scapy_ok = is_scapy_available()
    raw_socket_ok = can_open_raw_socket()

    # ARP discovery requires Scapy, root/admin, and raw packet capabilities on supported OS
    arp_supported = bool(not is_vercel and not is_cloud_container and root and scapy_ok and (raw_socket_ok or sys.platform != "linux"))

    supported_methods: List[str] = ["tcp_connect", "hostname_resolution"]
    if arp_supported:
        supported_methods.insert(0, "arp_discovery")

    deployment = "vercel" if is_vercel else ("cloud_run" if os.environ.get("K_SERVICE") else "local_linux" if sys.platform.startswith("linux") else sys.platform)

    status = "full" if arp_supported else "limited"

    reasons = []
    if is_vercel:
        reasons.append("Running in Vercel serverless sandbox (No raw socket or L2 broadcast access).")
    if not root:
        reasons.append("Running without elevated privileges (Root/sudo required for Scapy ARP broadcasts).")
    if not scapy_ok:
        reasons.append("Scapy library is not installed in the active environment.")
    if not raw_socket_ok and sys.platform.startswith("linux") and not is_vercel:
        reasons.append("Linux kernel CAP_NET_RAW capability is absent.")

    return {
        "deployment": deployment,
        "arp_discovery": arp_supported,
        "raw_packet_access": raw_socket_ok,
        "external_agent_configured": False,
        "supported_methods": supported_methods,
        "status": status,
        "is_root": root,
        "scapy_installed": scapy_ok,
        "platform": f"{platform.system()} {platform.release()}",
        "python_version": platform.python_version(),
        "limitations": reasons,
    }
