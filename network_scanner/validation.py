"""Input validation and network calculation module.

Validates CIDR subnets, individual IPv4 addresses, port ranges, and concurrency parameters
to ensure safe, bounded, and RFC-compliant network operations.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Tuple


# Maximum hosts allowed in a single scan batch to prevent accidental DOS or exhaustion
DEFAULT_MAX_HOSTS = 1024  # Equivalent to /22


class ValidationError(ValueError):
    """Raised when user network input fails validation."""
    pass


def validate_network(target: str, max_hosts: int = DEFAULT_MAX_HOSTS) -> ipaddress.IPv4Network:
    """Validate and parse an IPv4 address or CIDR notation string.

    Args:
        target: Target IP or CIDR (e.g., '192.168.1.0/24' or '10.0.0.5')
        max_hosts: Maximum permitted host count to prevent unbounded scans.

    Returns:
        ipaddress.IPv4Network object

    Raises:
        ValidationError: If target syntax is invalid or range exceeds max_hosts.
    """
    if not target or not isinstance(target, str):
        raise ValidationError("Target network or IP cannot be empty.")

    target = target.strip()

    # Append /32 if single IP provided without mask
    if "/" not in target:
        target = f"{target}/32"

    try:
        network = ipaddress.IPv4Network(target, strict=False)
    except ipaddress.AddressValueError as exc:
        raise ValidationError(f"Invalid IPv4 address or CIDR syntax: {exc}") from exc
    except ipaddress.NetmaskValueError as exc:
        raise ValidationError(f"Invalid netmask or prefix length: {exc}") from exc
    except ValueError as exc:
        raise ValidationError(f"Could not parse network '{target}': {exc}") from exc

    # Prohibit multicast or reserved unroutable addresses from general discovery
    if network.is_multicast:
        raise ValidationError(f"Multicast range '{network}' is not supported for standard network discovery.")
    if network.network_address == ipaddress.IPv4Address("255.255.255.255"):
        raise ValidationError("Limited broadcast address 255.255.255.255 is invalid as a scan target.")

    # Check host count limit
    total_hosts = network.num_addresses
    if total_hosts > max_hosts:
        raise ValidationError(
            f"Requested network '{network}' contains {total_hosts} addresses, exceeding the maximum safe limit of {max_hosts} hosts (minimum prefix /{32 - (max_hosts.bit_length() - 1)})."
        )

    return network


def enumerate_hosts(network: ipaddress.IPv4Network) -> List[str]:
    """Enumerate valid host IP addresses in a network as string representations.

    For a /32 or /31, returns all addresses.
    For /30 or larger, excludes network address and broadcast address per standard IPv4 rules.
    """
    if network.prefixlen >= 31:
        return [str(ip) for ip in network]
    return [str(ip) for ip in network.hosts()]


def parse_ports(port_input: str | None) -> List[int]:
    """Parse a comma-separated list or range of port numbers.

    Supported formats:
        - "22,80,443"
        - "80-85,443"
        - "8080"

    Returns:
        Sorted unique list of valid integer ports between 1 and 65535.

    Raises:
        ValidationError: On invalid port format or out-of-range value.
    """
    if not port_input:
        return []

    port_input = str(port_input).strip()
    if not port_input:
        return []

    ports_set = set()
    tokens = [t.strip() for t in port_input.split(",") if t.strip()]

    for token in tokens:
        if "-" in token:
            range_parts = token.split("-")
            if len(range_parts) != 2:
                raise ValidationError(f"Invalid port range format: '{token}'")
            try:
                start_p = int(range_parts[0].strip())
                end_p = int(range_parts[1].strip())
            except ValueError:
                raise ValidationError(f"Port range contains non-numeric values: '{token}'")

            if start_p > end_p:
                raise ValidationError(f"Start port {start_p} cannot be greater than end port {end_p}.")
            if start_p < 1 or end_p > 65535:
                raise ValidationError(f"Port range {start_p}-{end_p} out of valid range (1-65535).")
            if (end_p - start_p) > 1000:
                raise ValidationError(f"Port range too large: {end_p - start_p + 1} ports requested (maximum 1000).")

            for p in range(start_p, end_p + 1):
                ports_set.add(p)
        else:
            try:
                p = int(token)
            except ValueError:
                raise ValidationError(f"Invalid non-integer port value: '{token}'")
            if p < 1 or p > 65535:
                raise ValidationError(f"Port {p} is out of valid range (1-65535).")
            ports_set.add(p)

    return sorted(list(ports_set))


def validate_thread_count(threads: int, max_allowed: int = 200) -> int:
    """Validate thread pool concurrency bounds."""
    try:
        t = int(threads)
    except (ValueError, TypeError):
        raise ValidationError(f"Thread count must be an integer, received: {threads}")

    if t < 1:
        raise ValidationError("Thread count must be at least 1.")
    if t > max_allowed:
        raise ValidationError(f"Thread count {t} exceeds maximum permitted {max_allowed}.")
    return t
