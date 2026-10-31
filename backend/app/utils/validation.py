"""
SILENT WITNESS – IP Validation Utilities
All IP address validation is centralised here to ensure consistent safety checks
before any blocking or firewall action is taken.
"""

import ipaddress
import re
from typing import Optional

# IPs that must never be blocked under any circumstances
PROTECTED_PREFIXES = [
    "127.",       # loopback
    "0.0.0.0",   # unspecified
    "::1",        # IPv6 loopback
    "::ffff:",    # IPv4-mapped IPv6
    "ff00::",     # multicast
    "fe80::",     # link-local
]


def validate_ip(ip_str: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Parse and validate an IP address string.
    Returns the address object on success, None if invalid.
    """
    if not ip_str or not isinstance(ip_str, str):
        return None
    ip_str = ip_str.strip()
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return None


def is_safe_to_block(ip_str: str, allowlist: list[str] | None = None) -> tuple[bool, str]:
    """
    Determine whether an IP address is safe to block.

    Returns:
        (True, "ok") if blocking is acceptable.
        (False, reason) if the IP should not be blocked.
    """
    addr = validate_ip(ip_str)
    if addr is None:
        return False, f"Invalid IP address: {ip_str!r}"

    if addr.is_loopback:
        return False, "Loopback addresses must not be blocked"

    if addr.is_unspecified:
        return False, "Unspecified address must not be blocked"

    if addr.is_multicast:
        return False, "Multicast addresses must not be blocked"

    if addr.is_link_local:
        return False, "Link-local addresses must not be blocked"

    if addr.is_reserved:
        return False, "Reserved addresses must not be blocked"

    # Check against allow-list
    if allowlist:
        for entry in allowlist:
            try:
                # Support CIDR ranges
                network = ipaddress.ip_network(entry, strict=False)
                if addr in network:
                    return False, f"IP {ip_str} is in the allow-list ({entry})"
            except ValueError:
                if str(addr) == entry.strip():
                    return False, f"IP {ip_str} is in the allow-list"

    return True, "ok"


def is_private_ip(ip_str: str) -> bool:
    """Return True if the address is RFC-1918 private or loopback."""
    addr = validate_ip(ip_str)
    if addr is None:
        return False
    return addr.is_private or addr.is_loopback
