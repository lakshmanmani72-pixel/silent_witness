"""
SILENT WITNESS – Packet Capture Module (Live Monitoring)
=========================================================
Wraps Scapy's sniff() for passive observation of a network interface.

SAFETY NOTES
------------
• Only packet METADATA is extracted – payload data is never stored.
• No packets are ever sent by this module.
• No remote connections are initiated.
• Capture stops immediately when requested.
• On Windows, Npcap or WinPcap must be installed.
• When Scapy is unavailable, this module gracefully reports the limitation.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
from typing import Optional, Callable

logger = logging.getLogger("silent_witness.packet_capture")

# Check Scapy availability
try:
    from scapy.all import sniff, get_if_list, conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Live capture disabled.")
except Exception as exc:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy import error: %s. Live capture disabled.", exc)


def get_interfaces() -> list[str]:
    """Return available network interface friendly names and devices."""
    if not SCAPY_AVAILABLE:
        return []
    try:
        from scapy.all import conf
        names = []
        for iface in conf.ifaces.values():
            if iface.name and iface.name not in names:
                names.append(iface.name)
        return names if names else get_if_list()
    except Exception:
        return get_if_list()


def resolve_interface(name: str):
    """Resolve a friendly interface name (e.g. 'Wi-Fi') to a Scapy NetworkInterface object or device path."""
    if not SCAPY_AVAILABLE or not name:
        return name
    try:
        from scapy.all import conf
        # 1. Match by exact device path key in conf.ifaces
        if name in conf.ifaces:
            return conf.ifaces[name]
        # 2. Match by friendly name (case-insensitive)
        for iface in conf.ifaces.values():
            if iface.name and iface.name.lower() == name.lower():
                return iface
        # 3. Match by description
        for iface in conf.ifaces.values():
            if getattr(iface, "description", "").lower() == name.lower():
                return iface
    except Exception as ex:
        logger.debug("Interface resolution fallback for %s: %s", name, ex)
    return name


def get_best_interface() -> str:
    """Return the active network interface with an assigned IPv4 address (e.g. Wi-Fi)."""
    if not SCAPY_AVAILABLE:
        return ""
    try:
        from scapy.all import conf
        # 1. Search for interface with a valid routable/private IPv4
        for iface in conf.ifaces.values():
            ip = getattr(iface, "ip", "")
            if ip and not ip.startswith("127.") and not ip.startswith("169.254"):
                return iface.name
        # 2. Look for Wi-Fi or Ethernet names
        for iface in conf.ifaces.values():
            if iface.name in ("Wi-Fi", "Ethernet"):
                return iface.name
    except Exception as ex:
        logger.debug("Error finding best interface: %s", ex)

    ifaces = get_interfaces()
    return ifaces[0] if ifaces else ""


def extract_metadata(packet) -> Optional[dict]:
    """
    Extract only the minimum metadata needed for threat detection.
    Payload data is intentionally NOT included.
    """
    try:
        meta: dict = {
            "src_ip":   None,
            "dst_ip":   None,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "flags":    "",
        }

        if packet.haslayer("IP"):
            meta["src_ip"] = packet["IP"].src
            meta["dst_ip"] = packet["IP"].dst

        elif packet.haslayer("IPv6"):
            meta["src_ip"] = packet["IPv6"].src
            meta["dst_ip"] = packet["IPv6"].dst

        if packet.haslayer("TCP"):
            meta["protocol"] = "TCP"
            meta["src_port"] = packet["TCP"].sport
            meta["dst_port"] = packet["TCP"].dport
            flag_int = packet["TCP"].flags
            flag_str = ""
            if flag_int & 0x02:
                flag_str += "S"
            if flag_int & 0x10:
                flag_str += "A"
            if flag_int & 0x01:
                flag_str += "F"
            if flag_int & 0x04:
                flag_str += "R"
            if flag_int & 0x08:
                flag_str += "P"
            meta["flags"] = flag_str

        elif packet.haslayer("UDP"):
            meta["protocol"] = "UDP"
            meta["src_port"] = packet["UDP"].sport
            meta["dst_port"] = packet["UDP"].dport

        elif packet.haslayer("ICMP"):
            meta["protocol"] = "ICMP"

        if meta["src_ip"] is None:
            return None

        return meta

    except Exception as exc:
        logger.debug("Metadata extraction error: %s", exc)
        return None


class PacketCapture:
    """
    Wraps Scapy sniff in a background thread so it does not block asyncio.
    The caller provides a callback that receives extracted metadata dicts.
    """

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._active = False
        self._interface: Optional[str] = None
        self._packets_captured = 0
        self._packets_since_last_stat = 0
        self._suspicious_since_last_stat = 0
        self._threats_since_last_stat = 0
        self._unique_sources: set[str] = set()
        self._lock = threading.Lock()

    @property
    def active(self) -> bool:
        return self._active

    @property
    def interface(self) -> Optional[str]:
        return self._interface

    @property
    def packets_captured(self) -> int:
        return self._packets_captured

    def start(self, interface: str, callback: Callable[[dict], None]) -> None:
        """Start packet capture on the specified interface."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not available. Install it with: py -m pip install scapy\n"
                "On Windows, also install Npcap from https://npcap.com/"
            )

        resolved = resolve_interface(interface)
        ifaces = get_interfaces()
        valid = (interface in ifaces) or (resolved != interface)
        if not valid:
            from scapy.all import get_if_list
            valid = (interface in get_if_list())

        if not valid:
            raise ValueError(
                f"Interface '{interface}' not found. Available: {ifaces}"
            )

        target_iface = resolved if resolved else interface
        display_name = getattr(resolved, "name", interface)

        self._stop_event.clear()
        self._active = True
        self._interface = display_name
        self._packets_captured = 0
        with self._lock:
            self._packets_since_last_stat = 0
            self._suspicious_since_last_stat = 0
            self._threats_since_last_stat = 0
            self._unique_sources.clear()

        def _sniff_target():
            def _packet_handler(pkt):
                if self._stop_event.is_set():
                    return
                meta = extract_metadata(pkt)
                if meta:
                    self._packets_captured += 1
                    with self._lock:
                        self._packets_since_last_stat += 1
                        if meta.get("src_ip"):
                            self._unique_sources.add(meta["src_ip"])
                    callback(meta)

            try:
                sniff(
                    iface=target_iface,
                    prn=_packet_handler,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
            except Exception as exc:
                logger.error("Capture error on %s: %s", display_name, exc)
            finally:
                self._active = False
                logger.info("Packet capture stopped on %s", display_name)

        self._thread = threading.Thread(target=_sniff_target, daemon=True, name="packet_capture")
        self._thread.start()
        logger.info("Live packet capture started on interface %s", display_name)

    def record_detection_stat(self, is_threat: bool = True):
        with self._lock:
            if is_threat:
                self._threats_since_last_stat += 1
                self._suspicious_since_last_stat += 1
            else:
                self._suspicious_since_last_stat += 1

    def flush_stats(self) -> dict:
        """Flush accumulated packet counts for traffic_stats persistence."""
        with self._lock:
            stats = {
                "packets": self._packets_since_last_stat,
                "suspicious": self._suspicious_since_last_stat,
                "threats": self._threats_since_last_stat,
                "unique_sources": len(self._unique_sources),
            }
            self._packets_since_last_stat = 0
            self._suspicious_since_last_stat = 0
            self._threats_since_last_stat = 0
            self._unique_sources.clear()
            return stats

    def stop(self) -> None:
        """Signal the capture thread to stop."""
        self._stop_event.set()
        self._active = False
        logger.info("Packet capture stop requested")


_capture: Optional[PacketCapture] = None


def get_capture() -> PacketCapture:
    global _capture
    if _capture is None:
        _capture = PacketCapture()
    return _capture
