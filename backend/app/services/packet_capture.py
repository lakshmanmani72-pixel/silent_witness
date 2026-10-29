"""
SILENT WITNESS – Packet Capture Module (Live Monitoring & Wireshark-Style Inspection)
=====================================================================================
Wraps Scapy's sniff() for passive observation of a network interface, parses
real-time Layer 2/3/4 packet metadata, generates Wireshark-level inspection trees,
formats authentic packet hex dumps, and buffers packets for live SOC streaming.

SAFETY & ACADEMIC NOTES
-----------------------
• Only packet headers, metadata, and sanitized non-sensitive previews are captured.
• Zero offensive exploitation; safe dry-run containment integration.
• Hardware-level network adapter inspection for Wi-Fi, Ethernet, and Loopback.
• Supports on-demand synthetic packet injection for educational classroom demonstrations.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import random
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional, Callable, Any

logger = logging.getLogger("silent_witness.packet_capture")

# Check Scapy availability
try:
    from scapy.all import sniff, get_if_list, conf as scapy_conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Live capture disabled.")
except Exception as exc:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy import error: %s. Live capture disabled.", exc)

# Global packet broadcast callback (registered by main.py)
_packet_broadcast_callback: Optional[Callable[[dict], Any]] = None


_main_event_loop = None

def set_packet_broadcaster(fn: Callable[[dict], Any], loop=None) -> None:
    global _main_event_loop
    _main_event_loop = loop
    """Set the async or sync callback used to broadcast live packet events via WebSocket."""
    global _packet_broadcast_callback
    _packet_broadcast_callback = fn


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


def get_interfaces_detailed() -> list[dict]:
    """
    Return comprehensive hardware and protocol details for every network interface,
    mirroring Wireshark's interface selection dialogue.
    """
    if not SCAPY_AVAILABLE:
        return []
    detailed = []
    best_name = get_best_interface()
    try:
        from scapy.all import conf
        for iface in conf.ifaces.values():
            name = iface.name or "Unknown"
            desc = getattr(iface, "description", "") or name
            ip = getattr(iface, "ip", "") or ""
            mac = getattr(iface, "mac", "") or "00:00:00:00:00:00"

            # Determine interface classification
            lower_desc = (name + " " + desc).lower()
            if "wi-fi" in lower_desc or "wireless" in lower_desc or "802.11" in lower_desc:
                iface_type = "Wi-Fi (Wireless)"
            elif "ethernet" in lower_desc or "gigabit" in lower_desc or "lan" in lower_desc:
                iface_type = "Ethernet (Wired)"
            elif "loopback" in lower_desc:
                iface_type = "Loopback (Virtual)"
            elif "hyper-v" in lower_desc or "virtual" in lower_desc or "vethernet" in lower_desc:
                iface_type = "Virtual Network"
            else:
                iface_type = "Network Adapter"

            is_active = bool(ip and not ip.startswith("169.254"))
            detailed.append({
                "name": name,
                "description": desc,
                "ip": ip if ip else "Not Assigned",
                "mac": mac,
                "type": iface_type,
                "is_active": is_active,
                "is_default": (name == best_name),
                "status": "ONLINE" if is_active else "READY",
            })
    except Exception as ex:
        logger.warning("Error fetching detailed interfaces: %s", ex)
        for name in get_interfaces():
            detailed.append({
                "name": name,
                "description": name,
                "ip": "Unknown",
                "mac": "Unknown",
                "type": "Network Adapter",
                "is_active": True,
                "is_default": (name == best_name),
                "status": "READY",
            })

    # Sort so active/default interfaces appear first
    detailed.sort(key=lambda x: (not x["is_default"], not x["is_active"], x["name"]))
    return detailed


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


def format_hex_dump(raw_bytes: bytes, max_len: int = 64) -> str:
    """Format raw packet bytes into authentic Wireshark-style hex + ASCII dump."""
    raw = raw_bytes[:max_len]
    lines = []
    for i in range(0, len(raw), 16):
        chunk = raw[i:i+16]
        part1 = " ".join(f"{b:02x}" for b in chunk[:8])
        part2 = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_str = f"{part1:<23}  {part2:<23}" if len(chunk) > 8 else f"{part1:<48}"
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_str}   {ascii_str}")
    return "\n".join(lines)


def extract_metadata(packet) -> Optional[dict]:
    """
    Extract the minimum metadata needed for threat detection sliding windows.
    Payload data is intentionally NOT included for privacy compliance.
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


def parse_packet_for_inspector(packet, packet_no: int, iface_name: str, start_time: float) -> dict:
    """
    Generate a full Wireshark-like dissection model with collapsible layers,
    protocol categorization, header fields, and hex preview.
    """
    now = datetime.now()
    time_str = now.strftime("%H:%M:%S.%f")[:-3]
    time_rel = round(time.time() - start_time, 4) if start_time > 0 else 0.0000

    raw_bytes = bytes(packet) if hasattr(packet, "__bytes__") else b""
    pkt_len = len(raw_bytes) if raw_bytes else 60

    src_str = "Unknown"
    dst_str = "Unknown"
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    proto = "OTHER"
    flags_display = ""
    info_str = packet.summary() if hasattr(packet, "summary") else "Raw Network Packet"

    # Layer models
    frame_layer = {
        "title": f"Frame {packet_no}: {pkt_len} bytes on wire ({pkt_len * 8} bits) on interface {iface_name}",
        "fields": {
            "Frame Number": packet_no,
            "Interface": iface_name,
            "Arrival Time": time_str,
            "Frame Length": f"{pkt_len} bytes",
            "Capture Length": f"{pkt_len} bytes",
        }
    }

    ethernet_layer = None
    if packet.haslayer("Ether"):
        eth = packet["Ether"]
        ethernet_layer = {
            "title": f"Ethernet II, Src: {eth.src}, Dst: {eth.dst}",
            "fields": {
                "Source MAC": eth.src,
                "Destination MAC": eth.dst,
                "Type": hex(eth.type) if hasattr(eth, "type") else "0x0800 (IPv4)",
            }
        }

    ip_layer = None
    if packet.haslayer("IP"):
        ip = packet["IP"]
        src_ip = ip.src
        dst_ip = ip.dst
        src_str = src_ip
        dst_str = dst_ip
        proto_num = getattr(ip, "proto", 0)
        proto_name = "TCP (6)" if proto_num == 6 else ("UDP (17)" if proto_num == 17 else ("ICMP (1)" if proto_num == 1 else str(proto_num)))
        ip_layer = {
            "title": f"Internet Protocol Version 4, Src: {ip.src}, Dst: {ip.dst}",
            "fields": {
                "Version": getattr(ip, "version", 4),
                "Header Length": f"{(getattr(ip, 'ihl', None) or 5) * 4} bytes",
                "Total Length": getattr(ip, "len", pkt_len),
                "Identification": hex(getattr(ip, "id", None) or 0),
                "Time to Live (TTL)": getattr(ip, "ttl", 64),
                "Protocol": proto_name,
                "Header Checksum": hex(getattr(ip, "chksum", None) or 0),
                "Source IP": ip.src,
                "Destination IP": ip.dst,
            }
        }
    elif packet.haslayer("IPv6"):
        ip6 = packet["IPv6"]
        src_ip = ip6.src
        dst_ip = ip6.dst
        src_str = src_ip
        dst_str = dst_ip
        ip_layer = {
            "title": f"Internet Protocol Version 6, Src: {ip6.src}, Dst: {ip6.dst}",
            "fields": {
                "Source IP": ip6.src,
                "Destination IP": ip6.dst,
                "Next Header": getattr(ip6, "nh", 0),
                "Hop Limit": getattr(ip6, "hlim", 64),
            }
        }

    transport_layer = None
    if packet.haslayer("TCP"):
        tcp = packet["TCP"]
        proto = "TCP"
        src_port = tcp.sport
        dst_port = tcp.dport
        src_str = f"{src_ip}:{src_port}" if src_ip else str(src_port)
        dst_str = f"{dst_ip}:{dst_port}" if dst_ip else str(dst_port)

        flag_val = getattr(tcp, "flags", 0)
        # Check flags
        active_flags = []
        is_syn = bool(flag_val & 0x02)
        is_ack = bool(flag_val & 0x10)
        is_fin = bool(flag_val & 0x01)
        is_rst = bool(flag_val & 0x04)
        is_psh = bool(flag_val & 0x08)
        is_urg = bool(flag_val & 0x20)

        if is_syn: active_flags.append("SYN")
        if is_ack: active_flags.append("ACK")
        if is_fin: active_flags.append("FIN")
        if is_rst: active_flags.append("RST")
        if is_psh: active_flags.append("PSH")
        if is_urg: active_flags.append("URG")

        flags_display = f"[{', '.join(active_flags)}]" if active_flags else "[None]"
        seq_num = getattr(tcp, "seq", 0)
        ack_num = getattr(tcp, "ack", 0)
        win_size = getattr(tcp, "window", 65535)

        # Check application protocol hints
        if dst_port in (80, 8080) or src_port in (80, 8080):
            proto = "HTTP"
        elif dst_port == 443 or src_port == 443:
            proto = "TLS/HTTPS"
        elif dst_port == 53 or src_port == 53:
            proto = "DNS"

        info_str = f"{src_port} → {dst_port} {flags_display} Seq={seq_num} Ack={ack_num} Win={win_size} Len={pkt_len}"

        transport_layer = {
            "title": f"Transmission Control Protocol, Src Port: {src_port}, Dst Port: {dst_port}, Seq: {seq_num}, Ack: {ack_num}",
            "fields": {
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Sequence Number": seq_num,
                "Acknowledgment Number": ack_num,
                "Header Length": f"{(getattr(tcp, 'dataofs', None) or 5) * 4} bytes",
                "Flags": f"{hex(int(flag_val))} ({', '.join(active_flags)})",
                "Window Size": win_size,
                "Checksum": hex(getattr(tcp, "chksum", None) or 0),
            }
        }

    elif packet.haslayer("UDP"):
        udp = packet["UDP"]
        proto = "UDP"
        src_port = udp.sport
        dst_port = udp.dport
        src_str = f"{src_ip}:{src_port}" if src_ip else str(src_port)
        dst_str = f"{dst_ip}:{dst_port}" if dst_ip else str(dst_port)

        if dst_port == 53 or src_port == 53:
            proto = "DNS"
            info_str = f"DNS Query/Response {src_port} → {dst_port} Len={getattr(udp, 'len', pkt_len)}"
        elif dst_port in (67, 68) or src_port in (67, 68):
            proto = "DHCP"
            info_str = f"DHCP Dynamic Host Configuration {src_port} → {dst_port}"
        elif dst_port == 5353 or src_port == 5353:
            proto = "MDNS"
            info_str = f"Multicast DNS {src_port} → {dst_port}"
        elif dst_port == 1900 or src_port == 1900:
            proto = "SSDP"
            info_str = f"Simple Service Discovery Protocol {src_port} → {dst_port}"
        else:
            info_str = f"{src_port} → {dst_port} Len={getattr(udp, 'len', pkt_len)}"

        transport_layer = {
            "title": f"User Datagram Protocol, Src Port: {src_port}, Dst Port: {dst_port}, Len: {getattr(udp, 'len', pkt_len)}",
            "fields": {
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Length": getattr(udp, "len", pkt_len),
                "Checksum": hex(getattr(udp, "chksum", None) or 0),
            }
        }

    elif packet.haslayer("ICMP"):
        proto = "ICMP"
        icmp = packet["ICMP"]
        icmp_type = getattr(icmp, "type", 8)
        icmp_code = getattr(icmp, "code", 0)
        type_str = "Echo (ping) request" if icmp_type == 8 else ("Echo (ping) reply" if icmp_type == 0 else f"Type {icmp_type}")
        info_str = f"{type_str} id={hex(getattr(icmp, 'id', 1))} seq={getattr(icmp, 'seq', 1)}"
        transport_layer = {
            "title": f"Internet Control Message Protocol ({type_str})",
            "fields": {
                "Type": f"{icmp_type} ({type_str})",
                "Code": icmp_code,
                "Checksum": hex(getattr(icmp, "chksum", None) or 0),
                "Identifier": hex(getattr(icmp, "id", None) or 1),
                "Sequence Number": getattr(icmp, "seq", 1),
            }
        }

    elif packet.haslayer("ARP"):
        proto = "ARP"
        arp = packet["ARP"]
        src_str = arp.psrc
        dst_str = arp.pdst
        info_str = f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}"
        transport_layer = {
            "title": f"Address Resolution Protocol ({'request' if arp.op == 1 else 'reply'})",
            "fields": {
                "Hardware type": getattr(arp, "hwtype", 1),
                "Protocol type": hex(getattr(arp, "ptype", 0x0800)),
                "Sender MAC": arp.hwsrc,
                "Sender IP": arp.psrc,
                "Target MAC": arp.hwdst,
                "Target IP": arp.pdst,
            }
        }

    return {
        "no": packet_no,
        "time": time_str,
        "time_relative": time_rel,
        "source": src_str,
        "destination": dst_str,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "length": pkt_len,
        "flags": flags_display,
        "info": info_str,
        "layers": {
            "frame": frame_layer,
            "ethernet": ethernet_layer,
            "ip": ip_layer,
            "transport": transport_layer,
        },
        "hex_dump": format_hex_dump(raw_bytes, max_len=64),
        "is_threat": False,
        "threat_info": None,
    }


class PacketCapture:
    """
    Manages live packet capture in a background thread, maintains a rolling
    in-memory ring buffer of packet records for Wireshark-style inspection,
    and supports test packet synthesis for classroom presentations.
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

        # Rolling packet ring buffer (retains last 400 packets)
        self._packet_buffer = collections.deque(maxlen=400)
        self._packet_counter = 0
        self._start_time = 0.0
        self._last_ws_emit_time = 0.0

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
        """Start packet capture on the specified network interface."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not available. Install it with: py -m pip install scapy\n"
                "On Windows, Npcap must be installed from https://npcap.com/"
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
        self._start_time = time.time()

        with self._lock:
            self._packets_since_last_stat = 0
            self._suspicious_since_last_stat = 0
            self._threats_since_last_stat = 0
            self._unique_sources.clear()

        def _sniff_target():
            def _packet_handler(pkt):
                if self._stop_event.is_set():
                    return

                with self._lock:
                    self._packet_counter += 1
                    pkt_no = self._packet_counter

                # 1. Generate full Wireshark dissection record
                dissected = parse_packet_for_inspector(pkt, pkt_no, display_name, self._start_time)

                # 2. Extract lightweight metadata for sliding window threat detection
                meta = extract_metadata(pkt)
                if meta:
                    self._packets_captured += 1
                    with self._lock:
                        self._packets_since_last_stat += 1
                        if meta.get("src_ip"):
                            self._unique_sources.add(meta["src_ip"])

                    # Pass to threat detector callback
                    # If threat is detected by callback, it records stats
                    detection_result = callback(meta)
                    if detection_result:
                        dissected["is_threat"] = True
                        dissected["threat_info"] = {
                            "threat_type": detection_result.get("threat_type"),
                            "severity": detection_result.get("severity"),
                            "reason": detection_result.get("detection_reason"),
                        }

                # Store into rolling buffer
                with self._lock:
                    self._packet_buffer.append(dissected)

                # Broadcast to connected WebSocket clients (rate limited to max 25 pkts/sec)
                now_t = time.time()
                if _packet_broadcast_callback and (now_t - self._last_ws_emit_time >= 0.04 or dissected["is_threat"]):
                    self._last_ws_emit_time = now_t
                    try:
                        res = _packet_broadcast_callback({
                            "type": "packet",
                            "packet": dissected,
                            "interface": display_name,
                        })
                        if asyncio.iscoroutine(res):
                            try:
                                loop = _main_event_loop or asyncio.get_running_loop()
                                asyncio.run_coroutine_threadsafe(res, loop)
                            except RuntimeError:
                                pass
                    except Exception as err:
                        logger.debug("Packet broadcast error: %s", err)

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

    def get_recent_packets(self, limit: int = 100, protocol: Optional[str] = None, search: Optional[str] = None) -> list[dict]:
        """Return the most recent captured packets matching optional filters."""
        with self._lock:
            packets = list(self._packet_buffer)

        if protocol and protocol.upper() != "ALL":
            p_upper = protocol.upper()
            if p_upper == "THREATS":
                packets = [p for p in packets if p.get("is_threat")]
            else:
                packets = [p for p in packets if p.get("protocol", "").upper() == p_upper]

        if search:
            s_lower = search.lower()
            packets = [
                p for p in packets
                if s_lower in str(p.get("source", "")).lower()
                or s_lower in str(p.get("destination", "")).lower()
                or s_lower in str(p.get("info", "")).lower()
                or s_lower in str(p.get("protocol", "")).lower()
            ]

        # Return latest first or chronological
        return packets[-limit:]

    def clear_packets(self) -> None:
        """Clear the in-memory rolling packet buffer."""
        with self._lock:
            self._packet_buffer.clear()
            self._packet_counter = 0

    def inject_synthetic_traffic(self, traffic_type: str = "normal", count: int = 10, detector_callback: Optional[Callable] = None) -> list[dict]:
        """
        Generate and ingest synthetic packets directly through the inspection pipeline.
        Ideal for classroom and viva presentations to prove detection algorithms on demand.
        """
        injected = []
        iface = self._interface or get_best_interface() or "Wi-Fi"
        if self._start_time == 0.0:
            self._start_time = time.time()

        for i in range(count):
            with self._lock:
                self._packet_counter += 1
                pkt_no = self._packet_counter

            src_ip = f"198.51.100.{random.randint(10, 200)}"
            dst_ip = "10.160.93.91"

            if traffic_type == "syn_flood":
                # Simulated SYN flood packet
                src_ip = "203.0.113.88"  # Consistent attacker IP to trigger threshold
                sport = random.randint(30000, 65000)
                dport = 80
                pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S", seq=random.randint(1000, 90000), window=64240)
            elif traffic_type == "port_scan":
                # Simulated Port scan packet across sequential ports
                src_ip = "198.51.100.99"
                sport = 49152
                dport = (i * 7 + 21) % 1024 + 20
                pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S", seq=100)
            elif traffic_type == "ping":
                # ICMP Echo request
                pkt = IP(src=src_ip, dst=dst_ip)/ICMP(type=8, id=0x1234, seq=i+1)
            elif traffic_type == "dns":
                # DNS query
                query_names = ["google.com", "github.com", "fastapi.tiangolo.com", "cloudflare.com"]
                qname = query_names[i % len(query_names)]
                pkt = IP(src=dst_ip, dst="8.8.8.8")/UDP(sport=random.randint(40000, 60000), dport=53)/DNS(rd=1, qd=None)
            else:
                # Normal HTTP / TLS traffic
                sport = random.randint(40000, 60000)
                dport = 443 if i % 2 == 0 else 80
                flags = "A" if i % 3 != 0 else "PA"
                pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags=flags, seq=i*500, ack=i*500, window=65535)

            dissected = parse_packet_for_inspector(pkt, pkt_no, iface, self._start_time)
            meta = extract_metadata(pkt)

            if meta and detector_callback:
                det = detector_callback(meta)
                if det:
                    dissected["is_threat"] = True
                    dissected["threat_info"] = {
                        "threat_type": det.get("threat_type"),
                        "severity": det.get("severity"),
                        "reason": det.get("detection_reason"),
                    }

            with self._lock:
                self._packet_buffer.append(dissected)
                self._packets_captured += 1

            injected.append(dissected)

            # Broadcast packet
            if _packet_broadcast_callback:
                try:
                    res = _packet_broadcast_callback({
                        "type": "packet",
                        "packet": dissected,
                        "interface": iface,
                    })
                    if asyncio.iscoroutine(res):
                        try:
                            loop = _main_event_loop or asyncio.get_running_loop()
                            asyncio.run_coroutine_threadsafe(res, loop)
                        except RuntimeError:
                            pass
                except Exception as ex:
                    logger.debug("Broadcast error: %s", ex)

        return injected

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
