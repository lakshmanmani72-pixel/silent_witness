"""
SILENT WITNESS – Traffic Simulator
=====================================
Generates clearly labelled SYNTHETIC demonstration events for educational SOC analysis.

IMPORTANT ACADEMIC NOTES
-------------------------
• All generated events are tagged event_source='simulation'.
• No real packets are sent on external networks; no real hosts are contacted.
• The simulator produces realistic packet records in the live packet ring buffer
  and broadcasts them via WebSocket for the interactive network topology,
  pipeline journey, and Wireshark-style sniffer views.
• The dashboard clearly displays DEMO MODE — SYNTHETIC DATA.
• Every displayed counter is derived directly from actual simulator events.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import random
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.services.threat_detector import get_detector
from app.services.event_processor import process_detection, record_traffic_stat
from app.services.packet_capture import get_capture, format_hex_dump
import app.services.packet_capture as pc

logger = logging.getLogger("silent_witness.simulator")

# ── Simulated IP pools ────────────────────────────────────────────────────────
NORMAL_SOURCES = [f"192.168.1.{i}" for i in range(10, 50)]
ATTACKER_SOURCES = [
    "10.0.0.99",       # Primary attacker
    "172.16.5.200",    # Stealth reconnaissance attacker
    "198.51.100.77",   # Port scan attacker
    "203.0.113.45",    # Secondary threat source
]
SERVER_IPS = [
    "192.168.1.1",     # Protected Gateway & Web Server
    "192.168.1.254",   # Core Database Server
    "10.0.0.1",        # Protected Enterprise Host
]
COMMON_PORTS = [80, 443, 22, 21, 53, 3306, 5432, 6379, 8080, 8443]


class TrafficSimulator:
    """
    Async interactive simulation loop that feeds synthetic packet metadata
    through the ThreatDetector, records results, and drives real-time topology animations.
    """

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._active = False
        self._paused = False
        self._speed = 1.0
        self._scenario = "mixed"  # "normal" | "syn_flood" | "port_scan" | "suspicious_flags" | "mixed"
        self._start_time: Optional[datetime] = None
        self._detector = get_detector()
        self._capture = get_capture()

        # Strict real-time metric counters (No hardcoding)
        self._packets_generated = 0
        self._packets_processed = 0
        self._normal_packets = 0
        self._suspicious_packets = 0
        self._threats_detected = 0
        self._packets_blocked = 0

        # Rate tracking
        self._last_sec_timestamp = time.monotonic()
        self._last_sec_packet_count = 0
        self._current_rate = 0.0

        # Protocol distribution
        self._protocol_counts: Dict[str, int] = collections.defaultdict(int)

        # Source IP tracking
        self._source_counts: Dict[str, int] = collections.defaultdict(int)

        # Blocked IP set for simulation containment
        self._blocked_ips: set[str] = set()

        # Recent explainable threats cache (retains last 15)
        self._recent_threats = collections.deque(maxlen=15)

        # Traffic stats batching
        self._packets_since_stat = 0
        self._suspicious_since_stat = 0
        self._threats_since_stat = 0
        self._seen_ips_since_stat: set[str] = set()

    # ── Control Methods ───────────────────────────────────────────────────────

    async def start(self, speed: float = 1.0, scenario: str = "mixed") -> None:
        """Start or resume continuous simulation."""
        self._speed = max(0.1, min(speed, 10.0))
        if scenario in ("normal", "syn_flood", "port_scan", "suspicious_flags", "mixed"):
            self._scenario = scenario

        if self._active:
            self._paused = False
            logger.info("Simulator already active; updated speed=%.1fx scenario=%s", self._speed, self._scenario)
            return

        self._active = True
        self._paused = False
        if not self._start_time:
            self._start_time = datetime.now(timezone.utc)
        self._task = asyncio.create_task(self._loop(), name="simulator_loop")
        logger.info("Simulator started (scenario=%s, speed=%.1fx)", self._scenario, self._speed)

    async def pause(self) -> None:
        """Pause packet generation without clearing counters."""
        self._paused = True
        logger.info("Simulator paused")

    async def resume(self) -> None:
        """Resume paused packet generation."""
        self._paused = False
        logger.info("Simulator resumed")

    async def stop(self) -> None:
        """Stop packet generation loop."""
        self._active = False
        self._paused = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                loop = asyncio.get_running_loop()
                if self._task.get_loop() == loop:
                    await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._task = None
        self._current_rate = 0.0
        logger.info("Simulator stopped. Total packets: %d", self._packets_generated)

    async def reset(self) -> None:
        """Reset all counters, detector state, and blocked IP cache."""
        await self.stop()
        self._packets_generated = 0
        self._packets_processed = 0
        self._normal_packets = 0
        self._suspicious_packets = 0
        self._threats_detected = 0
        self._packets_blocked = 0
        self._current_rate = 0.0
        self._start_time = None
        self._protocol_counts.clear()
        self._source_counts.clear()
        self._blocked_ips.clear()
        self._recent_threats.clear()

        self._packets_since_stat = 0
        self._suspicious_since_stat = 0
        self._threats_since_stat = 0
        self._seen_ips_since_stat.clear()

        self._detector.reset()
        self._capture.clear_packets()
        logger.info("Simulator state and metrics reset")

    def set_scenario(self, scenario: str) -> None:
        """Change active scenario on the fly and reset relevant attacker state for clean demonstration replay."""
        if scenario in ("normal", "syn_flood", "port_scan", "suspicious_flags", "mixed"):
            self._scenario = scenario
            if scenario == "syn_flood":
                self._blocked_ips.discard(ATTACKER_SOURCES[0])
                if ATTACKER_SOURCES[0] in self._detector._ip_state:
                    del self._detector._ip_state[ATTACKER_SOURCES[0]]
            elif scenario == "port_scan":
                self._blocked_ips.discard(ATTACKER_SOURCES[2])
                if ATTACKER_SOURCES[2] in self._detector._ip_state:
                    del self._detector._ip_state[ATTACKER_SOURCES[2]]
            elif scenario == "suspicious_flags":
                self._blocked_ips.discard(ATTACKER_SOURCES[1])
                if ATTACKER_SOURCES[1] in self._detector._ip_state:
                    del self._detector._ip_state[ATTACKER_SOURCES[1]]
            elif scenario == "normal":
                self._blocked_ips.clear()
            logger.info("Simulator switched to scenario: %s", scenario)

    def set_speed(self, speed: float) -> None:
        """Change simulation speed multiplier on the fly."""
        self._speed = max(0.1, min(speed, 10.0))
        logger.info("Simulator speed set to %.1fx", self._speed)

    def mark_ip_blocked(self, ip: str) -> None:
        """Mark an IP as blocked by the defense barrier."""
        self._blocked_ips.add(ip)

    def unmark_ip_blocked(self, ip: str) -> None:
        """Unmark an IP when unblocked."""
        self._blocked_ips.discard(ip)

    # ── Status & Metrics ──────────────────────────────────────────────────────

    @property
    def status(self) -> dict:
        """Comprehensive, real-time metrics payload calculated strictly from events."""
        top_srcs = [
            {"ip": ip, "count": count, "blocked": ip in self._blocked_ips}
            for ip, count in sorted(self._source_counts.items(), key=lambda x: x[1], reverse=True)[:6]
        ]
        return {
            "active":                self._active and not self._paused,
            "paused":                self._paused,
            "running":               self._active,
            "speed":                 self._speed,
            "scenario":              self._scenario,
            "packets_generated":     self._packets_generated,
            "packets_processed":     self._packets_processed,
            "normal_packets":        self._normal_packets,
            "suspicious_packets":    self._suspicious_packets,
            "threats_detected":      self._threats_detected,
            "packets_blocked":       self._packets_blocked,
            "current_rate":          round(self._current_rate, 1),
            "start_time":            self._start_time.isoformat() if self._start_time else None,
            "protocol_distribution": dict(self._protocol_counts),
            "top_sources":           top_srcs,
            "blocked_ips":           list(self._blocked_ips),
            "recent_threats":        list(self._recent_threats),
        }

    # ── Packet Emission Pipeline ──────────────────────────────────────────────

    async def _emit_packet(
        self,
        meta: dict,
        is_threat: bool = False,
        threat_info: Optional[dict] = None,
        is_suspicious: bool = False,
    ) -> dict:
        """
        Process a single packet through the pipeline, update counters,
        append to rolling buffer, and broadcast to WebSocket clients.
        """
        src_ip = meta["src_ip"]
        dst_ip = meta["dst_ip"]
        src_port = meta["src_port"]
        dst_port = meta["dst_port"]
        protocol = meta["protocol"]
        flags = meta.get("flags", "")
        pkt_len = meta.get("length", 64)

        now = datetime.now()
        now_iso = now.strftime("%H:%M:%S.%f")[:-3]

        self._packets_generated += 1
        self._packets_processed += 1
        self._protocol_counts[protocol] += 1
        self._source_counts[src_ip] += 1
        self._seen_ips_since_stat.add(src_ip)
        self._packets_since_stat += 1

        # Check if source is blocked by defense barrier
        is_blocked = src_ip in self._blocked_ips

        if is_blocked:
            status = "blocked"
            self._packets_blocked += 1
            pipeline_stage = "response"
        elif is_threat:
            status = "threat"
            self._threats_detected += 1
            self._threats_since_stat += 1
            pipeline_stage = "alert"
            self._blocked_ips.add(src_ip)
        elif is_suspicious:
            status = "suspicious"
            self._suspicious_packets += 1
            self._suspicious_since_stat += 1
            pipeline_stage = "detection"
        else:
            status = "normal"
            self._normal_packets += 1
            pipeline_stage = "metadata"

        # Construct Wireshark-compatible dissection object
        pkt_no = self._packets_generated
        info_str = meta.get(
            "info",
            f"{src_port} → {dst_port} [{flags}] Len={pkt_len}"
        )

        packet_obj = {
            "id":             f"sim_{pkt_no}",
            "no":             pkt_no,
            "time":           now_iso,
            "timestamp":      now_iso,
            "source":         f"{src_ip}:{src_port}",
            "destination":    f"{dst_ip}:{dst_port}",
            "src_ip":         src_ip,
            "dst_ip":         dst_ip,
            "src_port":       src_port,
            "dst_port":       dst_port,
            "protocol":       protocol,
            "flags":          flags,
            "length":         pkt_len,
            "info":           info_str,
            "status":         status,
            "is_threat":      is_threat,
            "threat_info":    threat_info,
            "blocked":        is_blocked,
            "event_source":   "simulation",
            "pipeline_stage": pipeline_stage,
            "layers": {
                "frame": {
                    "title": f"Frame {pkt_no}: {pkt_len} bytes on wire (Simulated SOC Node)",
                    "fields": {
                        "Frame Number": pkt_no,
                        "Interface":    "SIMULATION_ADAPTER",
                        "Arrival Time": now_iso,
                        "Frame Length": f"{pkt_len} bytes",
                    }
                },
                "ethernet": {
                    "title": f"Ethernet II, Src: 02:42:ac:11:00:02, Dst: 02:42:ac:11:00:01",
                    "fields": {
                        "Source MAC":      "02:42:ac:11:00:02",
                        "Destination MAC": "02:42:ac:11:00:01",
                        "Type":            "0x0800 (IPv4)",
                    }
                },
                "ip": {
                    "title": f"Internet Protocol Version 4, Src: {src_ip}, Dst: {dst_ip}",
                    "fields": {
                        "Version":        4,
                        "Source IP":      src_ip,
                        "Destination IP": dst_ip,
                        "Protocol":       f"{protocol} ({6 if protocol == 'TCP' else (17 if protocol == 'UDP' else 1)})",
                        "TTL":            64,
                    }
                },
                "transport": {
                    "title": f"{protocol}, Src Port: {src_port}, Dst Port: {dst_port}, Flags: [{flags}]",
                    "fields": {
                        "Source Port":      src_port,
                        "Destination Port": dst_port,
                        "Flags":            flags if flags else "[None]",
                        "Length":           pkt_len,
                    }
                },
                "threat": {
                    "title":  f"⚠ THREAT ALERT: {threat_info.get('threat_type')}",
                    "fields": threat_info
                } if threat_info else None
            },
            "hex_dump": format_hex_dump(
                bytes([random.randint(0, 255) for _ in range(min(pkt_len, 48))]),
                max_len=48
            )
        }

        # Store in rolling buffer so recent-packets API returns it
        self._capture._packet_buffer.append(packet_obj)
        self._capture._packets_captured = self._packets_generated

        # Broadcast via WebSocket
        if pc._packet_broadcast_callback:
            try:
                res = pc._packet_broadcast_callback({
                    "type":         "packet",
                    "packet":       packet_obj,
                    "event_source": "simulation",
                })
                if asyncio.iscoroutine(res):
                    await res
            except Exception as ex:
                logger.debug("Packet broadcast error: %s", ex)

        return packet_obj

    # ── Simulation Scenarios ──────────────────────────────────────────────────

    async def _simulate_normal_packet(self) -> None:
        """Scenario A: Continuous benign network traffic (HTTP, TLS, DNS, NTP, ICMP)."""
        src = random.choice(NORMAL_SOURCES)
        dst = random.choice(SERVER_IPS)
        proto_choice = random.random()

        if proto_choice < 0.60:
            protocol = "TCP"
            src_port = random.randint(30000, 65000)
            dst_port = random.choice([80, 443, 8080, 8443])
            flags = random.choice(["SA", "A", "PA", "FA"])
            info = f"{src_port} → {dst_port} [{'HTTPS' if dst_port in (443, 8443) else 'HTTP'}] Flags=[{flags}]"
            length = random.randint(64, 1460)
        elif proto_choice < 0.85:
            protocol = "DNS"
            src_port = random.randint(40000, 60000)
            dst_port = 53
            flags = ""
            domain = random.choice(["api.internal.corp", "gateway.soc", "database.cluster", "auth.service"])
            info = f"Standard query 0x{random.randint(1000, 9999):x} A {domain}"
            length = random.randint(48, 128)
        elif proto_choice < 0.95:
            protocol = "UDP"
            src_port = random.randint(30000, 60000)
            dst_port = random.choice([123, 161, 514, 5353])
            flags = ""
            info = f"{src_port} → {dst_port} Len={random.randint(32, 256)}"
            length = random.randint(42, 256)
        else:
            protocol = "ICMP"
            src_port = 0
            dst_port = 0
            flags = ""
            info = f"Echo (ping) request id=0x{random.randint(100, 999):x} seq={random.randint(1, 50)}"
            length = 64

        meta = {
            "src_ip":   src,
            "dst_ip":   dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "flags":    flags,
            "length":   length,
            "info":     info,
        }
        self._detector.inspect_packet(meta)
        await self._emit_packet(meta, is_threat=False, is_suspicious=False)

    async def _simulate_syn_flood_burst(self, burst_size: int = 25) -> None:
        """Scenario B: Burst-send SYN-only packets from an attacker IP."""
        attacker = ATTACKER_SOURCES[0]  # 10.0.0.99
        target = SERVER_IPS[0]          # 192.168.1.1
        target_port = 80

        for _ in range(burst_size):
            if self._paused:
                break
            src_port = random.randint(1024, 65535)
            meta = {
                "src_ip":   attacker,
                "dst_ip":   target,
                "src_port": src_port,
                "dst_port": target_port,
                "protocol": "TCP",
                "flags":    "S",
                "length":   60,
                "info":     f"{src_port} → {target_port} [SYN] Seq={random.randint(1000, 99999)} Win=64240 Len=0",
            }
            detection = self._detector.inspect_packet(meta)

            if detection:
                self._recent_threats.append(detection)
                await process_detection(detection, "simulation")
                await self._emit_packet(meta, is_threat=True, threat_info=detection, is_suspicious=True)
                logger.info("SYN Flood alert triggered: %s [%s]", attacker, detection["severity"])
            else:
                await self._emit_packet(meta, is_threat=False, is_suspicious=True)

            await asyncio.sleep(0.12 / self._speed)

    async def _simulate_port_scan_sequence(self, num_ports: int = 30) -> None:
        """Scenario C: Contact many distinct ports from an attacker IP."""
        attacker = ATTACKER_SOURCES[2]  # 198.51.100.77
        target = SERVER_IPS[0]          # 192.168.1.1
        ports = random.sample(range(1, 65535), num_ports)

        for port in ports:
            if self._paused:
                break
            src_port = random.randint(40000, 65535)
            meta = {
                "src_ip":   attacker,
                "dst_ip":   target,
                "src_port": src_port,
                "dst_port": port,
                "protocol": "TCP",
                "flags":    "S",
                "length":   60,
                "info":     f"{src_port} → {port} [SYN] Port Sweep",
            }
            detection = self._detector.inspect_packet(meta)

            if detection:
                self._recent_threats.append(detection)
                await process_detection(detection, "simulation")
                await self._emit_packet(meta, is_threat=True, threat_info=detection, is_suspicious=True)
                logger.info("Port Scan alert triggered: %s [%s]", attacker, detection["severity"])
            else:
                await self._emit_packet(meta, is_threat=False, is_suspicious=True)

            await asyncio.sleep(0.14 / self._speed)

    async def _simulate_suspicious_flags_probe(self) -> None:
        """Scenario D: Controlled stealth probes with NULL, FIN, or XMAS flags."""
        attacker = ATTACKER_SOURCES[1]  # 172.16.5.200
        target = SERVER_IPS[0]          # 192.168.1.1
        target_port = random.choice([22, 80, 443, 3389])
        probe_type = random.choice(["NULL", "FIN", "XMAS"])

        if probe_type == "NULL":
            flags = ""
            desc = "NULL Scan (no flags)"
        elif probe_type == "FIN":
            flags = "F"
            desc = "FIN Scan [FIN]"
        else:
            flags = "FPU"
            desc = "XMAS Scan [FIN, PSH, URG]"

        meta = {
            "src_ip":   attacker,
            "dst_ip":   target,
            "src_port": random.randint(30000, 60000),
            "dst_port": target_port,
            "protocol": "TCP",
            "flags":    flags,
            "length":   54,
            "info":     f"Stealth Probe: {desc} → port {target_port}",
        }
        detection = self._detector.inspect_packet(meta)

        if detection:
            self._recent_threats.append(detection)
            await process_detection(detection, "simulation")
            await self._emit_packet(meta, is_threat=True, threat_info=detection, is_suspicious=True)
            logger.info("Stealth TCP scan alert triggered: %s [%s]", attacker, detection["severity"])
        else:
            await self._emit_packet(meta, is_threat=False, is_suspicious=True)

    # ── Main Simulation Loop ──────────────────────────────────────────────────

    async def _loop(self) -> None:
        """Main simulation execution loop with precise rate tracking."""
        stat_interval = 4.0
        stat_timer = time.monotonic()
        rate_timer = time.monotonic()
        rate_count = 0

        try:
            while self._active:
                if self._paused:
                    await asyncio.sleep(0.1)
                    continue

                now_t = time.monotonic()
                if now_t - rate_timer >= 1.0:
                    dt = now_t - rate_timer
                    self._current_rate = (self._packets_generated - rate_count) / dt
                    rate_count = self._packets_generated
                    rate_timer = now_t

                    if pc._packet_broadcast_callback:
                        try:
                            res = pc._packet_broadcast_callback({
                                "type":  "sim_stats",
                                "stats": self.status,
                            })
                            if asyncio.iscoroutine(res):
                                await res
                        except Exception:
                            pass

                # Scenario execution logic with clear educational pacing
                if self._scenario == "normal":
                    if self._paused or not self._active:
                        continue
                    await self._simulate_normal_packet()
                    await asyncio.sleep(0.35 / self._speed)

                elif self._scenario == "syn_flood":
                    await self._simulate_normal_packet()
                    await asyncio.sleep(0.20 / self._speed)
                    await self._simulate_syn_flood_burst(burst_size=24)
                    # Hold observation window so deflection at defense barrier is clearly observed
                    await asyncio.sleep(3.5 / self._speed)

                elif self._scenario == "port_scan":
                    await self._simulate_normal_packet()
                    await asyncio.sleep(0.20 / self._speed)
                    await self._simulate_port_scan_sequence(num_ports=20)
                    # Observation window for explainable threat inspection
                    await asyncio.sleep(3.5 / self._speed)

                elif self._scenario == "suspicious_flags":
                    await self._simulate_normal_packet()
                    await asyncio.sleep(0.20 / self._speed)
                    await self._simulate_suspicious_flags_probe()
                    await asyncio.sleep(2.5 / self._speed)

                else:
                    # Mixed continuous scenario
                    roll = random.random()
                    if roll < 0.15:
                        await self._simulate_syn_flood_burst(burst_size=22)
                        await asyncio.sleep(2.0 / self._speed)
                    elif roll < 0.28:
                        await self._simulate_port_scan_sequence(num_ports=20)
                        await asyncio.sleep(2.0 / self._speed)
                    elif roll < 0.38:
                        await self._simulate_suspicious_flags_probe()
                        await asyncio.sleep(1.5 / self._speed)
                    else:
                        await self._simulate_normal_packet()
                        await asyncio.sleep(0.25 / self._speed)

                # Periodic database stats snapshot
                if time.monotonic() - stat_timer >= stat_interval:
                    if self._packets_since_stat > 0:
                        await record_traffic_stat(
                            packets=self._packets_since_stat,
                            suspicious=self._suspicious_since_stat,
                            threats=self._threats_since_stat,
                            unique_sources=len(self._seen_ips_since_stat),
                            event_source="simulation",
                        )
                        self._packets_since_stat = 0
                        self._suspicious_since_stat = 0
                        self._threats_since_stat = 0
                        self._seen_ips_since_stat.clear()
                    stat_timer = time.monotonic()

                base_sleep = 0.08 / max(0.1, self._speed)
                await asyncio.sleep(base_sleep)

        except asyncio.CancelledError:
            logger.debug("Simulator loop cancelled gracefully")
        except Exception as exc:
            logger.exception("Simulator loop encountered error: %s", exc)
        finally:
            self._active = False
            self._current_rate = 0.0


# ── Singleton Instance ────────────────────────────────────────────────────────
_simulator: Optional[TrafficSimulator] = None


def get_simulator() -> TrafficSimulator:
    global _simulator
    if _simulator is None:
        _simulator = TrafficSimulator()
    return _simulator
