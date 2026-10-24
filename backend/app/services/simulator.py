"""
SILENT WITNESS – Traffic Simulator
=====================================
Generates clearly labelled SYNTHETIC demonstration events.

IMPORTANT
---------
• All generated events are tagged event_source='simulation'.
• No real packets are sent; no real hosts are contacted.
• The simulator only creates records in the local SQLite database.
• The dashboard clearly displays DEMO MODE — SYNTHETIC DATA.

The simulator generates a realistic mix of:
  • Normal background traffic (to populate traffic stats)
  • SYN flood bursts (triggers CRITICAL / HIGH detections)
  • Port scan sequences (triggers HIGH detections)
  • Repeated suspicious activity from known IPs

Speed multiplier allows faster/slower demonstrations.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from datetime import datetime, timezone
from typing import Optional

from app.services.threat_detector import ThreatDetector, get_detector
from app.services.event_processor import process_detection, record_traffic_stat

logger = logging.getLogger("silent_witness.simulator")

# ── Simulated IP pools ────────────────────────────────────────────────────────
NORMAL_SOURCES = [f"192.168.1.{i}" for i in range(10, 50)]
ATTACKER_SOURCES = [
    "10.0.0.99",
    "172.16.5.200",
    "45.33.32.156",
    "198.51.100.77",
    "203.0.113.45",
]
SERVER_IPS = [
    "192.168.1.1",
    "192.168.1.254",
    "10.0.0.1",
]
COMMON_PORTS = [80, 443, 22, 21, 3306, 5432, 6379, 8080, 8443, 53]


class TrafficSimulator:
    """
    Async simulation loop that feeds synthetic packet metadata to the
    ThreatDetector and records results.
    """

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._active = False
        self._paused = False
        self._speed  = 1.0
        self._events_generated = 0
        self._start_time: Optional[datetime] = None
        self._detector = get_detector()
        # local traffic counters between stat snapshots
        self._packets_since_last = 0
        self._suspicious_since_last = 0
        self._threats_since_last = 0
        self._seen_ips: set[str] = set()

    # ── Control ───────────────────────────────────────────────────────────────

    async def start(self, speed: float = 1.0) -> None:
        if self._active:
            logger.info("Simulator already running")
            return
        self._speed  = max(0.1, min(speed, 10.0))
        self._active = True
        self._paused = False
        self._start_time = datetime.now(timezone.utc)
        self._task = asyncio.create_task(self._loop(), name="simulator_loop")
        logger.info("Simulator started (speed=%.1f×)", self._speed)

    async def pause(self) -> None:
        self._paused = True
        logger.info("Simulator paused")

    async def resume(self) -> None:
        self._paused = False
        logger.info("Simulator resumed")

    async def stop(self) -> None:
        self._active = False
        self._paused = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Simulator stopped. Events generated: %d", self._events_generated)

    async def reset(self) -> None:
        await self.stop()
        self._events_generated = 0
        self._start_time = None
        self._packets_since_last = 0
        self._suspicious_since_last = 0
        self._threats_since_last = 0
        self._seen_ips = set()
        self._detector.reset()
        logger.info("Simulator reset")

    def set_speed(self, speed: float) -> None:
        self._speed = max(0.1, min(speed, 10.0))

    @property
    def status(self) -> dict:
        return {
            "active":           self._active and not self._paused,
            "paused":           self._paused,
            "running":          self._active,
            "speed":            self._speed,
            "events_generated": self._events_generated,
            "start_time":       self._start_time.isoformat() if self._start_time else None,
        }

    # ── Internal loop ──────────────────────────────────────────────────────────

    async def _loop(self) -> None:
        """Main simulation loop."""
        stat_interval = 5   # record traffic stats every N seconds
        stat_timer    = time.monotonic()
        cycle         = 0

        try:
            while self._active:
                if self._paused:
                    await asyncio.sleep(0.5)
                    continue

                cycle += 1
                base_sleep = 1.0 / self._speed

                # ── Decide what to simulate this tick ─────────────────────────
                roll = random.random()

                if roll < 0.10:
                    # SYN flood burst (~10% of ticks)
                    await self._simulate_syn_flood()
                elif roll < 0.18:
                    # Port scan (~8% of ticks)
                    await self._simulate_port_scan()
                elif roll < 0.25:
                    # Repeated suspicious activity (~7% of ticks)
                    await self._simulate_suspicious()
                else:
                    # Normal traffic (~75% of ticks)
                    await self._simulate_normal_traffic()

                # Record periodic traffic stats
                if time.monotonic() - stat_timer >= stat_interval:
                    await record_traffic_stat(
                        packets=self._packets_since_last,
                        suspicious=self._suspicious_since_last,
                        threats=self._threats_since_last,
                        unique_sources=len(self._seen_ips),
                        event_source="simulation",
                    )
                    self._packets_since_last    = 0
                    self._suspicious_since_last = 0
                    self._threats_since_last    = 0
                    self._seen_ips              = set()
                    stat_timer = time.monotonic()

                await asyncio.sleep(base_sleep)

        except asyncio.CancelledError:
            logger.debug("Simulator loop cancelled")
        except Exception as exc:
            logger.exception("Simulator loop error: %s", exc)
        finally:
            self._active = False

    # ── Scenario generators ───────────────────────────────────────────────────

    async def _simulate_syn_flood(self) -> None:
        """Burst-send SYN-only packets from an attacker IP to exceed threshold."""
        attacker   = random.choice(ATTACKER_SOURCES)
        target     = random.choice(SERVER_IPS)
        burst_size = random.randint(80, 150)  # enough to trigger HIGH or CRITICAL

        for _ in range(burst_size):
            meta = {
                "src_ip":   attacker,
                "dst_ip":   target,
                "src_port": random.randint(1024, 65535),
                "dst_port": 80,
                "protocol": "TCP",
                "flags":    "S",   # SYN only (no ACK)
            }
            result = self._detector.inspect_packet(meta)
            self._packets_since_last    += 1
            self._suspicious_since_last += 1
            self._seen_ips.add(attacker)

            if result:
                self._threats_since_last += 1
                self._events_generated   += 1
                await process_detection(result, "simulation")
                logger.debug("SYN Flood detected: %s [%s]", attacker, result["severity"])
                # short pause between detected bursts
                await asyncio.sleep(0.02)

    async def _simulate_port_scan(self) -> None:
        """Contact many distinct ports from an attacker IP."""
        attacker   = random.choice(ATTACKER_SOURCES)
        target     = random.choice(SERVER_IPS)
        num_ports  = random.randint(90, 130)
        ports      = random.sample(range(1, 65536), num_ports)

        for port in ports:
            meta = {
                "src_ip":   attacker,
                "dst_ip":   target,
                "src_port": random.randint(40000, 65535),
                "dst_port": port,
                "protocol": random.choice(["TCP", "UDP"]),
                "flags":    "S",
            }
            result = self._detector.inspect_packet(meta)
            self._packets_since_last    += 1
            self._suspicious_since_last += 1
            self._seen_ips.add(attacker)

            if result:
                self._threats_since_last += 1
                self._events_generated   += 1
                await process_detection(result, "simulation")
                logger.debug("Port scan detected: %s [%s]", attacker, result["severity"])
                await asyncio.sleep(0.01)

    async def _simulate_suspicious(self) -> None:
        """Generate a single suspicious activity record directly."""
        attacker = random.choice(ATTACKER_SOURCES)
        reason   = random.choice([
            "Unusual protocol combination",
            "High-frequency connection attempts",
            "Known suspicious port access",
        ])
        detection = {
            "threat_type":      "SUSPICIOUS",
            "src_ip":           attacker,
            "dst_ip":           random.choice(SERVER_IPS),
            "src_port":         random.randint(1024, 65535),
            "dst_port":         random.choice([23, 135, 139, 445, 3389]),
            "protocol":         "TCP",
            "count":            random.randint(1, 10),
            "severity":         "MEDIUM",
            "detection_reason": reason,
        }
        self._events_generated   += 1
        self._threats_since_last += 1
        self._seen_ips.add(attacker)
        await process_detection(detection, "simulation")

    async def _simulate_normal_traffic(self) -> None:
        """Generate normal background traffic (no alerts generated)."""
        n = random.randint(5, 20)
        for _ in range(n):
            src = random.choice(NORMAL_SOURCES)
            self._packets_since_last += 1
            self._seen_ips.add(src)
            # Normal traffic: SYN+ACK (established) or just ACK – won't trigger SYN flood
            meta = {
                "src_ip":   src,
                "dst_ip":   random.choice(SERVER_IPS),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice(COMMON_PORTS),
                "protocol": "TCP",
                "flags":    "SA",  # SYN-ACK – not counted as SYN-only
            }
            self._detector.inspect_packet(meta)


# ── Singleton ─────────────────────────────────────────────────────────────────
_simulator: Optional[TrafficSimulator] = None


def get_simulator() -> TrafficSimulator:
    global _simulator
    if _simulator is None:
        _simulator = TrafficSimulator()
    return _simulator
