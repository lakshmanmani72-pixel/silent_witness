"""
SILENT WITNESS – Threat Detection Engine
=========================================
Implements:
  • SYN Flood detection  (configurable rolling window + thresholds)
  • Port Scan detection  (distinct-port counting in rolling window)
  • Central severity classification

All thresholds are read from the live application settings so they can be
updated at runtime via the Settings page without restarting the backend.

IMPORTANT SAFETY NOTES
-----------------------
• This module only inspects packet *metadata* passed to it – it never
  initiates connections, sends packets, or interacts with remote hosts.
• Payload data is never stored.
• Detection heuristics are designed for educational demonstration.
  False-positive and false-negative rates have NOT been validated for
  production deployment.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("silent_witness.detector")


# ── Rolling-window counter ────────────────────────────────────────────────────

class RollingCounter:
    """
    Tracks timestamped events within a rolling time window.
    Uses a deque for O(1) append and O(k) expiry where k is the number
    of events that have expired – amortised O(1) in practice.
    """

    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self._events: collections.deque[float] = collections.deque()

    def add(self) -> None:
        self._events.append(time.monotonic())

    def _expire(self) -> None:
        cutoff = time.monotonic() - self.window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()

    def count(self) -> int:
        self._expire()
        return len(self._events)

    def update_window(self, seconds: float) -> None:
        self.window = seconds


class RollingSet:
    """
    Tracks distinct values (e.g. destination ports) within a rolling window.
    Stores (timestamp, value) tuples.
    """

    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self._events: collections.deque[tuple[float, object]] = collections.deque()

    def add(self, value: object) -> None:
        self._events.append((time.monotonic(), value))

    def _expire(self) -> set:
        cutoff = time.monotonic() - self.window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        return {v for _, v in self._events}

    def distinct_count(self) -> int:
        return len(self._expire())

    def update_window(self, seconds: float) -> None:
        self.window = seconds


# ── Severity classification ───────────────────────────────────────────────────

def classify_severity(
    threat_type: str,
    count: int,
    *,
    syn_critical: int = 100,
    syn_high: int = 50,
    port_high: int = 100,
) -> str:
    """
    Central severity classification function.

    Parameters
    ----------
    threat_type : "SYN_FLOOD" | "PORT_SCAN" | "SUSPICIOUS"
    count       : detection count (SYN packets or distinct ports)
    syn_critical: threshold for CRITICAL SYN flood
    syn_high    : threshold for HIGH SYN flood
    port_high   : threshold for HIGH port scan

    Returns
    -------
    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    """
    if threat_type == "SYN_FLOOD":
        if count > syn_critical:
            return "CRITICAL"
        if count > syn_high:
            return "HIGH"
        return "MEDIUM"
    if threat_type == "PORT_SCAN":
        if count > port_high:
            return "HIGH"
        return "MEDIUM"
    if threat_type == "SUSPICIOUS":
        return "MEDIUM"
    return "INFO"


# ── Per-IP state ──────────────────────────────────────────────────────────────

class IPState:
    """Holds all rolling-window counters for a single observed source IP."""

    def __init__(self, syn_window: float, port_window: float):
        self.syn_counter  = RollingCounter(syn_window)
        self.port_tracker = RollingSet(port_window)
        self.last_alert_time: dict[str, float] = {}  # threat_type → monotonic

    def seconds_since_last_alert(self, threat_type: str) -> float:
        t = self.last_alert_time.get(threat_type)
        if t is None:
            return float("inf")
        return time.monotonic() - t

    def record_alert(self, threat_type: str) -> None:
        self.last_alert_time[threat_type] = time.monotonic()


# ── Main detector ─────────────────────────────────────────────────────────────

class ThreatDetector:
    """
    Stateful, in-process threat detector.

    Call ``inspect_packet(meta)`` for every captured packet.
    The detector returns a detection result dict when a threshold is crossed
    and the cooldown has elapsed, or None if no alert should be raised.

    Thread-safety: this class is NOT thread-safe.  Call it from a single
    asyncio task.  All heavy work is synchronous CPU work; no I/O is done.
    """

    def __init__(self):
        # per-IP state keyed by source IP string
        self._ip_state: dict[str, IPState] = {}
        # live threshold cache – refreshed periodically
        self._syn_critical     = 100
        self._syn_high         = 50
        self._syn_window       = 10.0
        self._port_high        = 100
        self._port_window      = 60.0
        self._cooldown         = 30.0
        # housekeeping
        self._last_cleanup     = time.monotonic()
        self._cleanup_interval = 300.0  # clean stale IPs every 5 min

    def update_thresholds(
        self,
        *,
        syn_critical: int = 100,
        syn_high: int = 50,
        syn_window: float = 10.0,
        port_high: int = 100,
        port_window: float = 60.0,
        cooldown: float = 30.0,
    ) -> None:
        self._syn_critical = syn_critical
        self._syn_high     = syn_high
        self._syn_window   = syn_window
        self._port_high    = port_high
        self._port_window  = port_window
        self._cooldown     = cooldown
        # propagate window changes to existing state objects
        for state in self._ip_state.values():
            state.syn_counter.update_window(syn_window)
            state.port_tracker.update_window(port_window)

    def _get_state(self, ip: str) -> IPState:
        if ip not in self._ip_state:
            self._ip_state[ip] = IPState(self._syn_window, self._port_window)
        return self._ip_state[ip]

    def inspect_packet(self, meta: dict) -> Optional[dict]:
        """
        Inspect one packet's metadata and return a detection result or None.

        ``meta`` must contain at minimum:
            src_ip    : str
            dst_ip    : str  (optional)
            src_port  : int  (optional)
            dst_port  : int  (optional)
            protocol  : str  ("TCP" | "UDP" | ...)
            flags     : str  (TCP flags string e.g. "S", "SA" – optional)
        """
        src_ip   = meta.get("src_ip", "")
        protocol = meta.get("protocol", "")
        flags    = meta.get("flags", "")
        dst_port = meta.get("dst_port")

        if not src_ip:
            return None

        self._maybe_cleanup()
        state = self._get_state(src_ip)

        # ── SYN Flood check ───────────────────────────────────────────────────
        # A SYN-only packet has the SYN flag set WITHOUT ACK.
        is_syn_only = (protocol == "TCP" and "S" in flags and "A" not in flags)
        if is_syn_only:
            state.syn_counter.add()
            syn_count = state.syn_counter.count()
            severity = classify_severity(
                "SYN_FLOOD", syn_count,
                syn_critical=self._syn_critical,
                syn_high=self._syn_high,
            )
            if severity in ("CRITICAL", "HIGH"):
                if state.seconds_since_last_alert("SYN_FLOOD") >= self._cooldown:
                    state.record_alert("SYN_FLOOD")
                    return {
                        "threat_type":      "SYN_FLOOD",
                        "src_ip":           src_ip,
                        "dst_ip":           meta.get("dst_ip"),
                        "src_port":         meta.get("src_port"),
                        "dst_port":         dst_port,
                        "protocol":         protocol,
                        "count":            syn_count,
                        "severity":         severity,
                        "detection_reason": (
                            f"Detected {syn_count} SYN-only packets from {src_ip} "
                            f"within {self._syn_window}s window "
                            f"(threshold: CRITICAL>{self._syn_critical}, HIGH>{self._syn_high})"
                        ),
                    }

        # ── Port Scan check ───────────────────────────────────────────────────
        if dst_port and protocol in ("TCP", "UDP"):
            state.port_tracker.add(dst_port)
            port_count = state.port_tracker.distinct_count()
            if port_count > self._port_high:
                if state.seconds_since_last_alert("PORT_SCAN") >= self._cooldown:
                    state.record_alert("PORT_SCAN")
                    severity = classify_severity(
                        "PORT_SCAN", port_count,
                        port_high=self._port_high,
                    )
                    return {
                        "threat_type":      "PORT_SCAN",
                        "src_ip":           src_ip,
                        "dst_ip":           meta.get("dst_ip"),
                        "src_port":         meta.get("src_port"),
                        "dst_port":         dst_port,
                        "protocol":         protocol,
                        "count":            port_count,
                        "severity":         severity,
                        "detection_reason": (
                            f"Source IP {src_ip} contacted {port_count} distinct destination "
                            f"ports within {self._port_window}s "
                            f"(threshold: >{self._port_high} ports)"
                        ),
                    }

        # ── Suspicious Reconnaissance / Port Check ────────────────────────────
        # Section 7.C: Allow the detector to log other suspicious events as MEDIUM severity
        if protocol == "TCP":
            # Check for stealth scans (NULL scan: no flags, FIN scan: F only, XMAS: F+P+U)
            # Legitimate TCP teardown contains ACK ('A'). Stealth scans intentionally omit ACK.
            has_no_ack = "A" not in flags
            is_stealth_scan = has_no_ack and (
                flags == "" or
                flags == "F" or
                ("F" in flags and "P" in flags)
            )
            if is_stealth_scan and state.seconds_since_last_alert("SUSPICIOUS_SCAN") >= self._cooldown:
                state.record_alert("SUSPICIOUS_SCAN")
                scan_type = "NULL Scan" if flags == "" else ("FIN Scan" if flags == "F" else "XMAS Scan")
                return {
                    "threat_type":      "SUSPICIOUS",
                    "src_ip":           src_ip,
                    "dst_ip":           meta.get("dst_ip"),
                    "src_port":         meta.get("src_port"),
                    "dst_port":         dst_port,
                    "protocol":         "TCP",
                    "count":            1,
                    "severity":         "MEDIUM",
                    "detection_reason": f"TCP {scan_type} probe detected (flags: '{flags}') indicating reconnaissance scan.",
                }

            # Check for unauthorized probes to sensitive administrative ports (Telnet 23, SMB 445, RDP 3389)
            if dst_port in (23, 135, 139, 445, 3389):
                alert_key = f"SUSP_PORT_{dst_port}"
                if state.seconds_since_last_alert(alert_key) >= self._cooldown:
                    state.record_alert(alert_key)
                    return {
                        "threat_type":      "SUSPICIOUS",
                        "src_ip":           src_ip,
                        "dst_ip":           meta.get("dst_ip"),
                        "src_port":         meta.get("src_port"),
                        "dst_port":         dst_port,
                        "protocol":         "TCP",
                        "count":            1,
                        "severity":         "MEDIUM",
                        "detection_reason": f"Inbound probe to sensitive administrative port {dst_port} detected.",
                    }

        return None

    def _maybe_cleanup(self) -> None:
        """Remove stale IP state entries to prevent unbounded memory growth."""
        now = time.monotonic()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        stale = [
            ip for ip, st in self._ip_state.items()
            if st.syn_counter.count() == 0 and st.port_tracker.distinct_count() == 0
        ]
        for ip in stale:
            del self._ip_state[ip]
        if stale:
            logger.debug("Cleaned up %d stale IP state entries", len(stale))

    def reset(self) -> None:
        """Clear all in-memory state (used when resetting simulation)."""
        self._ip_state.clear()
        logger.info("ThreatDetector state reset")


# ── Singleton ─────────────────────────────────────────────────────────────────
_detector: Optional[ThreatDetector] = None


def get_detector() -> ThreatDetector:
    global _detector
    if _detector is None:
        _detector = ThreatDetector()
    return _detector
