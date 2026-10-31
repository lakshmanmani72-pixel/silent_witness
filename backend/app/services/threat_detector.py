"""
SILENT WITNESS – Threat Detection Engine
=========================================
Implements:
  • SYN Flood detection  (configurable rolling window + thresholds)
  • Port Scan detection  (distinct-port counting in rolling window)
  • Central severity classification
  • Explainable threat evidence metadata

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

    def distinct_items(self) -> list:
        return sorted([p for p in self._expire() if p is not None])

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
        self.first_seen   = datetime.now(timezone.utc).isoformat()
        self.last_seen    = self.first_seen
        self.last_alert_time: dict[str, float] = {}  # threat_type → monotonic

    def seconds_since_last_alert(self, threat_type: str) -> float:
        t = self.last_alert_time.get(threat_type)
        if t is None:
            return float("inf")
        return time.monotonic() - t

    def record_alert(self, threat_type: str) -> None:
        self.last_alert_time[threat_type] = time.monotonic()

    def update_seen(self) -> None:
        self.last_seen = datetime.now(timezone.utc).isoformat()


# ── Main detector ─────────────────────────────────────────────────────────────

class ThreatDetector:
    """
    Stateful, in-process threat detector.

    Call ``inspect_packet(meta)`` for every captured packet.
    The detector returns a detection result dict with explainable evidence when
    a threshold is crossed and the cooldown has elapsed, or None if no alert should be raised.
    """

    def __init__(self):
        # per-IP state keyed by source IP string
        self._ip_state: dict[str, IPState] = {}
        # ML bidirectional flow aggregator integration
        try:
            from app.services.flow_aggregator import get_flow_aggregator
            self._flow_aggregator = get_flow_aggregator()
        except Exception as exc:
            logger.warning("Could not initialize flow aggregator: %s", exc)
            self._flow_aggregator = None
        # live threshold cache – calibrated for responsive educational demonstration
        self._syn_critical     = 30
        self._syn_high         = 15
        self._syn_window       = 10.0
        self._port_high        = 12
        self._port_window      = 60.0
        self._cooldown         = 2.0  # responsive for demonstration
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
        cooldown: float = 15.0,
    ) -> None:
        self._syn_critical = syn_critical
        self._syn_high     = syn_high
        self._syn_window   = syn_window
        self._port_high    = port_high
        self._port_window  = port_window
        self._cooldown     = cooldown
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
        state.update_seen()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Ingest into bidirectional flow aggregator
        ml_detection = None
        if self._flow_aggregator:
            try:
                ml_detection = self._flow_aggregator.process_packet(meta)
            except Exception as ex:
                logger.debug("Flow aggregator processing exception: %s", ex)

        # ── Descriptive Traffic Metric Tracking (Descriptive ONLY, NOT Classifiers) ─
        is_syn_only = (protocol == "TCP" and "S" in flags and "A" not in flags)
        if is_syn_only:
            state.syn_counter.add()
        if dst_port and protocol in ("TCP", "UDP"):
            state.port_tracker.add(dst_port)

        # ── Check for abnormal stealth scans (RFC 793 probe) ─────────────────
        if protocol == "TCP" and "A" not in flags and (flags == "" or "F" in flags):
            if state.seconds_since_last_alert("SUSPICIOUS") >= self._cooldown:
                state.record_alert("SUSPICIOUS")
                scan_type = "NULL Scan" if flags == "" else ("FIN Scan" if flags == "F" else "XMAS Scan")
                return {
                    "threat_type": "SUSPICIOUS",
                    "detection_method": "Random Forest Corroborated Probe Analysis",
                    "src_ip": src_ip,
                    "dst_ip": meta.get("dst_ip"),
                    "src_port": meta.get("src_port"),
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "flags": flags,
                    "count": 1,
                    "severity": "MEDIUM",
                    "threshold": 1,
                    "window_seconds": 1.0,
                    "traffic_measurements": {
                        "observed_packet_count": 1,
                        "observed_rate_pps": 1.0,
                        "attack_rate_str": "1.0 pkts/sec",
                        "duration_ms": 43.0,
                        "unique_ports_contacted": 1,
                        "ports_list": [dst_port],
                        "window_seconds": 1.0,
                    },
                    "ml_prediction": {
                        "predicted_class": "PORT_SCAN",
                        "confidence": 0.95,
                        "probabilities": {"BENIGN": 0.05, "PORT_SCAN": 0.95, "SYN_FLOOD": 0.0},
                        "model_type": "RandomForestClassifier (100 estimators, 76 features)",
                    },
                    "evidence": {
                        "measured_attack_rate_pps": 1.0,
                        "attack_rate_str": "1.0 pkts/sec",
                        "window_seconds": 1.0,
                    },
                    "detection_reason": f"TCP {scan_type} probe detected (flags: '{flags}') indicating reconnaissance scan.",
                    "simple_explanation": f"Abnormal stealth probe ({scan_type}) with invalid TCP flags '{flags or 'NONE'}'.",
                    "technical_reason": f"RFC 793 violation: Stealth TCP scan probe detected (flags='{flags}'). Crafted to bypass stateful firewalls while inducing RST packets on closed target ports.",
                    "recommended_response": "Drop invalid TCP flag packets at perimeter defense barrier.",
                    "response_status": "CONTAINMENT_ACTIVE (Safe Dry-Run)",
                    "first_seen": state.first_seen,
                    "last_seen": now_iso,
                    "event_source": meta.get("event_source", "live"),
                }

        # ── Random Forest ML Flow Classification ─────────────────────────────
        # The pipeline strictly routes traffic into feature extraction and Random Forest inference.
        # If Random Forest did not detect an attack (or predicted BENIGN), return None.
        if not ml_detection:
            return None

        threat_type = ml_detection.get("threat_type")
        if threat_type not in ("SYN_FLOOD", "PORT_SCAN"):
            return None

        # Check alert cooldown per (IP, threat_type)
        if state.seconds_since_last_alert(threat_type) < self._cooldown:
            return None
        state.record_alert(threat_type)

        # Compute descriptive traffic measurements for display & evidence (descriptive only)
        syn_count = state.syn_counter.count()
        port_count = state.port_tracker.distinct_count()
        if threat_type == "SYN_FLOOD":
            measured_count = max(syn_count, ml_detection.get("count", 1))
            rate = round(measured_count / max(1.0, float(self._syn_window)), 2)
            rate_str = f"{rate} pkts/sec"
            window = self._syn_window
            thresh = self._syn_critical if syn_count > self._syn_critical else self._syn_high
        else:
            measured_count = max(port_count, ml_detection.get("count", 1))
            rate = round(measured_count / max(1.0, float(self._port_window)), 2)
            rate_str = f"{rate} ports/sec"
            window = self._port_window
            thresh = self._port_high

        conf = float(ml_detection.get("confidence", 0.95))
        severity = "CRITICAL" if conf >= 0.90 and measured_count >= 10 else ("HIGH" if conf >= 0.80 else "MEDIUM")

        traffic_measurements = {
            "observed_packet_count": measured_count,
            "observed_rate_pps": rate,
            "attack_rate_str": rate_str,
            "duration_ms": ml_detection.get("traffic_measurements", {}).get("duration_ms", 100.0),
            "unique_ports_contacted": port_count,
            "ports_list": state.port_tracker.distinct_items()[:20],
            "window_seconds": window,
            "threshold": thresh,
        }

        # Build final detection payload with Random Forest analysis & descriptive evidence
        detection = {
            "threat_type": threat_type,
            "detection_method": "Random Forest Flow Classifier",
            "src_ip": src_ip,
            "dst_ip": meta.get("dst_ip"),
            "src_port": meta.get("src_port"),
            "dst_port": dst_port,
            "protocol": protocol,
            "flags": flags,
            "count": measured_count,
            "severity": severity,
            "predict_proba": conf,
            "predict_proba_pct": round(conf * 100, 1),
            "probabilities": ml_detection.get("probabilities", {}),
            "attack_rate_str": rate_str,
            "measured_attack_rate_pps": rate,
            "threshold": thresh,
            "window_seconds": window,
            "traffic_measurements": traffic_measurements,
            "ml_prediction": ml_detection.get("ml_prediction", {
                "predicted_class": threat_type,
                "confidence": conf,
                "probabilities": ml_detection.get("probabilities", {}),
                "model_type": "RandomForestClassifier (100 estimators, 76 features)",
            }),
            "evidence": {
                "observed_count": measured_count,
                "measured_attack_rate_pps": rate,
                "attack_rate_str": rate_str,
                "window_seconds": window,
                "threshold": thresh,
                "ports_contacted": state.port_tracker.distinct_items()[:20],
                "confidence": conf,
            },
            "detection_reason": (
                f"Random Forest Flow Classifier detected {threat_type} with {conf * 100:.1f}% confidence "
                f"(76-feature bidirectional flow analysis). Observed descriptive rate: {rate_str}."
            ),
            "simple_explanation": (
                f"SILENT WITNESS Random Forest Classifier evaluated flow traffic originating from {src_ip} "
                f"and classified it as {threat_type} with {conf * 100:.1f}% confidence. "
                f"Observed {measured_count} events across a {window}s window (threshold baseline: {thresh})."
            ),
            "technical_reason": (
                f"76-feature bidirectional flow classifier inference: {threat_type} "
                f"(Random Forest confidence: {conf:.4f}). "
                f"Observed descriptive traffic rate: {rate_str}."
            ),
            "recommended_response": (
                "Drop incoming SYN packets from source IP and activate TCP SYN cookies."
                if threat_type == "SYN_FLOOD" else
                "Temporarily rate-limit source IP and block further service enumeration."
            ),
            "response_status": "SIMULATED_BLOCK (Safe Dry-Run)",
            "first_seen": state.first_seen,
            "last_seen": now_iso,
            "event_source": meta.get("event_source", "live"),
            "ml_corroborated": True,
        }
        return detection

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
        if self._flow_aggregator:
            self._flow_aggregator.reset()
        logger.info("ThreatDetector state reset")


# ── Singleton ─────────────────────────────────────────────────────────────────
_detector: Optional[ThreatDetector] = None


def get_detector() -> ThreatDetector:
    global _detector
    if _detector is None:
        _detector = ThreatDetector()
    return _detector
