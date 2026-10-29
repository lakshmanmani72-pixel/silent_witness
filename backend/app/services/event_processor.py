"""
SILENT WITNESS – Event Processor
==================================
Receives raw detection results from the ThreatDetector, persists them to
SQLite, triggers the response engine, and broadcasts events via WebSocket.

All database writes use parameterised queries.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.database import get_db
from app.services.response_engine import get_response_engine

logger = logging.getLogger("silent_witness.event_processor")

# WebSocket broadcast callback – set by main.py
_ws_broadcast = None


def set_ws_broadcaster(fn) -> None:
    global _ws_broadcast
    _ws_broadcast = fn


async def process_detection(detection: dict, event_source: str = "simulation") -> int:
    """
    Persist a threat detection result and trigger automated response.

    Parameters
    ----------
    detection   : dict from ThreatDetector.inspect_packet()
    event_source: "simulation" | "live"

    Returns
    -------
    Newly inserted threat row ID.
    """
    now = datetime.now(timezone.utc).isoformat()

    async with await get_db() as db:
        # Insert threat record
        cursor = await db.execute(
            """
            INSERT INTO threats
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                 threat_type, count, severity, detection_reason, event_source,
                 response_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                detection.get("src_ip"),
                detection.get("dst_ip"),
                detection.get("src_port"),
                detection.get("dst_port"),
                detection.get("protocol"),
                detection["threat_type"],
                detection.get("count", 1),
                detection["severity"],
                detection.get("detection_reason"),
                event_source,
                "pending",
            ),
        )
        threat_id = cursor.lastrowid
        await db.commit()

    logger.info(
        "Threat #%d recorded: %s from %s [%s]",
        threat_id,
        detection["threat_type"],
        detection.get("src_ip"),
        detection["severity"],
    )

    # Trigger response engine for HIGH / CRITICAL events
    if detection["severity"] in ("CRITICAL", "HIGH"):
        await get_response_engine().handle_threat(detection, threat_id, event_source)

    # Create incident record
    await _create_incident(detection, threat_id, event_source)

    # Broadcast to WebSocket clients
    if _ws_broadcast:
        try:
            await _ws_broadcast({
                "type":         "threat",
                "threat_id":    threat_id,
                "threat_type":  detection["threat_type"],
                "src_ip":       detection.get("src_ip"),
                "severity":     detection["severity"],
                "timestamp":    now,
                "event_source": event_source,
                "details":      detection,
            })
        except Exception as exc:
            logger.warning("WebSocket broadcast failed: %s", exc)

    return threat_id


async def _create_incident(detection: dict, threat_id: int, event_source: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    details = {
        "threat_type":      detection["threat_type"],
        "count":            detection.get("count"),
        "detection_reason": detection.get("detection_reason"),
        "protocol":         detection.get("protocol"),
    }
    async with await get_db() as db:
        await db.execute(
            """
            INSERT INTO incidents
                (incident_type, src_ip, threat_id, timestamp, severity,
                 action, action_status, details, event_source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                detection["threat_type"],
                detection.get("src_ip"),
                threat_id,
                now,
                detection["severity"],
                "block_requested" if detection["severity"] in ("CRITICAL", "HIGH") else "monitor",
                "pending",
                json.dumps(details),
                event_source,
            ),
        )
        await db.commit()


async def record_traffic_stat(
    packets: int,
    suspicious: int,
    threats: int,
    unique_sources: int,
    event_source: str = "simulation",
) -> None:
    """Append a traffic statistics snapshot."""
    now = datetime.now(timezone.utc).isoformat()
    async with await get_db() as db:
        await db.execute(
            """
            INSERT INTO traffic_stats
                (timestamp, packets_observed, suspicious_packets,
                 threats_detected, unique_sources, event_source)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (now, packets, suspicious, threats, unique_sources, event_source),
        )
        await db.commit()


async def update_threat_response_status(threat_id: int, status: str) -> None:
    async with await get_db() as db:
        await db.execute(
            "UPDATE threats SET response_status = ? WHERE id = ?",
            (status, threat_id),
        )
        await db.commit()
