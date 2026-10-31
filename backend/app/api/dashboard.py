"""Dashboard API routes."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
from typing import List

from fastapi import APIRouter
from app.database import get_db

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
async def get_summary():
    """Return KPI summary values for the overview dashboard."""
    import time
    from app.services.simulator import get_simulator
    from app.services.packet_capture import get_capture

    sim  = get_simulator()
    cap  = get_capture()

    async with await get_db() as db:
        async with db.execute("SELECT COUNT(*) as n FROM threats WHERE event_source IS NOT NULL") as cur:
            total_threats = (await cur.fetchone())["n"]

        async with db.execute("SELECT COUNT(*) as n FROM threats WHERE severity='CRITICAL'") as cur:
            critical = (await cur.fetchone())["n"]

        async with db.execute("SELECT COUNT(*) as n FROM threats WHERE severity='HIGH'") as cur:
            high = (await cur.fetchone())["n"]

        async with db.execute(
            "SELECT COUNT(*) as n FROM blocked_ips WHERE status='active'"
        ) as cur:
            active_blocked = (await cur.fetchone())["n"]

        async with db.execute(
            "SELECT SUM(packets_observed) as s FROM traffic_stats"
        ) as cur:
            row = await cur.fetchone()
            packets = row["s"] or 0

        async with db.execute(
            "SELECT timestamp FROM threats ORDER BY timestamp DESC LIMIT 1"
        ) as cur:
            row = await cur.fetchone()
            last_detection = row["timestamp"] if row else None

    mode    = "simulation" if (sim.status["running"] or not cap.active) else "live"
    active  = sim.status["running"] or cap.active

    from app import _start_time
    uptime = (datetime.now(timezone.utc) - _start_time).total_seconds()

    return {
        "total_threats":    total_threats,
        "critical_threats": critical,
        "high_threats":     high,
        "active_blocked_ips": active_blocked,
        "packets_analyzed": packets + (cap.packets_captured if cap.active else 0),
        "uptime_seconds":   uptime,
        "monitoring_mode":  mode,
        "monitoring_active": active,
        "last_detection":   last_detection,
    }


@router.get("/traffic")
async def get_traffic(range: str = "5m"):
    """Return traffic time series data for the area chart."""
    ranges = {
        "5m":  timedelta(minutes=5),
        "15m": timedelta(minutes=15),
        "1h":  timedelta(hours=1),
        "24h": timedelta(hours=24),
    }
    delta = ranges.get(range, timedelta(minutes=5))
    since = (datetime.now(timezone.utc) - delta).isoformat()

    async with await get_db() as db:
        async with db.execute(
            """
            SELECT timestamp, packets_observed, suspicious_packets,
                   threats_detected, unique_sources
            FROM traffic_stats
            WHERE timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (since,),
        ) as cur:
            rows = await cur.fetchall()

    return [dict(r) for r in rows]


@router.get("/severity-distribution")
async def get_severity_distribution():
    async with await get_db() as db:
        async with db.execute(
            "SELECT severity, COUNT(*) as count FROM threats GROUP BY severity ORDER BY count DESC"
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/threat-types")
async def get_threat_types():
    async with await get_db() as db:
        async with db.execute(
            "SELECT threat_type, COUNT(*) as count FROM threats GROUP BY threat_type ORDER BY count DESC"
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/recent-events")
async def get_recent_events(limit: int = 20):
    async with await get_db() as db:
        async with db.execute(
            """
            SELECT id, timestamp, src_ip, dst_ip, threat_type, count,
                   severity, response_status, event_source
            FROM threats
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/network-activity")
async def get_network_activity():
    """Aggregated network activity panel statistics."""
    from app.services.simulator import get_simulator
    from app.services.packet_capture import get_capture

    sim = get_simulator()
    cap = get_capture()

    async with await get_db() as db:
        async with db.execute(
            "SELECT SUM(packets_observed) as p, SUM(suspicious_packets) as s, "
            "SUM(unique_sources) as u FROM traffic_stats"
        ) as cur:
            row = await cur.fetchone()
            packets   = row["p"] or 0
            suspicious = row["s"] or 0
            unique    = row["u"] or 0

        async with db.execute(
            "SELECT timestamp FROM threats ORDER BY timestamp DESC LIMIT 1"
        ) as cur:
            row = await cur.fetchone()
            last = row["timestamp"] if row else None

    return {
        "monitoring_active": sim.status["running"] or cap.active,
        "mode":              "simulation" if sim.status["running"] else ("live" if cap.active else "idle"),
        "packets_observed":  packets,
        "suspicious_packets": suspicious,
        "unique_sources":    unique,
        "last_detection":    last,
    }
