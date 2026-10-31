"""Analytics API routes."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Query
from app.database import get_db

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


def _since(time_range: str) -> str:
    td_map = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
    hours = td_map.get(time_range, 24)
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


@router.get("/traffic")
async def traffic_over_time(time_range: str = Query("24h")):
    since = _since(time_range)
    async with await get_db() as db:
        async with db.execute(
            """
            SELECT timestamp, packets_observed, suspicious_packets,
                   threats_detected, unique_sources
            FROM traffic_stats WHERE timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (since,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/threats")
async def threats_over_time(time_range: str = Query("24h")):
    since = _since(time_range)
    async with await get_db() as db:
        async with db.execute(
            """
            SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour,
                   COUNT(*) as count,
                   severity,
                   threat_type
            FROM threats WHERE timestamp >= ?
            GROUP BY hour, severity, threat_type
            ORDER BY hour ASC
            """,
            (since,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/top-sources")
async def top_sources(limit: int = Query(10, ge=1, le=50), time_range: str = Query("24h")):
    since = _since(time_range)
    async with await get_db() as db:
        async with db.execute(
            """
            SELECT src_ip,
                   COUNT(*) as count,
                   MAX(CASE severity
                       WHEN 'CRITICAL' THEN 4
                       WHEN 'HIGH'     THEN 3
                       WHEN 'MEDIUM'   THEN 2
                       ELSE 1
                   END) as sev_rank,
                   MAX(timestamp) as last_seen
            FROM threats WHERE timestamp >= ?
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT ?
            """,
            (since, limit),
        ) as cur:
            rows = await cur.fetchall()

    def rank_to_label(r):
        return {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(r, "INFO")

    return [
        {
            "src_ip":           r["src_ip"],
            "count":            r["count"],
            "highest_severity": rank_to_label(r["sev_rank"]),
            "last_seen":        r["last_seen"],
        }
        for r in rows
    ]


@router.get("/top-ports")
async def top_ports(limit: int = Query(10, ge=1, le=50), time_range: str = Query("24h")):
    since = _since(time_range)
    async with await get_db() as db:
        async with db.execute(
            """
            SELECT dst_port, COUNT(*) as count
            FROM threats WHERE timestamp >= ? AND dst_port IS NOT NULL
            GROUP BY dst_port ORDER BY count DESC LIMIT ?
            """,
            (since, limit),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/protocol-distribution")
async def protocol_dist(time_range: str = Query("24h")):
    since = _since(time_range)
    async with await get_db() as db:
        async with db.execute(
            """
            SELECT COALESCE(protocol, 'Unknown') as protocol, COUNT(*) as count
            FROM threats WHERE timestamp >= ?
            GROUP BY protocol ORDER BY count DESC
            """,
            (since,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/blocked-trends")
async def blocked_trends(time_range: str = Query("24h")):
    since = _since(time_range)
    async with await get_db() as db:
        async with db.execute(
            """
            SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour,
                   COUNT(*) as count
            FROM blocked_ips WHERE timestamp >= ?
            GROUP BY hour ORDER BY hour ASC
            """,
            (since,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/ip-intelligence/{ip}")
async def ip_intelligence(ip: str):
    """Return all locally observed data for a given source IP."""
    async with await get_db() as db:
        async with db.execute(
            """
            SELECT COUNT(*) as event_count,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen,
                   GROUP_CONCAT(DISTINCT threat_type) as threat_types,
                   MAX(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                                     WHEN 'MEDIUM' THEN 2 ELSE 1 END) as sev_rank
            FROM threats WHERE src_ip = ?
            """,
            (ip,),
        ) as cur:
            row = await cur.fetchone()

        async with db.execute(
            "SELECT id, status, expires_at FROM blocked_ips WHERE ip = ? ORDER BY timestamp DESC LIMIT 1",
            (ip,),
        ) as cur:
            block = await cur.fetchone()

        async with db.execute(
            "SELECT id, timestamp, incident_type, severity, action_status FROM incidents WHERE src_ip = ? ORDER BY timestamp DESC LIMIT 20",
            (ip,),
        ) as cur:
            incidents = [dict(r) for r in await cur.fetchall()]

    def rank_to_label(r):
        return {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(r, "INFO")

    return {
        "ip":               ip,
        "event_count":      row["event_count"] if row else 0,
        "first_seen":       row["first_seen"] if row else None,
        "last_seen":        row["last_seen"] if row else None,
        "threat_types":     (row["threat_types"] or "").split(",") if row else [],
        "highest_severity": rank_to_label(row["sev_rank"]) if row else "INFO",
        "block_status":     dict(block) if block else None,
        "related_incidents": incidents,
    }
