"""Threats API routes."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Query
from app.database import get_db
import math

router = APIRouter(prefix="/api/threats", tags=["threats"])


@router.get("")
async def list_threats(
    page:       int   = Query(1, ge=1),
    page_size:  int   = Query(20, ge=1, le=100),
    severity:   str   = Query(None),
    threat_type: str  = Query(None),
    src_ip:     str   = Query(None),
    time_range: str   = Query(None),  # e.g. "1h", "24h", "7d"
    sort:       str   = Query("timestamp_desc"),
):
    from datetime import datetime, timezone, timedelta

    conditions = []
    params: list = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())

    if threat_type:
        conditions.append("threat_type = ?")
        params.append(threat_type.upper())

    if src_ip:
        conditions.append("src_ip LIKE ?")
        params.append(f"%{src_ip}%")

    if time_range:
        td_map = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
        hours = td_map.get(time_range, 24)
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        conditions.append("timestamp >= ?")
        params.append(since)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    sort_map = {
        "timestamp_desc": "timestamp DESC",
        "timestamp_asc":  "timestamp ASC",
        "severity_desc":  "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END",
        "severity_asc":   "CASE severity WHEN 'LOW' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'HIGH' THEN 3 ELSE 4 END",
    }
    order = sort_map.get(sort, "timestamp DESC")

    offset = (page - 1) * page_size

    async with await get_db() as db:
        async with db.execute(f"SELECT COUNT(*) as n FROM threats {where}", params) as cur:
            total = (await cur.fetchone())["n"]

        async with db.execute(
            f"""
            SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                   threat_type, count, severity, detection_reason,
                   event_source, response_status
            FROM threats {where}
            ORDER BY {order}
            LIMIT ? OFFSET ?
            """,
            params + [page_size, offset],
        ) as cur:
            rows = await cur.fetchall()

    return {
        "threats":   [dict(r) for r in rows],
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "pages":     math.ceil(total / page_size) if total else 0,
    }


@router.get("/recent")
async def recent_threats(limit: int = Query(10, ge=1, le=50)):
    async with await get_db() as db:
        async with db.execute(
            """
            SELECT id, timestamp, src_ip, dst_ip, threat_type, severity,
                   count, response_status, event_source
            FROM threats ORDER BY timestamp DESC LIMIT ?
            """,
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.get("/{threat_id}")
async def get_threat(threat_id: int):
    async with await get_db() as db:
        async with db.execute(
            "SELECT * FROM threats WHERE id = ?", (threat_id,)
        ) as cur:
            row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Threat not found")
    threat = dict(row)

    # Fetch related incidents
    async with await get_db() as db:
        async with db.execute(
            "SELECT id, incident_type, timestamp, action, action_status FROM incidents WHERE threat_id = ?",
            (threat_id,),
        ) as cur:
            incidents = [dict(r) for r in await cur.fetchall()]

    threat["related_incidents"] = incidents
    return threat
