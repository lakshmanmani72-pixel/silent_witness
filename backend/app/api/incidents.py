"""Incidents API routes."""
from __future__ import annotations
import math
from fastapi import APIRouter, HTTPException, Query
from app.database import get_db

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("")
async def list_incidents(
    page:       int  = Query(1, ge=1),
    page_size:  int  = Query(20, ge=1, le=100),
    severity:   str  = Query(None),
    incident_type: str = Query(None),
    search:     str  = Query(None),
    reviewed:   str  = Query(None),  # "true" | "false"
    time_range: str  = Query(None),
):
    from datetime import datetime, timezone, timedelta
    conditions, params = [], []

    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())

    if incident_type:
        conditions.append("incident_type = ?")
        params.append(incident_type.upper())

    if search:
        conditions.append("(src_ip LIKE ? OR CAST(id AS TEXT) LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    if reviewed in ("true", "false"):
        conditions.append("reviewed = ?")
        params.append(1 if reviewed == "true" else 0)

    if time_range:
        td_map = {"1h": 1, "24h": 24, "7d": 168}
        hours = td_map.get(time_range, 24)
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        conditions.append("timestamp >= ?")
        params.append(since)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    offset = (page - 1) * page_size

    async with await get_db() as db:
        async with db.execute(f"SELECT COUNT(*) as n FROM incidents {where}", params) as cur:
            total = (await cur.fetchone())["n"]

        async with db.execute(
            f"""
            SELECT id, incident_type, src_ip, threat_id, timestamp,
                   severity, action, action_status, details,
                   event_source, reviewed
            FROM incidents {where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """,
            params + [page_size, offset],
        ) as cur:
            rows = await cur.fetchall()

    return {
        "incidents": [dict(r) for r in rows],
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "pages":     math.ceil(total / page_size) if total else 0,
    }


@router.get("/{incident_id}")
async def get_incident(incident_id: int):
    async with await get_db() as db:
        async with db.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ) as cur:
            row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return dict(row)


@router.post("/{incident_id}/review")
async def review_incident(incident_id: int, body: dict = {}):
    reviewed = (body or {}).get("reviewed", True)
    async with await get_db() as db:
        cursor = await db.execute(
            "UPDATE incidents SET reviewed = ? WHERE id = ?",
            (1 if reviewed else 0, incident_id),
        )
        await db.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Incident not found")
    return {"message": f"Incident {incident_id} review status updated", "success": True}
