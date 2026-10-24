"""Blocked IPs API routes."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Query
from app.database import get_db
from app.services.response_engine import get_response_engine

router = APIRouter(prefix="/api/blocked-ips", tags=["blocked-ips"])


@router.get("")
async def list_blocked_ips(
    status:   str = Query(None),
    severity: str = Query(None),
    search:   str = Query(None),
):
    conditions, params = [], []

    if status:
        conditions.append("status = ?")
        params.append(status)

    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())

    if search:
        conditions.append("ip LIKE ?")
        params.append(f"%{search}%")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    async with await get_db() as db:
        async with db.execute(
            f"""
            SELECT id, ip, threat_type, severity, reason, timestamp,
                   expires_at, action_type, status, dry_run,
                   firewall_rule_reference
            FROM blocked_ips {where}
            ORDER BY timestamp DESC
            """,
            params,
        ) as cur:
            rows = await cur.fetchall()
        total = len(rows)

    return {
        "blocked_ips": [dict(r) for r in rows],
        "total": total,
    }


@router.get("/{block_id}")
async def get_blocked_ip(block_id: int):
    async with await get_db() as db:
        async with db.execute(
            "SELECT * FROM blocked_ips WHERE id = ?", (block_id,)
        ) as cur:
            row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Block record not found")
    return dict(row)


@router.post("/{block_id}/unblock")
async def unblock_ip(block_id: int, body: dict = {}):
    engine = get_response_engine()
    reason = (body or {}).get("reason", "Manual unblock by operator")
    success = await engine.unblock_ip(block_id, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Block record not found or already inactive")

    # Create incident record for the manual unblock
    from datetime import datetime, timezone
    import json
    now = datetime.now(timezone.utc).isoformat()
    async with await get_db() as db:
        async with db.execute("SELECT ip, severity FROM blocked_ips WHERE id = ?", (block_id,)) as cur:
            row = await cur.fetchone()
        if row:
            await db.execute(
                """
                INSERT INTO incidents
                    (incident_type, src_ip, timestamp, severity, action,
                     action_status, details, event_source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "MANUAL_UNBLOCK", row["ip"], now, row["severity"] or "INFO",
                    "manual_unblock", "completed",
                    json.dumps({"reason": reason, "block_id": block_id}),
                    "operator",
                ),
            )
            await db.commit()

    return {"message": f"Block {block_id} has been deactivated", "success": True}
