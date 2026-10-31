"""Blocked IPs API routes."""
from __future__ import annotations
from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query
from app.database import get_db, get_setting
from app.services.response_engine import get_response_engine

router = APIRouter(prefix="/api/blocked-ips", tags=["blocked-ips"])


class ManualBlockPayload(BaseModel):
    ip: str
    reason: Optional[str] = "Manual block by operator"
    duration_min: Optional[int] = 60


@router.post("/block")
async def manual_block_ip(payload: ManualBlockPayload):
    """Manually block a source IP address with safety exclusions and audit logging."""
    from app.utils.validation import is_safe_to_block
    from datetime import datetime, timezone, timedelta
    import json

    ip = payload.ip.strip()
    allowlist = await get_setting("allowlist_ips", ["127.0.0.1", "::1"])
    safe, reason = is_safe_to_block(ip, allowlist)
    if not safe:
        raise HTTPException(status_code=400, detail=f"Cannot block IP {ip}: {reason}")

    engine = get_response_engine()
    if await engine._is_already_blocked(ip):
        raise HTTPException(status_code=400, detail=f"IP {ip} is already actively blocked.")

    dry_run = await get_setting("dry_run_mode", True)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=payload.duration_min or 60)
    action = "simulated_block" if dry_run else "firewall_block"

    await engine._record_block(
        ip=ip,
        threat_type="MANUAL_OPERATOR_BLOCK",
        severity="HIGH",
        reason=payload.reason or "Manual block by SOC operator",
        timestamp=now.isoformat(),
        expires_at=expires.isoformat(),
        action_type=action,
        dry_run=dry_run,
    )

    if not dry_run:
        await engine._real_block(ip, payload.duration_min or 60)

    # Log incident audit
    async with await get_db() as db:
        await db.execute(
            """
            INSERT INTO incidents
                (incident_type, src_ip, timestamp, severity, action,
                 action_status, details, event_source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "MANUAL_BLOCK", ip, now.isoformat(), "HIGH",
                action, "completed",
                json.dumps({"reason": payload.reason, "dry_run": dry_run, "duration_min": payload.duration_min}),
                "operator",
            ),
        )
        await db.commit()

    return {
        "success": True,
        "message": f"Successfully blocked {ip} ({'Simulated Dry-Run' if dry_run else 'OS Firewall Rule'}).",
        "ip": ip,
        "dry_run": dry_run,
        "action": action,
    }


@router.post("/unblock-by-ip")
async def unblock_by_ip(payload: dict):
    """Deactivate block by IP address."""
    ip = (payload.get("ip") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="Missing IP address.")
    async with await get_db() as db:
        async with db.execute(
            "SELECT id FROM blocked_ips WHERE ip = ? AND status = 'active' ORDER BY id DESC LIMIT 1",
            (ip,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"No active block found for {ip}")
    return await unblock_ip(row["id"], payload)


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
