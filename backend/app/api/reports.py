"""
SILENT WITNESS - Reports and Data Export API
Generates CSV exports for threats and incidents with filter support,
and produces comprehensive SOC summary reports.
"""

from __future__ import annotations
import csv
import io
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Response, Query
from app.database import get_db

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/threats.csv")
async def export_threats_csv(
    severity: Optional[str] = Query(None),
    threat_type: Optional[str] = Query(None),
    event_source: Optional[str] = Query(None),
    time_range: Optional[str] = Query(None),
):
    """Export filtered threat records as downloadable CSV."""
    conditions, params = [], []

    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())
    if threat_type:
        conditions.append("threat_type = ?")
        params.append(threat_type.upper())
    if event_source:
        conditions.append("event_source = ?")
        params.append(event_source.lower())
    if time_range:
        td_map = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
        hours = td_map.get(time_range, 24)
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        conditions.append("timestamp >= ?")
        params.append(since)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    async with await get_db() as db:
        async with db.execute(
            f"""
            SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port,
                   protocol, threat_type, count, severity, detection_reason,
                   event_source, response_status
            FROM threats {where}
            ORDER BY timestamp DESC
            """,
            params,
        ) as cur:
            rows = await cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Incident ID", "Timestamp (UTC)", "Source IP", "Destination IP",
        "Source Port", "Destination Port", "Protocol", "Threat Type",
        "Packet Count", "Severity", "Detection Reason", "Event Source", "Response Status"
    ])

    for r in rows:
        writer.writerow([
            r["id"], r["timestamp"], r["src_ip"], r["dst_ip"] or "",
            r["src_port"] or "", r["dst_port"] or "", r["protocol"] or "",
            r["threat_type"], r["count"], r["severity"],
            r["detection_reason"] or "", r["event_source"], r["response_status"]
        ])

    csv_data = output.getvalue()
    filename = f"silent_witness_threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/incidents.csv")
async def export_incidents_csv(
    severity: Optional[str] = Query(None),
    incident_type: Optional[str] = Query(None),
    reviewed: Optional[str] = Query(None),
):
    """Export filtered incident records as downloadable CSV."""
    conditions, params = [], []

    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())
    if incident_type:
        conditions.append("incident_type = ?")
        params.append(incident_type.upper())
    if reviewed in ("true", "false"):
        conditions.append("reviewed = ?")
        params.append(1 if reviewed == "true" else 0)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    async with await get_db() as db:
        async with db.execute(
            f"""
            SELECT id, incident_type, src_ip, threat_id, timestamp,
                   severity, action, action_status, details, event_source, reviewed
            FROM incidents {where}
            ORDER BY timestamp DESC
            """,
            params,
        ) as cur:
            rows = await cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Incident ID", "Incident Type", "Source IP", "Threat Reference ID",
        "Timestamp (UTC)", "Severity", "Action Proposed/Taken",
        "Action Status", "Details", "Event Source", "Operator Reviewed"
    ])

    for r in rows:
        writer.writerow([
            r["id"], r["incident_type"], r["src_ip"], r["threat_id"] or "",
            r["timestamp"], r["severity"], r["action"] or "",
            r["action_status"], r["details"] or "", r["event_source"],
            "Yes" if r["reviewed"] else "No"
        ])

    csv_data = output.getvalue()
    filename = f"silent_witness_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/summary")
async def get_report_summary(time_range: str = Query("24h")):
    """Get full aggregated report summary for displaying or exporting."""
    td_map = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
    hours = td_map.get(time_range, 24)
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=hours)).isoformat()

    async with await get_db() as db:
        # Total threats in period
        async with db.execute("SELECT COUNT(*) as n FROM threats WHERE timestamp >= ?", (since,)) as cur:
            total_threats = (await cur.fetchone())["n"]

        # Threat types
        async with db.execute(
            "SELECT threat_type, COUNT(*) as cnt FROM threats WHERE timestamp >= ? GROUP BY threat_type", (since,)
        ) as cur:
            threat_distribution = [dict(r) for r in await cur.fetchall()]

        # Severity
        async with db.execute(
            "SELECT severity, COUNT(*) as cnt FROM threats WHERE timestamp >= ? GROUP BY severity", (since,)
        ) as cur:
            severity_distribution = [dict(r) for r in await cur.fetchall()]

        # Event source (simulated vs live)
        async with db.execute(
            "SELECT event_source, COUNT(*) as cnt FROM threats WHERE timestamp >= ? GROUP BY event_source", (since,)
        ) as cur:
            source_breakdown = {r["event_source"]: r["cnt"] for r in await cur.fetchall()}

        # Incidents & response actions
        async with db.execute(
            "SELECT action, COUNT(*) as cnt FROM incidents WHERE timestamp >= ? GROUP BY action", (since,)
        ) as cur:
            action_summary = [dict(r) for r in await cur.fetchall()]

        # Blocked IPs
        async with db.execute(
            "SELECT COUNT(*) as n FROM blocked_ips WHERE timestamp >= ?", (since,)
        ) as cur:
            blocked_count = (await cur.fetchone())["n"]

    return {
        "reporting_period": {
            "time_range": time_range,
            "start_time": since,
            "end_time": now.isoformat(),
        },
        "total_recorded_events": total_threats,
        "threat_distribution": threat_distribution,
        "severity_distribution": severity_distribution,
        "event_source_counts": {
            "simulation": source_breakdown.get("simulation", 0),
            "live": source_breakdown.get("live", 0),
        },
        "response_actions": action_summary,
        "total_blocks_recorded": blocked_count,
        "important_limitations": [
            "Defensive educational application. Never attacks, scans, or sends malicious traffic to external hosts.",
            "Dry-run mode is active by default to protect host network stability.",
            "Passive packet capture extracts packet headers only; raw payloads are strictly excluded to protect privacy.",
            "Synthetic simulation events are generated for educational demonstration and explicitly tagged.",
        ]
    }
