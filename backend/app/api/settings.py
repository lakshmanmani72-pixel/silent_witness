"""Settings API routes."""
from __future__ import annotations
import json
from fastapi import APIRouter, HTTPException
from app.database import get_db, get_setting, set_setting

router = APIRouter(prefix="/api/settings", tags=["settings"])

SETTING_KEYS = [
    "syn_flood_critical_threshold",
    "syn_flood_high_threshold",
    "syn_flood_window_seconds",
    "port_scan_high_threshold",
    "port_scan_window_seconds",
    "alert_cooldown_seconds",
    "dry_run_mode",
    "auto_response_enabled",
    "default_block_duration_min",
    "max_blocks_per_hour",
    "monitoring_mode",
    "allowlist_ips",
    "data_retention_days",
    "table_density",
]


@router.get("")
async def get_all_settings():
    async with await get_db() as db:
        async with db.execute("SELECT key, value FROM application_settings") as cur:
            rows = {r["key"]: r["value"] for r in await cur.fetchall()}

    def coerce(key: str, val: str):
        int_keys = {
            "syn_flood_critical_threshold", "syn_flood_high_threshold",
            "syn_flood_window_seconds", "port_scan_high_threshold",
            "port_scan_window_seconds", "alert_cooldown_seconds",
            "default_block_duration_min", "max_blocks_per_hour",
            "data_retention_days",
        }
        bool_keys = {"dry_run_mode", "auto_response_enabled"}
        json_keys = {"allowlist_ips"}

        if key in int_keys:
            try:
                return int(val)
            except (TypeError, ValueError):
                return val
        if key in bool_keys:
            return str(val).lower() == "true"
        if key in json_keys:
            try:
                return json.loads(val)
            except Exception:
                return []
        return val

    return {k: coerce(k, rows.get(k, "")) for k in SETTING_KEYS}


@router.put("")
async def update_settings(body: dict):
    """Update one or more settings. All values are validated before saving."""
    allowed = set(SETTING_KEYS)
    updates = {k: v for k, v in body.items() if k in allowed}

    if not updates:
        raise HTTPException(status_code=400, detail="No valid setting keys provided")

    for key, val in updates.items():
        # Validate numeric settings
        int_keys = {
            "syn_flood_critical_threshold", "syn_flood_high_threshold",
            "syn_flood_window_seconds", "port_scan_high_threshold",
            "port_scan_window_seconds", "alert_cooldown_seconds",
            "default_block_duration_min", "max_blocks_per_hour",
            "data_retention_days",
        }
        if key in int_keys:
            try:
                val = int(val)
                if val < 1:
                    raise ValueError
            except (ValueError, TypeError):
                raise HTTPException(
                    status_code=422,
                    detail=f"Setting '{key}' must be a positive integer",
                )

        if key == "monitoring_mode" and val not in ("simulation", "live"):
            raise HTTPException(
                status_code=422,
                detail="monitoring_mode must be 'simulation' or 'live'",
            )

        if key == "allowlist_ips":
            if not isinstance(val, list):
                raise HTTPException(
                    status_code=422,
                    detail="allowlist_ips must be a list of IP strings",
                )
            val = json.dumps(val)

        await set_setting(key, str(val) if not isinstance(val, str) else val)

    # Push updated thresholds to detector
    await _refresh_detector_thresholds()

    return {"message": "Settings updated", "success": True}


async def _refresh_detector_thresholds():
    """Push current DB settings into the live ThreatDetector instance."""
    from app.services.threat_detector import get_detector
    det = get_detector()
    det.update_thresholds(
        syn_critical=int(await get_setting("syn_flood_critical_threshold", 100)),
        syn_high=int(await get_setting("syn_flood_high_threshold", 50)),
        syn_window=float(await get_setting("syn_flood_window_seconds", 10)),
        port_high=int(await get_setting("port_scan_high_threshold", 100)),
        port_window=float(await get_setting("port_scan_window_seconds", 60)),
        cooldown=float(await get_setting("alert_cooldown_seconds", 30)),
    )
