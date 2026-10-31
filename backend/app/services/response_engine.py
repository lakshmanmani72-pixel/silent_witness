"""
SILENT WITNESS – Safe Response Engine
=======================================
Handles automated responses to detected threats.

SAFETY GUARANTEES
-----------------
• Dry-run mode is enabled by default and NEVER touches the OS firewall.
• Real firewall integration requires explicit administrator configuration
  AND a Linux platform.
• All IPs are validated before any action.
• A configurable allow-list prevents critical infrastructure IPs from
  being blocked.
• An hourly rate-limit prevents accidental mass-blocking.
• Only IPs not already blocked may be newly blocked.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.database import get_db, get_setting
from app.utils.validation import is_safe_to_block

logger = logging.getLogger("silent_witness.response")


class ResponseEngine:
    """
    Central automated response coordinator.

    All block decisions flow through ``handle_threat()``.
    The engine reads its configuration from the database on each call so
    that settings changes take effect immediately.
    """

    def __init__(self):
        self._block_timestamps: list[float] = []  # monotonic times of blocks this hour

    # ── Public API ────────────────────────────────────────────────────────────

    async def handle_threat(
        self,
        detection: dict,
        threat_id: int,
        event_source: str,
    ) -> None:
        """Evaluate a HIGH/CRITICAL detection and take the appropriate action."""
        src_ip   = detection.get("src_ip", "")
        severity = detection["severity"]

        # Read live settings
        dry_run         = (await get_setting("dry_run_mode", "true")).lower() == "true"
        auto_response   = (await get_setting("auto_response_enabled", "false")).lower() == "true"
        block_duration  = int(await get_setting("default_block_duration_min", "60"))
        max_per_hour    = int(await get_setting("max_blocks_per_hour", "20"))
        allowlist_raw   = await get_setting("allowlist_ips", '["127.0.0.1","::1"]')

        try:
            allowlist = json.loads(allowlist_raw)
        except Exception:
            allowlist = ["127.0.0.1", "::1"]

        if not auto_response:
            logger.info("Automatic blocking disabled (Manual Mode active); awaiting operator decision for %s", src_ip)
            return

        # Safety checks
        safe, reason = is_safe_to_block(src_ip, allowlist)
        if not safe:
            logger.info("Will not block %s: %s", src_ip, reason)
            return

        # Already blocked?
        if await self._is_already_blocked(src_ip):
            logger.debug("IP %s already has an active block", src_ip)
            return

        # Rate-limit check
        if not self._within_rate_limit(max_per_hour):
            logger.warning("Hourly block rate-limit reached (%d/h); skipping %s", max_per_hour, src_ip)
            return

        # Record the proposed / actual block
        now       = datetime.now(timezone.utc)
        expires   = now + timedelta(minutes=block_duration)
        action    = "simulated_block" if dry_run else "firewall_block"

        await self._record_block(
            ip=src_ip,
            threat_type=detection["threat_type"],
            severity=severity,
            reason=detection.get("detection_reason", ""),
            timestamp=now.isoformat(),
            expires_at=expires.isoformat(),
            action_type=action,
            dry_run=dry_run,
        )

        if dry_run:
            logger.info(
                "[DRY-RUN] Would block %s for %d min (severity=%s, threat=%s)",
                src_ip, block_duration, severity, detection["threat_type"],
            )
        else:
            # Real firewall integration – Linux only
            await self._real_block(src_ip, block_duration)

        # Update threat response status
        from app.services.event_processor import update_threat_response_status
        status = "blocked_simulated" if dry_run else "blocked"
        await update_threat_response_status(threat_id, status)

        self._block_timestamps.append(time.monotonic())

    async def unblock_ip(self, block_id: int, reason: str = "manual") -> bool:
        """Mark a blocked IP record as expired/unblocked and remove firewall rule if applicable."""
        from app.services.firewall import get_firewall
        async with await get_db() as db:
            async with db.execute("SELECT ip, dry_run FROM blocked_ips WHERE id = ? AND status = 'active'", (block_id,)) as cur:
                row = await cur.fetchone()
                if not row:
                    return False
                ip = row["ip"]
                dry_run = bool(row["dry_run"])

            now = datetime.now(timezone.utc).isoformat()
            cursor = await db.execute(
                "UPDATE blocked_ips SET status = 'unblocked', expires_at = ? WHERE id = ? AND status = 'active'",
                (now, block_id),
            )
            await db.commit()

        # Remove rule through firewall manager
        get_firewall().unblock_ip(ip, dry_run=dry_run)
        return True

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _is_already_blocked(self, ip: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        async with await get_db() as db:
            async with db.execute(
                "SELECT id FROM blocked_ips WHERE ip = ? AND status = 'active' AND expires_at > ?",
                (ip, now),
            ) as cur:
                return await cur.fetchone() is not None

    def _within_rate_limit(self, max_per_hour: int) -> bool:
        cutoff = time.monotonic() - 3600
        self._block_timestamps = [t for t in self._block_timestamps if t > cutoff]
        return len(self._block_timestamps) < max_per_hour

    async def _record_block(
        self,
        ip: str,
        threat_type: str,
        severity: str,
        reason: str,
        timestamp: str,
        expires_at: str,
        action_type: str,
        dry_run: bool,
        firewall_ref: str = "",
    ) -> int:
        async with await get_db() as db:
            cursor = await db.execute(
                """
                INSERT INTO blocked_ips
                    (ip, threat_type, severity, reason, timestamp, expires_at,
                     action_type, status, dry_run, firewall_rule_reference)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ip, threat_type, severity, reason, timestamp, expires_at,
                    action_type, "active", 1 if dry_run else 0, firewall_ref,
                ),
            )
            await db.commit()
            return cursor.lastrowid

    async def _real_block(self, ip: str, duration_min: int) -> None:
        """
        Attempt a real iptables block on Linux.

        This path is intentionally disabled on Windows and requires
        REAL_FIREWALL_ENABLED=True in config.
        """
        import sys
        import subprocess

        if sys.platform == "win32":
            logger.warning("Real firewall blocking is not supported on Windows. "
                           "Using simulated response.")
            return

        from app.config import REAL_FIREWALL_ENABLED
        if not REAL_FIREWALL_ENABLED:
            logger.info("Real firewall integration disabled; using dry-run.")
            return

        # Build iptables command using argument list (no shell injection possible)
        cmd = [
            "iptables", "-I", "INPUT", "-s", ip,
            "-j", "DROP", "-m", "comment",
            "--comment", f"silent_witness_block",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
                shell=False,   # NEVER use shell=True with user-controlled input
            )
            if result.returncode == 0:
                logger.info("Firewall block applied for %s", ip)
            else:
                logger.error("iptables error for %s: %s", ip, result.stderr)
        except Exception as exc:
            logger.error("Failed to apply firewall rule for %s: %s", ip, exc)

    async def expire_old_blocks(self) -> int:
        """Mark expired active blocks as 'expired'. Called periodically."""
        now = datetime.now(timezone.utc).isoformat()
        async with await get_db() as db:
            cursor = await db.execute(
                "UPDATE blocked_ips SET status = 'expired' WHERE status = 'active' AND expires_at < ?",
                (now,),
            )
            await db.commit()
            expired_count = cursor.rowcount
        if expired_count:
            logger.info("Expired %d block(s)", expired_count)
        return expired_count


_engine: Optional[ResponseEngine] = None


def get_response_engine() -> ResponseEngine:
    global _engine
    if _engine is None:
        _engine = ResponseEngine()
    return _engine
