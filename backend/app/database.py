"""
SILENT WITNESS – Database Layer
Async SQLite access via aiosqlite.  Tables are created automatically on startup.
"""

import aiosqlite
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

from app.config import DATABASE_URL

logger = logging.getLogger("silent_witness.db")

_db_path = DATABASE_URL


class DBContext:
    def __init__(self, path: str):
        self.path = path
        self._conn = None

    async def __aenter__(self) -> aiosqlite.Connection:
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._conn:
            await self._conn.close()


async def get_db() -> DBContext:
    """Return an async context manager that opens and properly closes a database connection."""
    return DBContext(_db_path)


async def init_db() -> None:
    """Create all required tables and indexes if they do not exist."""
    async with aiosqlite.connect(_db_path) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")

        # ── threats ───────────────────────────────────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                src_ip          TEXT    NOT NULL,
                dst_ip          TEXT,
                src_port        INTEGER,
                dst_port        INTEGER,
                protocol        TEXT,
                threat_type     TEXT    NOT NULL,
                count           INTEGER DEFAULT 1,
                severity        TEXT    NOT NULL,
                detection_reason TEXT,
                event_source    TEXT    DEFAULT 'simulation',
                response_status TEXT    DEFAULT 'pending'
            )
        """)

        await db.execute("CREATE INDEX IF NOT EXISTS idx_threats_ts        ON threats(timestamp)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threats_src_ip    ON threats(src_ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threats_severity  ON threats(severity)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threats_type      ON threats(threat_type)")

        # ── blocked_ips ───────────────────────────────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                ip                      TEXT    NOT NULL,
                threat_type             TEXT,
                severity                TEXT,
                reason                  TEXT,
                timestamp               TEXT    NOT NULL,
                expires_at              TEXT,
                action_type             TEXT    DEFAULT 'block',
                status                  TEXT    DEFAULT 'active',
                dry_run                 INTEGER DEFAULT 1,
                firewall_rule_reference TEXT
            )
        """)

        await db.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip        ON blocked_ips(ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_blocked_status    ON blocked_ips(status)")

        # ── incidents ─────────────────────────────────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_type TEXT    NOT NULL,
                src_ip        TEXT    NOT NULL,
                threat_id     INTEGER,
                timestamp     TEXT    NOT NULL,
                severity      TEXT    NOT NULL,
                action        TEXT,
                action_status TEXT    DEFAULT 'pending',
                details       TEXT,
                event_source  TEXT    DEFAULT 'simulation',
                reviewed      INTEGER DEFAULT 0
            )
        """)

        await db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_ts      ON incidents(timestamp)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_src_ip  ON incidents(src_ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_sev     ON incidents(severity)")

        # ── traffic_stats ─────────────────────────────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp          TEXT    NOT NULL,
                packets_observed   INTEGER DEFAULT 0,
                suspicious_packets INTEGER DEFAULT 0,
                threats_detected   INTEGER DEFAULT 0,
                unique_sources     INTEGER DEFAULT 0,
                event_source       TEXT    DEFAULT 'simulation'
            )
        """)

        await db.execute("CREATE INDEX IF NOT EXISTS idx_traffic_ts        ON traffic_stats(timestamp)")

        # ── application_settings ──────────────────────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS application_settings (
                key        TEXT PRIMARY KEY,
                value      TEXT,
                updated_at TEXT
            )
        """)

        await db.commit()
        logger.info("Database initialised at %s", _db_path)

        # Seed default settings if absent
        await _seed_defaults(db)


async def _seed_defaults(db: aiosqlite.Connection) -> None:
    """Insert default settings only if each key is not yet present."""
    from app.config import (
        SYN_FLOOD_CRITICAL_THRESHOLD, SYN_FLOOD_HIGH_THRESHOLD,
        SYN_FLOOD_WINDOW_SECONDS, PORT_SCAN_HIGH_THRESHOLD,
        PORT_SCAN_WINDOW_SECONDS, ALERT_COOLDOWN_SECONDS,
        DRY_RUN_MODE, DEFAULT_BLOCK_DURATION_MINUTES,
        MAX_BLOCKS_PER_HOUR, DEFAULT_MODE,
    )
    import json

    defaults = {
        "syn_flood_critical_threshold": SYN_FLOOD_CRITICAL_THRESHOLD,
        "syn_flood_high_threshold":     SYN_FLOOD_HIGH_THRESHOLD,
        "syn_flood_window_seconds":     SYN_FLOOD_WINDOW_SECONDS,
        "port_scan_high_threshold":     PORT_SCAN_HIGH_THRESHOLD,
        "port_scan_window_seconds":     PORT_SCAN_WINDOW_SECONDS,
        "alert_cooldown_seconds":       ALERT_COOLDOWN_SECONDS,
        "dry_run_mode":                 str(DRY_RUN_MODE).lower(),
        "auto_response_enabled":        "false",
        "default_block_duration_min":   DEFAULT_BLOCK_DURATION_MINUTES,
        "max_blocks_per_hour":          MAX_BLOCKS_PER_HOUR,
        "monitoring_mode":              DEFAULT_MODE,
        "allowlist_ips":                json.dumps(["127.0.0.1", "::1"]),
        "data_retention_days":          90,
        "table_density":                "comfortable",
    }

    now = datetime.now(timezone.utc).isoformat()
    for key, value in defaults.items():
        await db.execute(
            "INSERT OR IGNORE INTO application_settings (key, value, updated_at) VALUES (?, ?, ?)",
            (key, str(value), now),
        )
    await db.commit()


async def get_setting(key: str, default=None):
    """Return a single setting value from the database."""
    async with await get_db() as db:
        async with db.execute(
            "SELECT value FROM application_settings WHERE key = ?", (key,)
        ) as cur:
            row = await cur.fetchone()
            return row["value"] if row else default


async def set_setting(key: str, value: str) -> None:
    """Upsert a setting."""
    now = datetime.now(timezone.utc).isoformat()
    async with await get_db() as db:
        await db.execute(
            "INSERT INTO application_settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, str(value), now),
        )
        await db.commit()


async def db_health() -> dict:
    """Return database health information."""
    try:
        async with await get_db() as db:
            async with db.execute("SELECT COUNT(*) as n FROM threats") as cur:
                r = await cur.fetchone()
                threat_count = r["n"]
            async with db.execute("SELECT COUNT(*) as n FROM incidents") as cur:
                r = await cur.fetchone()
                incident_count = r["n"]
        return {
            "status": "healthy",
            "path": _db_path,
            "threat_count": threat_count,
            "incident_count": incident_count,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
