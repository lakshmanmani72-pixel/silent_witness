"""
SILENT WITNESS - Application Configuration
Centralised settings with environment variable override support.
"""

import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = str(DATA_DIR / "silent_witness.db")

# ── Detection Defaults ─────────────────────────────────────────────────────────
SYN_FLOOD_CRITICAL_THRESHOLD = 100   # packets in window → CRITICAL
SYN_FLOOD_HIGH_THRESHOLD = 50        # packets in window → HIGH
SYN_FLOOD_WINDOW_SECONDS = 10        # rolling window length

PORT_SCAN_HIGH_THRESHOLD = 100       # distinct ports in window → HIGH
PORT_SCAN_WINDOW_SECONDS = 60        # rolling window length

ALERT_COOLDOWN_SECONDS = 30          # min seconds between repeated alerts for same IP

# ── Response Defaults ──────────────────────────────────────────────────────────
DRY_RUN_MODE = True                  # NEVER modify firewall unless explicitly enabled
REAL_FIREWALL_ENABLED = False        # must be explicitly set to True + Linux only
DEFAULT_BLOCK_DURATION_MINUTES = 60
MAX_BLOCKS_PER_HOUR = 20

# ── Monitoring ─────────────────────────────────────────────────────────────────
DEFAULT_MODE = "simulation"          # "simulation" | "live"

# ── CORS ──────────────────────────────────────────────────────────────────────
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# ── Application ────────────────────────────────────────────────────────────────
APP_VERSION = "1.0.0"
APP_NAME = "Silent Witness"

# Allow-listed IPs that should never be blocked
DEFAULT_ALLOWLIST = [
    "127.0.0.1",
    "::1",
    "0.0.0.0",
]
