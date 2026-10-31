"""
SILENT WITNESS - Comprehensive Test Suite
Covers all 15 acceptance test areas using pytest & pytest-asyncio:
1. Database initialization
2. Health endpoint
3. SYN flood severity classification
4. Port scan detection
5. Normal traffic classification
6. Event persistence
7. Duplicate block prevention
8. Allow-listed IP protection
9. Block expiry
10. Rate-limit enforcement
11. Dry-run firewall behavior
12. Invalid IP rejection
13. CSV report generation
14. Simulation mode labeling
15. Incident audit logging
"""

import os
import sys
import tempfile
import asyncio
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport

# Set temporary test database path before loading app components
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
os.close(temp_db_fd)
os.environ["TESTING"] = "1"

# Point database URL to temp DB
import app.config
app.config.DATABASE_URL = temp_db_path
import app.database
app.database._db_path = temp_db_path

from app.database import init_db, get_db, db_health, set_setting, get_setting
from app.services.threat_detector import ThreatDetector, classify_severity
from app.services.response_engine import ResponseEngine
from app.services.firewall import FirewallManager
from app.utils.validation import validate_ip, is_safe_to_block
from app.services.event_processor import process_detection
from app.main import app as fastapi_app


@pytest.fixture(autouse=True)
async def setup_test_db():
    """Initialise test database before running tests."""
    await init_db()
    yield


@pytest.mark.asyncio
async def test_01_database_initialization():
    """Test 1: Verify tables and default settings are initialized properly."""
    health = await db_health()
    assert health["status"] == "healthy"
    assert "threat_count" in health

    async with await get_db() as db:
        async with db.execute("SELECT count(*) as c FROM sqlite_master WHERE type='table'") as cur:
            row = await cur.fetchone()
            assert row["c"] >= 5  # threats, blocked_ips, incidents, traffic_stats, application_settings


@pytest.mark.asyncio
async def test_02_health_endpoint():
    """Test 2: Check GET /api/health endpoint returns expected schema."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] in ("healthy", "degraded")
        assert "version" in data
        assert "monitoring" in data


def test_03_syn_flood_severity_classification():
    """Test 3: Test SYN flood thresholds classification logic."""
    # Count > 100 -> CRITICAL
    assert classify_severity("SYN_FLOOD", 101, syn_critical=100, syn_high=50) == "CRITICAL"
    # Count 51-100 -> HIGH
    assert classify_severity("SYN_FLOOD", 75, syn_critical=100, syn_high=50) == "HIGH"
    # Count <= 50 -> MEDIUM / INFO
    assert classify_severity("SYN_FLOOD", 30, syn_critical=100, syn_high=50) == "MEDIUM"


def test_04_port_scan_detection():
    """Test 4: Port scan detector tracks distinct destination ports within rolling window."""
    detector = ThreatDetector()
    detector.update_thresholds(port_high=5, port_window=10.0, cooldown=0.0)

    src_ip = "192.168.1.100"
    detection = None

    # Scan 6 distinct ports to trigger high threshold > 5
    for port in range(1001, 1007):
        meta = {
            "src_ip": src_ip,
            "dst_ip": "10.0.0.1",
            "src_port": 50000,
            "dst_port": port,
            "protocol": "TCP",
            "flags": "S"
        }
        res = detector.inspect_packet(meta)
        if res:
            detection = res

    assert detection is not None
    assert detection["threat_type"] == "PORT_SCAN"
    assert detection["severity"] == "HIGH"
    assert detection["count"] >= 6


def test_05_normal_traffic_classification():
    """Test 5: Normal traffic (SYN-ACK or ACK packets) does not trigger false alerts."""
    detector = ThreatDetector()
    src_ip = "192.168.1.50"

    # Send established TCP packets with SYN+ACK
    for _ in range(50):
        meta = {
            "src_ip": src_ip,
            "dst_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "SA"  # SYN-ACK
        }
        res = detector.inspect_packet(meta)
        assert res is None  # Should NOT trigger SYN flood or alert


@pytest.mark.asyncio
async def test_06_event_persistence():
    """Test 6: Verify detected events persist to SQLite database correctly."""
    detection = {
        "threat_type": "SYN_FLOOD",
        "src_ip": "172.16.0.44",
        "dst_ip": "10.0.0.1",
        "src_port": 4444,
        "dst_port": 80,
        "protocol": "TCP",
        "count": 120,
        "severity": "CRITICAL",
        "detection_reason": "Automated unit test burst",
    }
    threat_id = await process_detection(detection, event_source="simulation")
    assert threat_id > 0

    async with await get_db() as db:
        async with db.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)) as cur:
            row = await cur.fetchone()
            assert row is not None
            assert row["src_ip"] == "172.16.0.44"
            assert row["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_07_duplicate_block_prevention():
    """Test 7: Prevent creating duplicate active blocks for the same source IP."""
    engine = ResponseEngine()
    test_ip = "198.51.100.22"

    detection = {
        "threat_type": "SYN_FLOOD",
        "src_ip": test_ip,
        "severity": "CRITICAL",
        "detection_reason": "Duplicate block check",
    }

    # Enable dry_run and auto_response for test
    await set_setting("auto_response_enabled", "true")
    await set_setting("dry_run_mode", "true")

    await engine.handle_threat(detection, threat_id=1, event_source="simulation")

    # Count blocks for this IP
    async with await get_db() as db:
        async with db.execute("SELECT COUNT(*) as c FROM blocked_ips WHERE ip = ? AND status='active'", (test_ip,)) as cur:
            count1 = (await cur.fetchone())["c"]

    assert count1 == 1

    # Second invocation should not duplicate
    await engine.handle_threat(detection, threat_id=2, event_source="simulation")

    async with await get_db() as db:
        async with db.execute("SELECT COUNT(*) as c FROM blocked_ips WHERE ip = ? AND status='active'", (test_ip,)) as cur:
            count2 = (await cur.fetchone())["c"]

    assert count2 == 1


def test_08_allowlisted_ip_protection():
    """Test 8: Allow-listed and loopback IPs are protected from blocking."""
    allowlist = ["192.168.1.1", "10.0.0.0/24"]

    safe, reason = is_safe_to_block("127.0.0.1", allowlist)
    assert not safe
    assert "Loopback" in reason

    safe2, reason2 = is_safe_to_block("192.168.1.1", allowlist)
    assert not safe2
    assert "allow-list" in reason2

    safe3, reason3 = is_safe_to_block("10.0.0.45", allowlist)
    assert not safe3
    assert "allow-list" in reason3


@pytest.mark.asyncio
async def test_09_block_expiry():
    """Test 9: Past blocks with expired timestamps are transitioned to 'expired'."""
    engine = ResponseEngine()
    expired_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

    async with await get_db() as db:
        await db.execute(
            """
            INSERT INTO blocked_ips
                (ip, threat_type, severity, reason, timestamp, expires_at, status, dry_run)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("203.0.113.88", "PORT_SCAN", "HIGH", "Expiry test", expired_time, expired_time, "active", 1),
        )
        await db.commit()

    expired_count = await engine.expire_old_blocks()
    assert expired_count >= 1

    async with await get_db() as db:
        async with db.execute("SELECT status FROM blocked_ips WHERE ip = '203.0.113.88'") as cur:
            row = await cur.fetchone()
            assert row["status"] == "expired"


def test_10_rate_limit_enforcement():
    """Test 10: Enforce hourly block limit."""
    engine = ResponseEngine()
    # Fill up rate limiter
    for _ in range(5):
        engine._block_timestamps.append(1000000.0)

    # If limit is 5, within_rate_limit should return False
    # Using small limit for test
    assert not engine._within_rate_limit(max_per_hour=5)
    assert engine._within_rate_limit(max_per_hour=10)


def test_11_dry_run_firewall_behavior():
    """Test 11: Dry-run mode never modifies actual system firewall."""
    fw = FirewallManager()
    success, msg, ref = fw.block_ip("198.51.100.99", dry_run=True)
    assert success is True
    assert "SIMULATED" in msg or "DRY-RUN" in msg
    assert "simulated_rule" in ref


def test_12_invalid_ip_rejection():
    """Test 12: Validate that malformed and non-IP strings are strictly rejected."""
    assert validate_ip("not-an-ip") is None
    assert validate_ip("999.999.999.999") is None
    assert validate_ip("192.168.1.1; rm -rf /") is None

    safe, reason = is_safe_to_block("malformed; injection")
    assert safe is False
    assert "Invalid IP" in reason


@pytest.mark.asyncio
async def test_13_csv_report_generation():
    """Test 13: Generate and verify CSV threat and incident reports."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/reports/threats.csv")
        assert res.status_code == 200
        assert res.headers["content-type"].startswith("text/csv")
        assert "Incident ID,Timestamp (UTC),Source IP" in res.text

        res_inc = await client.get("/api/reports/incidents.csv")
        assert res_inc.status_code == 200
        assert "Incident ID,Incident Type,Source IP" in res_inc.text


@pytest.mark.asyncio
async def test_14_simulation_mode_labeling():
    """Test 14: Ensure simulated events are strictly labeled as event_source='simulation'."""
    detection = {
        "threat_type": "PORT_SCAN",
        "src_ip": "198.51.100.77",
        "dst_port": 80,
        "severity": "HIGH",
        "detection_reason": "Simulation check",
    }
    threat_id = await process_detection(detection, event_source="simulation")

    async with await get_db() as db:
        async with db.execute("SELECT event_source FROM threats WHERE id = ?", (threat_id,)) as cur:
            row = await cur.fetchone()
            assert row["event_source"] == "simulation"


@pytest.mark.asyncio
async def test_15_incident_audit_logging():
    """Test 15: Significant detection/response actions generate persistent incident audit log."""
    detection = {
        "threat_type": "SYN_FLOOD",
        "src_ip": "10.0.0.88",
        "severity": "CRITICAL",
        "count": 150,
        "detection_reason": "Audit verification",
    }
    threat_id = await process_detection(detection, event_source="simulation")

    async with await get_db() as db:
        async with db.execute("SELECT * FROM incidents WHERE threat_id = ?", (threat_id,)) as cur:
            row = await cur.fetchone()
            assert row is not None
            assert row["incident_type"] == "SYN_FLOOD"
            assert row["src_ip"] == "10.0.0.88"
            assert row["severity"] == "CRITICAL"
