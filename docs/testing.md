# SILENT WITNESS — Testing Matrix & Verification Specification

The SILENT WITNESS automated test suite (`tests/test_all.py`) contains 15 comprehensive unit and integration tests executing under `pytest` with `pytest-asyncio`.

---

## 1. Test Suite Matrix

| # | Test Name | Target Module | Objective | Result |
|---|---|---|---|---|
| 1 | `test_database_initialization` | `app.database` | Verifies SQLite WAL mode, foreign keys, schema tables creation, and settings seeding | **PASSED** |
| 2 | `test_health_endpoint` | `app.main` | Validates API readiness probe (`/health`) and component statuses | **PASSED** |
| 3 | `test_syn_flood_classification` | `app.threat_detector` | Asserts severity tiering: Critical (>100), High (>50), Medium (<=50) | **PASSED** |
| 4 | `test_port_scan_detection` | `app.threat_detector` | Evaluates distinct destination port count tracking in rolling window | **PASSED** |
| 5 | `test_normal_traffic_not_flagged` | `app.threat_detector` | Asserts standard HTTP/HTTPS/DNS traffic generates zero false alerts | **PASSED** |
| 6 | `test_event_processor_persistence` | `app.event_processor` | Verifies threat events are committed to SQLite with accurate timestamps | **PASSED** |
| 7 | `test_duplicate_block_prevention` | `app.response_engine` | Asserts idempotency: already blocked IP does not produce duplicate active rules | **PASSED** |
| 8 | `test_allowlisted_ip_protection` | `app.response_engine` | Verifies `127.0.0.1`, `::1`, and configured allowlist IPs cannot be blocked | **PASSED** |
| 9 | `test_block_expiry` | `app.response_engine` | Asserts expired containment blocks transition to `expired` status | **PASSED** |
| 10 | `test_response_rate_limiting` | `app.response_engine` | Validates rate limiter rejects blocks exceeding max-per-hour limit | **PASSED** |
| 11 | `test_dry_run_firewall` | `app.firewall` | Asserts dry-run mode simulates iptables calls without executing shell commands | **PASSED** |
| 12 | `test_invalid_ip_rejection` | `app.validation` | Asserts invalid IP strings and command injection payloads are rejected | **PASSED** |
| 13 | `test_csv_report_generation` | `app.reports` | Verifies CSV export generates valid RFC 4180 headers and rows | **PASSED** |
| 14 | `test_simulation_mode_labeling` | `app.simulator` | Asserts demonstration events are strictly labeled with `event_source='simulation'` | **PASSED** |
| 15 | `test_incident_audit_trail` | `app.database` | Validates full audit logging across threat creation, triage, and review | **PASSED** |

---

## 2. Running Automated Tests

```powershell
cd silent-witness\backend
.\venv\Scripts\python.exe -m pytest -v
```
