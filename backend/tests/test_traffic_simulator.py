"""
SILENT WITNESS – Network Traffic Simulator Test Suite
Verifies:
  1. Simulator lifecycle controls (start, pause, resume, stop, reset)
  2. Scenario A: Normal traffic generation and accurate metric accumulation
  3. Scenario B: SYN flood burst crossing detection threshold and raising explainable threat
  4. Scenario C: Port scan sequence crossing threshold and raising explainable threat
  5. Scenario D: Suspicious TCP flags probe (NULL, FIN, XMAS) detection
  6. Explainable evidence completeness (observed count vs threshold, simple & technical reasons)
  7. No hardcoded metrics (all counters strictly tied to actual generated events)
"""

import pytest
import asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app as fastapi_app
from app.services.simulator import TrafficSimulator
from app.services.threat_detector import get_detector


@pytest.fixture
def sim():
    instance = TrafficSimulator()
    yield instance
    # Clean teardown
    if instance._task and not instance._task.done():
        instance._task.cancel()


@pytest.mark.asyncio
async def test_simulator_lifecycle_controls(sim):
    """Verify start, pause, resume, stop, and reset controls."""
    await sim.reset()

    # Initial state
    assert not sim.status["running"]
    assert sim.status["packets_generated"] == 0

    # Start simulation in normal scenario
    await sim.start(speed=5.0, scenario="normal")
    assert sim.status["running"]
    assert not sim.status["paused"]
    assert sim.status["scenario"] == "normal"

    # Let it run briefly
    await asyncio.sleep(0.3)
    assert sim.status["packets_generated"] > 0
    assert sim.status["packets_processed"] == sim.status["packets_generated"]
    assert sim.status["normal_packets"] > 0

    # Pause
    await sim.pause()
    assert sim.status["paused"]
    await asyncio.sleep(0.1)
    count_after_pause = sim.status["packets_generated"]
    await asyncio.sleep(0.2)
    # Packets should not increase while paused
    assert sim.status["packets_generated"] == count_after_pause

    # Resume
    await sim.resume()
    assert not sim.status["paused"]
    await asyncio.sleep(0.2)
    assert sim.status["packets_generated"] > count_after_pause

    # Stop
    await sim.stop()
    assert not sim.status["running"]

    # Reset
    await sim.reset()
    assert sim.status["packets_generated"] == 0
    assert sim.status["normal_packets"] == 0
    assert sim.status["threats_detected"] == 0


@pytest.mark.asyncio
async def test_scenario_syn_flood_detection_and_explainability(sim):
    """Verify SYN flood burst triggers detection with complete explainable evidence."""
    detector = get_detector()
    await sim.reset()

    # Configure detector thresholds for predictable test
    detector.update_thresholds(syn_critical=100, syn_high=30, syn_window=10.0, cooldown=0.1)

    # Trigger SYN flood bursts
    await sim._simulate_syn_flood_burst(burst_size=35)

    assert sim.status["packets_generated"] >= 35
    assert sim.status["threats_detected"] >= 1
    assert len(sim.status["recent_threats"]) >= 1

    threat = sim.status["recent_threats"][-1]
    assert threat["threat_type"] == "SYN_FLOOD"
    assert threat["severity"] in ("HIGH", "CRITICAL")
    assert threat["count"] > 30
    assert threat["threshold"] in (30, 100)
    assert "simple_explanation" in threat
    assert "technical_reason" in threat
    assert "recommended_response" in threat
    assert "response_status" in threat

    # Ensure explanation contains observed count and threshold
    assert str(threat["count"]) in threat["simple_explanation"]
    assert str(threat["threshold"]) in threat["simple_explanation"]

    # Attacker IP should be marked blocked
    assert threat["src_ip"] in sim.status["blocked_ips"]

    await sim.stop()


@pytest.mark.asyncio
async def test_scenario_port_scan_detection(sim):
    """Verify Port Scan triggers alert when distinct port threshold is reached."""
    detector = get_detector()
    await sim.reset()

    # Lower port scan threshold for test
    detector.update_thresholds(port_high=20, port_window=60.0, cooldown=0.1)

    await sim._simulate_port_scan_sequence(num_ports=25)

    assert sim.status["threats_detected"] >= 1
    threat = sim.status["recent_threats"][-1]
    assert threat["threat_type"] == "PORT_SCAN"
    assert threat["count"] > 20
    assert "simple_explanation" in threat
    assert "technical_reason" in threat

    await sim.stop()


@pytest.mark.asyncio
async def test_scenario_stealth_flags_detection(sim):
    """Verify NULL, FIN, or XMAS stealth probes are detected."""
    detector = get_detector()
    await sim.reset()

    # Directly test stealth probe inspection
    meta = {
        "src_ip": "172.16.5.200",
        "dst_ip": "192.168.1.1",
        "src_port": 45000,
        "dst_port": 80,
        "protocol": "TCP",
        "flags": "FPU",  # XMAS scan
    }
    detection = detector.inspect_packet(meta)
    assert detection is not None
    assert detection["threat_type"] == "SUSPICIOUS"
    assert "XMAS Scan" in detection["detection_reason"]
    assert "simple_explanation" in detection
    assert "RFC 793" in detection["technical_reason"]


@pytest.mark.asyncio
async def test_simulation_api_endpoints():
    """Verify REST API endpoints for simulation control and status."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Start
        res = await ac.post("/api/simulation/start", json={"speed": 2.0, "scenario": "normal"})
        assert res.status_code == 200
        data = res.json()
        assert data["mode"] == "simulation"
        assert data["status"]["running"] is True

        # Switch Scenario
        res_scen = await ac.post("/api/simulation/scenario", json={"scenario": "syn_flood"})
        assert res_scen.status_code == 200
        assert res_scen.json()["status"]["scenario"] == "syn_flood"

        # Change Speed
        res_spd = await ac.post("/api/simulation/speed", json={"speed": 3.0})
        assert res_spd.status_code == 200
        assert res_spd.json()["status"]["speed"] == 3.0

        # Status
        res_stat = await ac.get("/api/simulation/status")
        assert res_stat.status_code == 200
        status = res_stat.json()
        assert "packets_generated" in status
        assert "current_rate" in status
        assert "protocol_distribution" in status

        # Stop
        res_stop = await ac.post("/api/simulation/stop")
        assert res_stop.status_code == 200
        assert res_stop.json()["status"]["running"] is False

        # Reset
        res_reset = await ac.post("/api/simulation/reset")
        assert res_reset.status_code == 200
        assert res_reset.json()["status"]["packets_generated"] == 0
