"""
SILENT WITNESS - Monitoring and Simulation Control API
Endpoints for starting, stopping, and inspecting both Live Packet Capture
and Educational Simulation modes, including Wireshark-style packet ring buffers.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, Any, Dict
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.simulator import get_simulator
from app.services.packet_capture import (
    get_capture,
    get_interfaces,
    get_interfaces_detailed,
    get_best_interface,
    resolve_interface,
    SCAPY_AVAILABLE,
)
from app.services.threat_detector import get_detector
from app.services.event_processor import process_detection
from app.services.ml_detector import get_ml_detector
from app.services.flow_aggregator import get_flow_aggregator

logger = logging.getLogger("silent_witness.api.monitoring")

router = APIRouter(prefix="/api", tags=["monitoring"])


class StartMonitoringPayload(BaseModel):
    interface: Optional[str] = None


class SimulationControlPayload(BaseModel):
    speed: Optional[float] = 1.0
    scenario: Optional[str] = "mixed"


class ScenarioPayload(BaseModel):
    scenario: str


class SpeedPayload(BaseModel):
    speed: float


class InjectTrafficPayload(BaseModel):
    type: str = "normal"  # "syn_flood", "port_scan", "normal", "ping", "dns", "suspicious_flags"
    count: int = 25


# ── Live Monitoring & Packet Dissection Endpoints ──────────────────────────

@router.get("/monitoring/interfaces")
async def list_network_interfaces():
    """List available network interfaces for live capture, with detailed hardware, IP, and MAC info."""
    interfaces = get_interfaces()
    detailed = get_interfaces_detailed()
    best = get_best_interface()
    return {
        "scapy_available": SCAPY_AVAILABLE,
        "interfaces": interfaces,
        "interfaces_detailed": detailed,
        "best_interface": best,
        "count": len(interfaces),
        "note": (
            "Live monitoring passively captures network metadata. "
            "On Windows, Npcap or WinPcap driver is required."
            if not SCAPY_AVAILABLE or not interfaces
            else "Available for authorized local monitoring."
        )
    }


@router.get("/monitoring/recent-packets")
@router.get("/packets/recent")
async def get_recent_packets(
    limit: int = 100,
    protocol: Optional[str] = None,
    search: Optional[str] = None,
):
    """Return the recent packet capture ring buffer for Wireshark-style inspection."""
    cap = get_capture()
    packets = cap.get_recent_packets(limit=limit, protocol=protocol, search=search)
    return {
        "success": True,
        "total_captured": cap.packets_captured,
        "active": cap.is_live,
        "interface": cap.interface or "NONE",
        "count": len(packets),
        "packets": packets,
    }


@router.post("/packets/clear")
async def clear_packet_buffer():
    """Flush and clear the live packet ring buffer."""
    cap = get_capture()
    cap.clear_packets()
    return {"message": "Packet buffer successfully cleared"}


@router.post("/monitoring/inject-traffic")
async def inject_test_traffic(payload: InjectTrafficPayload):
    """
    Synthesize and ingest test packets directly into the live inspection and detection pipeline.
    Used for live demonstrations to illustrate instant threat detection and containment.
    """
    cap = get_capture()
    detector = get_detector()
    main_loop = asyncio.get_running_loop()

    def _detector_cb(meta: dict):
        det = detector.inspect_packet(meta)
        if det:
            cap.record_detection_stat(is_threat=True)
            asyncio.run_coroutine_threadsafe(
                process_detection(det, event_source="simulation"),
                main_loop
            )
            return det
        return None

    injected = cap.inject_synthetic_traffic(
        traffic_type=payload.type,
        count=min(max(payload.count, 1), 100),
        detector_callback=_detector_cb,
    )
    return {
        "message": f"Successfully injected {len(injected)} {payload.type} test packets into inspection engine.",
        "count": len(injected),
        "type": payload.type,
    }


@router.get("/monitoring/status")
async def get_monitoring_status():
    """Get active monitoring status for both live and simulation modes."""
    cap = get_capture()
    sim = get_simulator()
    ml = get_ml_detector()
    agg = get_flow_aggregator()

    from app.database import get_setting
    auto_response = await get_setting("auto_response_enabled", False)
    dry_run = await get_setting("dry_run_mode", True)

    if sim.status["running"]:
        capture_status = "SIMULATION"
    elif cap.is_live:
        capture_status = "LIVE"
    elif cap.status_name == "STARTING":
        capture_status = "STARTING"
    elif cap.status_name == "ERROR":
        capture_status = "ERROR"
    else:
        capture_status = "STOPPED"

    return {
        "success": True,
        "active": cap.is_live or sim.status["active"],
        "capture_status": capture_status,
        "mode": capture_status.lower(),
        "blocking_mode": "automatic" if auto_response else "manual",
        "auto_response_enabled": auto_response,
        "dry_run_mode": dry_run,
        "live_capture": {
            "active": cap.is_live,
            "status": cap.status_name,
            "interface": cap.interface,
            "packets_captured": cap.packets_captured,
            "scapy_available": SCAPY_AVAILABLE,
            "error": cap.last_error,
        },
        "simulation": sim.status,
        "ml_model": ml.get_status(),
        "flow_aggregator": agg.get_status(),
    }


@router.get("/ml/status")
async def get_ml_status():
    """Return machine learning flow classifier model details and telemetry."""
    ml = get_ml_detector()
    agg = get_flow_aggregator()
    return {
        "status": "healthy" if ml.loaded else "unloaded",
        "model": ml.get_status(),
        "flow_aggregator": agg.get_status(),
    }


class ToggleBlockingModePayload(BaseModel):
    mode: str  # "manual" | "automatic"
    confidence_threshold: Optional[float] = 0.80


@router.post("/monitoring/toggle-blocking-mode")
async def toggle_blocking_mode(payload: ToggleBlockingModePayload):
    """Switch between Manual and Automatic blocking modes."""
    from app.database import set_setting
    target_mode = payload.mode.lower()
    if target_mode not in ("manual", "automatic"):
        raise HTTPException(status_code=400, detail="Mode must be either 'manual' or 'automatic'")
    auto_enabled = (target_mode == "automatic")
    await set_setting("auto_response_enabled", auto_enabled)
    logger.info("Operator changed blocking mode to: %s", target_mode)
    return {
        "success": True,
        "blocking_mode": target_mode,
        "auto_response_enabled": auto_enabled,
        "message": f"Blocking mode successfully switched to {target_mode.upper()}."
    }


class PredictFlowPayload(BaseModel):
    features: dict[str, Any]


class ExplainFlowPayload(BaseModel):
    features: Optional[dict[str, Any]] = None
    threat_type: Optional[str] = None


@router.post("/ml/predict")
async def predict_flow_sample(payload: PredictFlowPayload):
    """Predict attack class for an input flow feature dictionary."""
    ml = get_ml_detector()
    res = ml.predict_flow(payload.features)
    return res


@router.post("/ml/explain")
async def explain_flow_sample(payload: ExplainFlowPayload = ExplainFlowPayload()):
    """
    Explain a prediction using the trained Random Forest model:
    Returns class probabilities, Tree #0 decision steps, top influential features,
    and rule vs ML agreement evaluation.
    """
    ml = get_ml_detector()
    if payload.features:
        res = ml.explain_flow_prediction(payload.features, threat_type=payload.threat_type)
    else:
        target = payload.threat_type or "SYN_FLOOD"
        res = ml.get_sample_explanation(threat_type=target)
    return res


@router.get("/ml/tree-explanation")
async def get_tree_explanation(threat_type: Optional[str] = "SYN_FLOOD"):
    """
    Return step-by-step decision path through Tree #0 of the Random Forest
    and feature attribution table for the specified attack type or current active flow.
    """
    ml = get_ml_detector()
    fa = get_flow_aggregator()
    # If active flow aggregator has features from a live/sim flow, use them
    features = None
    if fa and fa.last_prediction and "features" in fa.last_prediction:
        features = fa.last_prediction["features"]

    if features:
        return ml.explain_flow_prediction(features, threat_type=threat_type)
    return ml.get_sample_explanation(threat_type=threat_type or "SYN_FLOOD")



@router.post("/monitoring/start")
async def start_monitoring(payload: StartMonitoringPayload = StartMonitoringPayload()):
    """Start live network packet capture on selected or default interface."""
    cap = get_capture()
    sim = get_simulator()

    if cap.is_live:
        return {
            "success": True,
            "status": "LIVE",
            "message": f"Live packet capture is already active on {cap.interface}",
            "interface": cap.interface,
            "mode": "live",
        }

    # If simulation is active, stop it when transitioning to live
    if sim.status["running"]:
        await sim.stop()

    if not SCAPY_AVAILABLE:
        raise HTTPException(
            status_code=400,
            detail=(
                "Scapy or compatible packet capture driver (Npcap on Windows) is not available. "
                "Ensure Npcap is installed with Administrator privileges from https://npcap.com/"
            )
        )

    interfaces = get_interfaces()
    if not interfaces:
        raise HTTPException(
            status_code=400,
            detail="No network interfaces found. Ensure Npcap driver is installed or run with Administrator privileges."
        )

    target_iface = payload.interface or get_best_interface() or (interfaces[0] if interfaces else "")
    resolved = resolve_interface(target_iface)
    if (target_iface not in interfaces) and (resolved == target_iface):
        raise HTTPException(
            status_code=400,
            detail=f"Interface '{target_iface}' not found. Available: {interfaces}"
        )

    detector = get_detector()
    main_loop = asyncio.get_running_loop()

    def on_packet_metadata(meta: dict):
        detection = detector.inspect_packet(meta)
        if detection:
            cap.record_detection_stat(is_threat=True)
            asyncio.run_coroutine_threadsafe(
                process_detection(detection, event_source="live"),
                main_loop
            )
            return detection
        return None

    try:
        cap.start(target_iface, on_packet_metadata)
    except Exception as ex:
        logger.error("Failed to start live capture on '%s': %s", target_iface, ex)
        raise HTTPException(status_code=400, detail=f"Failed to start live capture: {str(ex)}")

    display_name = cap.interface or str(target_iface)
    return {
        "success": True,
        "status": "LIVE",
        "message": f"Live packet capture started on {display_name}",
        "interface": display_name,
        "mode": "live",
        "warning": "Passive observation mode active. Payload data is never stored."
    }


@router.post("/monitoring/stop")
async def stop_monitoring():
    """Stop active live monitoring and/or simulation."""
    cap = get_capture()
    sim = get_simulator()

    stopped_live = False
    stopped_sim = False

    if cap.active:
        cap.stop()
        stopped_live = True

    if sim.status["running"]:
        await sim.stop()
        stopped_sim = True

    return {
        "success": True,
        "status": "STOPPED",
        "message": "Monitoring stopped",
        "stopped_live": stopped_live,
        "stopped_sim": stopped_sim
    }


# ── Simulation Control Endpoints ────────────────────────────────────────────

@router.post("/simulation/start")
async def start_simulation(payload: SimulationControlPayload = SimulationControlPayload()):
    """Start generating clearly labeled demonstration traffic events."""
    cap = get_capture()
    if cap.active:
        cap.stop()

    sim = get_simulator()
    await sim.start(speed=payload.speed or 1.0, scenario=payload.scenario or "mixed")
    return {
        "message": "Demonstration simulation started",
        "mode": "simulation",
        "status": sim.status
    }


@router.post("/simulation/pause")
async def pause_simulation():
    """Pause the demonstration traffic simulator."""
    sim = get_simulator()
    await sim.pause()
    return {"message": "Simulation paused", "status": sim.status}


@router.post("/simulation/resume")
async def resume_simulation():
    """Resume a paused demonstration simulator."""
    sim = get_simulator()
    await sim.resume()
    return {"message": "Simulation resumed", "status": sim.status}


@router.post("/simulation/stop")
async def stop_simulation():
    """Stop the demonstration traffic simulator."""
    sim = get_simulator()
    await sim.stop()
    return {"message": "Simulation stopped", "status": sim.status}


@router.post("/simulation/reset")
async def reset_simulation():
    """Reset the demonstration traffic simulator counters and detector state."""
    sim = get_simulator()
    await sim.reset()
    return {"message": "Simulation and detector state reset", "status": sim.status}


@router.post("/simulation/scenario")
async def set_simulation_scenario(payload: ScenarioPayload):
    """Switch simulation scenario on the fly (normal, syn_flood, port_scan, suspicious_flags, mixed)."""
    sim = get_simulator()
    if not sim.status["running"] or sim.status["paused"]:
        await sim.start(speed=sim.status.get("speed", 1.0) or 1.0, scenario=payload.scenario)
    else:
        sim.set_scenario(payload.scenario)
    return {"message": f"Simulation scenario switched to {payload.scenario}", "status": sim.status}


@router.post("/simulation/speed")
async def set_simulation_speed(payload: SpeedPayload):
    """Change simulation speed multiplier on the fly."""
    sim = get_simulator()
    sim.set_speed(payload.speed)
    return {"message": f"Simulation speed set to {payload.speed}x", "status": sim.status}


@router.get("/simulation/status")
async def get_simulation_status():
    """Get detailed simulation status with real-time calculated metrics."""
    sim = get_simulator()
    return sim.status


@router.post("/monitoring/clear-sample-data")
async def clear_sample_data():
    """Purge simulated demonstration records from database so only real-time live events remain."""
    from app.database import get_db
    async with await get_db() as db:
        await db.execute("DELETE FROM threats WHERE event_source='simulation'")
        await db.execute("DELETE FROM incidents WHERE event_source='simulation'")
        await db.execute("DELETE FROM traffic_stats WHERE event_source='simulation'")
        await db.commit()
    return {"message": "All simulation/sample records cleared successfully."}


@router.post("/monitoring/clear-all")
async def clear_all_events():
    """Clear all recorded events, traffic stats, and blocked IPs for a clean slate."""
    from app.database import get_db
    async with await get_db() as db:
        await db.execute("DELETE FROM threats")
        await db.execute("DELETE FROM incidents")
        await db.execute("DELETE FROM traffic_stats")
        await db.execute("DELETE FROM blocked_ips")
        await db.commit()
    return {"message": "All database events and telemetry reset."}


# ── Targeted Attack Generator Endpoints (Port Scan & SYN Flood) ─────────────

class GenerateAttackPayload(BaseModel):
    target: Optional[str] = "127.0.0.1"
    duration_sec: Optional[int] = 10
    port_range: Optional[str] = "1-1024"


def _validate_safe_lab_target(target: str) -> str:
    target_clean = (target or "").strip().lower()
    if target_clean in ("localhost", "127.0.0.1", "::1"):
        return "127.0.0.1"
    import ipaddress
    try:
        ip = ipaddress.ip_address(target_clean)
        if ip.is_loopback or ip.is_private:
            return str(ip)
    except ValueError:
        pass
    raise HTTPException(
        status_code=400,
        detail="Security restriction: Target must be localhost (127.0.0.1) or a private lab address (e.g. 192.168.x.x, 10.x.x.x). External attacks are strictly prohibited."
    )


@router.post("/simulation/generate-port-scan")
async def generate_port_scan(payload: GenerateAttackPayload = GenerateAttackPayload()):
    """Trigger a manual Port Scan attack generation with duration limit against lab/local target."""
    target = _validate_safe_lab_target(payload.target or "127.0.0.1")
    sim = get_simulator()
    status = await sim.start_attack_generator(
        attack_type="PORT_SCAN",
        target_ip=target,
        duration_sec=payload.duration_sec or 10,
        port_range=payload.port_range or "1-1024",
    )
    return {
        "success": True,
        "message": f"Port Scan generation started against {target} for {status['duration_limit']}s",
        "generator": status,
    }


@router.post("/simulation/generate-syn-flood")
async def generate_syn_flood(payload: GenerateAttackPayload = GenerateAttackPayload()):
    """Trigger a manual SYN Flood attack generation with duration limit against lab/local target."""
    target = _validate_safe_lab_target(payload.target or "127.0.0.1")
    sim = get_simulator()
    status = await sim.start_attack_generator(attack_type="SYN_FLOOD", target_ip=target, duration_sec=payload.duration_sec or 10)
    return {
        "success": True,
        "message": f"SYN Flood generation started against {target} for {status['duration_limit']}s",
        "generator": status,
    }


@router.post("/simulation/stop-generator")
async def stop_attack_generator():
    """Stop active manual attack generator."""
    sim = get_simulator()
    status = await sim.stop_attack_generator()
    return {
        "success": True,
        "message": "Attack generator stopped.",
        "generator": status,
    }


@router.get("/simulation/generator-status")
async def get_generator_status():
    """Return live status of the manual attack generator."""
    sim = get_simulator()
    return {
        "success": True,
        "generator": sim.generator_status,
    }
