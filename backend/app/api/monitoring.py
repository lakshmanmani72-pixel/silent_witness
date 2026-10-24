"""
SILENT WITNESS - Monitoring and Simulation Control API
Endpoints for starting, stopping, and inspecting both Live Packet Capture
and Educational Simulation modes.
"""

from __future__ import annotations
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.services.simulator import get_simulator
from app.services.packet_capture import get_capture, get_interfaces, SCAPY_AVAILABLE
from app.services.threat_detector import get_detector
from app.services.event_processor import process_detection

logger = logging.getLogger("silent_witness.api.monitoring")

router = APIRouter(prefix="/api", tags=["monitoring"])


class StartMonitoringPayload(BaseModel):
    interface: Optional[str] = None


class SimulationControlPayload(BaseModel):
    speed: Optional[float] = 1.0


# ── Live Monitoring Endpoints ───────────────────────────────────────────────

@router.get("/monitoring/interfaces")
async def list_network_interfaces():
    """List available network interfaces for live capture, noting Scapy/Npcap availability."""
    interfaces = get_interfaces()
    return {
        "scapy_available": SCAPY_AVAILABLE,
        "interfaces": interfaces,
        "count": len(interfaces),
        "note": (
            "Live monitoring passively captures network metadata. "
            "On Windows, Npcap or WinPcap driver is required."
            if not SCAPY_AVAILABLE or not interfaces
            else "Available for authorized local monitoring."
        )
    }


@router.get("/monitoring/status")
async def get_monitoring_status():
    """Get active monitoring status for both live and simulation modes."""
    cap = get_capture()
    sim = get_simulator()

    current_mode = "simulation" if sim.status["running"] else ("live" if cap.active else "idle")

    return {
        "active": cap.active or sim.status["active"],
        "mode": current_mode,
        "live_capture": {
            "active": cap.active,
            "interface": cap.interface,
            "packets_captured": cap.packets_captured,
            "scapy_available": SCAPY_AVAILABLE
        },
        "simulation": sim.status
    }


@router.post("/monitoring/start")
async def start_monitoring(payload: StartMonitoringPayload = StartMonitoringPayload()):
    """Start live network packet capture on selected or default interface."""
    cap = get_capture()
    sim = get_simulator()

    if cap.active:
        return {"message": "Live monitoring is already active", "interface": cap.interface}

    # If simulation is active, stop it when transitioning to live
    if sim.status["running"]:
        await sim.stop()

    if not SCAPY_AVAILABLE:
        raise HTTPException(
            status_code=400,
            detail=(
                "Scapy or compatible packet capture driver (Npcap on Windows) is not available. "
                "Please run in Simulation Mode for college demonstration."
            )
        )

    interfaces = get_interfaces()
    if not interfaces:
        raise HTTPException(
            status_code=400,
            detail="No network interfaces found. Ensure capture drivers are installed or use Simulation Mode."
        )

    from app.services.packet_capture import get_best_interface, resolve_interface
    target_iface = payload.interface or get_best_interface() or (interfaces[0] if interfaces else "")
    resolved = resolve_interface(target_iface)
    if (target_iface not in interfaces) and (resolved == target_iface):
        raise HTTPException(
            status_code=400,
            detail=f"Interface '{target_iface}' not found. Available: {interfaces}"
        )

    detector = get_detector()

    # Callback called for each packet metadata in the capture thread
    import asyncio
    main_loop = asyncio.get_running_loop()

    def on_packet_metadata(meta: dict):
        detection = detector.inspect_packet(meta)
        if detection:
            cap.record_detection_stat(is_threat=True)
            asyncio.run_coroutine_threadsafe(
                process_detection(detection, event_source="live"),
                main_loop
            )

    try:
        cap.start(target_iface, on_packet_metadata)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Failed to start live capture: {str(ex)}")

    return {
        "message": f"Live packet capture started on {cap.interface or target_iface}",
        "interface": cap.interface or target_iface,
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
    await sim.start(speed=payload.speed or 1.0)
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


@router.get("/simulation/status")
async def get_simulation_status():
    """Get detailed simulation status."""
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
