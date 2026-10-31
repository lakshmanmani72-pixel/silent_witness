"""
SILENT WITNESS - Main FastAPI Application
Real-Time Network Intrusion Detection & Automated Response System
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.config import APP_NAME, APP_VERSION, ALLOWED_ORIGINS
from app.database import init_db, db_health
from app.services.response_engine import get_response_engine
from app.services.event_processor import set_ws_broadcaster
from app.services.simulator import get_simulator
from app.services.packet_capture import (
    get_capture,
    get_best_interface,
    set_packet_broadcaster,
    SCAPY_AVAILABLE,
)
from app.services.threat_detector import get_detector
from app.services.event_processor import process_detection, record_traffic_stat

# Import all API routers
from app.api.dashboard import router as dashboard_router
from app.api.threats import router as threats_router
from app.api.blocked_ips import router as blocked_ips_router
from app.api.incidents import router as incidents_router
from app.api.analytics import router as analytics_router
from app.api.settings import router as settings_router
from app.api.monitoring import router as monitoring_router
from app.api.reports import router as reports_router
from app.api.explainer import router as explainer_router

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("silent_witness")

# Connected WebSocket clients
_active_websockets: Set[WebSocket] = set()


async def broadcast_ws_message(message: dict):
    """Broadcast JSON message to all connected real-time dashboard clients."""
    if not _active_websockets:
        return
    dead_sockets = set()
    for ws in list(_active_websockets):
        try:
            if getattr(ws, "client_state", None) is not None and ws.client_state.name != "CONNECTED":
                dead_sockets.add(ws)
                continue
            await ws.send_json(message)
        except (WebSocketDisconnect, ConnectionResetError, BrokenPipeError):
            dead_sockets.add(ws)
        except Exception:
            dead_sockets.add(ws)
    for ws in dead_sockets:
        _active_websockets.discard(ws)


async def _expiry_worker():
    """Background task to periodically expire timed-out IP blocks."""
    engine = get_response_engine()
    while True:
        try:
            await asyncio.sleep(30)
            await engine.expire_old_blocks()
        except asyncio.CancelledError:
            break
        except Exception as ex:
            logger.error("Error in expiry worker: %s", ex)


async def _live_telemetry_worker():
    """Background task to record live real-time packet telemetry into SQLite."""
    cap = get_capture()
    while True:
        try:
            await asyncio.sleep(3)
            if cap.active:
                stats = cap.flush_stats()
                if stats["packets"] > 0:
                    await record_traffic_stat(
                        packets=stats["packets"],
                        suspicious=stats["suspicious"],
                        threats=stats["threats"],
                        unique_sources=stats["unique_sources"],
                        event_source="live"
                    )
        except asyncio.CancelledError:
            break
        except Exception as ex:
            logger.debug("Live telemetry worker notice: %s", ex)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──
    logger.info("Initializing SILENT WITNESS database and real-time defensive engine...")
    await init_db()
    set_ws_broadcaster(broadcast_ws_message)
    set_packet_broadcaster(broadcast_ws_message, asyncio.get_running_loop())

    # Start block expiry and live telemetry background tasks
    expiry_task = asyncio.create_task(_expiry_worker(), name="block_expiry_worker")
    telemetry_task = asyncio.create_task(_live_telemetry_worker(), name="live_telemetry_worker")

    # Inspect driver and default interface
    best_iface = get_best_interface()
    if SCAPY_AVAILABLE:
        logger.info("Scapy/Npcap driver available. Detected default network adapter: '%s'", best_iface or "None")
    else:
        logger.warning("Scapy/Npcap driver unavailable or no active network adapter found.")

    logger.info("SILENT WITNESS services ready. Monitoring status: STOPPED.")

    yield

    # ── Shutdown ──
    logger.info("Shutting down SILENT WITNESS services...")
    expiry_task.cancel()
    telemetry_task.cancel()
    try:
        await expiry_task
    except asyncio.CancelledError:
        pass
    try:
        await telemetry_task
    except asyncio.CancelledError:
        pass

    if cap.active:
        cap.stop()

    sim = get_simulator()
    if sim.status["running"]:
        await sim.stop()

    # Close websockets
    for ws in list(_active_websockets):
        try:
            await ws.close()
        except Exception:
            pass
    _active_websockets.clear()


app = FastAPI(
    title=f"{APP_NAME} - Network Intrusion Detection & Response System",
    description="Real-Time Network Intrusion Detection & Automated Response SOC Application",
    version=APP_VERSION,
    lifespan=lifespan
)

# CORS Middleware for local frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS + ["*"],  # Friendly for local dev setups
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(dashboard_router)
app.include_router(threats_router)
app.include_router(blocked_ips_router)
app.include_router(incidents_router)
app.include_router(analytics_router)
app.include_router(settings_router)
app.include_router(monitoring_router)
app.include_router(reports_router)
app.include_router(explainer_router)


# ── Health Check ────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    """Application health and status summary."""
    sim = get_simulator()
    cap = get_capture()
    db_status = await db_health()

    if sim.status["running"]:
        status_name = "SIMULATION"
    elif cap.is_live:
        status_name = "LIVE"
    elif cap.status_name == "STARTING":
        status_name = "STARTING"
    elif cap.status_name == "ERROR":
        status_name = "ERROR"
    else:
        status_name = "STOPPED"

    return {
        "status": "healthy" if db_status.get("status") == "healthy" else "degraded",
        "name": APP_NAME,
        "version": APP_VERSION,
        "database": db_status,
        "monitoring": {
            "mode": status_name.lower(),
            "capture_status": status_name,
            "live_capture_active": cap.is_live,
            "scapy_available": SCAPY_AVAILABLE,
            "error": cap.last_error,
        },
        "simulation": sim.status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── WebSocket Real-Time Events ──────────────────────────────────────────────

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket endpoint for real-time detection notifications."""
    await websocket.accept()
    _active_websockets.add(websocket)
    logger.info("WebSocket client connected. Total clients: %d", len(_active_websockets))

    # Send initial welcome / status packet
    try:
        await websocket.send_json({
            "type": "connection_established",
            "message": "Connected to Silent Witness SOC Event Stream",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        while True:
            try:
                # Wait for client message or send periodic keepalive heartbeat (15s)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=15.0)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send server-initiated heartbeat only if connection is still active
                if getattr(websocket, "client_state", None) is not None and websocket.client_state.name == "CONNECTED":
                    await websocket.send_json({
                        "type": "heartbeat",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                else:
                    break
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected normally")
    except (ConnectionResetError, BrokenPipeError):
        logger.debug("WebSocket client connection reset or aborted")
    except Exception as ex:
        logger.debug("WebSocket exception: %s", ex)
    finally:
        _active_websockets.discard(websocket)
