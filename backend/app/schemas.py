"""
SILENT WITNESS – Pydantic Schemas
Request / response models for all API endpoints.
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field


# ── Threat ────────────────────────────────────────────────────────────────────

class ThreatOut(BaseModel):
    id: int
    timestamp: str
    src_ip: str
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    threat_type: str
    count: int
    severity: str
    detection_reason: Optional[str] = None
    event_source: str
    response_status: str

    class Config:
        from_attributes = True


class ThreatListResponse(BaseModel):
    threats: List[ThreatOut]
    total: int
    page: int
    page_size: int
    pages: int


# ── Blocked IP ────────────────────────────────────────────────────────────────

class BlockedIPOut(BaseModel):
    id: int
    ip: str
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    reason: Optional[str] = None
    timestamp: str
    expires_at: Optional[str] = None
    action_type: str
    status: str
    dry_run: bool
    firewall_rule_reference: Optional[str] = None

    class Config:
        from_attributes = True


class BlockedIPListResponse(BaseModel):
    blocked_ips: List[BlockedIPOut]
    total: int


class UnblockRequest(BaseModel):
    reason: Optional[str] = "Manual unblock by operator"


# ── Incident ──────────────────────────────────────────────────────────────────

class IncidentOut(BaseModel):
    id: int
    incident_type: str
    src_ip: str
    threat_id: Optional[int] = None
    timestamp: str
    severity: str
    action: Optional[str] = None
    action_status: str
    details: Optional[str] = None
    event_source: str
    reviewed: bool

    class Config:
        from_attributes = True


class IncidentListResponse(BaseModel):
    incidents: List[IncidentOut]
    total: int
    page: int
    page_size: int


class ReviewRequest(BaseModel):
    reviewed: bool = True
    notes: Optional[str] = None


# ── Traffic Stats ─────────────────────────────────────────────────────────────

class TrafficStatOut(BaseModel):
    id: int
    timestamp: str
    packets_observed: int
    suspicious_packets: int
    threats_detected: int
    unique_sources: int
    event_source: str

    class Config:
        from_attributes = True


# ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardSummary(BaseModel):
    total_threats: int
    critical_threats: int
    high_threats: int
    active_blocked_ips: int
    packets_analyzed: int
    uptime_seconds: float
    monitoring_mode: str
    monitoring_active: bool
    last_detection: Optional[str] = None


class SeverityDistribution(BaseModel):
    severity: str
    count: int


class ThreatTypeDistribution(BaseModel):
    threat_type: str
    count: int


# ── Settings ──────────────────────────────────────────────────────────────────

class SettingsOut(BaseModel):
    syn_flood_critical_threshold: int
    syn_flood_high_threshold: int
    syn_flood_window_seconds: int
    port_scan_high_threshold: int
    port_scan_window_seconds: int
    alert_cooldown_seconds: int
    dry_run_mode: bool
    auto_response_enabled: bool
    default_block_duration_min: int
    max_blocks_per_hour: int
    monitoring_mode: str
    allowlist_ips: List[str]
    data_retention_days: int
    table_density: str


class SettingsUpdate(BaseModel):
    syn_flood_critical_threshold: Optional[int] = None
    syn_flood_high_threshold: Optional[int] = None
    syn_flood_window_seconds: Optional[int] = None
    port_scan_high_threshold: Optional[int] = None
    port_scan_window_seconds: Optional[int] = None
    alert_cooldown_seconds: Optional[int] = None
    dry_run_mode: Optional[bool] = None
    auto_response_enabled: Optional[bool] = None
    default_block_duration_min: Optional[int] = None
    max_blocks_per_hour: Optional[int] = None
    monitoring_mode: Optional[str] = None
    allowlist_ips: Optional[List[str]] = None
    data_retention_days: Optional[int] = None
    table_density: Optional[str] = None


# ── Monitoring ────────────────────────────────────────────────────────────────

class MonitoringStatus(BaseModel):
    active: bool
    mode: str
    interface: Optional[str] = None
    packets_captured: int
    start_time: Optional[str] = None


class StartMonitoringRequest(BaseModel):
    interface: Optional[str] = None


# ── Simulation ────────────────────────────────────────────────────────────────

class SimulationStatus(BaseModel):
    active: bool
    speed: float
    events_generated: int
    start_time: Optional[str] = None


class SimulationControl(BaseModel):
    speed: Optional[float] = 1.0


# ── Analytics ─────────────────────────────────────────────────────────────────

class TopSourceIP(BaseModel):
    src_ip: str
    count: int
    highest_severity: str
    last_seen: str


class TopDestPort(BaseModel):
    dst_port: int
    count: int


class ProtocolDist(BaseModel):
    protocol: str
    count: int


# ── General ───────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    database: dict
    monitoring: dict
    simulation: dict
    timestamp: str


class MessageResponse(BaseModel):
    message: str
    success: bool = True
