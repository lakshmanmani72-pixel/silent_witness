"""
Integration test for Detection Explainer, Model Info, and Attack Generator endpoints.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database import init_db


@pytest.mark.asyncio
async def test_model_info_endpoint():
    """Verify GET /api/model/info returns real metrics from joblib metadata."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/model/info")
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["n_estimators"] == 100
        assert data["n_features"] == 76
        assert "BENIGN" in data["classes"]
        assert "PORT_SCAN" in data["classes"]
        assert "SYN_FLOOD" in data["classes"]
        assert data["metrics"]["accuracy"] > 0.99
        assert data["metrics"]["macro_f1"] > 0.99


@pytest.mark.asyncio
async def test_explain_endpoints():
    """Verify GET /api/explain/latest and /api/explain/recent return complete snapshots."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Latest snapshot
        res = await ac.get("/api/explain/latest")
        assert res.status_code == 200
        snap = res.json()["snapshot"]
        assert "walkthrough" in snap
        assert len(snap["walkthrough"]) == 5
        assert "tree_votes" in snap
        assert len(snap["tree_votes"]) == 100
        assert "evidence_table" in snap
        assert len(snap["evidence_table"]) > 0
        assert "attack_signature" in snap
        assert "decision_path_text" in snap

        # Recent list
        res_recent = await ac.get("/api/explain/recent")
        assert res_recent.status_code == 200
        assert "recent_detections" in res_recent.json()


@pytest.mark.asyncio
async def test_generator_endpoints():
    """Verify targeted Port Scan and SYN Flood generators start and report status."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Port scan generator
        res_ps = await ac.post("/api/simulation/generate-port-scan", json={"target": "127.0.0.1", "duration_sec": 4, "port_range": "20-80"})
        assert res_ps.status_code == 200
        assert res_ps.json()["success"] is True

        # Check status
        res_st = await ac.get("/api/simulation/generator-status")
        assert res_st.status_code == 200
        assert res_st.json()["generator"]["active"] is True
        assert res_st.json()["generator"]["attack_type"] == "PORT_SCAN"

        # Stop
        res_stop = await ac.post("/api/simulation/stop-generator")
        assert res_stop.status_code == 200

        # 2. SYN flood generator
        res_sf = await ac.post("/api/simulation/generate-syn-flood", json={"target": "127.0.0.1", "duration_sec": 4})
        assert res_sf.status_code == 200
        assert res_sf.json()["success"] is True

        # Stop
        res_stop = await ac.post("/api/simulation/stop-generator")
        assert res_stop.status_code == 200

