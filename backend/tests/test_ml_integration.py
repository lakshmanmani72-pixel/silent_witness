"""
SILENT WITNESS - ML Flow Aggregation & Inference Integration Tests
==================================================================
Tests the end-to-end Machine Learning pipeline:
  1. ML Model Artifact Loading & 76-Feature Schema
  2. Bidirectional Flow Feature Extraction
  3. ML Prediction: BENIGN traffic
  4. ML Prediction: SYN_FLOOD traffic
  5. ML Prediction: PORT_SCAN traffic
  6. Threat Detector Integration (Heuristics + ML)
  7. Safe Dry-Run Advisory (Requirement 10: No Auto-Block solely on ML)
  8. Event Persistence to SQLite & Incident Log
  9. ML API Status & Prediction Endpoints
"""

import os
import sys
import tempfile
import time
import pytest
from httpx import AsyncClient, ASGITransport

# Set testing environment before loading app
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
os.close(temp_db_fd)
os.environ["TESTING"] = "1"

import app.config
app.config.DATABASE_URL = temp_db_path
import app.database
app.database._db_path = temp_db_path

from app.database import init_db, get_db
from app.services.ml_detector import get_ml_detector
from app.services.flow_aggregator import FlowSession, FlowAggregator, get_flow_aggregator
from app.services.threat_detector import ThreatDetector
from app.services.event_processor import process_detection
from app.services.response_engine import get_response_engine
from app.main import app as fastapi_app


@pytest.fixture(autouse=True)
async def setup_test_db():
    """Initialise isolated test database for every test."""
    await init_db()
    yield


def test_01_ml_model_loading():
    """Test 1: Verify model artifact is loaded with 76 features and 3 classes."""
    ml = get_ml_detector()
    assert ml.loaded is True, "ML Model artifact should be loaded"
    assert len(ml.feature_names) == 76, f"Expected 76 features, got {len(ml.feature_names)}"
    assert set(ml.class_names) == {"BENIGN", "PORT_SCAN", "SYN_FLOOD"}
    status = ml.get_status()
    assert status["loaded"] is True
    assert status["feature_count"] == 76


def test_02_flow_feature_extraction():
    """Test 2: Verify FlowSession extracts all 76 features with valid numeric values."""
    now = time.time()
    session = FlowSession("192.168.1.10", 45000, "10.0.0.1", 80, "TCP", now)

    # Add forward packet (SYN)
    session.add_packet(now, is_fwd=True, length=60, header_len=20, flags="S", window=64240, payload_len=0)
    # Add backward packet (SYN-ACK)
    session.add_packet(now + 0.005, is_fwd=False, length=60, header_len=20, flags="SA", window=65535, payload_len=0)

    features = session.extract_features()
    ml = get_ml_detector()

    # Verify all 76 expected feature keys exist
    for feat_name in ml.feature_names:
        assert feat_name in features, f"Missing feature: {feat_name}"
        assert isinstance(features[feat_name], (int, float)), f"Non-numeric feature: {feat_name}"

    assert features["Total Fwd Packets"] == 1.0
    assert features["Total Backward Packets"] == 1.0
    assert features["SYN Flag Count"] == 2.0  # 1 fwd S + 1 bwd SA
    assert features["ACK Flag Count"] == 1.0
    assert features["Init_Win_bytes_forward"] == 64240.0
    assert features["Init_Win_bytes_backward"] == 65535.0


def test_03_ml_benign_prediction():
    """Test 3: Verify realistic benign web traffic predicts BENIGN with high confidence."""
    ml = get_ml_detector()
    now = time.time()
    session = FlowSession("192.168.1.25", 52140, "192.168.1.1", 443, "TCP", now)

    # 3-way handshake + payload exchanges
    session.add_packet(now + 0.000, is_fwd=True, length=54, header_len=20, flags="S", window=64240, payload_len=0)
    session.add_packet(now + 0.002, is_fwd=False, length=54, header_len=20, flags="SA", window=65535, payload_len=0)
    session.add_packet(now + 0.003, is_fwd=True, length=60, header_len=20, flags="A", window=64240, payload_len=0)
    session.add_packet(now + 0.010, is_fwd=True, length=512, header_len=20, flags="PA", window=64240, payload_len=452)
    session.add_packet(now + 0.015, is_fwd=False, length=1460, header_len=20, flags="A", window=65535, payload_len=1400)
    session.add_packet(now + 0.020, is_fwd=False, length=1460, header_len=20, flags="PA", window=65535, payload_len=1400)

    features = session.extract_features()
    result = ml.predict_flow(features)

    assert result["status"] == "ok"
    assert result["prediction"] == "BENIGN"
    assert result["is_threat"] is False
    assert result["confidence"] > 0.60


def test_04_ml_syn_flood_prediction():
    """Test 4: Verify SYN flood flow pattern is classified as SYN_FLOOD."""
    ml = get_ml_detector()
    # High-rate SYN burst matching DDoS2019 characteristics
    flow = {c: 0.0 for c in ml.feature_names}
    flow["Flow Duration"] = 115799309.0
    flow["Total Fwd Packets"] = 19.0
    flow["Total Backward Packets"] = 2.0
    flow["Flow IAT Mean"] = 5789965.45
    flow["Fwd IAT Total"] = 115799309.0
    flow["Fwd Header Length"] = 380.0
    flow["Bwd Header Length"] = 40.0
    flow["ACK Flag Count"] = 1.0
    flow["Subflow Fwd Packets"] = 19.0
    flow["Subflow Bwd Packets"] = 2.0
    flow["Init_Win_bytes_forward"] = 5840.0
    flow["min_seg_size_forward"] = 20.0

    result = ml.predict_flow(flow)
    assert result["status"] == "ok"
    assert result["prediction"] == "SYN_FLOOD"
    assert result["is_threat"] is True
    assert result["probabilities"]["SYN_FLOOD"] >= 0.70


def test_05_ml_port_scan_prediction():
    """Test 5: Verify port scan probe pattern is classified as PORT_SCAN."""
    ml = get_ml_detector()
    # Distinctive probe flow matching CIC-IDS2017 PortScan
    flow = {c: 0.0 for c in ml.feature_names}
    flow['Flow Duration'] = 43.0
    flow['Total Fwd Packets'] = 1.0
    flow['Total Backward Packets'] = 1.0
    flow['Total Length of Fwd Packets'] = 2.0
    flow['Total Length of Bwd Packets'] = 6.0
    flow['Fwd Packet Length Max'] = 2.0
    flow['Fwd Packet Length Min'] = 2.0
    flow['Fwd Packet Length Mean'] = 2.0
    flow['Bwd Packet Length Max'] = 6.0
    flow['Bwd Packet Length Min'] = 6.0
    flow['Bwd Packet Length Mean'] = 6.0
    flow['Flow Bytes/s'] = 186046.5116
    flow['Flow Packets/s'] = 46511.62791
    flow['Flow IAT Mean'] = 43.0
    flow['Flow IAT Max'] = 43.0
    flow['Flow IAT Min'] = 43.0
    flow['Fwd Header Length'] = 24.0
    flow['Bwd Header Length'] = 20.0
    flow['Fwd Packets/s'] = 23255.81395
    flow['Bwd Packets/s'] = 23255.81395
    flow['Min Packet Length'] = 2.0
    flow['Max Packet Length'] = 6.0
    flow['Packet Length Mean'] = 3.333333333
    flow['Packet Length Std'] = 2.309401077
    flow['Packet Length Variance'] = 5.333333333
    flow['PSH Flag Count'] = 1.0
    flow['Down/Up Ratio'] = 1.0
    flow['Average Packet Size'] = 5.0
    flow['Avg Fwd Segment Size'] = 2.0
    flow['Avg Bwd Segment Size'] = 6.0
    flow['Subflow Fwd Packets'] = 1.0
    flow['Subflow Fwd Bytes'] = 2.0
    flow['Subflow Bwd Packets'] = 1.0
    flow['Subflow Bwd Bytes'] = 6.0
    flow['Init_Win_bytes_forward'] = 1024.0
    flow['Init_Win_bytes_backward'] = 0.0
    flow['min_seg_size_forward'] = 24.0

    result = ml.predict_flow(flow)
    assert result["status"] == "ok"
    assert result["prediction"] == "PORT_SCAN"
    assert result["is_threat"] is True
    assert result["probabilities"]["PORT_SCAN"] > 0.90


def test_06_threat_detector_flow_aggregator_coexistence():
    """Test 6: Verify ThreatDetector still fires deterministic heuristics while aggregating flows."""
    detector = ThreatDetector()
    detector.update_thresholds(syn_critical=10, syn_high=5, cooldown=0.0)

    src_ip = "192.168.1.99"
    detection = None

    # Send 7 SYN-only packets
    for _ in range(7):
        meta = {
            "src_ip": src_ip,
            "dst_ip": "10.0.0.1",
            "src_port": 40000,
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "S",
            "length": 60,
            "header_len": 20,
            "window": 1024,
            "payload_len": 0,
        }
        res = detector.inspect_packet(meta)
        if res:
            detection = res

    assert detection is not None
    assert detection["threat_type"] == "SYN_FLOOD"
    assert detection["severity"] in ("HIGH", "CRITICAL")
    assert detection["src_ip"] == src_ip


@pytest.mark.asyncio
async def test_07_ml_advisory_no_auto_block():
    """Test 7: Requirement 10 - ML-only advisory events MUST NOT automatically block traffic."""
    test_ip = "198.51.100.123"
    detection = {
        "threat_type": "SYN_FLOOD",
        "src_ip": test_ip,
        "dst_ip": "10.0.0.1",
        "severity": "HIGH",
        "count": 5,
        "detection_reason": "ML flow anomaly",
        "response_status": "ML_ADVISORY (No Auto-Block)",
    }

    # Process through event pipeline
    threat_id = await process_detection(detection, event_source="live")
    assert threat_id > 0

    # Verify IP is NOT in active blocked_ips table
    async with await get_db() as db:
        async with db.execute("SELECT count(*) as c FROM blocked_ips WHERE ip = ? AND status='active'", (test_ip,)) as cur:
            row = await cur.fetchone()
            assert row["c"] == 0, "ML advisory event must not trigger automated IP block"


@pytest.mark.asyncio
async def test_08_ml_event_persistence():
    """Test 8: Verify ML detection records persist to SQLite threats and incidents tables."""
    test_ip = "198.51.100.155"
    detection = {
        "threat_type": "PORT_SCAN",
        "src_ip": test_ip,
        "dst_ip": "10.0.0.1",
        "src_port": 50000,
        "dst_port": 22,
        "protocol": "TCP",
        "count": 1,
        "severity": "HIGH",
        "detection_reason": "ML Flow Classifier detected PORT_SCAN with 98.5% confidence",
        "response_status": "ML_ADVISORY (No Auto-Block)",
    }

    threat_id = await process_detection(detection, event_source="live")
    assert threat_id > 0

    async with await get_db() as db:
        # Check threats table
        async with db.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)) as cur:
            threat = await cur.fetchone()
            assert threat is not None
            assert threat["src_ip"] == test_ip
            assert threat["threat_type"] == "PORT_SCAN"
            assert "ML Flow Classifier" in threat["detection_reason"]
            assert threat["response_status"] == "ML_ADVISORY (No Auto-Block)"

        # Check incidents table
        async with db.execute("SELECT * FROM incidents WHERE threat_id = ?", (threat_id,)) as cur:
            incident = await cur.fetchone()
            assert incident is not None
            assert incident["incident_type"] == "PORT_SCAN"
            assert incident["src_ip"] == test_ip


@pytest.mark.asyncio
async def test_09_ml_api_endpoints():
    """Test 9: Verify GET /api/ml/status and POST /api/ml/predict REST endpoints."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. GET /api/ml/status
        res_status = await client.get("/api/ml/status")
        assert res_status.status_code == 200
        data_status = res_status.json()
        assert data_status["status"] == "healthy"
        assert data_status["model"]["loaded"] is True
        assert data_status["model"]["feature_count"] == 76

        # 2. POST /api/ml/predict with sample features
        ml = get_ml_detector()
        sample_features = {c: 0.0 for c in ml.feature_names}
        sample_features["Flow Duration"] = 115799309.0
        sample_features["Total Fwd Packets"] = 19.0
        sample_features["Fwd Header Length"] = 380.0
        sample_features["Init_Win_bytes_forward"] = 5840.0

        res_pred = await client.post("/api/ml/predict", json={"features": sample_features})
        assert res_pred.status_code == 200
        data_pred = res_pred.json()
        assert data_pred["status"] == "ok"
        assert data_pred["prediction"] in ("BENIGN", "PORT_SCAN", "SYN_FLOOD")
        assert "confidence" in data_pred
        assert "probabilities" in data_pred


def test_10_estimator_type_is_random_forest():
    """Test 10: Verify the saved estimator artifact is RandomForestClassifier, not DecisionTree."""
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    ml = get_ml_detector()
    artifact = joblib.load(ml.model_path)
    pipeline = artifact["model"]
    classifier = pipeline.named_steps.get("classifier")
    assert isinstance(classifier, RandomForestClassifier), f"Expected RandomForestClassifier, got {type(classifier)}"
    assert getattr(classifier, "n_estimators", 0) == 100
    assert list(classifier.classes_) == ["BENIGN", "PORT_SCAN", "SYN_FLOOD"]


@pytest.mark.asyncio
async def test_11_manual_block_and_unblock_endpoints():
    """Test 11: Verify manual block and unblock controls with incident logging."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        test_ip = f"198.51.100.{int(time.time() * 1000) % 180 + 20}"
        # 1. Manual block
        res_block = await client.post(
            "/api/blocked-ips/block",
            json={"ip": test_ip, "reason": "Operator manual block test", "duration_min": 30}
        )
        assert res_block.status_code == 200
        assert res_block.json()["success"] is True

        # 2. Verify active in blocked IPs
        res_list = await client.get("/api/blocked-ips?status=active")
        blocked_list = res_list.json()["blocked_ips"]
        assert any(b["ip"] == test_ip for b in blocked_list)

        # 3. Manual unblock
        res_unblock = await client.post(
            "/api/blocked-ips/unblock-by-ip",
            json={"ip": test_ip, "reason": "Operator unblock test"}
        )
        assert res_unblock.status_code == 200
        assert res_unblock.json()["success"] is True


@pytest.mark.asyncio
async def test_12_loopback_and_allowlist_protection():
    """Test 12: Verify loopback IP addresses (127.0.0.1, ::1) can never be blocked."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Loopback IPv4
        res_v4 = await client.post(
            "/api/blocked-ips/block",
            json={"ip": "127.0.0.1", "reason": "Test loopback rejection"}
        )
        assert res_v4.status_code == 400
        assert "Loopback" in res_v4.json()["detail"]

        # Loopback IPv6
        res_v6 = await client.post(
            "/api/blocked-ips/block",
            json={"ip": "::1", "reason": "Test loopback rejection"}
        )
        assert res_v6.status_code == 400


@pytest.mark.asyncio
async def test_13_toggle_blocking_mode():
    """Test 13: Verify switching between Manual and Automatic blocking modes."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Switch to automatic
        res_auto = await client.post("/api/monitoring/toggle-blocking-mode", json={"mode": "automatic"})
        assert res_auto.status_code == 200
        assert res_auto.json()["blocking_mode"] == "automatic"

        # Switch back to manual
        res_manual = await client.post("/api/monitoring/toggle-blocking-mode", json={"mode": "manual"})
        assert res_manual.status_code == 200
        assert res_manual.json()["blocking_mode"] == "manual"


def test_14_telemetry_reset_sync():
    """Test 14: Verify FlowAggregator.reset() synchronizes with MLDetector.reset()."""
    ml = get_ml_detector()
    agg = get_flow_aggregator()

    # Score dummy flow
    flow = {c: 0.0 for c in ml.feature_names}
    ml.predict_flow(flow)
    assert ml.total_flows_evaluated > 0

    # Reset aggregator
    agg.reset()
    assert agg.flows_evaluated == 0
    assert agg.ml_threats_detected == 0
    assert ml.total_flows_evaluated == 0
    assert sum(ml.class_counts.values()) == 0


def test_15_live_vs_simulation_packet_distinction():
    """Test 15: Verify synthetic demonstration packets are tagged with is_simulation=True."""
    from app.services.packet_capture import get_capture
    cap = get_capture()
    injected = cap.inject_synthetic_traffic(traffic_type="normal", count=3)
    assert len(injected) == 3
    for pkt in injected:
        assert pkt["is_simulation"] is True
        assert pkt["source_tag"] == "SIMULATION"


def test_16_tree_decision_path_explanation():
    """Test 16: Verify Tree #0 decision path traversal and feature attribution."""
    ml = get_ml_detector()
    explanation = ml.get_sample_explanation("SYN_FLOOD")
    assert explanation["status"] == "ok"
    assert explanation["prediction"] in ("SYN_FLOOD", "PORT_SCAN", "BENIGN")
    assert "tree_decision_path" in explanation
    assert len(explanation["tree_decision_path"]) > 0
    # First step should have node_id, feature, threshold, operator, observed_value
    first_step = explanation["tree_decision_path"][0]
    assert "node_id" in first_step
    assert "feature" in first_step
    assert "threshold" in first_step
    assert "operator" in first_step
    # Check top features
    assert "top_features" in explanation
    assert len(explanation["top_features"]) <= 8
    for feat in explanation["top_features"]:
        assert "feature" in feat
        assert "importance_pct" in feat
        assert "description" in feat


@pytest.mark.asyncio
async def test_17_ml_explain_endpoint():
    """Test 17: Verify /api/ml/tree-explanation and /api/ml/explain endpoints."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/ml/tree-explanation?threat_type=PORT_SCAN")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert len(data["tree_decision_path"]) > 0
        assert data["prediction"] == "PORT_SCAN"

        # Test POST /api/ml/explain with sample
        post_res = await client.post("/api/ml/explain", json={"threat_type": "SYN_FLOOD"})
        assert post_res.status_code == 200
        post_data = post_res.json()
        assert post_data["status"] == "ok"
        assert post_data["prediction"] == "SYN_FLOOD"


