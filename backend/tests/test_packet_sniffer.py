"""
SILENT WITNESS - Packet Capture & Wireshark Inspector Tests
Verifies interface discovery, packet parsing, layer tree building,
hex dump formatting, and test packet synthesis.
"""

import pytest
from httpx import AsyncClient, ASGITransport

from app.services.packet_capture import (
    get_interfaces_detailed,
    format_hex_dump,
    parse_packet_for_inspector,
    get_capture,
)
from app.main import app as fastapi_app
from scapy.layers.inet import IP, TCP, UDP, ICMP


def test_interfaces_detailed():
    """Verify detailed interface model returns expected fields."""
    detailed = get_interfaces_detailed()
    assert isinstance(detailed, list)
    if detailed:
        first = detailed[0]
        assert "name" in first
        assert "description" in first
        assert "ip" in first
        assert "mac" in first
        assert "type" in first
        assert "status" in first


def test_packet_dissection_and_hex_dump():
    """Verify Scapy packet dissection builds valid Wireshark tree and hex dump."""
    pkt = IP(src="192.168.1.50", dst="10.160.93.91")/TCP(sport=51234, dport=443, flags="S", seq=1000)
    dissected = parse_packet_for_inspector(pkt, packet_no=1, iface_name="Wi-Fi", start_time=0.0)

    assert dissected["no"] == 1
    assert dissected["src_ip"] == "192.168.1.50"
    assert dissected["dst_ip"] == "10.160.93.91"
    assert dissected["protocol"] == "TLS/HTTPS"
    assert "SYN" in dissected["flags"]
    assert "layers" in dissected
    assert "frame" in dissected["layers"]
    assert "ip" in dissected["layers"]
    assert "transport" in dissected["layers"]
    assert len(dissected["hex_dump"]) > 0


@pytest.mark.asyncio
async def test_recent_packets_and_inject_api():
    """Verify recent packets API and test traffic injection."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Inject test traffic
        res_inject = await ac.post("/api/monitoring/inject-traffic", json={"type": "normal", "count": 5})
        assert res_inject.status_code == 200
        data_inject = res_inject.json()
        assert data_inject["count"] == 5

        # 2. Query recent packets
        res_pkts = await ac.get("/api/packets/recent?limit=10")
        assert res_pkts.status_code == 200
        data_pkts = res_pkts.json()
        assert "packets" in data_pkts
        assert len(data_pkts["packets"]) >= 5

        # 3. Query interfaces
        res_ifaces = await ac.get("/api/monitoring/interfaces")
        assert res_ifaces.status_code == 200
        assert "interfaces_detailed" in res_ifaces.json()

