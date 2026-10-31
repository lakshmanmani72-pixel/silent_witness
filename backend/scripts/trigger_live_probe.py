"""
SILENT WITNESS - Live Network Demonstration Utility
===================================================
Injects a safe, test-controlled packet pattern onto the local network interface
to demonstrate live real-time detection in the SILENT WITNESS SOC Dashboard.

Usage:
    py -3.10 scripts/trigger_live_probe.py [--type port_scan|syn_flood|admin_probe]
"""

import argparse
import sys
from pathlib import Path

# Add backend root to sys.path
backend_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_root))

try:
    from scapy.all import Ether, IP, TCP, sendp
    from app.services.packet_capture import resolve_interface, get_best_interface
except ImportError:
    print("[-] Scapy or app modules not found. Run inside the backend directory with venv activated:")
    print("    .\\venv\\Scripts\\python.exe scripts/trigger_live_probe.py")
    sys.exit(1)


def send_probe(probe_type: str, iface_name: str = None):
    target_iface_name = iface_name or get_best_interface()
    resolved = resolve_interface(target_iface_name)
    host_ip = getattr(resolved, "ip", "10.61.137.132")

    print(f"[*] Target Interface : {getattr(resolved, 'name', target_iface_name)}")
    print(f"[*] Target Host IP   : {host_ip}")
    print(f"[*] Probe Type       : {probe_type}")

    if probe_type == "admin_probe":
        print("[*] Sending probe to sensitive administrative port 445...")
        pkt = Ether() / IP(src="192.168.1.250", dst=host_ip) / TCP(sport=54321, dport=445, flags="S")
        sendp(pkt, iface=resolved, verbose=0)
        print("[+] Sent 1 probe packet to port 445. Check your Dashboard / Recent Events!")

    elif probe_type == "port_scan":
        print("[*] Sending port scan probe across 105 distinct ports...")
        pkts = [
            Ether() / IP(src="192.168.1.251", dst=host_ip) / TCP(sport=40000 + p, dport=1000 + p, flags="S")
            for p in range(105)
        ]
        sendp(pkts, iface=resolved, verbose=0)
        print("[+] Injected 105 port scan packets. Check your Dashboard & Blocked IPs!")

    elif probe_type == "syn_flood":
        print("[*] Sending burst of 60 SYN packets within 2 seconds...")
        pkts = [
            Ether() / IP(src="192.168.1.252", dst=host_ip) / TCP(sport=30000 + i, dport=80, flags="S")
            for i in range(60)
        ]
        sendp(pkts, iface=resolved, verbose=0)
        print("[+] Injected 60 SYN flood packets. Check your Dashboard for HIGH SYN_FLOOD detection!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Silent Witness Live Threat Generator")
    parser.add_argument(
        "--type",
        choices=["port_scan", "syn_flood", "admin_probe"],
        default="port_scan",
        help="Type of threat pattern to inject (default: port_scan)"
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Interface friendly name or device (default: active Wi-Fi)"
    )
    args = parser.parse_args()
    send_probe(args.type, args.iface)
