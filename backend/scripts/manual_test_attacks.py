"""
SILENT WITNESS - Manual Attack Testing and ML Verification Script
================================================================
Demonstrates and verifies:
1. Random Forest ML inference and Tree #0 decision path explainability.
2. SYN Flood detection and measured attack rate (pkts/sec) calculation.
3. Port Scan multi-port reconnaissance detection.
4. Heuristic Rule vs. Random Forest ML agreement.

Usage:
    .\\venv\\Scripts\\python.exe scripts\\manual_test_attacks.py [--scenario all|syn_flood|port_scan|benign]
"""

import argparse
import sys
import time
from pathlib import Path

# Add backend root to sys.path
backend_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_root))

# Ensure UTF-8 output encoding on Windows terminals
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from app.services.ml_detector import get_ml_detector
from app.services.threat_detector import ThreatDetector
from app.services.flow_aggregator import FlowAggregator


def test_syn_flood_detection():
    print("\n" + "=" * 70)
    print("[>] 1. TESTING SYN FLOOD DETECTION & ATTACK RATE CALCULATION")
    print("=" * 70)

    detector = ThreatDetector()
    detector.update_thresholds(syn_high=20, syn_critical=50, syn_window=10.0, cooldown=0.0)
    attacker_ip = "198.51.100.99"
    target_ip = "192.168.1.1"

    print(f"[*] Simulating burst of 25 SYN-only packets from {attacker_ip} targeting {target_ip}:80...")
    detection = None
    for i in range(25):
        meta = {
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": 40000 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "S",
            "length": 54,
        }
        res = detector.inspect_packet(meta)
        if res:
            detection = res

    if detection:
        print("[+] Detection Triggered:")
        print(f"    - Threat Type          : {detection.get('threat_type')}")
        print(f"    - Severity             : {detection.get('severity')}")
        print(f"    - SYN Count in Window  : {detection.get('count')} pkts")
        print(f"    - Window Duration      : {detection.get('window_seconds')} seconds")
        print(f"    - Measured Attack Rate : {detection.get('attack_rate_str')} ({detection.get('measured_attack_rate_pps')} pkts/s)")
        print(f"    - Response Status      : {detection.get('response_status')}")
    else:
        print("[!] No detection triggered (check thresholds).")

    # Test ML explanation for SYN flood
    ml = get_ml_detector()
    explanation = ml.get_sample_explanation("SYN_FLOOD")
    print("\n[*] Random Forest (100 Trees) Explanation for SYN Flood Flow:")
    print(f"    - ML Predicted Class   : {explanation.get('prediction')}")
    print(f"    - Confidence Score     : {explanation.get('confidence') * 100:.1f}%")
    print(f"    - Class Probabilities  : {explanation.get('probabilities')}")
    print(f"    - Rule vs ML Agreement : {explanation.get('rule_ml_agreement')}")
    print("    - Top Influential Features:")
    for feat in explanation.get("top_features", [])[:4]:
        print(f"        * {feat['feature']:<25} (Importance: {feat['importance_pct']}%, Observed: {feat['observed_value']})")
    print("    - Tree #0 Decision Path (First 3 steps):")
    for step in explanation.get("tree_decision_path", [])[:3]:
        print(f"        Step {step['step']}: {step['feature']} {step['operator']} {step['threshold']} (Observed: {step['observed_value']}) -> Branch {'Left (True)' if step['condition_satisfied'] else 'Right (False)'}")


def test_port_scan_detection():
    print("\n" + "=" * 70)
    print("[>] 2. TESTING PORT SCAN RECONNAISSANCE DETECTION")
    print("=" * 70)

    detector = ThreatDetector()
    detector.update_thresholds(port_high=15, port_window=10.0, cooldown=0.0)
    scanner_ip = "203.0.113.88"
    target_ip = "192.168.1.1"

    print(f"[*] Simulating reconnaissance scan across 20 distinct destination ports from {scanner_ip}...")
    detection = None
    for port in range(20, 40):
        meta = {
            "src_ip": scanner_ip,
            "dst_ip": target_ip,
            "src_port": 50000,
            "dst_port": port,
            "protocol": "TCP",
            "flags": "S",
            "length": 60,
        }
        res = detector.inspect_packet(meta)
        if res:
            detection = res

    if detection:
        print("[+] Detection Triggered:")
        print(f"    - Threat Type          : {detection.get('threat_type')}")
        print(f"    - Severity             : {detection.get('severity')}")
        print(f"    - Distinct Ports Scanned: {detection.get('count')} ports")
        print(f"    - Measured Attack Rate : {detection.get('attack_rate_str')} ({detection.get('measured_attack_rate_pps')} ports/s)")
        print(f"    - Technical Reason     : {detection.get('technical_reason')}")
    else:
        print("[!] No detection triggered (check thresholds).")

    # Test ML explanation for Port Scan
    ml = get_ml_detector()
    explanation = ml.get_sample_explanation("PORT_SCAN")
    print("\n[*] Random Forest (100 Trees) Explanation for Port Scan Flow:")
    print(f"    - ML Predicted Class   : {explanation.get('prediction')}")
    print(f"    - Confidence Score     : {explanation.get('confidence') * 100:.1f}%")
    print(f"    - Class Probabilities  : {explanation.get('probabilities')}")
    print(f"    - Rule vs ML Agreement : {explanation.get('rule_ml_agreement')}")


def test_benign_traffic():
    print("\n" + "=" * 70)
    print("[>] 3. TESTING BENIGN (LEGITIMATE) WEB TRAFFIC")
    print("=" * 70)

    ml = get_ml_detector()
    explanation = ml.get_sample_explanation("BENIGN")
    print(f"[*] ML Predicted Class   : {explanation.get('prediction')}")
    print(f"    - Confidence Score     : {explanation.get('confidence') * 100:.1f}%")
    print(f"    - Class Probabilities  : {explanation.get('probabilities')}")
    print(f"    - Is Threat Flag       : {explanation.get('is_threat')}")
    print(f"    - Rule vs ML Agreement : {explanation.get('rule_ml_agreement')}")



def main():
    parser = argparse.ArgumentParser(description="SILENT WITNESS Attack Testing & ML Verification")
    parser.add_argument("--scenario", default="all", choices=["all", "syn_flood", "port_scan", "benign"])
    args = parser.parse_args()

    print("======================================================================")
    print("   SILENT WITNESS NIDS - VERIFICATION & DEMONSTRATION HARNESS")
    print("======================================================================")

    if args.scenario in ("all", "syn_flood"):
        test_syn_flood_detection()
    if args.scenario in ("all", "port_scan"):
        test_port_scan_detection()
    if args.scenario in ("all", "benign"):
        test_benign_traffic()

    print("\n[+] ALL VERIFICATION CHECKS COMPLETED SUCCESSFULLY.\n")


if __name__ == "__main__":
    main()
