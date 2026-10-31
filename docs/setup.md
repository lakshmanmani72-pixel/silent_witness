# SILENT WITNESS — Setup & Installation Guide

This guide provides step-by-step instructions for running SILENT WITNESS on Windows, Linux, and macOS.

---

## 1. Prerequisites

- **Python 3.10+** (Python 3.10 or 3.11 recommended)
- **Node.js 18+** & **npm**
- **Npcap Driver (Windows only)**: Required for live packet capture on physical network adapters. Download and install from [npcap.com](https://npcap.com/) with *"Install Npcap in WinPcap API-compatible Mode"* checked.

---

## 2. Backend Setup

1. Open a terminal and navigate to the backend directory:
   ```powershell
   cd silent-witness\backend
   ```

2. Create and activate a Python virtual environment:
   ```powershell
   # Windows
   py -3.10 -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install required Python packages:
   ```powershell
   pip install -r requirements.txt
   ```

4. Launch the FastAPI server:
   ```powershell
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

   The backend will initialize the SQLite database automatically at `silent-witness/data/silent_witness.db` and start passive packet sniffing on the active network interface.

---

## 3. Frontend Setup

1. Open a second terminal and navigate to the frontend directory:
   ```powershell
   cd silent-witness\frontend
   ```

2. Install dependencies:
   ```powershell
   npm install
   ```

3. Launch the Vite development server:
   ```powershell
   npm run dev
   ```

4. Open your browser and navigate to:
   ```
   http://127.0.0.1:5173/
   ```

---

## 4. Running the Automated Test Suite

To verify all 15 system tests across database operations, threat detection algorithms, firewall safeguards, allowlist enforcement, and CSV report generation:

```powershell
cd silent-witness\backend
.\venv\Scripts\python.exe -m pytest -v tests/test_all.py
```

Expected result:
```
15 passed in 2.58s
```

---

## 5. Live Demonstration & Threat Probing

To test real-time threat detection on your active Wi-Fi adapter:

```powershell
cd silent-witness\backend
.\venv\Scripts\python.exe scripts/trigger_live_probe.py --type syn_flood
.\venv\Scripts\python.exe scripts/trigger_live_probe.py --type port_scan
.\venv\Scripts\python.exe scripts/trigger_live_probe.py --type admin_probe
```
