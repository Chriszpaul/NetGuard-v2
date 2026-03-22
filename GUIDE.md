# 📘 NetGuard v2.0: Setup & Operations Guide

This guide provides step-by-step instructions for installing, configuring, and demonstrating the NetGuard NIDS system. Developed as part of the **KTU Mini Project** curriculum.

---

## 🛠️ 1. Technical Prerequisites

Before initialization, ensure the following environment is prepared:

| Requirement | Specification | |
| :--- | :--- | :--- |
| **Operating System** | Windows 10/11 (Preferred) or Linux | |
| **Python Version** | 3.8 or higher | |
| **Network Driver** | [Npcap](https://nmap.org/npcap/) (Installed in WinPcap API-compatible mode) | |
| **Privileges** | Administrative / Root access (Required for Raw Sockets) | |

---

## 🚀 2. Quick-Start Installation

### Step A: Install Dependencies
Open PowerShell or Command Prompt as **Administrator** in the project root and run:
```powershell
pip install -r requirements.txt
```

### Step B: Launch the Capture Engine
Navigate to the `backend/` directory and execute:
```powershell
python live_capture.py
```
*Note: Keep this window open. It is the heart of the sniffer.*

### Step C: Launch the SOC Dashboard
Open a second terminal in the root directory and execute:
```powershell
streamlit run frontend/dashboard.py
```

---

## 🎮 3. Interactive Demonstration Guide (Viva Mode)

To showcase NetGuard's capabilities to examiners, follow this recommended workflow:

### Phase 1: Baseline Monitoring
- Observe the **Real-Time Throughput** line chart.
- Note the **Protocol Distribution** (TCP/UDP/ICMP/DNS) as background traffic flows.
- Verify the **Active Source Nodes** count matches the devices on your network.

### Phase 2: Cyber Attack Simulation
1. Open the provided `trigger_attacks.bat` script.
2. Select **Option 2 (SSH Brute Force Simulation)**.
3. Observe the **Instant Toast Notification** on the Dashboard.
4. Verify that the **Critical Events** metric has incremented.

### Phase 3: Forensic Intelligence
1. Navigate to the **Threat Intelligence** tab in the Dashboard.
2. Identify the Attacker IP and the specific threat classification (e.g., *Brute Force* or *Port Scan*).
3. Use the **Export Intelligence** buttons in the sidebar to generate a CSV audit report.

---

## ⚙️ 4. Calibration & Sensitivity

You can adjust the engine's behavior in real-time via the Sidebar:
- **Port Scan Limit**: Lower this to `2` for a fast demo, or set to `15+` for a stable production environment.
- **Refresh Rate**: Set to `1s` for high-speed live monitoring or `5s+` to reduce system overhead.
- **Traffic Spike Limit**: Adjust the threshold for Denial of Service (DoS) detection.

---

## 🔍 5. Troubleshooting (FAQ)

- **Metric "Total Captured" is 0**: Ensure `live_capture.py` is running as Admin. If using a VPN, disable it, as some VPNs block raw packet access to the physical NIC.
- **Dashboard "Stuck" or Lagging**: Click the **🚨 Purge Session Data** button in the sidebar. This clears the SQLite WAL logs and resets the UI cache.
- **Local Scan Not Appearing**: If scanning `127.0.0.1`, ensure the **Npcap Loopback Adapter** is selected in your system settings. For best results, scan your machine's **LAN IP** (found via `ipconfig`).

---

## 📜 6. Project Architecture Diagram

```text
[ Network Interface Card ] 
          │
          ▼
[ Scapy Sniffer (backend/) ] ──► [ Heuristic Detector (core/) ]
          │                             │
          ▼                             ▼
[ SQLite Database (WAL Mode) ] ◄── [ Alert Logs (logs/) ]
          │
          ▼
[ Streamlit Dashboard (frontend/) ] ──► [ CSV Export ]
```

---
**Developed by:** Chriszpaul
**Version:** 2.0.0 (Stable)
```

