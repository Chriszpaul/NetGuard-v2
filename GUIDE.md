📘 NetGuard v2.0: Setup & Operations Guide

This guide provides step-by-step instructions for installing, configuring, and demonstrating the NetGuard NIDS system. Developed specifically for the **KTU Mini Project** curriculum, this version features advanced **Heuristic Scoring** and **Deep Packet Analysis (DPI)**.

---

## 🛠️ 1. Technical Prerequisites

Before initialization, ensure the following environment is prepared for raw socket communication:

| Requirement | Specification |
| :--- | :--- |
| **Operating System** | Windows 10/11 (Preferred) or Linux |
| **Python Version** | 3.8 or higher |
| **Network Driver** | [Npcap](https://nmap.org/npcap/) (Installed in **WinPcap API-compatible** mode) |
| **Privileges** | **Administrative / Root** access (Required for Raw Packet Sniffing) |

---

## 🚀 2. Quick-Start Installation

### Step A: Install Dependencies
Open PowerShell or Command Prompt as **Administrator** in the project root and run:
```powershell
pip install -r requirements.txt
Step B: Launch the Capture Engine
Navigate to the project root and execute:

PowerShell
python backend/live_capture.py
Note: This terminal handles the Scapy sniffer and the Heuristic Engine. Keep it visible during your demo to show live detection logs.

Step C: Launch the SOC Dashboard
Open a second terminal in the root directory and execute:

PowerShell
streamlit run frontend/dashboard.py
🎮 3. Interactive Demonstration Guide (Viva Mode)
Follow this professional 4-phase workflow to showcase the full intelligence of NetGuard v2.0:

Phase 1: Baseline Telemetry
Observe the Live Throughput (PPS) line chart to see background network pulses.

Monitor the Protocol Distribution; explain how the system differentiates between TCP (Web/SSH) and UDP (Streaming/DNS).

Verify Active Source Nodes to see how many unique devices are currently interacting with your NIC.

Phase 2: Cyber Attack Simulation
Launch the trigger_attacks.bat script.

Select Option 2 (SSH Brute Force) or Option 1 (Port Scan).

Observe the Real-Time Toast Notification and the immediate jump in the Critical Events metric.

Show the Host Risk Scoring bar chart; point out how the Attacker IP has instantly gained a high "Danger Score."

Phase 3: Deep Packet Analysis (DPI)
Navigate to the Deep Packet Dissector tab.

Select "Incident Logs" as your data source to focus only on malicious traffic.

Pick a high-risk ID from the dropdown to perform Layer 7 Inspection.

Analyze the Payload: Explain how the ASCII decoder translates raw hex into human-readable text.

Expert Tip: Point out that "Header-only" frames (empty payloads) prove a Reconnaissance Scan is occurring, as no data is being exchanged yet.

Phase 4: Forensic Export
Use the Download Incident Logs button in the sidebar.

Open the generated CSV to show the examiner how NetGuard creates a permanent audit trail for security compliance.

⚙️ 4. Calibration & Sensitivity (SOC Tuning)
Fine-tune the engine's "Aggression" via the Sidebar sliders:

Port Scan Limit: Set to 3 for a highly sensitive demo or 10+ to ignore common network noise.

SSH Brute Force Limit: Adjust the number of failed attempts allowed on Port 22 before a High Severity alert is triggered.

Telemetry Refresh: Set to 1s for "Live" movement or 5s+ to reduce system CPU overhead.

🔍 5. Troubleshooting & Expert Tips
Error: no column 'raw_payload': This occurs if an old database exists. Delete alerts.db to allow the new schema to initialize with the DPI column.

Missing Metrics: Ensure live_capture.py is running as Admin. If using a VPN, disable it, as some VPNs block raw packet access to the physical NIC.

Dashboard Lag: If the UI is slow, increase the Telemetry Refresh slider or click Purge Session Data to clear the SQLite WAL logs.

📜 6. Project Architecture Diagram (L7 Enhanced)
Plaintext
[ Network Interface Card ] 
          │
          ▼
[ live_capture.py (Scapy) ] ──► [ Decapsulation: L2 -> L3 -> L4 ]
          │                             │
          ▼                             ▼
[ SQLite DB (raw_payload) ] ◄── [ Heuristic Engine (Scoring) ]
          │
          ▼
[ Streamlit Dashboard ] ──► [ L7 Deep Packet Dissector ] ──► [ CSV Export ]
Developed by: Chriszpaul
Version: 2.0.0 (Unified SOC Edition)