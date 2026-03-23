# 🛡️ NetGuard v2.0: Unified SOC & IDS Dashboard

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg">
  <img src="https://img.shields.io/badge/Security-NIDS-red.svg">
  <img src="https://img.shields.io/badge/Framework-Streamlit-orange.svg">
  <img src="https://img.shields.io/badge/Status-Operational-green.svg">
</p>

NetGuard v2.0 is a professional-grade **Network Intrusion Detection System (NIDS)** and **Security Operations Center (SOC)** dashboard. Designed for real-time monitoring, it utilizes **Stateful Heuristic Analysis** and **Layer 7 Deep Packet Inspection (DPI)** to identify and visualize network threats instantly.

---

## 🚀 Key Highlights

* **🔍 Deep Packet Dissector**: Wireshark-style forensic tool to inspect raw hex payloads and TCP/IP metadata.
* **🧠 Heuristic Engine**: Automated detection of Port Scans, SSH Brute Force, and Traffic Spikes.
* **📈 Live SOC Analytics**: Real-time PPS (Packets Per Second) throughput graphs and protocol distribution.
* **⚖️ Dynamic Risk Scoring**: Weighted threat levels (High/Medium/Low) assigned to every network node.
* **⚡ High-Performance Backend**: Multi-threaded Scapy engine with SQLite WAL-mode for concurrent data processing.

---

## 🛡️ Detection Capabilities

| Attack Type | Detection Logic | Severity |
| :--- | :--- | :--- |
| **Port Scanning** | Detects unique destination port hits from a single source. | **Medium/High** |
| **SSH Brute Force** | Tracks high-frequency TCP connection attempts on Port 22. | **CRITICAL** |
| **Traffic Spike** | Identifies volumetric anomalies and potential DoS flooding. | **Warning** |
| **Reconnaissance** | Flags header-only frames (SYN/ACK) with no data payload. | **Info** |

---

## 🛠️ Tech Stack

* **Engine:** Python & [Scapy](https://scapy.net/) (Raw Packet Sniffing)
* **Dashboard:** [Streamlit](https://streamlit.io/) (Security UI)
* **Data:** Pandas & NumPy (Telemetry Aggregation)
* **Storage:** SQLite3 (Transactional Threat Intelligence)
* **Driver:** Npcap (Windows Packet Capture Library)

---

## 📂 Project Structure

```text
NetGuard-v2.0/
├── backend/          # Scapy Capture Engine (live_capture.py)
├── core/             # Heuristics, Database Schema, & Detector Logic
├── frontend/         # Streamlit SOC Dashboard Implementation
├── logs/             # Automated Security Audit Trails (TXT)
└── screenshots/      # UI Visuals & Forensic Evidence
🔧 Getting Started
1. Prerequisites
Install Npcap (Install with "WinPcap API Compatibility" checked).

Python 3.8 or higher.

2. Installation
Bash
# Clone the repository
git clone [https://github.com/your-username/NetGuard-v2.0.git](https://github.com/your-username/NetGuard-v2.0.git)

# Install core dependencies
pip install -r requirements.txt
3. Execution
Start Sniffer (Admin): python backend/live_capture.py

Launch Dashboard: streamlit run frontend/dashboard.py
