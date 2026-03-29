# 🛡️ NetGuard v2.0: Unified SOC & IDS Dashboard

### 📝 Project Description
NetGuard v2.0 is a **Network Intrusion Detection System (NIDS)** and **Security Operations Center (SOC)** dashboard developed as a KTU Mini Project. The system provides real-time monitoring of network traffic to identify and visualize cyber threats. By combining behavioral analysis with deep inspection, it allows administrators to detect attacks and investigate the raw data hidden inside network packets.

---

### 🧠 Detection Method (Heuristics)
The system uses **Heuristic-based Detection** (Behavioral Analysis) to identify threats. Instead of looking for a specific "virus file," it looks for suspicious actions:

1.  **Port Scanning**: Flags an IP if it connects to more unique ports than the defined *Port Scan Limit*.
2.  **SSH Brute Force**: Monitors **Port 22** for high-frequency connection attempts.
3.  **Traffic Spikes**: Detects volumetric anomalies (DoS) by measuring **Packets Per Second (PPS)**.
4.  **Deep Packet Inspection (DPI)**: Decodes **Layer 7 (Application)** payloads from Hex to ASCII for manual forensic review.

---

### 🛠️ Tools & Technologies Used
* **Language**: Python 3.8+ (Core Logic & Data Processing)
* **Traffic Sniffing**: **Scapy** (Packet manipulation) & **Npcap** (Raw packet driver)
* **Frontend**: **Streamlit** (Interactive SOC Dashboard)
* **Database**: **SQLite3** (High-speed storage with WAL mode)
* **Data Analysis**: **Pandas** & **NumPy** (Risk scoring & graph math)

---

### 📂 Project Structure
```text
NetGuard-v2.0/
├── backend/          # Sniffer Engine (live_capture.py)
├── core/             # Rules, Database Schema, & Detector Logic
├── frontend/         # Streamlit Dashboard & UI Code
├── logs/             # Automated Security Audit Trails (.txt)
├── run_tool.bat      # Main One-Click Launcher (Admin)
├── trigger_attacks.bat # Demo Attack Simulator
└── requirements.txt  # Python Dependencies

