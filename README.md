# 🛡️ NetGuard v2.0: Network Intrusion Detection System

NetGuard is a high-performance, real-time Network Intrusion Detection System (NIDS) designed to monitor network traffic and identify malicious activities through heuristic analysis. Developed as a **KTU Mini Project**, this version (v2.0) introduces an integrated Security Operations Center (SOC) dashboard and advanced cyber-threat detection logic.

## 🚀 Version 2.0 Features
- **Heuristic Detection Engine**: Automated identification of Port Scanning, SSH Brute Force, and Traffic Spikes.
- **Thread-Safe Persistence**: Implements SQLite with WAL (Write-Ahead Logging) for concurrent read/write operations.
- **SOC Dashboard**: A formal Streamlit-based interface providing real-time telemetry, risk scoring, and protocol distribution.
- **Administrative Intelligence**: Filterable incident logs and raw packet stream analysis.
- **Forensic Export**: Integrated CSV export functionality for security auditing and reporting.

## 🛠️ Tech Stack & Tools
- **Language**: Python 3.x
- **Packet Sniffing**: [Scapy](https://scapy.net/) (Network layer abstraction)
- **Frontend**: [Streamlit](https://streamlit.io/) (Data visualization)
- **Data Handling**: Pandas & NumPy (Traffic aggregation)
- **Database**: SQLite3 (Transactional storage)
- **Environment**: Npcap (Raw packet access for Windows)

## 📦 Project Structure
- `backend/`: Core capture engine and sniffer implementation.
- `core/`: Modular detection logic, database management, and configuration.
- `frontend/`: Interactive web-based SOC dashboard.
- `logs/`: Automated text-based security audit trails.
- `trigger_attacks.bat`: Automated script to simulate cyber-threats for demonstration.

## 🔧 Installation & Usage

### 1. Prerequisites
- Install [Npcap](https://nmap.org/npcap/) (Required for packet capture on Windows).
- Ensure Python 3.8+ is installed.

### 2. Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Start the Capture Engine (Run as Administrator)
python backend/live_capture.py

# Launch the Dashboard
streamlit run frontend/dashboard.py
