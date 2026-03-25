🛡️ NetGuard v2.0: Unified SOC & Intrusion Detection System
NetGuard is a high-performance, real-time Network Intrusion Detection System (NIDS) designed to monitor network traffic and identify malicious activities through heuristic analysis. Developed as a KTU Mini Project, this version (v2.0) introduces an integrated Security Operations Center (SOC) dashboard and advanced cyber-threat detection logic.
🚀 Version 2.0 Features
Heuristic Detection Engine: Automated identification of Port Scanning, SSH Brute Force, and Traffic Spikes using stateful behavioral thresholds.
Deep Packet Inspection (DPI): Wireshark-style "Deep Packet Dissector" for Layer 7 forensic analysis of raw hexadecimal payloads.
Thread-Safe Persistence: Implements SQLite with WAL (Write-Ahead Logging) for high-speed concurrent packet storage and alert retrieval.
SOC Dashboard: A professional Streamlit-based interface providing real-time telemetry, PPS throughput graphs, and host-based risk scoring.
Administrative Intelligence: Multi-criteria filters for protocols, severity levels, and specific IP nodes.
Forensic Export: Integrated CSV export functionality for security auditing, incident response, and reporting.
🔍 Detection Logic & Risk Scoring
NetGuard uses a Weighted Heuristic Engine to categorize threats. Unlike simple loggers, it calculates a Cumulative Risk Score for every active node:
High Severity (Score 90-100): Aggressive threats like SSH Brute Force (Port 22) or high-frequency Port Scanning.
Medium Severity (Score 50-89): Suspicious reconnaissance, such as horizontal port probing or localized traffic spikes.
Low Severity (Score 10-49): General network discovery and routine system background tasks.
🛠️ Tech Stack & Tools
Language: Python 3.x
Packet Sniffing: Scapy (Network layer abstraction & raw frame capture)
Frontend: Streamlit (Data visualization & SOC UI)
Data Handling: Pandas & NumPy (Traffic aggregation & telemetry)
Database: SQLite3 (Transactional storage with custom schema for raw payloads)
Environment: Npcap (Raw packet access for Windows monitoring)
📦 Project Structure
backend/: Core capture engine (live_capture.py) and high-frequency sniffer implementation.
core/: Modular detection logic (detector.py), database management (database.py), and configuration.
frontend/: Interactive web-based SOC dashboard (dashboard.py).
logs/: Automated text-based security audit trails for offline review.
alerts.db: Relational database storing packet metadata and threat intelligence.
🔧 Installation & Usage
Prerequisites
Install Npcap (Required for raw packet capture on Windows).
Ensure Python 3.8+ is installed.
Setup & Execution
Bash
Install dependencies
pip install -r requirements.txt
Start the Capture Engine (Run as Administrator for Npcap access)
python backend/live_capture.py
Launch the Dashboard
streamlit run frontend/dashboard.py
