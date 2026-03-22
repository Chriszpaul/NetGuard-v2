# 📖 NetGuard v2.0: Comprehensive User Manual

## 1. Introduction
NetGuard v2.0 is a modular Network Intrusion Detection System (NIDS) designed for real-time traffic analysis and threat mitigation. It utilizes heuristic-based detection to identify common network-layer attacks and provides a high-fidelity dashboard for Security Operations Center (SOC) monitoring.

---

## 2. System Architecture
NetGuard is built on a decoupled architecture to ensure high performance and data integrity:

* **Data Acquisition Layer (backend/)**: Utilizes Scapy and Npcap to capture raw Ethernet frames and perform Layer 3/4 decapsulation.
* **Detection Engine (core/)**: Processes packet streams through heuristic filters to identify anomalies such as SYN Floods, Port Scanning, and Brute Force patterns.
* **Persistence Layer (SQLite)**: Employs Write-Ahead Logging (WAL) to allow simultaneous data insertion from the sniffer and querying from the dashboard.
* **Visualization Layer (frontend/)**: A Streamlit-based interface that translates raw database entries into actionable security telemetry.

---

## 3. Core Modules & Functionality

### 🛡️ Detection Logic
The system classifies network events based on the following criteria:
* **Port Scanning**: Detected when a single Source IP hits more than $N$ unique ports within a 60-second window.
* **Brute Force**: Identified by tracking rapid, repetitive connection attempts to specific service ports (e.g., Port 22 for SSH).
* **Traffic Spikes**: Monitoring the Packet-Per-Second (PPS) rate against a baseline to identify potential DoS/DDoS activity.

### 📊 SOC Dashboard Features
* **Real-Time Metrics**: Displays Total Packets, Active Alerts, and Risk Levels.
* **Protocol Distribution**: A dynamic pie chart showing the ratio of TCP, UDP, ICMP, and Other traffic.
* **Threat Intelligence Tab**: A filtered view focusing strictly on "CRITICAL" and "WARNING" level events.
* **Network Map**: A table of active internal and external IP addresses interacting with the host.

---

## 4. User Interface Navigation

### Sidebar Controls
* **Global Filters**: Filter the entire dashboard by Protocol (TCP/UDP/ICMP) or specific IP addresses.
* **Engine Tuning**: Adjust the thresholds for what constitutes an "Attack" in real-time.
* **Maintenance**: 
    * **Purge Session Data**: Resets the local database for a fresh monitoring session.
    * **Export Intelligence**: Downloads the current session's alert history as a CSV file.

### Main View
* **Traffic Stream**: A live-updating table showing the most recent 100 packets.
* **Risk Analysis**: A visual gauge indicating the current threat level of the network environment.

---

## 5. Security & Maintenance
* **Log Management**: Detailed text logs are stored in `logs/network_security.log` for forensic review.
* **Database Optimization**: The system automatically manages SQLite checkpoints to prevent file bloat during long monitoring sessions.
* **Data Integrity**: All alerts are timestamped using ISO 8601 format to ensure chronological accuracy during audits.

---

## 6. Project Scope & Limitations
* **Scope**: Designed for Local Area Network (LAN) monitoring and educational cybersecurity demonstrations.
* **Encrypted Traffic**: While the system can detect the *presence* of HTTPS/TLS traffic, it does not perform Deep Packet Inspection (DPI) on encrypted payloads to maintain user privacy and system speed.

---
**Prepared for:** KTU Mini Project Evaluation  
**Author:** Chriszpaul  
**Date:** March 2026