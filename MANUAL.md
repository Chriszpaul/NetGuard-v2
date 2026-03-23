# 📖 NetGuard v2.0: Comprehensive User Manual

## 1. Introduction
NetGuard v2.0 is a modular Network Intrusion Detection System (NIDS) designed for real-time traffic analysis and threat mitigation. It utilizes heuristic-based detection to identify common network-layer attacks and provides a high-fidelity dashboard for Security Operations Center (SOC) monitoring.

---

## 2. System Architecture
NetGuard is built on a decoupled architecture to ensure high performance and data integrity:

* **Data Acquisition Layer (backend/)**: Utilizes Scapy and Npcap to capture raw Ethernet frames and perform Layer 3/4 decapsulation.
* **Detection Engine (core/)**: Processes packet streams through heuristic filters to identify anomalies such as SYN Floods, Port Scanning, and Brute Force patterns.
* **Persistence Layer (SQLite)**: Employs Write-Ahead Logging (WAL) and custom schemas to store both packet metadata and raw hexadecimal payloads.
* **Visualization Layer (frontend/)**: A Streamlit-based interface that translates raw database entries into actionable security telemetry and forensic dissections.

---

## 3. Core Modules & Functionality

### 🛡️ Detection Logic & Heuristics
The system classifies network events based on the following weighted criteria:
* **Port Scanning**: Detected when a single Source IP hits unique ports beyond the defined threshold in the sidebar.
* **SSH Brute Force**: Identified by tracking high-frequency connection attempts to Port 22.
* **Traffic Spikes**: Monitors Packets Per Second (PPS) to detect volumetric Denial of Service (DoS) attempts.

### 🔍 Deep Packet Inspection (DPI)
New in v2.0, the system performs **Layer 7 Analysis**:
* **Raw Payload Capture**: Every packet is inspected for a data payload (Raw layer).
* **ASCII Decoding**: The system attempts to translate binary data into human-readable text.
* **Forensic Dissection**: Users can select specific Incident IDs to view a full breakdown of the packet's "inside" content.

---

## 4. Interface Navigation

### Sidebar Controls
* **Detection Sensitivity**: Adjust thresholds for Port Scans and Brute Force attacks in real-time.
* **System Settings**: Control the "Telemetry Refresh" rate to balance performance and live accuracy.
* **Maintenance**: 
    * **Purge Session Data**: Physically wipes the SQLite database and clears the UI cache.
    * **Export Intelligence**: Downloads the current session's alert history as a CSV file.

### Main View Tabs
* **Incident Logs**: A high-level report showing Severity, Source IP, and the specific alert message.
* **Packet Stream**: A live-updating table showing the most recent 100 raw packets.
* **Deep Packet Dissector**: The forensic tool used to inspect the metadata and payload of a single chosen packet ID.

---

## 5. Security & Maintenance
* **Log Management**: Detailed text logs are stored in `logs/` for offline forensic review.
* **Database Optimization**: The system uses `VACUUM` and `WAL` modes to prevent database corruption during high-speed sniffing.
* **Data Integrity**: All alerts are timestamped using local system time to ensure chronological accuracy during audits.

---

## 6. Project Scope & Capabilities
* **Scope**: Designed for Local Area Network (LAN) monitoring and educational cybersecurity demonstrations.
* **Payload Visibility**: The system provides full visibility into unencrypted protocols (HTTP, DNS, FTP, etc.).
* **Encrypted Traffic**: For HTTPS/TLS (Port 443), the system detects the traffic volume but flags the payload as "Encrypted" to maintain security standards.

---
**Prepared for:** KTU Mini Project Evaluation  
**Author:** Chriszpaul  
**Version:** 2.0.0 (SOC Edition)