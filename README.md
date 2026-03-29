#  NetGuard v2.0: Unified SOC & IDS Dashboard

###  Project Description
NetGuard v2.0 is a **Network Intrusion Detection System (NIDS)** and **Security Operations Center (SOC)** dashboard developed as a KTU Mini Project. The system provides real-time monitoring of network traffic to identify and visualize cyber threats. By combining behavioral analysis with deep inspection, it allows administrators to detect attacks and investigate the raw data hidden inside network packets.

---

###  Detection Method 
The system uses **Heuristic-based Detection** (Behavioral Analysis) to identify threats. Instead of looking for a specific "virus file," it looks for suspicious actions:

1.  **Port Scanning**: Flags an IP if it connects to more unique ports than the defined *Port Scan Limit*.
2.  **SSH Brute Force**: Monitors **Port 22** for high-frequency connection attempts.
3.  **Traffic Spikes**: Detects volumetric anomalies (DoS) by measuring **Packets Per Second (PPS)**.
4.  **Deep Packet Inspection (DPI)**: Decodes **Layer 7 (Application)** payloads from Hex to ASCII for manual forensic review.

---

###  Tools & Technologies Used
* **Language**: Python 3.8+ (Core Logic & Data Processing)
* **Traffic Sniffing**: **Scapy** (Packet manipulation) & **Npcap** (Raw packet driver)
* **Frontend**: **Streamlit** (Interactive SOC Dashboard)
* **Database**: **SQLite3** (High-speed storage with WAL mode)
* **Data Analysis**: **Pandas** & **NumPy** (Risk scoring & graph math)

---

###  Project Structure
```bash
NetGuard-v2.0/
├── backend/          # Sniffer Engine (live_capture.py)
├── core/             # Rules, Database Schema, & Detector Logic
├── frontend/         # Streamlit Dashboard & UI Code
├── logs/             # Automated Security Audit Trails (.txt)
├── run_tool.bat      # Main One-Click Launcher (Admin)
├── trigger_attacks.bat # Demo Attack Simulator
└── requirements.txt  # Python Dependencies
```

---

### How To Run NetGuard

1. **INSTALL PREREQUISITES**:
   - Install Python 3.8+
   - Install Npcap ([https://nmap.org/npcap/](https://nmap.org/npcap/))
     ***IMPORTANT**: Check "WinPcap API-compatible Mode" during installation.

2. **INSTALL DEPENDENCIES**:
   Open Command Prompt in the project folder and run:
   pip install -r requirements.txt

3. **START THE SYSTEM**:
   - Right-click "**run_tool.bat**"
   - Select "Run as **Administrator**"
   (This starts the sniffer and the dashboard automatically).

4. **SHUTDOWN**:
   - Close the command prompt window to stop all processes.

---

### Future Plans
* **Smart Detection**: Using AI to learn what "Normal" traffic looks like.

* **Auto-Block**: Automatically "banning" a hacker's IP instead of just showing an alert.

* **Phone Alerts**: Sending a WhatsApp or SMS when a high-risk attack is found.

---

### 🔍 How it Works (The 3-Step Process)

1.  **Capture (The Ears)**: Using **Npcap** and **Scapy**, the system "listens" to every packet moving through your network card. It ignores the noise and focuses on **IP Addresses** and **Port Numbers**.
2.  **Analyze (The Brain)**: Every packet is checked against our **Heuristic Rules**. If a single IP address starts acting weird (like trying to hit 20 ports in 1 second), the system calculates a **Risk Score**.
3.  **Visualize (The Face)**: The results are saved into a **Database** and instantly displayed on the **Streamlit Dashboard**. You see the live graphs move and the "High Risk" red alerts appear the moment an attack is detected.

