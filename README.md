# 🛡️ NetGuard v2.0: Unified SOC & IDS Dashboard

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg">
  <img src="https://img.shields.io/badge/Security-NIDS-red.svg">
  <img src="https://img.shields.io/badge/Framework-Streamlit-orange.svg">
  <img src="https://img.shields.io/badge/Status-Operational-green.svg">
</p>

NetGuard v2.0 is a professional-grade **Network Intrusion Detection System (NIDS)** and **Security Operations Center (SOC)** dashboard. Designed for real-time monitoring, it utilizes **Stateful Heuristic Analysis** and **Layer 7 Deep Packet Inspection (DPI)** to identify and visualize network threats instantly.

---

## 📋 Table of Contents

- [What is This?](#-what-is-this)
- [Key Highlights](#-key-highlights)
- [What Can It Detect?](#-what-can-it-detect)
- [Tech Stack](#️-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [How to Use](#-how-to-use)

---

## ❓ What is This?

NetGuard v2.0 is a **student project** that combines network packet sniffing with real-time threat detection. It monitors incoming network traffic, identifies suspicious activity (like port scans or brute force attacks), and displays everything in a nice dashboard. Think of it as a mini version of professional security monitoring tools—but built from scratch!

### Why I Built This
- Learn how network packets work (Wireshark-style inspection)
- Understand heuristic-based threat detection
- Build a real-time dashboard with live data
- Practice Python, databases, and UI development

---

## 🚀 Key Highlights

* **🔍 Deep Packet Dissector**: Inspect raw hex payloads and TCP/IP metadata like Wireshark
* **🧠 Heuristic Engine**: Automatically detect Port Scans, SSH Brute Force, and Traffic Spikes
* **📈 Live SOC Analytics**: Real-time graphs showing packets per second and protocol breakdown
* **⚖️ Dynamic Risk Scoring**: Assigns threat levels (High/Medium/Low) to network activity
* **⚡ High-Performance Backend**: Multi-threaded packet capture with SQLite database for storing events

---

## 🛡️ What Can It Detect?

| Attack Type | How It Works | Severity |
| :--- | :--- | :--- |
| **Port Scanning** | Detects when someone tries many different ports from the same IP | Medium/High |
| **SSH Brute Force** | Flags multiple failed login attempts on SSH (port 22) | CRITICAL |
| **Traffic Spike** | Identifies sudden floods of packets (potential DoS attack) | Warning |
| **Reconnaissance** | Spots empty packets (just headers, no data) often used for probing | Info |

---

## 🛠️ Tech Stack

* **Engine:** Python & [Scapy](https://scapy.net/) (packet sniffing)
* **Dashboard:** [Streamlit](https://streamlit.io/) (web UI)
* **Data Processing:** Pandas & NumPy (analyzing packet data)
* **Storage:** SQLite3 (storing detected threats)
* **Packet Capture:** Npcap (Windows driver for capturing packets)

---

## 📂 Project Structure

```
NetGuard-v2.0/
├── backend/          # Packet capture engine (live_capture.py)
├── core/             # Detection logic and database setup
├── frontend/         # Streamlit dashboard
├── logs/             # Security event logs
└── screenshots/      # Dashboard screenshots
```

---

## 🔧 Getting Started

### 1. Prerequisites

You'll need:
- **Python 3.8 or higher** ([Download here](https://www.python.org/downloads/))
- **Npcap** for Windows packet capture ([Download here](https://npcap.com/))
  - During installation, make sure to check "Install WinPcap API Compatibility"
- **Admin/Administrator access** (required to capture network packets)

### 2. Installation

```bash
# Clone the repository
git clone https://github.com/Chriszpaul/NetGuard-v2.git

# Navigate to the project folder
cd NetGuard-v2

# Install required Python libraries
pip install -r requirements.txt
```

### 3. Running the Project

**Step 1: Start the packet sniffer (run as Administrator)**
```bash
python backend/live_capture.py
```
You should see output like: `[*] Starting packet capture...`

**Step 2: Launch the dashboard (in a new terminal)**
```bash
streamlit run frontend/dashboard.py
```
The dashboard will open in your browser at `http://localhost:8501`

---

## 📊 How to Use

1. **Start the sniffer first** (it runs in the background capturing packets)
2. **Open the dashboard** to see live threat detection in real-time
3. **Check the logs folder** to see all detected threats saved as text files
4. **Inspect packets** using the Deep Packet Dissector to see raw hex data

### Common Issues

- **"Permission Denied" error?** → Run the terminal as Administrator
- **"No module named scapy"?** → Run `pip install -r requirements.txt` again
- **Dashboard won't connect?** → Make sure the sniffer is running first

---

## 🎓 What I Learned

This project helped me understand:
- How to capture and parse network packets at the byte level
- Building a real-time data pipeline (capture → analyze → display)
- Creating a web dashboard with live updates (Streamlit)
- Designing detection logic for common attacks
- Working with databases for storing security events

---

**Questions or ideas?** Feel free to open an issue! 😊