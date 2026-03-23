from core.config import CONFIG

# ===============================
# PORT SCAN DETECTION (AGGRESSIVE)
# ===============================
def detect_port_scan(traffic):
    """
    Identifies if an IP is hitting multiple different ports.
    Updated: Threshold lowered to 3 for instant demo results.
    """
    alerts = []
    # Force a very low threshold for the presentation
    threshold = 3 

    for ip, ports in traffic.items():
        unique_ports = {p for p in ports if p is not None}
        
        # High-intensity/Immediate scan -> HIGH Severity
        if len(unique_ports) >= threshold:
            alerts.append({
                "message": f"High: Port Scan Detected from {ip} ({len(unique_ports)} ports)",
                "score": 95,  # Matches High Level
                "src_ip": ip,
                "type": "PORT_SCAN"
            })
        # Even 2 ports is now suspicious -> MEDIUM Severity
        elif len(unique_ports) >= 2:
            alerts.append({
                "message": f"Medium: Suspicious Port Probing from {ip}",
                "score": 65,  # Matches Medium Level
                "src_ip": ip,
                "type": "PORT_SCAN"
            })

    return alerts

# ===============================
# TRAFFIC SPIKE (DoS / SYN FLOOD)
# ===============================
def detect_traffic_spike(packet_count):
    """
    Detects sudden bursts of traffic.
    Updated: Lowered limit to 50 packets to show results faster.
    """
    alerts = []
    threshold = 50 

    for ip, count in packet_count.items():
        # Severe spike -> HIGH Severity
        if count >= (threshold * 2):
            alerts.append({
                "message": f"High: Denial of Service (DoS) Pattern from {ip}",
                "score": 98,
                "src_ip": ip,
                "type": "TRAFFIC_SPIKE"
            })
        # Moderate spike -> MEDIUM Severity
        elif count >= threshold:
            alerts.append({
                "message": f"Medium: Traffic Spike from {ip} ({count} pkts)",
                "score": 70,
                "src_ip": ip,
                "type": "TRAFFIC_SPIKE"
            })

    return alerts

# ===============================
# CYBER ATTACK: SSH / BRUTE FORCE
# ===============================
def detect_brute_force(traffic):
    """
    Specifically looks for repeated hits on Port 22.
    Basis: High-frequency attempts on a single service.
    """
    alerts = []
    for ip, ports in traffic.items():
        ssh_hits = ports.count(22)
        if ssh_hits > 3: # Lowered from 10 to 3 for demo
            alerts.append({
                "message": f"High: SSH Brute Force Attempt from {ip}",
                "score": 100,
                "src_ip": ip,
                "type": "BRUTE_FORCE"
            })
    return alerts

# ===============================
# ACTIVE CONNECTION
# ==============================
def detect_active_ip(packet_count):
    """
    Tracks new active IPs -> LOW Severity.
    """
    alerts = []
    for ip, count in packet_count.items():
        if count >= 2:
            alerts.append({
                "message": f"Low: Active connection established: {ip}",
                "score": 20, # Matches Low Level
                "src_ip": ip,
                "type": "ACTIVE_IP"
            })
    return alerts

# =====================================
# LIVE ACTIVITY
# =====================================
def detect_live_activity(packet_count):
    """
    Baseline traffic observation -> LOW Severity.
    """
    alerts = []
    for ip, count in packet_count.items():
        if count >= 1:
            alerts.append({
                "message": f"Low: Live traffic observed from {ip}",
                "score": 10, # Matches Low Level
                "src_ip": ip,
                "type": "LIVE"
            })
    return alerts