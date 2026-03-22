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
        
        # High-intensity/Immediate scan
        if len(unique_ports) >= threshold:
            alerts.append({
                "message": f"CRITICAL: Port Scan Detected from {ip} ({len(unique_ports)} ports)",
                "score": 95,  # Force Critical Level
                "src_ip": ip,
                "type": "PORT_SCAN"
            })
        # Even 2 ports is now suspicious
        elif len(unique_ports) >= 2:
            alerts.append({
                "message": f"WARNING: Suspicious Port Probing from {ip}",
                "score": 65,  # Force Warning Level
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
        if count >= (threshold * 2):
            alerts.append({
                "message": f"CRITICAL: Denial of Service (DoS) Pattern from {ip}",
                "score": 98,
                "src_ip": ip,
                "type": "TRAFFIC_SPIKE"
            })
        elif count >= threshold:
            alerts.append({
                "message": f"WARNING: Traffic Spike from {ip} ({count} pkts)",
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
    """
    alerts = []
    for ip, ports in traffic.items():
        ssh_hits = ports.count(22)
        if ssh_hits > 3: # Lowered from 10 to 3 for demo
            alerts.append({
                "message": f"CRITICAL: SSH Brute Force Attempt from {ip}",
                "score": 100,
                "src_ip": ip,
                "type": "BRUTE_FORCE"
            })
    return alerts

# ===============================
# ACTIVE CONNECTION
# ==============================
def detect_active_ip(packet_count):
    alerts = []
    for ip, count in packet_count.items():
        if count >= 2:
            alerts.append({
                "message": f"Connection established: {ip}",
                "score": 20, # Remains INFO level
                "src_ip": ip,
                "type": "ACTIVE_IP"
            })
    return alerts

# =====================================
# LIVE ACTIVITY
# =====================================
def detect_live_activity(packet_count):
    alerts = []
    for ip, count in packet_count.items():
        if count >= 1:
            alerts.append({
                "message": f"Traffic observed from {ip}",
                "score": 10,
                "src_ip": ip,
                "type": "LIVE"
            })
    return alerts