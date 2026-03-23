from scapy.all import sniff, IP, TCP, Raw
from core.analyzer import analyze_packets
from core.detector import (
    detect_active_ip,
    detect_port_scan,
    detect_traffic_spike,
    detect_live_activity,
    detect_brute_force
)
from core.database import init_db, save_alert, save_packet
from core.config import CONFIG

import os
import time

STOP_FILE = "stop.signal"

# --- CONFIG ---
WINDOW_SIZE = CONFIG.get("WINDOW_SIZE", 10)
SAVE_RAW = CONFIG.get("SAVE_RAW_PACKETS", True)
SAVE_LIMIT = CONFIG.get("BATCH_SAVE_LIMIT", 100)

print(" ENGINE START: High-Frequency Monitoring Mode")
init_db()

captured_packets = []
last_alert_time = {}
ssh_attempts = {}

def process_packet(packet):
    global captured_packets, last_alert_time
    
    # --- 1. INSTANT CRITICAL CHECKS (SSH) ---
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].dport == 22:
        src = packet[IP].src
        now = time.time()
        ssh_attempts.setdefault(src, []).append(now)
        ssh_attempts[src] = [t for t in ssh_attempts[src] if now - t < 30]
        
        if len(ssh_attempts[src]) > CONFIG.get("SSH_BRUTE_FORCE_LIMIT", 5):
            msg = f"High: SSH Brute Force from {src}" # UPDATED LABEL
            if msg not in last_alert_time or (now - last_alert_time[msg] > 10):
                # Using new High/Medium/Low labels
                save_alert(msg, "High", src, packet[IP].dst, "TCP", 22, 1)
                last_alert_time[msg] = now
                print(f" ALERT: {msg}")

    # --- 2. BUFFERING ---
    captured_packets.append(packet)

    if len(captured_packets) >= WINDOW_SIZE:
        batch = captured_packets[:]
        captured_packets.clear()
        
        try:
            traffic, pkt_counts, details, stats = analyze_packets(batch)

            # --- 3. OPTIMIZED BULK SAVE (With Raw Payload for Wireshark Mode) ---
            if SAVE_RAW:
                for idx, p in enumerate(details[:SAVE_LIMIT]):
                    # Extract raw hex payload for Deep Packet Inspection
                    raw_payload = ""
                    try:
                        orig_pkt = batch[idx]
                        if orig_pkt.haslayer(Raw):
                            raw_payload = orig_pkt[Raw].load.hex()
                    except:
                        pass
                        
                    # Updated save_packet to include the raw payload hex
                    save_packet(
                        p['src_ip'], 
                        p['dst_ip'], 
                        p['protocol'], 
                        p['port'], 
                        p['packet_size'],
                        raw_payload # Added this to match dashboard needs
                    )

            # --- 4. DETECTORS (Dynamic Labeling) ---
            found = []
            found += detect_port_scan(traffic)
            found += detect_traffic_spike(pkt_counts)
            found += detect_brute_force(traffic)
            
            for a in found:
                msg = a["message"]
                now = time.time()
                if msg not in last_alert_time or (now - last_alert_time[msg] > 15):
                    score = a.get("score", 10)
                    
                    # RE-ALIGNED SEVERITY LABELS
                    if score >= 80: sev = "High"
                    elif score >= 50: sev = "Medium"
                    else: sev = "Low"
                    
                    save_alert(msg, sev, a.get("src_ip"), None, "TCP", None, None)
                    last_alert_time[msg] = now
                    print(f" {sev}: {msg}")
            
        except Exception as e:
            print(f"Error in processing: {e}")
            pass

def should_stop(pkt):
    return os.path.exists(STOP_FILE)

# store=False is important to prevent memory leaks during long demos
sniff(prn=process_packet, store=False, stop_filter=should_stop)