# ===============================
# GLOBAL CONFIGURATION
# ===============================

CONFIG = {
    # --- CAPTURE SETTINGS ---
    "WINDOW_SIZE": 10,              # REDUCED: Analyzes every 10 packets for faster UI updates
    "SAVE_RAW_PACKETS": True,       
    "BATCH_SAVE_LIMIT": 100,        # NEW: Max packets saved per cycle to prevent hanging

    # --- DETECTION THRESHOLDS ---
    "PORT_SCAN_THRESHOLD": 5,       
    "TRAFFIC_SPIKE_THRESHOLD": 150, # Adjusted for smaller window
    "ACTIVE_IP_THRESHOLD": 2,       
    "LIVE_ACTIVITY_THRESHOLD": 3,   

    # --- CYBER ATTACK SPECIFICS ---
    "SSH_BRUTE_FORCE_LIMIT": 5,     
    "SYN_FLOOD_THRESHOLD": 30,      
    "SUSPICIOUS_PORTS": [21, 22, 23, 445, 3389], 

    # --- THREAT SCORING (0-100) ---
    "PORT_SCAN_SCORE": 85,
    "TRAFFIC_SPIKE_SCORE": 65,
    "BRUTE_FORCE_SCORE": 90,
    "ACTIVE_IP_SCORE": 10,

    # --- DASHBOARD & UI ---
    "AUTO_REFRESH_SEC": 2,          # Faster UI polling
    "MAX_LOG_DISPLAY": 100,         

    # --- ALERT CONTROL ---
    "ALERT_COOLDOWN_SEC": 10        # Prevents popup spam during scans
}