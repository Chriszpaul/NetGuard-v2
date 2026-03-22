import sqlite3
import os
from datetime import datetime

DB_NAME = "alerts.db"
LOG_DIR = "logs"

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def write_log(message):
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        logfile = os.path.join(LOG_DIR, f"alerts_{today}.log")
        timestamp = datetime.now().strftime("%H:%M:%S")
        # Added explicit encoding and flush to ensure it writes immediately
        with open(logfile, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
            f.flush()
    except Exception as e:
        print(f"Logging Error: {e}")

def init_db():
    conn = sqlite3.connect(DB_NAME, timeout=20)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;") 
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, message TEXT, severity TEXT, score INTEGER, src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER, packet_count INTEGER)")
    cursor.execute("CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER, packet_size INTEGER)")
    conn.commit()
    conn.close()

def save_packet(src_ip, dst_ip, protocol, port, packet_size):
    try:
        conn = sqlite3.connect(DB_NAME, timeout=20)
        conn.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, port, packet_size) VALUES (?, ?, ?, ?, ?, ?)", 
                     (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), src_ip, dst_ip, protocol, port, packet_size))
        conn.commit()
        conn.close()
    except: pass

def save_alert(message, severity, src_ip=None, dst_ip=None, protocol=None, port=None, packet_count=None):
    score_map = {"INFO": 20, "WARNING": 60, "CRITICAL": 95}
    score = score_map.get(severity, 10)
    try:
        conn = sqlite3.connect(DB_NAME, timeout=20)
        conn.execute("INSERT INTO alerts (timestamp, message, severity, score, src_ip, dst_ip, protocol, port, packet_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message, severity, score, src_ip, dst_ip, protocol, port, packet_count))
        conn.commit()
        conn.close()
        write_log(f"{severity} | {message} | {src_ip}")
    except Exception as e:
        print(f"Alert Save Error: {e}")

def clear_database():
    try:
        conn = sqlite3.connect(DB_NAME, timeout=20)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts")
        cursor.execute("DELETE FROM packets")
        conn.commit()
        # VACUUM is critical here to physically wipe the file data
        cursor.execute("VACUUM")
        conn.close()
        return True
    except Exception as e:
        print(f"Reset Error: {e}")
        return False