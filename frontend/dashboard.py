import streamlit as st
import sqlite3
import pandas as pd
import time
import ctypes
from core.config import CONFIG
from core.database import clear_database

DB_NAME = "alerts.db"

# --- 1. SYSTEM CONFIGURATION ---
st.set_page_config(page_title="Network Intrusion Detection System", layout="wide")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ==============================
# DATA RETRIEVAL ENGINE
# ==============================
def load_data():
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False, timeout=20)
        p_df = pd.read_sql_query("SELECT * FROM packets ORDER BY id DESC LIMIT 5000", conn)
        a_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 1000", conn)
        total_p = pd.read_sql_query("SELECT COUNT(*) as count FROM packets", conn).iloc[0]['count']
        conn.close()
        
        proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '2': 'IGMP'}
        for df in [p_df, a_df]:
            if not df.empty and 'protocol' in df.columns:
                df['protocol'] = df['protocol'].astype(str).replace(proto_map)
        return p_df, a_df, total_p
    except Exception:
        return pd.DataFrame(), pd.DataFrame(), 0

# ==============================
# SIDEBAR: ADVANCED ENGINE CONTROLS
# ==============================
st.sidebar.title("System Control Panel")
st.sidebar.markdown("---")

# --- 1. SENSITIVITY CALIBRATION ---
with st.sidebar.expander("🎯 Detection Sensitivity", expanded=True):
    CONFIG["PORT_SCAN_THRESHOLD"] = st.slider("Port Scan Limit (Unique Ports)", 2, 50, CONFIG.get("PORT_SCAN_THRESHOLD", 5))
    CONFIG["SSH_BRUTE_FORCE_LIMIT"] = st.slider("SSH Brute Force Limit", 2, 20, CONFIG.get("SSH_BRUTE_FORCE_LIMIT", 5))
    CONFIG["TRAFFIC_SPIKE_THRESHOLD"] = st.slider("Traffic Spike Limit (PPS)", 10, 2000, CONFIG.get("TRAFFIC_SPIKE_THRESHOLD", 200))

# --- 2. TRAFFIC INSPECTION RULES ---
with st.sidebar.expander("📡 Traffic Inspection Rules", expanded=False):
    min_size = st.number_input("Min Packet Size (Bytes)", 0, 1500, 0)
    max_size = st.number_input("Max Packet Size (Bytes)", 0, 1500, 1500)
    refresh_rate = st.slider("Telemetry Refresh (s)", 1, 10, 2)

st.sidebar.markdown("---")
# --- EXPORT CONTROLS ---
st.sidebar.subheader("Export Intelligence")
p_df_dl, a_df_dl, _ = load_data()

if not a_df_dl.empty:
    csv_alerts = a_df_dl.to_csv(index=False).encode('utf-8')
    st.sidebar.download_button("📥 Download Incident Logs", data=csv_alerts, file_name="security_incidents.csv", mime="text/csv")

if not p_df_dl.empty:
    csv_packets = p_df_dl.to_csv(index=False).encode('utf-8')
    st.sidebar.download_button("📦 Download Packet Stream", data=csv_packets, file_name="traffic_stream.csv", mime="text/csv")

st.sidebar.markdown("---")
# --- RESET CONTROL ---
if st.sidebar.button("🚨 Purge Session Data"):
    if clear_database():
        st.cache_data.clear()
        st.sidebar.success("Database Purged.")
        time.sleep(1)
        st.rerun()

st.sidebar.markdown("---")
if is_admin():
    st.sidebar.success("Administrative Privileges: Enabled")
else:
    st.sidebar.error("Administrative Privileges: Required")

# ==============================
# UI HEADER
# ==============================
st.title("Network Monitoring and Security Intelligence")
st.caption("Status: Operational | Analysis Engine: Active")

# ==============================
# DASHBOARD CORE FRAGMENT
# ==============================
@st.fragment(run_every=refresh_rate)
def render_dashboard():
    p_df, a_df, total_count = load_data()

    if p_df.empty and a_df.empty:
        st.info("System initializing. Awaiting inbound network traffic data.")
        return

    # --- TOAST NOTIFICATIONS ---
    if not a_df.empty:
        latest = a_df.iloc[0]
        if latest["severity"] == "CRITICAL":
            st.toast(f"CRITICAL: {latest['message']}")

    # ==============================
    # KPI METRICS
    # ==============================
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Captured", f"{total_count:,}")
    m2.metric("Total Alerts", len(a_df))
    m3.metric("Critical Events", len(a_df[a_df["severity"] == "CRITICAL"]) if not a_df.empty else 0)
    m4.metric("Active Source Nodes", p_df['src_ip'].nunique() if not p_df.empty else 0)

    # ==============================
    # ANALYTICS VISUALIZATION
    # ==============================
    st.divider()
    chart_h = 350
    
    st.write("**Throughput Analysis (Packets Per Second)**")
    if not p_df.empty:
        p_time = p_df.copy()
        p_time['timestamp'] = pd.to_datetime(p_time['timestamp'])
        ts = p_time.resample('1S', on='timestamp').size()
        st.line_chart(ts, color="#29b5e8", height=250)

    g1, g2, g3 = st.columns(3)
    with g1:
        st.write("**Protocol Frequency Distribution**")
        st.bar_chart(p_df["protocol"].value_counts(), height=chart_h)
    with g2:
        st.write("**High-Activity Source Nodes**")
        st.bar_chart(p_df["src_ip"].value_counts().head(5), height=chart_h)
    with g3:
        st.write("**Cumulative Host Risk Scoring**")
        if not a_df.empty:
            risk = a_df.groupby("src_ip")["score"].sum().sort_values(ascending=False).head(5)
            st.bar_chart(risk, color="#ff4b4b", height=chart_h)

    # ==============================
    # DATA TABS
    # ==============================
    st.divider()
    tab1, tab2, tab3 = st.tabs(["Incident Logs", "Threat Intelligence", "Packet Stream"])
    
    def color_sev(val):
        if val == 'CRITICAL': return 'color: #ff4b4b; font-weight: bold'
        if val == 'WARNING': return 'color: #ffa500; font-weight: bold'
        return 'color: #1f77b4'

    with tab1:
        st.dataframe(a_df[["timestamp", "severity", "src_ip", "message"]].style.applymap(color_sev, subset=['severity']), use_container_width=True)

    with tab2:
        threat_patterns = 'Scan|Attack|Force|Spike|Brute'
        cyber_intel = a_df[a_df['message'].str.contains(threat_patterns, case=False, na=False)]
        st.dataframe(cyber_intel[["timestamp", "src_ip", "message", "port", "protocol", "severity"]], use_container_width=True)

    with tab3:
        st.dataframe(p_df[["timestamp", "src_ip", "dst_ip", "protocol", "port", "packet_size"]].head(500), use_container_width=True)

render_dashboard()