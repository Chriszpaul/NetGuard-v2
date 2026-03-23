import streamlit as st
import sqlite3
import pandas as pd
import time
import ctypes
from core.config import CONFIG
from core.database import clear_database

DB_NAME = "alerts.db"

# --- 1. SYSTEM CONFIGURATION ---
st.set_page_config(page_title="NetGuard v2.0 - SOC Dashboard", layout="wide")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ==============================
# DATA RETRIEVAL & SERVICE MAPPING
# ==============================
def load_data():
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False, timeout=20)
        p_df = pd.read_sql_query("SELECT * FROM packets ORDER BY id DESC LIMIT 5000", conn)
        a_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 1000", conn)
        total_p = pd.read_sql_query("SELECT COUNT(*) as count FROM packets", conn).iloc[0]['count']
        conn.close()
        
        # Protocol Layer Mapping
        proto_map = {'1': 'ICMP', '2': 'IGMP', '6': 'TCP', '17': 'UDP', '47': 'GRE', '50': 'ESP'}
        
        for df in [p_df, a_df]:
            if not df.empty:
                # Map Transport Protocols
                if 'protocol' in df.columns:
                    df['protocol'] = df['protocol'].astype(str).replace(proto_map)
                
                # NEW: Application Service Detection (Layer 7 Mapping)
                if 'port' in df.columns:
                    df['service'] = 'Other'
                    # Convert port to numeric for comparison
                    df['port_num'] = pd.to_numeric(df['port'], errors='coerce')
                    df.loc[df['port_num'] == 80, 'service'] = '🌐 HTTP'
                    df.loc[df['port_num'] == 443, 'service'] = '🔒 HTTPS'
                    df.loc[df['port_num'] == 22, 'service'] = '🔑 SSH'
                    df.loc[df['port_num'] == 53, 'service'] = '🆔 DNS'
                    df.loc[df['port_num'] == 3389, 'service'] = '🖥️ RDP'
        
        return p_df, a_df, total_p
    except Exception:
        return pd.DataFrame(), pd.DataFrame(), 0

# ==============================
# SIDEBAR: ADVANCED ENGINE CONTROLS
# ==============================
st.sidebar.title("🛡️ NetGuard v2.0")
st.sidebar.markdown("---")

# --- 1. SENSITIVITY CALIBRATION ---
with st.sidebar.expander("🎯 Detection Sensitivity", expanded=True):
    CONFIG["PORT_SCAN_THRESHOLD"] = st.slider("Port Scan Limit", 2, 50, CONFIG.get("PORT_SCAN_THRESHOLD", 5))
    CONFIG["SSH_BRUTE_FORCE_LIMIT"] = st.slider("SSH Brute Force Limit", 2, 20, CONFIG.get("SSH_BRUTE_FORCE_LIMIT", 5))
    CONFIG["TRAFFIC_SPIKE_THRESHOLD"] = st.slider("Traffic Spike Limit (PPS)", 10, 2000, CONFIG.get("TRAFFIC_SPIKE_THRESHOLD", 200))

with st.sidebar.expander("📡 System Settings", expanded=False):
    refresh_rate = st.slider("Telemetry Refresh (s)", 1, 10, 2)

st.sidebar.markdown("---")
# --- EXPORT CONTROLS ---
st.sidebar.subheader("Export Intelligence")
p_df_dl, a_df_dl, _ = load_data()

if not a_df_dl.empty:
    csv_alerts = a_df_dl.to_csv(index=False).encode('utf-8')
    st.sidebar.download_button("📥 Download Incident Logs", data=csv_alerts, file_name="security_incidents.csv", mime="text/csv")

# --- RESET CONTROL ---
if st.sidebar.button("🚨 Purge Session Data"):
    if clear_database():
        st.cache_data.clear()
        st.sidebar.success("Database Purged.")
        time.sleep(1)
        st.rerun()

# ==============================
# UI HEADER
# ==============================
st.title("Network Monitoring and Security Intelligence")
st.caption(f"Status: Operational | Host: 10.186.171.135 | Admin: {'Enabled' if is_admin() else 'Required'}")

# ==============================
# DASHBOARD CORE FRAGMENT
# ==============================
@st.fragment(run_every=refresh_rate)
def render_dashboard():
    p_df, a_df, total_count = load_data()

    if p_df.empty and a_df.empty:
        st.info("System initializing. Awaiting inbound network traffic data...")
        return

    # ==============================
    # SECURITY INTELLIGENCE FILTERS
    # ==============================
    with st.expander("🔍 Filter Threat Intelligence", expanded=False):
        f1, f2, f3 = st.columns(3)
        with f1:
            selected_proto = st.multiselect("Protocols", options=["TCP", "UDP", "ICMP", "IGMP"], default=["TCP", "UDP", "ICMP", "IGMP"])
        with f2:
            selected_sev = st.multiselect("Severity", options=["INFO", "WARNING", "CRITICAL"], default=["INFO", "WARNING", "CRITICAL"])
        with f3:
            ip_search = st.text_input("Search Source IP", placeholder="e.g. 10.186.171.135")

    # Apply Filters
    if not p_df.empty:
        p_df = p_df[p_df['protocol'].isin(selected_proto)]
        if ip_search:
            p_df = p_df[p_df['src_ip'].str.contains(ip_search, na=False)]
    
    if not a_df.empty:
        a_df = a_df[a_df['severity'].isin(selected_sev)]
        if ip_search:
            a_df = a_df[a_df['src_ip'].str.contains(ip_search, na=False)]

    # --- TOAST NOTIFICATIONS ---
    if not a_df.empty:
        latest = a_df.iloc[0]
        if latest["severity"] == "CRITICAL":
            st.toast(f"🚨 CRITICAL ALERT: {latest['message']}")

    # ==============================
    # KPI METRICS
    # ==============================
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Captured", f"{total_count:,}")
    m2.metric("Total Alerts", len(a_df))
    m3.metric("Critical Events", len(a_df[a_df["severity"] == "CRITICAL"]) if not a_df.empty else 0)
    m4.metric("Active Nodes", p_df['src_ip'].nunique() if not p_df.empty else 0)

    # ==============================
    # ANALYTICS VISUALIZATION
    # ==============================
    st.divider()
    chart_h = 300
    
    st.write("**Real-Time Network Throughput (PPS)**")
    if not p_df.empty:
        p_time = p_df.copy()
        p_time['timestamp'] = pd.to_datetime(p_time['timestamp'])
        ts = p_time.resample('1S', on='timestamp').size()
        st.line_chart(ts, color="#29b5e8", height=180)

    g1, g2, g3 = st.columns(3)
    with g1:
        st.write("**Top Application Services**")
        st.bar_chart(p_df["service"].value_counts(), height=chart_h)
    with g2:
        st.write("**Top Threat Sources**")
        if not a_df.empty:
            st.bar_chart(a_df["src_ip"].value_counts().head(5), height=chart_h)
    with g3:
        st.write("**Host Risk Scoring**")
        if not a_df.empty:
            risk = a_df.groupby("src_ip")["score"].sum().sort_values(ascending=False).head(5)
            st.bar_chart(risk, color="#ff4b4b", height=chart_h)

    # ==============================
    # DATA TABS
    # ==============================
    st.divider()
    tab1, tab2, tab3 = st.tabs(["🛡️ Incident Logs", "🧠 Threat Intelligence", "📦 Packet Stream"])
    
    def color_sev(val):
        if val == 'CRITICAL': return 'color: #ff4b4b; font-weight: bold'
        if val == 'WARNING': return 'color: #ffa500; font-weight: bold'
        return 'color: #1f77b4'

    with tab1:
        st.dataframe(a_df[["timestamp", "severity", "src_ip", "message"]].style.map(color_sev, subset=['severity']), use_container_width=True)

    with tab2:
        threat_patterns = 'Scan|Attack|Force|Spike|Brute'
        cyber_intel = a_df[a_df['message'].str.contains(threat_patterns, case=False, na=False)]
        st.dataframe(cyber_intel[["timestamp", "src_ip", "message", "service", "severity"]], use_container_width=True)

    with tab3:
        # Finalized Stream View with Service Labels
        st.dataframe(p_df[["timestamp", "src_ip", "dst_ip", "service", "protocol", "port", "packet_size"]].head(500), use_container_width=True)

render_dashboard()