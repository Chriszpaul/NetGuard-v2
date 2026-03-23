import streamlit as st
import sqlite3
import pandas as pd
import time
import ctypes
import binascii
from core.config import CONFIG
from core.database import clear_database

DB_NAME = "alerts.db"

# --- 1. SYSTEM CONFIGURATION ---
st.set_page_config(page_title="NetGuard v2.0 - Unified SOC", layout="wide")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ==============================
# DATA RETRIEVAL & DECODING
# ==============================
def decode_payload(hex_str):
    if not hex_str or hex_str == "":
        return "No Payload Data Available"
    try:
        data = binascii.unhexlify(hex_str)
        return "".join([chr(b) if 32 <= b <= 126 else "." for b in data])
    except:
        return "Binary Data (Non-ASCII)"

def load_data():
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False, timeout=20)
        p_df = pd.read_sql_query("SELECT * FROM packets ORDER BY id DESC LIMIT 5000", conn)
        a_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 1000", conn)
        total_p = pd.read_sql_query("SELECT COUNT(*) as count FROM packets", conn).iloc[0]['count']
        conn.close()
        
        proto_map = {'1': 'ICMP', '2': 'IGMP', '6': 'TCP', '17': 'UDP', '5353': 'mDNS'}
        sev_map = {'INFO': 'Low', 'WARNING': 'Medium', 'CRITICAL': 'High'}
        
        for df in [p_df, a_df]:
            if not df.empty:
                if 'protocol' in df.columns:
                    df['protocol'] = df['protocol'].astype(str).replace(proto_map)
                if 'severity' in df.columns:
                    df['severity'] = df['severity'].replace(sev_map)
                if 'port' in df.columns:
                    df['port_num'] = pd.to_numeric(df['port'], errors='coerce')
                    df['service'] = "Other"
                    df.loc[df['port_num'] == 80, 'service'] = 'HTTP'
                    df.loc[df['port_num'] == 443, 'service'] = 'HTTPS'
                    df.loc[df['port_num'] == 22, 'service'] = 'SSH'
                    df.loc[df['port_num'] == 53, 'service'] = 'DNS'
        
        return p_df, a_df, total_p
    except Exception:
        return pd.DataFrame(), pd.DataFrame(), 0

# ==============================
# SIDEBAR: SOC CONTROLS
# ==============================
st.sidebar.title("NetGuard v2.0")
st.sidebar.markdown("---")

with st.sidebar.expander("Detection Sensitivity", expanded=True):
    CONFIG["PORT_SCAN_THRESHOLD"] = st.slider("Port Scan Limit", 2, 50, 5)
    CONFIG["SSH_BRUTE_FORCE_LIMIT"] = st.slider("SSH Brute Force Limit", 2, 20, 5)
    CONFIG["TRAFFIC_SPIKE_THRESHOLD"] = st.slider("Traffic Spike Limit (PPS)", 10, 2000, 200)

with st.sidebar.expander("System Settings", expanded=False):
    refresh_rate = st.slider("Telemetry Refresh (s)", 1, 10, 2)

st.sidebar.markdown("---")
st.sidebar.subheader("Export Intelligence")
p_df_dl, a_df_dl, _ = load_data()

if not a_df_dl.empty:
    csv_alerts = a_df_dl.to_csv(index=False).encode('utf-8')
    st.sidebar.download_button("Download Incident Logs", data=csv_alerts, file_name="security_incidents.csv", mime="text/csv")

if not p_df_dl.empty:
    csv_packets = p_df_dl.to_csv(index=False).encode('utf-8')
    st.sidebar.download_button("Download Packet Stream", data=csv_packets, file_name="traffic_stream.csv", mime="text/csv")

st.sidebar.markdown("---")
if st.sidebar.button("Purge Session Data"):
    if clear_database():
        st.cache_data.clear()
        st.sidebar.success("Database Purged.")
        time.sleep(1)
        st.rerun()

# ==============================
# UI HEADER
# ==============================
st.title("Network Monitoring and Security Intelligence")
st.caption(f"Status: Operational | Host: 10.186.171.135 | Admin Privileges: {'Enabled' if is_admin() else 'Required'}")

# ==============================
# DASHBOARD CORE
# ==============================
@st.fragment(run_every=refresh_rate)
def render_dashboard():
    p_df, a_df, total_count = load_data()

    if p_df.empty and a_df.empty:
        st.info("System initializing. Awaiting inbound network traffic data...")
        return

    # 🔍 FILTERS (RESTORED)
    with st.expander("Filter Live Threat Intelligence", expanded=False):
        f1, f2, f3 = st.columns(3)
        with f1:
            selected_proto = st.multiselect("Protocols", options=["TCP", "UDP", "ICMP", "IGMP"], default=["TCP", "UDP", "ICMP", "IGMP"])
        with f2:
            selected_sev = st.multiselect("Severity", options=["Low", "Medium", "High"], default=["Low", "Medium", "High"])
        with f3:
            ip_search = st.text_input("Search Source IP", placeholder="e.g. 10.186.171.135")

    # Filter Logic
    if not p_df.empty:
        p_df = p_df[p_df['protocol'].isin(selected_proto)]
        if ip_search:
            p_df = p_df[p_df['src_ip'].str.contains(ip_search, na=False)]
    
    if not a_df.empty:
        a_df = a_df[a_df['severity'].isin(selected_sev)]
        if ip_search:
            a_df = a_df[a_df['src_ip'].str.contains(ip_search, na=False)]

    # POP-UP NOTIFICATION
    if not a_df.empty:
        latest = a_df.iloc[0]
        if latest["severity"] == "High":
            st.toast(f"HIGH SEVERITY ALERT: {latest['message']}")

    # KPI METRICS
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Captured", f"{total_count:,}")
    m2.metric("Total Alerts", len(a_df))
    m3.metric("High Severity", len(a_df[a_df["severity"] == "High"]) if not a_df.empty else 0)
    m4.metric("Active Nodes", p_df['src_ip'].nunique() if not p_df.empty else 0)

    # THROUGHPUT LINE GRAPH
    st.divider()
    st.write("**Throughput Analysis (Packets Per Second)**")
    if not p_df.empty:
        p_time = p_df.copy()
        p_time['timestamp'] = pd.to_datetime(p_time['timestamp'])
        ts = p_time.resample('1S', on='timestamp').size()
        st.line_chart(ts, color="#29b5e8", height=200)

    # THREE BAR GRAPHS
    g1, g2, g3 = st.columns(3)
    with g1:
        st.write("**Protocol Distribution**")
        st.bar_chart(p_df["protocol"].value_counts(), height=300)
    with g2:
        st.write("**High-Activity Source Nodes**")
        st.bar_chart(p_df["src_ip"].value_counts().head(5), height=300)
    with g3:
        st.write("**Cumulative Host Risk Scoring**")
        if not a_df.empty:
            risk = a_df.groupby("src_ip")["score"].sum().sort_values(ascending=False).head(5)
            st.bar_chart(risk, color="#ff4b4b", height=300)

    # DATA TABS
    st.divider()
    tab1, tab2, tab3 = st.tabs(["Incident Logs", "Packet Stream", "Deep Packet Dissector"])

    def color_sev(val):
        if val == 'High': return 'color: #ff4b4b; font-weight: bold'
        if val == 'Medium': return 'color: #ffa500; font-weight: bold'
        return 'color: #1f77b4'

    with tab1:
        st.write("**Recent Security Incidents**")
        if not a_df.empty:
            st.dataframe(a_df[["timestamp", "severity", "src_ip", "message"]].style.map(color_sev, subset=['severity']), use_container_width=True)

    with tab2:
        st.write("**Live Network Traffic Stream**")
        st.dataframe(p_df[["timestamp", "src_ip", "dst_ip", "protocol", "port", "packet_size"]].head(100), use_container_width=True)

    with tab3:
        st.write("**Wireshark Mode: Deep Packet Inspection**")
        source_choice = st.radio("Inspect Packet From:", ["Packet Stream", "Incident Logs"], horizontal=True)
        
        id_list = (p_df['id'] if source_choice == "Packet Stream" else a_df['id']).head(50).tolist()
            
        if id_list:
            selected_id = st.selectbox("Select ID to Dissect:", id_list)
            p_target = p_df[p_df['id'] == selected_id].iloc[0] if selected_id in p_df['id'].values else None
            
            if p_target is not None:
                c1, c2 = st.columns(2)
                with c1:
                    st.json({"Source": p_target['src_ip'], "Dest": p_target['dst_ip'], "Port": p_target['port'], "Protocol": p_target['protocol']})
                with c2:
                    decoded = decode_payload(p_target.get('raw_payload', ""))
                    st.code(decoded, language="text")

render_dashboard()