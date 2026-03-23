import streamlit as st
import sqlite3
import pandas as pd
import time
import binascii
from core.config import CONFIG
from core.database import clear_database

DB_NAME = "alerts.db"

st.set_page_config(page_title="NetGuard v2.0 - Unified SOC", layout="wide")

# ==============================
# DATA RETRIEVAL & DECODING
# ==============================
def decode_payload(hex_str, port, protocol):
    if not hex_str or hex_str == "" or hex_str == "None":
        return "ANALYSIS: Header-only frame (SYN/Ping/ACK). No data payload present."
    try:
        if str(port) == "443":
            return "ANALYSIS: HTTPS/TLS Encrypted. Payload is scrambled for privacy."
        data = binascii.unhexlify(hex_str)
        return "".join([chr(b) if 32 <= b <= 126 else "." for b in data])
    except:
        return f"ANALYSIS: Binary Data Detected ({len(hex_str)//2} bytes)."

def load_data():
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False, timeout=20)
        
        # FIXED SQL: Explicitly mapping columns so they don't swap in the table
        p_df = pd.read_sql_query("SELECT * FROM packets ORDER BY id DESC LIMIT 5000", conn)
        
        # We pull alerts and packets separately to avoid the 'Shifted Column' bug
        a_df = pd.read_sql_query("SELECT id, timestamp, severity, src_ip, message, score FROM alerts ORDER BY id DESC LIMIT 1000", conn)
        
        total_p = pd.read_sql_query("SELECT COUNT(*) as count FROM packets", conn).iloc[0]['count']
        conn.close()
        
        proto_map = {'1': 'ICMP', '2': 'IGMP', '6': 'TCP', '17': 'UDP', '5353': 'mDNS'}
        
        if not p_df.empty:
            p_df['protocol'] = p_df['protocol'].astype(str).replace(proto_map)
        
        return p_df, a_df, total_p
    except Exception as e:
        st.error(f"Load Error: {e}")
        return pd.DataFrame(), pd.DataFrame(), 0

# ==============================
# SIDEBAR
# ==============================
st.sidebar.title("NetGuard v2.0")
st.sidebar.markdown("---")
with st.sidebar.expander("Detection Sensitivity", expanded=True):
    CONFIG["PORT_SCAN_THRESHOLD"] = st.slider("Port Scan Limit", 2, 50, 5)
    CONFIG["SSH_BRUTE_FORCE_LIMIT"] = st.slider("SSH Brute Force Limit", 2, 20, 5)
    CONFIG["TRAFFIC_SPIKE_THRESHOLD"] = st.slider("Traffic Spike Limit (PPS)", 10, 2000, 150)

if "refresh_val" not in st.session_state: st.session_state.refresh_val = 2
with st.sidebar.expander("System Settings", expanded=False):
    st.session_state.refresh_val = st.slider("Telemetry Refresh (s)", 1, 10, st.session_state.refresh_val)

st.sidebar.markdown("---")
if st.sidebar.button("Purge Session Data"):
    if clear_database(): st.rerun()

# ==============================
# MAIN UI & FILTERS
# ==============================
st.title("Network Monitoring and Security Intelligence")
st.caption(f"Status: Operational | Host: 10.186.171.135 | Admin Privileges: Enabled")

# These filters stay outside the fragment so they don't reset
with st.expander("Filter Threat Intelligence", expanded=True):
    f1, f2, f3 = st.columns(3)
    with f1: sel_proto = st.multiselect("Protocols", options=["TCP", "UDP", "ICMP", "IGMP", "HTTPS", "mDNS"], default=["TCP", "UDP", "ICMP", "IGMP"])
    with f2: sel_sev = st.multiselect("Severity", options=["Low", "Medium", "High"], default=["Low", "Medium", "High"])
    with f3: ip_search = st.text_input("Search Source IP", placeholder="e.g. 10.186.171.135")

@st.fragment(run_every=st.session_state.refresh_val)
def render_main_dashboard():
    p_df, a_df, total_count = load_data()
    if p_df.empty and a_df.empty:
        st.warning("⚠️ Waiting for data from backend/live_capture.py...")
        return

    # Apply Filters
    if not p_df.empty:
        p_df = p_df[p_df['protocol'].isin(sel_proto)]
        if ip_search: p_df = p_df[p_df['src_ip'].str.contains(ip_search, na=False)]
    if not a_df.empty:
        a_df = a_df[a_df['severity'].isin(sel_sev)]
        if ip_search: a_df = a_df[a_df['src_ip'].str.contains(ip_search, na=False)]

    # Metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Captured", f"{total_count:,}")
    m2.metric("Total Alerts", len(a_df))
    m3.metric("Critical Events", len(a_df[a_df["severity"] == "High"]) if not a_df.empty else 0)
    m4.metric("Active Nodes", p_df['src_ip'].nunique() if not p_df.empty else 0)

    # Line Graph
    st.divider()
    if not p_df.empty:
        p_time = p_df.copy().assign(t=pd.to_datetime(p_df['timestamp']))
        st.line_chart(p_time.resample('1S', on='t').size(), color="#29b5e8", height=180)

    # Bar Charts
    g1, g2, g3 = st.columns(3)
    with g1: st.bar_chart(p_df["protocol"].value_counts(), height=250)
    with g2: st.bar_chart(a_df["src_ip"].value_counts().head(5), height=250)
    with g3: 
        if not a_df.empty: st.bar_chart(a_df.groupby("src_ip")["score"].sum().head(5), color="#ff4b4b", height=250)

    # TABS
    st.divider()
    tab1, tab2, tab3 = st.tabs(["Incident Logs", "Packet Stream", "Deep Packet Dissector"])

    def color_sev(val):
        if val == 'High': return 'color: #ff4b4b; font-weight: bold'
        if val == 'Medium': return 'color: #ffa500; font-weight: bold'
        return 'color: #1f77b4'

    with tab1:
        if not a_df.empty:
            # Table is now clean with correct column alignment
            st.dataframe(a_df[["timestamp", "severity", "src_ip", "message"]].style.map(color_sev, subset=['severity']), use_container_width=True)

    with tab2:
        st.dataframe(p_df[["id", "timestamp", "src_ip", "dst_ip", "protocol", "port", "packet_size"]].head(100), use_container_width=True)

    with tab3:
        st.write("**Wireshark Mode**")
        source_choice = st.radio("Inspect From:", ["Packet Stream", "Incident Logs"], horizontal=True)
        
        # ID selection
        ids = p_df['id'].tolist() if source_choice == "Packet Stream" else a_df['id'].tolist()
        
        if ids:
            sel_id = st.selectbox("Select ID:", ids)
            target = p_df[p_df['id'] == sel_id]
            
            if not target.empty:
                t = target.iloc[0]
                c1, c2 = st.columns(2)
                with c1:
                    st.json({"ID": int(t['id']), "Source": t['src_ip'], "Port": t['port'], "Protocol": t['protocol']})
                with c2:
                    decoded = decode_payload(t.get('raw_payload', ""), t['port'], t['protocol'])
                    st.code(decoded, language="text")

render_main_dashboard()