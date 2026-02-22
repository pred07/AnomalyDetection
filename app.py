import streamlit as st
import pandas as pd
import os
import time
import plotly.express as px
from modules.pcap_parser import parse_pcap
from modules.features import extract_features
from modules.anomaly_env import detect_anomalies
from modules.signatures import detect_signatures
from modules.scoring import calculate_threat_scores
from modules.report_gen import generate_pdf_report

# Page Config
st.set_page_config(page_title="NetShield | Anomaly Discovery", layout="wide", page_icon="🛡️")

# PREMIUM STYLING & CLEANUP
st.markdown("""
    <style>
    /* Hide Streamlit Header/Footer/Menu */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    .main {
        background-color: #0e1117;
        color: #e0e0e0;
    }
    .stMetric {
        background-color: #1a1c24;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #30363d;
    }
    div.stButton > button:first-child {
        background-color: #238636;
        color: white;
        border: none;
        border-radius: 6px;
    }
    h1, h2, h3 {
        color: #58a6ff;
    }
    /* Style the file uploader */
    .stFileUploader {
        padding: 20px;
        background-color: #161b22;
        border-radius: 10px;
        border: 2px dashed #30363d;
    }
    </style>
    """, unsafe_allow_html=True)

# App Title
st.title("🛡️ NetShield: Network Anomaly Discovery")
st.markdown("Advanced PCAP analysis with rule-based signature matching and statistical scoring.")

# INITIAL UPLOAD CONTAINER
uploaded_file = st.file_uploader("📂 Drag and drop or Click to upload PCAP/PCAPNG", type=['pcap', 'pcapng'], key="main_uploader")

if uploaded_file:
    temp_path = "temp_capture.pcap"
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    with st.spinner("🔍 Analyzing packets..."):
        progress_bar = st.progress(0)
        
        # 1. Parsing
        progress_bar.progress(10, text="Reading PCAP data...")
        df_raw = parse_pcap(temp_path)
        
        if not df_raw.empty:
            # 2. Features
            progress_bar.progress(30, text="Extracting behavioral features...")
            features_df = extract_features(df_raw)
            
            # 3. Anomaly Detection
            progress_bar.progress(50, text="Running statistical anomaly engine...")
            anomaly_alerts = detect_anomalies(features_df)
            
            # 4. Signature Matching
            progress_bar.progress(70, text="Matching attack signatures...")
            signature_alerts = detect_signatures(df_raw, features_df)
            
            all_alerts = anomaly_alerts + signature_alerts
            
            # 5. Scoring
            progress_bar.progress(90, text="Calculating threat scores...")
            threat_scores = calculate_threat_scores(features_df, all_alerts)
            
            progress_bar.progress(100, text="Analysis Complete!")

            # --- SECTION 2: Traffic Overview ---
            st.header("📈 Traffic Overview")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Packets", len(df_raw))
            m2.metric("Unique IPs", df_raw['src_ip'].nunique())
            m3.metric("Total Bytes", f"{df_raw['size'].sum() / 1024:.1f} KB")
            m4.metric("Total Alerts", len(all_alerts))
            
            c1, c2 = st.columns(2)
            with c1:
                fig_proto = px.pie(df_raw, names='protocol', title="Protocol Distribution", hole=0.4,
                                 color_discrete_sequence=px.colors.qualitative.Safe)
                st.plotly_chart(fig_proto, use_container_width=True)
            
            with c2:
                df_raw['time_bin'] = pd.to_datetime(df_raw['timestamp'], unit='s').dt.round('1s')
                timeline = df_raw.groupby('time_bin').size().reset_index(name='packets')
                fig_time = px.line(timeline, x='time_bin', y='packets', title="Traffic Volume Over Time")
                st.plotly_chart(fig_time, use_container_width=True)
            
            # --- SECTION 3: Alerts Panel ---
            st.header("⚠️ Threat Detection Alerts")
            if all_alerts:
                alerts_df = pd.DataFrame(all_alerts)
                st.table(alerts_df[['src_ip', 'type', 'severity', 'explanation']].sort_values(by='severity'))
            else:
                st.success("No anomalies or attack signatures detected.")
            
            # --- SECTION 4: Threat Scoreboard ---
            st.header("⚖️ IP Threat Scoreboard")
            st.dataframe(threat_scores, use_container_width=True, hide_index=True)
            
            # --- SECTION 5: Reports ---
            st.header("📄 Generate Reports")
            traff_summ = {
                "Filename": uploaded_file.name,
                "Total Packets": len(df_raw),
                "Unique IPs": df_raw['src_ip'].nunique(),
                "Critical Alerts": len([a for a in all_alerts if a['severity'] in ['High', 'Critical']])
            }
            
            pdf_data = generate_pdf_report(traff_summ, all_alerts, threat_scores)
            st.download_button(
                label="📥 Download PDF Report",
                data=pdf_data,
                file_name=f"Traffic_Report_{int(time.time())}.pdf",
                mime="application/pdf"
            )
            
        else:
            st.error("Could not parse PCAP. Please ensure the file is valid.")

else:
    # CLEAN LANDING PAGE
    st.markdown("---")
    st.info("### 🛡️ Welcome to NetShield")
    st.write("Please upload a network capture file (PCAP) above to start the behavioral analysis engine.")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("🔍 Detection Features")
        st.write("- **Port Scan** Detection")
        st.write("- **SYN Flood** Signatures")
        st.write("- **ARP Spoofing** Logic")
    with col2:
        st.subheader("📊 Analytical Results")
        st.write("- **IP Threat Scoring**")
        st.write("- **Traffic Timeline**")
        st.write("- **PDF Reporting**")

# Sidebar
with st.sidebar:
    st.header("System Status")
    st.success("✅ Engine Online")
    st.info("Analysis is 100% local.")
    if st.button("Reset Analysis"):
        st.rerun()
