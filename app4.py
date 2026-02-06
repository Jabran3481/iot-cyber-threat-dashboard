import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import time

#PAGE CONFIG
st.set_page_config(
    page_title="IoT Cyber Threat Intelligence Platform",
    layout="wide",
    page_icon="🛡️"
)

# DATA LOADING
@st.cache_data
def load_data():
    return pd.read_csv("RT_IOT2022.csv")

df_original = load_data()

# SIDEBAR
st.sidebar.title("⚙️ Control Panel")

refresh_rate = st.sidebar.slider("Refresh Interval (seconds)", 1, 10, 3)
live_samples = st.sidebar.slider("Live Traffic Volume", 100, 3000, 800)
attack_boost = st.sidebar.slider("Attack Intensity", 1, 10, 3)

# SEVERITY COLUMN (GLOBAL FIX)
severity_map = {
    "Normal": 1,
    "Probe": 2,
    "MQTT_Publish": 3,
    "DOS": 4,
    "DDoS": 5,
    "R2L": 5,
    "U2R": 5
}

df_original["severity"] = df_original["Attack_type"].map(severity_map).fillna(3)


page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Overview",
        "🎯 Theme & Objectives",
        "📊 EDA",
        "📡 Real-Time Traffic",
        "🚨 Threat & Severity",
        "🤖 AI Detection",
        "📈 Advanced Analytics",
        "📌 Insights",
        "📁 Reports"
    ]
)

# Simulated live data
df = df_original.sample(live_samples).copy()
df["fwd_pkts_tot"] *= attack_boost
df["bwd_pkts_tot"] *= attack_boost
df["flow_duration"] *= np.random.uniform(0.8, 1.2)

# OVERVIEW
if page == "🏠 Overview":
    st.title("🛡️ IoT Cyber Threat Intelligence Dashboard")

    st.markdown("""
    **Dataset Source:** UCI Machine Learning Repository  
    **Domain:** Cybersecurity / IoT Networks  
    **Purpose:** Monitor, analyze, and detect cyber threats in IoT traffic.
    """)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Live Connections", len(df))
    c2.metric("Attack Types", df["Attack_type"].nunique())
    c3.metric("Avg Flow Duration", f"{df['flow_duration'].mean():.2f}")
    c4.metric("Peak Forward Packets", int(df["fwd_pkts_tot"].max()))

    fig = px.pie(df, names="Attack_type", hole=0.4, template="plotly_dark")
    st.plotly_chart(fig, use_container_width=True)

    time.sleep(refresh_rate)
    st.rerun()

# THEME & OBJECTIVES
elif page == "🎯 Theme & Objectives":
    st.title("🎯 Project Theme & Objective Questions")

    st.subheader("📌 Theme")
    st.write("""
    **Real-Time IoT Cyber Threat Monitoring and Intelligence**
    """)

    st.subheader("❓ Objective Questions")
    st.markdown("""
    1. What types of cyber attacks are most frequent in IoT networks?  
    2. How do packet flow behaviors differ across attack types?  
    3. Which attacks pose the highest severity risk?  
    4. Can AI models detect anomalous network behavior?  
    5. What relationships exist among traffic features?
    """)

#  EDA
elif page == "📊 EDA":
    st.title("📊 Exploratory Data Analysis")

    st.subheader("🔍 Dataset Shape")
    st.write(df_original.shape)

    st.subheader("❗ Missing Values")
    st.write(df_original.isnull().sum())

    st.subheader("📊 Descriptive Statistics")
    st.dataframe(df_original.describe())

    st.subheader("📈 Univariate Analysis – Attack Distribution")
    fig = px.bar(df_original["Attack_type"].value_counts(),
                 template="plotly_dark")
    st.plotly_chart(fig, use_container_width=True)

# REAL-TIME TRAFFIC
elif page == "📡 Real-Time Traffic":
    st.title("📡 Live Network Traffic")

    fig = px.scatter(
        df, x="fwd_pkts_tot", y="bwd_pkts_tot",
        color="Attack_type", size="flow_duration",
        template="plotly_dark"
    )
    st.plotly_chart(fig, use_container_width=True)

# THREAT & SEVERITY
elif page == "🚨 Threat & Severity":
    st.title("🚨 Threat Severity Analysis")

    severity_map = {
        "Normal": 1, "Probe": 2, "MQTT_Publish": 3,
        "DOS": 4, "DDoS": 5, "R2L": 5, "U2R": 5
    }



    fig = px.line(df, x="severity", color="Attack_type",
                       template="plotly_dark")
    st.plotly_chart(fig, use_container_width=True)

    st.error(f"🚨 Critical Threats Detected: {len(df[df['severity']>=4])}")

# AI DETECTION
elif page == "🤖 AI Detection":
    st.title("🤖 AI-Based Anomaly Detection")

    features = df[["flow_duration", "fwd_pkts_tot", "bwd_pkts_tot"]]
    X = StandardScaler().fit_transform(features)

    model = IsolationForest(contamination=0.06)
    df["anomaly"] = model.fit_predict(X)
    df["anomaly"] = df["anomaly"].map({1: "Normal", -1: "Anomaly"})

    fig = px.scatter(df, x="fwd_pkts_tot", y="bwd_pkts_tot",
                     color="anomaly", template="plotly_dark")
    st.plotly_chart(fig, use_container_width=True)

# ADVANCED ANALYTICS
elif page == "📈 Advanced Analytics":
    st.title("📈 Correlation Analysis")

    corr = df[["flow_duration", "fwd_pkts_tot", "bwd_pkts_tot", "severity"]].corr()
    fig = px.imshow(corr, text_auto=True, template="plotly_dark")
    st.plotly_chart(fig, use_container_width=True)

# INSIGHTS
elif page == "📌 Insights":
    st.title("📌 Key Insights & Findings")

    st.markdown("""
    - DDoS and DOS attacks show extremely high packet rates.
    - Short-duration flows often indicate automated attacks.
    - AI-based anomaly detection successfully isolates abnormal traffic.
    - Strong correlation exists between packet count and severity.
    """)

# REPORTS
elif page == "📁 Reports":

    st.title("📁 SOC Threat Intelligence Report")

    report_df = (
        df.groupby("Attack_type")
        .agg(
            Total_Connections=("Attack_type", "count"),
            Avg_Flow_Duration=("flow_duration", "mean"),
            Avg_Forward_Packets=("fwd_pkts_tot", "mean"),
            Avg_Backward_Packets=("bwd_pkts_tot", "mean"),
            Max_Severity=("severity", "max")
        )
        .reset_index()
        .round(2)
    )

    st.dataframe(report_df, use_container_width=True)

    st.download_button(
        label="⬇ Download Threat Intelligence Report",
        data=report_df.to_csv(index=False),
        file_name="iot_threat_intelligence_report.csv",
        mime="text/csv"
    )
