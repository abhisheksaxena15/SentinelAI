"""
dashboard.py
------------
SentinelAI — Streamlit monitoring dashboard.
Run: streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite_utils
from datetime import datetime

st.set_page_config(
    page_title="SentinelAI",
    page_icon="🛡️",
    layout="wide",
)

DB_PATH = "sentinel.db"

SEVERITY_COLOR = {
    "CRITICAL": "#E24B4A",
    "HIGH":     "#EF9F27",
    "MEDIUM":   "#378ADD",
    "LOW":      "#1D9E75",
}

OWASP_LABELS = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Auth Failures",
    "A08": "Integrity Failures",
    "A09": "Logging Failures",
    "A10": "SSRF",
}

@st.cache_data(ttl=5)
def load_data():
    try:
        db = sqlite_utils.Database(DB_PATH)
        tables = db.table_names()
        reqs = pd.DataFrame(db["requests"].rows) if "requests" in tables else pd.DataFrame()
        threats = pd.DataFrame(db["threats"].rows) if "threats" in tables else pd.DataFrame()
        return reqs, threats
    except Exception:
        return pd.DataFrame(), pd.DataFrame()

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ SentinelAI — API Threat Monitor")
st.caption("Live OWASP Top 10 runtime analysis • Auto-refreshes every 5 seconds")
st.divider()

reqs, threats = load_data()

# ── KPI Row ────────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total requests",    len(reqs))
c2.metric("Threats detected",  len(threats))

critical = len(threats[threats.severity == "CRITICAL"]) if not threats.empty else 0
high     = len(threats[threats.severity == "HIGH"])     if not threats.empty else 0

c3.metric("Critical",  critical, delta=None)
c4.metric("High",      high,     delta=None)
c5.metric("Unique IPs",
    reqs["client_ip"].nunique() if not reqs.empty and "client_ip" in reqs.columns else 0)

st.divider()

# ── Charts row ─────────────────────────────────────────────────────────────────
col_a, col_b = st.columns(2)

with col_a:
    st.subheader("Threats by OWASP category")
    if not threats.empty and "owasp_id" in threats.columns:
        counts = threats["owasp_id"].value_counts().reset_index()
        counts.columns = ["owasp_id", "count"]
        counts["label"] = counts["owasp_id"].map(OWASP_LABELS).fillna(counts["owasp_id"])
        fig = px.bar(counts, x="count", y="label", orientation="h",
                     color="count", color_continuous_scale="Reds")
        fig.update_layout(
            showlegend=False, height=320,
            margin=dict(l=0, r=0, t=10, b=0),
            yaxis_title="", xaxis_title="Count",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No threats logged yet.")

with col_b:
    st.subheader("Severity distribution")
    if not threats.empty and "severity" in threats.columns:
        sev = threats["severity"].value_counts().reset_index()
        sev.columns = ["severity", "count"]
        colors = [SEVERITY_COLOR.get(s, "#888") for s in sev["severity"]]
        fig = go.Figure(go.Pie(
            labels=sev["severity"], values=sev["count"],
            marker_colors=colors, hole=0.45,
            textinfo="label+percent",
        ))
        fig.update_layout(
            height=320, margin=dict(l=0, r=0, t=10, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No threats logged yet.")

st.divider()

# ── Request timeline ───────────────────────────────────────────────────────────
st.subheader("Request volume over time")
if not reqs.empty and "timestamp" in reqs.columns:
    reqs["ts"] = pd.to_datetime(reqs["timestamp"], errors="coerce")
    timeline = reqs.set_index("ts").resample("1min").size().reset_index()
    timeline.columns = ["time", "count"]
    fig = px.area(timeline, x="time", y="count", line_shape="spline")
    fig.update_layout(
        height=200, margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis_title="", yaxis_title="req/min",
    )
    st.plotly_chart(fig, use_container_width=True)

st.divider()

# ── Live threat log ────────────────────────────────────────────────────────────
st.subheader("🚨 Threat log (latest 100)")
if not threats.empty:
    display_cols = [c for c in
        ["timestamp", "severity", "owasp_id", "threat_type", "detail", "path", "payload", "request_id"]
        if c in threats.columns]
    df_show = threats[display_cols].sort_values("timestamp", ascending=False).head(1000)
    df_show.rename(columns={
        "path": "endpoint"
    }, inplace=True)

    def color_severity(val):
        return f"color: {SEVERITY_COLOR.get(val, '#888')}"

    styled = df_show.style.map(color_severity, subset=["severity"])
    st.dataframe(styled, use_container_width=True, height=350)
else:
    st.info("No threats recorded yet. Send some requests through the proxy.")

st.divider()

# ── Raw request log ────────────────────────────────────────────────────────────
with st.expander("📋 Raw request log (latest 50)"):
    if not reqs.empty:
        show_cols = [c for c in
            ["timestamp", "method", "path", "status_code", "client_ip", "id"]
            if c in reqs.columns]
        st.dataframe(
            reqs[show_cols].sort_values("timestamp", ascending=False).head(500),
            use_container_width=True,
        )
    else:
        st.info("No requests logged yet.")

# ── Auto-refresh ──────────────────────────────────────────────────────────────
st.markdown(
    """<meta http-equiv="refresh" content="20">""",
    unsafe_allow_html=True,
)

