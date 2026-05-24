"""
Dashboard Page — Main analytics overview for the AI Context Firewall.
Shows real-time metrics, threat trends, and system health.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from utils.theme import action_badge, risk_score_bar, severity_badge


def render_dashboard(api_client) -> None:
    """Render the main dashboard page."""

    # --- Page Header ---
    st.markdown("""
    <div class="page-title">
        <span style="font-size:1.5rem;">📊</span>
        <div>
            <h1>Security Dashboard</h1>
            <p style="margin:0; font-size:0.8rem; color:#666;">
                Real-time AI context firewall activity and threat intelligence
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # --- Time range selector ---
    col_time, col_refresh = st.columns([3, 1])
    with col_time:
        time_range = st.selectbox(
            "Time Range",
            ["Last 1 Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days"],
            index=1,
            label_visibility="collapsed",
        )
    with col_refresh:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()

    # --- Demo data generation ---
    metrics = _get_demo_metrics()
    events = _get_demo_events()
    trend_data = _get_demo_trend_data()

    # --- KPI Metrics Row ---
    st.markdown("#### Key Metrics")
    m1, m2, m3, m4, m5, m6 = st.columns(6)

    with m1:
        st.metric(
            "Total Scans",
            f"{metrics['total_scans']:,}",
            delta=f"+{metrics['scans_delta']:,} today",
        )
    with m2:
        st.metric(
            "Threats Blocked",
            f"{metrics['blocked']:,}",
            delta=f"+{metrics['blocked_delta']} today",
            delta_color="inverse",
        )
    with m3:
        st.metric(
            "Redactions Applied",
            f"{metrics['redacted']:,}",
            delta=f"+{metrics['redacted_delta']} today",
        )
    with m4:
        st.metric(
            "Policy Violations",
            f"{metrics['violations']:,}",
            delta=f"+{metrics['violations_delta']} today",
            delta_color="inverse",
        )
    with m5:
        st.metric(
            "Avg Risk Score",
            f"{metrics['avg_risk']:.1%}",
            delta=f"{metrics['risk_delta']:+.1%}",
        )
    with m6:
        st.metric(
            "Avg Latency",
            f"{metrics['avg_latency']}ms",
            delta=f"{metrics['latency_delta']:+d}ms",
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Charts Row ---
    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.markdown("#### Scan Activity — 24 Hours")
        fig_trend = _make_trend_chart(trend_data)
        st.plotly_chart(fig_trend, use_container_width=True, config={"displayModeBar": False})

    with col_right:
        st.markdown("#### Detection Breakdown")
        fig_pie = _make_detection_pie(metrics)
        st.plotly_chart(fig_pie, use_container_width=True, config={"displayModeBar": False})

    # --- Second Row ---
    col_left2, col_right2 = st.columns([1, 1])

    with col_left2:
        st.markdown("#### Threat Distribution by Type")
        fig_bar = _make_threat_bar(metrics)
        st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar": False})

    with col_right2:
        st.markdown("#### Compliance Framework Coverage")
        _render_compliance_matrix()

    # --- Recent Events Table ---
    st.markdown("#### Recent Security Events")
    _render_events_table(events)


# ---------------------------------------------------------------------------
# Chart Builders
# ---------------------------------------------------------------------------

def _make_trend_chart(df: pd.DataFrame) -> go.Figure:
    """Build stacked area chart of scan activity over time."""
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=df["time"], y=df["allowed"],
        fill="tozeroy", name="Allowed",
        line=dict(color="#2ED573", width=1.5),
        fillcolor="rgba(46,213,115,0.12)",
    ))
    fig.add_trace(go.Scatter(
        x=df["time"], y=df["redacted"],
        fill="tozeroy", name="Redacted",
        line=dict(color="#FFE66D", width=1.5),
        fillcolor="rgba(255,230,109,0.12)",
    ))
    fig.add_trace(go.Scatter(
        x=df["time"], y=df["blocked"],
        fill="tozeroy", name="Blocked",
        line=dict(color="#FF4757", width=1.5),
        fillcolor="rgba(255,71,87,0.12)",
    ))

    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9999b3", size=11),
        margin=dict(l=0, r=0, t=10, b=0),
        height=220,
        legend=dict(
            orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
            bgcolor="rgba(0,0,0,0)", font=dict(size=10),
        ),
        xaxis=dict(gridcolor="#2a2a3a", linecolor="#2a2a3a"),
        yaxis=dict(gridcolor="#2a2a3a", linecolor="#2a2a3a"),
        hovermode="x unified",
    )
    return fig


def _make_detection_pie(metrics: dict) -> go.Figure:
    """Donut chart of detection type breakdown."""
    labels = ["PII", "PHI", "PCI Data", "Secrets", "Injections", "Toxicity"]
    values = [
        metrics["pii"], metrics["phi"], metrics["pci"],
        metrics["secrets"], metrics["injections"], metrics["toxicity"],
    ]
    colors = ["#6C63FF", "#00D4AA", "#FF6B35", "#FF4757", "#FFE66D", "#888"]

    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        hole=0.6,
        marker=dict(colors=colors, line=dict(color="#0a0a0f", width=2)),
        textinfo="percent",
        textfont=dict(size=10, color="white"),
    ))
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9999b3", size=10),
        margin=dict(l=10, r=10, t=10, b=10),
        height=220,
        showlegend=True,
        legend=dict(
            bgcolor="rgba(0,0,0,0)", font=dict(size=9),
            orientation="v", x=1.0,
        ),
    )
    return fig


def _make_threat_bar(metrics: dict) -> go.Figure:
    """Horizontal bar chart of threats by type."""
    categories = ["Prompt Injection", "Jailbreak", "Data Exfiltration",
                  "Unicode Attack", "RAG Injection", "Role Confusion"]
    values = [random.randint(10, 200) for _ in categories]
    colors = ["#FF4757", "#FF6B35", "#FFE66D", "#6C63FF", "#00D4AA", "#FF6B35"]

    fig = go.Figure(go.Bar(
        x=values, y=categories,
        orientation="h",
        marker=dict(color=colors, opacity=0.8),
        text=values, textposition="outside", textfont=dict(color="#9999b3", size=10),
    ))
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9999b3", size=10),
        margin=dict(l=0, r=40, t=10, b=0),
        height=220,
        xaxis=dict(gridcolor="#2a2a3a", showticklabels=False),
        yaxis=dict(gridcolor="rgba(0,0,0,0)", tickfont=dict(size=10)),
        bargap=0.3,
    )
    return fig


def _render_compliance_matrix() -> None:
    """Render compliance framework coverage indicators."""
    frameworks = [
        ("HIPAA", True, 0.95, "#00D4AA"),
        ("GDPR", True, 0.90, "#00D4AA"),
        ("PCI-DSS", True, 0.98, "#00D4AA"),
        ("SOC2", True, 0.85, "#00D4AA"),
        ("FINRA", True, 0.80, "#00D4AA"),
        ("NIST 800-53", False, 0.60, "#FFE66D"),
    ]

    for name, active, coverage, color in frameworks:
        pct = int(coverage * 100)
        status_icon = "✓" if active else "⚠"
        status_color = color if active else "#FFE66D"

        st.markdown(f"""
        <div style="display:flex; align-items:center; margin:0.4rem 0; gap:8px;">
            <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem;
                         color:{status_color}; min-width:16px;">{status_icon}</span>
            <span style="font-size:0.8rem; color:#ccc; min-width:90px;">{name}</span>
            <div style="flex:1; height:6px; background:#2a2a3a; border-radius:3px;">
                <div style="width:{pct}%; height:100%; background:{color};
                            border-radius:3px; opacity:0.8;"></div>
            </div>
            <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem;
                         color:{color}; min-width:30px;">{pct}%</span>
        </div>
        """, unsafe_allow_html=True)


def _render_events_table(events: list) -> None:
    """Render recent security events as a styled table."""
    if not events:
        st.info("No recent events")
        return

    for event in events[:8]:
        action = event["action"]
        action_colors = {"block": "#FF4757", "redact": "#FFE66D", "allow": "#2ED573", "alert": "#FF6B35"}
        color = action_colors.get(action, "#888")

        st.markdown(f"""
        <div style="display:flex; align-items:center; padding:0.6rem 1rem;
                    background:#16161f; border:1px solid #2a2a3a; border-radius:6px;
                    margin-bottom:4px; gap:12px; border-left:3px solid {color};">
            <span style="font-family:'JetBrains Mono',monospace; font-size:0.65rem;
                         color:#555; min-width:55px;">{event['time']}</span>
            <span style="font-size:0.75rem; color:#ccc; flex:1;">{event['description']}</span>
            <span style="font-size:0.7rem; color:#666; min-width:60px;">{event['type']}</span>
            <span class="badge badge-{event['severity']}" style="min-width:55px; text-align:center;">
                {event['severity']}
            </span>
            <span style="font-family:'JetBrains Mono',monospace; font-size:0.75rem;
                         font-weight:700; color:{color}; min-width:50px; text-align:right;">
                {action.upper()}
            </span>
        </div>
        """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Demo Data Generators
# ---------------------------------------------------------------------------

def _get_demo_metrics() -> dict:
    random.seed(42)
    return {
        "total_scans": 142_847,
        "scans_delta": 2341,
        "blocked": 1_204,
        "blocked_delta": 23,
        "redacted": 18_493,
        "redacted_delta": 312,
        "violations": 89,
        "violations_delta": 4,
        "avg_risk": 0.12,
        "risk_delta": 0.02,
        "avg_latency": 47,
        "latency_delta": -3,
        "pii": 8420,
        "phi": 2341,
        "pci": 1203,
        "secrets": 456,
        "injections": 312,
        "toxicity": 89,
    }


def _get_demo_events() -> list:
    severities = ["critical", "high", "medium", "low"]
    types = ["input_scan", "output_scan", "file_scan", "policy_violation", "agent_action"]
    actions = ["block", "block", "redact", "redact", "redact", "allow"]
    descriptions = [
        "SSN detected in healthcare query — HIPAA violation",
        "Prompt injection attempt: DAN jailbreak pattern",
        "Credit card PAN detected in document upload",
        "API key exposed in developer prompt",
        "PHI in LLM output — blocked before delivery",
        "GDPR PII redacted: email + phone in contract",
        "Unicode zero-width attack in RAG document",
        "Jailbreak attempt via role confusion attack",
        "AWS credentials detected in source code upload",
        "Output hallucinated SSN — blocked by output firewall",
    ]
    events = []
    now = datetime.now()
    for i, desc in enumerate(descriptions):
        events.append({
            "time": (now - timedelta(minutes=i * 7)).strftime("%H:%M"),
            "description": desc,
            "type": random.choice(types),
            "severity": severities[i % len(severities)],
            "action": actions[i % len(actions)],
        })
    return events


def _get_demo_trend_data() -> pd.DataFrame:
    random.seed(99)
    hours = 24
    times = [datetime.now() - timedelta(hours=h) for h in range(hours, 0, -1)]
    return pd.DataFrame({
        "time": times,
        "allowed": [random.randint(500, 2000) for _ in range(hours)],
        "redacted": [random.randint(50, 400) for _ in range(hours)],
        "blocked": [random.randint(5, 80) for _ in range(hours)],
    })
