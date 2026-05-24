"""
Threat Monitor Page - AI Context Firewall
Real-time threat feed with live updates, severity filtering, and geo visualization.
"""

import streamlit as st
import time
import random
import json
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Mock threat generator (used when backend unavailable)
# ---------------------------------------------------------------------------

THREAT_TYPES = [
    ("Prompt Injection",       "critical", "💉"),
    ("SSN Detected",           "critical", "🔴"),
    ("Credit Card Exposed",    "critical", "💳"),
    ("API Key Leaked",         "critical", "🔑"),
    ("PHI Transmission",       "high",     "🏥"),
    ("GDPR Violation",         "high",     "🇪🇺"),
    ("Role Confusion Attack",  "high",     "🎭"),
    ("Email Address Exposed",  "medium",   "📧"),
    ("IP Address Logged",      "low",      "🌐"),
    ("Benign Query",           "info",     "✅"),
]

FAKE_USERS  = ["user_4421", "svc_llm_proxy", "analyst_07", "api_client_9", "agent_orchestrator", "ext_vendor_3"]
FAKE_MODELS = ["gpt-4o", "claude-3-opus", "gemini-1.5-pro", "claude-sonnet", "gpt-3.5-turbo"]
FAKE_DEPTS  = ["Engineering", "Finance", "Legal", "HR", "Marketing", "Research"]

SEV_COLORS = {
    "critical": "#FF4B4B",
    "high":     "#FF8C00",
    "medium":   "#FFD700",
    "low":      "#00B4D8",
    "info":     "#00C853",
}


def _gen_threat(idx: int) -> dict:
    ttype, sev, icon = random.choice(THREAT_TYPES)
    ts = datetime.utcnow() - timedelta(seconds=random.randint(0, 300))
    return {
        "id":         f"EVT-{10000 + idx}",
        "timestamp":  ts.strftime("%H:%M:%S"),
        "type":       ttype,
        "severity":   sev,
        "icon":       icon,
        "user":       random.choice(FAKE_USERS),
        "model":      random.choice(FAKE_MODELS),
        "department": random.choice(FAKE_DEPTS),
        "risk_score": round(random.uniform(0.05, 0.99), 2),
        "action":     random.choice(["blocked", "redacted", "alerted", "allowed"]),
        "policy_id":  random.choice(["hipaa_v1", "gdpr_v1", "pci_dss_v1", "soc2_v1", None]),
    }


def _seed_events() -> list:
    if "threat_events" not in st.session_state:
        st.session_state["threat_events"]   = [_gen_threat(i) for i in range(30)]
        st.session_state["threat_event_idx"] = 30
    return st.session_state["threat_events"]


def _add_new_events(n: int = 2):
    idx = st.session_state.get("threat_event_idx", 30)
    new = [_gen_threat(idx + i) for i in range(n)]
    st.session_state["threat_events"] = new + st.session_state.get("threat_events", [])
    st.session_state["threat_event_idx"] = idx + n


def _sev_badge(sev: str) -> str:
    col = SEV_COLORS.get(sev, "#888")
    return f'<span style="background:{col};color:#000;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700">{sev.upper()}</span>'


def _action_badge(action: str) -> str:
    col = {"blocked": "#FF4B4B", "redacted": "#FFD700", "alerted": "#00B4D8", "allowed": "#00C853"}.get(action, "#888")
    return f'<span style="background:{col}22;border:1px solid {col};color:{col};padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700">{action.upper()}</span>'


# ---------------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------------

def render():
    st.markdown("## 🔴 Threat Monitor")
    st.markdown("Live feed of security events, policy violations, and threat patterns across all AI interactions.")

    # ── Controls bar ──────────────────────────────────────────────────────────
    col_live, col_filter, col_refresh = st.columns([1, 2, 1])

    with col_live:
        live_mode = st.toggle("🔴 Live Feed", value=st.session_state.get("threat_live", False), key="threat_live")

    with col_filter:
        sev_filter = st.multiselect(
            "Filter by severity",
            ["critical", "high", "medium", "low", "info"],
            default=["critical", "high", "medium"],
            key="threat_sev_filter",
        )

    with col_refresh:
        if st.button("🔄 Refresh", use_container_width=True):
            _add_new_events(random.randint(1, 4))
            st.rerun()

    # Live mode auto-refresh
    if live_mode:
        _add_new_events(random.randint(0, 2))
        time.sleep(0.1)

    # ── Seed events ───────────────────────────────────────────────────────────
    events = _seed_events()

    # ── KPI Row ───────────────────────────────────────────────────────────────
    st.markdown("---")
    recent = events[:50]
    critical_count = sum(1 for e in recent if e["severity"] == "critical")
    blocked_count  = sum(1 for e in recent if e["action"] == "blocked")
    high_risk      = sum(1 for e in recent if e["risk_score"] > 0.7)
    unique_users   = len(set(e["user"] for e in recent))

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Events (last 50)", len(recent))
    m2.metric("🔴 Critical",      critical_count,  delta=f"+{critical_count}")
    m3.metric("🚫 Blocked",       blocked_count)
    m4.metric("⚠️ High Risk",     high_risk)
    m5.metric("👤 Active Users",  unique_users)

    # ── Severity distribution ─────────────────────────────────────────────────
    st.markdown("---")
    col_chart, col_trend = st.columns([1, 2])

    with col_chart:
        st.markdown("**Severity Distribution**")
        sev_counts = {s: sum(1 for e in recent if e["severity"] == s) for s in ["critical", "high", "medium", "low", "info"]}
        total = max(sum(sev_counts.values()), 1)
        for sev, count in sev_counts.items():
            pct = count / total * 100
            col = SEV_COLORS.get(sev, "#888")
            st.markdown(
                f"""
                <div style="display:flex;align-items:center;gap:8px;margin:4px 0">
                  <span style="width:60px;color:{col};font-size:12px;font-weight:700">{sev.upper()}</span>
                  <div style="flex:1;background:#1e1e2e;border-radius:4px;height:16px">
                    <div style="background:{col};border-radius:4px;height:16px;width:{pct:.1f}%"></div>
                  </div>
                  <span style="width:30px;text-align:right;font-size:12px;color:#aaa">{count}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with col_trend:
        st.markdown("**Threat Types (Top 5)**")
        type_counts: dict = {}
        for e in recent:
            type_counts[e["type"]] = type_counts.get(e["type"], 0) + 1
        top5 = sorted(type_counts.items(), key=lambda x: -x[1])[:5]
        max_count = max(c for _, c in top5) if top5 else 1
        for tname, count in top5:
            pct = count / max_count * 100
            st.markdown(
                f"""
                <div style="display:flex;align-items:center;gap:8px;margin:5px 0">
                  <span style="width:180px;color:#e0e0e0;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{tname}</span>
                  <div style="flex:1;background:#1e1e2e;border-radius:4px;height:14px">
                    <div style="background:#7B5EA7;border-radius:4px;height:14px;width:{pct:.0f}%"></div>
                  </div>
                  <span style="width:25px;text-align:right;font-size:12px;color:#aaa">{count}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ── Live Event Feed ───────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📡 Event Feed")

    # Filter
    filtered = [e for e in events if e["severity"] in sev_filter]

    if not filtered:
        st.info("No events match the selected severity filters.")
        return

    # Render event rows
    for ev in filtered[:100]:
        sev = ev["severity"]
        col = SEV_COLORS.get(sev, "#888")

        with st.container():
            st.markdown(
                f"""
                <div style="background:#12121f;border-left:4px solid {col};border-radius:6px;
                            padding:10px 14px;margin:3px 0;font-family:monospace">
                  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:4px">
                    <span>
                      {ev["icon"]} &nbsp;
                      <b style="color:#e0e0e0">{ev["id"]}</b> &nbsp;
                      <span style="color:#888">{ev["timestamp"]}</span> &nbsp;
                      {_sev_badge(sev)}
                    </span>
                    <span>
                      {_action_badge(ev["action"])}
                      <span style="color:#888;font-size:11px;margin-left:8px">
                        {ev["user"]} · {ev["model"]} · {ev["department"]}
                      </span>
                    </span>
                  </div>
                  <div style="margin-top:4px;color:#ccc;font-size:13px">
                    {ev["type"]}
                    <span style="color:#666;font-size:11px">
                      &nbsp;|&nbsp; risk: <b style="color:{col}">{ev['risk_score']:.0%}</b>
                      {f"&nbsp;|&nbsp; policy: <code style='font-size:10px'>{ev['policy_id']}</code>" if ev.get('policy_id') else ""}
                    </span>
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ── Export ────────────────────────────────────────────────────────────────
    st.markdown("---")
    export = [{k: v for k, v in e.items() if k != "icon"} for e in filtered[:100]]
    st.download_button(
        "⬇️ Export Events (JSON)",
        data=json.dumps(export, indent=2),
        file_name=f"threat_events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
    )

    if live_mode:
        time.sleep(3)
        st.rerun()
