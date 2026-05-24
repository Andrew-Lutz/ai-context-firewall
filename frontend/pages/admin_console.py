"""
Admin Console Page - AI Context Firewall
Tenant management, user administration, system configuration, and health monitoring.
"""

import streamlit as st
import json
from datetime import datetime, timedelta
import random


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

MOCK_USERS = [
    {"id": "usr_001", "email": "alice@corp.com",    "role": "admin",              "dept": "Engineering",  "status": "active",   "last_login": "2026-05-22 09:14"},
    {"id": "usr_002", "email": "bob@corp.com",      "role": "analyst",            "dept": "Finance",      "status": "active",   "last_login": "2026-05-22 08:41"},
    {"id": "usr_003", "email": "carol@corp.com",    "role": "compliance_officer", "dept": "Legal",        "status": "active",   "last_login": "2026-05-21 17:03"},
    {"id": "usr_004", "email": "dave@corp.com",     "role": "employee",           "dept": "HR",           "status": "active",   "last_login": "2026-05-20 11:22"},
    {"id": "usr_005", "email": "svc_llm_api",       "role": "service_account",    "dept": "Platform",     "status": "active",   "last_login": "2026-05-22 09:45"},
    {"id": "usr_006", "email": "ext_vendor@acme.io","role": "employee",           "dept": "Vendor",       "status": "suspended","last_login": "2026-05-15 14:11"},
]

MOCK_TENANTS = [
    {"id": "tenant_acme_corp",   "name": "ACME Corporation",  "plan": "Enterprise", "users": 142,  "status": "active"},
    {"id": "tenant_healthco",    "name": "HealthCo Systems",  "plan": "Enterprise", "users": 89,   "status": "active"},
    {"id": "tenant_fingroup",    "name": "FinGroup Capital",  "plan": "Pro",        "users": 34,   "status": "active"},
    {"id": "tenant_retailcorp",  "name": "RetailCorp Inc.",   "plan": "Pro",        "users": 21,   "status": "trial"},
]

SYSTEM_HEALTH = {
    "API Gateway":        {"status": "healthy",  "latency": "12ms",  "uptime": "99.98%"},
    "Inspection Engine":  {"status": "healthy",  "latency": "8ms",   "uptime": "99.99%"},
    "Redaction Engine":   {"status": "healthy",  "latency": "5ms",   "uptime": "100%"},
    "Policy Engine":      {"status": "healthy",  "latency": "3ms",   "uptime": "100%"},
    "Token Vault (Redis)":{"status": "healthy",  "latency": "1ms",   "uptime": "99.97%"},
    "Database":           {"status": "healthy",  "latency": "4ms",   "uptime": "99.99%"},
    "Audit Logger":       {"status": "healthy",  "latency": "2ms",   "uptime": "100%"},
    "RAG Security":       {"status": "warning",  "latency": "45ms",  "uptime": "99.81%"},
}

ROLE_COLORS = {
    "admin":              "#FF4B4B",
    "compliance_officer": "#FFD700",
    "analyst":            "#00B4D8",
    "employee":           "#00C853",
    "service_account":    "#7B5EA7",
}

STATUS_COLORS = {
    "active":    "#00C853",
    "suspended": "#FF4B4B",
    "pending":   "#FFD700",
    "trial":     "#00B4D8",
}

HEALTH_COLORS = {
    "healthy": "#00C853",
    "warning": "#FFD700",
    "critical":"#FF4B4B",
}


def _role_badge(role: str) -> str:
    col = ROLE_COLORS.get(role, "#888")
    return f'<span style="background:{col}22;border:1px solid {col};color:{col};padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700">{role.replace("_"," ").upper()}</span>'


def _status_badge(status: str) -> str:
    col = STATUS_COLORS.get(status, "#888")
    return f'<span style="background:{col};color:#000;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700">{status.upper()}</span>'


def _health_dot(status: str) -> str:
    col = HEALTH_COLORS.get(status, "#888")
    return f'<span style="color:{col};font-weight:700">● {status.upper()}</span>'


# ---------------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------------

def render():
    # Access guard
    user_role = st.session_state.get("user_role", "employee")
    if user_role not in ["admin"]:
        st.warning("⛔ Admin Console requires admin privileges.")
        st.info("Current role: **" + user_role + "**. Contact your administrator for access.")
        return

    st.markdown("## ⚙️ Admin Console")
    st.markdown("System administration, user management, tenant configuration, and infrastructure monitoring.")

    tab_overview, tab_users, tab_tenants, tab_health, tab_config = st.tabs([
        "📊 Overview", "👥 Users", "🏢 Tenants", "💚 System Health", "⚙️ Configuration"
    ])

    with tab_overview:
        _render_overview()
    with tab_users:
        _render_users()
    with tab_tenants:
        _render_tenants()
    with tab_health:
        _render_health()
    with tab_config:
        _render_config()


def _render_overview():
    st.markdown("### Platform Overview")

    total_users   = sum(t["users"] for t in MOCK_TENANTS)
    active_tenants = sum(1 for t in MOCK_TENANTS if t["status"] == "active")
    warnings      = sum(1 for v in SYSTEM_HEALTH.values() if v["status"] == "warning")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Tenants",    len(MOCK_TENANTS))
    m2.metric("Active Tenants",   active_tenants)
    m3.metric("Total Users",      total_users)
    m4.metric("Active Users",     len([u for u in MOCK_USERS if u["status"] == "active"]))
    m5.metric("Health Warnings",  warnings, delta=f"+{warnings}" if warnings else None)

    # Recent activity
    st.markdown("---")
    st.markdown("### Recent Admin Activity")
    activity = [
        ("2026-05-22 09:41", "alice@corp.com",  "User suspended",       "ext_vendor@acme.io suspended for policy violation"),
        ("2026-05-22 08:15", "alice@corp.com",  "Policy updated",       "hipaa_v1 updated: added MRN redaction rule"),
        ("2026-05-21 17:30", "carol@corp.com",  "Compliance report",    "Generated HIPAA compliance report for May 2026"),
        ("2026-05-21 14:00", "alice@corp.com",  "Tenant onboarded",     "RetailCorp Inc. added on trial plan"),
        ("2026-05-20 11:00", "alice@corp.com",  "System config",        "Rate limit increased to 500 req/min for svc_llm_api"),
    ]
    for ts, actor, action, detail in activity:
        st.markdown(
            f'<div style="background:#1e1e2e;border-left:3px solid #7B5EA7;padding:8px 12px;margin:3px 0;border-radius:4px">'
            f'<span style="color:#888;font-size:11px">{ts}</span> &nbsp; '
            f'<b style="color:#e0e0e0">{action}</b> &nbsp; '
            f'<span style="color:#aaa;font-size:12px">by {actor}</span><br>'
            f'<span style="color:#777;font-size:12px">{detail}</span></div>',
            unsafe_allow_html=True,
        )


def _render_users():
    st.markdown("### User Management")

    col_search, col_role_filter = st.columns([2, 1])
    search   = col_search.text_input("Search users", placeholder="email, role, department…", key="admin_user_search")
    role_flt = col_role_filter.multiselect("Filter Role", list(ROLE_COLORS.keys()), default=list(ROLE_COLORS.keys()), key="admin_role_filter")

    filtered = MOCK_USERS
    if search:
        q = search.lower()
        filtered = [u for u in filtered if q in u["email"].lower() or q in u["role"].lower() or q in u["dept"].lower()]
    if role_flt:
        filtered = [u for u in filtered if u["role"] in role_flt]

    st.markdown(f"**{len(filtered)} users**")

    if st.button("➕ Invite User", key="admin_invite_user"):
        st.info("User invitation form would open here (requires backend connection).")

    st.markdown("---")

    for user in filtered:
        status_col = STATUS_COLORS.get(user["status"], "#888")

        with st.expander(f"{user['email']}  ·  {user['role'].replace('_',' ').title()}  ·  {user['status'].upper()}", expanded=False):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**User ID:** `{user['id']}`")
                st.markdown(f"**Email:** {user['email']}")
                st.markdown(f"**Role:** {_role_badge(user['role'])}", unsafe_allow_html=True)
                st.markdown(f"**Department:** {user['dept']}")
            with c2:
                st.markdown(f"**Status:** {_status_badge(user['status'])}", unsafe_allow_html=True)
                st.markdown(f"**Last Login:** {user['last_login']}")

            # Actions
            col_a, col_b, col_c = st.columns(3)
            if col_a.button("✏️ Edit Role", key=f"edit_{user['id']}"):
                st.info("Role editor would open here.")
            action = "Activate" if user["status"] == "suspended" else "Suspend"
            if col_b.button(f"{'✅' if action=='Activate' else '⛔'} {action}", key=f"sus_{user['id']}"):
                st.warning(f"{action} user '{user['email']}' — requires backend confirmation.")
            if col_c.button("🗑️ Delete", key=f"del_{user['id']}"):
                st.error("Delete user — requires confirmation dialog (backend required).")


def _render_tenants():
    st.markdown("### Tenant Management")

    plan_colors = {"Enterprise": "#FF4B4B", "Pro": "#FFD700", "Starter": "#00C853"}

    for tenant in MOCK_TENANTS:
        plan_col   = plan_colors.get(tenant["plan"], "#888")
        status_col = STATUS_COLORS.get(tenant["status"], "#888")

        with st.expander(f"🏢 {tenant['name']}  ·  {tenant['plan']}  ·  {tenant['users']} users", expanded=False):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**Tenant ID:** `{tenant['id']}`")
                st.markdown(f"**Name:** {tenant['name']}")
                st.markdown(
                    f"**Plan:** <span style='background:{plan_col};color:#000;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700'>{tenant['plan'].upper()}</span>",
                    unsafe_allow_html=True,
                )
            with c2:
                st.markdown(f"**Users:** {tenant['users']}")
                st.markdown(f"**Status:** {_status_badge(tenant['status'])}", unsafe_allow_html=True)

            col_a, col_b = st.columns(2)
            if col_a.button("⚙️ Configure", key=f"cfg_{tenant['id']}"):
                st.info("Tenant configuration panel (requires backend).")
            if col_b.button("📊 View Usage", key=f"use_{tenant['id']}"):
                st.info("Usage dashboard for this tenant (requires backend).")

    st.markdown("---")
    if st.button("➕ Create New Tenant", type="primary"):
        st.info("Tenant creation form (requires backend connection).")


def _render_health():
    st.markdown("### System Health")

    all_healthy = all(v["status"] == "healthy" for v in SYSTEM_HEALTH.values())
    if all_healthy:
        st.success("✅ All systems operational")
    else:
        warnings = [k for k, v in SYSTEM_HEALTH.items() if v["status"] != "healthy"]
        st.warning(f"⚠️ {len(warnings)} system(s) require attention: {', '.join(warnings)}")

    st.markdown("---")

    for service, info in SYSTEM_HEALTH.items():
        status = info["status"]
        col    = HEALTH_COLORS.get(status, "#888")

        st.markdown(
            f"""
            <div style="background:#1e1e2e;border-left:4px solid {col};border-radius:6px;
                        padding:10px 16px;margin:4px 0;display:flex;justify-content:space-between;align-items:center">
              <div>
                <b style="color:#e0e0e0">{service}</b>
                &nbsp; {_health_dot(status)}
              </div>
              <div style="color:#888;font-size:12px">
                Latency: <b style="color:#e0e0e0">{info['latency']}</b>
                &nbsp;|&nbsp; Uptime: <b style="color:{col}">{info['uptime']}</b>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown("### Resource Metrics")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("API Req/min",     "1,842",  delta="+12%")
    m2.metric("CPU Usage",       "23%")
    m3.metric("Memory",          "4.2 GB", delta="+0.3 GB")
    m4.metric("Redis Cache Hit", "94.7%",  delta="+1.2%")


def _render_config():
    st.markdown("### System Configuration")
    st.markdown("Core platform settings. Changes require admin confirmation and are audit-logged.")

    with st.expander("🔥 Firewall Defaults", expanded=True):
        c1, c2 = st.columns(2)
        with c1:
            st.selectbox("Default Redaction Mode", ["mask", "hash", "tokenize"], index=0, key="cfg_redact_mode")
            st.number_input("Risk Score Block Threshold", 0.0, 1.0, 0.75, 0.05, key="cfg_risk_threshold")
            st.checkbox("Enable Injection Blocking (Global)", value=True, key="cfg_inj_block")
        with c2:
            st.number_input("Token Vault TTL (hours)", 1, 720, 24, key="cfg_vault_ttl")
            st.number_input("Max File Size (MB)", 1, 500, 50, key="cfg_max_file")
            st.checkbox("Enable Output Inspection (Global)", value=True, key="cfg_out_inspect")

    with st.expander("⏱️ Rate Limiting"):
        c1, c2 = st.columns(2)
        with c1:
            st.number_input("Global Rate Limit (req/min)", 10, 10000, 500, key="cfg_rate_global")
            st.number_input("Per-User Rate Limit (req/min)", 1, 1000, 60, key="cfg_rate_user")
        with c2:
            st.number_input("Per-IP Rate Limit (req/min)", 1, 1000, 100, key="cfg_rate_ip")
            st.number_input("Burst Multiplier", 1.0, 5.0, 2.0, 0.5, key="cfg_burst")

    with st.expander("📧 Alerts & Notifications"):
        st.text_input("Alert Email", placeholder="security@your-org.com", key="cfg_alert_email")
        st.text_input("Slack Webhook URL", placeholder="https://hooks.slack.com/…", key="cfg_slack_url")
        st.multiselect(
            "Alert on Severity",
            ["critical", "high", "medium", "low"],
            default=["critical", "high"],
            key="cfg_alert_sev",
        )

    with st.expander("🔐 Authentication"):
        st.number_input("JWT Expiry (minutes)", 5, 1440, 60, key="cfg_jwt_expiry")
        st.number_input("Refresh Token Expiry (days)", 1, 90, 30, key="cfg_refresh_expiry")
        st.checkbox("Require MFA for Admin", value=True, key="cfg_mfa_admin")
        st.checkbox("Require MFA for All Users", value=False, key="cfg_mfa_all")

    st.markdown("---")
    col_save, col_reset = st.columns(2)
    if col_save.button("💾 Save Configuration", type="primary", use_container_width=True):
        st.success("✅ Configuration saved (demo mode — requires backend connection for persistence).")
    if col_reset.button("🔄 Reset to Defaults", use_container_width=True):
        st.info("Configuration reset to defaults.")
