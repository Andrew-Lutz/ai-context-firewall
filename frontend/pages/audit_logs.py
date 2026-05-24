"""
Audit Logs Page - AI Context Firewall
Searchable, filterable audit log table with export and compliance reporting.
"""

import streamlit as st
import json
import random
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Mock audit log generator
# ---------------------------------------------------------------------------

ACTIONS      = ["scan_prompt", "scan_file", "policy_evaluated", "entity_redacted", "injection_blocked", "gateway_request", "login", "policy_updated"]
OUTCOMES     = ["allowed", "blocked", "redacted", "alerted"]
USERS        = ["alice@corp.com", "bob@corp.com", "svc_llm_api", "analyst_07", "ext_vendor_3", "admin@corp.com"]
MODELS       = ["gpt-4o", "claude-3-opus", "claude-sonnet", "gemini-1.5-pro"]
POLICIES     = ["hipaa_v1", "gdpr_v1", "pci_dss_v1", "soc2_v1", None]
DEPARTMENTS  = ["Engineering", "Finance", "Legal", "HR", "Marketing", "Research"]
RISK_LEVELS  = ["critical", "high", "medium", "low", "none"]

SEV_COLORS = {
    "critical": "#FF4B4B",
    "high":     "#FF8C00",
    "medium":   "#FFD700",
    "low":      "#00B4D8",
    "none":     "#888888",
}

ACTION_COLORS = {
    "allowed":  "#00C853",
    "blocked":  "#FF4B4B",
    "redacted": "#FFD700",
    "alerted":  "#00B4D8",
}


def _gen_log_entry(idx: int) -> dict:
    ts = datetime.utcnow() - timedelta(minutes=random.randint(0, 10080))  # up to 1 week ago
    action   = random.choice(ACTIONS)
    outcome  = random.choice(OUTCOMES)
    risk     = random.choice(RISK_LEVELS)
    user     = random.choice(USERS)
    policy   = random.choice(POLICIES)
    dept     = random.choice(DEPARTMENTS)
    model    = random.choice(MODELS) if action in ["scan_prompt", "gateway_request"] else None
    entities = random.randint(0, 5) if outcome in ["redacted", "blocked"] else 0

    return {
        "log_id":     f"LOG-{100000 + idx}",
        "timestamp":  ts.strftime("%Y-%m-%d %H:%M:%S"),
        "ts_raw":     ts,
        "action":     action,
        "outcome":    outcome,
        "risk_level": risk,
        "user":       user,
        "department": dept,
        "model":      model,
        "policy_id":  policy,
        "entities_found": entities,
        "processing_ms":  random.randint(5, 450),
        "ip_hash":    f"sha256:{random.randint(10**15, 10**16-1):x}",
        "session_id": f"sess_{random.randint(1000, 9999)}",
        "tenant_id":  "tenant_acme_corp",
    }


def _seed_logs() -> list:
    if "audit_logs" not in st.session_state:
        st.session_state["audit_logs"] = sorted(
            [_gen_log_entry(i) for i in range(200)],
            key=lambda x: x["ts_raw"], reverse=True
        )
    return st.session_state["audit_logs"]


def _outcome_badge(outcome: str) -> str:
    col = ACTION_COLORS.get(outcome, "#888")
    return f'<span style="background:{col};color:#000;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700">{outcome.upper()}</span>'


def _risk_badge(risk: str) -> str:
    col = SEV_COLORS.get(risk, "#888")
    return f'<span style="background:{col}22;border:1px solid {col};color:{col};padding:2px 6px;border-radius:3px;font-size:10px;font-weight:700">{risk.upper()}</span>'


# ---------------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------------

def render():
    st.markdown("## 📋 Audit Logs")
    st.markdown("Immutable audit trail of all AI interactions, policy evaluations, and security events.")

    logs = _seed_logs()

    # ── Filters ────────────────────────────────────────────────────────────────
    with st.expander("🔍 Search & Filter", expanded=True):
        col1, col2, col3 = st.columns(3)

        with col1:
            search_text = st.text_input("Search (user, log ID, policy…)", key="audit_search")
            outcome_filter = st.multiselect("Outcome", OUTCOMES, default=OUTCOMES, key="audit_outcome")

        with col2:
            risk_filter = st.multiselect("Risk Level", RISK_LEVELS, default=RISK_LEVELS, key="audit_risk")
            action_filter = st.multiselect(
                "Action Type",
                ACTIONS,
                default=ACTIONS,
                key="audit_action",
            )

        with col3:
            dept_filter = st.multiselect("Department", DEPARTMENTS, default=DEPARTMENTS, key="audit_dept")
            date_range = st.selectbox(
                "Time Range",
                ["Last hour", "Last 24h", "Last 7 days", "All"],
                index=3,
                key="audit_daterange",
            )

    # Apply filters
    now = datetime.utcnow()
    range_map = {
        "Last hour":  timedelta(hours=1),
        "Last 24h":   timedelta(days=1),
        "Last 7 days": timedelta(days=7),
        "All":        None,
    }
    time_delta = range_map.get(date_range)

    filtered = logs
    if time_delta:
        cutoff   = now - time_delta
        filtered = [l for l in filtered if l["ts_raw"] >= cutoff]
    if outcome_filter:
        filtered = [l for l in filtered if l["outcome"] in outcome_filter]
    if risk_filter:
        filtered = [l for l in filtered if l["risk_level"] in risk_filter]
    if action_filter:
        filtered = [l for l in filtered if l["action"] in action_filter]
    if dept_filter:
        filtered = [l for l in filtered if l["department"] in dept_filter]
    if search_text:
        q = search_text.lower()
        filtered = [l for l in filtered if
                    q in l["log_id"].lower() or
                    q in l["user"].lower() or
                    q in (l["policy_id"] or "").lower() or
                    q in l["action"].lower()]

    # ── KPI row ────────────────────────────────────────────────────────────────
    st.markdown("---")
    total      = len(filtered)
    blocked    = sum(1 for l in filtered if l["outcome"] == "blocked")
    redacted   = sum(1 for l in filtered if l["outcome"] == "redacted")
    critical   = sum(1 for l in filtered if l["risk_level"] == "critical")
    avg_ms     = int(sum(l["processing_ms"] for l in filtered) / max(total, 1))

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Matching Events", total)
    m2.metric("🚫 Blocked",      blocked)
    m3.metric("🔒 Redacted",     redacted)
    m4.metric("🔴 Critical",     critical)
    m5.metric("⚡ Avg Latency",  f"{avg_ms}ms")

    # ── Compliance export buttons ──────────────────────────────────────────────
    st.markdown("---")
    col_e1, col_e2, col_e3, col_e4 = st.columns(4)

    export_rows = [
        {k: v for k, v in l.items() if k not in ("ts_raw",)}
        for l in filtered
    ]

    col_e1.download_button(
        "⬇️ Export JSON",
        data=json.dumps(export_rows, indent=2),
        file_name=f"audit_log_{now.strftime('%Y%m%d')}.json",
        mime="application/json",
        use_container_width=True,
    )

    # CSV export
    import csv, io
    csv_buf = io.StringIO()
    if export_rows:
        writer = csv.DictWriter(csv_buf, fieldnames=export_rows[0].keys())
        writer.writeheader()
        writer.writerows(export_rows)
    col_e2.download_button(
        "⬇️ Export CSV",
        data=csv_buf.getvalue(),
        file_name=f"audit_log_{now.strftime('%Y%m%d')}.csv",
        mime="text/csv",
        use_container_width=True,
    )

    # Compliance summary
    compliance_summary = {
        "report_generated": now.isoformat(),
        "time_range": date_range,
        "total_events": total,
        "blocked_events": blocked,
        "redacted_events": redacted,
        "critical_risk_events": critical,
        "compliance_frameworks": ["HIPAA", "GDPR", "PCI-DSS", "SOC2"],
        "audit_integrity": "SHA-256 hashed — tamper-evident",
    }
    col_e3.download_button(
        "⬇️ Compliance Report",
        data=json.dumps(compliance_summary, indent=2),
        file_name=f"compliance_report_{now.strftime('%Y%m%d')}.json",
        mime="application/json",
        use_container_width=True,
    )

    with col_e4:
        if st.button("🔄 Reset Filters", use_container_width=True):
            for key in ["audit_search", "audit_outcome", "audit_risk", "audit_action", "audit_dept"]:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()

    # ── Log table ──────────────────────────────────────────────────────────────
    st.markdown(f"### Events ({total:,} results)")

    if not filtered:
        st.info("No audit logs match your current filters.")
        return

    # Pagination
    PAGE_SIZE = 25
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)
    start = (page - 1) * PAGE_SIZE
    page_logs = filtered[start:start + PAGE_SIZE]

    st.markdown(f"<small style='color:#888'>Showing {start+1}–{min(start+PAGE_SIZE, total)} of {total}</small>", unsafe_allow_html=True)

    # Header
    st.markdown(
        """
        <div style="display:grid;grid-template-columns:120px 100px 160px 80px 80px 140px 80px 80px;
                    gap:4px;padding:6px 10px;background:#2d2d3e;border-radius:6px;
                    font-size:11px;font-weight:700;color:#888;margin-bottom:4px">
          <span>LOG ID</span><span>TIME</span><span>ACTION</span>
          <span>OUTCOME</span><span>RISK</span><span>USER</span>
          <span>ENTITIES</span><span>LATENCY</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    for log in page_logs:
        outcome_col = ACTION_COLORS.get(log["outcome"], "#888")
        risk_col    = SEV_COLORS.get(log["risk_level"], "#888")

        # Alternating row colors
        row_bg = "#12121f"

        with st.expander(
            f"{log['log_id']}  ·  {log['timestamp']}  ·  {log['action']}  ·  {log['outcome'].upper()}",
            expanded=False,
        ):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**Log ID:** `{log['log_id']}`")
                st.markdown(f"**Timestamp:** {log['timestamp']}")
                st.markdown(f"**Action:** `{log['action']}`")
                st.markdown(f"**Outcome:** {_outcome_badge(log['outcome'])}", unsafe_allow_html=True)
                st.markdown(f"**Risk Level:** {_risk_badge(log['risk_level'])}", unsafe_allow_html=True)
            with c2:
                st.markdown(f"**User:** `{log['user']}`")
                st.markdown(f"**Department:** {log['department']}")
                st.markdown(f"**Model:** {log.get('model') or '—'}")
                st.markdown(f"**Policy:** `{log.get('policy_id') or '—'}`")
                st.markdown(f"**Entities Found:** {log['entities_found']}")
                st.markdown(f"**Processing Time:** {log['processing_ms']}ms")
                st.markdown(f"**Session:** `{log['session_id']}`")
                st.markdown(f"**IP Hash:** `{log['ip_hash'][:24]}…`")

    # Page nav footer
    st.markdown(f"<div style='text-align:center;color:#666;font-size:12px;margin-top:12px'>Page {page} of {total_pages}</div>", unsafe_allow_html=True)
