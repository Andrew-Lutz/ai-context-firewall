"""
AI Context Firewall — Streamlit Frontend
Main entry point with navigation and global state management.
"""
import os
import sys
from pathlib import Path

import streamlit as st

# Add frontend dir to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.api_client import FirewallAPIClient
from utils.auth import check_auth, login_page
from utils.theme import inject_custom_css

# ---------------------------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="AI Context Firewall",
    page_icon="🔥",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://github.com/your-org/ai-context-firewall",
        "Report a bug": "https://github.com/your-org/ai-context-firewall/issues",
        "About": "AI Context Firewall v1.0.0 — Enterprise AI Security Platform",
    },
)

# ---------------------------------------------------------------------------
# Global CSS & Theme
# ---------------------------------------------------------------------------

inject_custom_css()

# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user" not in st.session_state:
    st.session_state.user = None
if "access_token" not in st.session_state:
    st.session_state.access_token = None
if "tenant_id" not in st.session_state:
    st.session_state.tenant_id = "default"
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "current_page" not in st.session_state:
    st.session_state.current_page = "Dashboard"

# ---------------------------------------------------------------------------
# Auth Check
# ---------------------------------------------------------------------------

if not st.session_state.authenticated:
    login_page()
    st.stop()

# ---------------------------------------------------------------------------
# Sidebar Navigation
# ---------------------------------------------------------------------------

api_client = FirewallAPIClient(
    base_url=os.getenv("API_BASE_URL", "http://localhost:8000"),
    token=st.session_state.access_token,
)

with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 1rem 0 0.5rem 0;">
        <span style="font-size: 2.2rem;">🔥</span>
        <h2 style="margin:0; font-family:'Courier New',monospace; color:#FF6B35; font-size:1.1rem; letter-spacing:0.1em;">
            AI CONTEXT<br>FIREWALL
        </h2>
        <p style="font-size:0.65rem; color:#888; margin:0.2rem 0 0 0; letter-spacing:0.15em;">
            ENTERPRISE SECURITY PLATFORM
        </p>
    </div>
    <hr style="border-color:#333; margin:0.75rem 0;">
    """, unsafe_allow_html=True)

    # User info
    user = st.session_state.user or {}
    role_colors = {
        "super_admin": "#FF6B35",
        "security_analyst": "#00D4AA",
        "tenant_admin": "#6C63FF",
        "developer": "#4ECDC4",
        "auditor": "#FFE66D",
        "read_only": "#888",
    }
    role = user.get("role", "developer")
    role_color = role_colors.get(role, "#888")

    st.markdown(f"""
    <div style="padding:0.5rem 0.75rem; background:#1a1a2e; border-radius:6px; margin-bottom:0.75rem; border-left:3px solid {role_color};">
        <div style="font-size:0.8rem; color:#ccc; font-weight:600;">{user.get('full_name', user.get('email', 'User'))}</div>
        <div style="font-size:0.7rem; color:{role_color}; text-transform:uppercase; letter-spacing:0.08em;">{role.replace('_',' ')}</div>
        <div style="font-size:0.65rem; color:#666;">{user.get('tenant_id', 'default')}</div>
    </div>
    """, unsafe_allow_html=True)

    # Navigation
    pages = {
        "📊 Dashboard": "Dashboard",
        "🔍 Prompt Scanner": "Prompt Scanner",
        "📁 File Scanner": "File Scanner",
        "📋 Policy Manager": "Policy Manager",
        "⚡ Threat Monitor": "Threat Monitor",
        "📜 Audit Logs": "Audit Logs",
        "🤖 Model Gateway": "Model Gateway",
        "🗄️ RAG Security": "RAG Security",
        "⚙️ Admin Console": "Admin Console",
    }

    for label, page_name in pages.items():
        is_active = st.session_state.current_page == page_name
        if st.button(
            label,
            key=f"nav_{page_name}",
            use_container_width=True,
            type="primary" if is_active else "secondary",
        ):
            st.session_state.current_page = page_name
            st.rerun()

    st.markdown("<hr style='border-color:#333; margin:0.75rem 0;'>", unsafe_allow_html=True)

    # Status indicators
    st.markdown("**System Status**")
    status_items = [
        ("Inspection Engine", "🟢"),
        ("Policy Engine", "🟢"),
        ("Redaction Engine", "🟢"),
        ("Audit Logger", "🟢"),
    ]
    for name, indicator in status_items:
        st.markdown(
            f"<div style='font-size:0.75rem; color:#aaa; margin:2px 0;'>{indicator} {name}</div>",
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🚪 Logout", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

# ---------------------------------------------------------------------------
# Page Router
# ---------------------------------------------------------------------------

page = st.session_state.current_page

# Inject api_client into session state so pages can access it
st.session_state["api_client"] = api_client

if page == "Dashboard":
    try:
        from pages.dashboard import render_dashboard
        render_dashboard(api_client)
    except TypeError:
        from pages.dashboard import render
        render()

elif page == "Prompt Scanner":
    try:
        from pages.prompt_scanner import render_prompt_scanner
        render_prompt_scanner(api_client)
    except TypeError:
        from pages.prompt_scanner import render
        render()

elif page == "File Scanner":
    from pages.file_scanner import render
    render()

elif page == "Policy Manager":
    from pages.policy_manager import render
    render()

elif page == "Threat Monitor":
    from pages.threat_monitor import render
    render()

elif page == "Audit Logs":
    from pages.audit_logs import render
    render()

elif page == "Model Gateway":
    from pages.model_gateway import render
    render()

elif page == "RAG Security":
    from pages.rag_security import render
    render()

elif page == "Admin Console":
    from pages.admin_console import render
    render()
