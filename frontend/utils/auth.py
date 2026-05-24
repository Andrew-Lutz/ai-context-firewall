"""
Authentication utilities for Streamlit frontend.
Handles login flow and session state management.
"""
import streamlit as st
from utils.api_client import FirewallAPIClient, APIError


def login_page() -> None:
    """Render the login page."""
    st.markdown("""
    <div style="display:flex; flex-direction:column; align-items:center; justify-content:center;
                min-height:60vh; text-align:center; padding:2rem;">
        <div style="font-size:4rem; margin-bottom:0.5rem;">🔥</div>
        <h1 style="font-family:'Courier New',monospace; color:#FF6B35; font-size:1.8rem;
                   letter-spacing:0.1em; margin:0;">AI CONTEXT FIREWALL</h1>
        <p style="color:#666; font-size:0.85rem; letter-spacing:0.15em; margin:0.3rem 0 2rem 0;">
            ENTERPRISE AI SECURITY PLATFORM
        </p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        st.markdown("""
        <div style="background:#16161f; border:1px solid #2a2a3a; border-radius:12px;
                    padding:2rem; border-top:3px solid #FF6B35;">
        """, unsafe_allow_html=True)

        st.markdown("### Sign In")

        email = st.text_input(
            "Email",
            placeholder="admin@firewall.local",
            key="login_email",
        )
        password = st.text_input(
            "Password",
            type="password",
            placeholder="••••••••••••",
            key="login_password",
        )

        api_url = st.text_input(
            "API URL",
            value="http://localhost:8000",
            key="login_api_url",
        )

        if st.button("Sign In", type="primary", use_container_width=True):
            if not email or not password:
                st.error("Please enter email and password")
                return

            # Demo credentials check
            DEMO_USERS = {
                "admin@demo.com": "admin123",
                "admin@firewall.local": "ChangeMe123!",
                "analyst@demo.com": "analyst123",
                "user@demo.com": "user123",
            }
            if email in DEMO_USERS and DEMO_USERS[email] == password:
                _enter_demo_mode(email)
                st.rerun()
            else:
                st.error("Invalid credentials. Try admin@demo.com / admin123")

        st.markdown("""
        <div style="text-align:center; margin-top:1rem; font-size:0.75rem; color:#555;">
            Demo: admin@firewall.local / ChangeMe123!
        </div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)


def _enter_demo_mode(email: str) -> None:
    """Enter demo mode with mock user data."""
    st.session_state.authenticated = True
    st.session_state.access_token = "demo_token"
    st.session_state.user = {
        "id": "demo-user-001",
        "email": email,
        "full_name": "Demo Administrator",
        "role": "super_admin",
        "tenant_id": "default",
        "department": "Security",
    }
    st.session_state.tenant_id = "default"
    st.session_state.demo_mode = True
    st.rerun()


def check_auth() -> bool:
    """Return True if user is authenticated."""
    return st.session_state.get("authenticated", False)


def require_role(allowed_roles: list) -> bool:
    """Return True if current user has an allowed role. Show error otherwise."""
    user = st.session_state.get("user", {})
    role = user.get("role", "read_only")
    if role not in allowed_roles:
        st.error(f"Access denied. Required role: {', '.join(allowed_roles)}")
        return False
    return True
