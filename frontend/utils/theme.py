"""
Custom CSS theme injection for the AI Context Firewall Streamlit app.
Enterprise dark theme with security-focused visual language.
"""
import streamlit as st


def inject_custom_css() -> None:
    """Inject enterprise dark theme CSS into Streamlit app."""
    st.markdown("""
    <style>
    /* ============================================================
       AI CONTEXT FIREWALL — ENTERPRISE DARK THEME
       Inspired by security operations centers (SOC dashboards)
    ============================================================ */

    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600;700&display=swap');

    /* Root variables */
    :root {
        --bg-primary: #0a0a0f;
        --bg-secondary: #111118;
        --bg-card: #16161f;
        --bg-elevated: #1c1c28;
        --border-color: #2a2a3a;
        --border-accent: #FF6B35;

        --text-primary: #e8e8f0;
        --text-secondary: #9999b3;
        --text-muted: #555570;

        --accent-orange: #FF6B35;
        --accent-teal: #00D4AA;
        --accent-purple: #6C63FF;
        --accent-yellow: #FFE66D;
        --accent-red: #FF4757;
        --accent-green: #2ED573;
        --accent-blue: #1E90FF;

        --severity-critical: #FF4757;
        --severity-high: #FF6B35;
        --severity-medium: #FFE66D;
        --severity-low: #00D4AA;
        --severity-info: #888;

        --font-mono: 'JetBrains Mono', 'Courier New', monospace;
        --font-sans: 'Inter', system-ui, sans-serif;
    }

    /* Global background */
    .stApp {
        background: var(--bg-primary) !important;
        font-family: var(--font-sans);
        color: var(--text-primary);
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: var(--bg-secondary) !important;
        border-right: 1px solid var(--border-color) !important;
    }
    [data-testid="stSidebar"] > div {
        background: transparent !important;
    }

    /* Headers */
    h1, h2, h3 {
        font-family: var(--font-sans) !important;
        color: var(--text-primary) !important;
        font-weight: 600;
    }
    h1 { font-size: 1.6rem !important; letter-spacing: -0.02em; }
    h2 { font-size: 1.2rem !important; }
    h3 { font-size: 1rem !important; color: var(--text-secondary) !important; }

    /* Metric cards */
    [data-testid="stMetric"] {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        padding: 1rem 1.2rem !important;
    }
    [data-testid="stMetricValue"] {
        font-family: var(--font-mono) !important;
        color: var(--accent-teal) !important;
        font-size: 1.8rem !important;
        font-weight: 700 !important;
    }
    [data-testid="stMetricLabel"] {
        color: var(--text-secondary) !important;
        font-size: 0.75rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.08em !important;
    }

    /* Buttons */
    [data-testid="stButton"] button {
        border-radius: 6px !important;
        font-family: var(--font-sans) !important;
        font-weight: 500 !important;
        transition: all 0.15s !important;
    }
    [data-testid="stButton"] button[kind="primary"] {
        background: var(--accent-orange) !important;
        border: none !important;
        color: white !important;
    }
    [data-testid="stButton"] button[kind="secondary"] {
        background: transparent !important;
        border: 1px solid var(--border-color) !important;
        color: var(--text-secondary) !important;
    }
    [data-testid="stButton"] button[kind="secondary"]:hover {
        border-color: var(--accent-orange) !important;
        color: var(--accent-orange) !important;
    }

    /* Text inputs */
    [data-testid="stTextInput"] input,
    [data-testid="stTextArea"] textarea,
    [data-testid="stSelectbox"] select {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 6px !important;
        color: var(--text-primary) !important;
        font-family: var(--font-sans) !important;
    }
    [data-testid="stTextInput"] input:focus,
    [data-testid="stTextArea"] textarea:focus {
        border-color: var(--accent-orange) !important;
        box-shadow: 0 0 0 2px rgba(255, 107, 53, 0.15) !important;
    }

    /* Code blocks */
    code, pre {
        font-family: var(--font-mono) !important;
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 4px !important;
        color: var(--accent-teal) !important;
    }

    /* DataFrames / Tables */
    [data-testid="stDataFrame"] {
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        overflow: hidden;
    }

    /* Expanders */
    [data-testid="stExpander"] {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
    }

    /* Tabs */
    [data-testid="stTabs"] [data-testid="stTabPanel"] {
        border: 1px solid var(--border-color);
        border-top: none;
        border-radius: 0 0 8px 8px;
        padding: 1rem;
    }

    /* Alerts */
    [data-testid="stAlert"] {
        border-radius: 8px !important;
        border: none !important;
    }

    /* File uploader */
    [data-testid="stFileUploader"] {
        background: var(--bg-card) !important;
        border: 2px dashed var(--border-color) !important;
        border-radius: 8px !important;
        transition: border-color 0.2s !important;
    }
    [data-testid="stFileUploader"]:hover {
        border-color: var(--accent-orange) !important;
    }

    /* Progress bars */
    [data-testid="stProgress"] > div > div {
        background: var(--accent-orange) !important;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-secondary); }
    ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--accent-orange); }

    /* Custom card component */
    .fw-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 0.75rem;
    }
    .fw-card-accent {
        border-left: 3px solid var(--accent-orange);
    }

    /* Severity badges */
    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-family: var(--font-mono);
    }
    .badge-critical { background: rgba(255,71,87,0.15); color: var(--severity-critical); border: 1px solid var(--severity-critical); }
    .badge-high     { background: rgba(255,107,53,0.15); color: var(--severity-high); border: 1px solid var(--severity-high); }
    .badge-medium   { background: rgba(255,230,109,0.15); color: var(--severity-medium); border: 1px solid var(--severity-medium); }
    .badge-low      { background: rgba(0,212,170,0.15); color: var(--severity-low); border: 1px solid var(--severity-low); }
    .badge-clean    { background: rgba(46,213,115,0.15); color: var(--accent-green); border: 1px solid var(--accent-green); }

    /* Risk score bar */
    .risk-bar {
        height: 8px;
        background: var(--border-color);
        border-radius: 4px;
        overflow: hidden;
        margin: 4px 0;
    }
    .risk-bar-fill {
        height: 100%;
        border-radius: 4px;
        transition: width 0.4s ease;
    }

    /* Page title */
    .page-title {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 1.5rem;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid var(--border-color);
    }
    .page-title h1 {
        margin: 0 !important;
        font-family: var(--font-sans) !important;
        font-size: 1.4rem !important;
        font-weight: 700 !important;
        color: var(--text-primary) !important;
    }

    /* Monospace text */
    .mono { font-family: var(--font-mono) !important; }

    /* Highlight redacted text */
    .redacted-token {
        background: rgba(255,107,53,0.2);
        border: 1px solid rgba(255,107,53,0.4);
        border-radius: 3px;
        padding: 1px 4px;
        font-family: var(--font-mono);
        font-size: 0.85em;
        color: var(--accent-orange);
    }

    /* Compliance badge */
    .compliance-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin: 2px;
    }
    .compliance-active {
        background: rgba(0,212,170,0.15);
        border: 1px solid var(--accent-teal);
        color: var(--accent-teal);
    }
    .compliance-violation {
        background: rgba(255,71,87,0.15);
        border: 1px solid var(--severity-critical);
        color: var(--severity-critical);
    }

    /* Hide Streamlit branding */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { visibility: hidden; }

    </style>
    """, unsafe_allow_html=True)


def severity_badge(severity: str) -> str:
    """Return HTML badge for a severity level."""
    return f'<span class="badge badge-{severity.lower()}">{severity}</span>'


def risk_score_bar(score: float) -> str:
    """Return HTML risk score progress bar."""
    pct = int(score * 100)
    if pct >= 80:
        color = "var(--severity-critical)"
    elif pct >= 60:
        color = "var(--severity-high)"
    elif pct >= 40:
        color = "var(--severity-medium)"
    else:
        color = "var(--accent-green)"

    return f"""
    <div style="display:flex; align-items:center; gap:8px;">
        <div class="risk-bar" style="flex:1;">
            <div class="risk-bar-fill" style="width:{pct}%; background:{color};"></div>
        </div>
        <span style="font-family:var(--font-mono); font-size:0.8rem; color:{color}; min-width:36px; text-align:right;">
            {pct}%
        </span>
    </div>
    """


def action_badge(action: str) -> str:
    """Return colored action indicator."""
    colors = {
        "allow": ("var(--accent-green)", "✓ ALLOW"),
        "redact": ("var(--accent-yellow)", "⚠ REDACT"),
        "block": ("var(--severity-critical)", "✗ BLOCK"),
        "alert": ("var(--severity-high)", "⚡ ALERT"),
    }
    color, label = colors.get(action.lower(), ("#888", action.upper()))
    return f'<span style="font-family:var(--font-mono); font-size:0.85rem; font-weight:700; color:{color};">{label}</span>'
