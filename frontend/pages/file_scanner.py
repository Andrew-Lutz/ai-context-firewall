"""
File Upload Scanner Page - AI Context Firewall
Drag-and-drop file scanning with full entity/injection detection.
"""

import streamlit as st
import time
import json
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Offline fallback scanner (mirrors prompt_scanner logic for files)
# ---------------------------------------------------------------------------

def _offline_scan_text(text: str) -> dict:
    """Run a local regex-based scan when the backend is unavailable."""
    patterns = {
        "SSN":           (r"\b\d{3}-\d{2}-\d{4}\b", "PHI/PII", "critical"),
        "Credit Card":   (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", "PCI", "critical"),
        "Email":         (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "PII", "medium"),
        "Phone":         (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b", "PII", "medium"),
        "API Key":       (r"\b(?:sk|pk|rk|api|key)[-_][A-Za-z0-9]{20,}\b", "SECRET", "critical"),
        "IP Address":    (r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", "NETWORK", "low"),
        "MRN":           (r"\bMRN[\s:#]*\d{6,10}\b", "PHI", "high"),
        "Bank Account":  (r"\b\d{8,17}\b", "PCI", "medium"),
    }
    injection_patterns = [
        (r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?", "Instruction Override"),
        (r"you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:evil|unrestricted|jailbroken|DAN)", "Role Confusion"),
        (r"(?:repeat|print|output|echo)\s+(?:the\s+)?(?:system\s+)?prompt", "Prompt Extraction"),
        (r"</?(system|human|assistant|instruction)\s*>", "Delimiter Injection"),
        (r"(?:act|pretend|simulate|roleplay)\s+as\s+(?:if\s+)?(?:you\s+(?:are|were|have\s+no))", "Persona Hijack"),
    ]

    entities = []
    redacted = text
    risk = 0.0

    for label, (pat, etype, severity) in patterns.items():
        for m in re.finditer(pat, text, re.IGNORECASE):
            entities.append({
                "text": m.group(),
                "type": etype,
                "label": label,
                "severity": severity,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.92,
            })
            redacted = redacted.replace(m.group(), f"[{label.upper().replace(' ', '_')}]")
            risk = max(risk, {"critical": 0.95, "high": 0.75, "medium": 0.50, "low": 0.25}[severity])

    injections = []
    for pat, iname in injection_patterns:
        if re.search(pat, text, re.IGNORECASE):
            injections.append({"type": iname, "severity": "critical", "confidence": 0.88})
            risk = max(risk, 0.95)

    return {
        "scan_id": f"offline-file-{int(time.time())}",
        "risk_score": risk,
        "entities_detected": entities,
        "injections_detected": injections,
        "redacted_content": redacted,
        "policy_violations": [],
        "recommendation": "Block and review" if risk > 0.7 else ("Review recommended" if risk > 0.3 else "Safe to proceed"),
        "processing_time_ms": 12,
        "offline_mode": True,
    }


def _extract_text_from_file(uploaded_file) -> tuple[str, str]:
    """Extract text from various file types. Returns (text, error_msg)."""
    name = uploaded_file.name.lower()
    raw = uploaded_file.read()

    try:
        if name.endswith(".txt") or name.endswith(".md"):
            return raw.decode("utf-8", errors="replace"), ""

        if name.endswith(".json"):
            data = json.loads(raw.decode("utf-8", errors="replace"))
            return json.dumps(data, indent=2), ""

        if name.endswith(".csv"):
            return raw.decode("utf-8", errors="replace"), ""

        if name.endswith(".pdf"):
            try:
                import pdfplumber
                import io
                with pdfplumber.open(io.BytesIO(raw)) as pdf:
                    pages = [p.extract_text() or "" for p in pdf.pages]
                return "\n\n".join(pages), ""
            except ImportError:
                return raw.decode("utf-8", errors="replace"), "pdfplumber not installed; decoded as text"

        if name.endswith(".docx"):
            try:
                import docx
                import io
                doc = docx.Document(io.BytesIO(raw))
                return "\n".join(p.text for p in doc.paragraphs), ""
            except ImportError:
                return raw.decode("utf-8", errors="replace"), "python-docx not installed; decoded as text"

        # Generic fallback
        return raw.decode("utf-8", errors="replace"), "Unknown type; decoded as UTF-8"

    except Exception as e:
        return "", str(e)


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "critical": "#FF4B4B",
    "high":     "#FF8C00",
    "medium":   "#FFD700",
    "low":      "#00C853",
}

def _severity_badge(sev: str) -> str:
    col = SEVERITY_COLORS.get(sev, "#888")
    return f'<span style="background:{col};color:#000;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">{sev.upper()}</span>'

def _risk_bar(score: float) -> str:
    pct = int(score * 100)
    col = "#FF4B4B" if score > 0.7 else ("#FFD700" if score > 0.4 else "#00C853")
    return f"""
    <div style="background:#1e1e2e;border-radius:6px;height:12px;width:100%">
      <div style="background:{col};border-radius:6px;height:12px;width:{pct}%"></div>
    </div>
    <div style="color:{col};font-weight:700;margin-top:4px">{pct}% Risk</div>
    """


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

def render():
    st.markdown("## 📂 File Upload Scanner")
    st.markdown("Upload documents for AI security scanning. Supports PDF, DOCX, TXT, CSV, JSON, and source code files.")

    # ── Upload area ──────────────────────────────────────────────────────────
    st.markdown("---")
    col_up, col_opts = st.columns([2, 1])

    with col_up:
        uploaded = st.file_uploader(
            "Drag and drop files here",
            type=["pdf", "docx", "txt", "md", "csv", "json", "py", "js", "ts", "yaml", "yml", "eml", "html"],
            accept_multiple_files=True,
            help="Max 50 MB per file",
        )

    with col_opts:
        st.markdown("**Scan Options**")
        scan_pii  = st.checkbox("PII / PHI Detection",   value=True)
        scan_pci  = st.checkbox("PCI / Financial Data",  value=True)
        scan_inj  = st.checkbox("Injection Detection",   value=True)
        scan_sec  = st.checkbox("Secrets / Credentials", value=True)
        redact_mode = st.selectbox("Redaction Mode", ["mask", "hash", "tokenize"], index=0)

    # ── Scan button ───────────────────────────────────────────────────────────
    if uploaded:
        st.markdown(f"**{len(uploaded)} file(s) ready to scan**")
        if st.button("🔍 Scan Files", type="primary", use_container_width=True):
            st.session_state["file_scan_results"] = []

            for uf in uploaded:
                uf.seek(0)          # reset after previous read
                text, warn = _extract_text_from_file(uf)

                if warn:
                    st.warning(f"⚠️  {uf.name}: {warn}")

                if not text.strip():
                    st.error(f"❌  Could not extract text from **{uf.name}**")
                    continue

                with st.spinner(f"Scanning {uf.name}…"):
                    api = st.session_state.get("api_client")
                    result = None

                    if api:
                        try:
                            result = api.scan_file(uf, {"redaction_mode": redact_mode})
                        except Exception:
                            pass

                    if not result:
                        result = _offline_scan_text(text)

                    result["filename"] = uf.name
                    result["char_count"] = len(text)
                    result["_raw_text"] = text
                    st.session_state["file_scan_results"].append(result)

    # ── Results ───────────────────────────────────────────────────────────────
    results: list = st.session_state.get("file_scan_results", [])

    if not results:
        # Placeholder UI
        st.markdown("---")
        st.markdown(
            """
            <div style="text-align:center;padding:60px 20px;color:#666">
              <div style="font-size:48px">📄</div>
              <div style="font-size:18px;margin-top:12px">Upload files above to begin scanning</div>
              <div style="font-size:13px;margin-top:8px">Supports PDF, DOCX, TXT, CSV, JSON, source code & more</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Sample threat cards
        st.markdown("### Example Detectable Threats")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("""
            **🏥 Healthcare Documents**
            - Patient MRN numbers
            - Social Security Numbers
            - Diagnosis / ICD codes
            - Prescription details
            - Insurance member IDs
            """)
        with c2:
            st.markdown("""
            **💳 Financial Records**
            - Credit card numbers (PAN)
            - Bank account numbers
            - Routing numbers
            - CVV / expiry data
            - Trading account IDs
            """)
        with c3:
            st.markdown("""
            **🔐 Technical Secrets**
            - API keys / tokens
            - Database credentials
            - SSH private keys
            - OAuth secrets
            - Hardcoded passwords
            """)
        return

    # ── Summary row ───────────────────────────────────────────────────────────
    st.markdown("---")
    total_entities   = sum(len(r.get("entities_detected", [])) for r in results)
    total_injections = sum(len(r.get("injections_detected", [])) for r in results)
    total_violations = sum(len(r.get("policy_violations", [])) for r in results)
    critical_files   = sum(1 for r in results if r.get("risk_score", 0) > 0.7)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Files Scanned",       len(results))
    m2.metric("Entities Found",       total_entities,   delta=f"+{total_entities}" if total_entities else None)
    m3.metric("Injection Attempts",   total_injections, delta=f"+{total_injections}" if total_injections else None)
    m4.metric("High-Risk Files",      critical_files,   delta=f"+{critical_files}" if critical_files else None)

    # ── Per-file results ──────────────────────────────────────────────────────
    st.markdown("### Scan Results")

    for result in results:
        fname      = result.get("filename", "unknown")
        risk       = result.get("risk_score", 0.0)
        entities   = result.get("entities_detected", [])
        injections = result.get("injections_detected", [])
        violations = result.get("policy_violations", [])
        redacted   = result.get("redacted_content", "")
        raw_text   = result.get("_raw_text", "")
        rec        = result.get("recommendation", "")
        chars      = result.get("char_count", 0)
        offline    = result.get("offline_mode", False)

        sev_label = "CRITICAL" if risk > 0.7 else ("HIGH" if risk > 0.5 else ("MEDIUM" if risk > 0.3 else "CLEAN"))
        sev_col   = SEVERITY_COLORS.get(sev_label.lower(), "#00C853")

        with st.expander(f"📄 {fname}  —  {sev_label}  ({int(risk*100)}% risk)", expanded=(risk > 0.3)):
            if offline:
                st.info("ℹ️  Offline mode — scanned locally without backend")

            # Risk bar
            st.markdown(_risk_bar(risk), unsafe_allow_html=True)
            st.markdown(f"**{chars:,} characters** scanned · Recommendation: **{rec}**")

            # Tabs
            tabs = st.tabs(["🔍 Entities", "💉 Injections", "🛡️ Redacted", "📜 Policy", "📄 Raw Text"])

            # --- Entities ---
            with tabs[0]:
                if entities:
                    for ent in entities:
                        ecol = SEVERITY_COLORS.get(ent.get("severity", "low"), "#888")
                        st.markdown(
                            f'<div style="background:#1e1e2e;border-left:3px solid {ecol};'
                            f'padding:8px 12px;margin:4px 0;border-radius:4px">'
                            f'<b>{ent.get("label","?")}</b> &nbsp; {_severity_badge(ent.get("severity","low"))} &nbsp; '
                            f'<code style="background:#2d2d3e;padding:2px 6px;border-radius:3px">{ent.get("text","")}</code> &nbsp; '
                            f'<span style="color:#888">confidence: {ent.get("confidence",0):.0%}</span>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
                else:
                    st.success("✅ No sensitive entities detected")

            # --- Injections ---
            with tabs[1]:
                if injections:
                    for inj in injections:
                        st.markdown(
                            f'<div style="background:#1e1e2e;border-left:3px solid #FF4B4B;'
                            f'padding:8px 12px;margin:4px 0;border-radius:4px">'
                            f'⚠️ <b>{inj.get("type","?")}</b> &nbsp; {_severity_badge(inj.get("severity","critical"))} &nbsp; '
                            f'<span style="color:#888">confidence: {inj.get("confidence",0):.0%}</span>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
                else:
                    st.success("✅ No injection attempts detected")

            # --- Redacted ---
            with tabs[2]:
                if redacted:
                    st.code(redacted[:3000] + ("…" if len(redacted) > 3000 else ""), language="text")
                    st.download_button(
                        "⬇️ Download Redacted Text",
                        data=redacted,
                        file_name=f"redacted_{fname}.txt",
                        mime="text/plain",
                    )
                else:
                    st.info("No redacted content available")

            # --- Policy ---
            with tabs[3]:
                if violations:
                    for v in violations:
                        st.markdown(
                            f'<div style="background:#1e1e2e;border-left:3px solid #FFD700;'
                            f'padding:8px 12px;margin:4px 0;border-radius:4px">'
                            f'📋 <b>{v.get("policy_id","?")}</b>: {v.get("rule_name","?")} — '
                            f'{_severity_badge(v.get("severity","medium"))} '
                            f'<br><span style="color:#aaa;font-size:12px">{v.get("explanation","")}</span>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
                else:
                    st.success("✅ No policy violations detected")

            # --- Raw ---
            with tabs[4]:
                st.code(raw_text[:2000] + ("…" if len(raw_text) > 2000 else ""), language="text")

    # ── Bulk export ───────────────────────────────────────────────────────────
    if results:
        st.markdown("---")
        export_data = [
            {
                "filename":   r.get("filename"),
                "risk_score": r.get("risk_score"),
                "entities":   len(r.get("entities_detected", [])),
                "injections": len(r.get("injections_detected", [])),
                "violations": len(r.get("policy_violations", [])),
                "recommendation": r.get("recommendation"),
            }
            for r in results
        ]
        st.download_button(
            "⬇️ Export Scan Report (JSON)",
            data=json.dumps(export_data, indent=2),
            file_name="file_scan_report.json",
            mime="application/json",
        )
