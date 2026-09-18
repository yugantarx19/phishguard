"""
PhishGuard - Phishing Email Analysis Tool
For defensive analysis only. Educational and security research purposes.
"""

import streamlit as st
import os
import json
import time
from pathlib import Path
import tempfile

# Local modules
from modules.email_parser import parse_eml
from modules.header_analyzer import analyze_headers
from modules.content_analyzer import analyze_content
from modules.url_analyzer import analyze_urls
from modules.attachment_analyzer import analyze_attachments
from modules.risk_scorer import compute_risk_score
from modules.report_generator import generate_html_report

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard – Email Threat Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Syne', sans-serif;
}
code, pre, .mono {
    font-family: 'IBM Plex Mono', monospace;
}
.stApp { background: #0a0e1a; }

.hero-title {
    font-size: 3rem;
    font-weight: 800;
    background: linear-gradient(135deg, #00d4ff, #7b2fff, #ff2d78);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -1px;
}
.hero-sub {
    color: #8892a4;
    font-size: 1.05rem;
    margin-top: -0.5rem;
}
.score-safe    { color: #00e676; font-weight: 700; font-size: 2rem; }
.score-warn    { color: #ffab40; font-weight: 700; font-size: 2rem; }
.score-danger  { color: #ff1744; font-weight: 700; font-size: 2rem; }
.badge-safe    { background:#00e676; color:#000; border-radius:4px; padding:2px 10px; font-size:0.8rem; font-weight:700; }
.badge-warn    { background:#ffab40; color:#000; border-radius:4px; padding:2px 10px; font-size:0.8rem; font-weight:700; }
.badge-danger  { background:#ff1744; color:#fff; border-radius:4px; padding:2px 10px; font-size:0.8rem; font-weight:700; }
.section-card {
    background: #111827;
    border: 1px solid #1e2d40;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.2rem;
}
.stProgress > div > div { background: linear-gradient(90deg,#00d4ff,#7b2fff); }
.disclaimer {
    background: #1a0a0a;
    border-left: 3px solid #ff1744;
    padding: 0.8rem 1.2rem;
    border-radius: 0 8px 8px 0;
    color: #ff6b6b;
    font-size: 0.82rem;
    margin-bottom: 1rem;
}
</style>
""", unsafe_allow_html=True)

# ── Sidebar – API Keys ────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ Configuration")
    st.markdown("---")
    vt_key = st.text_input("VirusTotal API Key", type="password",
                           help="Free key from virustotal.com – required for URL/attachment scanning")
    gsb_key = st.text_input("Google Safe Browsing Key", type="password",
                            help="Free key from Google Cloud Console")
    urlscan_key = st.text_input("URLScan.io API Key", type="password",
                                help="Free key from urlscan.io")
    st.markdown("---")
    st.markdown("**ClamAV**")
    use_clamav = st.toggle("Use local ClamAV", value=False,
                           help="Requires clamd running locally on port 3310")
    st.markdown("---")
    st.markdown("**NLP Engine**")
    nlp_engine = st.selectbox("Summarizer", ["spaCy (fast, local)", "Transformers (accurate)"])
    st.markdown("---")
    st.caption("⚠️ Keys stored only in session memory. Never logged.")

# ── Hero ──────────────────────────────────────────────────────────────────────
st.markdown('<div class="hero-title">🛡️ PhishGuard</div>', unsafe_allow_html=True)
st.markdown('<div class="hero-sub">Open-source phishing email forensics — runs 100 % locally</div>', unsafe_allow_html=True)
st.markdown("")

st.markdown("""
<div class="disclaimer">
⚠️ <strong>Defensive use only.</strong> This tool is for security analysts, incident responders, and researchers.
Do not use for malicious purposes. URLs and attachments are analysed via external APIs — do not upload sensitive personal data.
</div>
""", unsafe_allow_html=True)

# ── Upload ────────────────────────────────────────────────────────────────────
col1, col2 = st.columns([2, 1])
with col1:
    uploaded_file = st.file_uploader("Upload .eml file", type=["eml"],
                                     help="Drag & drop or click to browse")
with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    show_raw = st.checkbox("Preview raw email", value=False)

# ── Analysis pipeline ─────────────────────────────────────────────────────────
if uploaded_file:
    raw_bytes = uploaded_file.read()

    if show_raw:
        with st.expander("📄 Raw Email Content", expanded=False):
            st.text(raw_bytes.decode("utf-8", errors="replace")[:8000])

    st.markdown("---")
    st.markdown("### 🔬 Running Analysis…")

    progress = st.progress(0)
    status   = st.empty()

    # 1 – Parse
    status.info("📨 Parsing email structure…")
    parsed = parse_eml(raw_bytes)
    progress.progress(15)
    time.sleep(0.2)

    # 2 – Headers
    status.info("🔍 Analysing headers & authentication…")
    header_results = analyze_headers(parsed)
    progress.progress(30)
    time.sleep(0.2)

    # 3 – Content
    status.info("🧠 Running NLP content analysis…")
    content_results = analyze_content(parsed, engine=nlp_engine)
    progress.progress(50)
    time.sleep(0.2)

    # 4 – URLs
    status.info("🔗 Checking URLs against threat intelligence…")
    url_results = analyze_urls(
        parsed.get("urls", []),
        vt_key=vt_key,
        gsb_key=gsb_key,
        urlscan_key=urlscan_key,
    )
    progress.progress(70)
    time.sleep(0.2)

    # 5 – Attachments
    status.info("📎 Scanning attachments…")
    attachment_results = analyze_attachments(
        parsed.get("attachments", []),
        vt_key=vt_key,
        use_clamav=use_clamav,
    )
    progress.progress(85)
    time.sleep(0.2)

    # 6 – Score
    status.info("📊 Computing risk score…")
    risk = compute_risk_score(header_results, content_results, url_results, attachment_results)
    progress.progress(95)
    time.sleep(0.2)

    # 7 – Report
    status.info("📑 Generating HTML report…")
    html_report = generate_html_report(parsed, header_results, content_results,
                                       url_results, attachment_results, risk)
    progress.progress(100)
    status.success("✅ Analysis complete!")
    time.sleep(0.5)
    status.empty()
    progress.empty()

    # ── Results ───────────────────────────────────────────────────────────────
    score = risk["score"]
    verdict = risk["verdict"]

    score_class = "score-safe" if score < 40 else ("score-warn" if score < 70 else "score-danger")
    badge_class = "badge-safe" if score < 40 else ("badge-warn" if score < 70 else "badge-danger")

    st.markdown("---")
    st.markdown("## 📋 Analysis Results")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="{score_class}">{score}/100</div>', unsafe_allow_html=True)
        st.caption("Risk Score")
    with c2:
        st.markdown(f'<span class="{badge_class}">{verdict}</span>', unsafe_allow_html=True)
        st.caption("Verdict")
    with c3:
        st.metric("URLs Found", len(parsed.get("urls", [])))
    with c4:
        st.metric("Attachments", len(parsed.get("attachments", [])))

    st.markdown("---")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["📧 Headers", "📝 Content", "🔗 URLs", "📎 Attachments", "💡 Recommendations"])

    with tab1:
        st.markdown("#### Authentication Results")
        auth = header_results.get("auth", {})
        cols = st.columns(4)
        for i, proto in enumerate(["SPF", "DKIM", "DMARC", "ARC"]):
            val = auth.get(proto, "unknown")
            icon = "✅" if "pass" in str(val).lower() else ("❌" if "fail" in str(val).lower() else "⚠️")
            cols[i].metric(proto, f"{icon} {val}")

        st.markdown("#### Header Anomalies")
        anomalies = header_results.get("anomalies", [])
        if anomalies:
            for a in anomalies:
                st.warning(a)
        else:
            st.success("No header anomalies detected.")

        st.markdown("#### Key Headers")
        key_hdrs = header_results.get("key_headers", {})
        if key_hdrs:
            import pandas as pd
            df = pd.DataFrame(list(key_hdrs.items()), columns=["Header", "Value"])
            st.dataframe(df, use_container_width=True)

    with tab2:
        st.markdown("#### Email Summary")
        summary = content_results.get("summary", "Unable to generate summary.")
        st.info(f"💬 {summary}")

        st.markdown("#### Phishing Indicators")
        indicators = content_results.get("indicators", [])
        if indicators:
            for ind in indicators:
                st.error(f"🚩 {ind}")
        else:
            st.success("No strong phishing indicators found in content.")

        st.markdown("#### Trend Matches")
        trends = content_results.get("trend_matches", [])
        if trends:
            for t in trends:
                st.warning(f"📌 {t}")
        else:
            st.info("No known phishing kit patterns detected.")

    with tab3:
        urls = parsed.get("urls", [])
        if not urls:
            st.info("No URLs found in this email.")
        else:
            import pandas as pd
            rows = []
            for u in url_results:
                rows.append({
                    "URL": u.get("url", "")[:80],
                    "Resolved": u.get("resolved", "")[:60],
                    "VT Detections": u.get("vt_detections", "N/A"),
                    "Safe Browsing": u.get("gsb_status", "N/A"),
                    "URLScan": u.get("urlscan_verdict", "N/A"),
                    "Verdict": u.get("verdict", "Unknown"),
                })
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True)

    with tab4:
        attachments = parsed.get("attachments", [])
        if not attachments:
            st.info("No attachments found.")
        else:
            import pandas as pd
            rows = []
            for a in attachment_results:
                rows.append({
                    "Filename": a.get("filename", "unknown"),
                    "Size": a.get("size_str", "?"),
                    "MIME Type": a.get("mime_type", "?"),
                    "ClamAV": a.get("clamav", "Not scanned"),
                    "VirusTotal": a.get("vt_result", "Not scanned"),
                    "Verdict": a.get("verdict", "Unknown"),
                })
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True)

    with tab5:
        recs = risk.get("recommendations", [])
        for r in recs:
            st.markdown(f"- {r}")

    st.markdown("---")
    st.markdown("### 📥 Download Full Report")
    st.download_button(
        label="⬇️ Download HTML Report",
        data=html_report.encode("utf-8"),
        file_name=f"phishguard_report_{uploaded_file.name}.html",
        mime="text/html",
    )

else:
    st.markdown("""
    <div class="section-card">
    <h4>🚀 How to use PhishGuard</h4>
    <ol>
        <li>Add optional API keys in the sidebar (VirusTotal recommended)</li>
        <li>Upload a <code>.eml</code> email file using the uploader above</li>
        <li>PhishGuard will automatically analyse headers, content, URLs, and attachments</li>
        <li>Download the full HTML report for documentation</li>
    </ol>
    <p style="color:#8892a4; font-size:0.85rem">Tip: Export emails as .eml from Outlook (File → Save As), Gmail (⋮ → Download message), or Thunderbird.</p>
    </div>
    """, unsafe_allow_html=True)
