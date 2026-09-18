"""
report_generator.py – Generate a professional, self-contained HTML report.
"""
from datetime import datetime, timezone
from typing import Any
import html as html_lib


def _esc(s: str) -> str:
    return html_lib.escape(str(s))


def _verdict_color(verdict: str) -> str:
    v = verdict.lower()
    if "malicious" in v or "phishing" in v or "🔴" in verdict:
        return "#ff1744"
    if "suspicious" in v or "🟡" in verdict or "⚠️" in verdict:
        return "#ffab40"
    return "#00e676"


def generate_html_report(
    parsed: dict,
    header_results: dict,
    content_results: dict,
    url_results: list,
    attachment_results: list,
    risk: dict,
) -> str:
    now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    score    = risk["score"]
    verdict  = risk["verdict"]
    vcol     = _verdict_color(verdict)
    breakdown = risk.get("breakdown", {})

    # ── Score gauge ───────────────────────────────────────────────────────────
    gauge_color = "#00e676" if score < 40 else ("#ffab40" if score < 70 else "#ff1744")

    # ── URL table rows ────────────────────────────────────────────────────────
    url_rows = ""
    for u in url_results:
        vc = _verdict_color(u.get("verdict",""))
        url_rows += f"""
        <tr>
          <td class="mono">{_esc(u.get('url','')[:80])}</td>
          <td class="mono">{_esc(u.get('resolved','') or '—')[:60]}</td>
          <td>{_esc(u.get('vt_detections','N/A'))}</td>
          <td>{_esc(u.get('gsb_status','N/A'))}</td>
          <td>{_esc(u.get('urlscan_verdict','N/A'))}</td>
          <td style="color:{vc};font-weight:700">{_esc(u.get('verdict','Unknown'))}</td>
        </tr>"""

    if not url_rows:
        url_rows = '<tr><td colspan="6" style="text-align:center;color:#666">No URLs found</td></tr>'

    # ── Attachment table rows ─────────────────────────────────────────────────
    att_rows = ""
    for a in attachment_results:
        vc = _verdict_color(a.get("verdict",""))
        att_rows += f"""
        <tr>
          <td>{_esc(a.get('filename','unknown'))}</td>
          <td>{_esc(a.get('size_str','?'))}</td>
          <td class="mono">{_esc(a.get('mime_type','?'))}</td>
          <td class="mono" style="font-size:0.75rem">{_esc(a.get('sha256','')[:24])}…</td>
          <td>{_esc(a.get('clamav','Not scanned'))}</td>
          <td>{_esc(a.get('vt_result','Not scanned'))}</td>
          <td style="color:{vc};font-weight:700">{_esc(a.get('verdict','Unknown'))}</td>
        </tr>"""

    if not att_rows:
        att_rows = '<tr><td colspan="7" style="text-align:center;color:#666">No attachments found</td></tr>'

    # ── Header rows ───────────────────────────────────────────────────────────
    hdr_rows = ""
    for k, v in header_results.get("key_headers", {}).items():
        hdr_rows += f"<tr><td><strong>{_esc(k)}</strong></td><td class='mono'>{_esc(v[:200])}</td></tr>"

    # ── Auth table ────────────────────────────────────────────────────────────
    auth = header_results.get("auth", {})
    auth_rows = ""
    for proto in ["SPF", "DKIM", "DMARC", "ARC"]:
        val   = auth.get(proto, "none")
        color = "#00e676" if "pass" in str(val).lower() else ("#ffab40" if "none" in str(val).lower() else "#ff1744")
        auth_rows += f"<tr><td><strong>{proto}</strong></td><td style='color:{color};font-weight:700'>{_esc(val)}</td></tr>"

    # ── Anomalies ─────────────────────────────────────────────────────────────
    anomaly_html = ""
    for a in header_results.get("anomalies", []):
        anomaly_html += f'<li style="color:#ffab40">⚠️ {_esc(a)}</li>'
    if not anomaly_html:
        anomaly_html = '<li style="color:#00e676">✅ No anomalies detected</li>'

    # ── Indicators ────────────────────────────────────────────────────────────
    indicator_html = ""
    for ind in content_results.get("indicators", []):
        indicator_html += f'<li style="color:#ff6b6b">{_esc(ind)}</li>'
    if not indicator_html:
        indicator_html = '<li style="color:#00e676">✅ No indicators found</li>'

    # ── Trends ────────────────────────────────────────────────────────────────
    trend_html = ""
    for t in content_results.get("trend_matches", []):
        trend_html += f'<li style="color:#ffab40">{_esc(t)}</li>'
    if not trend_html:
        trend_html = '<li style="color:#8892a4">No known kit patterns detected</li>'

    # ── Recommendations ───────────────────────────────────────────────────────
    rec_html = ""
    for r in risk.get("recommendations", []):
        rec_html += f"<li>{_esc(r)}</li>"

    # ── Raw email (escaped) ───────────────────────────────────────────────────
    raw_text = ""
    for k, v in parsed.get("headers", {}).items():
        raw_text += f"{k}: {v}\n"
    raw_text += "\n" + parsed.get("plain_text", "")[:5000]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishGuard Report – {_esc(parsed.get('subject','No Subject'))}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap');
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background:#0a0e1a; color:#c9d1e0; font-family:'Syne',sans-serif; line-height:1.6; padding:2rem; }}
  .mono {{ font-family:'IBM Plex Mono',monospace; font-size:0.85rem; }}
  h1 {{ font-size:2.2rem; font-weight:800; background:linear-gradient(135deg,#00d4ff,#7b2fff,#ff2d78);
        -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:0.25rem; }}
  h2 {{ font-size:1.25rem; font-weight:700; color:#00d4ff; margin:2rem 0 0.75rem; border-bottom:1px solid #1e2d40; padding-bottom:0.4rem; }}
  h3 {{ font-size:1rem; font-weight:700; color:#8892a4; margin:1rem 0 0.4rem; }}
  .meta {{ color:#8892a4; font-size:0.85rem; margin-bottom:2rem; }}
  .card {{ background:#111827; border:1px solid #1e2d40; border-radius:12px; padding:1.5rem; margin-bottom:1.5rem; }}
  .score-ring {{ display:inline-flex; flex-direction:column; align-items:center; background:#0d1525;
                  border:3px solid {gauge_color}; border-radius:50%; width:120px; height:120px;
                  justify-content:center; margin-right:2rem; }}
  .score-num {{ font-size:2.2rem; font-weight:800; color:{gauge_color}; }}
  .score-lbl {{ font-size:0.7rem; color:#8892a4; }}
  .verdict {{ font-size:1.3rem; font-weight:700; color:{vcol}; }}
  .exec-row {{ display:flex; align-items:center; flex-wrap:wrap; gap:1rem; }}
  .breakdown {{ display:flex; gap:1.5rem; flex-wrap:wrap; margin-top:1rem; }}
  .bk-item {{ background:#0d1525; border-radius:8px; padding:0.8rem 1.2rem; flex:1; min-width:120px; text-align:center; }}
  .bk-val {{ font-size:1.5rem; font-weight:700; color:#7b2fff; }}
  .bk-lbl {{ font-size:0.75rem; color:#8892a4; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.88rem; }}
  th {{ background:#0d1525; color:#8892a4; font-weight:600; padding:0.6rem 0.8rem; text-align:left;
        border-bottom:2px solid #1e2d40; }}
  td {{ padding:0.5rem 0.8rem; border-bottom:1px solid #1a2233; vertical-align:top; word-break:break-all; }}
  tr:hover td {{ background:#0f1a2e; }}
  ul {{ padding-left:1.5rem; }}
  li {{ margin-bottom:0.4rem; }}
  .disclaimer {{ background:#1a0a0a; border-left:3px solid #ff1744; padding:0.8rem 1.2rem;
                  border-radius:0 8px 8px 0; color:#ff6b6b; font-size:0.8rem; margin-bottom:1.5rem; }}
  details summary {{ cursor:pointer; color:#7b2fff; font-weight:700; padding:0.5rem 0; }}
  pre {{ background:#050810; padding:1rem; border-radius:8px; overflow-x:auto; font-size:0.78rem;
         color:#8892a4; white-space:pre-wrap; word-break:break-all; max-height:400px; overflow-y:auto; }}
  @media print {{ body {{ background:#fff; color:#000; }} .card {{ border:1px solid #ccc; background:#f9f9f9; }} }}
</style>
</head>
<body>

<h1>🛡️ PhishGuard Analysis Report</h1>
<p class="meta">Generated: {now} &nbsp;|&nbsp; Subject: <em>{_esc(parsed.get('subject',''))}</em></p>

<div class="disclaimer">
  ⚠️ <strong>For defensive/educational use only.</strong> This report is generated by automated tools and should be reviewed by a qualified security analyst. Results may contain false positives or negatives.
</div>

<!-- Executive Summary -->
<div class="card">
  <h2>📋 Executive Summary</h2>
  <div class="exec-row">
    <div class="score-ring">
      <span class="score-num">{score}</span>
      <span class="score-lbl">RISK SCORE</span>
    </div>
    <div>
      <div class="verdict">{_esc(verdict)}</div>
      <p style="margin-top:0.5rem;color:#8892a4">From: <strong style="color:#c9d1e0">{_esc(parsed.get('from',''))}</strong></p>
      <p style="color:#8892a4">Org: <strong style="color:#c9d1e0">{_esc(header_results.get('sender_org','Unknown'))}</strong></p>
      <p style="color:#8892a4">Date: {_esc(parsed.get('date',''))}</p>
    </div>
  </div>
  <div class="breakdown">
    <div class="bk-item"><div class="bk-val">{breakdown.get('headers',0)}/30</div><div class="bk-lbl">Headers</div></div>
    <div class="bk-item"><div class="bk-val">{breakdown.get('content',0)}/25</div><div class="bk-lbl">Content</div></div>
    <div class="bk-item"><div class="bk-val">{breakdown.get('urls',0)}/25</div><div class="bk-lbl">URLs</div></div>
    <div class="bk-item"><div class="bk-val">{breakdown.get('attachments',0)}/20</div><div class="bk-lbl">Attachments</div></div>
  </div>
</div>

<!-- Email Summary -->
<div class="card">
  <h2>✉️ Email Summary</h2>
  <p style="font-style:italic;color:#c9d1e0">{_esc(content_results.get('summary','No summary available.'))}</p>
</div>

<!-- Header Analysis -->
<div class="card">
  <h2>🔍 Header Analysis</h2>
  <h3>Authentication</h3>
  <table><thead><tr><th>Protocol</th><th>Result</th></tr></thead><tbody>{auth_rows}</tbody></table>
  <h3 style="margin-top:1.5rem">Anomalies</h3>
  <ul>{anomaly_html}</ul>
  <h3 style="margin-top:1.5rem">Key Headers</h3>
  <table><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>{hdr_rows}</tbody></table>
</div>

<!-- Content Analysis -->
<div class="card">
  <h2>🧠 Content Analysis</h2>
  <h3>Phishing Indicators</h3>
  <ul>{indicator_html}</ul>
  <h3 style="margin-top:1.2rem">Trend / Kit Matches (MITRE ATT&CK T1566)</h3>
  <ul>{trend_html}</ul>
</div>

<!-- URL Analysis -->
<div class="card">
  <h2>🔗 URL Analysis ({len(url_results)} URLs)</h2>
  <table>
    <thead>
      <tr><th>URL</th><th>Resolved To</th><th>VT Detections</th><th>Safe Browsing</th><th>URLScan</th><th>Verdict</th></tr>
    </thead>
    <tbody>{url_rows}</tbody>
  </table>
</div>

<!-- Attachment Analysis -->
<div class="card">
  <h2>📎 Attachment Analysis ({len(attachment_results)} files)</h2>
  <table>
    <thead>
      <tr><th>Filename</th><th>Size</th><th>MIME Type</th><th>SHA-256</th><th>ClamAV</th><th>VirusTotal</th><th>Verdict</th></tr>
    </thead>
    <tbody>{att_rows}</tbody>
  </table>
</div>

<!-- Recommendations -->
<div class="card">
  <h2>💡 Recommendations</h2>
  <ul>{rec_html}</ul>
</div>

<!-- Raw Email -->
<div class="card">
  <details>
    <summary>📄 Raw Email Headers &amp; Body (click to expand)</summary>
    <pre>{_esc(raw_text)}</pre>
  </details>
</div>

<p class="meta" style="margin-top:2rem;text-align:center">
  PhishGuard v1.0 — Open Source — Defensive Use Only<br>
  <a href="https://github.com/iamnotprashant/phishguard" style="color:#7b2fff">github.com/iamnotprashant/phishguard</a>
</p>
</body>
</html>"""

    return html
