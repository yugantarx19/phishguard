"""
risk_scorer.py – Compute weighted phishing risk score (0–100) and recommendations.
"""
from typing import Any


def compute_risk_score(
    header_results: dict,
    content_results: dict,
    url_results: list,
    attachment_results: list,
) -> dict[str, Any]:
    """
    Weights:
        Headers     30%
        Content     25%
        URLs        25%
        Attachments 20%
    """

    # ── Header score (0–30) ────────────────────────────────────────────────────
    h_score  = 0
    auth     = header_results.get("auth", {})
    anomalies = header_results.get("anomalies", [])

    for proto in ["SPF", "DKIM", "DMARC"]:
        val = auth.get(proto, "none").lower()
        if val in ("fail", "hardfail", "softfail", "none"):
            h_score += 5
        elif val in ("neutral",):
            h_score += 2

    h_score += min(len(anomalies) * 4, 15)
    h_score = min(h_score, 30)

    # ── Content score (0–25) ───────────────────────────────────────────────────
    c_score     = 0
    indicators  = content_results.get("indicators", [])
    trend_matches = content_results.get("trend_matches", [])

    c_score += min(len(indicators) * 4, 16)
    c_score += min(len(trend_matches) * 3, 9)
    c_score = min(c_score, 25)

    # ── URL score (0–25) ───────────────────────────────────────────────────────
    u_score = 0
    for u in url_results:
        verdict = u.get("verdict", "")
        if "Malicious" in verdict:
            u_score += 10
        elif "Suspicious" in verdict:
            u_score += 4
        u_score += len(u.get("flags", [])) * 2

    u_score = min(u_score, 25)

    # ── Attachment score (0–20) ────────────────────────────────────────────────
    a_score = 0
    for att in attachment_results:
        verdict = att.get("verdict", "")
        if "Malicious" in verdict:
            a_score += 15
        elif "Suspicious" in verdict:
            a_score += 6
        a_score += len(att.get("flags", [])) * 3

    a_score = min(a_score, 20)

    # ── Total ─────────────────────────────────────────────────────────────────
    total = h_score + c_score + u_score + a_score
    total = min(total, 100)

    if total < 25:
        verdict = "✅ SAFE"
    elif total < 50:
        verdict = "⚠️ SUSPICIOUS"
    elif total < 75:
        verdict = "🚨 LIKELY PHISHING"
    else:
        verdict = "🔴 PHISHING"

    # ── Recommendations ───────────────────────────────────────────────────────
    recs: list[str] = []
    if total >= 25:
        recs.append("**Do not click any links** in this email without further verification.")
        recs.append("**Do not download or open attachments** from this email.")
        recs.append("Report this email to your security/IT team or abuse desk.")

    if any(a.get("verdict", "").startswith("🔴") for a in attachment_results):
        recs.append("🚨 Attachment flagged as malicious — quarantine immediately and report to IR team.")

    if any(u.get("verdict", "").startswith("🔴") for u in url_results):
        recs.append("🚨 At least one URL is confirmed malicious — block at email gateway and proxy.")

    if "fail" in str(auth.get("SPF", "")).lower() or "fail" in str(auth.get("DKIM", "")).lower():
        recs.append("Email failed SPF/DKIM authentication — sender may be spoofed. Do not trust sender identity.")

    if total < 25:
        recs.append("Email appears safe based on automated checks. Exercise normal caution.")

    recs.append("Forward suspicious emails to [abuse@yourdomain.com] with full headers.")
    recs.append("Consider reporting phishing URLs to PhishTank (phishtank.org) or NCSC (UK) / CISA (US).")

    return {
        "score":           total,
        "verdict":         verdict,
        "breakdown": {
            "headers":     h_score,
            "content":     c_score,
            "urls":        u_score,
            "attachments": a_score,
        },
        "recommendations": recs,
    }
