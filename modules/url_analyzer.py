"""
url_analyzer.py – Check URLs against VirusTotal, Google Safe Browsing, URLScan.io.
Resolve shortened URLs and detect homoglyphs / IP usage.
"""
import re
import time
import socket
import requests
from typing import Any
from urllib.parse import urlparse


# ── Known URL shorteners ──────────────────────────────────────────────────────
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "short.link", "tiny.cc", "cutt.ly",
    "bl.ink", "rb.gy", "s.id",
}

# ── Suspicious TLDs ───────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".click", ".link", ".work", ".loan", ".win",
    ".racing", ".download", ".accountant", ".science",
}


def _resolve_short_url(url: str, timeout: int = 5) -> str:
    """Follow redirects to get final destination URL."""
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout,
                          headers={"User-Agent": "Mozilla/5.0 (PhishGuard)"})
        return r.url
    except Exception:
        return url


def _check_vt(url: str, api_key: str) -> dict:
    """Query VirusTotal URL report (v3 API, free tier)."""
    if not api_key:
        return {"detections": "N/A", "total": "N/A", "vt_verdict": "No key"}
    try:
        import vt
        client  = vt.Client(api_key)
        url_id  = vt.url_id(url)
        analysis = client.get_object(f"/urls/{url_id}")
        stats   = analysis.last_analysis_stats
        malicious = stats.get("malicious", 0)
        total   = sum(stats.values())
        client.close()
        return {
            "detections": malicious,
            "total":      total,
            "vt_verdict": "Malicious" if malicious > 2 else ("Suspicious" if malicious > 0 else "Clean"),
        }
    except Exception as e:
        return {"detections": "Error", "total": "Error", "vt_verdict": str(e)[:60]}


def _check_gsb(url: str, api_key: str) -> str:
    """Query Google Safe Browsing API v4."""
    if not api_key:
        return "No key"
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(endpoint, json=body, timeout=8)
        data = r.json()
        if data.get("matches"):
            threat = data["matches"][0].get("threatType", "THREAT")
            return f"UNSAFE ({threat})"
        return "Safe"
    except Exception as e:
        return f"Error: {str(e)[:40]}"


def _check_urlscan(url: str, api_key: str) -> str:
    """Search URLScan.io for existing report on this URL."""
    if not api_key:
        return "No key"
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    try:
        # Search existing results first
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=page.url:{requests.utils.quote(url)}&size=1",
            headers=headers, timeout=8,
        )
        results = r.json().get("results", [])
        if results:
            verdict = results[0].get("verdicts", {}).get("overall", {})
            malicious = verdict.get("malicious", False)
            score     = verdict.get("score", 0)
            return f"{'Malicious' if malicious else 'Clean'} (score {score})"
        return "No prior scan"
    except Exception as e:
        return f"Error: {str(e)[:40]}"


def _detect_homoglyphs(domain: str) -> bool:
    """Detect non-ASCII characters (potential IDN homoglyph attack)."""
    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def _is_ip_url(url: str) -> bool:
    host = urlparse(url).hostname or ""
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False


def analyze_urls(
    urls: list[str],
    vt_key: str = "",
    gsb_key: str = "",
    urlscan_key: str = "",
) -> list[dict[str, Any]]:

    results = []
    for url in urls[:30]:  # cap to 30 to avoid API hammering
        parsed_url = urlparse(url)
        domain     = parsed_url.hostname or ""

        # Resolve shorteners
        resolved = url
        if any(s in domain for s in SHORTENERS):
            resolved = _resolve_short_url(url)

        # Basic flags
        flags: list[str] = []
        if _is_ip_url(url):
            flags.append("Uses raw IP address")
        if _detect_homoglyphs(domain):
            flags.append("Homoglyph / IDN domain detected")
        ext = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
        if ext in SUSPICIOUS_TLDS:
            flags.append(f"Suspicious TLD: {ext}")
        if resolved != url:
            flags.append(f"Redirect → {resolved[:80]}")

        # API checks
        vt_data     = _check_vt(resolved, vt_key)
        gsb_status  = _check_gsb(resolved, gsb_key)
        urlscan_res = _check_urlscan(resolved, urlscan_key)

        # Overall verdict
        is_bad = (
            vt_data.get("vt_verdict", "").lower() in ("malicious", "suspicious")
            or "unsafe" in gsb_status.lower()
            or "malicious" in urlscan_res.lower()
        )
        verdict = "🔴 Malicious" if is_bad else ("🟡 Suspicious" if flags else "🟢 Clean")

        results.append({
            "url":             url,
            "resolved":        resolved if resolved != url else "",
            "vt_detections":   f"{vt_data['detections']}/{vt_data['total']}",
            "vt_verdict":      vt_data["vt_verdict"],
            "gsb_status":      gsb_status,
            "urlscan_verdict": urlscan_res,
            "flags":           flags,
            "verdict":         verdict,
        })

        time.sleep(0.25)  # polite rate limiting

    return results
