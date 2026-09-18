"""
header_analyzer.py – SPF/DKIM/DMARC/ARC parsing, spoofing detection, WHOIS lookup.
"""
import re
import socket
from typing import Any

try:
    import whois as pythonwhois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_domain(addr: str) -> str:
    """Pull domain from email address or Return-Path."""
    m = re.search(r"@([\w.\-]+)", addr)
    return m.group(1).lower() if m else ""


def _parse_auth_results(header_val: str) -> dict[str, str]:
    """Extract SPF/DKIM/DMARC/ARC verdicts from Authentication-Results header."""
    result: dict[str, str] = {}
    patterns = {
        "SPF":  r"spf=(\S+)",
        "DKIM": r"dkim=(\S+)",
        "DMARC":r"dmarc=(\S+)",
        "ARC":  r"arc=(\S+)",
    }
    for proto, pat in patterns.items():
        m = re.search(pat, header_val, re.IGNORECASE)
        result[proto] = m.group(1).rstrip(";") if m else "none"
    return result


def _received_hops(headers: dict) -> list[str]:
    """Return all Received header values (oldest last)."""
    hops = []
    for k, v in headers.items():
        if k.lower() == "received":
            hops.append(v)
    return hops


def _whois_org(domain: str) -> str:
    if not WHOIS_AVAILABLE or not domain:
        return "Unknown (whois not installed)"
    try:
        w = pythonwhois.whois(domain)
        org = (w.get("org") or w.get("registrant_name") or
               w.get("name") or w.get("registrar") or "Unknown")
        if isinstance(org, list):
            org = org[0]
        return str(org).strip() or "Unknown"
    except Exception:
        return "Unknown"


def _resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


# ── Main ─────────────────────────────────────────────────────────────────────

def analyze_headers(parsed: dict[str, Any]) -> dict[str, Any]:
    headers   = parsed["headers"]
    from_addr = parsed["from"]
    reply_to  = parsed["reply_to"]
    anomalies: list[str] = []

    # ── Authentication ────────────────────────────────────────────────────────
    auth_header = ""
    for k, v in headers.items():
        if "authentication-results" in k.lower():
            auth_header = v
            break
    auth = _parse_auth_results(auth_header)

    # Flag failed auth
    for proto, val in auth.items():
        if val.lower() in ("fail", "hardfail", "softfail", "none") and proto != "ARC":
            anomalies.append(f"{proto} check failed or missing (status: {val})")

    # ── From / Reply-To mismatch ──────────────────────────────────────────────
    from_domain  = _extract_domain(from_addr)
    rt_domain    = _extract_domain(reply_to)
    if rt_domain and rt_domain != from_domain:
        anomalies.append(
            f"Reply-To domain ({rt_domain}) differs from From domain ({from_domain}) — possible phishing misdirection"
        )

    # ── Received path anomalies ───────────────────────────────────────────────
    hops = _received_hops(headers)
    if hops:
        first_hop = hops[-1]  # oldest hop
        if "unknown" in first_hop.lower():
            anomalies.append("First Received hop contains 'unknown' — sender may be hiding origin")
        if re.search(r"\d{1,3}(\.\d{1,3}){3}", first_hop):
            anomalies.append("Email sent directly from IP address (no reverse-DNS hostname) in first hop")

    # ── Spoofing: display-name vs envelope from ───────────────────────────────
    display_match = re.search(r'"?([^<"]+)"?\s*<', from_addr)
    if display_match:
        display_name = display_match.group(1).strip().lower()
        trusted_brands = [
            "paypal", "amazon", "microsoft", "apple", "google", "netflix",
            "facebook", "instagram", "twitter", "chase", "wellsfargo", "hsbc",
            "rakuten", "ebay", "dropbox", "linkedin", "zoom", "docusign",
        ]
        for brand in trusted_brands:
            if brand in display_name and brand not in from_domain:
                anomalies.append(
                    f"Display-name impersonates '{brand}' but sending domain is '{from_domain}' — likely spoofing"
                )

    # ── WHOIS sender org ──────────────────────────────────────────────────────
    sender_org = _whois_org(from_domain)
    sender_ip  = _resolve_ip(from_domain)

    # ── Key headers table ─────────────────────────────────────────────────────
    interesting = [
        "From", "To", "Subject", "Date", "Reply-To", "Message-ID",
        "X-Mailer", "X-Originating-IP", "X-Spam-Status", "X-Spam-Score",
        "Return-Path", "MIME-Version", "Content-Type",
    ]
    key_headers = {}
    for h in interesting:
        for k, v in headers.items():
            if k.lower() == h.lower():
                key_headers[h] = v[:200]
                break

    # ── Homoglyph / IDN check on from domain ─────────────────────────────────
    try:
        encoded = from_domain.encode("idna").decode("ascii")
        if encoded != from_domain and "xn--" in encoded:
            anomalies.append(f"Sender domain uses Internationalized Domain Name (IDN/homoglyph): {from_domain} → {encoded}")
    except Exception:
        pass

    return {
        "auth":        auth,
        "anomalies":   anomalies,
        "sender_org":  sender_org,
        "sender_ip":   sender_ip,
        "from_domain": from_domain,
        "key_headers": key_headers,
        "hops":        hops,
    }
