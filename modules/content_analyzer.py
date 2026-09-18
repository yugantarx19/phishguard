"""
content_analyzer.py – NLP summarization, phishing indicator detection, trend matching.
"""
import re
from typing import Any


# ── Phishing keyword patterns ─────────────────────────────────────────────────
URGENCY_PATTERNS = [
    r"urgent(?:ly)?", r"immediately", r"within\s+\d+\s+hour", r"act\s+now",
    r"limited\s+time", r"expire[sd]?", r"deadline", r"last\s+chance",
    r"account\s+(will\s+be\s+)?suspended", r"suspended", r"verify\s+now",
    r"confirm\s+your\s+account", r"update\s+your\s+(billing|payment|account)",
]
THREAT_PATTERNS = [
    r"will\s+be\s+(deleted|terminated|suspended|closed)",
    r"legal\s+action", r"law\s+enforcement", r"reported\s+to",
    r"unauthorized\s+access", r"hacked", r"compromised",
    r"your\s+account\s+has\s+been", r"suspicious\s+activity",
]
CREDENTIAL_PATTERNS = [
    r"(?:enter|provide|confirm|verify)\s+your\s+(?:password|credentials|pin|ssn|social\s+security)",
    r"log\s*in\s+to\s+(?:verify|confirm|secure)",
    r"reset\s+your\s+password",
    r"click\s+(?:here|below|the\s+link)\s+to\s+(?:verify|confirm|login)",
]
GENERIC_GREETING = [
    r"dear\s+(?:customer|user|member|account\s+holder|valued\s+customer|friend)",
    r"hello\s+(?:there|sir|madam)",
    r"good\s+day",
]
BRAND_IMPERSONATION = [
    "paypal", "amazon", "microsoft", "apple", "google", "netflix",
    "facebook", "instagram", "twitter/x", "chase", "wells fargo", "bank of america",
    "hsbc", "barclays", "rakuten", "ebay", "dropbox", "linkedin",
    "zoom", "docusign", "fedex", "dhl", "usps", "irs", "hmrc",
]

# ── Known phishing kit signatures (simplified MITRE T1566 patterns) ──────────
PHISHING_KIT_PATTERNS = [
    (r"microsoft\s*365|office\s*365|onedrive|sharepoint", "microsoft_365"),
    (r"paypal\.(?!com)", "paypal_clone"),
    (r"apple\s*id|icloud\s*support|apple\s*security", "apple_id"),
    (r"unusual\s*sign.?in|verify\s*your\s*identity|account\s*temporarily", "generic_credential_harvest"),
    (r"evilginx|modlishka|gophish", "known_phishing_framework"),
    (r"amazon\s*(prime|account|order\s*confirmation)", "amazon_impersonation"),
    (r"google\s*(account|security|drive)\s*(alert|warning|notice)", "google_impersonation"),
    (r"your\s*package\s*(could not|failed)\s*(be\s*)?(delivered|arrive)", "delivery_scam"),
    (r"tax\s*(refund|return|rebate)|irs\s*(refund|payment)", "tax_scam"),
    (r"crypto|bitcoin|wallet|investment\s*opportunity|guaranteed\s*return", "crypto_scam"),
]

TREND_LABELS = {
    "microsoft_365":              "⚠️ Matches 2024–2026 Microsoft 365/O365 credential harvesting kit pattern",
    "paypal_clone":               "⚠️ Possible PayPal phishing clone (PayPal mentioned, non-paypal.com domain)",
    "apple_id":                   "⚠️ Matches Apple ID / iCloud phishing pattern",
    "generic_credential_harvest": "⚠️ Matches generic credential-harvesting kit (identity verification lure)",
    "known_phishing_framework":   "🚨 References known phishing framework (Evilginx/Modlishka/GoPhish)",
    "amazon_impersonation":       "⚠️ Matches Amazon impersonation pattern (order/prime scam)",
    "google_impersonation":       "⚠️ Matches Google account phishing pattern",
    "delivery_scam":              "⚠️ Matches parcel/delivery failure scam (FedEx/DHL/USPS lure)",
    "tax_scam":                   "⚠️ Matches IRS/HMRC tax refund scam pattern",
    "crypto_scam":                "⚠️ Matches cryptocurrency/investment scam pattern",
}


def _spacy_summarize(text: str) -> str:
    """Extractive summary using spaCy (top sentences by entity density)."""
    try:
        import spacy
        try:
            nlp = spacy.load("en_core_web_sm")
        except OSError:
            return _rule_summarize(text)
        doc = nlp(text[:5000])
        sentences = [s.text.strip() for s in doc.sents if len(s.text.strip()) > 30]
        if not sentences:
            return _rule_summarize(text)
        # Score sentences by named-entity density
        scored = []
        for s in sentences:
            sdoc  = nlp(s)
            score = len(sdoc.ents) + (1 if any(t.is_alpha for t in sdoc) else 0)
            scored.append((score, s))
        scored.sort(reverse=True)
        top = [s for _, s in scored[:2]]
        summary = " ".join(top)[:400]
        return f"This email is regarding: {summary.strip()}"
    except Exception:
        return _rule_summarize(text)


def _transformers_summarize(text: str) -> str:
    """Abstractive summary using transformers (facebook/bart-large-cnn)."""
    try:
        from transformers import pipeline
        summarizer = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6",
                              max_length=80, min_length=20, truncation=True)
        chunk = text[:1024]
        result = summarizer(chunk, do_sample=False)
        raw = result[0]["summary_text"]
        return f"This email is regarding: {raw.strip()}"
    except Exception:
        return _spacy_summarize(text)


def _rule_summarize(text: str) -> str:
    """Fallback rule-based summary (first non-trivial sentence)."""
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    for s in sentences:
        s = s.strip()
        if len(s) > 40 and not s.startswith("http"):
            return f"This email is regarding: {s[:300]}"
    return "This email is regarding: (content could not be summarized automatically)"


def analyze_content(parsed: dict[str, Any], engine: str = "spaCy (fast, local)") -> dict[str, Any]:
    text = parsed.get("plain_text", "") or ""
    text_lower = text.lower()

    # ── Summary ───────────────────────────────────────────────────────────────
    if "transformers" in engine.lower():
        summary = _transformers_summarize(text)
    else:
        summary = _spacy_summarize(text)

    # ── Phishing indicators ───────────────────────────────────────────────────
    indicators: list[str] = []

    def _flag(patterns: list[str], label: str):
        for pat in patterns:
            if re.search(pat, text_lower):
                if label not in indicators:
                    indicators.append(label)
                return

    _flag(URGENCY_PATTERNS,    "🕐 Urgency tactics detected (pressure to act quickly)")
    _flag(THREAT_PATTERNS,     "🔒 Threat language detected (account suspension / legal action)")
    _flag(CREDENTIAL_PATTERNS, "🔑 Credential harvesting language (asking for passwords / login)")
    _flag(GENERIC_GREETING,    "👤 Generic greeting used (not personalised — mass phishing indicator)")

    # Brand impersonation check
    for brand in BRAND_IMPERSONATION:
        if brand in text_lower:
            from_domain = parsed.get("headers", {}).get("From", "")
            safe_domain = brand.replace(" ", "").replace("/x", "") + ".com"
            if safe_domain not in from_domain.lower():
                indicators.append(f"🏷️ Brand impersonation: '{brand}' mentioned but email not from official domain")
            break  # only flag once

    # Grammar / spelling heuristic (high punctuation noise)
    if text:
        excl = text.count("!") / max(len(text) / 100, 1)
        if excl > 3:
            indicators.append("❗ Excessive exclamation marks — aggressive urgency tactic")

    # Long URLs in text
    url_count = len(re.findall(r"https?://", text_lower))
    if url_count > 8:
        indicators.append(f"🔗 Unusually high number of links ({url_count}) in email body")

    # HTML-only (no plain text) — common in phishing
    if parsed.get("html_body") and not parsed.get("plain_text", "").strip():
        indicators.append("📄 Email has HTML body but no plain-text alternative — common in phishing kits")

    # ── Trend / kit matching ──────────────────────────────────────────────────
    trend_matches: list[str] = []
    html_text = parsed.get("html_body", "") or ""
    combined  = (text_lower + " " + html_text.lower())[:20000]

    for pat, label in PHISHING_KIT_PATTERNS:
        if re.search(pat, combined, re.IGNORECASE):
            friendly = TREND_LABELS.get(label, label)
            if friendly not in trend_matches:
                trend_matches.append(friendly)

    return {
        "summary":      summary,
        "indicators":   indicators,
        "trend_matches": trend_matches,
    }
