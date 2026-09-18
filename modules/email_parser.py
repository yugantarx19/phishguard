"""
email_parser.py – Parse .eml files into structured data.
"""
import email
import email.policy
import re
import quopri
import base64
from email import message_from_bytes
from bs4 import BeautifulSoup
from typing import Any


URL_RE = re.compile(
    r'https?://[^\s<>"\')\],;{}|\\^`\x00-\x1f]+',
    re.IGNORECASE,
)


def _decode_payload(part) -> str:
    """Safely decode a message part payload to string."""
    charset = part.get_content_charset() or "utf-8"
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def _extract_urls(text: str, html: str) -> list[str]:
    urls: set[str] = set()
    # From plain text
    for u in URL_RE.findall(text):
        urls.add(u.rstrip(".,)>;\"'"))
    # From HTML hrefs / src attributes
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(href=True):
            href = tag["href"].strip()
            if href.startswith("http"):
                urls.add(href.rstrip(".,)>;\"'"))
        for tag in soup.find_all(src=True):
            src = tag["src"].strip()
            if src.startswith("http"):
                urls.add(src.rstrip(".,)>;\"'"))
    return sorted(urls)


def parse_eml(raw_bytes: bytes) -> dict[str, Any]:
    """Parse raw .eml bytes and return structured dict."""
    msg = message_from_bytes(raw_bytes, policy=email.policy.compat32)

    # ── Headers ──────────────────────────────────────────────────────────────
    headers: dict[str, str] = {}
    for key in msg.keys():
        if key not in headers:
            headers[key] = str(msg[key])

    # ── Body parts ───────────────────────────────────────────────────────────
    plain_text = ""
    html_body  = ""
    attachments: list[dict] = []

    for part in msg.walk():
        ctype   = part.get_content_type()
        disp    = str(part.get("Content-Disposition", ""))
        fname   = part.get_filename()

        if fname or "attachment" in disp.lower():
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename":  fname or "unknown",
                "mime_type": ctype,
                "size":      len(payload),
                "size_str":  _human_size(len(payload)),
                "data":      payload,
            })
            continue

        if ctype == "text/plain" and not plain_text:
            plain_text = _decode_payload(part)
        elif ctype == "text/html" and not html_body:
            html_body = _decode_payload(part)

    # ── Text from HTML fallback ───────────────────────────────────────────────
    if html_body and not plain_text:
        soup = BeautifulSoup(html_body, "html.parser")
        plain_text = soup.get_text(separator=" ", strip=True)

    # ── URLs ─────────────────────────────────────────────────────────────────
    urls = _extract_urls(plain_text, html_body)

    return {
        "headers":     headers,
        "subject":     str(msg.get("Subject", "(No subject)")),
        "from":        str(msg.get("From", "")),
        "to":          str(msg.get("To", "")),
        "reply_to":    str(msg.get("Reply-To", "")),
        "date":        str(msg.get("Date", "")),
        "message_id":  str(msg.get("Message-ID", "")),
        "plain_text":  plain_text,
        "html_body":   html_body,
        "attachments": attachments,
        "urls":        urls,
    }


def _human_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
