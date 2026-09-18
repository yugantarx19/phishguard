"""
attachment_analyzer.py – Scan attachments via ClamAV and/or VirusTotal.
"""
import hashlib
import time
import io
from typing import Any


RISKY_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".reg", ".msi",
    ".dll", ".jar", ".hta", ".iso", ".img", ".lnk", ".docm", ".xlsm",
    ".xlam", ".pptm", ".accde", ".xll", ".vba",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".xlam", ".pptm", ".accde", ".xll"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check_clamav(data: bytes) -> str:
    try:
        import pyclamd
        cd = pyclamd.ClamdUnixSocket()
        result = cd.scan_stream(data)
        if result:
            return f"DETECTED: {list(result.values())[0][1]}"
        return "Clean"
    except Exception as e:
        try:
            import pyclamd
            cd = pyclamd.ClamdNetworkSocket(host="127.0.0.1", port=3310)
            result = cd.scan_stream(data)
            if result:
                return f"DETECTED: {list(result.values())[0][1]}"
            return "Clean"
        except Exception:
            return f"ClamAV unavailable: {str(e)[:60]}"


def _check_vt_file(data: bytes, api_key: str) -> str:
    if not api_key:
        return "No VT key"
    sha = _sha256(data)
    try:
        import vt
        client = vt.Client(api_key)
        try:
            file_obj = client.get_object(f"/files/{sha}")
            stats    = file_obj.last_analysis_stats
            malicious = stats.get("malicious", 0)
            total    = sum(stats.values())
            client.close()
            return f"{'MALICIOUS' if malicious > 2 else 'Clean'} ({malicious}/{total} engines)"
        except Exception:
            # Not found → upload
            analysis = client.scan_file(io.BytesIO(data), size=len(data))
            client.close()
            time.sleep(15)  # wait for analysis
            return "Submitted to VT (check dashboard)"
    except Exception as e:
        return f"VT Error: {str(e)[:60]}"


def analyze_attachments(
    attachments: list[dict],
    vt_key: str = "",
    use_clamav: bool = False,
) -> list[dict[str, Any]]:
    results = []
    for att in attachments:
        fname  = att.get("filename", "unknown")
        data   = att.get("data", b"")
        size   = att.get("size", 0)
        mime   = att.get("mime_type", "application/octet-stream")
        sha    = _sha256(data) if data else "n/a"

        # Extension risk
        import os
        ext    = os.path.splitext(fname)[1].lower()
        flags: list[str] = []
        if ext in RISKY_EXTENSIONS:
            flags.append(f"High-risk file type: {ext}")
        if ext in MACRO_EXTENSIONS:
            flags.append("Office file with macro support — may contain malicious macros")
        if not ext:
            flags.append("No file extension — suspicious")

        # ClamAV
        clam_result = "Not scanned"
        if use_clamav and data:
            clam_result = _check_clamav(data)

        # VirusTotal
        vt_result = "Not scanned"
        if vt_key and data:
            vt_result = _check_vt_file(data, vt_key)

        # Verdict
        is_bad = (
            "DETECTED" in clam_result
            or "MALICIOUS" in vt_result.upper()
        )
        verdict = "🔴 Malicious" if is_bad else ("🟡 Suspicious" if flags else "🟢 Clean")

        results.append({
            "filename":  fname,
            "size":      size,
            "size_str":  att.get("size_str", "?"),
            "mime_type": mime,
            "sha256":    sha,
            "extension": ext,
            "flags":     flags,
            "clamav":    clam_result,
            "vt_result": vt_result,
            "verdict":   verdict,
        })

    return results
