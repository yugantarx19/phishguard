@'
# PhishGuard - AI-Powered Phishing Email Analyzer

PhishGuard is a defensive security tool that analyzes `.eml` email files to identify potential phishing indicators, suspicious URLs, malicious attachments, and email authentication issues.

It provides a risk assessment and generates a detailed HTML security report.

> For defensive, educational, and security-research purposes only.

---

## Features

- **Email Parsing** - Extracts headers, body content, URLs, and attachments from `.eml` files.
- **Header Analysis** - Examines SPF, DKIM, DMARC, ARC, sender information, and spoofing indicators.
- **Content Analysis** - Detects urgency, threats, credential harvesting, and common phishing patterns.
- **URL Analysis** - Checks URLs for suspicious characteristics and reputation using available security APIs.
- **Attachment Analysis** - Supports local ClamAV scanning and VirusTotal file analysis.
- **Risk Assessment** - Combines detected indicators into a 0-100 risk score.
- **HTML Reports** - Generates a detailed report containing findings and an executive summary.
- **Streamlit Interface** - Simple browser-based interface for analyzing emails.

---

## Tech Stack

- Python
- Streamlit
- BeautifulSoup4
- Requests
- Pandas
- spaCy
- Python-WHOIS
- VirusTotal API
- Google Safe Browsing API
- URLScan.io
- ClamAV

---

## Project Structure

```text
phishguard/
|
|-- app.py
|-- requirements.txt
|-- setup.sh
|-- sample_phishing.eml
|-- README.md
|-- .gitignore
|
`-- modules/
    |-- __init__.py
    |-- email_parser.py
    |-- header_analyzer.py
    |-- content_analyzer.py
    |-- url_analyzer.py
    |-- attachment_analyzer.py
    |-- risk_scorer.py
    `-- report_generator.py