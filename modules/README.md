# 🛡️ PhishGuard — Open-Source Phishing Email Analyzer

!\[License](https://img.shields.io/badge/license-MIT-blue)
!\[Python](https://img.shields.io/badge/python-3.9%2B-green)
!\[Streamlit](https://img.shields.io/badge/UI-Streamlit-red)

> \*\*For defensive, educational, and security-research use only.\*\*  
> Do not use this tool for malicious purposes.

\---

## What It Does

PhishGuard analyses `.eml` email files and produces a detailed HTML threat report covering:

|Feature|Details|
|-|-|
|**Header Analysis**|SPF, DKIM, DMARC, ARC verification; spoofing detection; WHOIS org lookup|
|**Content Analysis**|NLP-based 3rd-person summary; urgency/threat/credential-harvest detection; phishing kit pattern matching|
|**URL Analysis**|VirusTotal, Google Safe Browsing, URLScan.io; redirect resolution; homoglyph / IP detection|
|**Attachment Scanning**|ClamAV (local) + VirusTotal multi-engine scan|
|**Risk Score**|0–100 weighted score → Green/Yellow/Red verdict|
|**HTML Report**|Professional downloadable report with executive summary|

\---

## Quick Start

### Prerequisites

* Python 3.9+
* Git

### 1\. Clone \& Install

```bash
git clone https://github.com/iamnotprashant/phishguard.git
cd phishguard
bash setup.sh
source .venv/bin/activate
```

### 2\. Run

```bash
streamlit run app.py
```

Open http://localhost:8501 in your browser.

\---

## Step-by-Step CMD Guide (Windows)

```cmd
REM 1. Open Command Prompt as normal user
REM 2. Check Python is installed
python --version

REM 3. Clone the repo (or download ZIP and extract)
git clone https://github.com/yourusername/phishguard.git
cd phishguard

REM 4. Create virtual environment
python -m venv .venv

REM 5. Activate it
.venv\\Scripts\\activate

REM 6. Upgrade pip
python -m pip install --upgrade pip

REM 7. Install dependencies
pip install -r requirements.txt

REM 8. Download spaCy model
python -m spacy download en\_core\_web\_sm

REM 9. Run the app
streamlit run app.py
```

\---

## API Keys (all free)

|API|Where to get|Used for|
|-|-|-|
|VirusTotal|https://www.virustotal.com/gui/join-us|URL + file scanning|
|Google Safe Browsing|https://console.cloud.google.com → APIs → Safe Browsing|URL reputation|
|URLScan.io|https://urlscan.io/user/signup|URL history lookup|

Enter keys in the sidebar — they are **never logged or stored**.

\---

## ClamAV Setup (optional, for local attachment scanning)

**Ubuntu/Debian:**

```bash
sudo apt install clamav clamav-daemon
sudo systemctl enable --now clamav-freshclam
sudo systemctl enable --now clamav-daemon
```

**macOS (Homebrew):**

```bash
brew install clamav
sudo freshclam
```

**Windows:** Download the installer from https://www.clamav.net/downloads  
Then enable the **ClamAV** toggle in the PhishGuard sidebar.

\---

## Free Deployment (Streamlit Community Cloud)

1. Push this repo to GitHub (keep API keys out of the repo!)
2. Go to https://share.streamlit.io → "New app"
3. Select your repo / `app.py`
4. Add secrets in the Streamlit Cloud dashboard:

```toml
   VT\_KEY = "your\_key"
   GSB\_KEY = "your\_key"
   ```

5. Click Deploy

\---

## Project Structure

```
phishguard/
├── app.py                    # Streamlit UI entry point
├── requirements.txt
├── setup.sh
├── sample\_phishing.eml       # Test email
├── .streamlit/
│   └── config.toml
└── modules/
    ├── email\_parser.py       # .eml parsing
    ├── header\_analyzer.py    # SPF/DKIM/DMARC + WHOIS
    ├── content\_analyzer.py   # NLP + phishing indicators
    ├── url\_analyzer.py       # VT / GSB / URLScan
    ├── attachment\_analyzer.py# ClamAV + VT file scan
    ├── risk\_scorer.py        # Weighted 0–100 score
    └── report\_generator.py   # HTML report
```

\---

## Extending PhishGuard

* **Add PhishTank checks** → `modules/url\_analyzer.py`: add `\_check\_phishtank(url)`
* **Add PDF export** → install `weasyprint`, call `weasyprint.HTML(string=html).write\_pdf()`
* **Add MISP integration** → query your MISP instance in `url\_analyzer.py`
* **Custom NLP models** → swap model in `content\_analyzer.py`

\---

## Disclaimer

This tool is provided **for defensive, educational, and security research purposes only**.  
The authors are not responsible for misuse. Malicious use is prohibited.  
URLs and files are submitted to third-party APIs (VirusTotal, Google) — do not upload sensitive personal data.

## License

MIT © 2026 PhishGuard Contributors

