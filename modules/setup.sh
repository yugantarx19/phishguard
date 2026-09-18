#!/usr/bin/env bash
# setup.sh – One-shot environment setup for PhishGuard
# Usage: bash setup.sh
set -e

echo "==========================================="
echo " PhishGuard Setup"
echo "==========================================="

# Python check
python3 --version || { echo "ERROR: Python 3.9+ required"; exit 1; }

# Virtualenv
if [ ! -d ".venv" ]; then
    echo "[1/5] Creating virtual environment..."
    python3 -m venv .venv
fi

echo "[2/5] Activating virtual environment..."
source .venv/bin/activate

echo "[3/5] Upgrading pip..."
pip install --upgrade pip -q

echo "[4/5] Installing Python dependencies..."
pip install -r requirements.txt -q

echo "[5/5] Downloading spaCy language model..."
python -m spacy download en_core_web_sm

echo ""
echo "==========================================="
echo " Optional: Install ClamAV (Linux/macOS)"
echo "==========================================="
echo " Ubuntu/Debian : sudo apt install clamav clamav-daemon && sudo freshclam"
echo " macOS         : brew install clamav && freshclam"
echo " Windows       : https://www.clamav.net/downloads"
echo ""
echo "==========================================="
echo " Setup complete! Run the app with:"
echo "   source .venv/bin/activate"
echo "   streamlit run app.py"
echo "==========================================="
