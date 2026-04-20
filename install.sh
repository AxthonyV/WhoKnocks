#!/usr/bin/env bash
# Quick Installer 
set -e

echo ""
echo "  WhoKnocks — Incoming Connection Monitor"
echo "  ────────────────────────────────────────"
echo ""

if ! command -v python3 &>/dev/null; then
    echo "  [!] Python 3 not found. Install Python 3.8+"
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "  [✓] Python $PY_VER detected"

echo "  [*] Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "  [✓] Done"
echo ""
echo "  Run with:"
echo "    sudo python3 whoknocks.py     # sudo recommended for full process visibility"
echo "    python3 whoknocks.py          # works without sudo (limited process info)"
echo ""
