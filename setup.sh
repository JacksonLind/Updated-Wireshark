#!/usr/bin/env bash
# NetGuard setup script for Linux/macOS

set -e

echo ""
echo "============================================================"
echo " NetGuard — Network Analyzer & IDS — Setup"
echo "============================================================"
echo ""

# Python check
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install Python 3.10+."
    exit 1
fi

echo "[1/2] Installing Python dependencies..."
pip3 install -r requirements.txt

echo ""
echo "[2/2] Done."
echo ""
echo "============================================================"
echo " Run NetGuard with:"
echo "   sudo python3 main.py    (root required for raw sockets)"
echo "============================================================"
echo ""
