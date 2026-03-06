#!/usr/bin/env bash
# ============================================================
#  NetGuard — Build script for Linux / macOS
#  Produces:  dist/NetGuard/NetGuard   (ELF binary)
# ============================================================
#
# Prerequisites:
#   pip install -r requirements.txt
#   sudo / CAP_NET_RAW is required at RUNTIME for packet capture,
#   but not needed during the build itself.
#
# Usage:
#   bash build.sh
#
# The finished binary will be at:
#   dist/NetGuard/NetGuard
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "============================================================"
echo " NetGuard Build (Linux / macOS)"
echo "============================================================"
echo ""

# ── Locate Python ─────────────────────────────────────────────────────────────
PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" --version 2>&1)
        echo " Python: $ver"
        PYTHON_CMD="$cmd"
        break
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "[ERROR] Python 3.10+ is required but could not be found."
    echo "Install it with your package manager, e.g.:"
    echo "  sudo apt install python3 python3-pip   (Debian / Ubuntu)"
    exit 1
fi
echo ""

# ── Ensure PyInstaller is available ──────────────────────────────────────────
echo " [1/3] Checking PyInstaller..."
if ! "$PYTHON_CMD" -m PyInstaller --version &>/dev/null; then
    echo "  Installing PyInstaller..."
    "$PYTHON_CMD" -m pip install "pyinstaller>=6.0"
fi
echo "  PyInstaller OK."
echo ""

# ── Ensure app dependencies are installed ────────────────────────────────────
echo " [2/3] Checking application dependencies..."
"$PYTHON_CMD" -m pip install -r requirements.txt --quiet
echo "  Dependencies OK."
echo ""

# ── Run PyInstaller ──────────────────────────────────────────────────────────
echo " [3/3] Building with PyInstaller (this may take 1–3 minutes)..."
echo ""
"$PYTHON_CMD" -m PyInstaller NetGuard.spec --noconfirm

echo ""
echo "============================================================"
echo " Build complete!"
echo ""
echo " Binary:  dist/NetGuard/NetGuard"
echo ""
echo " To run NetGuard:"
echo "   sudo dist/NetGuard/NetGuard"
echo "   (root / CAP_NET_RAW required for packet capture)"
echo "============================================================"
echo ""
