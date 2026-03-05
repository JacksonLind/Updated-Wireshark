# NetGuard launcher for Windows (PowerShell)
# -----------------------------------------------------------------------
# Use this script if Windows Smart App Control or Defender SmartScreen
# blocks run.bat.  PowerShell scripts run inside the already-trusted
# powershell.exe process, so they are not subject to the same reputation
# checks that apply to standalone .exe or .bat files.
#
# How to run:
#   1. Open PowerShell as Administrator (right-click → Run as administrator)
#   2. Navigate to this folder:
#         cd "C:\path\to\NetGuard"
#   3. Allow script execution for this session (if required):
#         Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   4. Launch NetGuard:
#         .\run.ps1
# -----------------------------------------------------------------------

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  NetGuard — Network Analyzer & IDS" -ForegroundColor Cyan
Write-Host "  -----------------------------------" -ForegroundColor DarkGray
Write-Host ""

# Verify Python is available
try {
    $pyVersion = & python --version 2>&1
    Write-Host "  Python: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Python not found.  Install Python 3.10+ from https://python.org" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "  Starting NetGuard..." -ForegroundColor Cyan
Write-Host ""

# Launch the application
try {
    & python "$PSScriptRoot\main.py"
} catch {
    Write-Host ""
    Write-Host "  [ERROR] NetGuard exited with an error:" -ForegroundColor Red
    Write-Host "  $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Common fixes:" -ForegroundColor Yellow
    Write-Host "    - Install Npcap (https://npcap.com) for packet capture on Windows." -ForegroundColor Yellow
    Write-Host "    - Run this script as Administrator." -ForegroundColor Yellow
    Write-Host "    - Run 'pip install -r requirements.txt' to install dependencies." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}
