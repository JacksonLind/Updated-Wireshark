@echo off
REM NetGuard Setup Script for Windows 11
REM Run this once to install all dependencies.

echo.
echo ============================================================
echo  NetGuard — Network Analyzer ^& IDS — Setup
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo  Please download Python 3.10+ from https://python.org
    pause
    exit /b 1
)

echo  [1/3] Checking Python version...
python --version

echo.
echo  [2/3] Installing Python dependencies...
pip install -r requirements.txt

if errorlevel 1 (
    echo  [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo  [3/3] Dependency check complete.
echo.
echo ============================================================
echo  IMPORTANT: Npcap must be installed for packet capture.
echo  Download from: https://npcap.com/#download
echo  Install with "WinPcap API-compatible Mode" enabled.
echo ============================================================
echo.
echo  Setup complete! Run NetGuard with:
echo    run.bat
echo.
pause
