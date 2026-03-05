@echo off
REM NetGuard launcher for Windows
REM Requires: Python 3.10+, Npcap, and pip install -r requirements.txt
REM
REM If Windows Smart App Control or Defender SmartScreen blocks this file,
REM run setup.bat first (it unblocks downloaded scripts automatically), or
REM use the PowerShell launcher instead:
REM   Right-click run.ps1 → "Run with PowerShell" (as Administrator)

echo Starting NetGuard...
python main.py
if errorlevel 1 (
    echo.
    echo [ERROR] NetGuard exited with an error.
    echo If capture fails, ensure Npcap is installed (https://npcap.com)
    echo and that you are running this as Administrator.
    pause
)
