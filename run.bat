@echo off
REM NetGuard launcher for Windows
REM Requires: Python 3.10+, Npcap, and pip install -r requirements.txt

echo Starting NetGuard...
python main.py
if errorlevel 1 (
    echo.
    echo [ERROR] NetGuard exited with an error.
    echo If capture fails, ensure Npcap is installed (https://npcap.com)
    echo and that you are running this as Administrator.
    pause
)
