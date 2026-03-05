@echo off
REM NetGuard launcher for Windows
REM Requires: Python 3.10+, Npcap, and pip install -r requirements.txt
REM
REM If Windows Smart App Control or Defender SmartScreen blocks this file,
REM run setup.bat first (it unblocks downloaded scripts automatically), or
REM use the PowerShell launcher instead:
REM   Right-click run.ps1 → "Run with PowerShell" (as Administrator)

REM ── Locate Python ──────────────────────────────────────────────────────────
set "PYTHON_CMD="

REM 1) Try 'python' already in PATH
python --version >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=python"
    goto :run
)

REM 2) Try Windows Python Launcher
py -3 --version >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=py -3"
    goto :run
)

REM 3) Search common install directories
powershell -NoProfile -Command ^
  "$dirs = @([System.IO.Path]::Combine($env:LOCALAPPDATA,'Programs\Python'), 'C:\Python312', 'C:\Python311', 'C:\Python310', $env:ProgramFiles, ${env:ProgramFiles(x86)}); $found = $null; foreach ($d in $dirs) { if (Test-Path $d) { $exe = Get-ChildItem -Path $d -Filter python.exe -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'WindowsApps' } | Sort-Object FullName -Descending | Select-Object -First 1; if ($exe) { $found = $exe.DirectoryName; break } } }; if ($found) { $found.Trim() } else { '' }" ^
  > "%TEMP%\_ng_pypath.txt" 2>nul
set /p PYTHON_DIR=<"%TEMP%\_ng_pypath.txt"
del /q "%TEMP%\_ng_pypath.txt" 2>nul

if not "%PYTHON_DIR%"=="" (
    set "PATH=%PYTHON_DIR%;%PYTHON_DIR%\Scripts;%PATH%"
    set "PYTHON_CMD=python"
    goto :run
)

echo.
echo [ERROR] Python 3.10+ is required but could not be found.
echo Run setup.bat first to install Python and all dependencies automatically.
pause
exit /b 1

:run
echo Starting NetGuard...
%PYTHON_CMD% "%~dp0main.py"
if errorlevel 1 (
    echo.
    echo [ERROR] NetGuard exited with an error.
    echo If capture fails, ensure Npcap is installed (https://npcap.com)
    echo and that you are running this as Administrator.
    pause
)
