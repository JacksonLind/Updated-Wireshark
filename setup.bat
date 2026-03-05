@echo off
REM NetGuard Setup Script for Windows 11
REM Run this once to install all dependencies.
REM Python is located (or installed automatically) — no manual steps required.

echo.
echo ============================================================
echo  NetGuard — Network Analyzer ^& IDS — Setup
echo ============================================================
echo.

REM ── Smart App Control / Mark-of-the-Web ────────────────────────────────────
REM Files downloaded from the internet may be blocked by Windows Smart App
REM Control or Defender SmartScreen.  The line below uses PowerShell's
REM Unblock-File to remove the Zone.Identifier stream from all scripts in
REM this folder so they run without prompts.
echo  [0/3] Unblocking downloaded scripts (removes Mark-of-the-Web)...
powershell -NoProfile -Command ^
  "Get-ChildItem -Path '%~dp0' -Include *.bat,*.ps1,*.py -Recurse | Unblock-File -ErrorAction SilentlyContinue"
echo        Done.
echo.

REM ── Locate or auto-install Python ──────────────────────────────────────────
echo  [1/3] Locating Python...
set "PYTHON_CMD="

REM 1) Try 'python' already in PATH
python --version >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=python"
    goto :have_python
)

REM 2) Try the Windows Python Launcher 'py' (installed even when Python is not in PATH)
py -3 --version >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=py -3"
    goto :have_python
)

REM 3) Search common installation directories via PowerShell
echo  Python not found in PATH — searching common install locations...
call :find_python
if not "%PYTHON_DIR%"=="" (
    echo  Found Python at: %PYTHON_DIR%
    set "PATH=%PYTHON_DIR%;%PYTHON_DIR%\Scripts;%PATH%"
    set "PYTHON_CMD=python"
    goto :have_python
)

REM 4) Auto-install Python via winget (built into Windows 10/11 with App Installer)
echo  Python not found — attempting automatic installation...
winget --version >nul 2>&1
if not errorlevel 1 (
    echo  Installing Python 3.12 via Windows Package Manager ^(winget^)...
    winget install --id Python.Python.3.12 --source winget --accept-package-agreements --accept-source-agreements --silent
    if not errorlevel 1 goto :find_after_install
    echo  winget install failed — falling back to direct download...
) else (
    echo  winget not available — falling back to direct download...
)

REM 5) Download the installer directly from python.org
echo  Downloading Python 3.12 installer from https://python.org ...
powershell -NoProfile -Command ^
  "try { Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe' -OutFile ([System.IO.Path]::Combine($env:TEMP,'python_installer.exe')) -UseBasicParsing; exit 0 } catch { Write-Host ('Download failed: ' + $_.Exception.Message); exit 1 }"
if errorlevel 1 (
    echo.
    echo  [ERROR] Could not download Python automatically.
    echo  Please install Python 3.10+ manually from https://python.org
    echo  and run this script again.
    pause
    exit /b 1
)
echo  Running Python installer (this may take a minute^)...
"%TEMP%\python_installer.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_test=0
del /q "%TEMP%\python_installer.exe" 2>nul

:find_after_install
REM Re-scan for Python after the installation completes
call :find_python

if not "%PYTHON_DIR%"=="" (
    set "PATH=%PYTHON_DIR%;%PYTHON_DIR%\Scripts;%PATH%"
    set "PYTHON_CMD=python"
    goto :have_python
)

echo.
echo  [ERROR] Python installation did not complete successfully.
echo  Please restart this script, or install Python 3.10+ from https://python.org
pause
exit /b 1

:have_python
echo  Python found:
%PYTHON_CMD% --version
echo.

echo  [2/3] Installing Python dependencies...
%PYTHON_CMD% -m pip install -r "%~dp0requirements.txt"

if errorlevel 1 (
    echo.
    echo  [ERROR] Failed to install dependencies. Check the errors above.
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
echo    run.bat          (Command Prompt)
echo    .\run.ps1        (PowerShell — preferred if Smart App Control blocks run.bat)
echo.
pause

REM ── Subroutines ────────────────────────────────────────────────────────────
:find_python
REM Searches common Python install locations and sets PYTHON_DIR to the
REM directory containing python.exe, or empty string if not found.
set "PYTHON_DIR="
powershell -NoProfile -Command ^
  "$dirs = @([System.IO.Path]::Combine($env:LOCALAPPDATA,'Programs\Python'), 'C:\Python312', 'C:\Python311', 'C:\Python310', $env:ProgramFiles, ${env:ProgramFiles(x86)}); $found = $null; foreach ($d in $dirs) { if (Test-Path $d) { $exe = Get-ChildItem -Path $d -Filter python.exe -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'WindowsApps' } | Sort-Object FullName -Descending | Select-Object -First 1; if ($exe) { $found = $exe.DirectoryName; break } } }; if ($found) { $found.Trim() } else { '' }" ^
  > "%TEMP%\_ng_pypath.txt" 2>nul
set /p PYTHON_DIR=<"%TEMP%\_ng_pypath.txt"
del /q "%TEMP%\_ng_pypath.txt" 2>nul
goto :eof
