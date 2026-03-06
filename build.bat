@echo off
REM ============================================================
REM  NetGuard — Build script for Windows
REM  Produces:  dist\NetGuard\NetGuard.exe
REM ============================================================
REM
REM Prerequisites (run setup.bat first if you haven't already):
REM   * Python 3.10+
REM   * pip install -r requirements.txt
REM   * Npcap (https://npcap.com) must be installed on the TARGET machine;
REM     it cannot be bundled inside the exe.
REM
REM Usage:
REM   build.bat
REM
REM The finished executable will be at:
REM   dist\NetGuard\NetGuard.exe
REM ============================================================

echo.
echo ============================================================
echo  NetGuard Build
echo ============================================================
echo.

REM ── Locate Python ──────────────────────────────────────────────────────────
set "PYTHON_CMD="

python --version >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=python"
    goto :have_python
)

py -3 --version >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=py -3"
    goto :have_python
)

echo [ERROR] Python 3.10+ is required but could not be found.
echo Run setup.bat first to install Python and all dependencies.
pause
exit /b 1

:have_python
echo  Python: 
%PYTHON_CMD% --version
echo.

REM ── Ensure PyInstaller is available ───────────────────────────────────────
%PYTHON_CMD% -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo  [1/3] Installing PyInstaller...
    %PYTHON_CMD% -m pip install "pyinstaller>=6.0"
    if errorlevel 1 (
        echo.
        echo  [ERROR] Failed to install PyInstaller.
        pause
        exit /b 1
    )
) else (
    echo  [1/3] PyInstaller already installed.
)
echo.

REM ── Ensure app dependencies are installed ─────────────────────────────────
echo  [2/3] Checking application dependencies...
%PYTHON_CMD% -m pip install -r "%~dp0requirements.txt" --quiet
if errorlevel 1 (
    echo.
    echo  [ERROR] Failed to install dependencies from requirements.txt.
    pause
    exit /b 1
)
echo  Dependencies OK.
echo.

REM ── Run PyInstaller ───────────────────────────────────────────────────────
echo  [3/3] Building NetGuard.exe with PyInstaller...
echo         (this may take 1–3 minutes)
echo.

cd /d "%~dp0"
%PYTHON_CMD% -m PyInstaller NetGuard.spec --noconfirm

if errorlevel 1 (
    echo.
    echo  [ERROR] PyInstaller build failed.  See the output above for details.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  Build complete!
echo.
echo  Executable:  dist\NetGuard\NetGuard.exe
echo.
echo  To run NetGuard on another machine:
echo    1. Copy the entire dist\NetGuard\ folder.
echo    2. Ensure Npcap is installed on the target machine.
echo       Download: https://npcap.com/#download
echo       Install with "WinPcap API-compatible Mode" enabled.
echo    3. Run NetGuard.exe (as Administrator for packet capture).
echo ============================================================
echo.
pause
