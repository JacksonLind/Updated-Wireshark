# -*- mode: python ; coding: utf-8 -*-
"""
NetGuard.spec — PyInstaller build specification
================================================

Build the Windows executable with:

    pip install pyinstaller
    pyinstaller NetGuard.spec

Or simply run:

    build.bat        (Windows)
    bash build.sh    (Linux / macOS)

Output:
    dist/NetGuard/NetGuard.exe   (Windows)
    dist/NetGuard/NetGuard       (Linux / macOS)
"""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# ── Collect Scapy data files and hidden imports ────────────────────────────────
scapy_datas   = collect_data_files("scapy")
scapy_hiddens = collect_submodules("scapy")

# ── Application data files to bundle ─────────────────────────────────────────
# Tuple format: (source_path, destination_folder_inside_bundle)
app_datas = [
    ("docs/USER_GUIDE.md", "docs"),
    ("samples",            "samples"),
]

# ── Analysis ──────────────────────────────────────────────────────────────────
a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[],
    datas=app_datas + scapy_datas,
    hiddenimports=scapy_hiddens + [
        # Scapy layers that are loaded on demand
        "scapy.layers.l2",
        "scapy.layers.inet",
        "scapy.layers.inet6",
        "scapy.layers.dns",
        "scapy.layers.http",
        "scapy.packet",
        "scapy.utils",
        "scapy.arch",
        "scapy.arch.windows",
        # PyQt5 modules
        "PyQt5.sip",
        "PyQt5.QtCore",
        "PyQt5.QtGui",
        "PyQt5.QtWidgets",
        # Our own package (usually auto-discovered, listed here as a safety net)
        "src",
        "src.core",
        "src.core.capture_engine",
        "src.core.ids_engine",
        "src.core.analyzer",
        "src.core.connections",
        "src.gui",
        "src.gui.main_window",
        "src.gui.capture_tab",
        "src.gui.alerts_tab",
        "src.gui.stats_tab",
        "src.gui.connections_tab",
        "src.gui.detail_panel",
        "src.gui.theme",
        "src.utils",
        "src.utils.helpers",
        "src.utils.resources",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude heavy unused packages to keep the exe smaller
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "IPython",
        "notebook",
        "PIL",
        "wx",
    ],
    noarchive=False,
)

# ── PYZ archive (compiled .pyc files) ────────────────────────────────────────
pyz = PYZ(a.pure, a.zipped_data, cipher=None)

# ── Executable ───────────────────────────────────────────────────────────────
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,   # binaries go into the COLLECT step (one-dir mode)
    name="NetGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,                # compress with UPX if available (reduces exe size)
    console=False,           # no separate console window — GUI-only app
    disable_windowed_traceback=False,
    target_arch=None,        # inherit from build machine (x86-64 on Windows)
    codesign_identity=None,
    entitlements_file=None,
    # icon="netguard.ico",   # place a netguard.ico in the repo root and uncomment to set a custom icon
)

# ── Collect (one-dir output) ──────────────────────────────────────────────────
# Produces dist/NetGuard/  containing NetGuard.exe + all DLLs + data files.
# This is more reliable than --onefile across antivirus scanners.
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="NetGuard",
)
