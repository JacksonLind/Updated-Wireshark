"""
Resource-path helper for NetGuard.

When the app is frozen by PyInstaller (sys.frozen == True) all bundled
data files are extracted to a temporary directory stored in sys._MEIPASS.
This helper resolves paths to those files correctly whether the app is
running from source or from a compiled executable.

Usage
-----
    from src.utils.resources import resource_path
    guide = resource_path("docs/USER_GUIDE.md")
"""

from __future__ import annotations

import sys
from pathlib import Path


def resource_path(relative: str) -> Path:
    """
    Return the absolute path to a bundled resource.

    When running from source the path is resolved relative to the repo root
    (the directory that contains main.py).  When running as a PyInstaller
    bundle the path is resolved relative to sys._MEIPASS, which is the
    temporary directory where PyInstaller extracts bundled files.

    Parameters
    ----------
    relative : str
        Path relative to the application root, e.g. ``"docs/USER_GUIDE.md"``.

    Returns
    -------
    pathlib.Path
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        # Running inside a PyInstaller bundle
        base = Path(sys._MEIPASS)
    else:
        # Running from source — base is the repo root (parent of src/)
        base = Path(__file__).resolve().parent.parent.parent

    return base / relative
