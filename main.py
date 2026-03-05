#!/usr/bin/env python3
"""
NetGuard — Network Analyzer & Intrusion Detection System
=========================================================
Entry point.  Run with:
    python main.py
Or on Linux/macOS (needs root for raw packet capture):
    sudo python main.py
"""

import sys
import os

# Allow running from the repo root without installing as a package
sys.path.insert(0, os.path.dirname(__file__))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from src.gui.main_window import MainWindow
from src.gui.theme import apply_theme


def main() -> int:
    # Enable high-DPI scaling on Windows / modern displays
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("NetGuard")
    app.setApplicationDisplayName("NetGuard")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("NetGuard")

    apply_theme(app)

    window = MainWindow()
    window.show()

    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
