"""
Dark, modern stylesheet and palette for NetGuard.

Usage
-----
    from src.gui.theme import apply_theme
    apply_theme(app)         # QApplication
"""

from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

# ── Color tokens ──────────────────────────────────────────────────────────────
BG_DARKEST  = "#0d0d0d"
BG_DARK     = "#141414"
BG_PANEL    = "#1a1a2e"
BG_WIDGET   = "#16213e"
BG_ALT_ROW  = "#0f3460"
ACCENT      = "#e94560"
ACCENT2     = "#533483"
TEXT_MAIN   = "#e0e0e0"
TEXT_DIM    = "#9e9e9e"
TEXT_ACCENT = "#ffffff"
BORDER      = "#2a2a4a"
SEL_BG      = "#e94560"
SEL_FG      = "#ffffff"

SEVERITY_PALETTE = {
    "CRITICAL": "#FF4444",
    "HIGH":     "#FF8800",
    "MEDIUM":   "#FFCC00",
    "LOW":      "#44AAFF",
    "INFO":     "#88CC88",
}

PROTO_PALETTE = {
    "TCP":      "#4fc3f7",
    "UDP":      "#81c784",
    "HTTP":     "#aed581",
    "HTTPS":    "#4db6ac",
    "DNS":      "#ffb74d",
    "DNS/TCP":  "#ffb74d",
    "ICMP":     "#f48fb1",
    "ARP":      "#ce93d8",
    "SSH":      "#80cbc4",
    "SMB":      "#ef9a9a",
    "Unknown":  "#9e9e9e",
}


STYLESHEET = f"""
/* ── Global ─────────────────────────────────────────────────────────────── */
QMainWindow, QDialog {{
    background-color: {BG_DARKEST};
}}

QWidget {{
    background-color: {BG_DARK};
    color: {TEXT_MAIN};
    font-family: "Segoe UI", "Inter", "Helvetica Neue", sans-serif;
    font-size: 13px;
}}

/* ── Menu bar ────────────────────────────────────────────────────────────── */
QMenuBar {{
    background-color: {BG_DARKEST};
    color: {TEXT_MAIN};
    border-bottom: 1px solid {BORDER};
    padding: 2px 0;
}}
QMenuBar::item:selected {{
    background-color: {ACCENT};
    color: {TEXT_ACCENT};
    border-radius: 3px;
}}
QMenu {{
    background-color: {BG_PANEL};
    color: {TEXT_MAIN};
    border: 1px solid {BORDER};
}}
QMenu::item:selected {{
    background-color: {ACCENT};
    color: {TEXT_ACCENT};
}}

/* ── Toolbar ─────────────────────────────────────────────────────────────── */
QToolBar {{
    background-color: {BG_PANEL};
    border-bottom: 1px solid {BORDER};
    spacing: 4px;
    padding: 4px 8px;
}}
QToolButton {{
    background-color: transparent;
    color: {TEXT_MAIN};
    border: none;
    border-radius: 4px;
    padding: 6px 10px;
    font-size: 12px;
}}
QToolButton:hover {{
    background-color: {BG_WIDGET};
    color: {TEXT_ACCENT};
}}
QToolButton:pressed, QToolButton:checked {{
    background-color: {ACCENT};
    color: {TEXT_ACCENT};
}}

/* ── Tab bar ─────────────────────────────────────────────────────────────── */
QTabBar::tab {{
    background-color: {BG_PANEL};
    color: {TEXT_DIM};
    padding: 8px 20px;
    border: none;
    border-bottom: 2px solid transparent;
    margin-right: 2px;
    font-weight: 600;
}}
QTabBar::tab:selected {{
    color: {TEXT_ACCENT};
    border-bottom: 2px solid {ACCENT};
    background-color: {BG_DARK};
}}
QTabBar::tab:hover {{
    color: {TEXT_MAIN};
    background-color: {BG_WIDGET};
}}
QTabWidget::pane {{
    border: 1px solid {BORDER};
    background-color: {BG_DARK};
}}

/* ── Table view ──────────────────────────────────────────────────────────── */
QTableWidget, QTableView {{
    background-color: {BG_DARK};
    alternate-background-color: {BG_PANEL};
    color: {TEXT_MAIN};
    gridline-color: {BORDER};
    border: none;
    selection-background-color: {SEL_BG};
    selection-color: {SEL_FG};
}}
QHeaderView::section {{
    background-color: {BG_PANEL};
    color: {TEXT_DIM};
    padding: 6px 8px;
    border: none;
    border-right: 1px solid {BORDER};
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
QTableWidget::item {{
    padding: 4px 6px;
}}

/* ── Push button ─────────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {ACCENT};
    color: {TEXT_ACCENT};
    border: none;
    border-radius: 5px;
    padding: 7px 18px;
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.5px;
}}
QPushButton:hover {{
    background-color: #ff6b81;
}}
QPushButton:pressed {{
    background-color: #c73652;
}}
QPushButton:disabled {{
    background-color: #555;
    color: #888;
}}

/* ── Secondary button ────────────────────────────────────────────────────── */
QPushButton[secondary="true"] {{
    background-color: {BG_WIDGET};
    color: {TEXT_MAIN};
    border: 1px solid {BORDER};
}}
QPushButton[secondary="true"]:hover {{
    background-color: {BORDER};
}}

/* ── Line edit / search box ──────────────────────────────────────────────── */
QLineEdit {{
    background-color: {BG_PANEL};
    color: {TEXT_MAIN};
    border: 1px solid {BORDER};
    border-radius: 5px;
    padding: 6px 10px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus {{
    border-color: {ACCENT};
}}

/* ── Combo box ───────────────────────────────────────────────────────────── */
QComboBox {{
    background-color: {BG_PANEL};
    color: {TEXT_MAIN};
    border: 1px solid {BORDER};
    border-radius: 5px;
    padding: 5px 10px;
    min-width: 160px;
}}
QComboBox:hover {{
    border-color: {ACCENT};
}}
QComboBox QAbstractItemView {{
    background-color: {BG_PANEL};
    color: {TEXT_MAIN};
    selection-background-color: {ACCENT};
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {TEXT_DIM};
    margin-right: 6px;
}}

/* ── Splitter ─────────────────────────────────────────────────────────────── */
QSplitter::handle {{
    background-color: {BORDER};
}}
QSplitter::handle:horizontal {{
    width: 2px;
}}
QSplitter::handle:vertical {{
    height: 2px;
}}

/* ── Scroll bars ─────────────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: {BG_PANEL};
    width: 8px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background: {ACCENT};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: {BG_PANEL};
    height: 8px;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER};
    border-radius: 4px;
    min-width: 20px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {ACCENT};
}}

/* ── Labels ──────────────────────────────────────────────────────────────── */
QLabel {{
    background: transparent;
}}

/* ── Group box ────────────────────────────────────────────────────────────── */
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 10px;
    color: {TEXT_DIM};
    font-weight: 600;
    font-size: 11px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    top: -1px;
    color: {ACCENT};
}}

/* ── Status bar ──────────────────────────────────────────────────────────── */
QStatusBar {{
    background-color: {BG_DARKEST};
    color: {TEXT_DIM};
    border-top: 1px solid {BORDER};
    font-size: 11px;
}}

/* ── Tree / detail panel ─────────────────────────────────────────────────── */
QTreeWidget {{
    background-color: {BG_DARK};
    color: {TEXT_MAIN};
    border: none;
    alternate-background-color: {BG_PANEL};
}}
QTreeWidget::item:selected {{
    background-color: {SEL_BG};
    color: {SEL_FG};
}}
QTreeWidget::item:hover {{
    background-color: {BG_WIDGET};
}}

/* ── Text edit (packet hex dump) ─────────────────────────────────────────── */
QTextEdit, QPlainTextEdit {{
    background-color: {BG_DARKEST};
    color: #b0bec5;
    border: none;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
}}

/* ── Check box ────────────────────────────────────────────────────────────── */
QCheckBox {{
    spacing: 6px;
}}
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border-radius: 3px;
    border: 1px solid {BORDER};
    background: {BG_PANEL};
}}
QCheckBox::indicator:checked {{
    background: {ACCENT};
    border-color: {ACCENT};
}}

/* ── Tooltip ─────────────────────────────────────────────────────────────── */
QToolTip {{
    background-color: {BG_PANEL};
    color: {TEXT_MAIN};
    border: 1px solid {BORDER};
    padding: 4px 8px;
    border-radius: 4px;
}}
"""


def apply_theme(app: QApplication) -> None:
    """Apply the NetGuard dark theme to a QApplication."""
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window,          QColor(BG_DARK))
    palette.setColor(QPalette.WindowText,      QColor(TEXT_MAIN))
    palette.setColor(QPalette.Base,            QColor(BG_DARKEST))
    palette.setColor(QPalette.AlternateBase,   QColor(BG_PANEL))
    palette.setColor(QPalette.ToolTipBase,     QColor(BG_PANEL))
    palette.setColor(QPalette.ToolTipText,     QColor(TEXT_MAIN))
    palette.setColor(QPalette.Text,            QColor(TEXT_MAIN))
    palette.setColor(QPalette.Button,          QColor(BG_PANEL))
    palette.setColor(QPalette.ButtonText,      QColor(TEXT_MAIN))
    palette.setColor(QPalette.Link,            QColor(ACCENT))
    palette.setColor(QPalette.Highlight,       QColor(ACCENT))
    palette.setColor(QPalette.HighlightedText, QColor(SEL_FG))
    app.setPalette(palette)
    app.setStyleSheet(STYLESHEET)
