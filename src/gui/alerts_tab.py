"""
IDS Alerts tab for NetGuard.

Real-time table of intrusion-detection alerts, colour-coded by severity.
"""

from __future__ import annotations

import time
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QPushButton, QAbstractItemView,
    QComboBox,
)

from src.gui.theme import SEVERITY_PALETTE, BG_PANEL, TEXT_DIM, BORDER, ACCENT
from src.core.ids_engine import IDSAlert
from src.utils.helpers import format_timestamp

COLUMNS = [
    ("#",         40,  Qt.AlignRight),
    ("Time",      90,  Qt.AlignLeft),
    ("Severity",  80,  Qt.AlignCenter),
    ("Category",  130, Qt.AlignLeft),
    ("Source IP", 130, Qt.AlignLeft),
    ("Dest IP",   130, Qt.AlignLeft),
    ("Description", 400, Qt.AlignLeft),
]


class AlertsTab(QWidget):
    """Displays IDS alerts in real-time."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._alerts: list[IDSAlert] = []
        self._build_ui()

    # ── Public API ─────────────────────────────────────────────────────────

    def add_alert(self, alert: IDSAlert) -> None:
        self._alerts.append(alert)
        if not self._passes_filter(alert):
            return
        self._append_row(alert)
        self._count_label.setText(f"{len(self._alerts):,} alerts")

    def clear(self) -> None:
        self._alerts.clear()
        self._table.setRowCount(0)
        self._count_label.setText("0 alerts")

    # ── UI ─────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Controls bar
        bar = QWidget()
        bar.setFixedHeight(52)
        bar.setStyleSheet(f"background:{BG_PANEL}; border-bottom:1px solid {BORDER};")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(12, 8, 12, 8)
        bar_layout.setSpacing(8)

        bar_layout.addWidget(QLabel("Severity:"))
        self._sev_filter = QComboBox()
        self._sev_filter.addItems(
            ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        )
        self._sev_filter.currentTextChanged.connect(self._apply_filter)
        bar_layout.addWidget(self._sev_filter)

        bar_layout.addSpacing(16)
        bar_layout.addWidget(QLabel("Category:"))
        self._cat_filter = QComboBox()
        self._cat_filter.addItems([
            "All", "Port Scan", "SYN Flood", "ICMP Flood", "ARP Spoofing",
            "DNS Tunneling", "Brute Force", "NULL Scan", "XMAS Scan",
            "Large Packet", "SQL Injection", "XSS Attempt",
        ])
        self._cat_filter.currentTextChanged.connect(self._apply_filter)
        bar_layout.addWidget(self._cat_filter)

        bar_layout.addStretch()

        self._count_label = QLabel("0 alerts")
        self._count_label.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        bar_layout.addWidget(self._count_label)

        clear_btn = QPushButton("Clear")
        clear_btn.setProperty("secondary", "true")
        clear_btn.setFixedWidth(70)
        clear_btn.clicked.connect(self.clear)
        bar_layout.addWidget(clear_btn)

        outer.addWidget(bar)

        # Alerts table
        self._table = QTableWidget()
        self._table.setColumnCount(len(COLUMNS))
        self._table.setHorizontalHeaderLabels([c[0] for c in COLUMNS])
        self._table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        for i, (_, w, _) in enumerate(COLUMNS):
            if i != 6:
                self._table.setColumnWidth(i, w)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(False)
        self._table.verticalHeader().setDefaultSectionSize(24)

        # Expand last column
        self._table.horizontalHeader().setStretchLastSection(True)
        outer.addWidget(self._table, 1)

        # Bottom info strip
        info_bar = QLabel(
            "  ⚠  Alerts are raised in real-time as suspicious patterns are detected. "
            "Click a row for details."
        )
        info_bar.setFixedHeight(26)
        info_bar.setStyleSheet(
            f"background:{BG_PANEL}; color:{TEXT_DIM}; font-size:11px; "
            f"border-top:1px solid {BORDER};"
        )
        outer.addWidget(info_bar)

    # ── Private ─────────────────────────────────────────────────────────────

    def _append_row(self, alert: IDSAlert) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)

        sev_color = QColor(SEVERITY_PALETTE.get(alert.severity, "#ccc"))

        values = [
            str(alert.alert_id),
            format_timestamp(alert.timestamp),
            alert.severity,
            alert.category,
            alert.src_ip,
            alert.dst_ip,
            alert.description,
        ]
        aligns = [c[2] for c in COLUMNS]

        for col, (val, align) in enumerate(zip(values, aligns)):
            item = QTableWidgetItem(val)
            item.setTextAlignment(align | Qt.AlignVCenter)
            if col == 2:  # Severity badge
                item.setForeground(sev_color)
                f = QFont()
                f.setBold(True)
                item.setFont(f)
            elif col == 3:  # Category
                item.setForeground(QColor(ACCENT))
            else:
                item.setForeground(QColor("#e0e0e0"))
            self._table.setItem(row, col, item)

        self._table.scrollToBottom()

    def _passes_filter(self, alert: IDSAlert) -> bool:
        sev = self._sev_filter.currentText()
        if sev != "All" and alert.severity != sev:
            return False
        cat = self._cat_filter.currentText()
        if cat != "All" and alert.category != cat:
            return False
        return True

    def _apply_filter(self) -> None:
        self._table.setRowCount(0)
        for alert in self._alerts:
            if self._passes_filter(alert):
                self._append_row(alert)
