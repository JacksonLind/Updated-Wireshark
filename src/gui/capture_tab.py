"""
Packet Capture tab for NetGuard.

Displays a live scrolling table of captured packets with per-protocol
colour coding, a BPF filter bar, and a detail panel at the bottom.
"""

from __future__ import annotations

import time
from typing import Any

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QPushButton, QLineEdit, QComboBox,
    QAbstractItemView, QCheckBox,
)

from src.gui.theme import PROTO_PALETTE, BG_PANEL, TEXT_DIM, ACCENT, BORDER, BG_DARK
from src.gui.detail_panel import DetailPanel

MAX_ROWS = 5_000   # Cap rows to keep the UI snappy

COLUMNS = [
    ("No.",      50, Qt.AlignRight),
    ("Time",     90, Qt.AlignLeft),
    ("Source IP",130, Qt.AlignLeft),
    ("Dest IP",  130, Qt.AlignLeft),
    ("Protocol", 80,  Qt.AlignCenter),
    ("Length",   70,  Qt.AlignRight),
    ("Info",     350, Qt.AlignLeft),
]


class CaptureTab(QWidget):
    """Live packet capture view."""

    # Emitted when user clicks a row (gives the raw packet info dict)
    packet_selected = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._packets: list[dict] = []
        self._filtered: list[dict] = []
        self._filter_text: str = ""
        self._auto_scroll: bool = True
        self._paused: bool = False

        self._build_ui()

    # ── Public API ─────────────────────────────────────────────────────────

    def add_packet(self, info: dict) -> None:
        """Append a new packet (called from the main window via Qt signal)."""
        if self._paused:
            return
        self._packets.append(info)
        if len(self._packets) > MAX_ROWS:
            self._packets = self._packets[-MAX_ROWS:]

        if self._matches_filter(info):
            self._append_row(info)

    def clear(self) -> None:
        self._packets.clear()
        self._filtered.clear()
        self._table.setRowCount(0)
        self._detail.clear()

    def set_paused(self, paused: bool) -> None:
        self._paused = paused

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Filter / controls bar ──────────────────────────────────────────
        bar = QWidget()
        bar.setFixedHeight(52)
        bar.setStyleSheet(f"background:{BG_PANEL}; border-bottom:1px solid {BORDER};")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(12, 8, 12, 8)
        bar_layout.setSpacing(8)

        bar_layout.addWidget(QLabel("Filter:"))

        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText(
            "e.g.  tcp   |   192.168.1.1   |   dns   |   port 443"
        )
        self._filter_input.setMinimumWidth(300)
        self._filter_input.textChanged.connect(self._apply_filter)
        bar_layout.addWidget(self._filter_input)

        self._proto_filter = QComboBox()
        self._proto_filter.addItems([
            "All Protocols", "TCP", "UDP", "HTTP", "HTTPS",
            "DNS", "ICMP", "ARP", "SSH",
        ])
        self._proto_filter.currentTextChanged.connect(self._apply_filter)
        bar_layout.addWidget(self._proto_filter)

        self._auto_scroll_cb = QCheckBox("Auto-scroll")
        self._auto_scroll_cb.setChecked(True)
        self._auto_scroll_cb.stateChanged.connect(
            lambda s: setattr(self, "_auto_scroll", bool(s))
        )
        bar_layout.addWidget(self._auto_scroll_cb)

        bar_layout.addStretch()

        self._row_label = QLabel("0 packets")
        self._row_label.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        bar_layout.addWidget(self._row_label)

        clear_btn = QPushButton("Clear")
        clear_btn.setProperty("secondary", "true")
        clear_btn.setFixedWidth(70)
        clear_btn.clicked.connect(self.clear)
        bar_layout.addWidget(clear_btn)

        outer.addWidget(bar)

        # ── Splitter: table (top) + detail (bottom) ────────────────────────
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet(f"background:{BG_DARK};")

        self._table = QTableWidget()
        self._table.setColumnCount(len(COLUMNS))
        self._table.setHorizontalHeaderLabels([c[0] for c in COLUMNS])
        self._table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        for i, (_, w, _) in enumerate(COLUMNS):
            if i != 6:
                self._table.setColumnWidth(i, w)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(False)
        self._table.setWordWrap(False)
        self._table.verticalHeader().setDefaultSectionSize(22)
        self._table.currentItemChanged.connect(
            lambda cur, _: self._on_row_selected(cur.row() if cur else -1)
        )

        splitter.addWidget(self._table)

        self._detail = DetailPanel()
        splitter.addWidget(self._detail)

        splitter.setSizes([550, 250])
        outer.addWidget(splitter, 1)

    # ── Private helpers ────────────────────────────────────────────────────

    def _append_row(self, info: dict) -> None:
        from src.utils.helpers import format_timestamp
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._filtered.append(info)

        proto = info.get("protocol", "Unknown")
        color = QColor(PROTO_PALETTE.get(proto, "#9e9e9e"))
        dim = QColor(TEXT_DIM)

        ts = format_timestamp(info.get("timestamp", time.time()))
        values = [
            str(row + 1),
            ts,
            info.get("src_ip", ""),
            info.get("dst_ip", ""),
            proto,
            str(info.get("length", "")),
            info.get("info", ""),
        ]
        aligns = [c[2] for c in COLUMNS]

        for col, (val, align) in enumerate(zip(values, aligns)):
            item = QTableWidgetItem(val)
            item.setTextAlignment(align | Qt.AlignVCenter)
            if col == 4:  # Protocol column gets accent colour
                item.setForeground(color)
                font = QFont()
                font.setBold(True)
                item.setFont(font)
            else:
                item.setForeground(dim if col in (0, 5) else QColor("#e0e0e0"))
            self._table.setItem(row, col, item)

        self._row_label.setText(f"{row + 1:,} packets")

        if self._auto_scroll:
            self._table.scrollToBottom()

    def _apply_filter(self) -> None:
        self._filter_text = self._filter_input.text().lower().strip()
        proto_sel = self._proto_filter.currentText()
        proto_filter = "" if proto_sel == "All Protocols" else proto_sel.upper()

        self._table.setRowCount(0)
        self._filtered.clear()

        for info in self._packets:
            if proto_filter and info.get("protocol", "").upper() != proto_filter:
                continue
            if self._filter_text and not self._matches_filter(info):
                continue
            self._append_row(info)

    def _matches_filter(self, info: dict) -> bool:
        proto_sel = self._proto_filter.currentText()
        if proto_sel != "All Protocols":
            if info.get("protocol", "").upper() != proto_sel.upper():
                return False

        txt = self._filter_text
        if not txt:
            return True

        # Simple keyword matching across key fields
        searchable = " ".join([
            info.get("src_ip", ""),
            info.get("dst_ip", ""),
            info.get("protocol", ""),
            info.get("info", ""),
            str(info.get("src_port", "")),
            str(info.get("dst_port", "")),
        ]).lower()
        return txt in searchable

    def _on_row_selected(self, row: int) -> None:
        if 0 <= row < len(self._filtered):
            info = self._filtered[row]
            self._detail.show_packet(info)
            self.packet_selected.emit(info)
