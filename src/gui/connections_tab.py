"""
Connections tab for NetGuard.

Displays active TCP/UDP flows tracked in real-time, with protocol
and state filters.
"""

from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QPushButton, QAbstractItemView,
    QComboBox,
)

from src.gui.theme import PROTO_PALETTE, BG_PANEL, TEXT_DIM, BORDER, ACCENT
from src.core.connections import Connection, TRACKED_PROTOCOLS
from src.utils.helpers import format_bytes

COLUMNS = [
    ("Protocol",  80,  Qt.AlignCenter),
    ("Source IP", 130, Qt.AlignLeft),
    ("Src Port",  70,  Qt.AlignRight),
    ("Dest IP",   130, Qt.AlignLeft),
    ("Dst Port",  70,  Qt.AlignRight),
    ("State",     100, Qt.AlignCenter),
    ("Packets",   70,  Qt.AlignRight),
    ("Data",      80,  Qt.AlignRight),
    ("Duration",  80,  Qt.AlignRight),
]

STATE_COLORS = {
    "ESTABLISHED": "#4fc3f7",
    "SYN":         "#ffb74d",
    "SYN-ACK":     "#ffb74d",
    "CLOSING":     "#FF8800",
    "RESET":       "#FF4444",
    "UDP":         "#81c784",
}


class ConnectionsTab(QWidget):
    """Live view of tracked network connections / flows."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._connections: list[Connection] = []
        self._build_ui()

    # ── Public API ─────────────────────────────────────────────────────────

    def update_connections(self, conns: list[Connection]) -> None:
        """Receive an updated connection list and refresh the table."""
        self._connections = conns
        self._conn_count.setText(f"{len(conns):,} connections")
        self._refresh()

    def clear(self) -> None:
        self._connections.clear()
        self._table.setRowCount(0)
        self._conn_count.setText("0 connections")

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Filter bar
        bar = QWidget()
        bar.setFixedHeight(52)
        bar.setStyleSheet(f"background:{BG_PANEL}; border-bottom:1px solid {BORDER};")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(12, 8, 12, 8)
        bar_layout.setSpacing(8)

        bar_layout.addWidget(QLabel("Protocol:"))
        self._proto_filter = QComboBox()
        self._proto_filter.addItems(["All"] + list(TRACKED_PROTOCOLS))
        self._proto_filter.currentTextChanged.connect(self._refresh)
        bar_layout.addWidget(self._proto_filter)

        bar_layout.addSpacing(16)
        bar_layout.addWidget(QLabel("State:"))
        self._state_filter = QComboBox()
        self._state_filter.addItems(
            ["All", "ESTABLISHED", "SYN", "SYN-ACK", "CLOSING", "RESET", "UDP"]
        )
        self._state_filter.currentTextChanged.connect(self._refresh)
        bar_layout.addWidget(self._state_filter)

        bar_layout.addStretch()

        self._conn_count = QLabel("0 connections")
        self._conn_count.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        bar_layout.addWidget(self._conn_count)

        clear_btn = QPushButton("Clear")
        clear_btn.setProperty("secondary", "true")
        clear_btn.setFixedWidth(70)
        clear_btn.clicked.connect(self.clear)
        bar_layout.addWidget(clear_btn)

        outer.addWidget(bar)

        # Connections table
        self._table = QTableWidget()
        self._table.setColumnCount(len(COLUMNS))
        self._table.setHorizontalHeaderLabels([c[0] for c in COLUMNS])
        # Stretch Source IP and Dest IP columns
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        for i, (_, w, _) in enumerate(COLUMNS):
            if i not in (1, 3):
                self._table.setColumnWidth(i, w)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(False)
        self._table.verticalHeader().setDefaultSectionSize(22)
        outer.addWidget(self._table, 1)

        # Info strip
        info_bar = QLabel(
            "  🔗  Flows are tracked automatically during live capture and offline file analysis."
        )
        info_bar.setFixedHeight(26)
        info_bar.setStyleSheet(
            f"background:{BG_PANEL}; color:{TEXT_DIM}; font-size:11px; "
            f"border-top:1px solid {BORDER};"
        )
        outer.addWidget(info_bar)

    # ── Internal ───────────────────────────────────────────────────────────

    def _refresh(self) -> None:
        """Rebuild the table from the current connection list, applying filters."""
        proto_sel = self._proto_filter.currentText()
        state_sel = self._state_filter.currentText()

        visible = [
            c for c in self._connections
            if (proto_sel == "All" or c.protocol.upper() == proto_sel.upper())
            and (state_sel == "All" or c.state.upper() == state_sel.upper())
        ]

        self._table.setRowCount(len(visible))
        for row, conn in enumerate(visible):
            proto_color = QColor(PROTO_PALETTE.get(conn.protocol, "#9e9e9e"))
            state_color = QColor(STATE_COLORS.get(conn.state, TEXT_DIM))

            dur = conn.duration
            if dur < 60:
                dur_str = f"{int(dur)}s"
            else:
                dur_str = f"{int(dur // 60)}m {int(dur % 60)}s"

            values = [
                conn.protocol,
                conn.src_ip,
                str(conn.src_port if conn.src_port is not None else "—"),
                conn.dst_ip,
                str(conn.dst_port if conn.dst_port is not None else "—"),
                conn.state,
                f"{conn.packets:,}",
                format_bytes(conn.bytes_total),
                dur_str,
            ]
            aligns = [c[2] for c in COLUMNS]

            for col, (val, align) in enumerate(zip(values, aligns)):
                item = QTableWidgetItem(val)
                item.setTextAlignment(align | Qt.AlignVCenter)
                if col == 0:
                    item.setForeground(proto_color)
                    f = QFont()
                    f.setBold(True)
                    item.setFont(f)
                elif col == 5:
                    item.setForeground(state_color)
                    f = QFont()
                    f.setBold(True)
                    item.setFont(f)
                else:
                    item.setForeground(QColor("#e0e0e0"))
                self._table.setItem(row, col, item)
