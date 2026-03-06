"""
Connections tab for NetGuard.

Displays active TCP/UDP flows tracked in real-time, with protocol
and state filters.
"""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from PyQt5.QtCore import Qt, QObject, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QPushButton, QAbstractItemView,
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QFrame,
)

from src.gui.theme import PROTO_PALETTE, BG_PANEL, TEXT_DIM, BORDER, ACCENT
from src.core.connections import Connection, TRACKED_PROTOCOLS
from src.utils.helpers import format_bytes

_DNS_TIMEOUT = 2.0        # seconds per reverse-DNS lookup
_DNS_MAX_WORKERS = 8      # maximum concurrent DNS threads


class _DnsSignals(QObject):
    """Qt signals for thread-safe DNS result delivery."""
    resolved = pyqtSignal(str, str)  # ip, hostname

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
        self._dns_cache: dict[str, str] = {}
        self._dns_pending: set[str] = set()
        self._dns_executor = ThreadPoolExecutor(max_workers=_DNS_MAX_WORKERS)
        self._dns_signals = _DnsSignals()
        self._dns_signals.resolved.connect(self._on_dns_resolved)
        # Debounce timer: batch rapid DNS results into a single table refresh
        self._dns_refresh_timer = QTimer(self)
        self._dns_refresh_timer.setSingleShot(True)
        self._dns_refresh_timer.setInterval(150)
        self._dns_refresh_timer.timeout.connect(self._refresh)
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
        self._table.cellDoubleClicked.connect(self._on_row_double_clicked)
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

            # Schedule DNS lookups for both endpoints
            self._schedule_dns(conn.src_ip)
            self._schedule_dns(conn.dst_ip)

            # Use resolved hostname when available; fall back to raw IP
            src_display = self._display_ip(conn.src_ip, self._dns_cache.get(conn.src_ip, ""))
            dst_display = self._display_ip(conn.dst_ip, self._dns_cache.get(conn.dst_ip, ""))

            values = [
                conn.protocol,
                src_display,
                str(conn.src_port if conn.src_port is not None else "—"),
                dst_display,
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
                elif col == 1:
                    item.setForeground(QColor("#e0e0e0"))
                    if src_display != conn.src_ip:
                        item.setToolTip(f"IP: {conn.src_ip}")
                elif col == 3:
                    item.setForeground(QColor("#e0e0e0"))
                    if dst_display != conn.dst_ip:
                        item.setToolTip(f"IP: {conn.dst_ip}")
                elif col == 5:
                    item.setForeground(state_color)
                    f = QFont()
                    f.setBold(True)
                    item.setFont(f)
                else:
                    item.setForeground(QColor("#e0e0e0"))
                self._table.setItem(row, col, item)

    # ── DNS helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _display_ip(ip: str, hostname: str) -> str:
        """Return *hostname* when available, otherwise return *ip* unchanged."""
        return hostname if hostname else ip

    def _schedule_dns(self, ip: str) -> None:
        """Submit a background reverse-DNS lookup for *ip* if not already known."""
        if not ip or ip in self._dns_cache or ip in self._dns_pending:
            return
        self._dns_pending.add(ip)
        self._dns_executor.submit(self._resolve_ip, ip)

    def _resolve_ip(self, ip: str) -> None:
        """Thread-pool worker: reverse-DNS lookup with a short timeout."""
        hostname = ""
        result: list[str] = []

        def _do_lookup() -> None:
            try:
                result.append(socket.gethostbyaddr(ip)[0])
            except Exception:
                pass

        t = threading.Thread(target=_do_lookup, daemon=True)
        t.start()
        t.join(timeout=_DNS_TIMEOUT)
        if result:
            hostname = result[0]
        self._dns_signals.resolved.emit(ip, hostname)

    def _on_dns_resolved(self, ip: str, hostname: str) -> None:
        """Main-thread slot: cache the resolved name and schedule a re-render."""
        self._dns_pending.discard(ip)
        if hostname and hostname != ip:
            self._dns_cache[ip] = hostname
            if not self._dns_refresh_timer.isActive():
                self._dns_refresh_timer.start()

    # ── Connection detail dialog ─────────────────────────────────────────────

    def _on_row_double_clicked(self, row: int, _col: int) -> None:
        """Show a detail dialog for the double-clicked connection row."""
        proto_sel = self._proto_filter.currentText()
        state_sel = self._state_filter.currentText()
        visible = [
            c for c in self._connections
            if (proto_sel == "All" or c.protocol.upper() == proto_sel.upper())
            and (state_sel == "All" or c.state.upper() == state_sel.upper())
        ]
        if row < 0 or row >= len(visible):
            return
        self._show_detail_dialog(visible[row])

    def _show_detail_dialog(self, conn: Connection) -> None:
        """Display a modal dialog with full details for *conn*."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Connection Details")
        dlg.setMinimumWidth(420)

        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(8)

        src_hostname = self._dns_cache.get(conn.src_ip, "")
        dst_hostname = self._dns_cache.get(conn.dst_ip, "")

        src_display = self._display_ip(conn.src_ip, src_hostname)
        dst_display = self._display_ip(conn.dst_ip, dst_hostname)

        src_text = f"{src_display}  ({conn.src_ip})" if src_hostname else conn.src_ip
        dst_text = f"{dst_display}  ({conn.dst_ip})" if dst_hostname else conn.dst_ip

        dur = conn.duration
        if dur < 60:
            dur_str = f"{int(dur)}s"
        else:
            dur_str = f"{int(dur // 60)}m {int(dur % 60)}s"

        fields = [
            ("Protocol",    conn.protocol),
            ("State",       conn.state),
            ("Source",      f"{src_text}  :  {conn.src_port or '—'}"),
            ("Destination", f"{dst_text}  :  {conn.dst_port or '—'}"),
            ("Packets",     f"{conn.packets:,}"),
            ("Data",        format_bytes(conn.bytes_total)),
            ("Duration",    dur_str),
        ]

        for label_text, value_text in fields:
            lbl = QLabel(f"<b>{label_text}</b>")
            val = QLabel(value_text)
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            val.setWordWrap(True)
            form.addRow(lbl, val)

        layout.addLayout(form)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFrameShadow(QFrame.Sunken)
        layout.addWidget(sep)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.accept)
        layout.addWidget(btns)

        dlg.exec_()
