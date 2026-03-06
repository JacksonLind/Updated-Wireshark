"""
Packet Capture tab for NetGuard.

Displays a live scrolling table of captured packets with per-protocol
colour coding, a BPF filter bar, regex-powered search, packet bookmarking,
and a detail panel at the bottom.
"""

from __future__ import annotations

import re
import time
from typing import Any

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QPushButton, QLineEdit, QComboBox,
    QAbstractItemView, QCheckBox, QMenu, QAction, QMessageBox, QFrame,
)

from src.gui.theme import PROTO_PALETTE, BG_PANEL, TEXT_DIM, ACCENT, BORDER, BG_DARK
from src.gui.detail_panel import DetailPanel

MAX_ROWS = 5_000   # Cap rows to keep the UI snappy

COLUMNS = [
    ("★",        30,  Qt.AlignCenter),
    ("No.",      50, Qt.AlignRight),
    ("Time",     90, Qt.AlignLeft),
    ("Source IP",130, Qt.AlignLeft),
    ("Dest IP",  130, Qt.AlignLeft),
    ("Protocol", 90,  Qt.AlignCenter),
    ("Length",   70,  Qt.AlignRight),
    ("Info",     350, Qt.AlignLeft),
]

# Internal data columns (not shown in COLUMNS but used for alignment mapping)
_INFO_COL = 7   # "Info" column index in new COLUMNS layout
_PROTO_COL = 5
_STAR_COL  = 0


class CaptureTab(QWidget):
    """Live packet capture view."""

    # Emitted when user clicks a row (gives the raw packet info dict)
    packet_selected = pyqtSignal(dict)
    # Emitted when user requests to follow a stream
    follow_stream_requested = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._packets: list[dict] = []
        self._filtered: list[dict] = []
        self._filter_text: str = ""
        self._auto_scroll: bool = True
        self._paused: bool = False
        self._bookmarked: set[int] = set()   # indices into self._packets
        self._show_bookmarks_only: bool = False
        self._use_regex: bool = False
        self._stream_reassembler = None   # injected by MainWindow

        self._build_ui()

    # ── Public API ─────────────────────────────────────────────────────────

    def add_packet(self, info: dict) -> None:
        """Append a new packet (called from the main window via Qt signal)."""
        if self._paused:
            return
        self._packets.append(info)
        if len(self._packets) > MAX_ROWS:
            # Trim bookmarks that are now out of range
            offset = len(self._packets) - MAX_ROWS
            self._bookmarked = {i - offset for i in self._bookmarked if i >= offset}
            self._packets = self._packets[-MAX_ROWS:]

        if self._show_bookmarks_only:
            return

        if self._matches_filter(info):
            self._append_row(info, len(self._packets) - 1)

    def clear(self) -> None:
        self._packets.clear()
        self._filtered.clear()
        self._bookmarked.clear()
        self._table.setRowCount(0)
        self._detail.clear()

    def set_paused(self, paused: bool) -> None:
        self._paused = paused

    def focus_filter(self) -> None:
        """Give keyboard focus to the display filter input."""
        self._filter_input.setFocus()
        self._filter_input.selectAll()

    def set_stream_reassembler(self, reassembler) -> None:
        """Inject the StreamReassembler so we can open stream viewers."""
        self._stream_reassembler = reassembler

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
        bar_layout.setContentsMargins(12, 6, 12, 6)
        bar_layout.setSpacing(6)

        bar_layout.addWidget(QLabel("Filter:"))

        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText(
            "e.g.  tcp  |  192.168.1.1  |  dns  |  port:443  |  /regex/"
        )
        self._filter_input.setMinimumWidth(260)
        self._filter_input.textChanged.connect(self._apply_filter)
        bar_layout.addWidget(self._filter_input, 1)

        self._regex_cb = QCheckBox("Regex")
        self._regex_cb.setToolTip(
            "Enable regular-expression matching in the filter bar.\n"
            "Example:  192\\.168\\.[0-9]+\\.1"
        )
        self._regex_cb.stateChanged.connect(self._apply_filter)
        bar_layout.addWidget(self._regex_cb)

        self._proto_filter = QComboBox()
        self._proto_filter.addItems([
            "All Protocols", "TCP", "UDP", "HTTP", "HTTPS",
            "DNS", "ICMP", "ARP", "SSH",
        ])
        self._proto_filter.currentTextChanged.connect(self._apply_filter)
        bar_layout.addWidget(self._proto_filter)

        # Visual separator
        _sep1 = QFrame()
        _sep1.setFrameShape(QFrame.VLine)
        _sep1.setStyleSheet(f"color:{BORDER};")
        bar_layout.addWidget(_sep1)

        self._bookmarks_btn = QPushButton("★ Bookmarks")
        self._bookmarks_btn.setProperty("secondary", "true")
        self._bookmarks_btn.setCheckable(True)
        self._bookmarks_btn.setFixedWidth(120)
        self._bookmarks_btn.setToolTip("Show only bookmarked packets")
        self._bookmarks_btn.clicked.connect(self._toggle_bookmarks)
        bar_layout.addWidget(self._bookmarks_btn)

        self._auto_scroll_cb = QCheckBox("Auto-scroll")
        self._auto_scroll_cb.setChecked(True)
        self._auto_scroll_cb.stateChanged.connect(
            lambda s: setattr(self, "_auto_scroll", bool(s))
        )
        bar_layout.addWidget(self._auto_scroll_cb)

        self._pause_btn = QPushButton("⏸ Pause")
        self._pause_btn.setProperty("secondary", "true")
        self._pause_btn.setFixedWidth(100)
        self._pause_btn.setToolTip("Pause display updates (packets still captured)")
        self._pause_btn.setCheckable(True)
        self._pause_btn.clicked.connect(self._toggle_pause)
        bar_layout.addWidget(self._pause_btn)

        bar_layout.addStretch()

        self._row_label = QLabel("0 packets")
        self._row_label.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        bar_layout.addWidget(self._row_label)

        # Visual separator
        _sep2 = QFrame()
        _sep2.setFrameShape(QFrame.VLine)
        _sep2.setStyleSheet(f"color:{BORDER};")
        bar_layout.addWidget(_sep2)

        clear_btn = QPushButton("Clear")
        clear_btn.setProperty("secondary", "true")
        clear_btn.setFixedWidth(80)
        clear_btn.clicked.connect(self.clear)
        bar_layout.addWidget(clear_btn)

        outer.addWidget(bar)

        # ── Splitter: table (top) + detail (bottom) ────────────────────────
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet(f"background:{BG_DARK};")

        self._table = QTableWidget()
        self._table.setColumnCount(len(COLUMNS))
        self._table.setHorizontalHeaderLabels([c[0] for c in COLUMNS])
        self._table.horizontalHeader().setSectionResizeMode(_INFO_COL, QHeaderView.Stretch)
        for i, (_, w, _) in enumerate(COLUMNS):
            if i != _INFO_COL:
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
        self._table.cellDoubleClicked.connect(self._on_row_double_clicked)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)

        splitter.addWidget(self._table)

        self._detail = DetailPanel()
        splitter.addWidget(self._detail)

        splitter.setSizes([550, 250])
        outer.addWidget(splitter, 1)

    # ── Private helpers ────────────────────────────────────────────────────

    def _append_row(self, info: dict, pkt_idx: int) -> None:
        from src.utils.helpers import format_timestamp
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._filtered.append(info)

        proto = info.get("protocol", "Unknown")
        color = QColor(PROTO_PALETTE.get(proto, "#9e9e9e"))
        dim = QColor(TEXT_DIM)

        ts = format_timestamp(info.get("timestamp", time.time()))

        is_bookmarked = pkt_idx in self._bookmarked
        star_val = "★" if is_bookmarked else "☆"

        values = [
            star_val,
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
            if col == _STAR_COL:
                item.setForeground(QColor(ACCENT) if is_bookmarked else QColor(TEXT_DIM))
                item.setToolTip("Click ★ to bookmark / unbookmark this packet")
                # Store packet index for later toggle
                item.setData(Qt.UserRole, pkt_idx)
            elif col == _PROTO_COL:
                item.setForeground(color)
                font = QFont()
                font.setBold(True)
                item.setFont(font)
            else:
                item.setForeground(dim if col in (1, 6) else QColor("#e0e0e0"))
            self._table.setItem(row, col, item)

        self._row_label.setText(f"{row + 1:,} packets")

        if self._auto_scroll:
            self._table.scrollToBottom()

    def _apply_filter(self) -> None:
        self._filter_text = self._filter_input.text().strip()
        self._use_regex = self._regex_cb.isChecked()
        proto_sel = self._proto_filter.currentText()
        proto_filter = "" if proto_sel == "All Protocols" else proto_sel.upper()

        self._table.setRowCount(0)
        self._filtered.clear()

        for idx, info in enumerate(self._packets):
            if self._show_bookmarks_only and idx not in self._bookmarked:
                continue
            if proto_filter and info.get("protocol", "").upper() != proto_filter:
                continue
            if self._filter_text and not self._matches_filter(info):
                continue
            self._append_row(info, idx)

    def _matches_filter(self, info: dict) -> bool:
        proto_sel = self._proto_filter.currentText()
        if proto_sel != "All Protocols":
            if info.get("protocol", "").upper() != proto_sel.upper():
                return False

        txt = self._filter_text
        if not txt:
            return True

        # Handle port: shorthand (e.g. "port:443")
        port_match = re.match(r'^port:(\d+)$', txt, re.IGNORECASE)
        if port_match:
            target_port = int(port_match.group(1))
            return (
                info.get("src_port") == target_port
                or info.get("dst_port") == target_port
            )

        searchable = " ".join([
            info.get("src_ip", ""),
            info.get("dst_ip", ""),
            info.get("protocol", ""),
            info.get("info", ""),
            str(info.get("src_port", "")),
            str(info.get("dst_port", "")),
        ])

        if self._use_regex:
            try:
                return bool(re.search(txt, searchable, re.IGNORECASE))
            except re.error:
                return False
        return txt.lower() in searchable.lower()

    def _on_row_selected(self, row: int) -> None:
        if 0 <= row < len(self._filtered):
            info = self._filtered[row]
            self._detail.show_packet(info)
            self.packet_selected.emit(info)

    def _on_row_double_clicked(self, row: int, _col: int) -> None:
        """Open a full packet detail popup when the user double-clicks a row."""
        if 0 <= row < len(self._filtered):
            info = self._filtered[row]
            star_item = self._table.item(row, _STAR_COL)
            pkt_number = row + 1
            if star_item is not None:
                # Prefer the visible row number
                no_item = self._table.item(row, 1)
                if no_item is not None:
                    try:
                        pkt_number = int(no_item.text())
                    except ValueError:
                        pass
            from src.gui.packet_detail_dialog import PacketDetailDialog
            dlg = PacketDetailDialog(info, pkt_number=pkt_number, parent=self)
            dlg.show()

    def _toggle_pause(self, checked: bool) -> None:
        self._paused = checked
        self._pause_btn.setText("▶ Resume" if checked else "⏸ Pause")

    def _toggle_bookmarks(self, checked: bool) -> None:
        self._show_bookmarks_only = checked
        self._bookmarks_btn.setText(
            "★ All" if checked else "★ Bookmarks"
        )
        self._apply_filter()

    def _show_context_menu(self, pos) -> None:
        """Right-click context menu for packet table rows."""
        item = self._table.itemAt(pos)
        if item is None:
            return

        row = item.row()
        if row < 0 or row >= len(self._filtered):
            return

        info = self._filtered[row]
        star_item = self._table.item(row, _STAR_COL)
        pkt_idx = star_item.data(Qt.UserRole) if star_item else None

        menu = QMenu(self)

        # Bookmark toggle
        is_bookmarked = (pkt_idx is not None and pkt_idx in self._bookmarked)
        bm_text = "☆ Remove Bookmark" if is_bookmarked else "★ Bookmark Packet"
        bm_action = QAction(bm_text, self)
        bm_action.triggered.connect(lambda: self._toggle_packet_bookmark(row, pkt_idx))
        menu.addAction(bm_action)

        menu.addSeparator()

        # Follow stream
        has_payload = bool(info.get("payload"))
        proto = info.get("protocol", "")
        can_follow = has_payload and proto in (
            "TCP", "HTTP", "HTTPS", "SSH", "UDP", "DNS"
        )
        stream_action = QAction("🔍  Follow TCP/UDP Stream", self)
        stream_action.setEnabled(can_follow)
        stream_action.triggered.connect(lambda: self._follow_stream(info))
        menu.addAction(stream_action)

        menu.addSeparator()

        # Copy actions
        copy_src = QAction(f"Copy Source IP  ({info.get('src_ip', '')})", self)
        copy_src.triggered.connect(
            lambda: self._copy_to_clipboard(info.get("src_ip", ""))
        )
        menu.addAction(copy_src)

        copy_dst = QAction(f"Copy Dest IP  ({info.get('dst_ip', '')})", self)
        copy_dst.triggered.connect(
            lambda: self._copy_to_clipboard(info.get("dst_ip", ""))
        )
        menu.addAction(copy_dst)

        copy_info = QAction("Copy Info", self)
        copy_info.triggered.connect(
            lambda: self._copy_to_clipboard(info.get("info", ""))
        )
        menu.addAction(copy_info)

        menu.addSeparator()

        # Filter shortcuts
        filter_src = QAction(f"Filter: src = {info.get('src_ip', '')}", self)
        filter_src.triggered.connect(
            lambda: self._filter_input.setText(info.get("src_ip", ""))
        )
        menu.addAction(filter_src)

        filter_proto = QAction(f"Filter: protocol = {proto}", self)
        filter_proto.triggered.connect(
            lambda: self._filter_input.setText(proto.lower())
        )
        menu.addAction(filter_proto)

        menu.exec_(self._table.viewport().mapToGlobal(pos))

    def _toggle_packet_bookmark(self, row: int, pkt_idx) -> None:
        if pkt_idx is None:
            return
        if pkt_idx in self._bookmarked:
            self._bookmarked.discard(pkt_idx)
            star_char = "☆"
            star_color = QColor(TEXT_DIM)
        else:
            self._bookmarked.add(pkt_idx)
            star_char = "★"
            star_color = QColor(ACCENT)

        star_item = self._table.item(row, _STAR_COL)
        if star_item:
            star_item.setText(star_char)
            star_item.setForeground(star_color)

    def _follow_stream(self, info: dict) -> None:
        if self._stream_reassembler is None:
            QMessageBox.information(
                self, "Follow Stream",
                "Stream data is not available yet.\n"
                "Start a capture or load a file first."
            )
            return
        stream = self._stream_reassembler.get_stream_for_packet(info)
        if stream is None or not stream.segments:
            QMessageBox.information(
                self, "Follow Stream",
                "No stream data found for this packet.\n"
                "Only packets with payload data can be followed."
            )
            return
        from src.gui.stream_viewer import StreamViewerDialog
        dlg = StreamViewerDialog(stream, parent=self)
        dlg.exec_()

    @staticmethod
    def _copy_to_clipboard(text: str) -> None:
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
