"""
Packet Capture tab for NetGuard.

Displays a live scrolling table of captured packets with per-protocol
colour coding, a BPF filter bar, regex-powered search, packet bookmarking,
column sorting (click any header), natural-language query support,
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
    QToolTip,
)

from src.gui.theme import PROTO_PALETTE, BG_PANEL, TEXT_DIM, ACCENT, BORDER, BG_DARK
from src.gui.detail_panel import DetailPanel

MAX_ROWS = 5_000   # Cap rows to keep the UI snappy

# Column index constants (must match COLUMNS order)
_STAR_COL  = 0
_NO_COL    = 1
_TIME_COL  = 2
_SRC_COL   = 3
_DST_COL   = 4
_PROTO_COL = 5
_LEN_COL   = 6
_INFO_COL  = 7   # stretched

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


class _NumericItem(QTableWidgetItem):
    """QTableWidgetItem whose less-than comparison uses numeric ordering."""

    def __lt__(self, other: QTableWidgetItem) -> bool:  # type: ignore[override]
        try:
            return float(self.text()) < float(other.text())
        except (ValueError, TypeError):
            return self.text() < other.text()


# ── Natural-language query translation ───────────────────────────────────────

# Maps human-friendly phrases to (field, value) or special filter strings
# The translator returns a tuple:
#   ("proto", "DNS")  →  protocol filter
#   ("text", "ssh")   →  free-text filter
#   ("port", 443)     →  port filter string "port:443"
#   ("size", ">1500") →  not currently used but reserved
_NLQ_RULES: list[tuple[re.Pattern, str]] = [
    # Protocol shortcuts
    (re.compile(r'\b(dns\s*quer(y|ies)|show\s+dns|dns\s+traffic)\b', re.I), "__proto__:DNS"),
    (re.compile(r'\b(http\s*traffic|web\s*traffic|show\s+http)\b',   re.I), "__proto__:HTTP"),
    (re.compile(r'\b(https?\s*traffic|tls\s*traffic)\b',              re.I), "__proto__:HTTPS"),
    (re.compile(r'\b(icmp|ping\s*traffic)\b',                         re.I), "__proto__:ICMP"),
    (re.compile(r'\b(arp\s*traffic)\b',                               re.I), "__proto__:ARP"),
    (re.compile(r'\b(udp\s*traffic)\b',                               re.I), "__proto__:UDP"),
    (re.compile(r'\b(tcp\s*traffic)\b',                               re.I), "__proto__:TCP"),
    (re.compile(r'\b(ssh\s*traffic)\b',                               re.I), "__proto__:SSH"),
    # Intent shortcuts
    (re.compile(r'\b(fail(ed)?\s*logins?|brute\s*force|login\s*attempts?)\b', re.I), "ssh"),
    (re.compile(r'\b(large\s*packets?|big\s*packets?)\b',                re.I), "__size__:>1500"),
    (re.compile(r'\b(port\s*scans?|scanning)\b',                         re.I), "SYN"),
    # IP filters  "from 1.2.3.4" or "src 1.2.3.4"
    (re.compile(r'\b(?:from|src(?:ip)?)\s+(\d{1,3}(?:\.\d{1,3}){3})\b', re.I), "__src__"),
    (re.compile(r'\b(?:to|dst(?:ip)?|dest(?:ip)?)\s+(\d{1,3}(?:\.\d{1,3}){3})\b', re.I), "__dst__"),
    # Port filter  "port 443" or "port:443"
    (re.compile(r'\bport[\s:]+(\d+)\b', re.I), "__port__"),
]


def _translate_nlq(query: str) -> tuple[str, str]:
    """
    Translate a natural-language query to (filter_text, proto_override).

    Returns
    -------
    filter_text   : text to put into the free-text filter box
    proto_override: protocol name or "" (used to set the combo-box)
    """
    q = query.strip()
    for pattern, result in _NLQ_RULES:
        m = pattern.search(q)
        if m is None:
            continue
        if result.startswith("__proto__:"):
            return "", result.split(":", 1)[1]
        if result == "__src__":
            return m.group(1), ""
        if result == "__dst__":
            return m.group(1), ""
        if result == "__port__":
            return f"port:{m.group(1)}", ""
        if result == "__size__:>1500":
            # We handle this via text filter — the _matches_filter already checks it
            return "__large__", ""
        # Plain text shortcut
        return result, ""
    return q, ""  # passthrough


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
        self._sort_col: int = -1          # column being sorted (-1 = none)
        self._sort_order: Qt.SortOrder = Qt.AscendingOrder

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
            'e.g.  tcp  |  192.168.1.1  |  dns  |  port:443  |  /regex/  |  "failed logins"'
        )
        self._filter_input.setMinimumWidth(300)
        self._filter_input.textChanged.connect(self._on_filter_changed)
        bar_layout.addWidget(self._filter_input, 1)

        self._nlq_btn = QPushButton("🔍 NLQ")
        self._nlq_btn.setProperty("secondary", "true")
        self._nlq_btn.setFixedWidth(70)
        self._nlq_btn.setToolTip(
            "Natural Language Query — type a human-readable query and press this button.\n\n"
            "Examples:\n"
            "  • failed logins\n"
            "  • dns queries\n"
            "  • http traffic\n"
            "  • from 192.168.1.1\n"
            "  • port 443\n"
            "  • large packets"
        )
        self._nlq_btn.clicked.connect(self._apply_nlq)
        bar_layout.addWidget(self._nlq_btn)

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
        # Enable interactive sorting by clicking column headers
        self._table.setSortingEnabled(True)
        self._table.horizontalHeader().setSortIndicatorShown(True)
        self._table.horizontalHeader().sectionClicked.connect(self._on_header_clicked)
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
        # Temporarily disable sorting so insertion order is preserved
        self._table.setSortingEnabled(False)
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
            # Use numeric-sort item for No. and Length columns
            if col in (_NO_COL, _LEN_COL):
                item = _NumericItem(val)
            else:
                item = QTableWidgetItem(val)
            item.setTextAlignment(align | Qt.AlignVCenter)
            if col == _STAR_COL:
                item.setForeground(QColor(ACCENT) if is_bookmarked else QColor(TEXT_DIM))
                item.setToolTip("Click ★ to bookmark / unbookmark this packet")
                # Store both the packet index and the full packet dict for
                # row lookup after sorting (UserRole = pkt_idx, UserRole+1 = info)
                item.setData(Qt.UserRole, pkt_idx)
                item.setData(Qt.UserRole + 1, info)
            elif col == _PROTO_COL:
                item.setForeground(color)
                font = QFont()
                font.setBold(True)
                item.setFont(font)
            else:
                item.setForeground(dim if col in (_NO_COL, _LEN_COL) else QColor("#e0e0e0"))
            self._table.setItem(row, col, item)

        self._row_label.setText(f"{row + 1:,} packets")

        # Re-enable sorting (Qt will re-sort existing rows if a sort is active)
        self._table.setSortingEnabled(True)

        if self._auto_scroll and self._sort_col == -1:
            self._table.scrollToBottom()

    def _apply_filter(self) -> None:
        # Read from the input box, UNLESS a special NLQ sentinel is already set
        # (e.g. "__large__" is set by _apply_nlq and not shown in the text box)
        if self._filter_text != "__large__":
            self._filter_text = self._filter_input.text().strip()
        self._use_regex = self._regex_cb.isChecked()
        proto_sel = self._proto_filter.currentText()
        proto_filter = "" if proto_sel == "All Protocols" else proto_sel.upper()

        self._table.setSortingEnabled(False)
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

        self._table.setSortingEnabled(True)

    def _matches_filter(self, info: dict) -> bool:
        proto_sel = self._proto_filter.currentText()
        if proto_sel != "All Protocols":
            if info.get("protocol", "").upper() != proto_sel.upper():
                return False

        txt = self._filter_text
        if not txt:
            return True

        # Special NLQ token: large packets (>1500 bytes)
        if txt == "__large__":
            return info.get("length", 0) > 1500

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

    def _on_filter_changed(self) -> None:
        """Called whenever the filter text changes (live filtering)."""
        self._filter_text = self._filter_input.text().strip()
        self._use_regex = self._regex_cb.isChecked()
        self._apply_filter()

    def _apply_nlq(self) -> None:
        """Translate the current filter text as a natural-language query."""
        raw = self._filter_input.text().strip()
        if not raw:
            return
        text, proto_override = _translate_nlq(raw)

        # Update the proto filter combo if a protocol was detected
        if proto_override:
            idx = self._proto_filter.findText(proto_override)
            if idx >= 0:
                self._proto_filter.setCurrentIndex(idx)
            else:
                self._proto_filter.setCurrentIndex(0)

        # Handle special __large__ token
        if text == "__large__":
            self._filter_input.blockSignals(True)
            self._filter_input.setText("")
            self._filter_input.blockSignals(False)
            self._filter_text = "__large__"
            self._use_regex = False
            self._apply_filter()
            return

        if text != raw:
            # Update the text box with the translated filter (keep signals to trigger re-filter)
            self._filter_input.setText(text)
        else:
            self._apply_filter()

    def _on_header_clicked(self, col: int) -> None:
        """Track which column is currently being sorted."""
        if self._sort_col == col:
            # Cycle through Ascending → Descending → None
            if self._sort_order == Qt.AscendingOrder:
                self._sort_order = Qt.DescendingOrder
            else:
                self._sort_col = -1
                self._table.horizontalHeader().setSortIndicator(-1, Qt.AscendingOrder)
                return
        else:
            self._sort_col = col
            self._sort_order = Qt.AscendingOrder
        self._table.horizontalHeader().setSortIndicator(self._sort_col, self._sort_order)

    def _get_row_info(self, row: int) -> dict | None:
        """Return the packet info dict for the given visual row (sort-safe)."""
        star_item = self._table.item(row, _STAR_COL)
        if star_item is None:
            return None
        info = star_item.data(Qt.UserRole + 1)
        return info

    def _on_row_selected(self, row: int) -> None:
        if row < 0:
            return
        info = self._get_row_info(row)
        if info is not None:
            self._detail.show_packet(info)
            self.packet_selected.emit(info)

    def _on_row_double_clicked(self, row: int, _col: int) -> None:
        """Open a full packet detail popup when the user double-clicks a row."""
        info = self._get_row_info(row)
        if info is None:
            return
        star_item = self._table.item(row, _STAR_COL)
        pkt_number = row + 1
        if star_item is not None:
            no_item = self._table.item(row, _NO_COL)
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
        info = self._get_row_info(row)
        if info is None:
            return

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
