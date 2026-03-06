"""
Stream viewer dialog for NetGuard.

Shows the reassembled payload of a TCP/UDP conversation with
direction markers, colour coding, and search / copy capabilities.
"""

from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QTextCursor, QTextCharFormat, QColor, QBrush
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QLineEdit,
    QCheckBox, QComboBox, QDialogButtonBox, QSplitter,
    QWidget, QScrollArea, QFrame,
)

from src.core.stream_reassembler import Stream, StreamSegment
from src.gui.theme import (
    ACCENT, BG_DARKEST, BG_PANEL, BORDER, TEXT_DIM, TEXT_MAIN, BG_DARK,
)

_CLIENT_BG = "#0d2a1a"   # dark green tint – client → server
_SERVER_BG = "#0d1a2a"   # dark blue tint – server → client


class StreamViewerDialog(QDialog):
    """Modal dialog that shows a reassembled network stream."""

    def __init__(self, stream: Stream, parent=None):
        super().__init__(parent)
        self._stream = stream
        self._current_search: str = ""
        self.setWindowTitle(f"Follow Stream  —  {stream.protocol}  [{stream.key}]")
        self.resize(900, 650)
        self._build_ui()
        self._populate()

    # ── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Info strip
        info = QLabel(
            f"  Protocol: <b>{self._stream.protocol}</b>  |  "
            f"Segments: <b>{len(self._stream.segments)}</b>  |  "
            f"Total data: <b>{_fmt_bytes(self._stream.total_bytes)}</b>"
        )
        info.setStyleSheet(
            f"background:{BG_PANEL}; color:{TEXT_MAIN}; "
            f"padding:6px 10px; border-radius:4px; font-size:12px;"
        )
        layout.addWidget(info)

        # Search bar
        search_bar = QHBoxLayout()
        search_bar.setSpacing(6)
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search in stream…")
        self._search_input.textChanged.connect(self._on_search_changed)
        search_bar.addWidget(QLabel("Find:"))
        search_bar.addWidget(self._search_input, 1)

        self._case_cb = QCheckBox("Case sensitive")
        self._case_cb.stateChanged.connect(self._on_search_changed)
        search_bar.addWidget(self._case_cb)

        self._view_mode = QComboBox()
        self._view_mode.addItems(["Text (ASCII)", "Hex dump", "Raw bytes"])
        self._view_mode.currentTextChanged.connect(self._populate)
        search_bar.addWidget(QLabel("View:"))
        search_bar.addWidget(self._view_mode)
        layout.addLayout(search_bar)

        # Legend
        legend = QHBoxLayout()
        legend.setSpacing(16)
        for color, label in ((_CLIENT_BG, "→ Client → Server"), (_SERVER_BG, "← Server → Client")):
            lbl = QLabel(f"  {label}  ")
            lbl.setStyleSheet(
                f"background:{color}; color:{TEXT_MAIN}; "
                f"padding:2px 8px; border-radius:3px; font-size:11px;"
            )
            legend.addWidget(lbl)
        legend.addStretch()
        layout.addLayout(legend)

        # Stream content viewer
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont("Consolas", 11))
        self._text.setStyleSheet(
            f"background:{BG_DARKEST}; color:{TEXT_MAIN}; "
            f"border:1px solid {BORDER}; border-radius:4px;"
        )
        layout.addWidget(self._text, 1)

        # Buttons
        btn_row = QHBoxLayout()
        copy_btn = QPushButton("Copy All")
        copy_btn.clicked.connect(self._copy_all)
        copy_btn.setFixedWidth(100)
        btn_row.addWidget(copy_btn)
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        close_btn.setFixedWidth(80)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

    # ── Population ──────────────────────────────────────────────────────────

    def _populate(self) -> None:
        self._text.clear()
        mode = self._view_mode.currentText()

        if mode == "Hex dump":
            self._populate_hex()
        elif mode == "Raw bytes":
            all_data = b"".join(s.data for s in self._stream.segments)
            self._text.setPlainText(all_data.decode("latin-1", errors="replace"))
        else:
            self._populate_text()

    def _populate_text(self) -> None:
        cursor = self._text.textCursor()
        cursor.movePosition(QTextCursor.End)

        for seg in self._stream.segments:
            # Direction header
            hdr_fmt = QTextCharFormat()
            hdr_color = _CLIENT_BG if seg.direction == "→" else _SERVER_BG
            hdr_fmt.setBackground(QBrush(QColor(hdr_color)))
            hdr_fmt.setForeground(QBrush(QColor(ACCENT)))
            hdr_fmt.setFontWeight(700)
            cursor.setCharFormat(hdr_fmt)
            cursor.insertText(
                f"\n{seg.direction}  {seg.src_ip}:{seg.src_port or '?'}  "
                f"→  {seg.dst_ip}:{seg.dst_port or '?'}  "
                f"  [{len(seg.data)} bytes]\n"
            )

            # Payload
            body_fmt = QTextCharFormat()
            body_fmt.setBackground(QBrush(QColor(hdr_color)))
            body_fmt.setForeground(QBrush(QColor(TEXT_MAIN)))
            body_fmt.setFontWeight(400)
            cursor.setCharFormat(body_fmt)
            text = "".join(
                chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "."
                for b in seg.data[:4096]
            )
            cursor.insertText(text + "\n")

        self._text.setTextCursor(cursor)
        self._text.moveCursor(QTextCursor.Start)
        self._highlight_search()

    def _populate_hex(self) -> None:
        lines: list[str] = []
        offset = 0
        for seg in self._stream.segments:
            lines.append(
                f"\n{'─'*20}  {seg.direction}  "
                f"{seg.src_ip}:{seg.src_port or '?'}  "
                f"[{len(seg.data)} bytes]  {'─'*20}"
            )
            for i in range(0, min(len(seg.data), 2048), 16):
                chunk = seg.data[i: i + 16]
                hex_p = " ".join(f"{b:02x}" for b in chunk)
                asc_p = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"  {offset + i:06x}  {hex_p:<47}  {asc_p}")
            offset += len(seg.data)
        self._text.setPlainText("\n".join(lines))
        self._text.moveCursor(QTextCursor.Start)

    # ── Search / highlight ──────────────────────────────────────────────────

    def _on_search_changed(self) -> None:
        self._current_search = self._search_input.text()
        self._highlight_search()

    def _highlight_search(self) -> None:
        # Clear previous highlights
        cursor = self._text.textCursor()
        cursor.select(QTextCursor.Document)
        fmt_clear = QTextCharFormat()
        cursor.mergeCharFormat(fmt_clear)

        term = self._current_search
        if not term:
            return

        flags = Qt.MatchFlags()
        if self._case_cb.isChecked():
            flags = Qt.MatchCaseSensitive  # type: ignore[assignment]

        # Use QTextDocument's find()
        doc = self._text.document()
        find_flags = (
            Qt.FindCaseSensitively if self._case_cb.isChecked() else Qt.FindFlags()
        )
        highlight = QTextCharFormat()
        highlight.setBackground(QBrush(QColor(ACCENT)))
        highlight.setForeground(QBrush(QColor("#ffffff")))

        cursor = doc.find(term, 0, find_flags)  # type: ignore[arg-type]
        while not cursor.isNull():
            cursor.mergeCharFormat(highlight)
            cursor = doc.find(term, cursor, find_flags)  # type: ignore[arg-type]

    # ── Actions ─────────────────────────────────────────────────────────────

    def _copy_all(self) -> None:
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(self._text.toPlainText())


def _fmt_bytes(v: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024:
            return f"{v} {unit}"
        v //= 1024
    return f"{v} TB"
