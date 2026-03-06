"""
Packet Detail Dialog for NetGuard.

Opens as a pop-out window when the user double-clicks any row in the
capture table.  Shows a full layer-by-layer breakdown (Frame, Ethernet,
Network, Transport, DNS / Application) alongside a hex dump, and lets
the user copy all fields to the clipboard.
"""

from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QTreeWidget, QTreeWidgetItem, QTextEdit,
    QSplitter, QPushButton, QApplication, QFrame,
)

from src.gui.theme import ACCENT, BG_PANEL, BORDER, TEXT_DIM, BG_DARKEST

# Limits for data displayed in the dialog
_MAX_HEX_BYTES = 512      # bytes of raw packet shown in hex dump
_MAX_PAYLOAD_TEXT = 400   # characters of decoded payload text shown in tree


class PacketDetailDialog(QDialog):
    """Full-detail packet inspection popup opened on double-click."""

    def __init__(self, info: dict, pkt_number: int = 0, parent=None) -> None:
        super().__init__(parent)
        self._info = info
        self._pkt_number = pkt_number
        proto = info.get("protocol", "Unknown")
        self.setWindowTitle(f"Packet #{pkt_number}  —  {proto}")
        self.setMinimumSize(820, 580)
        self.resize(960, 680)
        # Keep dialog on top of main window but still allow interaction
        self.setWindowFlags(
            Qt.Window
            | Qt.WindowCloseButtonHint
            | Qt.WindowMaximizeButtonHint
            | Qt.WindowMinimizeButtonHint
        )
        self._build_ui()

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 10)
        layout.setSpacing(8)

        # ── Summary header ───────────────────────────────────────────────────
        info = self._info
        proto = info.get("protocol", "Unknown")
        src   = info.get("src_ip", "")
        dst   = info.get("dst_ip", "")
        info_text = info.get("info", "")

        header = QLabel(
            f"<span style='color:{ACCENT}; font-weight:700;'>#{self._pkt_number}</span>"
            f"&nbsp;&nbsp;<b>{proto}</b>&nbsp;&nbsp;&nbsp;"
            f"<span style='color:#e0e0e0;'>{src}</span>"
            f"<span style='color:{TEXT_DIM};'> → </span>"
            f"<span style='color:#e0e0e0;'>{dst}</span>"
            f"<br><span style='color:{TEXT_DIM}; font-size:11px;'>{info_text}</span>"
        )
        header.setWordWrap(True)
        header.setContentsMargins(4, 4, 4, 4)
        layout.addWidget(header)

        # Thin separator
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color:{BORDER};")
        layout.addWidget(sep)

        # ── Splitter: layer tree (left) + hex dump (right) ───────────────────
        splitter = QSplitter(Qt.Horizontal)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setAlternatingRowColors(True)
        self._tree.setMinimumWidth(340)
        self._tree.setColumnCount(1)
        splitter.addWidget(self._tree)

        self._hex = QTextEdit()
        self._hex.setReadOnly(True)
        self._hex.setFont(QFont("Consolas", 10))
        self._hex.setPlaceholderText("Hex dump will appear here…")
        splitter.addWidget(self._hex)

        splitter.setSizes([440, 420])
        layout.addWidget(splitter, 1)

        # ── Bottom button row ────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        copy_btn = QPushButton("📋  Copy All to Clipboard")
        copy_btn.setProperty("secondary", "true")
        copy_btn.setToolTip("Copy all packet fields as plain text")
        copy_btn.clicked.connect(self._copy_to_clipboard)
        btn_row.addWidget(copy_btn)

        btn_row.addStretch()

        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(90)
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)

        layout.addLayout(btn_row)

        self._populate()

    # ── Data population ──────────────────────────────────────────────────────

    def _populate(self) -> None:
        from src.utils.helpers import format_timestamp, get_port_service
        info = self._info

        def add_section(title: str, fields: list[tuple[str, str]]) -> None:
            root = QTreeWidgetItem(self._tree, [title])
            root.setForeground(0, QColor(ACCENT))
            font = QFont()
            font.setBold(True)
            root.setFont(0, font)
            for key, val in fields:
                child = QTreeWidgetItem(root, [f"  {key}:  {val}"])
                child.setForeground(0, QColor("#e0e0e0"))
            root.setExpanded(True)

        # ── Frame ────────────────────────────────────────────────────────────
        add_section("▸ Frame", [
            ("Timestamp",  format_timestamp(info.get("timestamp", 0))),
            ("Length",     f"{info.get('length', 0)} bytes"),
            ("Layers",     " / ".join(info.get("layers", []))),
        ])

        # ── Ethernet ─────────────────────────────────────────────────────────
        if info.get("src_mac") or info.get("dst_mac"):
            add_section("▸ Ethernet", [
                ("Source MAC", info.get("src_mac", "")),
                ("Dest MAC",   info.get("dst_mac", "")),
            ])

        # ── Network ──────────────────────────────────────────────────────────
        if info.get("src_ip"):
            add_section("▸ Network", [
                ("Source IP", info.get("src_ip", "")),
                ("Dest IP",   info.get("dst_ip", "")),
                ("Protocol",  info.get("protocol", "")),
            ])

        # ── Transport ────────────────────────────────────────────────────────
        src_p = info.get("src_port")
        dst_p = info.get("dst_port")
        if src_p is not None:
            t_fields = [
                ("Source Port", f"{src_p}  ({get_port_service(src_p)})"),
                ("Dest Port",   f"{dst_p}  ({get_port_service(dst_p)})"),
            ]
            if info.get("flags"):
                t_fields.append(("TCP Flags", info["flags"]))
            add_section("▸ Transport", t_fields)

        # ── DNS ──────────────────────────────────────────────────────────────
        if info.get("dns_query") is not None:
            qr = info.get("dns_qr", 0)
            dns_fields: list[tuple[str, str]] = [
                ("Direction",      "Query" if qr == 0 else "Response"),
                ("Transaction ID", f"0x{info.get('dns_transaction_id', 0):04x}"),
                ("Query Name",     info.get("dns_query", "")),
                ("Query Type",     info.get("dns_qtype", "")),
            ]
            answers = info.get("dns_answers", [])
            if answers:
                for i, ans in enumerate(answers, 1):
                    dns_fields.append((f"Answer {i}", ans))
            else:
                if qr == 1:
                    dns_fields.append(("Answers", "(none)"))
            add_section("▸ DNS", dns_fields)

        # ── Payload (application layer) ───────────────────────────────────────
        payload = info.get("payload", b"")
        if payload:
            try:
                text = payload[:_MAX_HEX_BYTES].decode("utf-8", errors="replace")
                add_section("▸ Payload", [("Data (first 512 B)", text[:_MAX_PAYLOAD_TEXT])])
            except Exception:
                pass

        # ── Hex dump ─────────────────────────────────────────────────────────
        raw = info.get("raw_bytes", b"")
        dump_src = raw if raw else payload
        if dump_src:
            lines: list[str] = []
            for i in range(0, min(len(dump_src), _MAX_HEX_BYTES), 16):
                chunk = dump_src[i: i + 16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"  {i:04x}  {hex_part:<47}  {asc_part}")
            self._hex.setPlainText("\n".join(lines))
        else:
            self._hex.setPlainText("  (no payload / raw bytes)")

    # ── Clipboard copy ───────────────────────────────────────────────────────

    def _copy_to_clipboard(self) -> None:
        from src.utils.helpers import format_timestamp, get_port_service
        info = self._info
        lines = [
            f"=== Packet #{self._pkt_number} ===",
            f"Protocol:        {info.get('protocol', '')}",
            f"Timestamp:       {format_timestamp(info.get('timestamp', 0))}",
            f"Length:          {info.get('length', 0)} bytes",
            f"Source MAC:      {info.get('src_mac', '')}",
            f"Dest MAC:        {info.get('dst_mac', '')}",
            f"Source IP:       {info.get('src_ip', '')}",
            f"Dest IP:         {info.get('dst_ip', '')}",
        ]
        src_p = info.get("src_port")
        if src_p is not None:
            dst_p = info.get("dst_port")
            lines += [
                f"Source Port:     {src_p}  ({get_port_service(src_p)})",
                f"Dest Port:       {dst_p}  ({get_port_service(dst_p)})",
            ]
        if info.get("flags"):
            lines.append(f"TCP Flags:       {info['flags']}")
        if info.get("dns_query") is not None:
            qr = info.get("dns_qr", 0)
            lines += [
                f"DNS Direction:   {'Query' if qr == 0 else 'Response'}",
                f"DNS Txn ID:      0x{info.get('dns_transaction_id', 0):04x}",
                f"DNS Query:       {info.get('dns_query', '')}",
                f"DNS Type:        {info.get('dns_qtype', '')}",
            ]
            for i, ans in enumerate(info.get("dns_answers", []), 1):
                lines.append(f"DNS Answer {i}:    {ans}")
        lines.append(f"Info:            {info.get('info', '')}")
        QApplication.clipboard().setText("\n".join(lines))
