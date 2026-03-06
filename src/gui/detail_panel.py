"""
Packet detail panel for NetGuard.

Shows layer-by-layer breakdown + hex dump for the selected packet.
"""

from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QTextEdit,
    QSplitter, QLabel,
)

from src.gui.theme import BG_DARKEST, BG_PANEL, BORDER, TEXT_DIM, ACCENT


class DetailPanel(QWidget):
    """Bottom panel that shows protocol layers and hex dump."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QLabel("  Packet Details  —  double-click a row to open full view")
        header.setFixedHeight(28)
        header.setStyleSheet(
            f"background:{BG_PANEL}; color:{TEXT_DIM}; "
            f"font-size:11px; font-weight:700; letter-spacing:1px; "
            f"border-top:1px solid {BORDER};"
        )
        layout.addWidget(header)

        splitter = QSplitter(Qt.Horizontal)

        # Layer tree
        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setAlternatingRowColors(True)
        self._tree.setMinimumWidth(280)
        splitter.addWidget(self._tree)

        # Hex dump
        self._hex = QTextEdit()
        self._hex.setReadOnly(True)
        self._hex.setFont(QFont("Consolas", 11))
        self._hex.setPlaceholderText("Hex dump will appear here…")
        splitter.addWidget(self._hex)

        splitter.setSizes([300, 400])
        layout.addWidget(splitter, 1)

    # ── Public API ─────────────────────────────────────────────────────────

    def show_packet(self, info: dict) -> None:
        """Populate the panel with packet info dict."""
        self._tree.clear()
        self._hex.clear()

        from src.utils.helpers import format_timestamp, get_port_service

        # ── Layer tree ─────────────────────────────────────────────────────
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

        add_section("Frame", [
            ("Timestamp",  format_timestamp(info.get("timestamp", 0))),
            ("Length",     f"{info.get('length', 0)} bytes"),
            ("Layers",     " / ".join(info.get("layers", []))),
        ])

        if info.get("src_mac") or info.get("dst_mac"):
            add_section("Ethernet", [
                ("Source MAC", info.get("src_mac", "")),
                ("Dest MAC",   info.get("dst_mac", "")),
            ])

        if info.get("src_ip"):
            add_section("Network", [
                ("Source IP",  info.get("src_ip", "")),
                ("Dest IP",    info.get("dst_ip", "")),
                ("Protocol",   info.get("protocol", "")),
            ])

        src_p = info.get("src_port")
        dst_p = info.get("dst_port")
        if src_p is not None:
            fields = [
                ("Source Port", f"{src_p}  ({get_port_service(src_p)})"),
                ("Dest Port",   f"{dst_p}  ({get_port_service(dst_p)})"),
            ]
            if info.get("flags"):
                fields.append(("TCP Flags", info["flags"]))
            add_section("Transport", fields)

        # DNS layer
        if info.get("dns_query") is not None:
            qr = info.get("dns_qr", 0)
            dns_fields = [
                ("Direction",      "Query" if qr == 0 else "Response"),
                ("Transaction ID", f"0x{info.get('dns_transaction_id', 0):04x}"),
                ("Query Name",     info.get("dns_query", "")),
                ("Query Type",     info.get("dns_qtype", "")),
            ]
            answers = info.get("dns_answers", [])
            if answers:
                for i, ans in enumerate(answers, 1):
                    dns_fields.append((f"Answer {i}", ans))
            elif qr == 1:
                dns_fields.append(("Answers", "(none)"))
            add_section("DNS", dns_fields)

        payload = info.get("payload", b"")
        if payload:
            try:
                text = payload[:512].decode("utf-8", errors="replace")
                add_section("Payload (text)", [("Data", text[:200])])
            except Exception:
                pass

        # ── Hex dump ───────────────────────────────────────────────────────
        if payload:
            lines = []
            for i in range(0, min(len(payload), 256), 16):
                chunk = payload[i: i + 16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                asc_part = "".join(
                    chr(b) if 32 <= b < 127 else "." for b in chunk
                )
                lines.append(f"  {i:04x}  {hex_part:<47}  {asc_part}")
            self._hex.setPlainText("\n".join(lines))
        else:
            self._hex.setPlainText("  (no payload)")

    def clear(self) -> None:
        self._tree.clear()
        self._hex.clear()
