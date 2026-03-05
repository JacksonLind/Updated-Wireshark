"""
Statistics / Dashboard tab for NetGuard.

Shows live counters, protocol distribution, top talkers, and threat summary.
"""

from __future__ import annotations

from collections import defaultdict
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QFrame, QGroupBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView,
    QProgressBar,
)

from src.gui.theme import ACCENT, BG_PANEL, TEXT_DIM, BORDER, SEVERITY_PALETTE, PROTO_PALETTE, BG_DARK


class _StatCard(QFrame):
    """Single KPI card: large number + label."""

    def __init__(self, title: str, color: str = ACCENT, parent=None):
        super().__init__(parent)
        self.setFixedSize(170, 90)
        self.setStyleSheet(
            f"QFrame {{ background:{BG_PANEL}; border:1px solid {BORDER}; border-radius:8px; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        self._value = QLabel("0")
        self._value.setAlignment(Qt.AlignCenter)
        self._value.setStyleSheet(
            f"color:{color}; font-size:28px; font-weight:700; background:transparent;"
        )
        layout.addWidget(self._value)

        lbl = QLabel(title)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet(f"color:{TEXT_DIM}; font-size:10px; font-weight:600; background:transparent;")
        layout.addWidget(lbl)

    def set_value(self, v: int | str) -> None:
        if isinstance(v, int):
            self._value.setText(f"{v:,}")
        else:
            self._value.setText(str(v))


class _ProtoBar(QWidget):
    """Horizontal bar with label and percentage for protocol distribution."""

    def __init__(self, proto: str, parent=None):
        super().__init__(parent)
        self.proto = proto
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(8)

        self._label = QLabel(proto)
        self._label.setFixedWidth(70)
        self._label.setStyleSheet(
            f"color:{PROTO_PALETTE.get(proto, '#9e9e9e')}; font-size:12px; font-weight:600;"
        )
        layout.addWidget(self._label)

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(10)
        color = PROTO_PALETTE.get(proto, "#9e9e9e")
        self._bar.setStyleSheet(
            f"QProgressBar {{ background:{BG_PANEL}; border-radius:4px; border:none; }}"
            f"QProgressBar::chunk {{ background:{color}; border-radius:4px; }}"
        )
        layout.addWidget(self._bar, 1)

        self._pct = QLabel("0%")
        self._pct.setFixedWidth(38)
        self._pct.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._pct.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        layout.addWidget(self._pct)

    def update_value(self, pct: float) -> None:
        self._bar.setValue(int(pct))
        self._pct.setText(f"{pct:.0f}%")


class StatsTab(QWidget):
    """Live statistics dashboard."""

    PROTO_ROWS = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP", "ARP"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._proto_counts: dict[str, int] = defaultdict(int)
        self._src_counts:   dict[str, int] = defaultdict(int)
        self._alert_counts: dict[str, int] = defaultdict(int)
        self._total         = 0
        self._total_bytes   = 0
        self._alerts_total  = 0

        self._build_ui()

        # Refresh the UI every second to avoid per-packet redraws
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh)
        self._refresh_timer.start(1000)

    # ── Public API ─────────────────────────────────────────────────────────

    def record_packet(self, info: dict) -> None:
        proto = info.get("protocol", "Unknown")
        src   = info.get("src_ip", "—")
        self._proto_counts[proto] += 1
        self._src_counts[src]     += 1
        self._total               += 1
        self._total_bytes         += info.get("length", 0)

    def record_alert(self, severity: str) -> None:
        self._alert_counts[severity] += 1
        self._alerts_total           += 1

    def reset(self) -> None:
        self._proto_counts.clear()
        self._src_counts.clear()
        self._alert_counts.clear()
        self._total = 0
        self._total_bytes = 0
        self._alerts_total = 0
        self._refresh()

    # ── UI ─────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(16)

        # ── KPI cards row ──────────────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)

        self._card_total   = _StatCard("PACKETS",   ACCENT)
        self._card_bytes   = _StatCard("DATA",      "#4fc3f7")
        self._card_alerts  = _StatCard("ALERTS",    "#FF8800")
        self._card_critical = _StatCard("CRITICAL", "#FF4444")

        for card in (self._card_total, self._card_bytes, self._card_alerts, self._card_critical):
            cards_row.addWidget(card)
        cards_row.addStretch()
        main_layout.addLayout(cards_row)

        # ── Middle row: protocol bars + top talkers ─────────────────────────
        mid = QHBoxLayout()
        mid.setSpacing(16)

        # Protocol distribution
        proto_group = QGroupBox("Protocol Distribution")
        proto_group.setMinimumWidth(320)
        proto_layout = QVBoxLayout(proto_group)
        proto_layout.setSpacing(4)
        self._proto_bars: dict[str, _ProtoBar] = {}
        for p in self.PROTO_ROWS:
            bar = _ProtoBar(p)
            self._proto_bars[p] = bar
            proto_layout.addWidget(bar)
        proto_layout.addStretch()
        mid.addWidget(proto_group)

        # Top talkers
        talkers_group = QGroupBox("Top Talkers  (Source IPs)")
        talkers_layout = QVBoxLayout(talkers_group)
        talkers_layout.setContentsMargins(4, 8, 4, 4)

        self._talkers_table = QTableWidget(0, 3)
        self._talkers_table.setHorizontalHeaderLabels(["IP Address", "Packets", "Share"])
        self._talkers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._talkers_table.setColumnWidth(1, 70)
        self._talkers_table.setColumnWidth(2, 60)
        self._talkers_table.verticalHeader().setVisible(False)
        self._talkers_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._talkers_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._talkers_table.setAlternatingRowColors(True)
        self._talkers_table.setShowGrid(False)
        self._talkers_table.verticalHeader().setDefaultSectionSize(22)
        talkers_layout.addWidget(self._talkers_table)
        mid.addWidget(talkers_group, 1)

        main_layout.addLayout(mid)

        # ── Alert severity breakdown ────────────────────────────────────────
        sev_group = QGroupBox("Alert Severity Breakdown")
        sev_layout = QHBoxLayout(sev_group)
        sev_layout.setSpacing(12)
        self._sev_labels: dict[str, QLabel] = {}
        for sev, color in SEVERITY_PALETTE.items():
            card = QFrame()
            card.setFixedSize(140, 70)
            card.setStyleSheet(
                f"QFrame {{ background:{BG_PANEL}; border:1px solid {color}; border-radius:6px; }}"
            )
            cl = QVBoxLayout(card)
            cl.setContentsMargins(8, 6, 8, 6)
            cl.setSpacing(2)
            num = QLabel("0")
            num.setAlignment(Qt.AlignCenter)
            num.setStyleSheet(f"color:{color}; font-size:22px; font-weight:700; background:transparent;")
            cl.addWidget(num)
            name_lbl = QLabel(sev)
            name_lbl.setAlignment(Qt.AlignCenter)
            name_lbl.setStyleSheet(f"color:{TEXT_DIM}; font-size:10px; font-weight:600; background:transparent;")
            cl.addWidget(name_lbl)
            self._sev_labels[sev] = num
            sev_layout.addWidget(card)
        sev_layout.addStretch()
        main_layout.addWidget(sev_group)

    # ── Refresh ─────────────────────────────────────────────────────────────

    def _refresh(self) -> None:
        # KPI cards
        from src.utils.helpers import format_bytes
        self._card_total.set_value(self._total)
        self._card_bytes.set_value(format_bytes(self._total_bytes))
        self._card_alerts.set_value(self._alerts_total)
        self._card_critical.set_value(self._alert_counts.get("CRITICAL", 0))

        # Protocol bars
        total = max(self._total, 1)
        for proto, bar in self._proto_bars.items():
            bar.update_value(self._proto_counts.get(proto, 0) / total * 100)

        # Top talkers
        top = sorted(self._src_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        self._talkers_table.setRowCount(len(top))
        for row, (ip, count) in enumerate(top):
            pct = count / total * 100
            for col, val in enumerate([ip, str(count), f"{pct:.1f}%"]):
                item = QTableWidgetItem(val)
                item.setForeground(QColor("#e0e0e0"))
                item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                if col == 0:
                    item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                self._talkers_table.setItem(row, col, item)

        # Severity labels
        for sev, lbl in self._sev_labels.items():
            lbl.setText(str(self._alert_counts.get(sev, 0)))
