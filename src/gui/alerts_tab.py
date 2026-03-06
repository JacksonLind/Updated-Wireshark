"""
IDS Alerts tab for NetGuard.

Real-time table of intrusion-detection alerts, colour-coded by severity.
Clicking a row opens a full packet-detail panel at the bottom.
Double-clicking a row opens a full packet-detail popup for deeper analysis.
"""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QPushButton, QAbstractItemView,
    QComboBox, QSplitter, QFileDialog, QMessageBox,
)

from src.gui.theme import SEVERITY_PALETTE, BG_PANEL, TEXT_DIM, BORDER, ACCENT
from src.gui.detail_panel import DetailPanel
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
    """Displays IDS alerts in real-time with a clickable detail panel."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._alerts: list[IDSAlert] = []
        # Parallel list that tracks which alert corresponds to each visible row
        self._visible_alerts: list[IDSAlert] = []
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
        self._visible_alerts.clear()
        self._table.setRowCount(0)
        self._count_label.setText("0 alerts")
        self._detail.clear()

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
            "All", "Port Scan", "SYN Flood", "ICMP Flood", "UDP Flood",
            "ARP Spoofing", "DNS Tunneling", "Brute Force", "HTTP Brute Force",
            "NULL Scan", "XMAS Scan", "FIN Scan",
            "Large Packet", "SQL Injection", "XSS Attempt",
            "Credential Harvesting",
            "Traffic Spike", "Unusual Packet Size", "Protocol Shift", "New Talker",
        ])
        self._cat_filter.currentTextChanged.connect(self._apply_filter)
        bar_layout.addWidget(self._cat_filter)

        bar_layout.addStretch()

        self._count_label = QLabel("0 alerts")
        self._count_label.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        bar_layout.addWidget(self._count_label)

        export_btn = QPushButton("Export")
        export_btn.setProperty("secondary", "true")
        export_btn.setFixedWidth(70)
        export_btn.setToolTip("Save alerts to CSV or JSON")
        export_btn.clicked.connect(self._export_alerts)
        bar_layout.addWidget(export_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setProperty("secondary", "true")
        clear_btn.setFixedWidth(70)
        clear_btn.clicked.connect(self.clear)
        bar_layout.addWidget(clear_btn)

        outer.addWidget(bar)

        # ── Splitter: alerts table (top) + packet detail (bottom) ──────────
        splitter = QSplitter(Qt.Vertical)

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
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(False)
        self._table.verticalHeader().setDefaultSectionSize(24)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.currentItemChanged.connect(
            lambda cur, _: self._on_row_selected(cur.row() if cur is not None else -1)
        )
        self._table.cellDoubleClicked.connect(self._on_row_double_clicked)
        splitter.addWidget(self._table)

        # Packet detail panel
        self._detail = DetailPanel()
        splitter.addWidget(self._detail)

        splitter.setSizes([400, 200])
        outer.addWidget(splitter, 1)

        # Bottom info strip
        info_bar = QLabel(
            "  ⚠  Alerts are raised in real-time as suspicious patterns are detected. "
            "Click a row to inspect the triggering packet.  "
            "Double-click a row to open a full packet analysis popup."
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
        self._visible_alerts.append(alert)

        sev_color = QColor(SEVERITY_PALETTE.get(alert.severity, "#ccc"))

        # Dim tint colors for row background by severity
        _SEV_ROW_BG = {
            "CRITICAL": "#2d1010",
            "HIGH":     "#2d1d08",
            "MEDIUM":   "#2d2b08",
            "LOW":      "#08182d",
            "INFO":     "#0a1f0a",
        }
        row_bg = QColor(_SEV_ROW_BG.get(alert.severity, BG_PANEL))

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
            item.setBackground(row_bg)
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

    def _on_row_selected(self, row: int) -> None:
        """Show packet details for the selected alert row."""
        if 0 <= row < len(self._visible_alerts):
            alert = self._visible_alerts[row]
            self._detail.show_packet(self._get_alert_packet_info(alert))

    def _on_row_double_clicked(self, row: int, _col: int) -> None:
        """Open a full packet detail popup when the user double-clicks an alert row."""
        if not (0 <= row < len(self._visible_alerts)):
            return
        alert = self._visible_alerts[row]
        from src.gui.packet_detail_dialog import PacketDetailDialog
        dlg = PacketDetailDialog(
            self._get_alert_packet_info(alert),
            pkt_number=alert.alert_id,
            parent=self,
        )
        dlg.setWindowTitle(
            f"Alert #{alert.alert_id}  [{alert.severity}]  —  {alert.category}"
        )
        dlg.show()

    def _get_alert_packet_info(self, alert: IDSAlert) -> dict:
        """Return the packet info dict for an alert.

        If the alert carries the full triggering packet, that is returned.
        Otherwise a minimal synthetic dict is built from the alert fields.
        """
        if alert.raw_packet and 'timestamp' in alert.raw_packet:
            return alert.raw_packet
        return {
            "timestamp": alert.timestamp,
            "src_ip":    alert.src_ip,
            "dst_ip":    alert.dst_ip,
            "protocol":  alert.category,
            "src_port":  None,
            "dst_port":  None,
            "length":    0,
            "layers":    [],
            "flags":     "",
            "payload":   b"",
            "info":      alert.description,
        }

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
        self._visible_alerts.clear()
        self._detail.clear()
        for alert in self._alerts:
            if self._passes_filter(alert):
                self._append_row(alert)

    def _export_alerts(self) -> None:
        """Save all alerts to CSV or JSON."""
        if not self._alerts:
            QMessageBox.information(self, "No Alerts", "No alerts to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Alerts",
            str(Path.home() / "netguard_alerts"),
            "CSV Files (*.csv);;JSON Files (*.json)",
        )
        if not path:
            return

        try:
            if path.endswith(".json"):
                data = [
                    {
                        "id":          a.alert_id,
                        "timestamp":   a.timestamp,
                        "severity":    a.severity,
                        "category":    a.category,
                        "src_ip":      a.src_ip,
                        "dst_ip":      a.dst_ip,
                        "description": a.description,
                    }
                    for a in self._alerts
                ]
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            else:
                fields = ["id", "timestamp", "severity", "category",
                          "src_ip", "dst_ip", "description"]
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=fields)
                    writer.writeheader()
                    for a in self._alerts:
                        writer.writerow({
                            "id":          a.alert_id,
                            "timestamp":   a.timestamp,
                            "severity":    a.severity,
                            "category":    a.category,
                            "src_ip":      a.src_ip,
                            "dst_ip":      a.dst_ip,
                            "description": a.description,
                        })
            QMessageBox.information(self, "Exported", f"Alerts saved to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))
