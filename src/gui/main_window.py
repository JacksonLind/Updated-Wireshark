"""
Main application window for NetGuard.

Hosts the toolbar, tabbed views, status bar, and wires together
the capture engine, IDS engine, and GUI tabs.
"""

from __future__ import annotations

import csv
import json
import os
import time
from pathlib import Path

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer
from PyQt5.QtGui import QIcon, QFont, QColor
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QToolBar, QComboBox, QLabel,
    QStatusBar, QAction, QFileDialog, QMessageBox,
    QDialog, QDialogButtonBox, QTextBrowser,
    QSplitter, QPushButton, QLineEdit,
)

from src.gui.capture_tab import CaptureTab
from src.gui.alerts_tab  import AlertsTab
from src.gui.stats_tab   import StatsTab
from src.gui.theme       import ACCENT, BG_PANEL, BORDER, TEXT_DIM, BG_DARK
from src.core.capture_engine import CaptureEngine, list_interfaces
from src.core.ids_engine     import IDSEngine, IDSAlert
from src.utils.helpers       import format_timestamp


# ── Qt-safe bridge: capture thread → main thread ─────────────────────────────

class _CaptureSignals(QObject):
    packet_received = pyqtSignal(dict)
    alert_raised    = pyqtSignal(object)   # IDSAlert
    error_occurred  = pyqtSignal(str)


class MainWindow(QMainWindow):
    """NetGuard main application window."""

    APP_NAME = "NetGuard"
    VERSION  = "1.0.0"

    def __init__(self):
        super().__init__()
        self._signals  = _CaptureSignals()
        self._engine   = CaptureEngine(
            packet_callback=self._on_packet_captured,
            error_callback=self._on_capture_error,
        )
        self._ids      = IDSEngine(alert_callback=self._on_alert_raised)
        self._captured: list[dict] = []
        self._running   = False

        self._build_ui()
        self._connect_signals()
        self._status("Ready — select an interface and press  ▶  Start")
        self.setWindowTitle(f"{self.APP_NAME}  {self.VERSION}")
        self.resize(1280, 800)

    # ── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Toolbar ────────────────────────────────────────────────────────
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        self.addToolBar(toolbar)

        # Interface selector
        self._iface_label = QLabel("  Interface: ")
        toolbar.addWidget(self._iface_label)

        self._iface_combo = QComboBox()
        self._iface_combo.setMinimumWidth(200)
        self._iface_combo.setToolTip("Select a network interface to capture on")
        self._populate_interfaces()
        toolbar.addWidget(self._iface_combo)

        toolbar.addSeparator()

        # BPF filter
        filter_label = QLabel("  Filter: ")
        toolbar.addWidget(filter_label)

        self._bpf_input = QLineEdit()
        self._bpf_input.setPlaceholderText("BPF filter (e.g. tcp port 80)")
        self._bpf_input.setMinimumWidth(180)
        self._bpf_input.setMaximumWidth(250)
        toolbar.addWidget(self._bpf_input)

        toolbar.addSeparator()

        # Start / Stop buttons
        self._start_action = QAction("▶  Start", self)
        self._start_action.setToolTip("Start capturing packets")
        self._start_action.triggered.connect(self._start_capture)
        toolbar.addAction(self._start_action)

        self._stop_action = QAction("■  Stop", self)
        self._stop_action.setToolTip("Stop capturing packets")
        self._stop_action.setEnabled(False)
        self._stop_action.triggered.connect(self._stop_capture)
        toolbar.addAction(self._stop_action)

        toolbar.addSeparator()

        open_action = QAction("📂  Open", self)
        open_action.setToolTip("Load packets from a .pcap / .pcapng file")
        open_action.triggered.connect(self._open_capture_file)
        toolbar.addAction(open_action)

        save_action = QAction("💾  Save", self)
        save_action.setToolTip("Export captured packets to CSV or JSON")
        save_action.triggered.connect(self._save_capture)
        toolbar.addAction(save_action)

        toolbar.addSeparator()

        help_action = QAction("❓  Help", self)
        help_action.setToolTip("Show the user guide")
        help_action.triggered.connect(self._show_help)
        toolbar.addAction(help_action)

        # ── Central widget ─────────────────────────────────────────────────
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        layout.addWidget(self._tabs)

        self._capture_tab = CaptureTab()
        self._alerts_tab  = AlertsTab()
        self._stats_tab   = StatsTab()

        self._tabs.addTab(self._capture_tab, "📡  Capture")
        self._tabs.addTab(self._alerts_tab,  "🚨  IDS Alerts")
        self._tabs.addTab(self._stats_tab,   "📊  Statistics")

        # ── Status bar ─────────────────────────────────────────────────────
        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)

        self._pkt_counter = QLabel("Packets: 0")
        self._pkt_counter.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        self._status_bar.addPermanentWidget(self._pkt_counter)

        self._alert_counter = QLabel("Alerts: 0")
        self._alert_counter.setStyleSheet(f"color:#FF8800; font-size:11px;")
        self._status_bar.addPermanentWidget(self._alert_counter)

        self._elapsed_label = QLabel("  00:00")
        self._elapsed_label.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        self._status_bar.addPermanentWidget(self._elapsed_label)

        # Elapsed timer
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.timeout.connect(self._update_elapsed)
        self._start_time: float = 0.0

    def _populate_interfaces(self) -> None:
        ifaces = list_interfaces()
        self._iface_combo.clear()
        if ifaces:
            self._iface_combo.addItem("All interfaces", "")
            for iface in ifaces:
                self._iface_combo.addItem(iface, iface)
        else:
            self._iface_combo.addItem("No interfaces found (check Npcap/root)", "")

    # ── Signal connections ──────────────────────────────────────────────────

    def _connect_signals(self) -> None:
        self._signals.packet_received.connect(self._handle_packet)
        self._signals.alert_raised.connect(self._handle_alert)
        self._signals.error_occurred.connect(self._handle_error)

    # ── Callbacks from capture / IDS threads ─────────────────────────────────

    def _on_packet_captured(self, info: dict) -> None:
        """Called from capture thread — emit signal to jump to main thread."""
        self._signals.packet_received.emit(info)

    def _on_alert_raised(self, alert: IDSAlert) -> None:
        """Called from capture thread — emit signal to jump to main thread."""
        self._signals.alert_raised.emit(alert)

    def _on_capture_error(self, exc: Exception) -> None:
        self._signals.error_occurred.emit(str(exc))

    # ── Main-thread handlers ────────────────────────────────────────────────

    def _handle_packet(self, info: dict) -> None:
        self._captured.append(info)
        self._capture_tab.add_packet(info)
        self._stats_tab.record_packet(info)

        # Run IDS — attach the triggering packet so the Alerts tab can show details
        alerts = self._ids.check(info)
        for alert in alerts:
            alert.raw_packet = info
            self._handle_alert(alert)

        count = len(self._captured)
        self._pkt_counter.setText(f"Packets: {count:,}")

    def _handle_alert(self, alert: IDSAlert) -> None:
        self._alerts_tab.add_alert(alert)
        self._stats_tab.record_alert(alert.severity)
        self._alert_counter.setText(f"Alerts: {self._stats_tab._alerts_total}")
        # Flash to the alerts tab badge (optional: bold if new alert)

    def _handle_error(self, msg: str) -> None:
        self._running = False
        self._start_action.setEnabled(True)
        self._stop_action.setEnabled(False)
        QMessageBox.critical(
            self,
            "Capture Error",
            f"<b>Capture failed:</b><br><br>{msg}"
            "<br><br><b>Common causes:</b>"
            "<ul>"
            "<li>On Windows: Npcap not installed — download from <a href='https://npcap.com'>npcap.com</a></li>"
            "<li>On Linux: run with <code>sudo</code> or grant CAP_NET_RAW</li>"
            "</ul>",
        )

    # ── Capture control ─────────────────────────────────────────────────────

    def _start_capture(self) -> None:
        if self._running:
            return

        iface = self._iface_combo.currentData() or ""
        bpf   = self._bpf_input.text().strip()

        self._ids.reset()
        self._captured.clear()
        self._capture_tab.clear()
        self._alerts_tab.clear()
        self._stats_tab.reset()

        self._engine.start(interface=iface, bpf_filter=bpf)
        self._running = True
        self._start_action.setEnabled(False)
        self._stop_action.setEnabled(True)
        self._start_time = time.time()
        self._elapsed_timer.start(1000)
        self._status(f"Capturing on  {iface or 'all interfaces'}…")

    def _stop_capture(self) -> None:
        if not self._running:
            return
        self._engine.stop()
        self._running = False
        self._start_action.setEnabled(True)
        self._stop_action.setEnabled(False)
        self._elapsed_timer.stop()
        count = len(self._captured)
        self._status(f"Capture stopped — {count:,} packets captured.")

    def _update_elapsed(self) -> None:
        elapsed = int(time.time() - self._start_time)
        m, s = divmod(elapsed, 60)
        self._elapsed_label.setText(f"  {m:02d}:{s:02d}")

    # ── Open capture file ────────────────────────────────────────────────────

    def _open_capture_file(self) -> None:
        """Load packets from a .pcap or .pcapng file for offline analysis."""
        if self._running:
            QMessageBox.warning(
                self,
                "Capture in progress",
                "Stop the live capture before loading a file.",
            )
            return

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Capture File",
            str(Path.home()),
            "Capture Files (*.pcap *.pcapng *.cap);;All Files (*)",
        )
        if not path:
            return

        try:
            from scapy.all import rdpcap
            from src.core.analyzer import analyze_packet

            self._ids.reset()
            self._captured.clear()
            self._capture_tab.clear()
            self._alerts_tab.clear()
            self._stats_tab.reset()

            raw_packets = rdpcap(path)
            for pkt in raw_packets:
                info = analyze_packet(pkt)
                self._captured.append(info)
                self._capture_tab.add_packet(info)
                self._stats_tab.record_packet(info)
                for alert in self._ids.check(info):
                    self._handle_alert(alert)

            count = len(self._captured)
            self._pkt_counter.setText(f"Packets: {count:,}")
            self._status(
                f"Loaded {count:,} packet{'s' if count != 1 else ''} from {Path(path).name}"
            )
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Open Error",
                f"<b>Could not load capture file:</b><br><br>{exc}",
            )

    # ── Save capture ────────────────────────────────────────────────────────

    def _save_capture(self) -> None:
        if not self._captured:
            QMessageBox.information(self, "Nothing to save", "No packets have been captured yet.")
            return

        path, filt = QFileDialog.getSaveFileName(
            self, "Save Capture",
            str(Path.home() / "netguard_capture"),
            "CSV Files (*.csv);;JSON Files (*.json)",
        )
        if not path:
            return

        try:
            if path.endswith(".json"):
                safe = []
                for p in self._captured:
                    d = {k: v for k, v in p.items() if k not in ("payload", "tcp_flags")}
                    safe.append(d)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(safe, f, indent=2)
            else:
                fields = ["timestamp", "src_ip", "dst_ip", "protocol",
                          "src_port", "dst_port", "length", "flags", "info"]
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(self._captured)

            QMessageBox.information(self, "Saved", f"Capture saved to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Save Error", str(exc))

    # ── Help ────────────────────────────────────────────────────────────────

    def _show_help(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle(f"{self.APP_NAME} — User Guide")
        dlg.resize(700, 560)
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(16, 16, 16, 16)

        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)

        # Load docs/USER_GUIDE.md if available, else inline text
        guide_path = Path(__file__).parent.parent.parent / "docs" / "USER_GUIDE.md"
        if guide_path.exists():
            browser.setMarkdown(guide_path.read_text(encoding="utf-8"))
        else:
            browser.setPlainText(
                "User guide not found.\n\n"
                "Please see docs/USER_GUIDE.md in the repository."
            )

        layout.addWidget(browser)
        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.accept)
        layout.addWidget(btns)
        dlg.exec_()

    # ── Status bar helper ───────────────────────────────────────────────────

    def _status(self, msg: str) -> None:
        self._status_bar.showMessage(f"  {msg}")

    # ── Window close ────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        if self._running:
            self._engine.stop()
        # Wait for the capture thread to finish before allowing the app to exit
        self._engine.join_thread(timeout=3.0)
        event.accept()
