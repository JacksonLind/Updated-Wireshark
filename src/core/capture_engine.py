"""
Packet capture engine for NetGuard.

Uses Scapy to sniff on a selected network interface in a background thread.
Emits packets via a callback so the GUI remains fully responsive.

On Windows, Npcap (https://npcap.com) must be installed.
On Linux, the process must have CAP_NET_RAW (run as root or with sudo).
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from src.core.analyzer import analyze_packet


class CaptureEngine:
    """
    Thread-safe packet capture wrapper around Scapy's ``sniff()``.

    Parameters
    ----------
    packet_callback : callable
        Called from the capture thread with a single ``dict`` (packet info).
        The callback must be thread-safe (e.g. use Qt signals).
    error_callback : callable, optional
        Called when a fatal capture error occurs, with the exception as argument.
    """

    def __init__(
        self,
        packet_callback: Callable[[dict], None],
        error_callback:  Callable[[Exception], None] | None = None,
    ):
        self._pkt_cb   = packet_callback
        self._err_cb   = error_callback
        self._thread:  threading.Thread | None = None
        self._stop_evt = threading.Event()
        self._running  = False

        self.interface:    str  = ""
        self.bpf_filter:   str  = ""
        self.packet_count: int  = 0

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, interface: str = "", bpf_filter: str = "") -> None:
        """Start capturing packets on *interface* (empty = all interfaces)."""
        if self._running:
            return
        self.interface   = interface
        self.bpf_filter  = bpf_filter
        self.packet_count = 0
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="NetGuard-Capture",
        )
        self._running = True
        self._thread.start()

    def stop(self) -> None:
        """Signal the capture thread to stop and wait for it to exit."""
        if not self._running:
            return
        self._stop_evt.set()
        self._running = False
        if self._thread:
            self._thread.join(timeout=3.0)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _capture_loop(self) -> None:
        try:
            from scapy.all import sniff, conf
            conf.verb = 0  # silence Scapy output

            kwargs: dict = {
                "prn":      self._handle_packet,
                "store":    False,
                "stop_filter": lambda _: self._stop_evt.is_set(),
            }
            if self.interface:
                kwargs["iface"] = self.interface
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter

            sniff(**kwargs)
        except Exception as exc:
            self._running = False
            if self._err_cb:
                self._err_cb(exc)

    def _handle_packet(self, pkt) -> None:
        if self._stop_evt.is_set():
            return
        try:
            info = analyze_packet(pkt)
            self.packet_count += 1
            self._pkt_cb(info)
        except Exception:
            pass


# ── Interface enumeration ─────────────────────────────────────────────────────

def list_interfaces() -> list[str]:
    """
    Return a list of available network interface names.

    Falls back to an empty list if Scapy / Npcap are unavailable.
    """
    try:
        from scapy.all import get_if_list
        ifaces = get_if_list()
        return ifaces if ifaces else []
    except Exception:
        return []
