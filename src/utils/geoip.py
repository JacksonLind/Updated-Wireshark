"""
Lightweight IP-address classification helper for NetGuard.

Provides:
- RFC 1918 / special range detection (private, loopback, link-local, …)
- Country/region hint derived from the reverse-DNS label when available
- A simple in-process async lookup cache so the UI never blocks
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
from typing import Optional


# ── Special-range classification ──────────────────────────────────────────────

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),        # IPv6 ULA
]
_LOOPBACK_V4  = ipaddress.ip_network("127.0.0.0/8")
_LOOPBACK_V6  = ipaddress.ip_network("::1/128")
_LINK_LOCAL   = ipaddress.ip_network("169.254.0.0/16")
_LINK_LOCAL6  = ipaddress.ip_network("fe80::/10")
_MULTICAST_V4 = ipaddress.ip_network("224.0.0.0/4")
_MULTICAST_V6 = ipaddress.ip_network("ff00::/8")
_BROADCAST    = ipaddress.ip_network("255.255.255.255/32")
_DOCUMENTATION = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def classify_ip(ip: str) -> str:
    """
    Return a short human-readable category for *ip*.

    Examples: "Private", "Loopback", "Link-Local", "Multicast",
              "Broadcast", "Public", "Unknown"
    """
    if not ip:
        return "Unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "Unknown"

    if addr == ipaddress.ip_address("255.255.255.255"):
        return "Broadcast"
    if addr.is_loopback:
        return "Loopback"
    if addr.is_link_local:
        return "Link-Local"
    if addr.is_multicast:
        return "Multicast"
    for net in _PRIVATE_NETS:
        if addr in net:
            return "Private"
    for net in _DOCUMENTATION:
        if addr in net:
            return "Documentation"
    if addr.is_private:
        return "Private"
    if addr.is_global:
        return "Public"
    return "Special"


def is_private(ip: str) -> bool:
    return classify_ip(ip) in ("Private", "Loopback", "Link-Local")


# ── Icon / emoji for classification ──────────────────────────────────────────

_CLASS_ICON = {
    "Private":       "🏠",
    "Loopback":      "🔄",
    "Link-Local":    "🔗",
    "Multicast":     "📡",
    "Broadcast":     "📢",
    "Public":        "🌐",
    "Documentation": "📄",
    "Special":       "⚙️",
    "Unknown":       "❓",
}


def ip_icon(ip: str) -> str:
    return _CLASS_ICON.get(classify_ip(ip), "❓")


def ip_badge(ip: str) -> str:
    """Return 'icon Classification' string, e.g. '🏠 Private'."""
    cls = classify_ip(ip)
    return f"{_CLASS_ICON.get(cls, '❓')} {cls}"


# ── Async reverse-DNS with cache ──────────────────────────────────────────────

class GeoIPCache:
    """
    Thread-safe cache of IP → (hostname, classification) pairs.

    Reverse-DNS lookups run in a daemon thread so the GUI never blocks.
    """

    def __init__(self, timeout: float = 2.0) -> None:
        self._timeout = timeout
        self._cache: dict[str, tuple[str, str]] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()

    def lookup(self, ip: str) -> tuple[str, str]:
        """
        Return *(hostname, classification)* immediately.

        If a reverse-DNS lookup is not yet complete, the hostname field
        will be an empty string.  Call this method repeatedly (e.g. from
        a refresh timer) to pick up completed results.
        """
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
            if ip not in self._pending:
                self._pending.add(ip)
                t = threading.Thread(
                    target=self._resolve, args=(ip,), daemon=True
                )
                t.start()
        return ("", classify_ip(ip))

    def get_cached(self, ip: str) -> Optional[tuple[str, str]]:
        """Return cached *(hostname, classification)* or *None* if not yet resolved."""
        with self._lock:
            return self._cache.get(ip)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._pending.clear()

    def _resolve(self, ip: str) -> None:
        hostname = ""
        try:
            result: list[str] = []

            def _do() -> None:
                try:
                    result.append(socket.gethostbyaddr(ip)[0])
                except Exception:
                    pass

            t = threading.Thread(target=_do, daemon=True)
            t.start()
            t.join(timeout=self._timeout)
            if result:
                hostname = result[0]
        except Exception:
            pass

        cls = classify_ip(ip)
        with self._lock:
            self._cache[ip] = (hostname, cls)
            self._pending.discard(ip)


# Module-level singleton so all tabs share one cache
_default_cache = GeoIPCache()


def lookup(ip: str) -> tuple[str, str]:
    """Module-level shortcut – uses the shared default cache."""
    return _default_cache.lookup(ip)


def get_cached(ip: str) -> Optional[tuple[str, str]]:
    return _default_cache.get_cached(ip)


def clear_cache() -> None:
    _default_cache.clear()
