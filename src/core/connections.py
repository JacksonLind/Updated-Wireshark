"""
Connection / flow tracker for NetGuard.

Tracks active TCP and UDP flows derived from packet info dicts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


# Protocols that ConnectionTracker follows (also used for the UI filter)
TRACKED_PROTOCOLS = ("TCP", "UDP", "HTTP", "HTTPS", "SSH", "DNS", "DNS/TCP")


@dataclass
class Connection:
    """Represents a single bidirectional network flow."""

    key:         str
    protocol:    str
    src_ip:      str
    dst_ip:      str
    src_port:    Optional[int]
    dst_port:    Optional[int]
    state:       str        # ESTABLISHED / SYN / SYN-ACK / CLOSING / RESET / UDP
    first_seen:  float
    last_seen:   float
    packets:     int = 0
    bytes_total: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)


class ConnectionTracker:
    """
    Track TCP/UDP connections from a stream of packet info dicts.

    Call ``process(info)`` for each packet; call ``prune()`` periodically
    to drop stale entries.
    """

    TIMEOUT_TCP = 300.0   # 5 minutes
    TIMEOUT_UDP = 60.0    # 1 minute

    def __init__(self) -> None:
        self._connections: dict[str, Connection] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def process(self, info: dict) -> Optional[Connection]:
        """Update or create a connection for the packet.  Returns the flow."""
        proto    = info.get("protocol", "")
        src_ip   = info.get("src_ip", "")
        dst_ip   = info.get("dst_ip", "")
        src_port = info.get("src_port")
        dst_port = info.get("dst_port")

        # Only track flows with IP + port info
        if proto not in TRACKED_PROTOCOLS:
            return None
        if not src_ip or not dst_ip:
            return None

        key = self._make_key(src_ip, src_port, dst_ip, dst_port, proto)
        now    = info.get("timestamp", time.time())
        length = info.get("length", 0)
        flags  = info.get("tcp_flags", {})

        conn = self._connections.get(key)
        if conn is None:
            initial_state = "UDP" if proto == "UDP" else "SYN"
            conn = Connection(
                key=key,
                protocol=proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                state=initial_state,
                first_seen=now,
                last_seen=now,
            )
            self._connections[key] = conn

        conn.last_seen   = now
        conn.packets     += 1
        conn.bytes_total += length

        # Advance TCP state machine
        if proto in ("TCP", "HTTP", "HTTPS", "SSH", "DNS/TCP"):
            if flags.get("RST"):
                conn.state = "RESET"
            elif flags.get("FIN"):
                conn.state = "CLOSING"
            elif flags.get("SYN") and flags.get("ACK"):
                conn.state = "SYN-ACK"
            elif flags.get("ACK") and conn.state in ("SYN", "SYN-ACK"):
                conn.state = "ESTABLISHED"

        return conn

    def get_active(self) -> list[Connection]:
        """Return all connections sorted by most-recently-seen first."""
        return sorted(
            self._connections.values(),
            key=lambda c: c.last_seen,
            reverse=True,
        )

    def prune(self, now: Optional[float] = None) -> None:
        """Remove connections that have been idle beyond their timeout."""
        if now is None:
            now = time.time()
        stale = [
            key for key, conn in self._connections.items()
            if now - conn.last_seen > (
                self.TIMEOUT_UDP if conn.protocol == "UDP" else self.TIMEOUT_TCP
            )
        ]
        for key in stale:
            del self._connections[key]

    def reset(self) -> None:
        """Clear all tracked connections."""
        self._connections.clear()

    @property
    def count(self) -> int:
        return len(self._connections)

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _make_key(
        src_ip: str, src_port: Optional[int],
        dst_ip: str, dst_port: Optional[int],
        proto: str,
    ) -> str:
        """Build a bidirectional canonical key (A↔B == B↔A)."""
        a = (src_ip, src_port or 0)
        b = (dst_ip, dst_port or 0)
        if a > b:
            a, b = b, a
        return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}-{proto}"
