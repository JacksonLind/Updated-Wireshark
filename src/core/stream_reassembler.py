"""
TCP / UDP stream reassembler for NetGuard.

Collects raw payload bytes for each bidirectional flow, ordered by
the sequence of arrival, and exposes the reconstructed conversation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StreamSegment:
    """One captured payload fragment belonging to a stream."""
    direction: str          # "→" (client→server) or "←" (server→client)
    src_ip:    str
    dst_ip:    str
    src_port:  Optional[int]
    dst_port:  Optional[int]
    timestamp: float
    data:      bytes


@dataclass
class Stream:
    """A reassembled bidirectional conversation."""
    key:      str
    protocol: str
    segments: list[StreamSegment] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(len(s.data) for s in self.segments)

    def conversation_text(self, max_bytes: int = 32_768) -> str:
        """
        Render the stream as a text conversation.

        Printable bytes are shown as-is; non-printable bytes are
        replaced with a dot.
        """
        parts: list[str] = []
        seen = 0
        for seg in self.segments:
            if seen >= max_bytes:
                parts.append("\n… (truncated)")
                break
            chunk = seg.data[:max_bytes - seen]
            seen += len(chunk)
            text = "".join(
                chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "."
                for b in chunk
            )
            parts.append(f"\n{seg.direction}  [{seg.src_ip}:{seg.src_port or '?'}]\n{text}")
        return "".join(parts).strip()


class StreamReassembler:
    """
    Collects packet info dicts and builds per-flow ``Stream`` objects.

    Call :meth:`process` for each packet; use :meth:`get_stream` to
    retrieve a stream by its canonical key, or :meth:`all_streams` to
    get every stream ordered by most-recently-updated.
    """

    # Track these protocols
    TRACKED = frozenset({"TCP", "HTTP", "HTTPS", "SSH", "DNS/TCP", "UDP", "DNS"})

    def __init__(self) -> None:
        self._streams: dict[str, Stream] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def process(self, info: dict) -> Optional[Stream]:
        """Update the matching stream with payload data from *info*."""
        proto = info.get("protocol", "")
        if proto not in self.TRACKED:
            return None

        payload = info.get("payload", b"")
        if not payload:
            return None

        src_ip   = info.get("src_ip", "")
        dst_ip   = info.get("dst_ip", "")
        src_port = info.get("src_port")
        dst_port = info.get("dst_port")

        key = self._make_key(src_ip, src_port, dst_ip, dst_port, proto)

        stream = self._streams.get(key)
        if stream is None:
            stream = Stream(key=key, protocol=proto)
            self._streams[key] = stream

        # Determine direction: lower-endpoint is always "client"
        a = (src_ip, src_port or 0)
        b = (dst_ip, dst_port or 0)
        direction = "→" if a <= b else "←"

        seg = StreamSegment(
            direction=direction,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            timestamp=info.get("timestamp", 0.0),
            data=payload,
        )
        stream.segments.append(seg)
        return stream

    def get_stream(self, key: str) -> Optional[Stream]:
        return self._streams.get(key)

    def get_stream_for_packet(self, info: dict) -> Optional[Stream]:
        """Return the stream that *info* belongs to (without adding it)."""
        proto    = info.get("protocol", "")
        src_ip   = info.get("src_ip", "")
        dst_ip   = info.get("dst_ip", "")
        src_port = info.get("src_port")
        dst_port = info.get("dst_port")
        key = self._make_key(src_ip, src_port, dst_ip, dst_port, proto)
        return self._streams.get(key)

    def all_streams(self) -> list[Stream]:
        """Return all streams sorted by total byte count (largest first)."""
        return sorted(
            self._streams.values(),
            key=lambda s: s.total_bytes,
            reverse=True,
        )

    def reset(self) -> None:
        self._streams.clear()

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _make_key(
        src_ip: str, src_port: Optional[int],
        dst_ip: str, dst_port: Optional[int],
        proto: str,
    ) -> str:
        a = (src_ip, src_port or 0)
        b = (dst_ip, dst_port or 0)
        if a > b:
            a, b = b, a
        return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}-{proto}"
