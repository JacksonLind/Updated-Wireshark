"""
Statistical Anomaly Detection Engine for NetGuard.

Uses rolling-window baselines and z-score analysis to detect unusual
traffic patterns without requiring any external ML libraries.

Detections
----------
1.  Traffic Spike      — per-source packet rate suddenly exceeds baseline (>5×)
2.  Unusual Packet Size — single packet size is >3σ above the rolling mean
3.  Protocol Shift     — a protocol appears far more than its baseline share
4.  New Talker         — a previously-unseen source IP suddenly generates traffic
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Deque


# ── Anomaly event data class ─────────────────────────────────────────────────

@dataclass
class AnomalyEvent:
    timestamp:    float
    anomaly_type: str          # e.g. "Traffic Spike"
    severity:     str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    src_ip:       str
    description:  str
    score:        float = 0.0  # z-score or ratio that triggered this event


# ── Anomaly Engine ───────────────────────────────────────────────────────────

class AnomalyEngine:
    """
    Stateful anomaly detector.  Call ``analyze(pkt_info)`` for every packet.
    Optionally provide an ``event_callback`` to receive real-time events.
    """

    # Rolling-window durations (seconds)
    _RATE_WINDOW   = 60    # lookback window for rate baseline
    _RECENT_WINDOW = 10    # "recent" bucket compared against baseline
    _PROTO_WINDOW  = 200   # last N packets for protocol distribution

    # Tuning
    _MIN_BASELINE_PKTS = 30   # min packets before raising rate anomalies
    _RATE_SPIKE_RATIO  = 5.0  # raise alert if recent_rate > 5× baseline_rate
    _SIZE_ZSCORE_MIN   = 3.0  # z-score threshold for packet-size anomaly
    _SIZE_MIN_SAMPLES  = 50   # min samples before raising size anomalies
    _PROTO_SHIFT_MIN_SAMPLES = 100
    _PROTO_SHIFT_RATIO = 3.0  # protocol fraction is 3× its usual share

    # De-duplicate cooldowns (seconds)
    _RATE_COOLDOWN  = 30
    _SIZE_COOLDOWN  = 60
    _PROTO_COOLDOWN = 120
    _NEW_IP_COOLDOWN = 30

    def __init__(self, event_callback: Callable[[AnomalyEvent], None] | None = None):
        self._callback = event_callback

        # Per-IP packet timestamps  (deque keeps last 1000 timestamps per IP)
        self._ip_timestamps: dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=1000)
        )

        # Global rolling packet sizes
        self._size_window: Deque[int] = deque(maxlen=500)

        # Protocol distribution (rolling last N packets)
        self._proto_window: Deque[str] = deque(maxlen=self._PROTO_WINDOW)

        # Known source IPs (for "new talker" detection after baselining)
        self._known_ips: set[str] = set()
        self._total_packets: int = 0

        # De-duplication: event_key → last alert timestamp
        self._last_alerted: dict[str, float] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, info: dict) -> list[AnomalyEvent]:
        """Analyse one packet; return any new AnomalyEvent objects."""
        events: list[AnomalyEvent] = []
        now   = info.get("timestamp", time.time())
        src   = info.get("src_ip", "")
        proto = info.get("protocol", "Unknown")
        size  = info.get("length", 0)

        self._total_packets += 1

        # Update per-IP rate tracker
        if src:
            self._ip_timestamps[src].append(now)
            events += self._check_traffic_spike(src, now)
            events += self._check_new_talker(src, now)

        # Update size baseline
        self._size_window.append(size)
        if src:
            events += self._check_size_anomaly(size, src, now)

        # Update protocol window
        self._proto_window.append(proto)
        events += self._check_protocol_shift(proto, now)

        return events

    def reset(self) -> None:
        """Clear all state (call when starting a new capture session)."""
        self._ip_timestamps.clear()
        self._size_window.clear()
        self._proto_window.clear()
        self._known_ips.clear()
        self._total_packets = 0
        self._last_alerted.clear()

    # ── Internal checks ───────────────────────────────────────────────────────

    def _check_traffic_spike(self, src: str, now: float) -> list[AnomalyEvent]:
        timestamps = self._ip_timestamps[src]

        # Count packets in the "recent" bucket
        recent = sum(1 for t in timestamps if now - t <= self._RECENT_WINDOW)

        # Count packets in the "baseline" bucket (older than recent, within window)
        baseline_pkts = sum(
            1 for t in timestamps
            if self._RECENT_WINDOW < now - t <= self._RATE_WINDOW
        )

        if baseline_pkts < self._MIN_BASELINE_PKTS:
            return []

        # Normalise to per-10-second rate
        baseline_periods = (self._RATE_WINDOW - self._RECENT_WINDOW) / self._RECENT_WINDOW
        baseline_rate = baseline_pkts / max(baseline_periods, 1)
        if baseline_rate < 1:
            return []

        ratio = recent / baseline_rate
        if ratio < self._RATE_SPIKE_RATIO:
            return []

        return self._emit(
            key=f"spike_{src}",
            cooldown=self._RATE_COOLDOWN,
            now=now,
            anomaly_type="Traffic Spike",
            severity="HIGH" if ratio >= 10 else "MEDIUM",
            src_ip=src,
            description=(
                f"Traffic spike from {src}: {recent} pkt/{self._RECENT_WINDOW}s "
                f"vs baseline {baseline_rate:.1f} pkt/{self._RECENT_WINDOW}s "
                f"({ratio:.1f}× above normal)"
            ),
            score=ratio,
        )

    def _check_new_talker(self, src: str, now: float) -> list[AnomalyEvent]:
        # Only flag new IPs after we have seen enough traffic to call it "new"
        if self._total_packets < self._MIN_BASELINE_PKTS:
            self._known_ips.add(src)
            return []
        if src in self._known_ips:
            return []
        self._known_ips.add(src)
        return self._emit(
            key=f"new_ip_{src}",
            cooldown=self._NEW_IP_COOLDOWN,
            now=now,
            anomaly_type="New Talker",
            severity="INFO",
            src_ip=src,
            description=f"First-seen source IP: {src} (not observed in the initial baseline)",
            score=1.0,
        )

    def _check_size_anomaly(self, size: int, src: str, now: float) -> list[AnomalyEvent]:
        if len(self._size_window) < self._SIZE_MIN_SAMPLES:
            return []
        data = list(self._size_window)
        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        stddev = math.sqrt(variance)
        if stddev < 1:
            return []
        zscore = (size - mean) / stddev
        if zscore < self._SIZE_ZSCORE_MIN:
            return []
        return self._emit(
            key=f"size_{src}",
            cooldown=self._SIZE_COOLDOWN,
            now=now,
            anomaly_type="Unusual Packet Size",
            severity="LOW",
            src_ip=src,
            description=(
                f"Packet from {src} is {size}B — {zscore:.1f}σ above mean "
                f"(μ={mean:.0f}B, σ={stddev:.0f}B)"
            ),
            score=zscore,
        )

    def _check_protocol_shift(self, proto: str, now: float) -> list[AnomalyEvent]:
        if len(self._proto_window) < self._PROTO_SHIFT_MIN_SAMPLES:
            return []
        # Compare last 20 packets vs the full window
        recent_slice = list(self._proto_window)[-20:]
        recent_frac = recent_slice.count(proto) / len(recent_slice)
        baseline_frac = list(self._proto_window).count(proto) / len(self._proto_window)
        if baseline_frac < 0.01:
            return []  # too rare to baseline
        ratio = recent_frac / baseline_frac
        if ratio < self._PROTO_SHIFT_RATIO:
            return []
        return self._emit(
            key=f"proto_{proto}",
            cooldown=self._PROTO_COOLDOWN,
            now=now,
            anomaly_type="Protocol Shift",
            severity="LOW",
            src_ip="",
            description=(
                f"Protocol {proto} is {ratio:.1f}× above its baseline share "
                f"({recent_frac:.0%} recently vs {baseline_frac:.0%} baseline)"
            ),
            score=ratio,
        )

    # ── Helper ────────────────────────────────────────────────────────────────

    def _emit(
        self,
        key: str,
        cooldown: float,
        now: float,
        anomaly_type: str,
        severity: str,
        src_ip: str,
        description: str,
        score: float,
    ) -> list[AnomalyEvent]:
        last = self._last_alerted.get(key, -float("inf"))
        if now - last < cooldown:
            return []
        self._last_alerted[key] = now
        event = AnomalyEvent(
            timestamp=now,
            anomaly_type=anomaly_type,
            severity=severity,
            src_ip=src_ip,
            description=description,
            score=score,
        )
        if self._callback:
            self._callback(event)
        return [event]
