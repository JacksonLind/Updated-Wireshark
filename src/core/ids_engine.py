"""
IDS (Intrusion Detection System) engine for NetGuard.

Rules implemented
-----------------
1.  Port Scan          - ≥15 distinct dst-ports contacted from same src in 10 s
2.  SYN Flood          - ≥50 SYN-only packets from same src in 5 s
3.  ICMP Flood         - ≥30 ICMP echo-requests from same src in 5 s
4.  ARP Spoofing       - same IP announced by ≥2 different MACs
5.  DNS Tunneling      - DNS query name longer than 80 characters
6.  Brute Force        - ≥20 TCP SYN packets to port 22/3389/21/23 in 30 s
7.  NULL Scan          - TCP packet with no flags set
8.  XMAS Scan          - TCP packet with FIN+PSH+URG set
9.  Large Packet       - single packet > 9000 bytes
10. HTTP Injection     - SQL/XSS patterns detected in HTTP payload
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

# ── Alert data class ─────────────────────────────────────────────────────────

@dataclass
class IDSAlert:
    alert_id:    int
    timestamp:   float
    severity:    str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category:    str          # e.g. "Port Scan"
    src_ip:      str
    dst_ip:      str
    description: str
    packet_info: str = ""
    raw_packet:  dict = field(default_factory=dict)


# ── IDS Engine ────────────────────────────────────────────────────────────────

class IDSEngine:
    """
    Stateful IDS engine.  Call ``check(pkt_info)`` for every captured packet.
    Provide an ``alert_callback`` to receive real-time alerts.
    """

    BRUTE_FORCE_PORTS = {22, 21, 23, 3389, 5900}
    SQL_PATTERNS = re.compile(
        r"(union\s+select|drop\s+table|or\s+1\s*=\s*1|insert\s+into"
        r"|select\s+\*|exec\s*\(|xp_cmdshell|information_schema)",
        re.IGNORECASE,
    )
    XSS_PATTERNS = re.compile(
        r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()",
        re.IGNORECASE,
    )

    def __init__(self, alert_callback: Callable[[IDSAlert], None] | None = None):
        self._callback = alert_callback
        self._alert_counter = 0

        # State trackers (src_ip → data)
        self._port_scan:    dict[str, dict] = defaultdict(lambda: {"ports": set(), "ts": 0.0})
        self._syn_flood:    dict[str, dict] = defaultdict(lambda: {"count": 0, "ts": 0.0})
        self._icmp_flood:   dict[str, dict] = defaultdict(lambda: {"count": 0, "ts": 0.0})
        self._brute_force:  dict[str, dict] = defaultdict(lambda: {"count": 0, "ts": 0.0})

        # ARP table: ip → set of MACs
        self._arp_table:    dict[str, set] = defaultdict(set)

        # Already-alerted keys to avoid spam (key → last alert time)
        self._alerted:      dict[str, float] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, info: dict) -> list[IDSAlert]:
        """Analyse one packet info dict and return any new alerts."""
        alerts: list[IDSAlert] = []
        now = info.get("timestamp", time.time())

        src = info.get("src_ip", "")
        dst = info.get("dst_ip", "")
        proto = info.get("protocol", "")
        flags = info.get("tcp_flags", {})
        src_port = info.get("src_port")
        dst_port = info.get("dst_port")
        length = info.get("length", 0)
        payload = info.get("payload", b"")

        # 1. Large Packet
        if length > 9000:
            alerts += self._alert(
                "large_pkt", now, "LOW", "Large Packet", src, dst,
                f"Packet of {length} bytes detected (> 9000 B).",
                info.get("info", ""),
            )

        # 2. ARP Spoofing
        if proto == "ARP":
            alerts += self._check_arp_spoof(info, now)
            return alerts

        # 3. NULL Scan
        if proto in ("TCP", "HTTP", "HTTPS", "SSH") and flags:
            if not any(flags.values()):
                alerts += self._alert(
                    f"null_{src}_{dst}", now, "HIGH", "NULL Scan", src, dst,
                    "TCP packet with no flags set – likely a NULL port scan.",
                    info.get("info", ""),
                )

            # 4. XMAS Scan
            if flags.get("FIN") and flags.get("PSH") and flags.get("URG"):
                alerts += self._alert(
                    f"xmas_{src}_{dst}", now, "HIGH", "XMAS Scan", src, dst,
                    "TCP FIN+PSH+URG flags set – likely an XMAS port scan.",
                    info.get("info", ""),
                )

            # 5. SYN Flood
            if flags.get("SYN") and not flags.get("ACK"):
                alerts += self._check_syn_flood(src, dst, now)

            # 6. Port Scan
            if dst_port is not None:
                alerts += self._check_port_scan(src, dst, dst_port, now)

            # 7. Brute Force
            if dst_port in self.BRUTE_FORCE_PORTS and flags.get("SYN") and not flags.get("ACK"):
                alerts += self._check_brute_force(src, dst, dst_port, now)

        # 8. UDP port scan (no flags, rapid distinct ports)
        if proto == "UDP" and dst_port is not None:
            alerts += self._check_port_scan(src, dst, dst_port, now)

        # 9. ICMP Flood
        if proto == "ICMP":
            alerts += self._check_icmp_flood(src, dst, now)

        # 10. DNS Tunneling
        if proto == "DNS":
            dns_info = info.get("info", "")
            qname_match = re.search(r"DNS (?:Query|Response): (.+)", dns_info)
            if qname_match:
                qname = qname_match.group(1).strip(".")
                if len(qname) > 80:
                    alerts += self._alert(
                        f"dns_tunnel_{src}", now, "HIGH", "DNS Tunneling", src, dst,
                        f"Unusually long DNS query ({len(qname)} chars): {qname[:60]}…",
                        dns_info,
                    )

        # 11. HTTP Injection
        if proto in ("HTTP", "TCP") and payload:
            try:
                text = payload.decode("utf-8", errors="ignore")
                if self.SQL_PATTERNS.search(text):
                    alerts += self._alert(
                        f"sqli_{src}_{dst}", now, "CRITICAL", "SQL Injection", src, dst,
                        "Possible SQL injection pattern detected in HTTP payload.",
                        info.get("info", ""),
                    )
                if self.XSS_PATTERNS.search(text):
                    alerts += self._alert(
                        f"xss_{src}_{dst}", now, "HIGH", "XSS Attempt", src, dst,
                        "Possible XSS pattern detected in HTTP payload.",
                        info.get("info", ""),
                    )
            except Exception:
                pass

        return alerts

    # ── Internal checks ───────────────────────────────────────────────────────

    def _check_port_scan(self, src, dst, dst_port, now) -> list[IDSAlert]:
        key = src
        state = self._port_scan[key]
        if now - state["ts"] > 10:
            state["ports"] = set()
            state["ts"] = now
        state["ports"].add(dst_port)
        if len(state["ports"]) >= 15:
            port_count = len(state["ports"])
            state["ports"] = set()  # reset after alert
            return self._alert(
                f"portscan_{src}", now, "HIGH", "Port Scan", src, dst,
                f"Port scan detected from {src} – {port_count} distinct ports probed in 10 s.",
                f"Latest dst port: {dst_port}",
            )
        return []

    def _check_syn_flood(self, src, dst, now) -> list[IDSAlert]:
        state = self._syn_flood[src]
        if now - state["ts"] > 5:
            state["count"] = 0
            state["ts"] = now
        state["count"] += 1
        if state["count"] >= 50:
            state["count"] = 0
            return self._alert(
                f"synflood_{src}", now, "CRITICAL", "SYN Flood", src, dst,
                f"SYN flood from {src}: ≥50 SYN packets in 5 s.",
                "",
            )
        return []

    def _check_icmp_flood(self, src, dst, now) -> list[IDSAlert]:
        state = self._icmp_flood[src]
        if now - state["ts"] > 5:
            state["count"] = 0
            state["ts"] = now
        state["count"] += 1
        if state["count"] >= 30:
            state["count"] = 0
            return self._alert(
                f"icmpflood_{src}", now, "HIGH", "ICMP Flood", src, dst,
                f"ICMP flood from {src}: ≥30 echo requests in 5 s.",
                "",
            )
        return []

    def _check_brute_force(self, src, dst, port, now) -> list[IDSAlert]:
        key = f"{src}:{port}"
        state = self._brute_force[key]
        if now - state["ts"] > 30:
            state["count"] = 0
            state["ts"] = now
        state["count"] += 1
        if state["count"] >= 20:
            state["count"] = 0
            from src.utils.helpers import get_port_service
            svc = get_port_service(port)
            return self._alert(
                f"bruteforce_{src}_{port}", now, "CRITICAL", "Brute Force", src, dst,
                f"Brute-force attack on {svc} (port {port}) from {src}: ≥20 attempts in 30 s.",
                "",
            )
        return []

    def _check_arp_spoof(self, info: dict, now: float) -> list[IDSAlert]:
        src_ip = info.get("src_ip", "")
        src_mac = info.get("src_mac", "")
        if not src_ip or not src_mac:
            return []

        existing = self._arp_table[src_ip]
        if src_mac not in existing and existing:
            existing.add(src_mac)
            return self._alert(
                f"arpspoof_{src_ip}", now, "CRITICAL", "ARP Spoofing", src_ip, "",
                f"ARP spoofing detected! IP {src_ip} announced by multiple MACs: "
                + ", ".join(existing),
                info.get("info", ""),
            )
        existing.add(src_mac)
        return []

    def _alert(
        self,
        dedup_key: str,
        now: float,
        severity: str,
        category: str,
        src: str,
        dst: str,
        description: str,
        packet_info: str,
        cooldown: float = 5.0,
    ) -> list[IDSAlert]:
        """Emit an alert, respecting a per-key cooldown to avoid spam."""
        last = self._alerted.get(dedup_key, -float("inf"))
        if now - last < cooldown:
            return []
        self._alerted[dedup_key] = now
        self._alert_counter += 1
        alert = IDSAlert(
            alert_id=self._alert_counter,
            timestamp=now,
            severity=severity,
            category=category,
            src_ip=src,
            dst_ip=dst,
            description=description,
            packet_info=packet_info,
        )
        if self._callback:
            self._callback(alert)
        return [alert]

    def reset(self) -> None:
        """Clear all state (called when a new capture session starts)."""
        self._port_scan.clear()
        self._syn_flood.clear()
        self._icmp_flood.clear()
        self._brute_force.clear()
        self._arp_table.clear()
        self._alerted.clear()
        self._alert_counter = 0
