"""
Protocol analyzer for NetGuard.

Provides a pure-Python layer that parses Scapy packets into a
flat dictionary that the GUI can display without importing Scapy
in every UI module.
"""

from __future__ import annotations
from typing import Any
from src.utils.helpers import get_protocol_name, get_port_service, format_mac


def analyze_packet(pkt) -> dict[str, Any]:
    """
    Accept a Scapy packet and return a flat info dictionary.

    Keys guaranteed to be present
    -----------------------------
    timestamp   float   capture time (epoch seconds)
    src_ip      str
    dst_ip      str
    src_mac     str
    dst_mac     str
    protocol    str     e.g. "TCP", "UDP", "ICMP"
    src_port    int | None
    dst_port    int | None
    length      int     total packet length in bytes
    info        str     one-line summary
    layers      list[str]   ordered layer names
    raw_summary str     Scapy summary string
    flags       str     TCP flags as string (or "")
    payload     bytes   innermost raw payload (may be empty)
    tcp_flags   dict    individual flag booleans (SYN/ACK/RST/FIN/PSH/URG)
    """
    result: dict[str, Any] = {
        "timestamp":   getattr(pkt, "time", 0.0),
        "src_ip":      "",
        "dst_ip":      "",
        "src_mac":     "",
        "dst_mac":     "",
        "protocol":    "Unknown",
        "src_port":    None,
        "dst_port":    None,
        "length":      len(pkt),
        "info":        "",
        "layers":      [],
        "raw_summary": pkt.summary(),
        "flags":       "",
        "payload":     b"",
        "tcp_flags":   {f: False for f in ("SYN", "ACK", "RST", "FIN", "PSH", "URG")},
    }

    try:
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.dns import DNS
        from scapy.packet import Raw

        layers = []
        layer = pkt
        while layer:
            layers.append(type(layer).__name__)
            layer = layer.payload if hasattr(layer, "payload") and layer.payload else None

        result["layers"] = layers

        # Ethernet
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            result["src_mac"] = eth.src or ""
            result["dst_mac"] = eth.dst or ""

        # ARP
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            result["protocol"] = "ARP"
            result["src_ip"] = arp.psrc or ""
            result["dst_ip"] = arp.pdst or ""
            op = "Request" if arp.op == 1 else "Reply"
            result["info"] = f"ARP {op}: who has {arp.pdst}? Tell {arp.psrc}"
            return result

        # IP
        if pkt.haslayer(IP):
            ip = pkt[IP]
            result["src_ip"] = ip.src or ""
            result["dst_ip"] = ip.dst or ""
            result["protocol"] = get_protocol_name(ip.proto)

        # IPv6
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            result["src_ip"] = ip6.src or ""
            result["dst_ip"] = ip6.dst or ""
            result["protocol"] = "IPv6"

        # TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            result["src_port"] = tcp.sport
            result["dst_port"] = tcp.dport
            result["protocol"] = "TCP"

            flag_int = int(tcp.flags)
            flag_names = {
                "FIN": 0x01, "SYN": 0x02, "RST": 0x04,
                "PSH": 0x08, "ACK": 0x10, "URG": 0x20,
            }
            active = [name for name, bit in flag_names.items() if flag_int & bit]
            result["flags"] = " ".join(active)
            result["tcp_flags"] = {name: bool(flag_int & bit) for name, bit in flag_names.items()}

            # Refine protocol label for well-known ports
            for port in (tcp.sport, tcp.dport):
                if port in (80, 8080):
                    result["protocol"] = "HTTP"
                    break
                if port in (443, 8443):
                    result["protocol"] = "HTTPS"
                    break
                if port == 53:
                    result["protocol"] = "DNS/TCP"
                    break
                if port == 22:
                    result["protocol"] = "SSH"
                    break

            src_svc = get_port_service(tcp.sport)
            dst_svc = get_port_service(tcp.dport)
            result["info"] = (
                f"{result['src_ip']}:{src_svc} → {result['dst_ip']}:{dst_svc}"
                f"  [{result['flags']}]  Seq={tcp.seq}"
            )

        # UDP
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            result["src_port"] = udp.sport
            result["dst_port"] = udp.dport
            result["protocol"] = "UDP"

            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                result["protocol"] = "DNS"
                if dns.qd:
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode(errors="replace")
                    result["info"] = f"DNS {'Query' if dns.qr == 0 else 'Response'}: {qname}"
                else:
                    result["info"] = "DNS"
            else:
                src_svc = get_port_service(udp.sport)
                dst_svc = get_port_service(udp.dport)
                result["info"] = (
                    f"{result['src_ip']}:{src_svc} → {result['dst_ip']}:{dst_svc}"
                    f"  Len={udp.len}"
                )

        # ICMP
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            types = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
            icmp_type = types.get(icmp.type, f"Type {icmp.type}")
            result["protocol"] = "ICMP"
            result["info"] = (
                f"ICMP {icmp_type}: {result['src_ip']} → {result['dst_ip']}"
            )

        # Raw payload
        if pkt.haslayer(Raw):
            result["payload"] = bytes(pkt[Raw].load)

        if not result["info"]:
            result["info"] = result["raw_summary"]

    except Exception as exc:
        result["info"] = f"Parse error: {exc}"

    return result
