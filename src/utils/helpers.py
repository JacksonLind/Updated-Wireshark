"""Utility helpers for NetGuard."""

import time
import struct
import socket
from datetime import datetime


def format_timestamp(ts: float) -> str:
    """Format a Unix timestamp to a human-readable string."""
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


def format_bytes(size: int) -> str:
    """Format byte count to human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def format_mac(mac_bytes: bytes) -> str:
    """Format raw MAC bytes to colon-separated hex string."""
    if isinstance(mac_bytes, str):
        return mac_bytes
    return ":".join(f"{b:02x}" for b in mac_bytes)


def ip_to_str(ip_bytes) -> str:
    """Convert raw IP bytes to dotted-decimal string."""
    if isinstance(ip_bytes, str):
        return ip_bytes
    try:
        return socket.inet_ntoa(ip_bytes)
    except Exception:
        return str(ip_bytes)


PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def get_protocol_name(proto_num: int) -> str:
    """Return a human-friendly protocol name."""
    return PROTOCOL_NAMES.get(proto_num, str(proto_num))


def get_port_service(port: int) -> str:
    """Return service name for well-known ports."""
    return WELL_KNOWN_PORTS.get(port, str(port))


SEVERITY_COLORS = {
    "CRITICAL": "#FF4444",
    "HIGH":     "#FF8800",
    "MEDIUM":   "#FFCC00",
    "LOW":      "#44AAFF",
    "INFO":     "#88CC88",
}


def severity_color(severity: str) -> str:
    """Return the hex color string for an alert severity level."""
    return SEVERITY_COLORS.get(severity.upper(), "#CCCCCC")
