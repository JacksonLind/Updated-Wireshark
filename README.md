# NetGuard — Network Analyzer & Intrusion Detection System

> A sleek, open-source alternative to Wireshark that combines live packet capture with a built-in IDS — designed for clarity, not complexity.

---

## ✨ Features

| Feature | Details |
|---|---|
| **Live Packet Capture** | Real-time capture on any network interface |
| **Protocol Colour Coding** | Instantly identify TCP, UDP, DNS, HTTP, ARP, ICMP at a glance |
| **Smart Filtering** | Type-to-search filter + BPF syntax support |
| **Packet Detail View** | Layer-by-layer breakdown with hex dump |
| **Built-in IDS** | 11 detection rules: port scans, SYN floods, ARP spoofing, brute force, SQL injection & more |
| **Live Dashboard** | Real-time statistics, top talkers, protocol distribution, alert breakdown |
| **Export** | Save captures as CSV or JSON |
| **Modern Dark UI** | Clean, minimal interface — no jargon overload |
| **Cross-platform** | Windows 11 ✅ · Linux ✅ (macOS compatible) |

---

## 🚀 Quick Start

### Windows 11

1. Install **Python 3.10+** from [python.org](https://www.python.org/downloads/)
   *(tick "Add Python to PATH" during install)*
2. Install **Npcap** from [npcap.com](https://npcap.com/#download)
   *(tick "WinPcap API-compatible Mode")*
3. Run setup:
   ```
   setup.bat
   ```
4. Launch:
   ```
   run.bat
   ```
   *(Run as Administrator if capture fails)*

### Linux / macOS

```bash
bash setup.sh
sudo python3 main.py
```

---

## 🛡️ IDS Detection Rules

NetGuard monitors traffic in real time for:

| Threat | Severity |
|---|---|
| Port Scan | HIGH |
| SYN Flood | CRITICAL |
| ICMP Flood | HIGH |
| ARP Spoofing | CRITICAL |
| DNS Tunneling | HIGH |
| Brute Force (SSH, RDP, FTP) | CRITICAL |
| NULL Scan | HIGH |
| XMAS Scan | HIGH |
| Large Packet (> 9000 B) | LOW |
| SQL Injection in HTTP | CRITICAL |
| XSS Attempt in HTTP | HIGH |

---

## 📖 Full Documentation

See **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)** for:
- Complete interface walkthrough
- BPF filter reference
- Troubleshooting guide
- How to expand the app (ML anomaly detection, GeoIP, PCAP export, web dashboard, and more)

---

## 🗂️ Project Structure

```
.
├── main.py              ← Entry point
├── requirements.txt     ← Python dependencies
├── setup.bat / run.bat  ← Windows launchers
├── setup.sh  / run.sh   ← Linux launchers
├── src/
│   ├── core/
│   │   ├── capture_engine.py   ← Scapy capture thread
│   │   ├── ids_engine.py       ← IDS detection engine
│   │   └── analyzer.py         ← Protocol parser
│   ├── gui/
│   │   ├── main_window.py      ← Application window
│   │   ├── capture_tab.py      ← Live packet table
│   │   ├── alerts_tab.py       ← IDS alert feed
│   │   ├── stats_tab.py        ← Statistics dashboard
│   │   ├── detail_panel.py     ← Packet detail view
│   │   └── theme.py            ← Dark theme / stylesheet
│   └── utils/
│       └── helpers.py          ← Shared utilities
└── docs/
    └── USER_GUIDE.md           ← Full documentation
```

---

## 📋 Requirements

- Python 3.10+
- PyQt5 >= 5.15
- Scapy >= 2.5
- **Windows only:** [Npcap](https://npcap.com) (for raw packet access)
- **Linux only:** `sudo` / `CAP_NET_RAW`

---

## License

MIT — free to use, modify, and distribute.
