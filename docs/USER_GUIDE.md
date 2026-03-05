# NetGuard — User Guide

## What is NetGuard?

NetGuard is a sleek, open-source **network traffic analyzer** and **Intrusion Detection System (IDS)** for Windows 11 (with Linux support).  
It lets you see every packet flowing across your network, spot suspicious behaviour in real time, and understand exactly what your devices are doing — all from a clean, easy-to-use interface.

---

## Quick Start

### Windows 11

1. **Install Python 3.10+** from [python.org](https://www.python.org/downloads/).  
   ✅ During install, tick **"Add Python to PATH"**.

2. **Install Npcap** from [npcap.com](https://npcap.com/#download).  
   ✅ During install, tick **"Install Npcap in WinPcap API-compatible Mode"**.

3. **Install dependencies** — double-click `setup.bat` (or run in a terminal):
   ```
   setup.bat
   ```
   > ⚠️ **Smart App Control / SmartScreen warning?**  
   > If Windows blocks `setup.bat` with *"Smart App Control blocked a file that may be unsafe"*, see the [Smart App Control](#smart-app-control-windows-11) section below.

4. **Run NetGuard** — double-click `run.bat` or:
   ```
   python main.py
   ```
   > 💡 If you see a "Permission denied" error, right-click `run.bat` → **Run as Administrator**.

### Linux / macOS

```bash
bash setup.sh          # installs Python dependencies
sudo python3 main.py   # root required for raw packet capture
```

---

## Interface Overview

NetGuard has three main tabs:

### 📡 Capture Tab

| Element | Description |
|---|---|
| **Interface** selector | Choose which network adapter to monitor |
| **Filter** box | Type-to-search across source IP, dest IP, protocol, and port |
| **Protocol** filter | Quickly narrow to TCP, UDP, HTTP, DNS, etc. |
| **▶ Start / ■ Stop** | Begin or end a capture session |
| **📂 Open** | Load packets from a `.pcap` / `.pcapng` file for offline analysis |
| **Packet table** | Colour-coded list of live packets |
| **Detail panel** | Click any row to see full layer breakdown + hex dump |

**Packet colour coding by protocol:**

| Colour | Protocol |
|---|---|
| Blue | TCP |
| Green | UDP |
| Amber | DNS |
| Pink | ICMP |
| Purple | ARP |
| Teal | HTTPS / SSH |

### 🚨 IDS Alerts Tab

Displays real-time threat detections.  Each alert shows:
- **Severity** (CRITICAL / HIGH / MEDIUM / LOW)
- **Category** (e.g. Port Scan, SYN Flood)
- **Source / Destination IP**
- **Description** of what was detected

You can filter by severity or category using the dropdowns.

### 📊 Statistics Tab

Live dashboard showing:
- Total packets captured and data volume
- Total IDS alerts and critical count
- Protocol distribution (bar chart)
- Top 10 most active source IPs
- Alert breakdown by severity

---

## IDS Detection Rules

NetGuard automatically monitors for the following threats:

| Threat | Trigger | Severity |
|---|---|---|
| **Port Scan** | ≥ 15 distinct destination ports from one IP in 10 s | HIGH |
| **SYN Flood** | ≥ 50 SYN-only packets from one IP in 5 s | CRITICAL |
| **ICMP Flood** | ≥ 30 ICMP echo-requests from one IP in 5 s | HIGH |
| **ARP Spoofing** | Same IP announced by two or more MAC addresses | CRITICAL |
| **DNS Tunneling** | DNS query name longer than 80 characters | HIGH |
| **Brute Force** | ≥ 20 connection attempts to SSH/RDP/FTP in 30 s | CRITICAL |
| **NULL Scan** | TCP packet with no flags set | HIGH |
| **XMAS Scan** | TCP packet with FIN + PSH + URG flags set | HIGH |
| **Large Packet** | Single packet exceeding 9000 bytes | LOW |
| **SQL Injection** | SQL keywords detected in HTTP payload | CRITICAL |
| **XSS Attempt** | Script/event-handler patterns in HTTP payload | HIGH |

---

## Opening a Capture File (Offline Analysis)

You can analyse existing `.pcap` or `.pcapng` files without performing a live capture:

1. Click **📂 Open** in the toolbar.
2. Browse to a `.pcap`, `.pcapng`, or `.cap` file (e.g. one saved by Wireshark or tcpdump).
3. NetGuard loads all packets, populates the Capture tab, runs the IDS engine, and updates Statistics — exactly as if the packets had been captured live.

> 💡 A ready-made test file is included in the repository:  
> `samples/sample_capture.pcapng`  
> It contains 18 packets covering ARP, DNS, HTTP, ICMP, UDP, HTTPS, SSH, and IPv6 — great for exploring the interface without needing a network interface or Npcap.

---

## Smart App Control (Windows 11)

Windows 11 *Smart App Control* (SAC) and *Defender SmartScreen* may block `.bat` and `.ps1` files downloaded from the internet with the message **"Smart App Control blocked a file that may be unsafe"**.  This is a reputation-based check — not a virus detection — and is safe to work around using the steps below.

### Option A — Run `setup.bat` first (recommended)

`setup.bat` includes a step that calls PowerShell's `Unblock-File` to remove the *Mark-of-the-Web* (Zone.Identifier) from all scripts in the project folder.  Once unblocked, `run.bat` will open normally.

If SAC also blocks `setup.bat` itself, use Option B.

### Option B — Unblock manually via File Properties

1. Right-click the blocked file (e.g. `setup.bat`) → **Properties**.
2. At the bottom of the *General* tab, tick **Unblock**.
3. Click **OK**, then re-run the file.

### Option C — Use the PowerShell launcher

`run.ps1` runs inside the already-trusted `powershell.exe` process, so it is not subject to the same reputation checks:

1. Open **PowerShell as Administrator** (right-click the Start button → *Windows PowerShell (Admin)*).
2. Navigate to the project folder:
   ```powershell
   cd "C:\path\to\NetGuard"
   ```
3. Allow scripts for this session:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. Run:
   ```powershell
   .\run.ps1
   ```

### Option D — Run `python main.py` directly

Open a terminal (Command Prompt or PowerShell) in the project folder and run:

```
python main.py
```

Python's interpreter (`python.exe`) is a signed, trusted binary — scripts passed to it are not blocked by Smart App Control.

---



Click **💾 Save** in the toolbar at any time.  
Supported formats:
- **CSV** — open in Excel, grep, or any text editor
- **JSON** — for scripting and programmatic analysis

---

## BPF Filters (Advanced)

The **Filter** field in the toolbar accepts standard **Berkeley Packet Filter** syntax, which is the same system used by Wireshark and tcpdump:

| Filter | Captures |
|---|---|
| `tcp` | All TCP traffic |
| `udp port 53` | DNS only |
| `host 192.168.1.1` | Traffic to/from that IP |
| `not arp` | Everything except ARP |
| `tcp port 80 or tcp port 443` | Web traffic |
| `src net 10.0.0.0/8` | Traffic from 10.x.x.x |

---

## Troubleshooting

### "Smart App Control blocked a file" (Windows 11)
See the [Smart App Control](#smart-app-control-windows-11) section above.

### "No interfaces found" or capture won't start (Windows)
- Make sure **Npcap** is installed.
- Try running as **Administrator** (right-click → Run as administrator).
- Disable your Windows Firewall temporarily for testing.

### No packets appear
- Check you selected the correct interface (e.g. "Wi-Fi" vs "Ethernet").
- Make sure network activity is happening (open a browser, ping, etc.).

### App won't open
- Confirm Python 3.10+ is installed: `python --version`
- Confirm PyQt5 is installed: `pip show PyQt5`

---

## Expanding NetGuard

Here are areas where NetGuard can be extended:

### 1. PCAP File Import ✅ (implemented)
`scapy.utils.rdpcap()` is used by the **📂 Open** toolbar button to load `.pcap` / `.pcapng` files captured by Wireshark or tcpdump for offline analysis.

### 2. Machine-Learning Anomaly Detection
Replace or augment the rule-based IDS with a trained classifier (e.g. using `scikit-learn`) to detect zero-day attacks that don't match known signatures.

### 3. GeoIP Lookup
Integrate `geoip2` or `maxminddb` to show the physical location of external IPs on a world map.

### 4. Alert Notifications
Use Windows Toast notifications (`win10toast`) or email alerts (`smtplib`) to push real-time warnings to your desktop or inbox.

### 5. PCAP Export
Add `scapy.utils.wrpcap()` to save raw packets in `.pcap` format, fully compatible with Wireshark.

### 6. Web Dashboard
Expose a REST API (FastAPI) and serve a real-time dashboard in the browser using WebSockets, enabling remote monitoring.

### 7. Rule Editor
Build a GUI tab that lets users create, enable, and disable IDS rules without editing code.

### 8. Database Logging
Store all packets and alerts in an SQLite database so you can query historical data after a session ends.

### 9. IPv6 Full Support
Extend the analyzer and IDS rules to cover ICMPv6, NDP spoofing, and IPv6 extension headers.

### 10. Plugin System
Design a plugin loader so community-contributed detection rules can be dropped in as Python files without modifying the core engine.

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+S` | Save capture |
| `Ctrl+F` | Focus filter box |
| `Space` | Pause / resume auto-scroll |

---

## License

NetGuard is open-source software released under the MIT License.  
You are free to use, modify, and distribute it.

---

*Built on [Scapy](https://scapy.net) and [PyQt5](https://riverbankcomputing.com/software/pyqt/).*
