<div align="center">

<br/>

```
 ██╗    ██╗██╗  ██╗ ██████╗ ██╗  ██╗███╗   ██╗ ██████╗  ██████╗██╗  ██╗███████╗
 ██║    ██║██║  ██║██╔═══██╗██║ ██╔╝████╗  ██║██╔═══██╗██╔════╝██║ ██╔╝██╔════╝
 ██║ █╗ ██║███████║██║   ██║█████╔╝ ██╔██╗ ██║██║   ██║██║     █████╔╝ ███████╗
 ██║███╗██║██╔══██║██║   ██║██╔═██╗ ██║╚██╗██║██║   ██║██║     ██╔═██╗ ╚════██║
 ╚███╔███╔╝██║  ██║╚██████╔╝██║  ██╗██║ ╚████║╚██████╔╝╚██████╗██║  ██╗███████║
  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝
```

**Real-time incoming connection monitor for your terminal.**  
*Know exactly who's knocking on your machine — and why.*

<br/>

[![Python](https://img.shields.io/badge/Python-3.8%2B-C8934A?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-C8934A?style=flat-square)](https://github.com/AxthonyV/WhoKnocks)
[![License](https://img.shields.io/badge/License-MIT-C8934A?style=flat-square)](LICENSE)

</div>

---

## What is WhoKnocks?

WhoKnocks is a real-time terminal dashboard that shows every active network connection on **your own machine** — where it's coming from, which country, which process opened it, and whether the port looks suspicious.

Ever wondered *"what is my browser actually connecting to?"* or *"why is something listening on port 445?"* — WhoKnocks answers that live, with geolocation, threat assessment, and automatic JSON logging. Zero config, one command.

> ⚠️ **WhoKnocks only monitors your own machine's connections.** It does not scan external networks, does not perform any intrusive actions, and is designed strictly for personal network visibility and educational use.

---

## Features

- **Live connection table** — every active connection with remote IP, port, country, city, process name and threat level
- **Geolocation** — resolves each external IP to country and city in the background
- **Country flags** — visual origin identification at a glance
- **Threat assessment** — flags connections on suspicious ports (SSH, RDP, SMB, VNC, Metasploit, etc.)
- **Top Origins** — bar chart of the countries connecting to you most
- **Suspicious Ports panel** — dedicated view for high-risk port activity
- **By Process** — see which apps have the most active connections
- **Auto JSON logging** — saves a snapshot to `whoknocks_log.json` every few seconds
- **Cross-platform** — Windows, Linux, macOS
- **Zero config** — clone, install, run

---

## Preview

```
╭──────────────────────────────────────────────────────────────────────────────╮
│   WhoKnocks  ·  watching your connections  ·  Sun Apr 20  14:55:03  · 12 IPs │
╰──────────────────────────────────────────────────────────────────────────────╯

┌─ Active Connections [14] ───────────────────────────────────────────────────┐
│ Time      Remote IP          Port   Country              Process    Threat   │
│ 14:55:01  142.250.80.46      443    🇺🇸 United States   chrome     LOW      │
│ 14:55:01  185.125.188.55     443    🇬🇧 United Kingdom  snapd      LOW      │
│ 14:55:02  31.13.72.36        443    🇺🇸 United States   chrome     LOW      │
│ 14:55:03  192.168.1.1        22     Local Network        ssh        LOCAL    │
└─────────────────────────────────────────────────────────────────────────────┘

┌─ Stats ──────┐  ┌─ Top Origins ───────────┐  ┌─ ⚠ Suspicious Ports ───────┐
│ Established 9│  │ 🇺🇸 United States ████ 7│  │ ✓ No suspicious ports      │
│ Listening   3│  │ 🇬🇧 United Kingdom ██  2│  │   detected                  │
│ External   11│  │ 🇩🇪 Germany        █   1│  └─────────────────────────────┘
│ ⚠ High    0 │  └─────────────────────────┘
└─────────────┘
```
<img width="1920" height="1080" alt="preview" src="https://github.com/user-attachments/assets/9403d767-6956-474c-88e0-cb794aa763ee" />

---

## Getting Started

### Requirements

- Python 3.8+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/AxthonyV/WhoKnocks.git
cd WhoKnocks
```

**Linux / macOS**
```bash
bash install.sh
```

**Windows**
```bat
install.bat
```

**Or manually**
```bash
pip install -r requirements.txt
```

### Run

```bash
# Linux / macOS (recommended: sudo for full process visibility)
sudo python3 whoknocks.py

# Without sudo (works, some process names may show as "?")
python3 whoknocks.py

# Windows (run as Administrator for best results)
python whoknocks.py
```

---

## Understanding Threat Levels

| Level | Color | Meaning |
|-------|-------|---------|
| `HIGH` | 🔴 Red | Connection on a known high-risk port (RDP, SMB, VNC, etc.) |
| `MED` | 🟡 Amber | External connection on a privileged port (<1024) |
| `LOW` | 🔵 Teal | External connection, standard port |
| `LOCAL` | 🟢 Green | Connection within your local network |

---

## Monitored Suspicious Ports

| Port | Service | Port | Service |
|------|---------|------|---------|
| 22 | SSH | 3389 | RDP |
| 23 | Telnet | 5900 | VNC |
| 445 | SMB | 1433 | MSSQL |
| 3306 | MySQL | 6379 | Redis |
| 27017 | MongoDB | 9200 | Elasticsearch |
| 4444 | Metasploit | 1337 | Backdoor/Leet |

---

## Log Output

WhoKnocks automatically saves a JSON snapshot every few seconds:

```json
[
  {
    "time": "14:55:03",
    "remote_ip": "142.250.80.46",
    "remote_port": 443,
    "country": "United States",
    "city": "Mountain View",
    "process": "chrome",
    "threat": "LOW",
    "status": "ESTABLISHED"
  }
]
```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `psutil` | ≥ 6.1.0 | Network connections & process info |
| `rich` | ≥ 13.9.4 | Terminal UI rendering |
| `requests` | ≥ 2.32.3 | IP geolocation lookup |

---

## Compatibility

| OS | Status |
|----|--------|
| Windows 10 / 11 | ✅ Full support |
| Ubuntu / Debian | ✅ Full support |
| Arch Linux | ✅ Full support |
| macOS 12+ | ✅ Full support |
| Raspberry Pi OS | ✅ Full support |

> Run with `sudo` / Administrator privileges for full process name visibility.

---

## Project Structure

```
WhoKnocks/
├── whoknocks.py        # Main application
├── requirements.txt    # Dependencies
├── install.sh          # Linux/macOS installer
├── install.bat         # Windows installer
├── whoknocks_log.json  # Auto-generated connection log
├── LICENSE
└── README.md
```

---

## Educational Use

WhoKnocks was built as a learning tool for network engineering and computer science students. It demonstrates:

- Real-time socket monitoring with `psutil`
- IP geolocation via public APIs
- Threat heuristics based on well-known port registries
- Async background data fetching with Python threads
- Rich terminal UI design

---

## Contributing

Issues, ideas and pull requests are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## Author

<img src="https://github.com/AxthonyV.png" alt="AxthonyV" width="100px" style="border-radius: 50%;">

**AxthonyV**
- GitHub: [@AxthonyV](https://github.com/AxthonyV)

If you find this useful, consider starring the repository ⭐

---

## License

MIT License — see [LICENSE](LICENSE) for details.
