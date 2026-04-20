#!/usr/bin/env python3
"""
WhoKnocks v2 — Real-time Incoming Connection Monitor
Monitor every connection hitting YOUR machine. Know who knocks.
Author: AxthonyV | github.com/AxthonyV
License: MIT
"""

import os
import sys
import time
import socket
import platform
import threading
import subprocess
import json
from datetime import datetime
from collections import deque, defaultdict
from pathlib import Path

try:
    import psutil
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.align import Align
    from rich.rule import Rule
    from rich import box
    import requests
except ImportError as e:
    print(f"\n  [!] Missing dependency: {e}")
    print("  [*] Run: pip install -r requirements.txt\n")
    sys.exit(1)

# ─── Palette ──────────────────────────────────────────────────────────────────
PRIMARY      = "#C8934A"
PRIMARY_DIM  = "#8A5F2A"
PRIMARY_DARK = "#2A1F0F"
ACCENT       = "#E8B97A"
TEXT_LIGHT   = "#D4C5B0"
TEXT_MUTED   = "#4A4035"
SUCCESS      = "#6A9E6A"
WARNING      = "#C8934A"
DANGER       = "#B85A5A"
SUBTLE       = "#141008"
TEAL         = "#5A8A8A"
INFO         = "#6A8A9E"

console = Console()
IS_WINDOWS = platform.system().lower() == "windows"

# ─── State ────────────────────────────────────────────────────────────────────
_geo_cache:      dict[str, dict]    = {}
_geo_lock                           = threading.Lock()
_log_path                           = Path("whoknocks_log.json")
_country_counts: defaultdict        = defaultdict(int)
_isp_counts:     defaultdict        = defaultdict(int)
_total_seen:     set                = set()
_new_ips:        deque              = deque(maxlen=8)   # recently seen new IPs
_geo_results:    dict[str, dict]    = {}
_provider_fails: defaultdict        = defaultdict(int)

# ─── Process cache (pid → name) to avoid repeated Access Denied ───────────────
_proc_cache:     dict[int, str]     = {}
_proc_lock                          = threading.Lock()

# ─── Port registry ────────────────────────────────────────────────────────────
SUSPICIOUS_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 110: "POP3", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 445: "SMB", 512: "rexec",
    513: "rlogin", 514: "rsh", 873: "rsync",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    2375: "Docker", 2376: "Docker-TLS", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "Alt-HTTP",
    8443: "Alt-HTTPS", 9200: "Elasticsearch",
    27017: "MongoDB", 1337: "Backdoor",
}

KNOWN_SAFE_PORTS = {80: "HTTP", 443: "HTTPS", 853: "DNS-TLS"}

PRIVATE_RANGES = [
    "10.", "192.168.", "127.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "::1", "fe80", "fc00", "fd",
]

# ─── Well-known process→service hints for ? processes ─────────────────────────
SYSTEM_PROC_HINTS = {
    # Windows system processes often seen as ?
    4:    "System (kernel)",
    0:    "Idle",
}

KNOWN_PROCESS_PORTS = {
    # port → likely process hint when PID is inaccessible
    443:  "browser/app",
    80:   "browser/app",
    53:   "DNS resolver",
    123:  "NTP sync",
    67:   "DHCP",
    68:   "DHCP",
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def is_private(ip: str) -> bool:
    return any(ip.startswith(r) for r in PRIVATE_RANGES)

def normalize_ipv6(ip: str) -> str:
    """Unwrap IPv4-mapped IPv6 addresses."""
    if ip.startswith("::ffff:") and "." in ip:
        return ip[7:]
    return ip

def flag_for_country(country: str) -> str:
    flags = {
        "United States": "🇺🇸", "China": "🇨🇳", "Russia": "🇷🇺",
        "Germany": "🇩🇪", "United Kingdom": "🇬🇧", "France": "🇫🇷",
        "Brazil": "🇧🇷", "India": "🇮🇳", "Japan": "🇯🇵",
        "Canada": "🇨🇦", "Australia": "🇦🇺", "Netherlands": "🇳🇱",
        "South Korea": "🇰🇷", "Mexico": "🇲🇽", "Argentina": "🇦🇷",
        "Colombia": "🇨🇴", "Venezuela": "🇻🇪", "Chile": "🇨🇱",
        "Spain": "🇪🇸", "Italy": "🇮🇹", "Ukraine": "🇺🇦",
        "Poland": "🇵🇱", "Singapore": "🇸🇬", "Sweden": "🇸🇪",
        "Peru": "🇵🇪", "Costa Rica": "🇨🇷", "Ecuador": "🇪🇨",
        "Bolivia": "🇧🇴", "Paraguay": "🇵🇾", "Uruguay": "🇺🇾",
        "Panama": "🇵🇦", "Honduras": "🇭🇳", "Guatemala": "🇬🇹",
        "Dominican Republic": "🇩🇴", "Cuba": "🇨🇺",
        "Turkey": "🇹🇷", "Israel": "🇮🇱", "Saudi Arabia": "🇸🇦",
        "United Arab Emirates": "🇦🇪", "South Africa": "🇿🇦",
        "Nigeria": "🇳🇬", "Egypt": "🇪🇬", "Kenya": "🇰🇪",
        "Indonesia": "🇮🇩", "Malaysia": "🇲🇾", "Thailand": "🇹🇭",
        "Philippines": "🇵🇭", "Vietnam": "🇻🇳", "Pakistan": "🇵🇰",
        "Bangladesh": "🇧🇩", "New Zealand": "🇳🇿",
        "Local Network": "🏠", "Unknown": "🌐",
    }
    return flags.get(country, "🌐")

def threat_level(ip: str, port: int) -> tuple[str, str]:
    if port in SUSPICIOUS_PORTS:
        return ("HIGH", DANGER)
    if not is_private(ip) and port < 1024 and port not in KNOWN_SAFE_PORTS:
        return ("MED", WARNING)
    if not is_private(ip):
        return ("LOW", TEAL)
    return ("LOCAL", SUCCESS)

# ─── Process resolution — robust, cached, multi-strategy ─────────────────────

def _resolve_process_windows(pid: int) -> str:
    """Try multiple Windows strategies to get process name."""
    # Strategy 1: psutil with full access
    try:
        p = psutil.Process(pid)
        name = p.name()
        if name:
            return name[:22]
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return "ended"
    except psutil.AccessDenied:
        pass

    # Strategy 2: psutil exe path
    try:
        p = psutil.Process(pid)
        exe = p.exe()
        if exe:
            return Path(exe).name[:22]
    except Exception:
        pass

    # Strategy 3: wmic (works even for protected processes)
    try:
        result = subprocess.run(
            ["wmic", "process", "where", f"ProcessId={pid}", "get", "Name", "/value"],
            capture_output=True, text=True, timeout=2, creationflags=0x08000000
        )
        for line in result.stdout.splitlines():
            if line.startswith("Name=") and line[5:].strip():
                return line[5:].strip()[:22]
    except Exception:
        pass

    # Strategy 4: tasklist
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=2, creationflags=0x08000000
        )
        parts = result.stdout.strip().strip('"').split('","')
        if parts and parts[0]:
            return parts[0][:22]
    except Exception:
        pass

    return f"PID:{pid}"

def _resolve_process_unix(pid: int) -> str:
    """Linux/macOS process resolution."""
    try:
        p = psutil.Process(pid)
        return p.name()[:22]
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return "ended"
    except psutil.AccessDenied:
        pass

    # /proc fallback
    try:
        comm = Path(f"/proc/{pid}/comm")
        if comm.exists():
            return comm.read_text().strip()[:22]
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True, text=True, timeout=2
        )
        name = result.stdout.strip()
        if name:
            return name[:22]
    except Exception:
        pass

    return f"PID:{pid}"

def get_process_name(pid: int, remote_port: int) -> str:
    if pid == 0 or pid is None:
        hint = KNOWN_PROCESS_PORTS.get(remote_port, "system")
        return f"[{hint}]"

    # Check system hint first
    if pid in SYSTEM_PROC_HINTS:
        return SYSTEM_PROC_HINTS[pid]

    # Check cache
    with _proc_lock:
        if pid in _proc_cache:
            return _proc_cache[pid]

    name = _resolve_process_windows(pid) if IS_WINDOWS else _resolve_process_unix(pid)

    with _proc_lock:
        _proc_cache[pid] = name

    return name

# ─── Geo resolution — 4-provider cascade ──────────────────────────────────────

def _try_ip_api_com(ip: str) -> dict | None:
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,org,isp,as",
            timeout=5
        )
        d = r.json()
        if d.get("status") == "success":
            org = d.get("org") or d.get("isp") or d.get("as") or "—"
            return {
                "country": d.get("country") or "Unknown",
                "city":    d.get("city")    or "—",
                "org":     org[:32],
                "isp":     (d.get("isp") or org)[:28],
            }
    except Exception:
        pass
    return None

def _try_ipwho_is(ip: str) -> dict | None:
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        d = r.json()
        if d.get("success"):
            conn = d.get("connection", {})
            org  = conn.get("org") or conn.get("isp") or conn.get("domain") or "—"
            return {
                "country": d.get("country") or "Unknown",
                "city":    d.get("city")    or "—",
                "org":     org[:32],
                "isp":     (conn.get("isp") or org)[:28],
            }
    except Exception:
        pass
    return None

def _try_freeipapi(ip: str) -> dict | None:
    try:
        r = requests.get(f"https://freeipapi.com/api/json/{ip}", timeout=5)
        d = r.json()
        if d.get("countryName"):
            return {
                "country": d.get("countryName") or "Unknown",
                "city":    d.get("cityName")    or "—",
                "org":     "—",
                "isp":     "—",
            }
    except Exception:
        pass
    return None

def _try_ipapi_co(ip: str) -> dict | None:
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        d = r.json()
        country = d.get("country_name", "")
        if country and country != "Undefined":
            org = d.get("org") or "—"
            return {
                "country": country,
                "city":    d.get("city")  or "—",
                "org":     org[:32],
                "isp":     org[:28],
            }
    except Exception:
        pass
    return None

GEO_PROVIDERS = [
    ("ip-api.com",    _try_ip_api_com),
    ("ipwho.is",      _try_ipwho_is),
    ("freeipapi.com", _try_freeipapi),
    ("ipapi.co",      _try_ipapi_co),
]

def get_geo(ip: str) -> dict:
    if is_private(ip):
        return {"country": "Local Network", "city": "LAN", "org": "Local", "isp": "Local"}

    ip = normalize_ipv6(ip)

    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]

    result = None
    for name, fn in GEO_PROVIDERS:
        if _provider_fails[name] >= 6:
            continue
        result = fn(ip)
        if result:
            break
        _provider_fails[name] += 1

    if not result:
        result = {"country": "Unknown", "city": "—", "org": "—", "isp": "—"}

    with _geo_lock:
        _geo_cache[ip] = result

    return result

def _fetch_one_ip(ip: str):
    ip = normalize_ipv6(ip)
    geo = get_geo(ip)
    country = geo.get("country", "Unknown")
    isp     = geo.get("isp", "—")
    if country not in ("Unknown", "Local Network"):
        _country_counts[country] += 1
    if isp and isp not in ("—", "Local"):
        _isp_counts[isp] += 1
    with _geo_lock:
        _geo_results[ip] = geo

def _bg_geo_fetch(conns: list[dict]):
    uncached = {
        normalize_ipv6(c["remote_ip"])
        for c in conns
        if not c["is_private"]
        and normalize_ipv6(c["remote_ip"]) not in _geo_cache
    }
    threads = [
        threading.Thread(target=_fetch_one_ip, args=(ip,), daemon=True)
        for ip in list(uncached)[:24]
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=6)

    # Sync cached → results
    for c in conns:
        ip = normalize_ipv6(c["remote_ip"])
        if ip in _geo_cache:
            with _geo_lock:
                _geo_results[ip] = _geo_cache[ip]

# ─── Connection scanner ───────────────────────────────────────────────────────

def get_connections() -> list[dict]:
    conns = []
    try:
        raw = psutil.net_connections(kind="inet")
    except Exception:
        return conns

    for c in raw:
        if not (c.raddr and c.raddr.ip):
            continue

        rip   = c.raddr.ip
        rport = c.raddr.port
        lport = c.laddr.port if c.laddr else 0
        pid   = c.pid

        pname = get_process_name(pid, rport)
        tlevel, tcolor = threat_level(rip, rport)

        # Track new IPs
        norm = normalize_ipv6(rip)
        if norm not in _total_seen and not is_private(rip):
            _new_ips.appendleft({
                "ip": norm,
                "port": rport,
                "process": pname,
                "time": datetime.now().strftime("%H:%M:%S"),
            })

        conns.append({
            "remote_ip":   rip,
            "remote_port": rport,
            "local_port":  lport,
            "status":      c.status or "—",
            "pid":         pid or 0,
            "process":     pname,
            "threat":      tlevel,
            "tcolor":      tcolor,
            "seen_at":     datetime.now().strftime("%H:%M:%S"),
            "is_private":  is_private(rip),
        })

    return conns

# ─── Panels ───────────────────────────────────────────────────────────────────

def make_header() -> Panel:
    now  = datetime.now().strftime("%H:%M:%S")
    date = datetime.now().strftime("%a %b %d, %Y")
    t = Text()
    t.append("  WhoKnocks", style=f"bold {PRIMARY}")
    t.append("  ·  ", style=TEXT_MUTED)
    t.append("watching your connections", style=TEXT_MUTED)
    t.append("  ·  ", style=TEXT_MUTED)
    t.append(f"{date}  ", style=TEXT_MUTED)
    t.append(now, style=f"bold {ACCENT}")
    t.append("  ·  seen ", style=TEXT_MUTED)
    t.append(str(len(_total_seen)), style=f"bold {PRIMARY}")
    t.append(" unique IPs  ", style=TEXT_MUTED)
    return Panel(
        Align.center(t),
        style=PRIMARY_DARK,
        box=box.HORIZONTALS,
        padding=(0, 2),
    )

def _terminal_size() -> tuple[int, int]:
    """Cross-platform terminal size detection."""
    try:
        sz = os.get_terminal_size()
        return sz.columns, sz.lines
    except Exception:
        try:
            import shutil
            sz = shutil.get_terminal_size(fallback=(120, 35))
            return sz.columns, sz.lines
        except Exception:
            return 120, 35

def make_connections_panel(conns: list[dict]) -> Panel:
    cols, rows = _terminal_size()

    # How many rows the main panel can use:
    # total rows - header(3) - footer(3) - bottom panels(~12) - panel borders(4) - table header(2)
    max_rows = max(4, rows - 24)

    # Column visibility based on width
    wide     = cols >= 140
    standard = 100 <= cols < 140
    compact  = cols < 100
    ip_w     = 40 if wide else (30 if standard else 22)

    table = Table(
        box=None, show_header=True,
        header_style=f"bold {PRIMARY_DIM}",
        padding=(0, 1), expand=True,
        row_styles=["", f"on {SUBTLE}"],
    )
    table.add_column("Time",      width=9,   style=TEXT_MUTED, no_wrap=True)
    table.add_column("Remote IP", width=ip_w, style=TEXT_LIGHT, no_wrap=True)
    table.add_column("Port",      width=10,  justify="right",  no_wrap=True)
    table.add_column("Country",   width=22,  no_wrap=True)
    if not compact:
        table.add_column("City",  width=14,  style=TEXT_MUTED, no_wrap=True)
    if wide:
        table.add_column("ISP / Org", width=26, style=INFO,    no_wrap=True)
    table.add_column("Process",   width=22,  style=ACCENT,     no_wrap=True)
    table.add_column("Threat",    width=7,   justify="center", no_wrap=True)
    table.add_column("Status",    width=12,  no_wrap=True)

    displayed = sorted(
        conns,
        key=lambda x: (
            x["threat"] == "HIGH",
            x["threat"] == "MED",
            x["status"] == "ESTABLISHED",
        ),
        reverse=True
    )[:max_rows]

    for c in displayed:
        ip  = normalize_ipv6(c["remote_ip"])
        geo = _geo_results.get(ip) or _geo_cache.get(ip)

        if c["is_private"]:
            country, city, isp, flag = "Local Network", "LAN", "—", "🏠"
        elif geo:
            country = geo.get("country", "…") or "…"
            city    = geo.get("city",    "—") or "—"
            isp     = geo.get("isp",     "—") or "—"
            flag    = flag_for_country(country)
        else:
            country, city, isp, flag = "Resolving…", "—", "—", "⏳"

        service = SUSPICIOUS_PORTS.get(c["remote_port"]) or KNOWN_SAFE_PORTS.get(c["remote_port"], "")
        if c["remote_port"] in SUSPICIOUS_PORTS:
            port_txt = Text(f"{c['remote_port']} {service[:5]}", style=f"bold {DANGER}")
        else:
            port_txt = Text(str(c["remote_port"]), style=TEXT_LIGHT if service else TEXT_MUTED)

        status_colors = {
            "ESTABLISHED": SUCCESS, "LISTEN": TEAL,
            "TIME_WAIT": TEXT_MUTED, "CLOSE_WAIT": WARNING,
            "SYN_SENT": WARNING, "SYN_RECV": WARNING,
            "FIN_WAIT1": TEXT_MUTED, "FIN_WAIT2": TEXT_MUTED,
        }
        status_color = status_colors.get(c["status"], TEXT_MUTED)

        proc       = c["process"]
        proc_style = TEXT_MUTED if (proc.startswith("PID:") or proc == "?") else (INFO if proc.startswith("[") else ACCENT)

        row = [c["seen_at"], ip[:ip_w], port_txt, f"{flag} {country}"[:22]]
        if not compact:
            row.append(city[:14])
        if wide:
            row.append(isp[:26])
        row += [Text(proc, style=proc_style), Text(c["threat"], style=f"bold {c['tcolor']}"), Text(c["status"], style=status_color)]
        table.add_row(*row)

    shown = len(displayed)
    total = len(conns)
    extra = f" (+{total - shown} not shown — resize terminal)" if total > shown else ""
    title = f"[bold {PRIMARY}] Active Connections [{total}]{extra} [/]"
    return Panel(table, title=title, border_style=PRIMARY_DARK, box=box.ROUNDED, padding=(0, 1))

def make_header() -> Panel:
    now  = datetime.now().strftime("%H:%M:%S")
    date = datetime.now().strftime("%a %b %d, %Y")
    t = Text()
    t.append("  WhoKnocks", style=f"bold {PRIMARY}")
    t.append("  ·  ", style=TEXT_MUTED)
    t.append("watching your connections", style=TEXT_MUTED)
    t.append("  ·  ", style=TEXT_MUTED)
    t.append(f"{date}  ", style=TEXT_MUTED)
    t.append(now, style=f"bold {ACCENT}")
    t.append("  ·  seen ", style=TEXT_MUTED)
    t.append(str(len(_total_seen)), style=f"bold {PRIMARY}")
    t.append(" unique IPs  ", style=TEXT_MUTED)
    return Panel(
        Align.center(t),
        style=PRIMARY_DARK,
        box=box.HORIZONTALS,
        padding=(0, 2),
    )

def _terminal_size() -> tuple[int, int]:
    """Returns (columns, rows) of the current terminal, cross-platform."""
    try:
        sz = os.get_terminal_size()
        return sz.columns, sz.lines
    except Exception:
        try:
            import shutil
            sz = shutil.get_terminal_size(fallback=(120, 30))
            return sz.columns, sz.lines
        except Exception:
            return 120, 30

def make_connections_panel(conns: list[dict]) -> Panel:
    cols, rows = _terminal_size()

    # ── Adaptive row count ─────────────────────────────────────────────────
    # header=3, footer=3, bottom panels≈10, panel borders=2, table header=1
    reserved    = 3 + 3 + 10 + 4
    max_rows    = max(5, rows - reserved)

    # ── Adaptive columns based on terminal width ───────────────────────────
    # Narrow  < 100 : compact mode  (hide City + ISP)
    # Medium  100-139: standard     (hide ISP)
    # Wide    >= 140: full mode     (all columns)
    compact  = cols < 100
    standard = 100 <= cols < 140
    wide     = cols >= 140

    ip_width   = 40 if wide else (28 if standard else 20)
    show_city  = not compact
    show_isp   = wide

    table = Table(
        box=None, show_header=True,
        header_style=f"bold {PRIMARY_DIM}",
        padding=(0, 1), expand=True,
        row_styles=["", f"on {SUBTLE}"],
    )
    table.add_column("Time",      width=9,         style=TEXT_MUTED, no_wrap=True)
    table.add_column("Remote IP", width=ip_width,  style=TEXT_LIGHT, no_wrap=True)
    table.add_column("Port",      width=10,        justify="right",  no_wrap=True)
    table.add_column("Country",   width=22,        no_wrap=True)
    if show_city:
        table.add_column("City",  width=15,        style=TEXT_MUTED, no_wrap=True)
    if show_isp:
        table.add_column("ISP / Org", width=26,    style=INFO,       no_wrap=True)
    table.add_column("Process",   width=22,        style=ACCENT,     no_wrap=True)
    table.add_column("Threat",    width=7,         justify="center", no_wrap=True)
    table.add_column("Status",    width=12,        no_wrap=True)

    displayed = sorted(
        conns,
        key=lambda x: (
            x["threat"] == "HIGH",
            x["threat"] == "MED",
            x["status"] == "ESTABLISHED",
        ),
        reverse=True
    )[:max_rows]

    for c in displayed:
        ip  = normalize_ipv6(c["remote_ip"])
        geo = _geo_results.get(ip) or _geo_cache.get(ip)

        if c["is_private"]:
            country = "Local Network"
            city    = "LAN"
            isp     = "—"
            flag    = "🏠"
        elif geo:
            country = geo.get("country", "…")
            city    = geo.get("city",    "—") or "—"
            isp     = geo.get("isp",     "—") or "—"
            flag    = flag_for_country(country)
        else:
            country = "Resolving…"
            city    = "—"
            isp     = "—"
            flag    = "⏳"

        # Port label
        service = SUSPICIOUS_PORTS.get(c["remote_port"]) or KNOWN_SAFE_PORTS.get(c["remote_port"], "")
        port_txt = Text(str(c["remote_port"]))
        if c["remote_port"] in SUSPICIOUS_PORTS:
            port_txt = Text(f"{c['remote_port']} {service[:5]}", style=f"bold {DANGER}")
        elif service:
            port_txt = Text(str(c["remote_port"]), style=TEXT_LIGHT)
        else:
            port_txt.stylize(TEXT_MUTED)

        status_colors = {
            "ESTABLISHED": SUCCESS, "LISTEN": TEAL,
            "TIME_WAIT": TEXT_MUTED, "CLOSE_WAIT": WARNING,
            "SYN_SENT": WARNING, "SYN_RECV": WARNING,
            "FIN_WAIT1": TEXT_MUTED, "FIN_WAIT2": TEXT_MUTED,
        }
        status_color = status_colors.get(c["status"], TEXT_MUTED)

        # Process display — highlight resolved vs unknown
        proc = c["process"]
        if proc.startswith("PID:") or proc == "?":
            proc_style = TEXT_MUTED
        elif proc.startswith("["):
            proc_style = INFO
        else:
            proc_style = ACCENT

        row = [
            c["seen_at"],
            ip[:ip_width],
            port_txt,
            f"{flag} {country}"[:22],
        ]
        if show_city:
            row.append(city[:15])
        if show_isp:
            row.append(isp[:26])
        row += [
            Text(proc, style=proc_style),
            Text(c["threat"], style=f"bold {c['tcolor']}"),
            Text(c["status"], style=status_color),
        ]
        table.add_row(*row)

    title = f"[bold {PRIMARY}] Active Connections [{len(conns)}] [/]"
    return Panel(table, title=title, border_style=PRIMARY_DARK, box=box.ROUNDED, padding=(0, 1))

def make_stats_panel(conns: list[dict]) -> Panel:
    established = sum(1 for c in conns if c["status"] == "ESTABLISHED")
    listening   = sum(1 for c in conns if c["status"] == "LISTEN")
    time_wait   = sum(1 for c in conns if c["status"] == "TIME_WAIT")
    external    = sum(1 for c in conns if not c["is_private"])
    high_threat = sum(1 for c in conns if c["threat"] == "HIGH")
    med_threat  = sum(1 for c in conns if c["threat"] == "MED")
    resolved    = sum(
        1 for c in conns
        if not c["is_private"]
        and normalize_ipv6(c["remote_ip"]) in _geo_cache
        and _geo_cache[normalize_ipv6(c["remote_ip"])].get("country", "Unknown") != "Unknown"
    )

    t = Table.grid(padding=(0, 2))
    t.add_column(justify="left",  no_wrap=True)
    t.add_column(justify="right", no_wrap=True)
    t.add_row(Text("Established",  style=TEXT_MUTED), Text(str(established), style=f"bold {SUCCESS}"))
    t.add_row(Text("Listening",    style=TEXT_MUTED), Text(str(listening),   style=f"bold {TEAL}"))
    t.add_row(Text("Time Wait",    style=TEXT_MUTED), Text(str(time_wait),   style=TEXT_MUTED))
    t.add_row(Text("External",     style=TEXT_MUTED), Text(str(external),    style=f"bold {ACCENT}"))
    t.add_row(Text("⚠ High",       style=TEXT_MUTED), Text(str(high_threat), style=f"bold {DANGER}"))
    t.add_row(Text("● Med",        style=TEXT_MUTED), Text(str(med_threat),  style=f"bold {WARNING}"))
    t.add_row(Text("Unique IPs",   style=TEXT_MUTED), Text(str(len(_total_seen)), style=f"bold {PRIMARY}"))
    t.add_row(Text("Geo resolved", style=TEXT_MUTED), Text(str(resolved),    style=f"bold {SUCCESS}"))

    return Panel(t, title=f"[bold {PRIMARY}] Stats [/]", border_style=PRIMARY_DARK, box=box.ROUNDED, padding=(0, 1))

def make_top_countries_panel() -> Panel:
    top = sorted(_country_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    mx  = top[0][1] if top else 1

    t = Table.grid(padding=(0, 1))
    t.add_column(no_wrap=True)
    t.add_column(no_wrap=True)
    t.add_column(no_wrap=True)
    t.add_column(no_wrap=True, justify="right")

    for country, count in top:
        bar_w = int((count / mx) * 11)
        bar   = f"[{PRIMARY}]{'█'*bar_w}[/{PRIMARY}][{TEXT_MUTED}]{'░'*(11-bar_w)}[/{TEXT_MUTED}]"
        t.add_row(flag_for_country(country), country[:20], bar, Text(str(count), style=f"bold {ACCENT}"))

    if not top:
        t.add_row("", Text("Resolving IPs…", style=TEXT_MUTED), "", "")

    return Panel(t, title=f"[bold {PRIMARY}] Top Origins [/]", border_style=PRIMARY_DARK, box=box.ROUNDED, padding=(0, 1))

def make_suspicious_panel(conns: list[dict]) -> Panel:
    suspicious = [c for c in conns if c["remote_port"] in SUSPICIOUS_PORTS and not c["is_private"]]

    t = Table.grid(padding=(0, 2))
    t.add_column(no_wrap=True)
    t.add_column(no_wrap=True)
    t.add_column(no_wrap=True)

    if suspicious:
        for c in suspicious[:6]:
            service = SUSPICIOUS_PORTS.get(c["remote_port"], "?")
            t.add_row(
                Text(normalize_ipv6(c["remote_ip"])[:18], style=TEXT_LIGHT),
                Text(f":{c['remote_port']} {service}",   style=f"bold {DANGER}"),
                Text(c["process"], style=ACCENT),
            )
    else:
        t.add_row(Text("  ✓ No suspicious ports", style=SUCCESS), "", "")

    return Panel(t, title=f"[bold {DANGER}] ⚠ Suspicious Ports [/]", border_style=PRIMARY_DARK, box=box.ROUNDED, padding=(0, 1))

def make_process_panel(conns: list[dict]) -> Panel:
    proc_count: defaultdict = defaultdict(int)
    for c in conns:
        proc_count[c["process"]] += 1

    top_procs = sorted(proc_count.items(), key=lambda x: x[1], reverse=True)[:8]

    t = Table.grid(padding=(0, 2))
    t.add_column(no_wrap=True)
    t.add_column(no_wrap=True, justify="right")

    for pname, cnt in top_procs:
        if pname.startswith("["):
            style = INFO
        elif pname.startswith("PID:"):
            style = TEXT_MUTED
        else:
            style = ACCENT
        t.add_row(
            Text(pname, style=style),
            Text(f"{cnt} conn{'s' if cnt>1 else ''}", style=TEXT_MUTED),
        )

    if not top_procs:
        t.add_row(Text("No active processes", style=TEXT_MUTED), "")

    return Panel(t, title=f"[bold {PRIMARY}] By Process [/]", border_style=PRIMARY_DARK, box=box.ROUNDED, padding=(0, 1))

def make_new_ips_panel() -> Panel:
    """Shows recently discovered IPs this session."""
    t = Table.grid(padding=(0, 1))
    t.add_column(no_wrap=True, style=TEXT_MUTED)
    t.add_column(no_wrap=True, style=TEXT_LIGHT)
    t.add_column(no_wrap=True, style=TEXT_MUTED, justify="right")
    t.add_column(no_wrap=True, style=INFO)

    items = list(_new_ips)[:6]
    if items:
        for entry in items:
            ip  = entry["ip"]
            geo = _geo_results.get(ip) or _geo_cache.get(ip)
            country = geo.get("country", "…") if geo else "…"
            t.add_row(
                entry["time"],
                ip[:18],
                str(entry["port"]),
                f"{flag_for_country(country)} {country[:10]}",
            )
    else:
        t.add_row("", Text("Monitoring…", style=TEXT_MUTED), "", "")

    return Panel(t, title=f"[bold {ACCENT}] New IPs This Session [/]", border_style=PRIMARY_DARK, box=box.ROUNDED, padding=(0, 1))

def make_footer() -> Panel:
    t = Text(justify="center")
    t.append("Ctrl+C", style=f"bold {PRIMARY}")
    t.append(" exit  ", style=TEXT_MUTED)
    t.append("log → ", style=TEXT_MUTED)
    t.append("whoknocks_log.json", style=ACCENT)
    t.append("  ·  WhoKnocks v2 by ", style=TEXT_MUTED)
    t.append("AxthonyV", style=f"bold {PRIMARY}")
    t.append("  ·  github.com/AxthonyV", style=TEXT_MUTED)
    return Panel(Align.center(t), style=PRIMARY_DARK, box=box.HORIZONTALS, padding=(0, 1))

# ─── Layout ───────────────────────────────────────────────────────────────────

def build_layout() -> Layout:
    """Build a fixed 5-panel bottom layout. Panels update content dynamically."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_column(
        Layout(name="main",   ratio=3),
        Layout(name="bottom", ratio=2),
    )
    layout["bottom"].split_row(
        Layout(name="stats",       ratio=1),
        Layout(name="countries",   ratio=1),
        Layout(name="suspicious",  ratio=1),
        Layout(name="processes",   ratio=1),
        Layout(name="new_ips",     ratio=1),
    )
    return layout

def update_layout(layout: Layout, conns: list[dict]):
    """Update all panel contents. Panels adapt internally to terminal size."""
    layout["header"].update(make_header())
    layout["main"].update(make_connections_panel(conns))
    layout["stats"].update(make_stats_panel(conns))
    layout["countries"].update(make_top_countries_panel())
    layout["suspicious"].update(make_suspicious_panel(conns))
    layout["processes"].update(make_process_panel(conns))
    layout["new_ips"].update(make_new_ips_panel())
    layout["footer"].update(make_footer())

def save_log(conns: list[dict]):
    entries = []
    for c in conns:
        ip  = normalize_ipv6(c["remote_ip"])
        geo = _geo_results.get(ip) or _geo_cache.get(ip) or {}
        entries.append({
            "time":        c["seen_at"],
            "remote_ip":   ip,
            "remote_port": c["remote_port"],
            "country":     geo.get("country", "?"),
            "city":        geo.get("city",    "?"),
            "isp":         geo.get("isp",     "?"),
            "process":     c["process"],
            "pid":         c["pid"],
            "threat":      c["threat"],
            "status":      c["status"],
        })
    try:
        _log_path.write_text(json.dumps(entries, indent=2))
    except Exception:
        pass

# ─── Entry point ──────────────────────────────────────────────────────────────

def run():
    console.clear()

    if IS_WINDOWS:
        console.print(f"\n  [dim]Tip: Run as Administrator for full process name visibility.[/]\n")
        time.sleep(1)

    psutil.net_connections(kind="inet")  # warm up

    layout = build_layout()
    tick   = 0

    try:
        with Live(layout, refresh_per_second=2, screen=True, console=console):
            while True:
                conns = get_connections()

                for c in conns:
                    _total_seen.add(normalize_ipv6(c["remote_ip"]))

                if tick % 2 == 0:
                    threading.Thread(target=_bg_geo_fetch, args=(conns,), daemon=True).start()

                if tick % 12 == 0:
                    threading.Thread(target=save_log, args=(conns,), daemon=True).start()

                update_layout(layout, conns)
                tick += 1
                time.sleep(0.5)

    except KeyboardInterrupt:
        console.clear()
        save_log(get_connections())
        console.print(f"\n  [bold {PRIMARY}]WhoKnocks[/] [dim]closed. Log saved.[/]\n")

if __name__ == "__main__":
    run()
