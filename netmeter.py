#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetMeter v2 - network usage monitor + traffic inspector for Linux (PyQt6, single file)

Pages:
  Dashboard   live speed, usage since boot / today / month, top apps (donut chart)
  Apps        per-app usage; click an app for full details (process info, sockets,
              usage history, and a live packet log - Burp-style, but passive: no proxy)
  Inspector   live packet capture on this machine (tcpdump), flows table, packet decoder
              (DNS, TLS SNI, plain HTTP, hex dump, follow-flow). Scope: default route
              interface (gateway), all interfaces, or one specific interface
  Interfaces  live per-interface speed + DAILY usage limits with alerts (80% / 100%)
  Networks    per-network (Wi-Fi / Ethernet) usage + monthly quota with remaining data
  History     daily / monthly / per-boot-session usage with charts

Install:   pip install PyQt6      (or: sudo pacman -S python-pyqt6)
Optional:  sudo pacman -S tcpdump libnotify nethogs
Run:       python3 netmeter.py            (detaches from the terminal)
Debug:     python3 netmeter.py --foreground
Options:   --minimized  --install-autostart  --remove-autostart

Packet capture permissions (pick ONE):
  a) do nothing: NetMeter asks for authorization with pkexec each time you press Start
  b) sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)    (no prompt; any local
     user can then sniff with tcpdump - fine on a single-user laptop)

What the Inspector can and cannot see:
  * It sees packets of THIS machine only. It does not intercept other devices or the modem.
  * HTTPS/QUIC payloads are encrypted: you get hostnames (SNI/DNS), sizes, timing, flags.
    Plain HTTP shows request lines and headers.
"""

import fcntl
import html as _html
import math
import os
import pwd
import re
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import date, datetime, timedelta
from pathlib import Path

from PyQt6.QtCore import (QAbstractTableModel, QModelIndex, QPointF, QRectF, QSize, Qt,
                          QThread, QTimer, pyqtSignal)
from PyQt6.QtGui import (QAction, QColor, QFont, QFontMetrics, QIcon, QLinearGradient,
                         QPainter, QPainterPath, QPen, QPixmap, QPolygonF)
from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QButtonGroup, QCheckBox,
                             QComboBox, QFrame, QHBoxLayout, QHeaderView, QInputDialog,
                             QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox,
                             QPlainTextEdit, QPushButton, QSplitter, QStackedWidget,
                             QStyledItemDelegate, QSystemTrayIcon, QTabWidget,
                             QTableView, QTableWidget, QTableWidgetItem, QTextBrowser,
                             QToolTip, QVBoxLayout, QWidget)

APP_NAME = "NetMeter"
DB_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "netmeter"
DB_PATH = DB_DIR / "usage.db"
LOG_PATH = DB_DIR / "netmeter.log"
AUTOSTART_FILE = Path.home() / ".config/autostart/netmeter.desktop"
FLUSH_EVERY = 3.0
GB = 1024 ** 3

SNAPLEN = 700          # bytes captured per packet
MAX_PACKETS = 20000    # packets kept in memory by the inspector
MAX_FLOWS = 6000

C_BG = "#0b0f17"
C_SIDE = "#0e131d"
C_PANEL = "#121826"
C_PANEL2 = "#161d2c"
C_BORDER = "#1c2536"
C_TEXT = "#e6e9ef"
C_MUTED = "#8b93a3"
C_DL = "#4cc9f0"
C_UL = "#b388ff"
C_OK = "#3ddc97"
C_WARN = "#ffb703"
C_BAD = "#ff5d73"
PALETTE = [C_DL, C_UL, C_OK, C_WARN, "#ff7a90", "#6ea8ff", "#f78fb3"]


# ───────────────────────── formatting helpers ─────────────────────────

def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def fmt_speed(bps):
    return fmt_bytes(bps) + "/s"


def fmt_dur(sec):
    sec = int(sec)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)


def hexdump(b, width=16):
    out = []
    for i in range(0, len(b), width):
        ch = b[i:i + width]
        hx = " ".join(f"{c:02x}" for c in ch)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in ch)
        out.append(f"{i:04x}  {hx:<{width * 3 - 1}}  {asc}")
    return "\n".join(out)


# ───────────────────────── database ─────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(boot_id TEXT PRIMARY KEY, start_ts REAL, last_ts REAL);
CREATE TABLE IF NOT EXISTS net_usage(day TEXT, boot_id TEXT, net TEXT, rx INTEGER, tx INTEGER,
                                     PRIMARY KEY(day, boot_id, net));
CREATE TABLE IF NOT EXISTS app_usage(day TEXT, boot_id TEXT, app TEXT, rx INTEGER, tx INTEGER,
                                     PRIMARY KEY(day, boot_id, app));
CREATE TABLE IF NOT EXISTS iface_usage(day TEXT, boot_id TEXT, iface TEXT, rx INTEGER, tx INTEGER,
                                       PRIMARY KEY(day, boot_id, iface));
CREATE TABLE IF NOT EXISTS ifstate(iface TEXT PRIMARY KEY, boot_id TEXT, rx INTEGER, tx INTEGER);
CREATE TABLE IF NOT EXISTS quotas(net TEXT PRIMARY KEY, quota_bytes INTEGER, cycle_day INTEGER);
CREATE TABLE IF NOT EXISTS limits(kind TEXT, name TEXT, daily_bytes INTEGER, PRIMARY KEY(kind, name));
CREATE TABLE IF NOT EXISTS alerts_sent(key TEXT PRIMARY KEY);
"""


def open_db():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.executescript(SCHEMA)
    return db


def read_boot_id():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "unknown-boot"


def read_uptime():
    try:
        return float(Path("/proc/uptime").read_text().split()[0])
    except OSError:
        return 0.0


BOOT_ID = read_boot_id()


def today_str():
    return date.today().isoformat()


def period_clause(period):
    t = date.today()
    if period == "session":
        return "boot_id=?", (BOOT_ID,)
    if period == "today":
        return "day=?", (t.isoformat(),)
    if period == "week":
        return "day>=?", ((t - timedelta(days=6)).isoformat(),)
    if period == "month":
        return "day>=?", (t.replace(day=1).isoformat(),)
    return "1=1", ()


def totals(db, period):
    w, p = period_clause(period)
    return db.execute(f"SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM net_usage WHERE {w}", p).fetchone()


def cycle_start(cycle_day, today=None):
    today = today or date.today()
    d = max(1, min(int(cycle_day), 28))
    if today.day >= d:
        return today.replace(day=d)
    prev_month_last = today.replace(day=1) - timedelta(days=1)
    return prev_month_last.replace(day=d)


def cycle_used(db, net, cycle_day):
    start = cycle_start(cycle_day).isoformat()
    return db.execute("SELECT COALESCE(SUM(rx+tx),0) FROM net_usage WHERE net=? AND day>=?",
                      (net, start)).fetchone()[0]


# ───────────────────────── system helpers ─────────────────────────

SS_PROC = re.compile(r'\(\("((?:[^"\\]|\\.)*)",pid=(\d+)')
RE_SENT = re.compile(r"\bbytes_sent:(\d+)")
RE_RECV = re.compile(r"\bbytes_received:(\d+)")
RE_RTT = re.compile(r"\brtt:([\d.]+)/")


def physical_ifaces():
    base = Path("/sys/class/net")
    try:
        return sorted(p.name for p in base.iterdir() if p.name != "lo" and (p / "device").exists())
    except OSError:
        return []


def iface_up(iface):
    try:
        return Path(f"/sys/class/net/{iface}/operstate").read_text().strip() in ("up", "unknown")
    except OSError:
        return False


def iface_type(iface):
    if os.path.isdir(f"/sys/class/net/{iface}/wireless"):
        return "Wi-Fi"
    if iface.startswith(("en", "eth")):
        return "Ethernet"
    if iface.startswith("ww"):
        return "Mobile"
    if iface.startswith("usb"):
        return "USB"
    return "Other"


def read_net_dev():
    phys = set(physical_ifaces())
    res = {}
    try:
        with open("/proc/net/dev") as f:
            lines = f.read().splitlines()[2:]
    except OSError:
        return res
    for line in lines:
        name, _, data = line.partition(":")
        name = name.strip()
        if name in phys:
            cols = data.split()
            res[name] = (int(cols[0]), int(cols[8]))
    return res


def _split_nm(line):
    parts = re.split(r"(?<!\\):", line)
    return [p.replace("\\:", ":").replace("\\\\", "\\") for p in parts]


def network_names():
    """{iface: network name (SSID or connection name)}"""
    names = {}
    try:
        out = subprocess.run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"],
                             capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            p = _split_nm(line)
            if len(p) >= 2 and p[1] and p[1] != "--":
                names[p[1]] = p[0]
    except Exception:
        pass
    if shutil.which("iwgetid"):
        for iface in physical_ifaces():
            if iface not in names and os.path.isdir(f"/sys/class/net/{iface}/wireless"):
                try:
                    ssid = subprocess.run(["iwgetid", iface, "-r"], capture_output=True,
                                          text=True, timeout=2).stdout.strip()
                    if ssid:
                        names[iface] = ssid
                except Exception:
                    pass
    return names


def is_loopback(ip):
    return ip.startswith("127.") or ip == "::1" or ip.startswith("::ffff:127.")


def split_addr(a):
    ip, _, port = a.rpartition(":")
    ip = ip.strip("[]").split("%")[0]
    try:
        return ip, int(port)
    except ValueError:
        return ip, 0


def ss_connections(kind="t", info=False, all_socks=False):
    """Parse `ss` output. kind: 't' (tcp) or 'u' (udp) - one at a time so the format is stable."""
    cmd = ["ss", "-H", "-n", "-p", f"-{kind}"]
    if all_socks:
        cmd.append("-a")
    if info:
        cmd.append("-i")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return []
    proto = "tcp" if kind == "t" else "udp"
    conns, cur = [], None
    for line in out.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            if cur:
                conns.append(cur)
            f = line.split()
            if len(f) < 5:
                cur = None
                continue
            lip, lport = split_addr(f[3])
            rip, rport = split_addr(f[4])
            m = SS_PROC.search(line)
            cur = {"proto": proto, "state": f[0], "lip": lip, "lport": lport, "rip": rip, "rport": rport,
                   "name": m.group(1) if m else None, "pid": int(m.group(2)) if m else None,
                   "sent": None, "recv": None, "rtt": None}
        elif cur:
            ms, mr, mt = RE_SENT.search(line), RE_RECV.search(line), RE_RTT.search(line)
            if ms:
                cur["sent"] = int(ms.group(1))
            if mr:
                cur["recv"] = int(mr.group(1))
            if mt:
                cur["rtt"] = float(mt.group(1))
    if cur:
        conns.append(cur)
    return conns


def local_ip_set():
    ips = set()
    try:
        out = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            f = line.split()
            if len(f) >= 4 and f[2] in ("inet", "inet6"):
                ips.add(f[3].split("/")[0])
    except Exception:
        pass
    return ips


def gateway_info():
    """Default route: {'gw','dev','mac','metric'} or None."""
    try:
        out = subprocess.run(["ip", "-o", "route", "show", "default"], capture_output=True,
                             text=True, timeout=3).stdout
    except Exception:
        return None
    best = None
    for line in out.splitlines():
        f = line.split()
        if "via" in f and "dev" in f:
            metric = int(f[f.index("metric") + 1]) if "metric" in f else 0
            if best is None or metric < best["metric"]:
                best = {"gw": f[f.index("via") + 1], "dev": f[f.index("dev") + 1], "metric": metric, "mac": None}
    if best:
        try:
            out = subprocess.run(["ip", "neigh", "show", best["gw"], "dev", best["dev"]],
                                 capture_output=True, text=True, timeout=3).stdout
            f = out.split()
            if "lladdr" in f:
                best["mac"] = f[f.index("lladdr") + 1]
        except Exception:
            pass
    return best


def find_pids(app, conns=None):
    pids = sorted({c["pid"] for c in (conns or []) if c["name"] == app and c["pid"]})
    if pids:
        return pids
    try:
        for d in os.listdir("/proc"):
            if d.isdigit():
                try:
                    if Path(f"/proc/{d}/comm").read_text().strip() == app[:15]:
                        pids.append(int(d))
                except OSError:
                    pass
    except OSError:
        pass
    return pids


def proc_info(pid):
    d = {"pid": pid, "exe": "(no access)", "cmdline": "", "user": "?", "rss": 0, "threads": 0, "started": None}
    try:
        d["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        d["cmdline"] = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
    except OSError:
        pass
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
                try:
                    d["user"] = pwd.getpwuid(uid).pw_name
                except KeyError:
                    d["user"] = str(uid)
            elif line.startswith("VmRSS:"):
                d["rss"] = int(line.split()[1]) * 1024
            elif line.startswith("Threads:"):
                d["threads"] = int(line.split()[1])
    except OSError:
        pass
    try:
        data = Path(f"/proc/{pid}/stat").read_text()
        fields = data[data.rfind(")") + 2:].split()
        ticks = int(fields[19])
        d["started"] = time.time() - read_uptime() + ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        pass
    return d


# ───────────────────────── packet parsing (pure Python, no dependencies) ─────────────────────────

class PcapStream:
    """Incremental parser for the pcap stream produced by `tcpdump -w -`."""

    def __init__(self):
        self.buf = bytearray()
        self.endian = None
        self.nano = False
        self.linktype = None

    def feed(self, chunk):
        buf = self.buf
        buf += chunk
        out, pos = [], 0
        while True:
            if self.endian is None:
                if len(buf) - pos < 24:
                    break
                magic = bytes(buf[pos:pos + 4])
                if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                    self.endian = "<"
                elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                    self.endian = ">"
                else:
                    raise ValueError("not a pcap stream")
                self.nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
                self.linktype = struct.unpack_from(self.endian + "I", buf, pos + 20)[0] & 0x0FFFFFFF
                pos += 24
                continue
            if len(buf) - pos < 16:
                break
            sec, frac, caplen, _ = struct.unpack_from(self.endian + "IIII", buf, pos)
            if caplen > 262144:
                raise ValueError("bad packet length")
            if len(buf) - pos < 16 + caplen:
                break
            data = bytes(buf[pos + 16:pos + 16 + caplen])
            pos += 16 + caplen
            out.append((sec + frac / (1e9 if self.nano else 1e6), data))
        del buf[:pos]
        return out


def l2_strip(data, lt):
    """-> (ethertype, ip_bytes, pkttype, ifindex) or None"""
    if lt == 1:  # Ethernet
        if len(data) < 14:
            return None
        et, off = (data[12] << 8) | data[13], 14
        while et in (0x8100, 0x88A8) and len(data) >= off + 4:
            et = (data[off + 2] << 8) | data[off + 3]
            off += 4
        return et, data[off:], None, None
    if lt == 113:  # Linux cooked v1
        if len(data) < 16:
            return None
        return (data[14] << 8) | data[15], data[16:], (data[0] << 8) | data[1], None
    if lt == 276:  # Linux cooked v2
        if len(data) < 20:
            return None
        return (data[0] << 8) | data[1], data[20:], data[10], int.from_bytes(data[4:8], "big")
    if lt in (101, 12, 14):  # raw IP
        if not data:
            return None
        return (0x0800 if data[0] >> 4 == 4 else 0x86DD), data, None, None
    return None


def parse_ip(et, b):
    """-> (ver, src, dst, proto, l4_bytes, total_len, ttl, hdr_len) or None"""
    if et == 0x0800:
        if len(b) < 20:
            return None
        ihl = (b[0] & 0x0F) * 4
        frag = ((b[6] & 0x1F) << 8) | b[7]
        pl = b[ihl:] if not frag else b""
        return (4, socket.inet_ntoa(b[12:16]), socket.inet_ntoa(b[16:20]), b[9], pl,
                (b[2] << 8) | b[3], b[8], ihl)
    if et == 0x86DD:
        if len(b) < 40:
            return None
        nxt, off = b[6], 40
        while nxt in (0, 43, 60) and len(b) >= off + 8:
            ln = (b[off + 1] + 1) * 8
            nxt = b[off]
            off += ln
        return (6, socket.inet_ntop(socket.AF_INET6, b[8:24]), socket.inet_ntop(socket.AF_INET6, b[24:40]),
                nxt, b[off:], ((b[4] << 8) | b[5]) + 40, b[7], off)
    return None


TCP_FLAG_BITS = ((0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"), (0x20, "URG"))


def tcp_flags_str(f):
    return ",".join(n for bit, n in TCP_FLAG_BITS if f & bit) or "-"


DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


def dns_name(d, off):
    labels, jumped, ret, hops = [], False, None, 0
    while True:
        if off >= len(d) or hops > 20:
            return None, off
        l = d[off]
        if l == 0:
            off += 1
            break
        if l & 0xC0 == 0xC0:
            if off + 1 >= len(d):
                return None, off
            ptr = ((l & 0x3F) << 8) | d[off + 1]
            if not jumped:
                ret, jumped = off + 2, True
            off, hops = ptr, hops + 1
            continue
        off += 1
        labels.append(d[off:off + l].decode("ascii", "replace"))
        off += l
    return ".".join(labels), (ret if jumped else off)


def parse_dns(d):
    """-> (is_response, qname, qtype, rcode, [(name, ip)]) or None"""
    if len(d) < 12:
        return None
    flags, qd, an = (d[2] << 8) | d[3], (d[4] << 8) | d[5], (d[6] << 8) | d[7]
    off, qname, qtype = 12, None, None
    for _ in range(qd):
        n, off = dns_name(d, off)
        if n is None or off + 4 > len(d):
            return None
        if qname is None:
            qname, qtype = n, (d[off] << 8) | d[off + 1]
        off += 4
    answers = []
    for _ in range(an):
        n, off = dns_name(d, off)
        if n is None or off + 10 > len(d):
            break
        t, rdlen = (d[off] << 8) | d[off + 1], (d[off + 8] << 8) | d[off + 9]
        off += 10
        rd = d[off:off + rdlen]
        off += rdlen
        if t == 1 and rdlen == 4:
            answers.append((qname or n, socket.inet_ntoa(rd)))
        elif t == 28 and rdlen == 16:
            answers.append((qname or n, socket.inet_ntop(socket.AF_INET6, rd)))
    return bool(flags & 0x8000), qname, qtype, flags & 0xF, answers


def parse_sni(d):
    try:
        if len(d) < 6 or d[0] != 0x16 or d[5] != 0x01:
            return None
        pos = 9 + 2 + 32
        pos += 1 + d[pos]
        pos += 2 + ((d[pos] << 8) | d[pos + 1])
        pos += 1 + d[pos]
        el = (d[pos] << 8) | d[pos + 1]
        pos += 2
        end = min(pos + el, len(d))
        while pos + 4 <= end:
            et, ln = (d[pos] << 8) | d[pos + 1], (d[pos + 2] << 8) | d[pos + 3]
            pos += 4
            if et == 0 and d[pos + 2] == 0:
                nl = (d[pos + 3] << 8) | d[pos + 4]
                return d[pos + 5:pos + 5 + nl].decode("ascii", "replace")
            pos += ln
    except IndexError:
        return None
    return None


HTTP_START = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"HTTP/1.")


def parse_http(d):
    if d.startswith(HTTP_START):
        head = d.split(b"\r\n\r\n", 1)[0]
        lines = head.decode("latin-1").split("\r\n")
        host = None
        for ln in lines[1:]:
            if ln.lower().startswith("host:"):
                host = ln[5:].strip()
        return lines[0], host, lines
    return None


TLS_HS = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 11: "Certificate",
          12: "ServerKeyExchange", 14: "ServerHelloDone", 16: "ClientKeyExchange", 20: "Finished"}


class Packet:
    __slots__ = ("seq", "ts", "iface", "dir", "proto", "lip", "lport", "rip", "rport", "length",
                 "flags", "tseq", "tack", "win", "ttl", "info", "payload", "flow")


class Flow:
    __slots__ = ("proto", "lip", "lport", "rip", "rport", "app", "pid", "host", "kind", "pkts_out",
                 "pkts_in", "bytes_out", "bytes_in", "first", "last", "iface")


# ───────────────────────── capture engine (tcpdump) ─────────────────────────

class CaptureEngine(QThread):
    status = pyqtSignal(str)
    stateChanged = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.packets = deque(maxlen=MAX_PACKETS)
        self.flows = {}
        self.dns = {}
        self.seq = 0
        self.proc = None
        self.running = False
        self.port_map = {}
        self.local_ips = set()
        self.iface = "any"
        self.bpf = ""
        self._stop = threading.Event()
        self._ifnames = {}
        self.err_lines = deque(maxlen=20)

    def configure(self, iface, bpf=""):
        self.iface, self.bpf = iface, bpf

    def stop(self):
        self._stop.set()

    def clear(self):
        with self.lock:
            self.packets.clear()
            self.flows.clear()

    # -- queries used by the UI --
    def packets_since(self, seq):
        with self.lock:
            if not self.packets or self.packets[-1].seq <= seq:
                return []
            out = []
            for p in reversed(self.packets):
                if p.seq <= seq:
                    break
                out.append(p)
        out.reverse()
        return out

    def packets_snapshot(self):
        with self.lock:
            return list(self.packets)

    def flows_snapshot(self):
        with self.lock:
            return sorted(self.flows.values(), key=lambda f: -f.last)

    def flow_packets(self, flow, limit=300):
        with self.lock:
            out = [p for p in self.packets if p.flow is flow]
        return out[-limit:]

    # -- thread body --
    def run(self):
        stop = self._stop = threading.Event()
        self.running = True
        self.err_lines.clear()
        self.stateChanged.emit(True)
        proc = None
        try:
            self.local_ips = local_ip_set()
            proc = self._spawn(stop)
            if proc is None:
                return
            self.proc = proc
            threading.Thread(target=self._ss_loop, args=(stop,), daemon=True).start()
            self._read_loop(proc, stop)
        except Exception as e:
            self.status.emit(f"Capture error: {e}")
        finally:
            stop.set()
            self._close(proc)
            self.proc = None
            self.running = False
            self.stateChanged.emit(False)

    def _spawn(self, stop):
        exe = shutil.which("tcpdump")
        if not exe:
            self.status.emit("tcpdump is not installed:  sudo pacman -S tcpdump")
            return None
        cmd = [exe, "-l", "-n", "-U", "--immediate-mode", "-s", str(SNAPLEN), "-i", self.iface, "-w", "-"]
        if self.bpf:
            cmd.append(self.bpf)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        threading.Thread(target=self._err_reader, args=(p,), daemon=True).start()
        time.sleep(0.8)
        if p.poll() is None:
            return p
        err = " ".join(self.err_lines).lower()
        if "permission" in err or "not permitted" in err or "operation not permitted" in err:
            self.status.emit("Waiting for authorization (pkexec)...")
            self.err_lines.clear()
            p = subprocess.Popen(["pkexec"] + cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            threading.Thread(target=self._err_reader, args=(p,), daemon=True).start()
            return p
        self.status.emit("tcpdump failed: " + (" ".join(self.err_lines) or "unknown error")[:240])
        return None

    def _err_reader(self, p):
        try:
            for line in iter(p.stderr.readline, b""):
                self.err_lines.append(line.decode(errors="replace").strip())
        except Exception:
            pass

    def _read_loop(self, proc, stop):
        import select
        fd = proc.stdout.fileno()
        stream = PcapStream()
        started = False
        while not stop.is_set():
            r, _, _ = select.select([fd], [], [], 0.5)
            if not r:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            for ts, data in stream.feed(chunk):
                if not started:
                    started = True
                    self.status.emit(f"Capturing on {self.iface}" + (f"  (filter: {self.bpf})" if self.bpf else ""))
                self._handle(ts, data, stream.linktype)
            if not started and stream.linktype is not None:
                started = True
                self.status.emit(f"Capturing on {self.iface}" + (f"  (filter: {self.bpf})" if self.bpf else ""))
        if not started:
            self.status.emit("Capture did not start: " + (" ".join(self.err_lines) or "authorization cancelled?")[:240])
        elif not stop.is_set():
            self.status.emit("Capture ended: " + " ".join(self.err_lines)[-200:])

    def _close(self, proc):
        if not proc:
            return
        try:
            proc.stdout.close()  # tcpdump exits on SIGPIPE; works even for the root pkexec process
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass
        threading.Thread(target=proc.wait, daemon=True).start()

    def _ss_loop(self, stop):
        n = 0
        while not stop.is_set():
            try:
                pm = {}
                for kind in ("t", "u"):
                    for c in ss_connections(kind, all_socks=True):
                        if c["name"] and c["lport"]:
                            pm[(c["proto"], c["lport"])] = (c["name"], c["pid"])
                self.port_map = pm
                if n % 10 == 0:
                    self.local_ips = local_ip_set()
                n += 1
                with self.lock:
                    for fl in self.flows.values():
                        if fl.app is None:
                            v = pm.get((fl.proto, fl.lport))
                            if v:
                                fl.app, fl.pid = v
            except Exception:
                pass
            stop.wait(1.0)

    def _if_name(self, idx):
        if idx not in self._ifnames:
            try:
                self._ifnames[idx] = socket.if_indextoname(idx)
            except OSError:
                self._ifnames[idx] = f"if{idx}"
        return self._ifnames[idx]

    def _handle(self, ts, data, lt):
        r = l2_strip(data, lt)
        if not r:
            return
        et, b, pkttype, ifidx = r
        ip = parse_ip(et, b)
        if not ip:
            return
        ver, src, dst, proto, pl, total, ttl, hlen = ip
        if is_loopback(src) or is_loopback(dst):
            return
        sport = dport = 0
        flags = ""
        tseq = tack = win = 0
        payload = b""
        l4hdr = 0
        if proto == 6 and len(pl) >= 20:
            sport, dport = struct.unpack("!HH", pl[:4])
            tseq, tack = struct.unpack("!II", pl[4:12])
            win = (pl[14] << 8) | pl[15]
            flags = tcp_flags_str(pl[13])
            l4hdr = (pl[12] >> 4) * 4
            payload = pl[l4hdr:]
            pname = "tcp"
        elif proto == 17 and len(pl) >= 8:
            sport, dport = struct.unpack("!HH", pl[:2] + pl[2:4])
            l4hdr = 8
            payload = pl[8:]
            pname = "udp"
        elif proto == 1:
            pname = "icmp"
        elif proto == 58:
            pname = "icmpv6"
        else:
            pname = f"ip/{proto}"
        plen = max(total - hlen - l4hdr, 0) if proto in (6, 17) else 0

        # direction
        if src in self.local_ips:
            direction, lip, lport, rip, rport = "out", src, sport, dst, dport
        elif dst in self.local_ips:
            direction, lip, lport, rip, rport = "in", dst, dport, src, sport
        elif pkttype in (0, 1, 2):
            direction, lip, lport, rip, rport = "in", dst, dport, src, sport
        elif pkttype == 4:
            direction, lip, lport, rip, rport = "out", src, sport, dst, dport
        else:
            direction, lip, lport, rip, rport = "fwd", src, sport, dst, dport

        # application layer
        info, host, kind = "", None, None
        if pname in ("tcp", "udp"):
            if sport in (53, 5353) or dport in (53, 5353):
                dn = parse_dns(payload[2:] if pname == "tcp" else payload)
                if dn:
                    is_resp, qname, qtype, rcode, answers = dn
                    tn = DNS_TYPES.get(qtype, str(qtype))
                    kind = "DNS"
                    if is_resp:
                        info = f"DNS response {tn} {qname} -> " + (", ".join(a[1] for a in answers) if answers
                                                                    else ("NXDOMAIN" if rcode == 3 else "no answer"))
                        for name, addr in answers:
                            self.dns[addr] = name
                        if len(self.dns) > 20000:
                            self.dns.clear()
                    else:
                        info = f"DNS query {tn} {qname}"
            if not info and pname == "tcp" and payload:
                sni = parse_sni(payload)
                http = None
                if sni:
                    info, host, kind = f"TLS ClientHello  SNI={sni}", sni, "TLS"
                    self.dns.setdefault(rip, sni)
                elif len(payload) > 5 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
                    kind = "TLS"
                    if payload[0] == 0x16:
                        info = "TLS handshake " + TLS_HS.get(payload[5], "")
                    elif payload[0] == 0x17:
                        info = f"TLS application data ({plen} B)"
                    elif payload[0] == 0x15:
                        info = "TLS alert"
                    else:
                        info = "TLS change-cipher-spec"
                else:
                    http = parse_http(payload)
                    if http:
                        kind, host = "HTTP", http[1]
                        info = "HTTP " + http[0][:140]
            if not info and pname == "udp" and 443 in (sport, dport) and payload and payload[0] & 0x80:
                info, kind = f"QUIC ({plen} B)", "QUIC"
        if not info:
            info = (flags if pname == "tcp" else pname.upper())
            if plen:
                info += f"  len={plen}"

        # flow bookkeeping
        key = (pname, lip, lport, rip, rport)
        with self.lock:
            fl = self.flows.get(key)
            if fl is None:
                fl = Flow()
                fl.proto, fl.lip, fl.lport, fl.rip, fl.rport = pname, lip, lport, rip, rport
                fl.app = fl.pid = fl.host = fl.kind = None
                fl.pkts_out = fl.pkts_in = fl.bytes_out = fl.bytes_in = 0
                fl.first = ts
                fl.iface = self.iface if not ifidx else self._if_name(ifidx)
                v = self.port_map.get((pname, lport))
                if v:
                    fl.app, fl.pid = v
                self.flows[key] = fl
                if len(self.flows) > MAX_FLOWS:
                    for k, _ in sorted(self.flows.items(), key=lambda kv: kv[1].last)[:MAX_FLOWS // 6]:
                        del self.flows[k]
            fl.last = ts
            if direction == "in":
                fl.pkts_in += 1
                fl.bytes_in += total
            else:
                fl.pkts_out += 1
                fl.bytes_out += total
            if host and not fl.host:
                fl.host = host
            if kind and (fl.kind is None or kind in ("TLS", "HTTP")):
                fl.kind = kind
            self.seq += 1
            p = Packet()
            p.seq, p.ts, p.dir, p.proto = self.seq, ts, direction, pname
            p.iface = fl.iface if not ifidx else self._if_name(ifidx)
            p.lip, p.lport, p.rip, p.rport = lip, lport, rip, rport
            p.length, p.flags, p.tseq, p.tack, p.win, p.ttl = total, flags, tseq, tack, win, ttl
            p.info, p.payload, p.flow = info, payload[:SNAPLEN], fl
            self.packets.append(p)


def packet_detail(p, engine):
    fl = p.flow
    host = fl.host or engine.dns.get(p.rip) or "-"
    dirtxt = {"out": "outgoing (sent by this machine)", "in": "incoming (received)"}.get(p.dir, "forwarded / unknown")
    L = [f"Packet #{p.seq}    {datetime.fromtimestamp(p.ts):%Y-%m-%d %H:%M:%S.%f}", "",
         "== General ==",
         f"Application : {fl.app or 'unknown'}" + (f"   (pid {fl.pid})" if fl.pid else ""),
         f"Direction   : {dirtxt}",
         f"Interface   : {p.iface}",
         f"Local       : {p.lip}:{p.lport}",
         f"Remote      : {p.rip}:{p.rport}      host: {host}",
         f"Protocol    : {p.proto.upper()}",
         f"IP length   : {p.length} bytes      TTL / hop limit: {p.ttl}"]
    if p.proto == "tcp":
        L += ["", "== TCP ==", f"Flags       : {p.flags}", f"Seq / Ack   : {p.tseq} / {p.tack}", f"Window      : {p.win}"]
    L += ["", "== Summary ==", p.info]
    http = parse_http(p.payload) if p.payload else None
    if http:
        L += ["", "== HTTP (plain text) =="] + http[2]
    if p.payload:
        L += ["", f"== Payload (first {len(p.payload)} bytes captured) ==", hexdump(p.payload)]
    elif p.proto in ("tcp", "udp"):
        L += ["", "(no payload)"]
    return "\n".join(L)


def follow_text(engine, flow):
    out = []
    for p in engine.flow_packets(flow):
        if not p.payload:
            continue
        arrow = "-> SENT    " if p.dir == "out" else "<- RECEIVED"
        out.append(f"{arrow}  {datetime.fromtimestamp(p.ts):%H:%M:%S.%f}"[:-3] + f"   ({len(p.payload)} bytes captured)")
        txt = "".join(chr(c) if (32 <= c < 127 or c in (9, 10, 13)) else "." for c in p.payload)
        out += [txt.replace("\r\n", "\n"), ""]
    return "\n".join(out) or "(no readable payload captured for this flow - HTTPS / QUIC content is encrypted)"


def make_matcher(text="", app=None, proto=None):
    t = (text or "").strip().lower()

    def m(p):
        fl = p.flow
        if app and (fl.app or "unknown") != app:
            return False
        if proto:
            if proto in ("DNS", "TLS", "HTTP", "QUIC"):
                if not p.info.startswith(proto):
                    return False
            elif p.proto != proto.lower():
                return False
        if t:
            hay = f"{fl.app or 'unknown'} {fl.host or ''} {p.rip} {p.rport} {p.lport} {p.proto} {p.info}".lower()
            return t in hay
        return True
    return m


# ───────────────────────── usage collector ─────────────────────────

def nh_name(ident):
    parts = ident.rsplit("/", 2)
    name = (parts[0] if len(parts) == 3 else ident).strip()
    if name.startswith("unknown"):
        return "unknown"
    toks = name.split()
    first = os.path.basename(toks[0]) if toks else name
    if first.startswith("python") and len(toks) > 1:
        for t in toks[1:]:
            if not t.startswith("-"):
                return os.path.basename(t)
    return first or "unknown"


class Collector(QThread):
    live = pyqtSignal(object)   # {"rx","tx","ifaces":{...},"networks":[...]}
    backend = pyqtSignal(str)
    flushed = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._stop_evt = threading.Event()
        self.lock = threading.Lock()
        self.pend_net, self.pend_app, self.pend_if = {}, {}, {}
        self.last, self.names = {}, {}
        self.names_t = 0.0
        self.t_prev = time.time()
        self.first = True
        self.ss_prev = None
        self.nh = None
        self.last_flush = time.time()

    def stop(self):
        self._stop_evt.set()

    # ---- nethogs (optional, more accurate) ----
    def start_nethogs(self):
        exe, ifs = shutil.which("nethogs"), physical_ifaces()
        if not exe or not ifs:
            return None
        try:
            p = subprocess.Popen([exe, "-t", "-d", "1"] + ifs, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except Exception:
            return None
        time.sleep(0.8)
        if p.poll() is not None:
            return None
        threading.Thread(target=self._read_nethogs, args=(p,), daemon=True).start()
        return p

    def _read_nethogs(self, p):
        try:
            for line in p.stdout:
                line = line.rstrip("\n")
                if "\t" not in line:
                    continue
                try:
                    ident, sent, recv = line.rsplit("\t", 2)
                    sent, recv = float(sent), float(recv)
                except ValueError:
                    continue
                tx, rx = int(sent * 1024), int(recv * 1024)
                if rx or tx:
                    self._add_app(nh_name(ident), rx, tx)
        except Exception:
            pass

    def _add_app(self, name, rx, tx):
        with self.lock:
            e = self.pend_app.setdefault(name, [0, 0])
            e[0] += rx
            e[1] += tx

    # ---- ss (default) ----
    def poll_ss(self):
        cur = {}
        for c in ss_connections("t", info=True):
            if is_loopback(c["lip"]) or is_loopback(c["rip"]) or c["sent"] is None:
                continue
            cur[(c["lip"], c["lport"], c["rip"], c["rport"])] = (c["name"] or "unknown", c["sent"], c["recv"] or 0)
        first = self.ss_prev is None
        new_prev = {}
        for key, (name, sent, recv) in cur.items():
            new_prev[key] = (sent, recv)
            if first:
                continue
            p = self.ss_prev.get(key)
            if p is None:
                ds, dr = sent, recv
            else:
                ds, dr = sent - p[0], recv - p[1]
                if ds < 0 or dr < 0:
                    ds, dr = sent, recv
            if ds or dr:
                self._add_app(name, dr, ds)
        self.ss_prev = new_prev

    # ---- main loop ----
    def run(self):
        db = open_db()
        boot_ts = time.time() - read_uptime()
        db.execute("INSERT OR IGNORE INTO sessions(boot_id,start_ts,last_ts) VALUES(?,?,?)",
                   (BOOT_ID, boot_ts, time.time()))
        db.commit()
        # Continue from the last saved counters if restarted mid-boot; otherwise count from boot.
        self.last = {r[0]: (r[1], r[2]) for r in
                     db.execute("SELECT iface,rx,tx FROM ifstate WHERE boot_id=?", (BOOT_ID,))}
        self.nh = self.start_nethogs()
        self.backend.emit("nethogs (accurate)" if self.nh else "ss (approximate; UDP/QUIC not counted)")
        try:
            while True:
                try:
                    self.tick(db)
                except Exception as e:
                    print("tick error:", e, file=sys.stderr)
                if self._stop_evt.wait(1.0):
                    break
            self.flush(db)
        finally:
            if self.nh and self.nh.poll() is None:
                self.nh.terminate()
            db.close()

    def tick(self, db):
        now = time.time()
        dt = max(now - self.t_prev, 0.001)
        self.t_prev = now
        if now - self.names_t > 5:
            self.names = network_names()
            self.names_t = now

        cur = read_net_dev()
        sum_rx = sum_tx = 0
        ifs = {}
        for iface, (rx, tx) in cur.items():
            prx, ptx = self.last.get(iface, (0, 0))
            drx = rx - prx if rx >= prx else rx
            dtx = tx - ptx if tx >= ptx else tx
            self.last[iface] = (rx, tx)
            sum_rx += drx
            sum_tx += dtx
            netname = self.names.get(iface, "")
            ifs[iface] = {"net": netname, "type": iface_type(iface), "up": iface_up(iface),
                          "rx": 0.0 if self.first else drx / dt, "tx": 0.0 if self.first else dtx / dt}
            if drx or dtx:
                with self.lock:
                    for d, k in ((self.pend_net, netname or iface), (self.pend_if, iface)):
                        e = d.setdefault(k, [0, 0])
                        e[0] += drx
                        e[1] += dtx
        active = sorted({v["net"] or i for i, v in ifs.items() if v["net"] or v["up"]})
        self.live.emit({"rx": 0.0 if self.first else sum_rx / dt, "tx": 0.0 if self.first else sum_tx / dt,
                        "ifaces": ifs, "networks": active})
        self.first = False

        if self.nh is not None and self.nh.poll() is not None:
            self.nh = None
            self.backend.emit("ss (approximate; nethogs stopped)")
        if self.nh is None:
            self.poll_ss()

        if now - self.last_flush >= FLUSH_EVERY:
            self.flush(db)
            self.last_flush = now
            self.flushed.emit()

    def flush(self, db):
        day = today_str()
        with self.lock:
            pn, pa, pi = self.pend_net, self.pend_app, self.pend_if
            self.pend_net, self.pend_app, self.pend_if = {}, {}, {}
        for table, col, data in (("net_usage", "net", pn), ("app_usage", "app", pa), ("iface_usage", "iface", pi)):
            for k, (rx, tx) in data.items():
                db.execute(f"""INSERT INTO {table}(day,boot_id,{col},rx,tx) VALUES(?,?,?,?,?)
                               ON CONFLICT(day,boot_id,{col}) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx""",
                           (day, BOOT_ID, k, rx, tx))
        for iface, (rx, tx) in self.last.items():
            db.execute("INSERT OR REPLACE INTO ifstate(iface,boot_id,rx,tx) VALUES(?,?,?,?)",
                       (iface, BOOT_ID, rx, tx))
        db.execute("UPDATE sessions SET last_ts=? WHERE boot_id=?", (time.time(), BOOT_ID))
        db.commit()


# ───────────────────────── custom widgets ─────────────────────────

def mono_font(size=9):
    f = QFont("DejaVu Sans Mono")
    f.setStyleHint(QFont.StyleHint.Monospace)
    f.setPointSize(size)
    return f


class SpeedGraph(QWidget):
    N = 90

    def __init__(self):
        super().__init__()
        self.setMinimumHeight(190)
        self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.rx = deque([0.0] * self.N, maxlen=self.N)
        self.tx = deque([0.0] * self.N, maxlen=self.N)

    def push(self, rx, tx):
        self.rx.append(rx)
        self.tx.append(tx)
        if self.isVisible():
            self.update()

    def _path(self, data, w, h, mx):
        path = QPainterPath()
        n = len(data)
        for i, v in enumerate(data):
            x, y = i * w / (n - 1), h - (v / mx) * (h - 34) - 6
            path.moveTo(x, y) if i == 0 else path.lineTo(x, y)
        return path

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(C_PANEL))
        p.drawRoundedRect(QRectF(0, 0, w, h), 14, 14)
        mx = max(max(self.rx), max(self.tx), 50 * 1024.0)
        p.setPen(QPen(QColor("#1d2636"), 1))
        for i in range(1, 4):
            p.drawLine(QPointF(12, 28 + (h - 36) * i / 4), QPointF(w - 12, 28 + (h - 36) * i / 4))
        for data, color in ((self.rx, C_DL), (self.tx, C_UL)):
            line = self._path(data, w, h, mx)
            fill = QPainterPath(line)
            fill.lineTo(w, h)
            fill.lineTo(0, h)
            fill.closeSubpath()
            g = QLinearGradient(0, 0, 0, h)
            c1, c2 = QColor(color), QColor(color)
            c1.setAlpha(80)
            c2.setAlpha(4)
            g.setColorAt(0, c1)
            g.setColorAt(1, c2)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(g)
            p.drawPath(fill)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(QColor(color), 2))
            p.drawPath(line)
        p.setPen(QColor(C_MUTED))
        p.drawText(QRectF(14, 8, 160, 16), Qt.AlignmentFlag.AlignLeft, "max " + fmt_speed(mx))
        x = w - 14
        for label, color, val in (("UP", C_UL, self.tx[-1]), ("DOWN", C_DL, self.rx[-1])):
            txt = f"{label} {fmt_speed(val)}"
            tw = p.fontMetrics().horizontalAdvance(txt)
            p.setPen(QColor(C_TEXT))
            p.drawText(QPointF(x - tw, 20), txt)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(color))
            p.drawEllipse(QPointF(x - tw - 10, 16), 4, 4)
            x -= tw + 30


class DonutChart(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumHeight(190)
        self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.items, self.center = [], ("", "")

    def set_data(self, items, center_main="", center_sub=""):
        self.items, self.center = items, (center_main, center_sub)
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(C_PANEL))
        p.drawRoundedRect(QRectF(0, 0, w, h), 14, 14)
        total = sum(v for _, v, _ in self.items)
        side = min(h - 40, w * 0.42)
        thick = 16
        ring = QRectF(22 + thick / 2, (h - side) / 2 + thick / 2, side - thick, side - thick)
        pen = QPen(QColor("#1d2636"), thick)
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        if total <= 0:
            p.drawArc(ring, 0, 360 * 16)
        else:
            start = 90 * 16
            for _, v, color in self.items:
                span = -int(360 * 16 * v / total)
                pen.setColor(QColor(color))
                p.setPen(pen)
                p.drawArc(ring, start, span)
                start += span
        cx, cy = ring.center().x(), ring.center().y()
        f = p.font()
        f.setPointSize(13)
        f.setBold(True)
        p.setFont(f)
        p.setPen(QColor(C_TEXT))
        p.drawText(QRectF(cx - 60, cy - 18, 120, 22), Qt.AlignmentFlag.AlignCenter, self.center[0] or "-")
        f.setPointSize(8)
        f.setBold(False)
        p.setFont(f)
        p.setPen(QColor(C_MUTED))
        p.drawText(QRectF(cx - 60, cy + 4, 120, 16), Qt.AlignmentFlag.AlignCenter, self.center[1])
        # legend
        f.setPointSize(9)
        p.setFont(f)
        fm = QFontMetrics(f)
        lx, ly = side + 56, (h - min(len(self.items), 7) * 24) / 2 + 4
        for i, (label, v, color) in enumerate(self.items[:7]):
            y = ly + i * 24
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(color))
            p.drawEllipse(QPointF(lx, y + 9), 5, 5)
            vt = fmt_bytes(v)
            vw = fm.horizontalAdvance(vt)
            p.setPen(QColor(C_TEXT))
            p.drawText(QPointF(lx + 14, y + 13), fm.elidedText(label, Qt.TextElideMode.ElideRight, int(w - lx - vw - 44)))
            p.setPen(QColor(C_MUTED))
            p.drawText(QPointF(w - vw - 18, y + 13), vt)


class BarChart(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumHeight(190)
        self.setMouseTracking(True)
        self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.data = []

    def set_data(self, data):
        self.data = data
        self.update()

    def _area(self):
        return QRectF(12, 12, self.width() - 24, self.height() - 38)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(C_PANEL))
        p.drawRoundedRect(QRectF(0, 0, w, h), 14, 14)
        n = len(self.data)
        if n == 0:
            p.setPen(QColor(C_MUTED))
            p.drawText(QRectF(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, "No data recorded yet")
            return
        area = self._area()
        mx = max((r + t) for _, r, t in self.data) or 1
        slot = area.width() / n
        bw = min(slot * 0.68, 38)
        step = max(1, math.ceil(n / 10))
        for i, (lab, rx, tx) in enumerate(self.data):
            x = area.left() + slot * i + (slot - bw) / 2
            hr, ht = area.height() * rx / mx, area.height() * tx / mx
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(C_DL))
            p.drawRoundedRect(QRectF(x, area.bottom() - hr, bw, max(hr, 0)), 3, 3)
            p.setBrush(QColor(C_UL))
            p.drawRoundedRect(QRectF(x, area.bottom() - hr - ht, bw, max(ht, 0)), 3, 3)
            if i % step == 0 or i == n - 1:
                p.setPen(QColor(C_MUTED))
                p.drawText(QRectF(x - 20, h - 22, bw + 40, 18), Qt.AlignmentFlag.AlignCenter, lab)

    def mouseMoveEvent(self, ev):
        if not self.data:
            return
        area = self._area()
        i = int((ev.position().x() - area.left()) / (area.width() / len(self.data)))
        if 0 <= i < len(self.data):
            lab, rx, tx = self.data[i]
            QToolTip.showText(ev.globalPosition().toPoint(),
                              f"{lab}\nDown {fmt_bytes(rx)}   Up {fmt_bytes(tx)}\nTotal: {fmt_bytes(rx + tx)}", self)


class BarDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        ratio = index.data(Qt.ItemDataRole.UserRole) or 0
        color = index.data(Qt.ItemDataRole.UserRole + 1) or C_DL
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(option.rect.adjusted(6, 8, -6, -8))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#1d2636"))
        painter.drawRoundedRect(r, 5, 5)
        w = r.width() * min(max(ratio, 0.0), 1.0)
        if w > 1:
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(QRectF(r.left(), r.top(), w, r.height()), 5, 5)
        painter.setPen(QColor(C_TEXT))
        painter.drawText(r, Qt.AlignmentFlag.AlignCenter, index.data(Qt.ItemDataRole.DisplayRole) or "")
        painter.restore()


class Card(QFrame):
    def __init__(self, title, accent=C_TEXT):
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(2)
        self.t = QLabel(title)
        self.t.setObjectName("cardTitle")
        self.v = QLabel("-")
        self.v.setObjectName("cardValue")
        self.v.setStyleSheet(f"color:{accent};")
        self.s = QLabel("")
        self.s.setObjectName("cardSub")
        for w in (self.t, self.v, self.s):
            lay.addWidget(w)

    def set(self, value, sub=""):
        self.v.setText(value)
        self.s.setText(sub)


def make_table(headers):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(36)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setShowGrid(False)
    t.setAlternatingRowColors(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    t.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    return t


def cell(text, align=Qt.AlignmentFlag.AlignCenter):
    it = QTableWidgetItem(text)
    it.setTextAlignment(align | Qt.AlignmentFlag.AlignVCenter)
    return it


def ratio_color(r):
    return C_OK if r < 0.7 else (C_WARN if r < 0.9 else C_BAD)


def period_combo(default=0):
    c = QComboBox()
    for key, label in (("session", "Since boot (current session)"), ("today", "Today"),
                       ("week", "Last 7 days"), ("month", "This month"), ("all", "All time")):
        c.addItem(label, key)
    c.setCurrentIndex(default)
    return c


def page_header(title, subtitle=""):
    w = QWidget()
    l = QVBoxLayout(w)
    l.setContentsMargins(0, 0, 0, 4)
    l.setSpacing(2)
    t = QLabel(title)
    t.setObjectName("pageTitle")
    l.addWidget(t)
    if subtitle:
        s = QLabel(subtitle)
        s.setObjectName("pageSub")
        s.setWordWrap(True)
        l.addWidget(s)
    return w


def note(text):
    n = QLabel(text)
    n.setObjectName("cardSub")
    n.setWordWrap(True)
    return n


def nav_icon(kind):
    icon = QIcon()
    for color, state in ((C_MUTED, QIcon.State.Off), (C_DL, QIcon.State.On)):
        pm = QPixmap(40, 40)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(color), 3)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        P = QPointF
        if kind == "dashboard":
            for x, y in ((6, 6), (23, 6), (6, 23), (23, 23)):
                p.drawRoundedRect(QRectF(x, y, 11, 11), 3, 3)
        elif kind == "apps":
            for y in (9, 20, 31):
                p.drawLine(P(14, y), P(33, y))
                p.drawPoint(P(7, y))
        elif kind == "inspector":
            p.drawEllipse(QRectF(6, 6, 20, 20))
            p.drawLine(P(23, 23), P(33, 33))
        elif kind == "interfaces":
            p.drawLine(P(26, 32), P(26, 8))
            p.drawLine(P(26, 8), P(20, 14))
            p.drawLine(P(26, 8), P(32, 14))
            p.drawLine(P(14, 8), P(14, 32))
            p.drawLine(P(14, 32), P(8, 26))
            p.drawLine(P(14, 32), P(20, 26))
        elif kind == "networks":
            for r in (7, 13, 19):
                p.drawArc(QRectF(20 - r, 31 - r, 2 * r, 2 * r), 50 * 16, 80 * 16)
            p.drawPoint(P(20, 31))
        elif kind == "history":
            for x, y0 in ((9, 20), (20, 10), (31, 25)):
                p.drawLine(P(x, 33), P(x, y0))
        p.end()
        icon.addPixmap(pm, QIcon.Mode.Normal, state)
    return icon


def make_icon():
    pm = QPixmap(64, 64)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    g = QLinearGradient(0, 0, 64, 64)
    g.setColorAt(0, QColor("#1b2a4a"))
    g.setColorAt(1, QColor("#0d1424"))
    p.setBrush(g)
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(2, 2, 60, 60), 14, 14)
    p.setBrush(QColor(C_DL))
    p.drawPolygon(QPolygonF([QPointF(14, 34), QPointF(26, 34), QPointF(26, 14), QPointF(32, 14),
                             QPointF(32, 34), QPointF(44, 34), QPointF(29, 52)]))
    p.setBrush(QColor(C_UL))
    p.drawPolygon(QPolygonF([QPointF(40, 30), QPointF(52, 30), QPointF(46, 12)]))
    p.end()
    return QIcon(pm)


# ───────────────────────── packet view (table + decoder) ─────────────────────────

class PacketModel(QAbstractTableModel):
    HEAD = ["#", "Time", "App", "Dir", "Proto", "Remote", "Size", "Info"]

    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.rows = []
        self.matcher = make_matcher()
        self.last_seq = 0
        self.maxrows = 4000

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEAD)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEAD[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        p, c = self.rows[index.row()], index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if c == 0:
                return str(p.seq)
            if c == 1:
                return datetime.fromtimestamp(p.ts).strftime("%H:%M:%S.%f")[:-3]
            if c == 2:
                return p.flow.app or "unknown"
            if c == 3:
                return {"out": "->", "in": "<-"}.get(p.dir, "<>")
            if c == 4:
                return p.proto.upper()
            if c == 5:
                host = p.flow.host or self.engine.dns.get(p.rip) or p.rip
                return f"{host}:{p.rport}" if p.rport else host
            if c == 6:
                return str(p.length)
            return p.info
        if role == Qt.ItemDataRole.ForegroundRole:
            return QColor({"out": "#c9b3ff", "in": "#8fdcf7"}.get(p.dir, C_MUTED))
        return None

    def append(self, pkts):
        pkts = [p for p in pkts if self.matcher(p)]
        if not pkts:
            return
        n = len(self.rows)
        self.beginInsertRows(QModelIndex(), n, n + len(pkts) - 1)
        self.rows.extend(pkts)
        self.endInsertRows()
        excess = len(self.rows) - self.maxrows
        if excess > 0:
            self.beginRemoveRows(QModelIndex(), 0, excess - 1)
            del self.rows[:excess]
            self.endRemoveRows()

    def rebuild(self):
        snap = self.engine.packets_snapshot()
        self.beginResetModel()
        self.rows = [p for p in snap if self.matcher(p)][-self.maxrows:]
        self.endResetModel()
        self.last_seq = snap[-1].seq if snap else self.engine.seq

    def clear(self):
        self.beginResetModel()
        self.rows = []
        self.endResetModel()
        self.last_seq = self.engine.seq


class PacketView(QWidget):
    def __init__(self, engine, fixed_app=None):
        super().__init__()
        self.engine = engine
        self.fixed_app = fixed_app
        self.paused = False
        self.autoscroll = True
        self.text, self.app, self.proto = "", None, None
        self.model = PacketModel(engine)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(Qt.Orientation.Vertical)
        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.view.setShowGrid(False)
        self.view.setAlternatingRowColors(True)
        self.view.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.view.setFont(mono_font(9))
        self.view.verticalHeader().setVisible(False)
        self.view.verticalHeader().setDefaultSectionSize(24)
        h = self.view.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        h.setStretchLastSection(True)
        for i, w in enumerate((60, 96, 120, 40, 60, 250, 56)):
            self.view.setColumnWidth(i, w)
        self.view.selectionModel().currentRowChanged.connect(self.on_row)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.txt_pkt, self.txt_flow = QPlainTextEdit(), QPlainTextEdit()
        for t, name in ((self.txt_pkt, "Packet details"), (self.txt_flow, "Follow flow (ASCII)")):
            t.setReadOnly(True)
            t.setFont(mono_font(9))
            t.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            self.tabs.addTab(t, name)
        self.txt_pkt.setPlainText("Select a packet to see its details.")
        split.addWidget(self.view)
        split.addWidget(self.tabs)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay.addWidget(split)

    def set_filter(self, text=None, app="__keep__", proto="__keep__"):
        if text is not None:
            self.text = text
        if app != "__keep__":
            self.app = app
        if proto != "__keep__":
            self.proto = proto
        self.model.matcher = make_matcher(self.text, self.fixed_app or self.app, self.proto)
        self.model.rebuild()

    def tick(self):
        if self.paused:
            return
        new = self.engine.packets_since(self.model.last_seq)
        if new:
            self.model.last_seq = new[-1].seq
            self.model.append(new[-1500:])
            if self.autoscroll:
                self.view.scrollToBottom()

    def clear(self):
        self.model.clear()
        self.txt_pkt.setPlainText("")
        self.txt_flow.setPlainText("")

    def on_row(self, cur, _prev):
        if not cur.isValid() or cur.row() >= len(self.model.rows):
            return
        p = self.model.rows[cur.row()]
        self.txt_pkt.setPlainText(packet_detail(p, self.engine))
        self.txt_flow.setPlainText(follow_text(self.engine, p.flow))


# ───────────────────────── pages ─────────────────────────

class DashboardPage(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        root = QVBoxLayout(self)
        root.setSpacing(14)
        root.addWidget(page_header("Dashboard", "Live network activity of this machine"))

        r1 = QHBoxLayout()
        self.c_net = Card("Current network")
        self.c_dl = Card("Download speed", C_DL)
        self.c_ul = Card("Upload speed", C_UL)
        for c in (self.c_net, self.c_dl, self.c_ul):
            r1.addWidget(c)
        root.addLayout(r1)
        r2 = QHBoxLayout()
        self.c_ses = Card("Since boot", C_OK)
        self.c_day = Card("Today")
        self.c_mon = Card("This month")
        for c in (self.c_ses, self.c_day, self.c_mon):
            r2.addWidget(c)
        root.addLayout(r2)
        self.boot_lbl = note("")
        root.addWidget(self.boot_lbl)

        r3 = QHBoxLayout()
        self.graph = SpeedGraph()
        self.donut = DonutChart()
        r3.addWidget(self.graph, 3)
        r3.addWidget(self.donut, 2)
        root.addLayout(r3, 1)

        foot = QHBoxLayout()
        self.auto_cb = QCheckBox("Start at login (desktop autostart file; Hyprland needs an exec line in its config)")
        self.auto_cb.setChecked(AUTOSTART_FILE.exists())
        self.auto_cb.toggled.connect(lambda on: (install_autostart if on else remove_autostart)())
        self.backend_lbl = note("")
        foot.addWidget(self.auto_cb)
        foot.addStretch(1)
        foot.addWidget(self.backend_lbl)
        root.addLayout(foot)

    def on_live(self, d):
        self.c_dl.set(fmt_speed(d["rx"]))
        self.c_ul.set(fmt_speed(d["tx"]))
        self.graph.push(d["rx"], d["tx"])
        nets = d["networks"]
        self.c_net.set(" + ".join(nets) if nets else "Not connected")

    def on_backend(self, text):
        self.backend_lbl.setText("App measurement: " + text)

    def refresh(self):
        for card, period in ((self.c_ses, "session"), (self.c_day, "today"), (self.c_mon, "month")):
            rx, tx = totals(self.db, period)
            card.set(fmt_bytes(rx + tx), f"Down {fmt_bytes(rx)}   Up {fmt_bytes(tx)}")
        up = read_uptime()
        self.boot_lbl.setText(f"Booted at {datetime.fromtimestamp(time.time() - up):%Y-%m-%d %H:%M}   -   Uptime {fmt_dur(up)}")
        rows = self.db.execute("SELECT app, SUM(rx+tx) s FROM app_usage WHERE day=? GROUP BY app ORDER BY s DESC",
                               (today_str(),)).fetchall()
        items = [(a, s, PALETTE[i]) for i, (a, s) in enumerate(rows[:6])]
        rest = sum(s for _, s in rows[6:])
        grand_rx, grand_tx = totals(self.db, "today")
        other = max(grand_rx + grand_tx - sum(s for _, s in rows), 0)
        if rest:
            items.append(("Other apps", rest, "#5b6b8c"))
        if other > 1024 * 1024:
            items.append(("Unattributed", other, "#3a4358"))
        self.donut.set_data(items, fmt_bytes(grand_rx + grand_tx), "today")


class AppDetail(QWidget):
    def __init__(self, db, engine, request_capture):
        super().__init__()
        self.db, self.engine, self.request_capture = db, engine, request_capture
        self.app = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.title = QLabel("Select an application above")
        self.title.setObjectName("sectionTitle")
        lay.addWidget(self.title)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        lay.addWidget(self.tabs, 1)

        ov = QWidget()
        ol = QHBoxLayout(ov)
        ol.setContentsMargins(0, 8, 0, 0)
        self.chart = BarChart()
        self.chart.setMinimumHeight(120)
        self.info = QTextBrowser()
        self.info.setOpenLinks(False)
        ol.addWidget(self.info, 3)
        ol.addWidget(self.chart, 2)
        self.tabs.addTab(ov, "Overview")

        self.conn_table = make_table(["Proto", "State", "Local", "Remote", "Host", "Sent", "Received", "RTT"])
        self.conn_table.verticalHeader().setDefaultSectionSize(28)
        self.tabs.addTab(self.conn_table, "Connections")

        pk = QWidget()
        pl = QVBoxLayout(pk)
        pl.setContentsMargins(0, 8, 0, 0)
        bar = QHBoxLayout()
        self.cap_btn = QPushButton("Start capture")
        self.cap_btn.clicked.connect(self.request_capture)
        self.pause_btn = QPushButton("Pause")
        self.pause_btn.setCheckable(True)
        self.pause_btn.toggled.connect(self.on_pause)
        clr = QPushButton("Clear")
        clr.clicked.connect(lambda: self.pv.clear())
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter: host, ip, port, info...")
        self.filter.textChanged.connect(lambda t: self.pv.set_filter(text=t))
        self.hint = note("")
        for w in (self.cap_btn, self.pause_btn, clr):
            bar.addWidget(w)
        bar.addWidget(self.filter, 1)
        pl.addLayout(bar)
        pl.addWidget(self.hint)
        self.pv = PacketView(engine, fixed_app="")
        pl.addWidget(self.pv, 1)
        self.tabs.addTab(pk, "Packets")

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.update_capture_state(False)

    def on_pause(self, on):
        self.pv.paused = on
        self.pause_btn.setText("Resume" if on else "Pause")

    def update_capture_state(self, running):
        self.cap_btn.setEnabled(not running)
        self.cap_btn.setText("Capturing..." if running else "Start capture")
        self.hint.setText("Packets of this app appear live while capture is running (attribution is by local port, "
                          "so very short connections can show as 'unknown')." if running else
                          "Capture is off. Press Start capture (uses tcpdump; may ask for authorization).")

    def showEvent(self, e):
        self.timer.start(2000)
        super().showEvent(e)

    def hideEvent(self, e):
        self.timer.stop()
        super().hideEvent(e)

    def set_app(self, app):
        self.app = app
        self.pv.fixed_app = app
        self.pv.set_filter()
        self.title.setText(f"{app}" if app else "Select an application above")
        self.refresh()

    def refresh(self):
        app = self.app
        if not app or app.startswith("("):
            self.info.setHtml(f"<p style='color:{C_MUTED}'>No per-process details for this row.</p>")
            self.conn_table.setRowCount(0)
            return
        tcp = ss_connections("t", info=True, all_socks=True)
        udp = ss_connections("u", all_socks=True)
        mine = [c for c in tcp + udp if c["name"] == app]
        pids = find_pids(app, mine)
        self.info.setHtml(self.overview_html(app, mine, pids))
        rows = self.db.execute("SELECT day, SUM(rx), SUM(tx) FROM app_usage WHERE app=? GROUP BY day "
                               "ORDER BY day DESC LIMIT 14", (app,)).fetchall()
        self.chart.set_data([(d[5:], rx, tx) for d, rx, tx in reversed(rows)])

        live = [c for c in mine if c["state"] not in ("LISTEN", "UNCONN") or c["proto"] == "tcp" and c["rip"] not in ("", "*", "0.0.0.0")]
        live.sort(key=lambda c: -((c["sent"] or 0) + (c["recv"] or 0)))
        self.conn_table.setRowCount(len(live[:300]))
        for i, c in enumerate(live[:300]):
            host = self.engine.dns.get(c["rip"], "")
            vals = [c["proto"].upper(), c["state"], f"{c['lip']}:{c['lport']}", f"{c['rip']}:{c['rport']}", host,
                    fmt_bytes(c["sent"]) if c["sent"] is not None else "-",
                    fmt_bytes(c["recv"]) if c["recv"] is not None else "-",
                    f"{c['rtt']:.0f} ms" if c["rtt"] is not None else "-"]
            for j, v in enumerate(vals):
                self.conn_table.setItem(i, j, cell(v))

    def overview_html(self, app, conns, pids):
        e = _html.escape
        rows = []

        def kv(k, v):
            rows.append(f"<tr><td style='color:{C_MUTED};padding:3px 18px 3px 0'>{e(str(k))}</td><td>{e(str(v))}</td></tr>")
        if pids:
            kv("Status", f"running  (pid {', '.join(map(str, pids[:6]))}{'...' if len(pids) > 6 else ''})")
            pi = proc_info(pids[0])
            kv("Executable", pi["exe"])
            kv("Command line", pi["cmdline"][:240])
            kv("User", pi["user"])
            if pi["started"]:
                kv("Started", f"{datetime.fromtimestamp(pi['started']):%Y-%m-%d %H:%M:%S}  ({fmt_dur(time.time() - pi['started'])} ago)")
            kv("Memory / threads", f"{fmt_bytes(pi['rss'])}  /  {pi['threads']}")
        else:
            kv("Status", "not running (or process not visible)")
        listening = sorted({c["lport"] for c in conns if c["state"] in ("LISTEN", "UNCONN") and c["lport"]})
        est = [c for c in conns if c["proto"] == "tcp" and c["state"] == "ESTAB"]
        kv("Open sockets", f"{len(est)} TCP established, {sum(1 for c in conns if c['proto'] == 'udp')} UDP, "
                           f"{len(listening)} listening ports")
        if listening:
            kv("Listening ports", ", ".join(map(str, listening[:12])))
        kv("Live TCP bytes", f"sent {fmt_bytes(sum(c['sent'] or 0 for c in est))}, "
                             f"received {fmt_bytes(sum(c['recv'] or 0 for c in est))}  (open connections only)")
        by_host = {}
        for c in est:
            k = self.engine.dns.get(c["rip"]) or c["rip"]
            by_host[k] = by_host.get(k, 0) + (c["sent"] or 0) + (c["recv"] or 0)
        top = sorted(by_host.items(), key=lambda kv_: -kv_[1])[:6]
        if top:
            kv("Top remotes", ";  ".join(f"{h} ({fmt_bytes(b)})" for h, b in top))
        fl = [f for f in self.engine.flows_snapshot() if f.app == app]
        if fl:
            kv("Captured packets", f"{sum(f.pkts_out for f in fl)} sent / {sum(f.pkts_in for f in fl)} received "
                                   f"in {len(fl)} flows  ({fmt_bytes(sum(f.bytes_out for f in fl))} out, "
                                   f"{fmt_bytes(sum(f.bytes_in for f in fl))} in)")
        usage = []
        for period, label in (("session", "Since boot"), ("today", "Today"), ("week", "7 days"), ("month", "Month"), ("all", "All time")):
            w, p = period_clause(period)
            rx, tx = self.db.execute(f"SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM app_usage WHERE app=? AND {w}",
                                     (app,) + p).fetchone()
            usage.append(f"<tr><td style='color:{C_MUTED};padding:2px 18px 2px 0'>{label}</td>"
                         f"<td style='color:{C_DL};padding-right:14px'>{fmt_bytes(rx)}</td>"
                         f"<td style='color:{C_UL};padding-right:14px'>{fmt_bytes(tx)}</td><td>{fmt_bytes(rx + tx)}</td></tr>")
        return (f"<table>{''.join(rows)}</table><p style='margin-top:10px;color:{C_MUTED}'>Usage (down / up / total)</p>"
                f"<table>{''.join(usage)}</table>")


class AppsPage(QWidget):
    def __init__(self, db, engine, request_capture):
        super().__init__()
        self.db = db
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(page_header("Apps", "Click an application to inspect it: process info, sockets, history and live packets."))
        top = QHBoxLayout()
        self.combo = period_combo(1)
        self.combo.currentIndexChanged.connect(self.refresh)
        top.addWidget(QLabel("Period:"))
        top.addWidget(self.combo)
        top.addStretch(1)
        lay.addLayout(top)
        split = QSplitter(Qt.Orientation.Vertical)
        self.table = make_table(["App", "Download", "Upload", "Total", "Share"])
        self.table.setItemDelegateForColumn(4, BarDelegate(self.table))
        self.table.itemSelectionChanged.connect(self.on_select)
        self.detail = AppDetail(db, engine, request_capture)
        split.addWidget(self.table)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        lay.addWidget(split, 1)
        lay.addWidget(note("Per-app totals are approximate and only recorded while NetMeter runs. "
                           "Enable nethogs (setcap) for better accuracy including UDP/QUIC."))

    def selected_app(self):
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def on_select(self):
        self.detail.set_app(self.selected_app())

    def refresh(self):
        keep = self.selected_app()
        w, p = period_clause(self.combo.currentData())
        rows = self.db.execute(
            f"SELECT app, SUM(rx), SUM(tx) FROM app_usage WHERE {w} GROUP BY app "
            f"ORDER BY SUM(rx)+SUM(tx) DESC LIMIT 200", p).fetchall()
        tot_rx, tot_tx = totals(self.db, self.combo.currentData())
        miss_rx, miss_tx = tot_rx - sum(r[1] for r in rows), tot_tx - sum(r[2] for r in rows)
        if miss_rx + miss_tx > 1024 * 1024:
            rows.append(("(unattributed: before NetMeter started / UDP / other)", max(miss_rx, 0), max(miss_tx, 0)))
        grand = sum(r[1] + r[2] for r in rows) or 1
        self.table.blockSignals(True)
        self.table.setRowCount(len(rows))
        for i, (app, rx, tx) in enumerate(rows):
            share = (rx + tx) / grand
            name = cell(app)
            name.setData(Qt.ItemDataRole.UserRole, app)
            self.table.setItem(i, 0, name)
            self.table.setItem(i, 1, cell(fmt_bytes(rx)))
            self.table.setItem(i, 2, cell(fmt_bytes(tx)))
            self.table.setItem(i, 3, cell(fmt_bytes(rx + tx)))
            bar = cell(f"{share * 100:.1f}%")
            bar.setData(Qt.ItemDataRole.UserRole, share)
            bar.setData(Qt.ItemDataRole.UserRole + 1, C_DL)
            self.table.setItem(i, 4, bar)
            if app == keep:
                self.table.selectRow(i)
        self.table.blockSignals(False)


class InspectorPage(QWidget):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.gi = None
        lay = QVBoxLayout(self)
        lay.setSpacing(8)
        lay.addWidget(page_header("Inspector", "Passive packet capture of this machine (like Wireshark / Burp history, without a proxy)."))

        bar = QHBoxLayout()
        self.btn = QPushButton("Start capture")
        self.btn.setObjectName("primary")
        self.btn.clicked.connect(self.toggle)
        self.scope = QComboBox()
        self.scope.setMinimumWidth(320)
        self.gw_only = QCheckBox("Gateway traffic only (internet-bound)")
        self.gw_only.setToolTip("Keeps only frames to/from the default gateway's MAC address (works on a single interface).")
        self.pause = QPushButton("Pause")
        self.pause.setCheckable(True)
        self.pause.toggled.connect(self.on_pause)
        clr = QPushButton("Clear")
        clr.clicked.connect(self.clear)
        self.auto = QCheckBox("Auto-scroll")
        self.auto.setChecked(True)
        self.auto.toggled.connect(lambda on: setattr(self.pv, "autoscroll", on))
        for w in (self.btn, QLabel("Scope:"), self.scope, self.gw_only, self.pause, clr, self.auto):
            bar.addWidget(w)
        bar.addStretch(1)
        lay.addLayout(bar)

        fb = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter: app, host, ip, port, info...")
        self.filter.textChanged.connect(self.apply_filter)
        self.app_combo = QComboBox()
        self.app_combo.addItem("All apps", None)
        self.app_combo.currentIndexChanged.connect(self.apply_filter)
        self.proto_combo = QComboBox()
        for label, v in (("All protocols", None), ("TCP", "TCP"), ("UDP", "UDP"), ("DNS", "DNS"),
                         ("TLS", "TLS"), ("HTTP", "HTTP"), ("QUIC", "QUIC"), ("ICMP", "ICMP")):
            self.proto_combo.addItem(label, v)
        self.proto_combo.currentIndexChanged.connect(self.apply_filter)
        self.status = QLabel("Capture is off")
        self.status.setObjectName("cardSub")
        fb.addWidget(self.filter, 1)
        fb.addWidget(self.app_combo)
        fb.addWidget(self.proto_combo)
        lay.addLayout(fb)
        lay.addWidget(self.status)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.pv = PacketView(engine)
        self.flows = make_table(["App", "Proto", "Local", "Remote", "Host", "Out pkts", "In pkts", "Out", "In", "Last seen", "Kind"])
        self.flows.verticalHeader().setDefaultSectionSize(28)
        self.flows.cellDoubleClicked.connect(self.on_flow_dbl)
        self.tabs.addTab(self.pv, "Packets")
        self.tabs.addTab(self.flows, "Flows (double-click to filter)")
        lay.addWidget(self.tabs, 1)
        lay.addWidget(note("Scope: 'Default route' captures the interface your internet goes through (your gateway). "
                           "'All interfaces' also shows VPN/tunnel copies of the same traffic. "
                           "HTTPS content is encrypted - you see hostnames (DNS/SNI), sizes, flags and timing."))
        self.populate_scope()
        self.set_running(False)

    def populate_scope(self):
        cur = self.scope.currentData()
        self.scope.clear()
        self.gi = gateway_info()
        if self.gi:
            self.scope.addItem(f"Default route: {self.gi['dev']}  ->  gateway {self.gi['gw']}", ("iface", self.gi["dev"]))
        self.scope.addItem("All interfaces (any)", ("any",))
        for i in physical_ifaces():
            self.scope.addItem(f"Interface: {i}", ("iface", i))
        for k in range(self.scope.count()):
            if self.scope.itemData(k) == cur:
                self.scope.setCurrentIndex(k)

    def showEvent(self, e):
        if not self.engine.running:
            self.populate_scope()
        super().showEvent(e)

    def set_running(self, running):
        self.btn.setText("Stop capture" if running else "Start capture")
        self.scope.setEnabled(not running)
        self.gw_only.setEnabled(not running)

    def toggle(self):
        if self.engine.running:
            self.engine.stop()
        else:
            self.start()

    def start(self):
        if self.engine.running:
            return
        sc = self.scope.currentData() or ("any",)
        iface = "any" if sc[0] == "any" else sc[1]
        bpf = ""
        if self.gw_only.isChecked():
            gi = gateway_info()
            if iface == "any" or not gi or gi["dev"] != iface or not gi.get("mac"):
                self.status.setText("Gateway filter needs the default-route interface selected (and a known gateway MAC).")
                return
            bpf = f"ether host {gi['mac']}"
        self.engine.clear()
        self.pv.clear()
        self.engine.configure(iface, bpf)
        self.status.setText("Starting capture...")
        self.engine.start()

    def on_pause(self, on):
        self.pv.paused = on
        self.pause.setText("Resume" if on else "Pause")

    def clear(self):
        self.engine.clear()
        self.pv.clear()

    def apply_filter(self, *_):
        self.pv.set_filter(text=self.filter.text(), app=self.app_combo.currentData(), proto=self.proto_combo.currentData())

    def on_flow_dbl(self, row, _col):
        it = self.flows.item(row, 3)
        if it:
            self.filter.setText(it.data(Qt.ItemDataRole.UserRole) or "")
            self.tabs.setCurrentIndex(0)

    def tick(self):
        self.pv.tick()

    def refresh(self):
        flows = self.engine.flows_snapshot()
        apps = sorted({f.app or "unknown" for f in flows})
        cur = self.app_combo.currentData()
        if [self.app_combo.itemData(i) for i in range(1, self.app_combo.count())] != apps:
            self.app_combo.blockSignals(True)
            self.app_combo.clear()
            self.app_combo.addItem("All apps", None)
            for a in apps:
                self.app_combo.addItem(a, a)
            k = self.app_combo.findData(cur)
            self.app_combo.setCurrentIndex(max(k, 0))
            self.app_combo.blockSignals(False)
        top = flows[:400]
        self.flows.setRowCount(len(top))
        for i, f in enumerate(top):
            vals = [f.app or "unknown", f.proto.upper(), f"{f.lip}:{f.lport}", f"{f.rip}:{f.rport}",
                    f.host or self.engine.dns.get(f.rip, ""), str(f.pkts_out), str(f.pkts_in),
                    fmt_bytes(f.bytes_out), fmt_bytes(f.bytes_in),
                    datetime.fromtimestamp(f.last).strftime("%H:%M:%S"), f.kind or ""]
            for j, v in enumerate(vals):
                it = cell(v)
                if j == 3:
                    it.setData(Qt.ItemDataRole.UserRole, f.rip)
                self.flows.setItem(i, j, it)


class InterfacesPage(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.live = {}
        lay = QVBoxLayout(self)
        lay.addWidget(page_header("Interfaces", "Live speed and daily usage per network interface. Set a daily limit to get alerts at 80% and 100%."))
        top = QHBoxLayout()
        btn = QPushButton("Set daily limit for selected interface...")
        btn.clicked.connect(self.set_limit)
        top.addStretch(1)
        top.addWidget(btn)
        lay.addLayout(top)
        self.table = make_table(["Interface", "Type", "Network", "State", "Download", "Upload", "Today", "Daily limit", "Usage"])
        self.table.setItemDelegateForColumn(8, BarDelegate(self.table))
        lay.addWidget(self.table, 1)
        lay.addWidget(note("Alerts are sent through your desktop notifications (notify-send) or the tray icon, once per threshold per day."))

    def on_live(self, d):
        self.live = d["ifaces"]
        if self.isVisible():
            self.refresh()

    def selected(self):
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def refresh(self):
        keep = self.selected()
        usage = {i: (rx, tx) for i, rx, tx in self.db.execute(
            "SELECT iface,SUM(rx),SUM(tx) FROM iface_usage WHERE day=? GROUP BY iface", (today_str(),))}
        limits = {n: b for n, b in self.db.execute("SELECT name,daily_bytes FROM limits WHERE kind='iface'")}
        names = sorted(set(self.live) | set(usage) | set(limits))
        self.table.setRowCount(len(names))
        for i, n in enumerate(names):
            lv = self.live.get(n, {})
            rx, tx = usage.get(n, (0, 0))
            it = cell(n)
            it.setData(Qt.ItemDataRole.UserRole, n)
            self.table.setItem(i, 0, it)
            self.table.setItem(i, 1, cell(lv.get("type", iface_type(n))))
            self.table.setItem(i, 2, cell(lv.get("net") or "-"))
            self.table.setItem(i, 3, cell("up" if lv.get("up") else "down"))
            self.table.setItem(i, 4, cell(fmt_speed(lv.get("rx", 0))))
            self.table.setItem(i, 5, cell(fmt_speed(lv.get("tx", 0))))
            self.table.setItem(i, 6, cell(fmt_bytes(rx + tx)))
            lim = limits.get(n)
            self.table.setItem(i, 7, cell(fmt_bytes(lim) if lim else "-"))
            if lim:
                ratio = (rx + tx) / lim
                bar = cell(f"{ratio * 100:.0f}%")
                bar.setData(Qt.ItemDataRole.UserRole, ratio)
                bar.setData(Qt.ItemDataRole.UserRole + 1, ratio_color(ratio))
            else:
                bar = cell("")
            self.table.setItem(i, 8, bar)
            if n == keep:
                self.table.selectRow(i)

    def set_limit(self):
        n = self.selected()
        if not n:
            QMessageBox.information(self, APP_NAME, "Select an interface from the table first.")
            return
        cur = self.db.execute("SELECT daily_bytes FROM limits WHERE kind='iface' AND name=?", (n,)).fetchone()
        gb, ok = QInputDialog.getDouble(self, "Daily limit", f"Daily limit for {n} (GB)\n0 = remove limit",
                                        (cur[0] / GB) if cur else 0.0, 0.0, 100000.0, 2)
        if not ok:
            return
        if gb <= 0:
            self.db.execute("DELETE FROM limits WHERE kind='iface' AND name=?", (n,))
        else:
            self.db.execute("INSERT OR REPLACE INTO limits(kind,name,daily_bytes) VALUES('iface',?,?)", (n, int(gb * GB)))
        self.db.commit()
        self.refresh()


class NetworksPage(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.active = []
        lay = QVBoxLayout(self)
        lay.addWidget(page_header("Networks", "Usage per Wi-Fi / Ethernet network, with a monthly quota and the remaining data."))
        top = QHBoxLayout()
        self.combo = period_combo(3)
        self.combo.currentIndexChanged.connect(self.refresh)
        btn = QPushButton("Set quota for selected network...")
        btn.clicked.connect(self.set_quota)
        top.addWidget(QLabel("Period:"))
        top.addWidget(self.combo)
        top.addStretch(1)
        top.addWidget(btn)
        lay.addLayout(top)
        self.table = make_table(["Network", "Download", "Upload", "Total", "Quota", "Used (cycle)", "Remaining", "Quota status"])
        self.table.setItemDelegateForColumn(7, BarDelegate(self.table))
        lay.addWidget(self.table, 1)
        lay.addWidget(note("A dot marks networks you are connected to right now. Quota columns always use the quota's own "
                           "monthly cycle (from its start day); the other columns follow the period above."))

    def selected_net(self):
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def refresh(self):
        keep = self.selected_net()
        w, p = period_clause(self.combo.currentData())
        data = {n: (rx, tx) for n, rx, tx in self.db.execute(
            f"SELECT net, SUM(rx), SUM(tx) FROM net_usage WHERE {w} GROUP BY net", p)}
        quotas = {n: (q, d) for n, q, d in self.db.execute("SELECT net,quota_bytes,cycle_day FROM quotas")}
        for n in quotas:
            data.setdefault(n, (0, 0))
        rows = sorted(data.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))
        self.table.setRowCount(len(rows))
        for i, (net, (rx, tx)) in enumerate(rows):
            name = cell(("● " if net in self.active else "") + net)
            name.setData(Qt.ItemDataRole.UserRole, net)
            self.table.setItem(i, 0, name)
            self.table.setItem(i, 1, cell(fmt_bytes(rx)))
            self.table.setItem(i, 2, cell(fmt_bytes(tx)))
            self.table.setItem(i, 3, cell(fmt_bytes(rx + tx)))
            if net in quotas:
                q, d = quotas[net]
                used = cycle_used(self.db, net, d)
                ratio = used / q if q else 0
                self.table.setItem(i, 4, cell(fmt_bytes(q)))
                self.table.setItem(i, 5, cell(fmt_bytes(used)))
                self.table.setItem(i, 6, cell(fmt_bytes(max(q - used, 0))))
                bar = cell(f"{ratio * 100:.0f}%")
                bar.setData(Qt.ItemDataRole.UserRole, ratio)
                bar.setData(Qt.ItemDataRole.UserRole + 1, ratio_color(ratio))
                self.table.setItem(i, 7, bar)
            else:
                for c in (4, 5, 6):
                    self.table.setItem(i, c, cell("-"))
                self.table.setItem(i, 7, cell(""))
            if net == keep:
                self.table.selectRow(i)

    def set_quota(self):
        net = self.selected_net()
        if not net:
            QMessageBox.information(self, APP_NAME, "Select a network from the table first.")
            return
        cur = self.db.execute("SELECT quota_bytes,cycle_day FROM quotas WHERE net=?", (net,)).fetchone()
        gb, ok = QInputDialog.getDouble(self, "Quota", f"Quota for \"{net}\" (GB)\n0 = remove quota",
                                        (cur[0] / GB) if cur else 0.0, 0.0, 100000.0, 2)
        if not ok:
            return
        if gb <= 0:
            self.db.execute("DELETE FROM quotas WHERE net=?", (net,))
        else:
            day, ok2 = QInputDialog.getInt(self, "Cycle start", "Monthly cycle start day (1-28):",
                                           cur[1] if cur else 1, 1, 28)
            if not ok2:
                return
            self.db.execute("INSERT OR REPLACE INTO quotas(net,quota_bytes,cycle_day) VALUES(?,?,?)", (net, int(gb * GB), day))
        self.db.commit()
        self.refresh()


class HistoryPage(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        lay = QVBoxLayout(self)
        lay.addWidget(page_header("History", "Daily, monthly and per-boot usage."))
        top = QHBoxLayout()
        self.combo = QComboBox()
        self.combo.addItem("Daily (last 30 days)", "daily")
        self.combo.addItem("Monthly (last 12 months)", "monthly")
        self.combo.addItem("Every boot session", "sessions")
        self.combo.currentIndexChanged.connect(self.refresh)
        top.addWidget(QLabel("View:"))
        top.addWidget(self.combo)
        top.addStretch(1)
        top.addWidget(QLabel(f'<span style="color:{C_DL}">■</span> Download &nbsp; <span style="color:{C_UL}">■</span> Upload'))
        lay.addLayout(top)
        self.chart = BarChart()
        lay.addWidget(self.chart)
        self.table = make_table(["Period", "Download", "Upload", "Total"])
        lay.addWidget(self.table, 1)

    def refresh(self):
        mode = self.combo.currentData()
        db, headers = self.db, ["Period", "Download", "Upload", "Total"]
        if mode == "daily":
            rows = db.execute("SELECT day, SUM(rx), SUM(tx) FROM net_usage GROUP BY day ORDER BY day DESC LIMIT 30").fetchall()
            table_rows = [(d, rx, tx, "") for d, rx, tx in rows]
            chart = [(d[5:], rx, tx) for d, rx, tx in reversed(rows)]
        elif mode == "monthly":
            rows = db.execute("SELECT substr(day,1,7), SUM(rx), SUM(tx) FROM net_usage GROUP BY 1 ORDER BY 1 DESC LIMIT 12").fetchall()
            table_rows = [(m, rx, tx, "") for m, rx, tx in rows]
            chart = [(m, rx, tx) for m, rx, tx in reversed(rows)]
        else:
            headers.append("Duration")
            rows = db.execute(
                "SELECT s.boot_id, s.start_ts, s.last_ts, COALESCE(SUM(n.rx),0), COALESCE(SUM(n.tx),0) "
                "FROM sessions s LEFT JOIN net_usage n ON n.boot_id=s.boot_id "
                "GROUP BY s.boot_id ORDER BY s.start_ts DESC LIMIT 40").fetchall()
            table_rows, chart = [], []
            for bid, st, en, rx, tx in rows:
                s = datetime.fromtimestamp(st)
                if bid == BOOT_ID:
                    label, dur = f"{s:%Y-%m-%d %H:%M} -> now (running)", read_uptime()
                else:
                    label, dur = f"{s:%Y-%m-%d %H:%M} -> {datetime.fromtimestamp(en):%Y-%m-%d %H:%M}", max(en - st, 0)
                table_rows.append((label, rx, tx, fmt_dur(dur)))
                chart.append((s.strftime("%m-%d"), rx, tx))
            chart.reverse()
        self.chart.set_data(chart)
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setRowCount(len(table_rows))
        for i, (label, rx, tx, extra) in enumerate(table_rows):
            self.table.setItem(i, 0, cell(label))
            self.table.setItem(i, 1, cell(fmt_bytes(rx)))
            self.table.setItem(i, 2, cell(fmt_bytes(tx)))
            self.table.setItem(i, 3, cell(fmt_bytes(rx + tx)))
            if len(headers) == 5:
                self.table.setItem(i, 4, cell(extra))


# ───────────────────────── main window ─────────────────────────

class MainWindow(QMainWindow):
    def __init__(self, collector, engine):
        super().__init__()
        self.collector, self.engine = collector, engine
        self.db = open_db()
        self.quitting = False
        self.flush_count = 0
        self.setWindowTitle("NetMeter")
        self.setWindowIcon(make_icon())
        self.resize(1240, 800)

        self.dash = DashboardPage(self.db)
        self.apps = AppsPage(self.db, engine, self.start_capture)
        self.inspector = InspectorPage(engine)
        self.ifaces = InterfacesPage(self.db)
        self.nets = NetworksPage(self.db)
        self.hist = HistoryPage(self.db)
        pages = [(self.dash, "Dashboard", "dashboard"), (self.apps, "Apps", "apps"),
                 (self.inspector, "Inspector", "inspector"), (self.ifaces, "Interfaces", "interfaces"),
                 (self.nets, "Networks", "networks"), (self.hist, "History", "history")]

        root = QWidget()
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(210)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(14, 18, 14, 14)
        sl.setSpacing(4)
        logo = QHBoxLayout()
        pm = QLabel()
        pm.setPixmap(make_icon().pixmap(34, 34))
        name = QLabel("NetMeter")
        name.setObjectName("logo")
        logo.addWidget(pm)
        logo.addWidget(name)
        logo.addStretch(1)
        sl.addLayout(logo)
        sl.addSpacing(16)
        self.stack = QStackedWidget()
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        for i, (page, title, kind) in enumerate(pages):
            b = QPushButton("  " + title)
            b.setObjectName("nav")
            b.setCheckable(True)
            b.setIcon(nav_icon(kind))
            b.setIconSize(QSize(20, 20))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            self.group.addButton(b, i)
            sl.addWidget(b)
            wrap = QWidget()
            wl = QVBoxLayout(wrap)
            wl.setContentsMargins(24, 20, 24, 16)
            wl.addWidget(page)
            self.stack.addWidget(wrap)
        self.group.button(0).setChecked(True)
        self.group.idClicked.connect(self.stack.setCurrentIndex)
        sl.addStretch(1)
        self.cap_lbl = QLabel("Capture: off")
        self.cap_lbl.setObjectName("cardSub")
        self.cap_lbl.setWordWrap(True)
        sl.addWidget(self.cap_lbl)
        h.addWidget(side)
        h.addWidget(self.stack, 1)
        self.setCentralWidget(root)
        self.pages = [p for p, _, _ in pages]
        self.stack.currentChanged.connect(lambda _: self.refresh())

        collector.live.connect(self.on_live)
        collector.backend.connect(self.dash.on_backend)
        collector.flushed.connect(self.on_flushed)
        engine.status.connect(self.on_cap_status)
        engine.stateChanged.connect(self.on_cap_state)

        self.tray = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(make_icon(), self)
            menu = QMenu()
            a_show = QAction("Show window", self)
            a_show.triggered.connect(self.show_window)
            a_quit = QAction("Quit", self)
            a_quit.triggered.connect(self.quit_app)
            menu.addAction(a_show)
            menu.addSeparator()
            menu.addAction(a_quit)
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(
                lambda r: self.show_window() if r == QSystemTrayIcon.ActivationReason.Trigger else None)
            self.tray.show()

        self.ui_timer = QTimer(self)
        self.ui_timer.timeout.connect(self.ui_tick)
        self.ui_timer.start(300)
        self.slow = 0
        self.refresh()

    # -- capture glue --
    def start_capture(self):
        self.inspector.start()

    def on_cap_status(self, text):
        self.inspector.status.setText(text)
        self.cap_lbl.setText("Capture: " + text[:70])

    def on_cap_state(self, running):
        self.inspector.set_running(running)
        self.apps.detail.update_capture_state(running)
        if not running:
            self.cap_lbl.setText("Capture: off")

    def ui_tick(self):
        if not self.isVisible():
            return
        cur = self.pages[self.stack.currentIndex()]
        self.slow += 1
        if cur is self.inspector:
            self.inspector.tick()
            if self.slow % 3 == 0:
                self.inspector.refresh()
        elif cur is self.apps:
            self.apps.detail.pv.tick()

    # -- live data --
    def on_live(self, d):
        self.dash.on_live(d)
        self.ifaces.on_live(d)
        self.nets.active = d["networks"]
        if self.tray:
            self.tray.setToolTip(f"{APP_NAME}\nDown {fmt_speed(d['rx'])}\nUp {fmt_speed(d['tx'])}")

    def on_flushed(self):
        self.flush_count += 1
        if self.isVisible():
            self.refresh()
        if self.flush_count % 10 == 1:
            self.check_alerts()

    def refresh(self):
        page = self.pages[self.stack.currentIndex()]
        if page is not self.inspector:
            page.refresh()
        else:
            self.inspector.refresh()

    # -- alerts --
    def notify(self, title, msg, critical=False):
        if shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "-a", APP_NAME, "-u", "critical" if critical else "normal", title, msg])
        elif self.tray:
            self.tray.showMessage(title, msg, QSystemTrayIcon.MessageIcon.Warning, 10000)

    def notify_once(self, key, title, msg, critical=False):
        if self.db.execute("SELECT 1 FROM alerts_sent WHERE key=?", (key,)).fetchone():
            return
        self.db.execute("INSERT OR IGNORE INTO alerts_sent(key) VALUES(?)", (key,))
        self.db.commit()
        self.notify(title, msg, critical)

    def check_alerts(self):
        today = today_str()
        for name, lim in self.db.execute("SELECT name,daily_bytes FROM limits WHERE kind='iface'").fetchall():
            used = self.db.execute("SELECT COALESCE(SUM(rx+tx),0) FROM iface_usage WHERE day=? AND iface=?",
                                   (today, name)).fetchone()[0]
            ratio = used / lim if lim else 0
            for th, msg in ((1.0, "Daily limit reached"), (0.8, "80% of the daily limit is used")):
                if ratio >= th:
                    self.notify_once(f"{today}|iface|{name}|{th}", f"{APP_NAME} - {name}",
                                     f"{msg}: {fmt_bytes(used)} of {fmt_bytes(lim)} today.", th >= 1.0)
                    break
        for net, q, d in self.db.execute("SELECT net,quota_bytes,cycle_day FROM quotas").fetchall():
            if not q:
                continue
            ratio = cycle_used(self.db, net, d) / q
            start = cycle_start(d).isoformat()
            for th, msg in ((1.0, "Quota used up!"), (0.9, "More than 90% of the quota is used.")):
                if ratio >= th:
                    self.notify_once(f"{start}|net|{net}|{th}", f"{APP_NAME} - {net}", msg, th >= 1.0)
                    break

    # -- window lifecycle --
    def show_window(self):
        self.show()
        self.raise_()
        self.activateWindow()
        self.refresh()

    def quit_app(self):
        self.quitting = True
        self.engine.stop()
        self.collector.stop()
        self.collector.wait(5000)
        self.engine.wait(3000)
        QApplication.instance().quit()

    def closeEvent(self, ev):
        if self.tray and self.tray.isVisible() and not self.quitting:
            self.hide()
            ev.ignore()
            if not getattr(self, "_told", False):
                self._told = True
                self.tray.showMessage(APP_NAME, "Still running in the system tray. Use the tray menu > Quit to exit.",
                                      QSystemTrayIcon.MessageIcon.Information, 4000)
        else:
            self.quit_app()
            ev.accept()


# ───────────────────────── autostart, single instance, background mode ─────────────────────────

def install_autostart():
    AUTOSTART_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTOSTART_FILE.write_text(
        "[Desktop Entry]\nType=Application\nName=NetMeter\nComment=Network usage monitor\n"
        f'Exec="{sys.executable}" "{Path(__file__).resolve()}" --minimized --foreground\n'
        "Icon=network-transmit-receive\nX-GNOME-Autostart-enabled=true\nTerminal=false\n")


def remove_autostart():
    try:
        AUTOSTART_FILE.unlink()
    except FileNotFoundError:
        pass


_lock_fd = None


def acquire_lock():
    """flock-based single-instance lock (survives fork, so the detached child keeps it)."""
    global _lock_fd
    DB_DIR.mkdir(parents=True, exist_ok=True)
    fd = open(DB_DIR / "netmeter.lock", "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fd.close()
        return False
    _lock_fd = fd
    return True


def daemonize():
    """Detach from the terminal so closing it does not kill the app."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid > 0:
        print(f"NetMeter is running in the background (PID {pid}).")
        print(f"Log file: {LOG_PATH}")
        print("To quit: tray icon menu > Quit, or:  kill", pid)
        os._exit(0)
    os.setsid()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    devnull = os.open(os.devnull, os.O_RDWR)
    log = os.open(str(LOG_PATH), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(devnull, 0)
    os.dup2(log, 1)
    os.dup2(log, 2)
    print(f"\n--- NetMeter started {datetime.now():%Y-%m-%d %H:%M:%S} (PID {os.getpid()}) ---", flush=True)


STYLE = f"""
QWidget {{ background:{C_BG}; color:{C_TEXT}; font-size:13px; }}
QLabel {{ background:transparent; }}
#sidebar {{ background:{C_SIDE}; border-right:1px solid {C_BORDER}; }}
#sidebar QWidget {{ background:transparent; }}
#logo {{ font-size:18px; font-weight:800; color:{C_TEXT}; }}
QPushButton#nav {{ text-align:left; padding:11px 14px; border:none; border-radius:10px; color:{C_MUTED}; font-weight:600; background:transparent; }}
QPushButton#nav:hover {{ background:#141b29; color:{C_TEXT}; }}
QPushButton#nav:checked {{ background:#142238; color:{C_DL}; }}
#pageTitle {{ font-size:24px; font-weight:800; }}
#pageSub {{ color:{C_MUTED}; font-size:12px; }}
#sectionTitle {{ font-size:15px; font-weight:700; padding:2px 0; }}
#card {{ background:{C_PANEL}; border:1px solid {C_BORDER}; border-radius:14px; }}
#cardTitle {{ color:{C_MUTED}; font-size:12px; }}
#cardValue {{ font-size:22px; font-weight:700; }}
#cardSub {{ color:{C_MUTED}; font-size:11px; }}
QTabWidget::pane {{ border:none; }}
QTabBar::tab {{ background:transparent; color:{C_MUTED}; padding:8px 18px; font-weight:600; border-bottom:2px solid transparent; }}
QTabBar::tab:selected {{ color:{C_DL}; border-bottom:2px solid {C_DL}; }}
QTabBar::tab:hover {{ color:{C_TEXT}; }}
QComboBox, QLineEdit {{ background:{C_PANEL}; border:1px solid #232d42; border-radius:8px; padding:7px 12px; }}
QComboBox {{ min-width:190px; }}
QLineEdit:focus, QComboBox:focus {{ border:1px solid {C_DL}; }}
QComboBox QAbstractItemView {{ background:{C_PANEL}; selection-background-color:#1d2e4a; border:1px solid #232d42; }}
QPushButton {{ background:#1c2840; border:none; border-radius:8px; padding:8px 16px; }}
QPushButton:hover {{ background:#25375a; }}
QPushButton:checked {{ background:#25375a; color:{C_DL}; }}
QPushButton#primary {{ background:{C_DL}; color:#06202b; font-weight:700; }}
QPushButton#primary:hover {{ background:#74d9f5; }}
QPushButton:disabled {{ color:#5b6478; background:#151c2b; }}
QTableWidget, QTableView {{ background:{C_PANEL}; alternate-background-color:#141b29; border:1px solid {C_BORDER};
                           border-radius:10px; gridline-color:transparent; }}
QTableWidget::item, QTableView::item {{ padding:4px; }}
QTableWidget::item:selected, QTableView::item:selected {{ background:#1d2e4a; }}
QHeaderView::section {{ background:#151c2b; color:{C_MUTED}; border:none; padding:8px; font-weight:600; }}
QPlainTextEdit, QTextBrowser {{ background:#0d121c; border:1px solid {C_BORDER}; border-radius:10px; padding:6px; }}
QSplitter::handle {{ background:{C_BORDER}; height:2px; }}
QCheckBox {{ spacing:8px; background:transparent; }}
QCheckBox::indicator {{ width:16px; height:16px; border-radius:4px; border:1px solid #2a3652; background:{C_PANEL}; }}
QCheckBox::indicator:checked {{ background:{C_DL}; }}
QScrollBar:vertical {{ background:transparent; width:10px; }}
QScrollBar::handle:vertical {{ background:#26324a; border-radius:5px; min-height:24px; }}
QScrollBar:horizontal {{ background:transparent; height:10px; }}
QScrollBar::handle:horizontal {{ background:#26324a; border-radius:5px; min-width:24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height:0; width:0; }}
QToolTip {{ background:{C_PANEL}; color:{C_TEXT}; border:1px solid #232d42; }}
"""


def main():
    if "--install-autostart" in sys.argv:
        install_autostart()
        print("autostart installed:", AUTOSTART_FILE)
        return 0
    if "--remove-autostart" in sys.argv:
        remove_autostart()
        print("autostart removed")
        return 0
    if not acquire_lock():
        print("NetMeter is already running (look for its tray icon).")
        return 1
    if "--foreground" not in sys.argv:
        daemonize()

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setQuitOnLastWindowClosed(False)
    font = QFont()
    font.setFamilies(["Inter", "Noto Sans", "DejaVu Sans"])
    font.setPointSize(10)
    app.setFont(font)
    app.setStyleSheet(STYLE)
    open_db().close()

    collector = Collector()
    engine = CaptureEngine()
    win = MainWindow(collector, engine)
    collector.start()
    if not ("--minimized" in sys.argv and win.tray):
        win.show()

    signal.signal(signal.SIGINT, lambda *_: win.quit_app())
    ticker = QTimer()
    ticker.start(500)
    ticker.timeout.connect(lambda: None)  # lets Ctrl+C work in the terminal

    code = app.exec()
    engine.stop()
    collector.stop()
    collector.wait(5000)
    return code


if __name__ == "__main__":
    sys.exit(main())