# NetMeter

**A modern network usage monitor and passive traffic inspector for Linux.**
Single Python file, PyQt6 GUI, no cloud, no proxy. Everything stays on your machine.

NetMeter answers the questions your distro never does:

- How much data did I use since this boot? Today? This month?
- Which **app** used it, and what exactly is it talking to?
- Which **Wi-Fi / interface** burned it, and how much of each network's quota is left?
- Tell me when an interface passes its **daily limit**.

---

## Demo

<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="NetMeter dashboard" width="860">
  <br><em>Dashboard: live speed, usage since boot / today / month, top apps today</em>
</p>

<p align="center">
  <img src="docs/screenshots/inspector.png" alt="NetMeter packet inspector" width="860">
  <br><em>Inspector: live packets, DNS / TLS SNI / HTTP decoding, hex dump, follow flow</em>
</p>

---

## Features

| Page | What it does |
|------|--------------|
| **Dashboard** | Live download/upload speed graph, current network, usage since boot, today and this month, donut chart of the top apps today. |
| **Apps** | Per-app usage for any period. Click an app for details: process info (pid, executable, command line, user, memory, start time), open sockets with bytes and RTT, 14-day history, and a live packet log for that app. |
| **Inspector** | Burp-style history without a proxy: live packet capture of this machine, flows table, filters (app / protocol / host / port), decoder for DNS, TLS ClientHello (SNI) and plain HTTP, hex dump and *Follow flow*. |
| **Interfaces** | Live speed and daily usage per interface (Wi-Fi, Ethernet, USB tethering...). Set a **daily limit** per interface and get notified at 80% and 100%. |
| **Networks** | Usage per network name (each Wi-Fi SSID / wired connection). Set a **monthly quota** with a custom cycle start day and see what is left. |
| **History** | Daily (30 days), monthly (12 months) and per-boot-session usage with charts. |

Also: system tray icon, desktop notifications, runs detached from the terminal, single-instance lock, English UI, dark theme.

## How it works

| Data | Source |
|------|--------|
| Total usage and per-interface usage | Kernel counters from `/proc/net/dev`, **physical interfaces only** (VPN tunnels, Docker bridges and loopback are ignored, so nothing is counted twice) |
| Usage since boot | Kernel counters are per-boot, so the session is accurate even if NetMeter starts late or restarts mid-boot |
| Per-app usage | `ss` (per-socket TCP byte counters) by default; [`nethogs`](https://github.com/raboof/nethogs) automatically if installed and permitted (also counts UDP/QUIC) |
| Network names | `nmcli` (NetworkManager), falls back to `iwgetid` for Wi-Fi |
| Packet inspector | `tcpdump` streaming pcap to NetMeter, parsed in pure Python (no scapy needed) |
| Storage | SQLite at `~/.local/share/netmeter/usage.db` |

## Requirements

- Linux with Python 3.9+ and `PyQt6`
- `iproute2` (`ss`, `ip`) — present on practically every distro

Optional:

| Package | Enables |
|---------|---------|
| `networkmanager` (`nmcli`) | Network names (SSID) per connection |
| `tcpdump` | Inspector page and per-app packet logs |
| `nethogs` | More accurate per-app usage (UDP/QUIC included) |
| `libnotify` (`notify-send`) | Desktop notifications for limits and quotas |

## Install

```bash
git clone https://github.com/<your-user>/netmeter.git
cd netmeter

# PyQt6 - pick one
pip install PyQt6                    # inside a venv
sudo pacman -S python-pyqt6          # Arch

# optional tools (Arch)
sudo pacman -S tcpdump nethogs libnotify
```

## Run

```bash
python netmeter.py
```

NetMeter **detaches from the terminal** and lives in the system tray, so you can close the terminal safely. Output and errors go to `~/.local/share/netmeter/netmeter.log`.

| Option | Meaning |
|--------|---------|
| `--foreground` | Stay attached to the terminal (debugging) |
| `--minimized` | Start hidden in the tray |
| `--install-autostart` | Create an XDG autostart entry (GNOME, KDE, XFCE, ...) |
| `--remove-autostart` | Remove it |

To quit: tray icon menu → **Quit**, or `pkill -f netmeter.py`.

### Start at login

**GNOME / KDE / XFCE and other XDG desktops:**

```bash
python netmeter.py --install-autostart
```

The entry stores the exact Python interpreter you ran it with, so virtualenvs work without activating them.

**Hyprland** does not read XDG autostart files. Add this to your config.

Lua config (Hyprland 0.55+):

```lua
hl.on("hyprland.start", function()
    hl.exec_cmd("sleep 5 && /path/to/python /path/to/netmeter.py --minimized --foreground")
end)
```

Classic config (older versions):

```
exec-once = sleep 5 && /path/to/python /path/to/netmeter.py --minimized --foreground
```

The `sleep 5` gives your bar a moment to create the tray. Use the full path to your virtualenv's Python instead of `activate` (shell aliases and `activate` are not available at session start). Keep the script somewhere that is always mounted, e.g. `~/.local/share/netmeter/netmeter.py`.

## Packet capture permissions

The Inspector uses `tcpdump`, which needs privileges. Pick one:

1. **Do nothing.** NetMeter asks for authorization through `pkexec` every time you press *Start capture*.
2. **No prompt:**
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
   ```
   Any local user will then be able to capture with `tcpdump`. That is fine on a single-user laptop, think twice on a shared machine.

For accurate per-app numbers with `nethogs`:

```bash
sudo setcap "cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace+pe" $(which nethogs)
```

(Re-run after upgrading the package; the capability is dropped when the binary is replaced.)

## Inspector scope

- **Default route interface**: the interface your internet goes through (your gateway).
- **All interfaces (any)**: everything, including tunnel copies of the same traffic.
- **A single interface**.
- **Gateway traffic only**: keeps frames to/from the default gateway's MAC (internet-bound traffic, no LAN chatter). Works on a single interface.

## Limitations (please read)

- The Inspector sees **this machine only**. It does not intercept other devices or your router/modem, and NetMeter does not do ARP spoofing or MITM. For per-device usage on your whole network, measure at the router (SNMP, OpenWrt, vnStat...).
- **HTTPS and QUIC payloads are encrypted.** You get hostnames (DNS / SNI), sizes, flags and timing. Plain HTTP shows request lines and headers. There is no TLS decryption.
- Per-app attribution matches packets to sockets by local port, polled once per second. Very short-lived connections can show as `unknown`.
- Per-app totals with the default `ss` backend are approximate (TCP only, short connections can be missed). Install and enable `nethogs` for better numbers.
- Per-app history only starts when NetMeter first runs; usage before that appears as *unattributed*.
- Inspector data lives in memory only (last 20,000 packets) and is not saved to the database.

## Data and privacy

- Everything is stored locally in `~/.local/share/netmeter/` (`usage.db`, `netmeter.log`).
- No network requests are made by NetMeter itself, no telemetry.
- The Inspector shows hostnames and IP addresses you connect to. Remember that when sharing screenshots.

## Troubleshooting

| Problem | Try |
|---------|-----|
| Nothing appears after login | Check `pgrep -af netmeter` and `cat ~/.local/share/netmeter/netmeter.log`. On Hyprland use the config lines above. |
| "NetMeter is already running" | It is in the tray. Quit it from the tray menu first. |
| No tray icon | Your bar needs a StatusNotifier/AppIndicator tray. Without a tray the window close button quits the app. |
| Footer says `ss (approximate...)` | `nethogs` is missing or has no permission, see *Packet capture permissions*. |
| Inspector: "tcpdump is not installed" | `sudo pacman -S tcpdump` (or your distro's package) |
| Inspector: capture ends right after authorization | Authorization was cancelled, or no polkit agent is running. Use the `setcap` option instead. |
| No notifications | Install `libnotify` and make sure a notification daemon is running. |
| Network names show interface names | NetworkManager / `nmcli` is not available. |

Run `python netmeter.py --foreground` to see errors directly in the terminal.

## Roadmap

Ideas, not implemented yet:

- Save captures as `.pcap` for Wireshark
- Daily limits per network (currently per interface), predicted usage until the end of the cycle
- Jalali (Persian) calendar for daily / monthly views
- CSV export

## Contributing

Issues and pull requests are welcome. The whole app is one file (`netmeter.py`) on purpose: easy to read, easy to copy.

## License

[MIT](LICENSE)
