# SilentGuard

[![Release](https://img.shields.io/badge/release-v0.1.0--alpha-blue)](https://codeberg.org/TheZupZup/SilentGuard/releases)
[![AUR](https://img.shields.io/badge/AUR-available-blue?logo=arch-linux)](#)
[![Python](https://img.shields.io/badge/python-3.x-blue?logo=python)](#)
![CI](https://github.com/TheZupZup/SilentGuard/actions/workflows/python-app.yml/badge.svg)



A lightweight network & privacy monitor with smart alerts.

SilentGuard helps you visualize outgoing network connections in real time and detect suspicious activity on your system.

---
## Screenshots

![SilentGuard UI](screenshot.png)

---

## Features

- Real-time monitoring of outgoing connections
- Process → IP mapping
- Trust classification with local rules file (`~/.silentguard_rules.json`):
  - Known
  - Unknown
  - Local
- Blocked
- Detection of new connections
- Simple and clean GTK interface
- TUI mode with memory actions, blocklist updates (`B` key), and JSON export (`E` key)

---

## Requirements

- Python 3
- GTK 3
- psutil

---
## Quick start

# Codeberg
```bash
git clone https://codeberg.org/TheZupZup/SilentGuard
cd SilentGuard
pip install .
silentguard
```

# TUI (server / headless)
```
silentguard-tui
```
---

## How to run

```bash
pip install .
silentguard      # GTK GUI
silentguard-tui  # Text UI
silentguard-api  # Read-only local API (optional)
```

## Read-only local API (preview)

SilentGuard ships an optional local-only HTTP API that exposes the same
data the TUI/GUI display. It is intended as the foundation for future
integrations (notably Nova) to consume SilentGuard state.

Important properties:

- **Local-only by default.** Binds to `127.0.0.1:8765`.
- **Read-only.** Only `GET` is supported. The API never blocks IPs,
  unblocks IPs, mutates trusted IPs, or touches the firewall.
- **Optional.** The TUI and GUI work whether or not the API is running.
- **No new dependencies.** Built on the Python standard library.

Start it with:

```bash
silentguard-api               # http://127.0.0.1:8765
silentguard-api --port 9000   # custom port
```

Endpoints:

| Method | Path                   | Purpose                                          |
| ------ | ---------------------- | ------------------------------------------------ |
| GET    | `/status`              | API identity / health summary                    |
| GET    | `/connections`         | Current outgoing connection snapshot             |
| GET    | `/connections/summary` | Compact aggregate view of outgoing connections   |
| GET    | `/blocked`             | Locally-marked blocked IPs from rules            |
| GET    | `/trusted`             | Trusted IPs from rules                           |
| GET    | `/alerts`              | Alerts (placeholder, currently empty)            |

Each endpoint returns JSON. Collections use a stable `{"items": [...]}`
shape so future schema additions stay backwards compatible. When data is
not yet available (for example, alerts are not implemented yet), the
response includes `"status": "not_available"` alongside an empty list.

### `/connections/summary`

`/connections/summary` is intended for Nova and other local tools that
want to describe the network state at a glance without parsing the full
connection list. It is **visibility only** — it does not, and never will,
control the firewall, mutate rules, or take any action.

Example payload:

```json
{
  "total": 55,
  "local": 38,
  "known": 12,
  "unknown": 5,
  "blocked": 0,
  "by_process": [
    {"process": "firefox", "count": 8, "known": 6, "unknown": 2}
  ],
  "top_remote_hosts": [
    {"ip": "93.184.216.34", "count": 3, "classification": "known"}
  ]
}
```

Notes:

- Top-level counts use the same trust labels SilentGuard already applies
  in the TUI (`local`, `known`, `unknown`, `blocked`). Trusted IPs from
  the rules file are folded into `known`, matching the existing
  classifier.
- `by_process` groups connections by process name and is capped to a
  small number of entries.
- `top_remote_hosts` lists the most-frequent non-local remote IPs and is
  also capped. Hostnames are not resolved (the API performs no DNS or
  external network calls), so only the IP is reported.
- When no connections can be enumerated (for example, if `psutil` lacks
  permissions), the response carries zeros plus `"status": "not_available"`.

## Rules file (optional)

Create `~/.silentguard_rules.json` to customize trust classification:

```json
{
  "known_processes": ["firefox", "python3"],
  "trusted_ips": ["1.1.1.1"],
  "blocked_ips": ["203.0.113.10"]
}
```

When an IP is in `blocked_ips`, it appears as `Blocked` in the UI/TUI.
---

## Arch Linux (AUR - in progress)

You can already build and install manually:

```bash
git clone https://codeberg.org/TheZupZup/SilentGuard
cd SilentGuard/packaging/aur
makepkg -si
```
---
## Mirror & Contributing

- GitLab: https://gitlab.com/TheZupZup/SilentGuard
- Codeberg: https://codeberg.org/TheZupZup/SilentGuard

Contributions welcome! Check the [ROADMAP](ROADMAP.md) and open issues.
Feel free to open a PR or issue on either platform.

## Status 

Early development — actively improving

## Branding

The name "SilentGuard" and associated branding may not be used without permission.
