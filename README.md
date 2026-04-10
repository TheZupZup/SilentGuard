# SilentGuard

[![Release](https://img.shields.io/badge/release-v0.1.0--alpha-blue)](https://codeberg.org/TheZupZup/SilentGuard/releases)
[![AUR](https://img.shields.io/badge/AUR-available-blue?logo=arch-linux)](#)
[![Python](https://img.shields.io/badge/python-3.x-blue?logo=python)](#)


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
```

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
