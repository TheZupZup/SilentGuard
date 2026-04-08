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
- Trust classification:
  - Known
  - Unknown
  - Local
- Detection of new connections
- Simple and clean GTK interface

---

## Requirements

- Python 3
- GTK 3
- psutil

---
## Quick start

# GitLab
```
git clone https://gitlab.com/TheZupZup/SilentGuard
cd SilentGuard
pip install psutil
python3 main.py
```
# Codeberg
```bash
git clone https://codeberg.org/TheZupZup/SilentGuard
cd SilentGuard
pip install psutil
python3 main.py
```
---

## How to run

```bash
pip install psutil
python3 main.py
```
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

Early developpement-actively improving

## Branding

The name "SilentGuard" and associated branding may not be used without permission.
