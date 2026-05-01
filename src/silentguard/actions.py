"""
actions.py

Future system actions for SilentGuard.

Planned features:
- Kill a selected process from the TUI or GUI
- Block an IP address
- Unblock a previously blocked IP
- Potentially block by service / port later

Important:
These actions should be implemented carefully and only after
the memory / history layer is stable.

Ideas for contributors:
- Safe process termination flow
- Confirmation prompts
- Firewall integration (ufw / firewalld / nftables)
"""

# TODO:
# - Add IP blocking backend
# - Add unblock function
# - Add confirmation system before dangerous actions

import psutil


def kill_process(pid: int) -> tuple[bool, str]:
    """Send SIGTERM to a process by PID. Returns (success, user-facing message)."""
    if pid <= 0:
        return False, f"Invalid PID {pid} — no process to kill"

    try:
        psutil.Process(pid).terminate()
        return True, f"Sent SIGTERM to PID {pid}"
    except psutil.ZombieProcess:
        return False, f"PID {pid} is a zombie process"
    except psutil.NoSuchProcess:
        return False, f"PID {pid} no longer exists"
    except psutil.AccessDenied:
        return False, f"Permission denied killing PID {pid} — try running with sudo"


def block_ip(ip: str) -> None:
    """Future feature: block an IP address."""
    pass


def unblock_ip(ip: str) -> None:
    """Future feature: unblock an IP address."""
    pass
