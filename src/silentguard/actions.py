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
# - Add safe process kill function
# - Add IP blocking backend
# - Add unblock function
# - Add confirmation system before dangerous actions


def kill_process(pid: int) -> None:
    """Future feature: kill a process by PID."""
    pass


def block_ip(ip: str) -> None:
    """Future feature: block an IP address."""
    pass


def unblock_ip(ip: str) -> None:
    """Future feature: unblock an IP address."""
    pass
