# memory.py
# Future persistence layer for SilentGuard

# This module stores a local memory of actions such as:
# - blocked IPs
# - killed processes
# - timestamps
# - reasons / notes
# - future active/inactive state

import json
from pathlib import Path
from datetime import datetime

MEMORY_FILE = Path.home() / ".silentguard_memory.json"


def load_memory():
    """Load SilentGuard memory from disk."""
    if not MEMORY_FILE.exists():
        return []

    try:
        with open(MEMORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_memory(data) -> None:
    """Save SilentGuard memory to disk."""
    with open(MEMORY_FILE, "w") as f:
        json.dump(data, f, indent=2)


def add_entry(action: str, target: str, reason: str = ""):
    """Append a new action to memory."""
    data = load_memory()

    entry = {
        "action": action,
        "target": target,
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat()
    }

    data.append(entry)
    save_memory(data)


def remove_entry(target: str):
    """Remove all entries matching a target (IP, process, etc.)."""
    data = load_memory()
    data = [entry for entry in data if entry.get("target") != target]
    save_memory(data)
