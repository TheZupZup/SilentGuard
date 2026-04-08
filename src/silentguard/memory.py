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
from typing import Any

MEMORY_FILE = Path.home() / ".silentguard_memory.json"


def load_memory() -> list[dict[str, Any]]:
    """Load SilentGuard memory from disk."""
    if not MEMORY_FILE.exists():
        return []

    try:
        with open(MEMORY_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            if isinstance(loaded, list):
                return loaded
            return []
    except Exception:
        return []


def save_memory(data: list[dict[str, Any]]) -> None:
    """Save SilentGuard memory to disk."""
    tmp_file = MEMORY_FILE.with_suffix(".tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp_file.replace(MEMORY_FILE)


def add_entry(action: str, target: str, reason: str = "") -> None:
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


def remove_entry(target: str) -> None:
    """Remove all entries matching a target (IP, process, etc.)."""
    data = load_memory()
    data = [entry for entry in data if entry.get("target") != target]
    save_memory(data)
