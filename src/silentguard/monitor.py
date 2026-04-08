from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path
import json
import ipaddress
import logging
import psutil

RULES_FILE = Path.home() / ".silentguard_rules.json"
DEFAULT_KNOWN_PROCESSES = {"firefox", "brave", "chrome", "code", "python3", "python"}
DEFAULT_RULES = {
    "known_processes": sorted(DEFAULT_KNOWN_PROCESSES),
    "trusted_ips": [],
    "blocked_ips": [],
}
LOGGER = logging.getLogger(__name__)


@dataclass
class ConnectionInfo:
    process_name: str
    pid: Optional[int]
    remote_ip: str
    remote_port: int
    status: str
    trust: str


def load_rules() -> dict:
    if not RULES_FILE.exists():
        return dict(DEFAULT_RULES)

    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        LOGGER.warning("Unable to parse rules file %s: %s", RULES_FILE, exc)
        return dict(DEFAULT_RULES)
    except OSError as exc:
        LOGGER.warning("Unable to read rules file %s: %s", RULES_FILE, exc)
        return dict(DEFAULT_RULES)

    return {
        "known_processes": data.get("known_processes", DEFAULT_RULES["known_processes"]),
        "trusted_ips": data.get("trusted_ips", []),
        "blocked_ips": data.get("blocked_ips", []),
    }


def save_rules(rules: dict) -> None:
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)


def block_ip_in_rules(ip: str) -> bool:
    rules = load_rules()
    blocked_ips = {str(value) for value in rules.get("blocked_ips", [])}
    if ip in blocked_ips:
        return False

    blocked_ips.add(ip)
    rules["blocked_ips"] = sorted(blocked_ips)
    save_rules(rules)
    return True


def unblock_ip_in_rules(ip: str) -> bool:
    rules = load_rules()
    blocked_ips = {str(value) for value in rules.get("blocked_ips", [])}
    if ip not in blocked_ips:
        return False

    blocked_ips.remove(ip)
    rules["blocked_ips"] = sorted(blocked_ips)
    save_rules(rules)
    return True


def classify_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)

        if addr.is_loopback or addr.is_private or addr.is_link_local:
            return "Local"

        return "Unknown"
    except ValueError:
        return "Unknown"


def get_outgoing_connections() -> List[ConnectionInfo]:
    results: List[ConnectionInfo] = []
    rules = load_rules()
    known_processes = {str(p).lower() for p in rules.get("known_processes", [])}
    trusted_ips = {str(ip) for ip in rules.get("trusted_ips", [])}
    blocked_ips = {str(ip) for ip in rules.get("blocked_ips", [])}
    process_name_cache: dict[int, str] = {}

    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr:
            continue

        pid = conn.pid
        process_name = "Unknown"

        if pid:
            if pid in process_name_cache:
                process_name = process_name_cache[pid]
            else:
                try:
                    process_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "Access denied"
                process_name_cache[pid] = process_name

        trust = classify_ip(conn.raddr.ip)

        if conn.raddr.ip in blocked_ips:
            trust = "Blocked"
        elif conn.raddr.ip in trusted_ips:
            trust = "Known"
        elif process_name.lower() in known_processes and trust == "Unknown":
            trust = "Known"

        results.append(
            ConnectionInfo(
                process_name=process_name,
                pid=pid,
                remote_ip=conn.raddr.ip,
                remote_port=conn.raddr.port,
                status=conn.status,
                trust=trust,
            )
        )

    return results
