from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path
import json
import ipaddress
import psutil

RULES_FILE = Path.home() / ".silentguard_rules.json"
DEFAULT_KNOWN_PROCESSES = {"firefox", "brave", "chrome", "code", "python3", "python"}


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
        return {
            "known_processes": sorted(DEFAULT_KNOWN_PROCESSES),
            "trusted_ips": [],
            "blocked_ips": [],
        }

    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {
            "known_processes": sorted(DEFAULT_KNOWN_PROCESSES),
            "trusted_ips": [],
            "blocked_ips": [],
        }

    return {
        "known_processes": data.get("known_processes", sorted(DEFAULT_KNOWN_PROCESSES)),
        "trusted_ips": data.get("trusted_ips", []),
        "blocked_ips": data.get("blocked_ips", []),
    }


def classify_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)

        if addr.is_loopback or addr.is_private or addr.is_link_local:
            return "Local"

        return "Unknown"
    except ValueError:
        return "Unknown"


def determine_trust(process_name: str, remote_ip: str, rules: dict) -> str:
    trust = classify_ip(remote_ip)
    known_processes = {str(p).lower() for p in rules.get("known_processes", [])}
    trusted_ips = {str(ip) for ip in rules.get("trusted_ips", [])}
    blocked_ips = {str(ip) for ip in rules.get("blocked_ips", [])}

    if remote_ip in blocked_ips:
        return "Blocked"
    if remote_ip in trusted_ips:
        return "Known"
    if process_name.lower() in known_processes and trust == "Unknown":
        return "Known"
    return trust


def get_outgoing_connections() -> List[ConnectionInfo]:
    results: List[ConnectionInfo] = []
    rules = load_rules()

    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr:
            continue

        pid = conn.pid
        process_name = "Unknown"

        if pid:
            try:
                process_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "Access denied"

        trust = determine_trust(process_name, conn.raddr.ip, rules)

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
