from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
import ipaddress
import psutil


@dataclass
class ConnectionInfo:
    process_name: str
    pid: Optional[int]
    remote_ip: str
    remote_port: int
    status: str
    trust: str


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

        trust = classify_ip(conn.raddr.ip)

        if process_name.lower() in {"firefox", "brave", "chrome", "code", "python3", "python"}:
            if trust == "Unknown":
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
