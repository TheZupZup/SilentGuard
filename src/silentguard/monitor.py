from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path
import json
import ipaddress
import logging
import psutil

from silentguard.connection_state import (
    classification_from_label,
    classify_connection,
    display_label,
    record_connections,
)

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
    classification: str = ""

    def __post_init__(self) -> None:
        if not self.classification:
            self.classification = classification_from_label(self.trust)


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


def is_blockable_ip(ip: str) -> tuple[bool, str | None]:
    """Return (True, None) if ``ip`` is safe to block, otherwise (False, reason).

    Refuses loopback, link-local, multicast, unspecified, reserved, and private
    addresses (including RFC 1918 and the documentation ranges) so users cannot
    accidentally cut themselves off from local or infrastructure traffic.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"{ip!r} is not a valid IP address"

    if addr.is_loopback:
        return False, f"{ip} is a loopback address"
    if addr.is_link_local:
        return False, f"{ip} is a link-local address"
    if addr.is_multicast:
        return False, f"{ip} is a multicast address"
    if addr.is_unspecified:
        return False, f"{ip} is the unspecified address"
    if addr.is_reserved:
        return False, f"{ip} is a reserved address"
    if addr.is_private:
        return False, f"{ip} is a local/private address"

    return True, None


def block_ip_in_rules(ip: str) -> bool:
    ok, reason = is_blockable_ip(ip)
    if not ok:
        raise ValueError(reason)

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


def untrust_ip_in_rules(ip: str) -> bool:
    rules = load_rules()
    trusted_ips = {str(value) for value in rules.get("trusted_ips", [])}
    if ip not in trusted_ips:
        return False

    trusted_ips.remove(ip)
    rules["trusted_ips"] = sorted(trusted_ips)
    save_rules(rules)
    return True


def classify_ip(ip: str) -> str:
    """Return the title-case classification for ``ip`` ignoring user rules.

    Kept for backward compatibility with tests and earlier callers; new
    code should prefer :func:`silentguard.connection_state.classify_connection`,
    which folds in trusted/blocked rule overrides.
    """
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

        classification = classify_connection(conn.raddr.ip, process_name, rules)
        results.append(
            ConnectionInfo(
                process_name=process_name,
                pid=pid,
                remote_ip=conn.raddr.ip,
                remote_port=conn.raddr.port,
                status=conn.status,
                trust=display_label(classification),
                classification=classification,
            )
        )

    try:
        record_connections(results)
    except Exception:
        LOGGER.debug(
            "Skipping unknown destinations cache update due to error",
            exc_info=True,
        )

    return results
