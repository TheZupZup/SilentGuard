"""Pure-Python handlers for the SilentGuard read-only API.

Each handler returns a JSON-serializable ``dict``. They are intentionally
free of HTTP-specific concerns so the same functions can be unit-tested,
embedded in another transport, or reused by future consumers.

All handlers are read-only: they never mutate rules, memory, sockets,
processes, or system state.
"""

from __future__ import annotations

import logging
from typing import Any

from silentguard.monitor import get_outgoing_connections, load_rules

LOGGER = logging.getLogger(__name__)


def get_status() -> dict[str, Any]:
    """Return a stable identity/health summary of the local API."""
    return {
        "service": "silentguard",
        "available": True,
        "mode": "read_only",
        "message": "SilentGuard read-only API is running",
    }


def get_connections() -> dict[str, Any]:
    """Return the current snapshot of outgoing connections.

    Falls back to ``{"items": [], "status": "not_available"}`` if the
    underlying monitor cannot enumerate connections (for example because
    ``psutil`` lacks permissions in the current environment).
    """
    try:
        connections = get_outgoing_connections()
    except Exception as exc:
        LOGGER.warning("get_connections: monitor unavailable: %s", exc)
        return {"items": [], "status": "not_available"}

    items = [
        {
            "process_name": conn.process_name,
            "pid": conn.pid,
            "remote_ip": conn.remote_ip,
            "remote_port": conn.remote_port,
            "status": conn.status,
            "trust": conn.trust,
        }
        for conn in connections
    ]
    return {"items": items}


def get_blocked() -> dict[str, Any]:
    """Return the locally-known blocked IPs from the rules file."""
    try:
        rules = load_rules()
    except Exception as exc:
        LOGGER.warning("get_blocked: rules unavailable: %s", exc)
        return {"items": [], "status": "not_available"}

    items = [{"ip": str(value)} for value in rules.get("blocked_ips", []) or []]
    return {"items": items}


def get_trusted() -> dict[str, Any]:
    """Return the locally-known trusted IPs from the rules file."""
    try:
        rules = load_rules()
    except Exception as exc:
        LOGGER.warning("get_trusted: rules unavailable: %s", exc)
        return {"items": [], "status": "not_available"}

    items = [{"ip": str(value)} for value in rules.get("trusted_ips", []) or []]
    return {"items": items}


def get_alerts() -> dict[str, Any]:
    """Return security alerts.

    SilentGuard does not yet emit a first-class alert stream, so this
    endpoint deliberately returns an empty list with ``not_available``
    status. The schema is fixed in advance so future consumers can rely
    on the shape once alerts land.
    """
    return {"items": [], "status": "not_available"}
