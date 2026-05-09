"""Pure-Python handlers for the SilentGuard read-only API.

Each handler returns a JSON-serializable ``dict``. They are intentionally
free of HTTP-specific concerns so the same functions can be unit-tested,
embedded in another transport, or reused by future consumers.

All handlers are read-only: they never mutate rules, memory, sockets,
processes, or system state. ``get_connections_summary`` does write to a
small local cache of recently-seen unknown destinations
(``~/.silentguard_unknown.json``) so consumers like Nova can describe
recent unknown traffic; that cache stores only minimal, non-sensitive
metadata (IP, process, timestamps, count, classification) and never
leaves the local machine.
"""

from __future__ import annotations

import logging
from typing import Any

from silentguard.connection_state import (
    CLASSIFICATION_PRIORITY,
    classification_from_label,
    record_connections,
    recent_unknown_destinations,
)
from silentguard.monitor import get_outgoing_connections, load_rules

LOGGER = logging.getLogger(__name__)

SUMMARY_PROCESS_LIMIT = 10
SUMMARY_REMOTE_HOST_LIMIT = 10
SUMMARY_RECENT_UNKNOWN_LIMIT = 5
RECENT_UNKNOWN_LIMIT = 50

_KNOWN_CLASSIFICATIONS = ("local", "known", "unknown", "trusted", "blocked")


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


def _empty_summary(status: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "total": 0,
        "local": 0,
        "known": 0,
        "unknown": 0,
        "trusted": 0,
        "blocked": 0,
        "recent_unknown": [],
        "by_process": [],
        "top_remote_hosts": [],
    }
    if status:
        payload["status"] = status
    return payload


def _classification_for(conn: Any) -> str:
    canonical = (getattr(conn, "classification", "") or "").strip().lower()
    if canonical in _KNOWN_CLASSIFICATIONS:
        return canonical
    return classification_from_label(getattr(conn, "trust", None))


def _serialize_recent_unknown(entry: dict) -> dict[str, Any]:
    return {
        "ip": entry.get("ip"),
        "process": entry.get("process"),
        "seen_count": entry.get("seen_count"),
        "first_seen": entry.get("first_seen"),
        "last_seen": entry.get("last_seen"),
        "classification": entry.get("classification", "unknown"),
    }


def get_connections_summary() -> dict[str, Any]:
    """Return a compact summary of current outgoing connections.

    Aggregates counts by trust classification (``local``, ``known``,
    ``unknown``, ``trusted``, ``blocked``), by process name, and the
    most-frequent remote IPs so consumers can describe network state
    without ingesting the full connection list. Lists are capped to keep
    the response small.

    The summary deliberately omits PIDs, ports, and per-connection rows
    that ``/connections`` already exposes — this endpoint is for
    at-a-glance overviews, not detailed inspection. No DNS resolution is
    performed, so ``top_remote_hosts`` carries IPs only.

    ``recent_unknown`` is sourced from the local unknown-destinations
    cache that ``record_connections`` keeps in sync. Each entry contains
    only non-sensitive metadata (IP, process, timestamps, count, current
    classification) — see ``connection_state`` for the storage policy.
    """
    try:
        connections = get_outgoing_connections()
    except Exception as exc:
        LOGGER.warning("get_connections_summary: monitor unavailable: %s", exc)
        return _empty_summary(status="not_available")

    counts = {key: 0 for key in _KNOWN_CLASSIFICATIONS}
    process_buckets: dict[str, dict[str, Any]] = {}
    remote_buckets: dict[str, dict[str, Any]] = {}
    total = 0

    for conn in connections:
        total += 1
        classification = _classification_for(conn)
        counts[classification] += 1

        process_name = (conn.process_name or "").strip() or "unknown"
        bucket = process_buckets.setdefault(
            process_name,
            {"process": process_name, "count": 0, "known": 0, "unknown": 0},
        )
        bucket["count"] += 1
        if classification in ("known", "unknown"):
            bucket[classification] += 1

        if classification == "local":
            continue
        ip = (conn.remote_ip or "").strip()
        if not ip:
            continue
        remote = remote_buckets.setdefault(
            ip, {"ip": ip, "count": 0, "classification": classification}
        )
        remote["count"] += 1
        if (
            CLASSIFICATION_PRIORITY[classification]
            > CLASSIFICATION_PRIORITY[remote["classification"]]
        ):
            remote["classification"] = classification

    by_process = sorted(
        process_buckets.values(),
        key=lambda b: (-b["count"], b["process"]),
    )[:SUMMARY_PROCESS_LIMIT]
    top_remote_hosts = sorted(
        remote_buckets.values(),
        key=lambda b: (-b["count"], b["ip"]),
    )[:SUMMARY_REMOTE_HOST_LIMIT]

    try:
        record_connections(connections)
    except Exception as exc:
        LOGGER.debug(
            "get_connections_summary: cache sync skipped: %s", exc, exc_info=True
        )

    try:
        recent_unknown = [
            _serialize_recent_unknown(entry)
            for entry in recent_unknown_destinations(SUMMARY_RECENT_UNKNOWN_LIMIT)
        ]
    except Exception as exc:
        LOGGER.warning(
            "get_connections_summary: unknown destinations cache unreadable: %s",
            exc,
        )
        recent_unknown = []

    if total == 0:
        payload = _empty_summary()
        payload["recent_unknown"] = recent_unknown
        return payload

    return {
        "total": total,
        "local": counts["local"],
        "known": counts["known"],
        "unknown": counts["unknown"],
        "trusted": counts["trusted"],
        "blocked": counts["blocked"],
        "recent_unknown": recent_unknown,
        "by_process": by_process,
        "top_remote_hosts": top_remote_hosts,
    }


def get_recent_unknown() -> dict[str, Any]:
    """Return recently-observed unknown destinations from the local cache.

    Read-only: this handler does not enumerate live sockets. It surfaces
    the entries that ``get_connections_summary`` (or other code calling
    ``record_connections``) has already persisted. Each entry exposes
    only the minimal metadata documented in ``connection_state``.
    """
    try:
        items = recent_unknown_destinations(RECENT_UNKNOWN_LIMIT)
    except Exception as exc:
        LOGGER.warning("get_recent_unknown: cache unavailable: %s", exc)
        return {"items": [], "status": "not_available"}

    return {"items": [_serialize_recent_unknown(entry) for entry in items]}
