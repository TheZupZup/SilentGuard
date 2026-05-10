"""Pure-Python handlers for the SilentGuard local API.

Each handler returns a JSON-serializable ``dict``. They are intentionally
free of HTTP-specific concerns so the same functions can be unit-tested,
embedded in another transport, or reused by future consumers.

The vast majority of handlers are read-only: they never mutate rules,
memory, sockets, processes, or system state. ``get_connections_summary``
writes to a small local cache of recently-seen unknown destinations
(``~/.silentguard_unknown.json``) so consumers like Nova can describe
recent unknown traffic; that cache stores only minimal, non-sensitive
metadata (IP, process, timestamps, count, classification) and never
leaves the local machine.

The mitigation handlers (``set_mitigation_mode``, ``add_temporary_block``,
``remove_temporary_block``) are the **only** write surface. They are
narrow on purpose: each handler validates its inputs, refuses
private/local/trusted/protected IPs, writes an audit entry on every
outcome, and is safe to call only from a loopback caller (the HTTP
layer enforces that).
"""

from __future__ import annotations

import logging
from typing import Any

from silentguard import detection, events, mitigation
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
EVENTS_LIST_LIMIT = 100
EVENTS_SUMMARY_RECENT_LIMIT = 5

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


def _empty_alert_summary(status: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "total": 0,
        "by_severity": {severity: 0 for severity in detection.SEVERITIES},
        "by_type": {},
        "highest_severity": None,
    }
    if status:
        payload["status"] = status
    return payload


def get_alerts() -> dict[str, Any]:
    """Return read-only flood/anomaly alerts derived from current connections.

    SilentGuard analyses the current connection snapshot (and the small
    local unknown-destinations cache) for conservative flood patterns
    and returns the resulting alerts. The endpoint is **detection only**:
    it never blocks IPs, mutates rules, or changes the firewall.

    SilentGuard cannot absorb upstream DDoS attacks that saturate the
    network link before traffic reaches the local machine — see
    ``silentguard.detection`` for the full set of caveats.

    When the underlying monitor cannot enumerate connections (for
    example because ``psutil`` lacks permissions), the response degrades
    to ``{"items": [], "status": "not_available"}`` so consumers can
    distinguish "no alerts" from "could not check".

    As a side effect, ``possible_flood`` alerts are also persisted to
    the local event history (see :mod:`silentguard.events`) so the
    ``/events`` and ``/events/summary`` endpoints can describe the
    history of flood patterns over time. Other detection alert types
    are not yet promoted to persistent history.
    """
    try:
        connections = get_outgoing_connections()
    except Exception as exc:
        LOGGER.warning("get_alerts: monitor unavailable: %s", exc)
        return {"items": [], "status": "not_available"}

    try:
        alerts = detection.evaluate(connections)
    except Exception:
        LOGGER.exception("get_alerts: detection failed")
        return {"items": [], "status": "not_available"}

    try:
        events.record_detection_alerts(alerts)
    except Exception:
        LOGGER.debug("get_alerts: event-history sync skipped", exc_info=True)

    return {"items": [alert.to_dict() for alert in alerts]}


def get_alerts_summary() -> dict[str, Any]:
    """Return a compact summary of the current flood/anomaly alerts.

    Intended for at-a-glance consumers (badges, status lines) that do
    not need the full alert list. Read-only and degrades to a zeroed
    payload with ``"status": "not_available"`` if the monitor or
    detection layer is unreachable.
    """
    try:
        connections = get_outgoing_connections()
    except Exception as exc:
        LOGGER.warning("get_alerts_summary: monitor unavailable: %s", exc)
        return _empty_alert_summary(status="not_available")

    try:
        alerts = detection.evaluate(connections)
    except Exception:
        LOGGER.exception("get_alerts_summary: detection failed")
        return _empty_alert_summary(status="not_available")

    return detection.summarize(alerts)


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


# ---------------------------------------------------------------------------
# Event history
# ---------------------------------------------------------------------------


def _empty_events_summary(status: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "total": 0,
        "active": 0,
        "by_severity": {severity: 0 for severity in events.SEVERITIES},
        "recent": [],
    }
    if status:
        payload["status"] = status
    return payload


def get_events() -> dict[str, Any]:
    """Return persisted security/network events newest-first.

    Read-only. Reads the local event-history store populated as a side
    effect of monitor refreshes and mitigation lifecycle changes. The
    list is capped to ``EVENTS_LIST_LIMIT`` so the response stays
    bounded; the on-disk store itself is also bounded — see
    :data:`silentguard.events.MAX_EVENTS`.

    On read failure the response degrades gracefully to
    ``{"items": [], "status": "not_available"}``.
    """
    try:
        items = events.list_events(limit=EVENTS_LIST_LIMIT)
    except Exception as exc:
        LOGGER.warning("get_events: store unavailable: %s", exc)
        return {"items": [], "status": "not_available"}
    return {"items": items}


def get_events_summary() -> dict[str, Any]:
    """Return a compact summary of the local event-history store.

    Shape (always present, even when empty)::

        {
            "total": <int>,
            "active": <int>,
            "by_severity": {"info": 0, "low": 0, "medium": 0,
                             "high": 0, "critical": 0},
            "recent": [<recent event recap>...],
        }

    Each entry in ``recent`` carries the minimal fields suggested by
    the event-history feature spec (id, type, severity, title, message,
    seen_count, last_seen, plus optional remote_ip / process). Read
    failures degrade to a zeroed payload tagged ``"status": "not_available"``.
    """
    try:
        return events.summary(recent_limit=EVENTS_SUMMARY_RECENT_LIMIT)
    except Exception as exc:
        LOGGER.warning("get_events_summary: store unavailable: %s", exc)
        return _empty_events_summary(status="not_available")


# ---------------------------------------------------------------------------
# Mitigation: read
# ---------------------------------------------------------------------------


def get_mitigation() -> dict[str, Any]:
    """Return the current mitigation posture, active temp blocks, and audit tail.

    Read-only. The status payload is shaped so a Nova/UI consumer can
    render the prompt copy, the current mode, and the most recent
    actions in one screen without making multiple round trips.
    """
    try:
        return mitigation.status_payload()
    except Exception as exc:
        LOGGER.warning("get_mitigation: state unavailable: %s", exc)
        return {
            "mode": mitigation.DEFAULT_MODE,
            "default_mode": mitigation.DEFAULT_MODE,
            "available_modes": list(mitigation.MITIGATION_MODES),
            "prompt": mitigation.MITIGATION_PROMPT,
            "disclaimer": mitigation.MITIGATION_DISCLAIMER,
            "active_temp_blocks": [],
            "recent_audit": [],
            "status": "not_available",
        }


# ---------------------------------------------------------------------------
# Mitigation: write helpers
#
# Each write handler returns ``(status, payload)``. The HTTP layer is
# responsible for actually setting the response code; passing it through
# the return value keeps the handlers easy to unit test without HTTP
# infrastructure.
# ---------------------------------------------------------------------------


def _bad_request(reason: str, **extra: Any) -> tuple[int, dict[str, Any]]:
    payload: dict[str, Any] = {"error": "bad_request", "reason": reason}
    payload.update(extra)
    return 400, payload


def enable_temporary_mitigation(body: dict | None) -> tuple[int, dict[str, Any]]:
    """Switch to ``temporary_auto_block`` mode.

    The body must include ``"acknowledge": true``. Without it the
    handler refuses so this endpoint cannot escalate the mode by
    accident (for example, a stray ``curl -XPOST``). The server
    additionally rejects non-loopback callers before the handler is
    invoked.
    """
    body = body or {}
    if body.get("acknowledge") is not True:
        return _bad_request(
            "acknowledge_required",
            message=(
                "Pass {\"acknowledge\": true} to confirm you understand "
                "that SilentGuard will temporarily block IPs that exceed "
                "the conservative high-severity threshold. Blocks are "
                "local, time-bounded, and reversible."
            ),
            prompt=mitigation.MITIGATION_PROMPT,
            disclaimer=mitigation.MITIGATION_DISCLAIMER,
        )
    note = body.get("note")
    if note is not None and not isinstance(note, str):
        return _bad_request("note_must_be_string")
    try:
        mitigation.set_mode(
            mitigation.MODE_TEMPORARY_AUTO_BLOCK,
            actor="api",
            note=note,
        )
    except ValueError as exc:
        return _bad_request("invalid_mode", detail=str(exc))
    return 200, {
        "ok": True,
        "mode": mitigation.MODE_TEMPORARY_AUTO_BLOCK,
        "disclaimer": mitigation.MITIGATION_DISCLAIMER,
        "auto_block_threshold": "REMOTE_IP_FLOOD_HIGH",
    }


def disable_mitigation(body: dict | None) -> tuple[int, dict[str, Any]]:
    """Switch back to ``detection_only`` mode.

    Optionally clears any currently-active temporary blocks if the body
    sets ``"clear_temp_blocks": true`` so the operator can return the
    machine to a clean read-only posture in one call.
    """
    body = body or {}
    note = body.get("note")
    if note is not None and not isinstance(note, str):
        return _bad_request("note_must_be_string")
    try:
        mitigation.set_mode(
            mitigation.MODE_DETECTION_ONLY,
            actor="api",
            note=note,
        )
    except ValueError as exc:
        return _bad_request("invalid_mode", detail=str(exc))

    cleared: list[str] = []
    if body.get("clear_temp_blocks") is True:
        for entry in list(mitigation.active_temp_blocks()):
            ok, _ = mitigation.remove_temporary_block(entry["ip"], actor="api")
            if ok:
                cleared.append(entry["ip"])

    return 200, {
        "ok": True,
        "mode": mitigation.MODE_DETECTION_ONLY,
        "cleared_temp_blocks": cleared,
    }


def add_temporary_block(body: dict | None) -> tuple[int, dict[str, Any]]:
    """Add a temporary block, validating the IP and rate-limit posture.

    Refuses local, private, multicast, reserved, trusted, protected, or
    already-blocked addresses, and never blocks based on body fields
    other than the ones listed below. ``source`` is forced to
    ``"manual"`` because the API endpoint represents an explicit user
    action; auto-block goes through :func:`mitigation.apply_auto_blocks`.
    """
    body = body or {}
    ip = body.get("ip")
    if not isinstance(ip, str) or not ip.strip():
        return _bad_request("ip_required")
    reason = body.get("reason", "")
    if reason is not None and not isinstance(reason, str):
        return _bad_request("reason_must_be_string")
    duration = body.get("duration_seconds")
    if duration is not None and not isinstance(duration, (int, float)):
        return _bad_request("duration_must_be_number")
    try:
        rules = load_rules()
    except Exception:
        rules = {}
    ok, payload = mitigation.add_temporary_block(
        ip,
        reason=str(reason or ""),
        duration_seconds=duration,
        source="manual",
        rules=rules,
    )
    if not ok:
        return 400, {
            "error": "rejected",
            "reason": payload.get("reason", "rejected"),
        }
    return 201, {"ok": True, "block": payload}


def remove_temporary_block(ip: str) -> tuple[int, dict[str, Any]]:
    """Remove a temporary block by IP. Returns 404 if no such block exists."""
    if not isinstance(ip, str) or not ip.strip():
        return _bad_request("ip_required")
    ok, payload = mitigation.remove_temporary_block(ip, actor="api")
    if not ok:
        if payload.get("reason") == "not_found":
            return 404, {"error": "not_found", "ip": ip.strip()}
        return _bad_request(payload.get("reason", "rejected"))
    return 200, {"ok": True, "removed": payload}
