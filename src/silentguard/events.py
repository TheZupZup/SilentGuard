"""Local alert/event history for SilentGuard.

This module gives SilentGuard a small, bounded, local-only timeline of
meaningful security and network state changes. It is intentionally
separate from:

* :mod:`silentguard.connection_state` — owns the unknown-destinations
  cache and per-IP observation counters.
* :mod:`silentguard.detection` — produces stateless, snapshot-derived
  alerts on every poll.
* :mod:`silentguard.mitigation` — owns mitigation policy and the
  mitigation audit log.

This module never replaces those layers; it sits alongside them so
the TUI/API/Nova can describe *what changed over time* without
re-deriving state on every poll.

Design constraints
==================

* **Local-only.** The events file lives under the user's home directory
  and is never sent anywhere by this module.
* **Read-only API surface.** Events are recorded as side effects of
  existing state changes (unknown connection observed, mitigation mode
  changed, temporary block created/expired). The HTTP layer in
  :mod:`silentguard.api` only exposes ``GET`` endpoints for events.
* **Bounded storage.** The on-disk file is capped at :data:`MAX_EVENTS`
  so it cannot grow unbounded.
* **Deterministic.** The same input always maps to the same event id,
  type, and severity, so behaviour is auditable. Callers can pass
  ``now`` for tests.
* **Privacy-respecting.** Only minimal metadata is persisted: type,
  severity, title, message, source module name, remote IP, process
  name, timestamps, ``seen_count``, ``status``. **No** command lines,
  environment variables, packet contents, full process metadata, or
  raw socket internals.
* **No autonomous actions.** The events module never blocks IPs, never
  modifies firewall rules, never runs privileged commands, and never
  sends notifications. It is visibility/history only.

Event lifecycle
===============

Events that can naturally repeat (an unknown destination being seen
again, an alert firing on the same source IP) are coalesced by a stable
id keyed on the source. Coalescing updates ``last_seen`` and increments
``seen_count``. Once a coalesced ``unknown_connection_seen`` reaches
:data:`REPEAT_THRESHOLD` observations its type is promoted to
``repeated_unknown_connection`` and severity bumps to ``medium``. The
id stays stable across the promotion so consumers tracking the entry
do not see it disappear.

One-shot events (mode changes, temporary block creation/expiry) are
recorded as new entries each time. Their ids include a timestamp so
they remain unique.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# File location and bounds
# ---------------------------------------------------------------------------

EVENTS_FILE = Path.home() / ".silentguard_events.json"

# Hard cap on persisted events. Newest are kept; the oldest are evicted
# first so the file stays small and contributor-friendly.
MAX_EVENTS = 500

# Default cap used by ``recent_events`` and the summary helper.
DEFAULT_RECENT_LIMIT = 5

# ``unknown_connection_seen`` events are promoted to
# ``repeated_unknown_connection`` once the rolling ``seen_count``
# reaches this threshold.
REPEAT_THRESHOLD = 5


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITIES: tuple[str, ...] = (
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

TYPE_UNKNOWN_CONNECTION_SEEN = "unknown_connection_seen"
TYPE_REPEATED_UNKNOWN_CONNECTION = "repeated_unknown_connection"
TYPE_POSSIBLE_FLOOD = "possible_flood"
TYPE_MITIGATION_ENABLED = "mitigation_enabled"
TYPE_MITIGATION_DISABLED = "mitigation_disabled"
TYPE_TEMPORARY_BLOCK_CREATED = "temporary_block_created"
TYPE_TEMPORARY_BLOCK_EXPIRED = "temporary_block_expired"
TYPE_TRUSTED_IP_SEEN = "trusted_ip_seen"
TYPE_BLOCKED_IP_SEEN = "blocked_ip_seen"

EVENT_TYPES: tuple[str, ...] = (
    TYPE_UNKNOWN_CONNECTION_SEEN,
    TYPE_REPEATED_UNKNOWN_CONNECTION,
    TYPE_POSSIBLE_FLOOD,
    TYPE_MITIGATION_ENABLED,
    TYPE_MITIGATION_DISABLED,
    TYPE_TEMPORARY_BLOCK_CREATED,
    TYPE_TEMPORARY_BLOCK_EXPIRED,
    TYPE_TRUSTED_IP_SEEN,
    TYPE_BLOCKED_IP_SEEN,
)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

STATUS_ACTIVE = "active"
STATUS_RESOLVED = "resolved"

STATUSES: tuple[str, ...] = (STATUS_ACTIVE, STATUS_RESOLVED)


# ---------------------------------------------------------------------------
# Field caps
# ---------------------------------------------------------------------------

MAX_TITLE_LENGTH = 120
MAX_MESSAGE_LENGTH = 280
MAX_PROCESS_NAME_LENGTH = 128
MAX_SOURCE_LENGTH = 64

_SEVERITY_KEYS_FOR_SUMMARY: tuple[str, ...] = (
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso(now: datetime | None = None) -> str:
    return (now or _utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sanitize_id_segment(value: str) -> str:
    """Return ``value`` with characters that are unfriendly in ids replaced.

    We keep dots and digits so IPv4 addresses round-trip cleanly. IPv6
    colons are replaced with ``-`` so the resulting id stays usable in
    URLs and shell-friendly contexts.
    """
    return re.sub(r"[^A-Za-z0-9._-]", "-", str(value or ""))


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def _empty_store() -> dict:
    return {"version": 1, "events": []}


def _coerce_event(raw: Any) -> dict | None:
    if not isinstance(raw, dict):
        return None
    event_id = str(raw.get("id") or "").strip()
    type_ = str(raw.get("type") or "").strip()
    severity = str(raw.get("severity") or "").strip()
    if not event_id or type_ not in EVENT_TYPES or severity not in SEVERITIES:
        return None
    try:
        seen_count = int(raw.get("seen_count") or 1)
    except (TypeError, ValueError):
        seen_count = 1
    if seen_count < 1:
        seen_count = 1
    title = str(raw.get("title") or "")[:MAX_TITLE_LENGTH]
    message = str(raw.get("message") or "")[:MAX_MESSAGE_LENGTH]
    source = str(raw.get("source") or "")[:MAX_SOURCE_LENGTH]
    status = raw.get("status")
    if status not in STATUSES:
        status = STATUS_ACTIVE
    first_seen = str(raw.get("first_seen") or "")
    last_seen = str(raw.get("last_seen") or "")
    if not first_seen and not last_seen:
        return None
    if not first_seen:
        first_seen = last_seen
    if not last_seen:
        last_seen = first_seen
    entry: dict[str, Any] = {
        "id": event_id,
        "type": type_,
        "severity": severity,
        "title": title,
        "message": message,
        "source": source,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "seen_count": seen_count,
        "status": status,
    }
    remote_ip = raw.get("remote_ip")
    if isinstance(remote_ip, str) and remote_ip.strip():
        entry["remote_ip"] = remote_ip.strip()
    process = raw.get("process")
    if isinstance(process, str) and process.strip():
        entry["process"] = process.strip()[:MAX_PROCESS_NAME_LENGTH]
    return entry


def _load_store(path: Path | None = None) -> dict:
    file_path = path if path is not None else EVENTS_FILE
    if not file_path.exists():
        return _empty_store()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        LOGGER.warning("Events file %s invalid: %s", file_path, exc)
        return _empty_store()
    except OSError as exc:
        LOGGER.warning("Events file %s unreadable: %s", file_path, exc)
        return _empty_store()
    if not isinstance(data, dict):
        return _empty_store()
    raw_events = data.get("events")
    if not isinstance(raw_events, list):
        return _empty_store()
    cleaned: list[dict] = []
    for raw in raw_events:
        entry = _coerce_event(raw)
        if entry is not None:
            cleaned.append(entry)
    return {"version": 1, "events": cleaned}


def _save_store(store: dict, path: Path | None = None) -> None:
    file_path = path if path is not None else EVENTS_FILE
    events = list(store.get("events") or [])
    events.sort(key=lambda e: e.get("last_seen", ""), reverse=True)
    if len(events) > MAX_EVENTS:
        events = events[:MAX_EVENTS]
    payload = {"version": 1, "events": events}
    try:
        _atomic_write_json(file_path, payload)
    except OSError as exc:
        LOGGER.warning("Unable to write events file %s: %s", file_path, exc)


# ---------------------------------------------------------------------------
# ID helpers
# ---------------------------------------------------------------------------


def _ip_lifecycle_id(prefix: str, remote_ip: str) -> str:
    """Stable id for IP-keyed coalesced events.

    The ``prefix`` describes the lifecycle (e.g. ``unknown``,
    ``trusted``, ``blocked``, ``flood``) rather than the current event
    type so the id stays stable across deterministic type promotions.
    """
    return f"evt_{prefix}_{_sanitize_id_segment(remote_ip)}"


def _one_shot_id(type_: str, timestamp: str, *, suffix: str = "") -> str:
    """Stable id for one-shot (non-coalesced) events."""
    safe_ts = _sanitize_id_segment(timestamp)
    if suffix:
        return f"evt_{type_}_{safe_ts}_{_sanitize_id_segment(suffix)}"
    return f"evt_{type_}_{safe_ts}"


# ---------------------------------------------------------------------------
# Internal record helpers
# ---------------------------------------------------------------------------


def _find_index(events: list[dict], event_id: str) -> int | None:
    for index, entry in enumerate(events):
        if entry.get("id") == event_id:
            return index
    return None


def _new_entry(
    *,
    event_id: str,
    type_: str,
    severity: str,
    title: str,
    message: str,
    source: str,
    timestamp: str,
    remote_ip: str | None = None,
    process: str | None = None,
) -> dict:
    entry: dict[str, Any] = {
        "id": event_id,
        "type": type_,
        "severity": severity,
        "title": title[:MAX_TITLE_LENGTH],
        "message": message[:MAX_MESSAGE_LENGTH],
        "source": source[:MAX_SOURCE_LENGTH],
        "first_seen": timestamp,
        "last_seen": timestamp,
        "seen_count": 1,
        "status": STATUS_ACTIVE,
    }
    if remote_ip:
        entry["remote_ip"] = str(remote_ip).strip()
    if process:
        entry["process"] = str(process).strip()[:MAX_PROCESS_NAME_LENGTH]
    return entry


def _persist(store: dict, path: Path | None) -> None:
    """Save ``store`` swallowing failures so callers never break.

    Recording an event must never escalate into an exception that breaks
    the monitor refresh path or a mitigation write. The error has
    already been logged inside :func:`_save_store`.
    """
    try:
        _save_store(store, path)
    except Exception:  # noqa: BLE001 - defensive belt-and-braces
        LOGGER.debug("Failed to save events store", exc_info=True)


# ---------------------------------------------------------------------------
# Recording — connection observations
# ---------------------------------------------------------------------------


def record_unknown_connection_seen(
    remote_ip: str,
    process: str | None = None,
    *,
    path: Path | None = None,
    now: datetime | None = None,
) -> dict | None:
    """Record (or update) an event for an unknown remote destination.

    Coalesces by IP. The event type promotes from
    ``unknown_connection_seen`` (low severity) to
    ``repeated_unknown_connection`` (medium) once ``seen_count`` reaches
    :data:`REPEAT_THRESHOLD`. The id stays stable across the promotion.

    Returns the resulting entry (a copy), or ``None`` if ``remote_ip``
    is empty.
    """
    ip = (remote_ip or "").strip()
    if not ip:
        return None
    timestamp = _utc_now_iso(now)
    event_id = _ip_lifecycle_id("unknown", ip)

    store = _load_store(path)
    events: list[dict] = list(store.get("events") or [])
    index = _find_index(events, event_id)

    if index is None:
        entry = _new_entry(
            event_id=event_id,
            type_=TYPE_UNKNOWN_CONNECTION_SEEN,
            severity=SEVERITY_LOW,
            title="Unknown connection observed",
            message=(
                "A previously unknown remote destination was observed."
            ),
            source="connection_state",
            timestamp=timestamp,
            remote_ip=ip,
            process=process,
        )
        events.append(entry)
    else:
        entry = dict(events[index])
        entry["last_seen"] = timestamp
        entry["seen_count"] = int(entry.get("seen_count") or 0) + 1
        entry["status"] = STATUS_ACTIVE
        if process and str(process).strip():
            entry["process"] = str(process).strip()[:MAX_PROCESS_NAME_LENGTH]
        if entry["seen_count"] >= REPEAT_THRESHOLD:
            entry["type"] = TYPE_REPEATED_UNKNOWN_CONNECTION
            entry["severity"] = SEVERITY_MEDIUM
            entry["title"] = "Repeated unknown connection"
            entry["message"] = (
                "An unknown remote destination was observed repeatedly."
            )
        events[index] = entry

    store["events"] = events
    _persist(store, path)
    return dict(entry)


def record_trusted_ip_seen(
    remote_ip: str,
    process: str | None = None,
    *,
    path: Path | None = None,
    now: datetime | None = None,
) -> dict | None:
    """Record that a trusted remote IP was observed (coalesced by IP)."""
    ip = (remote_ip or "").strip()
    if not ip:
        return None
    timestamp = _utc_now_iso(now)
    event_id = _ip_lifecycle_id("trusted", ip)

    store = _load_store(path)
    events: list[dict] = list(store.get("events") or [])
    index = _find_index(events, event_id)

    if index is None:
        entry = _new_entry(
            event_id=event_id,
            type_=TYPE_TRUSTED_IP_SEEN,
            severity=SEVERITY_INFO,
            title="Trusted IP observed",
            message="A trusted remote destination was observed.",
            source="connection_state",
            timestamp=timestamp,
            remote_ip=ip,
            process=process,
        )
        events.append(entry)
    else:
        entry = dict(events[index])
        entry["last_seen"] = timestamp
        entry["seen_count"] = int(entry.get("seen_count") or 0) + 1
        entry["status"] = STATUS_ACTIVE
        if process and str(process).strip():
            entry["process"] = str(process).strip()[:MAX_PROCESS_NAME_LENGTH]
        events[index] = entry

    store["events"] = events
    _persist(store, path)
    return dict(entry)


def record_blocked_ip_seen(
    remote_ip: str,
    process: str | None = None,
    *,
    path: Path | None = None,
    now: datetime | None = None,
) -> dict | None:
    """Record that a blocked remote IP was observed (coalesced by IP)."""
    ip = (remote_ip or "").strip()
    if not ip:
        return None
    timestamp = _utc_now_iso(now)
    event_id = _ip_lifecycle_id("blocked", ip)

    store = _load_store(path)
    events: list[dict] = list(store.get("events") or [])
    index = _find_index(events, event_id)

    if index is None:
        entry = _new_entry(
            event_id=event_id,
            type_=TYPE_BLOCKED_IP_SEEN,
            severity=SEVERITY_MEDIUM,
            title="Blocked IP still observed",
            message=(
                "A blocked remote destination is still appearing in "
                "outgoing connections."
            ),
            source="connection_state",
            timestamp=timestamp,
            remote_ip=ip,
            process=process,
        )
        events.append(entry)
    else:
        entry = dict(events[index])
        entry["last_seen"] = timestamp
        entry["seen_count"] = int(entry.get("seen_count") or 0) + 1
        entry["status"] = STATUS_ACTIVE
        if process and str(process).strip():
            entry["process"] = str(process).strip()[:MAX_PROCESS_NAME_LENGTH]
        events[index] = entry

    store["events"] = events
    _persist(store, path)
    return dict(entry)


def record_connection_observations(
    connections: Iterable,
    *,
    path: Path | None = None,
    now: datetime | None = None,
) -> None:
    """Record per-IP events for a snapshot of outgoing connections.

    Coalesces within the snapshot: each remote IP increments its
    ``seen_count`` at most once per call regardless of how many
    concurrent sockets target it. Local connections are ignored to keep
    the event history focused on outbound destinations the user might
    care about. Failures are logged and swallowed so this never breaks
    the monitor refresh path.
    """
    timestamp_dt = now or _utc_now()
    seen_unknown: set[str] = set()
    seen_trusted: set[str] = set()
    seen_blocked: set[str] = set()

    for conn in connections:
        ip = str(getattr(conn, "remote_ip", "") or "").strip()
        if not ip:
            continue
        classification = (
            str(getattr(conn, "classification", "") or "").strip().lower()
        )
        if not classification:
            try:
                from silentguard.connection_state import classification_from_label

                classification = classification_from_label(
                    getattr(conn, "trust", None)
                )
            except Exception:
                continue
        if classification == "local":
            continue
        process = str(getattr(conn, "process_name", "") or "").strip() or None

        try:
            if classification == "unknown" and ip not in seen_unknown:
                seen_unknown.add(ip)
                record_unknown_connection_seen(
                    ip, process=process, path=path, now=timestamp_dt
                )
            elif classification == "trusted" and ip not in seen_trusted:
                seen_trusted.add(ip)
                record_trusted_ip_seen(
                    ip, process=process, path=path, now=timestamp_dt
                )
            elif classification == "blocked" and ip not in seen_blocked:
                seen_blocked.add(ip)
                record_blocked_ip_seen(
                    ip, process=process, path=path, now=timestamp_dt
                )
        except Exception:
            LOGGER.debug(
                "Failed to record event for connection ip=%s class=%s",
                ip,
                classification,
                exc_info=True,
            )


# ---------------------------------------------------------------------------
# Recording — mitigation lifecycle
# ---------------------------------------------------------------------------


def record_mitigation_mode_change(
    new_mode: str,
    previous_mode: str,
    *,
    actor: str = "user",
    path: Path | None = None,
    now: datetime | None = None,
) -> dict | None:
    """Record a mitigation mode change. ``mitigation_enabled`` when the
    new mode is the auto-block mode, ``mitigation_disabled`` when the
    machine returns to ``detection_only``, otherwise no-op.
    """
    timestamp = _utc_now_iso(now)
    new_mode = str(new_mode or "").strip()
    previous_mode = str(previous_mode or "").strip()
    if new_mode == previous_mode:
        return None

    if new_mode == "temporary_auto_block":
        type_ = TYPE_MITIGATION_ENABLED
        title = "Mitigation enabled"
        message = (
            "SilentGuard switched to temporary_auto_block mode. "
            "High-severity flood IPs may now be temporarily blocked."
        )
    elif new_mode == "detection_only":
        type_ = TYPE_MITIGATION_DISABLED
        title = "Mitigation disabled"
        message = (
            "SilentGuard returned to detection_only mode. "
            "No automatic blocking will occur."
        )
    else:
        # ``ask_before_blocking`` and other transitions are deliberately
        # not promoted to a top-level event here; they remain in the
        # mitigation audit log as the authoritative record.
        return None

    event_id = _one_shot_id(type_, timestamp, suffix=actor or "user")
    severity = SEVERITY_INFO

    store = _load_store(path)
    events: list[dict] = list(store.get("events") or [])
    if _find_index(events, event_id) is not None:
        # An event with this id already exists (same actor, same second);
        # avoid creating a duplicate.
        return None

    entry = _new_entry(
        event_id=event_id,
        type_=type_,
        severity=severity,
        title=title,
        message=message,
        source="mitigation",
        timestamp=timestamp,
    )
    events.append(entry)
    store["events"] = events
    _persist(store, path)
    return dict(entry)


def record_temporary_block_created(
    remote_ip: str,
    *,
    reason: str | None = None,
    expires_at: str | None = None,
    block_source: str | None = None,
    path: Path | None = None,
    now: datetime | None = None,
) -> dict | None:
    """Record a ``temporary_block_created`` event."""
    ip = (remote_ip or "").strip()
    if not ip:
        return None
    timestamp = _utc_now_iso(now)
    event_id = _one_shot_id(
        TYPE_TEMPORARY_BLOCK_CREATED, timestamp, suffix=ip
    )

    store = _load_store(path)
    events: list[dict] = list(store.get("events") or [])
    if _find_index(events, event_id) is not None:
        return None

    note = (reason or "").strip()
    extra = ""
    if block_source:
        extra = f" Source: {block_source}."
    if expires_at:
        extra += f" Expires at {expires_at}."
    message = (
        "A temporary local block was created for the remote IP."
        + (f" Reason: {note}." if note else "")
        + extra
    )
    entry = _new_entry(
        event_id=event_id,
        type_=TYPE_TEMPORARY_BLOCK_CREATED,
        severity=SEVERITY_MEDIUM,
        title="Temporary block created",
        message=message,
        source="mitigation",
        timestamp=timestamp,
        remote_ip=ip,
    )
    events.append(entry)
    store["events"] = events
    _persist(store, path)
    return dict(entry)


def record_temporary_block_expired(
    remote_ip: str,
    *,
    path: Path | None = None,
    now: datetime | None = None,
) -> dict | None:
    """Record a ``temporary_block_expired`` event."""
    ip = (remote_ip or "").strip()
    if not ip:
        return None
    timestamp = _utc_now_iso(now)
    event_id = _one_shot_id(
        TYPE_TEMPORARY_BLOCK_EXPIRED, timestamp, suffix=ip
    )

    store = _load_store(path)
    events: list[dict] = list(store.get("events") or [])
    if _find_index(events, event_id) is not None:
        return None

    entry = _new_entry(
        event_id=event_id,
        type_=TYPE_TEMPORARY_BLOCK_EXPIRED,
        severity=SEVERITY_INFO,
        title="Temporary block expired",
        message=(
            "A temporary local block expired and the IP is no longer "
            "treated as blocked."
        ),
        source="mitigation",
        timestamp=timestamp,
        remote_ip=ip,
    )
    events.append(entry)
    store["events"] = events
    _persist(store, path)
    return dict(entry)


# ---------------------------------------------------------------------------
# Recording — detection alerts (currently: possible_flood)
# ---------------------------------------------------------------------------


_DETECTION_SEVERITY_FALLBACK = {
    "low": SEVERITY_LOW,
    "medium": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "critical": SEVERITY_CRITICAL,
}


def record_possible_flood(
    remote_ip: str,
    *,
    severity: str = SEVERITY_MEDIUM,
    count: int | None = None,
    path: Path | None = None,
    now: datetime | None = None,
) -> dict | None:
    """Record (or update) a ``possible_flood`` event for ``remote_ip``."""
    ip = (remote_ip or "").strip()
    if not ip:
        return None
    severity = _DETECTION_SEVERITY_FALLBACK.get(severity, SEVERITY_MEDIUM)
    timestamp = _utc_now_iso(now)
    event_id = _ip_lifecycle_id("flood", ip)

    store = _load_store(path)
    events: list[dict] = list(store.get("events") or [])
    index = _find_index(events, event_id)

    suffix = f" (count={int(count)})" if isinstance(count, int) else ""
    if index is None:
        entry = _new_entry(
            event_id=event_id,
            type_=TYPE_POSSIBLE_FLOOD,
            severity=severity,
            title="Possible flood pattern detected",
            message=(
                "One remote IP appears in many concurrent outgoing "
                "connections, which can indicate a flood pattern."
                + suffix
            ),
            source="detection",
            timestamp=timestamp,
            remote_ip=ip,
        )
        events.append(entry)
    else:
        entry = dict(events[index])
        entry["last_seen"] = timestamp
        entry["seen_count"] = int(entry.get("seen_count") or 0) + 1
        entry["status"] = STATUS_ACTIVE
        # Keep severity in sync with the latest observation so consumers
        # see escalations promptly.
        entry["severity"] = severity
        events[index] = entry

    store["events"] = events
    _persist(store, path)
    return dict(entry)


def record_detection_alerts(
    alerts: Iterable[Any],
    *,
    path: Path | None = None,
    now: datetime | None = None,
) -> None:
    """Persist any ``possible_flood`` alerts as events.

    Other detection alert types are intentionally not promoted into
    persistent history yet; they remain available via the live
    ``/alerts`` endpoint. Each call coalesces by IP so repeated polls
    do not spam the history.
    """
    timestamp_dt = now or _utc_now()
    for alert in alerts:
        if hasattr(alert, "to_dict"):
            payload = alert.to_dict()
        elif isinstance(alert, dict):
            payload = alert
        else:
            continue
        if payload.get("type") != "possible_flood":
            continue
        ip = (payload.get("source_ip") or "").strip()
        if not ip:
            continue
        try:
            record_possible_flood(
                ip,
                severity=str(payload.get("severity") or SEVERITY_MEDIUM),
                count=payload.get("count"),
                path=path,
                now=timestamp_dt,
            )
        except Exception:
            LOGGER.debug(
                "Failed to record possible_flood event for ip=%s",
                ip,
                exc_info=True,
            )


# ---------------------------------------------------------------------------
# Read-only access
# ---------------------------------------------------------------------------


def list_events(
    *,
    path: Path | None = None,
    limit: int | None = None,
    statuses: Iterable[str] | None = None,
) -> list[dict]:
    """Return events newest-first.

    ``limit`` clamps the response size. ``statuses`` filters by the
    ``status`` field; pass ``None`` to include every status.
    """
    store = _load_store(path)
    events = list(store.get("events") or [])
    events.sort(key=lambda e: e.get("last_seen", ""), reverse=True)
    if statuses is not None:
        allowed = {str(s) for s in statuses}
        events = [e for e in events if e.get("status") in allowed]
    if limit is None:
        return events
    if limit <= 0:
        return []
    return events[:limit]


def recent_events(
    *,
    limit: int = DEFAULT_RECENT_LIMIT,
    path: Path | None = None,
) -> list[dict]:
    """Convenience wrapper used by the API summary."""
    return list_events(path=path, limit=limit)


def _serialize_recent(entry: dict) -> dict[str, Any]:
    """Return a compact, JSON-friendly recap of ``entry`` for summaries."""
    payload: dict[str, Any] = {
        "id": entry.get("id"),
        "type": entry.get("type"),
        "severity": entry.get("severity"),
        "title": entry.get("title"),
        "message": entry.get("message"),
        "seen_count": entry.get("seen_count"),
        "last_seen": entry.get("last_seen"),
    }
    if entry.get("remote_ip"):
        payload["remote_ip"] = entry["remote_ip"]
    if entry.get("process"):
        payload["process"] = entry["process"]
    return payload


def summary(
    *,
    path: Path | None = None,
    recent_limit: int = DEFAULT_RECENT_LIMIT,
) -> dict[str, Any]:
    """Return the suggested ``/alerts/summary`` shape for event history.

    Always returns a stable structure even when no events have been
    recorded. ``by_severity`` always contains every severity key with
    a numeric count so consumers can treat the response uniformly.
    """
    events = list_events(path=path)
    by_severity: dict[str, int] = {key: 0 for key in _SEVERITY_KEYS_FOR_SUMMARY}
    active = 0
    for entry in events:
        sev = entry.get("severity")
        if sev in by_severity:
            by_severity[sev] += 1
        if entry.get("status") == STATUS_ACTIVE:
            active += 1
    recent = [
        _serialize_recent(entry) for entry in events[: max(0, recent_limit)]
    ]
    return {
        "total": len(events),
        "active": active,
        "by_severity": by_severity,
        "recent": recent,
    }


def clear_events(path: Path | None = None) -> None:
    """Remove the events file. Safe to call when the file is missing."""
    file_path = path if path is not None else EVENTS_FILE
    try:
        file_path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        LOGGER.warning("Unable to remove events file %s: %s", file_path, exc)
