"""Connection classification + unknown-destination sync layer.

This module owns three responsibilities so the TUI, GUI, and read-only
API never duplicate classification logic:

1. ``classify_connection`` returns a canonical lowercase classification
   (``"local"``, ``"known"``, ``"unknown"``, ``"trusted"``, ``"blocked"``)
   for a remote IP and process name against the user's rules.

2. ``display_label`` and ``classification_from_label`` translate between
   the canonical classifications and the title-case labels the existing
   TUI/GUI render.

3. The unknown-destinations cache (``~/.silentguard_unknown.json``)
   stores minimal metadata for outgoing connections we have observed
   with classification ``"unknown"`` so the API can report recent
   unknown destinations to local consumers (notably Nova) as read-only
   context.

Privacy / safety:

* The cache is **local-only** and never sent anywhere by this module.
* Stored fields are intentionally minimal: remote IP, process name,
  ``first_seen`` / ``last_seen`` ISO timestamps, ``seen_count``, and
  the most recent classification.
* Command lines, environment variables, packet contents, and raw socket
  internals are **not** stored.
* Local connections never enter the cache.
* Corrupted reads degrade gracefully to an empty cache instead of
  raising.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

LOGGER = logging.getLogger(__name__)

UNKNOWN_DESTINATIONS_FILE = Path.home() / ".silentguard_unknown.json"

# Hard cap to keep the on-disk cache small and contributor-friendly.
MAX_UNKNOWN_ENTRIES = 200

# Default cap used by ``recent_unknown_destinations`` and the API summary.
DEFAULT_RECENT_UNKNOWN_LIMIT = 5

LOCAL = "local"
KNOWN = "known"
UNKNOWN = "unknown"
TRUSTED = "trusted"
BLOCKED = "blocked"

CANONICAL_CLASSIFICATIONS: tuple[str, ...] = (LOCAL, KNOWN, UNKNOWN, TRUSTED, BLOCKED)

_DISPLAY_LABELS: dict[str, str] = {
    LOCAL: "Local",
    KNOWN: "Known",
    UNKNOWN: "Unknown",
    TRUSTED: "Trusted",
    BLOCKED: "Blocked",
}
_LABEL_TO_CANONICAL: dict[str, str] = {
    label.lower(): canonical for canonical, label in _DISPLAY_LABELS.items()
}

# Higher = more security-relevant. Used so a single Unknown hit on an
# IP isn't masked by other connections to the same IP being labelled
# Known or Trusted in summary aggregations.
CLASSIFICATION_PRIORITY: dict[str, int] = {
    BLOCKED: 5,
    UNKNOWN: 4,
    KNOWN: 3,
    TRUSTED: 2,
    LOCAL: 1,
}


def display_label(classification: str) -> str:
    """Return the title-case label used by the TUI/GUI for ``classification``."""
    return _DISPLAY_LABELS.get(classification, _DISPLAY_LABELS[UNKNOWN])


def classification_from_label(label: str | None) -> str:
    """Best-effort map of a user-facing trust label to its canonical form."""
    if not label:
        return UNKNOWN
    return _LABEL_TO_CANONICAL.get(str(label).strip().lower(), UNKNOWN)


def _is_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


def classify_connection(
    remote_ip: str,
    process_name: str | None,
    rules: dict | None,
) -> str:
    """Classify a connection against the loaded rules.

    Precedence (most specific first):

    * ``blocked`` — IP is in ``rules["blocked_ips"]``.
    * ``trusted`` — IP is in ``rules["trusted_ips"]``.
    * ``local``   — IP is loopback / RFC 1918 / link-local.
    * ``known``   — process is in ``rules["known_processes"]``.
    * ``unknown`` — anything else.
    """
    rules = rules or {}
    blocked_ips = {str(ip) for ip in rules.get("blocked_ips") or []}
    trusted_ips = {str(ip) for ip in rules.get("trusted_ips") or []}
    known_processes = {
        str(p).lower() for p in rules.get("known_processes") or []
    }

    ip = (remote_ip or "").strip()
    if ip in blocked_ips:
        return BLOCKED
    if ip in trusted_ips:
        return TRUSTED
    if _is_local_ip(ip):
        return LOCAL

    name = (process_name or "").strip().lower()
    if name and name in known_processes:
        return KNOWN

    return UNKNOWN


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _empty_cache() -> dict:
    return {"version": 1, "destinations": []}


def _coerce_entry(raw: dict, fallback_now: str) -> dict | None:
    if not isinstance(raw, dict):
        return None
    ip = str(raw.get("ip", "")).strip()
    if not ip:
        return None
    classification = raw.get("classification")
    if classification not in CANONICAL_CLASSIFICATIONS:
        classification = UNKNOWN
    try:
        seen_count = int(raw.get("seen_count") or 0)
    except (TypeError, ValueError):
        seen_count = 0
    return {
        "ip": ip,
        "process": str(raw.get("process") or "Unknown"),
        "first_seen": str(raw.get("first_seen") or fallback_now),
        "last_seen": str(raw.get("last_seen") or fallback_now),
        "seen_count": max(0, seen_count),
        "classification": classification,
    }


def _load_cache(path: Path | None = None) -> dict:
    file_path = path if path is not None else UNKNOWN_DESTINATIONS_FILE
    if not file_path.exists():
        return _empty_cache()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        LOGGER.warning(
            "Unable to parse unknown destinations cache %s: %s", file_path, exc
        )
        return _empty_cache()
    except OSError as exc:
        LOGGER.warning(
            "Unable to read unknown destinations cache %s: %s", file_path, exc
        )
        return _empty_cache()

    if not isinstance(data, dict):
        return _empty_cache()
    raw_destinations = data.get("destinations")
    if not isinstance(raw_destinations, list):
        return _empty_cache()

    fallback_now = _utc_now_iso()
    cleaned: list[dict] = []
    for raw in raw_destinations:
        entry = _coerce_entry(raw, fallback_now)
        if entry is not None:
            cleaned.append(entry)
    return {"version": 1, "destinations": cleaned}


def _save_cache(data: dict, path: Path | None = None) -> None:
    file_path = path if path is not None else UNKNOWN_DESTINATIONS_FILE
    file_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=".silentguard_unknown.",
        suffix=".tmp",
        dir=str(file_path.parent),
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp_name, file_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def load_unknown_destinations(path: Path | None = None) -> list[dict]:
    """Return cache entries sorted most-recent first."""
    cache = _load_cache(path)
    return sorted(
        cache.get("destinations", []),
        key=lambda e: e.get("last_seen", ""),
        reverse=True,
    )


def recent_unknown_destinations(
    limit: int = DEFAULT_RECENT_UNKNOWN_LIMIT,
    path: Path | None = None,
) -> list[dict]:
    """Return the most-recently-seen entries currently classified as ``unknown``."""
    if limit <= 0:
        return []
    items = [
        entry
        for entry in load_unknown_destinations(path)
        if entry.get("classification") == UNKNOWN
    ]
    return items[:limit]


def clear_unknown_destinations(path: Path | None = None) -> None:
    """Remove the cache file. Safe to call when the file does not exist."""
    file_path = path if path is not None else UNKNOWN_DESTINATIONS_FILE
    try:
        file_path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        LOGGER.warning(
            "Unable to remove unknown destinations cache %s: %s", file_path, exc
        )


def record_connections(
    connections: Iterable, path: Path | None = None
) -> None:
    """Synchronise the unknown-destinations cache from a fresh snapshot.

    For each connection we add or refresh entries when the classification
    is ``unknown``. Entries already in the cache that transition to a
    different classification (for example because the user trusted the
    IP) have their ``classification`` field updated in place so the cache
    reflects current state.

    ``seen_count`` increments at most once per IP per snapshot. Local
    connections never enter the cache. The on-disk write is skipped if
    nothing changed so frequent refreshes from the TUI/GUI do not cause
    needless I/O. Failures to persist are logged and swallowed; the
    in-memory state of the caller is never corrupted.
    """
    cache = _load_cache(path)
    by_ip: dict[str, dict] = {
        entry["ip"]: entry for entry in cache.get("destinations", [])
    }
    now = _utc_now_iso()
    counted_this_snapshot: set[str] = set()
    changed = False

    # Snapshot once so the connections iterable can be replayed for
    # the event-history sync below even if the caller passed a
    # one-shot generator.
    snapshot = list(connections)

    for conn in snapshot:
        ip = str(getattr(conn, "remote_ip", "") or "").strip()
        if not ip:
            continue
        classification = str(getattr(conn, "classification", "") or "").strip().lower()
        if classification not in CANONICAL_CLASSIFICATIONS:
            classification = classification_from_label(
                getattr(conn, "trust", None)
            )
        if classification == LOCAL:
            continue

        process = str(getattr(conn, "process_name", "") or "").strip() or "Unknown"
        entry = by_ip.get(ip)

        if classification == UNKNOWN:
            if entry is None:
                by_ip[ip] = {
                    "ip": ip,
                    "process": process,
                    "first_seen": now,
                    "last_seen": now,
                    "seen_count": 1,
                    "classification": UNKNOWN,
                }
                counted_this_snapshot.add(ip)
                changed = True
            else:
                entry["last_seen"] = now
                entry["classification"] = UNKNOWN
                entry["process"] = process
                if ip not in counted_this_snapshot:
                    entry["seen_count"] = int(entry.get("seen_count", 0)) + 1
                    counted_this_snapshot.add(ip)
                changed = True
        else:
            # Connection is now known/trusted/blocked. Update existing
            # entry's classification so consumers can see the transition,
            # but do not start tracking IPs we never saw as unknown.
            if entry is not None and entry.get("classification") != classification:
                entry["classification"] = classification
                entry["last_seen"] = now
                changed = True

    try:
        from silentguard import events as _events

        _events.record_connection_observations(snapshot)
    except Exception:
        LOGGER.debug(
            "Skipping event-history sync due to error", exc_info=True
        )

    if not changed:
        return

    destinations = sorted(
        by_ip.values(),
        key=lambda e: e.get("last_seen", ""),
        reverse=True,
    )[:MAX_UNKNOWN_ENTRIES]
    cache["destinations"] = destinations
    cache["version"] = 1
    try:
        _save_cache(cache, path)
    except OSError as exc:
        LOGGER.warning("Unable to write unknown destinations cache: %s", exc)
