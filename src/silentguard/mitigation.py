"""Local, opt-in flood mitigation policy for SilentGuard.

This module is the **policy + state** layer for the first safe,
human-approved mitigation flow. It is intentionally separate from
``silentguard.detection`` (signals) and from the rules file
(``~/.silentguard_rules.json``) which holds permanent user choices.

Goals
=====

* **Detection stays read-only.** ``detection.evaluate`` never blocks.
* **Default behaviour is detection-only.** No mode switch ever happens
  implicitly; a user must explicitly opt in.
* **Blocks are local, temporary, and reversible.** Every automatic block
  has an explicit ``expires_at`` and an entry in the audit log.
* **SilentGuard owns enforcement; Nova only explains and asks.** This
  module exposes pure-Python primitives the read-only API can wrap; it
  never spawns shells, calls firewalls, or talks to Nova directly.

Modes
=====

* ``detection_only`` (default) — never block automatically.
* ``ask_before_blocking`` — surface alerts to the UI/Nova, but the
  policy still does not auto-block. A separate user action must enable
  ``temporary_auto_block`` if they want enforcement.
* ``temporary_auto_block`` — when an alert at ``high`` or ``critical``
  severity (and only then, conservatively) names a specific source IP,
  block that IP for a bounded duration and write an audit entry. Mode
  must be enabled by the user via the API; it is *never* the default.

Safety invariants
=================

* The default mode is always ``detection_only``. State files that fail
  to load fall back to ``detection_only``.
* ``temporary_auto_block`` only fires for ``high``/``critical``
  ``possible_flood`` alerts (one specific source IP), never on
  threshold-medium alerts.
* IPs that fail :func:`silentguard.monitor.is_blockable_ip` (loopback,
  link-local, multicast, unspecified, reserved, private) are refused.
* Trusted IPs (from the rules file) and any user-configured
  ``protected_ips`` are refused. ``protected_ips`` is the user's escape
  hatch for VPN/Tailscale/Cloudflare-Tunnel endpoints, gateway/router
  IPs, DNS resolver IPs, and the Nova/SilentGuard host's own IPs.
* A conservative rate limit caps how many automatic blocks can be added
  per minute so an alert storm cannot fan out into a wall of blocks.

This module does not touch the firewall, does not run shell commands,
and does not require root. ``temp_blocks`` are merged into the trust
classification path via :mod:`silentguard.monitor` so the existing
TUI/GUI/API show them as ``Blocked`` until they expire.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# File locations
# ---------------------------------------------------------------------------

MITIGATION_FILE = Path.home() / ".silentguard_mitigation.json"
AUDIT_FILE = Path.home() / ".silentguard_mitigation_audit.json"


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

MODE_DETECTION_ONLY = "detection_only"
MODE_ASK_BEFORE_BLOCKING = "ask_before_blocking"
MODE_TEMPORARY_AUTO_BLOCK = "temporary_auto_block"

MITIGATION_MODES: tuple[str, ...] = (
    MODE_DETECTION_ONLY,
    MODE_ASK_BEFORE_BLOCKING,
    MODE_TEMPORARY_AUTO_BLOCK,
)

DEFAULT_MODE = MODE_DETECTION_ONLY


# ---------------------------------------------------------------------------
# Thresholds and safety caps
# ---------------------------------------------------------------------------

# Conservative auto-block threshold. Only ``possible_flood`` alerts whose
# severity reaches ``high`` (count >= REMOTE_IP_FLOOD_HIGH) are eligible
# for automatic temporary blocking. ``medium`` alerts surface for human
# review only, never trigger an auto-block.
AUTO_BLOCK_ELIGIBLE_SEVERITIES: frozenset[str] = frozenset({"high", "critical"})
AUTO_BLOCK_ELIGIBLE_TYPES: frozenset[str] = frozenset({"possible_flood"})

# Default temporary block lifetime, in seconds. The cap is intentionally
# short so a misconfiguration self-heals quickly.
DEFAULT_TEMP_BLOCK_DURATION = 600       # 10 minutes
MIN_TEMP_BLOCK_DURATION = 30            # 30 seconds
MAX_TEMP_BLOCK_DURATION = 3600          # 1 hour

# Rate limit: at most this many automatic blocks may be created in a
# rolling sixty-second window. Above the limit, additional candidates
# are refused with reason ``rate_limited`` and the audit log records
# the rejection.
AUTO_BLOCK_RATE_LIMIT = 10
AUTO_BLOCK_RATE_WINDOW_SECONDS = 60

MAX_AUDIT_ENTRIES = 1000

# Maximum length of free-form ``reason`` strings on a temporary block.
# Keeps the on-disk store and audit log compact.
MAX_REASON_LENGTH = 200


# ---------------------------------------------------------------------------
# UX copy. Stored here so Nova, the TUI, and the API surface use the same
# wording when asking the user for explicit consent.
# ---------------------------------------------------------------------------

MITIGATION_PROMPT = (
    "This activity resembles a possible flood/DDoS-style attack. "
    "Do you want SilentGuard to temporarily block sources that "
    "continue matching this pattern?"
)

MITIGATION_DISCLAIMER = (
    "SilentGuard cannot absorb upstream DDoS attacks that saturate the "
    "network link before traffic reaches the local NIC. This is local "
    "mitigation only: blocks are temporary, opt-in, and reversible."
)


# ---------------------------------------------------------------------------
# Audit log event types
# ---------------------------------------------------------------------------

EVENT_MODE_CHANGED = "mode_changed"
EVENT_TEMP_BLOCK_ADDED = "temp_block_added"
EVENT_TEMP_BLOCK_REMOVED = "temp_block_removed"
EVENT_TEMP_BLOCK_EXPIRED = "temp_block_expired"
EVENT_TEMP_BLOCK_REJECTED = "temp_block_rejected"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso(now: datetime | None = None) -> str:
    return (now or _utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_z(value: str) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _coerce_str_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    return out


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
# Validation
# ---------------------------------------------------------------------------


def is_valid_mode(mode: str) -> bool:
    return mode in MITIGATION_MODES


def normalize_duration(seconds: Any) -> int:
    """Clamp ``seconds`` to ``[MIN, MAX]_TEMP_BLOCK_DURATION``.

    ``None`` and invalid values fall back to ``DEFAULT_TEMP_BLOCK_DURATION``.
    The return value is always an ``int`` so the on-disk shape is
    predictable.
    """
    if seconds is None:
        return DEFAULT_TEMP_BLOCK_DURATION
    try:
        value = int(seconds)
    except (TypeError, ValueError):
        return DEFAULT_TEMP_BLOCK_DURATION
    if value < MIN_TEMP_BLOCK_DURATION:
        return MIN_TEMP_BLOCK_DURATION
    if value > MAX_TEMP_BLOCK_DURATION:
        return MAX_TEMP_BLOCK_DURATION
    return value


def _is_safe_to_block(ip: str) -> tuple[bool, str | None]:
    """Wrapper around :func:`silentguard.monitor.is_blockable_ip`.

    Done as a thin local proxy so callers in this module do not have to
    import :mod:`silentguard.monitor` (which pulls in ``psutil``).
    """
    # Lazy import to avoid a hard dependency on psutil for tests that
    # only exercise the policy primitives.
    from silentguard.monitor import is_blockable_ip

    return is_blockable_ip(ip)


def evaluate_block_candidate(
    ip: str,
    *,
    rules: dict | None = None,
    state: dict | None = None,
) -> tuple[bool, str | None]:
    """Decide whether ``ip`` is safe to block under mitigation policy.

    Returns ``(True, None)`` when blocking is allowed, otherwise
    ``(False, reason)``. ``reason`` is short and stable so callers can
    surface it directly to the user or include it in audit entries.

    The check folds together every "never block" guarantee documented
    on this module:

    * Invalid IPs are rejected.
    * Loopback / private / link-local / multicast / reserved / unspec
      addresses are rejected (covers gateway/router and most LAN
      hardware whose addresses are private).
    * Trusted IPs from the rules file are rejected.
    * User-configured ``protected_ips`` (VPN endpoints, DNS resolvers,
      Nova/SilentGuard host IPs) are rejected.
    * IPs already temporarily blocked are rejected with reason
      ``already_blocked`` so callers can short-circuit cleanly.
    """
    raw = (ip or "").strip()
    if not raw:
        return False, "ip_required"

    ok, reason = _is_safe_to_block(raw)
    if not ok:
        # Remap reasons into stable machine-readable codes while keeping
        # the human-readable detail available via ``reason``. Callers
        # log both.
        return False, reason or "not_blockable"

    rules = rules or {}
    trusted_ips = {str(value) for value in rules.get("trusted_ips") or []}
    if raw in trusted_ips:
        return False, "ip_is_trusted"

    state = state or {}
    protected = {str(value) for value in state.get("protected_ips") or []}
    if raw in protected:
        return False, "ip_is_protected"

    active = {entry["ip"] for entry in active_temp_blocks(state=state)}
    if raw in active:
        return False, "already_blocked"

    return True, None


# ---------------------------------------------------------------------------
# State shape
# ---------------------------------------------------------------------------


def _empty_state() -> dict:
    now = _utc_now_iso()
    return {
        "version": 1,
        "mode": DEFAULT_MODE,
        "mode_changed_at": now,
        "protected_ips": [],
        "temp_blocks": [],
    }


def _coerce_temp_block(raw: Any) -> dict | None:
    if not isinstance(raw, dict):
        return None
    ip = str(raw.get("ip") or "").strip()
    if not ip:
        return None
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    blocked_at = str(raw.get("blocked_at") or "").strip()
    expires_at = str(raw.get("expires_at") or "").strip()
    if not blocked_at or not expires_at:
        return None
    if _parse_iso_z(blocked_at) is None or _parse_iso_z(expires_at) is None:
        return None
    reason = str(raw.get("reason") or "")[:MAX_REASON_LENGTH]
    source = str(raw.get("source") or "manual")
    if source not in {"auto", "manual"}:
        source = "manual"
    threshold = str(raw.get("threshold") or "")
    alert_id = raw.get("alert_id")
    if alert_id is not None:
        alert_id = str(alert_id)[:128]
    count = raw.get("count")
    try:
        count = int(count) if count is not None else None
    except (TypeError, ValueError):
        count = None
    entry: dict[str, Any] = {
        "ip": ip,
        "reason": reason,
        "source": source,
        "threshold": threshold,
        "blocked_at": blocked_at,
        "expires_at": expires_at,
    }
    if alert_id:
        entry["alert_id"] = alert_id
    if count is not None:
        entry["count"] = count
    return entry


def load_state(path: Path | None = None) -> dict:
    """Load mitigation state, falling back to a safe default.

    Corruption, missing files, and unreadable JSON all degrade silently
    to the default state with mode ``detection_only`` so a partially
    bad on-disk store can never escalate the mitigation posture.
    """
    file_path = path if path is not None else MITIGATION_FILE
    if not file_path.exists():
        return _empty_state()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        LOGGER.warning("Mitigation state file %s is invalid: %s", file_path, exc)
        return _empty_state()
    except OSError as exc:
        LOGGER.warning("Mitigation state file %s unreadable: %s", file_path, exc)
        return _empty_state()

    if not isinstance(data, dict):
        return _empty_state()

    mode = data.get("mode")
    if mode not in MITIGATION_MODES:
        mode = DEFAULT_MODE

    state = _empty_state()
    state["mode"] = mode
    if isinstance(data.get("mode_changed_at"), str):
        state["mode_changed_at"] = data["mode_changed_at"]
    state["protected_ips"] = sorted({
        str(value).strip()
        for value in _coerce_str_list(data.get("protected_ips"))
        if str(value).strip()
    })

    temp_blocks_raw = data.get("temp_blocks")
    cleaned: list[dict] = []
    if isinstance(temp_blocks_raw, list):
        for entry in temp_blocks_raw:
            coerced = _coerce_temp_block(entry)
            if coerced is not None:
                cleaned.append(coerced)
    state["temp_blocks"] = cleaned
    return state


def save_state(state: dict, path: Path | None = None) -> None:
    file_path = path if path is not None else MITIGATION_FILE
    payload = _empty_state()
    mode = state.get("mode")
    if mode in MITIGATION_MODES:
        payload["mode"] = mode
    if isinstance(state.get("mode_changed_at"), str):
        payload["mode_changed_at"] = state["mode_changed_at"]
    payload["protected_ips"] = sorted({
        str(value).strip()
        for value in _coerce_str_list(state.get("protected_ips"))
        if str(value).strip()
    })
    payload["temp_blocks"] = [
        coerced
        for coerced in (
            _coerce_temp_block(entry) for entry in state.get("temp_blocks") or []
        )
        if coerced is not None
    ]
    _atomic_write_json(file_path, payload)


# ---------------------------------------------------------------------------
# Mode management
# ---------------------------------------------------------------------------


def get_mode(path: Path | None = None) -> str:
    return load_state(path).get("mode", DEFAULT_MODE)


def set_mode(
    mode: str,
    *,
    path: Path | None = None,
    audit_path: Path | None = None,
    actor: str = "user",
    note: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Switch the mitigation mode and write an audit entry.

    Raises :class:`ValueError` if ``mode`` is not one of
    :data:`MITIGATION_MODES` so a typo cannot accidentally enable
    blocking.
    """
    if mode not in MITIGATION_MODES:
        raise ValueError(f"unknown mitigation mode: {mode!r}")
    state = load_state(path)
    previous = state.get("mode", DEFAULT_MODE)
    timestamp = _utc_now_iso(now)
    state["mode"] = mode
    state["mode_changed_at"] = timestamp
    save_state(state, path)
    record_audit(
        {
            "event": EVENT_MODE_CHANGED,
            "previous_mode": previous,
            "mode": mode,
            "actor": actor,
            "note": (note or "")[:MAX_REASON_LENGTH] if note else None,
            "timestamp": timestamp,
        },
        path=audit_path,
    )
    return state


# ---------------------------------------------------------------------------
# Temporary blocks
# ---------------------------------------------------------------------------


def active_temp_blocks(
    *,
    state: dict | None = None,
    path: Path | None = None,
    now: datetime | None = None,
) -> list[dict]:
    """Return temp-block entries whose ``expires_at`` is still in the future.

    Pass ``state`` to avoid a re-read when the caller already has it.
    Otherwise the file is loaded; corrupt data degrades to ``[]``.
    """
    state = state if state is not None else load_state(path)
    cutoff = (now or _utc_now()).timestamp()
    active: list[dict] = []
    for entry in state.get("temp_blocks") or []:
        expires_at = _parse_iso_z(entry.get("expires_at", ""))
        if expires_at is None:
            continue
        if expires_at.timestamp() <= cutoff:
            continue
        active.append(dict(entry))
    return sorted(active, key=lambda e: e.get("blocked_at", ""), reverse=True)


def current_temp_blocked_ips(
    *,
    path: Path | None = None,
    now: datetime | None = None,
) -> set[str]:
    """Return the IPs currently under a non-expired temporary block."""
    return {entry["ip"] for entry in active_temp_blocks(path=path, now=now)}


def expire_temp_blocks(
    *,
    path: Path | None = None,
    audit_path: Path | None = None,
    now: datetime | None = None,
) -> list[dict]:
    """Remove expired temp blocks from disk and audit each removal.

    Returns the list of expired entries (in their original on-disk
    shape). Safe to call on every refresh.
    """
    state = load_state(path)
    cutoff = (now or _utc_now()).timestamp()
    expired: list[dict] = []
    survivors: list[dict] = []
    for entry in state.get("temp_blocks") or []:
        expires_at = _parse_iso_z(entry.get("expires_at", ""))
        if expires_at is None or expires_at.timestamp() <= cutoff:
            expired.append(entry)
        else:
            survivors.append(entry)
    if not expired:
        return []
    state["temp_blocks"] = survivors
    save_state(state, path)
    timestamp = _utc_now_iso(now)
    for entry in expired:
        record_audit(
            {
                "event": EVENT_TEMP_BLOCK_EXPIRED,
                "ip": entry.get("ip"),
                "expired_at": timestamp,
                "originally_blocked_at": entry.get("blocked_at"),
                "expires_at": entry.get("expires_at"),
                "reason": entry.get("reason"),
                "timestamp": timestamp,
            },
            path=audit_path,
        )
    return expired


def _recent_auto_block_count(
    state: dict,
    *,
    now: datetime | None = None,
) -> int:
    cutoff = (now or _utc_now()).timestamp() - AUTO_BLOCK_RATE_WINDOW_SECONDS
    count = 0
    for entry in state.get("temp_blocks") or []:
        if entry.get("source") != "auto":
            continue
        ts = _parse_iso_z(entry.get("blocked_at", ""))
        if ts is None:
            continue
        if ts.timestamp() >= cutoff:
            count += 1
    return count


def add_temporary_block(
    ip: str,
    *,
    reason: str = "",
    duration_seconds: int | None = None,
    source: str = "manual",
    threshold: str = "",
    alert_id: str | None = None,
    count: int | None = None,
    rules: dict | None = None,
    path: Path | None = None,
    audit_path: Path | None = None,
    now: datetime | None = None,
) -> tuple[bool, dict]:
    """Add a temporary block.

    ``source`` is ``"manual"`` (added via the API by a human) or
    ``"auto"`` (added by :func:`apply_auto_blocks`). Returns
    ``(True, entry)`` on success or ``(False, {"reason": code})`` on
    rejection. Every outcome — including rejections — writes an audit
    entry so the operator has a single timeline to review.
    """
    state = load_state(path)
    if source not in {"auto", "manual"}:
        source = "manual"

    timestamp_dt = now or _utc_now()
    timestamp = _utc_now_iso(timestamp_dt)

    ok, fail_reason = evaluate_block_candidate(
        ip,
        rules=rules,
        state=state,
    )
    if not ok:
        record_audit(
            {
                "event": EVENT_TEMP_BLOCK_REJECTED,
                "ip": (ip or "").strip(),
                "source": source,
                "rejection_reason": fail_reason,
                "alert_id": alert_id,
                "timestamp": timestamp,
            },
            path=audit_path,
        )
        return False, {"reason": fail_reason or "not_blockable"}

    if source == "auto":
        recent = _recent_auto_block_count(state, now=timestamp_dt)
        if recent >= AUTO_BLOCK_RATE_LIMIT:
            record_audit(
                {
                    "event": EVENT_TEMP_BLOCK_REJECTED,
                    "ip": (ip or "").strip(),
                    "source": source,
                    "rejection_reason": "rate_limited",
                    "alert_id": alert_id,
                    "timestamp": timestamp,
                },
                path=audit_path,
            )
            return False, {"reason": "rate_limited"}

    duration = normalize_duration(duration_seconds)
    expires_dt = datetime.fromtimestamp(
        timestamp_dt.timestamp() + duration, tz=timezone.utc
    )
    entry: dict[str, Any] = {
        "ip": (ip or "").strip(),
        "reason": (reason or "")[:MAX_REASON_LENGTH],
        "source": source,
        "threshold": (threshold or "")[:64],
        "blocked_at": timestamp,
        "expires_at": _utc_now_iso(expires_dt),
    }
    if alert_id:
        entry["alert_id"] = str(alert_id)[:128]
    if count is not None:
        try:
            entry["count"] = int(count)
        except (TypeError, ValueError):
            pass

    state.setdefault("temp_blocks", []).append(entry)
    save_state(state, path)
    record_audit(
        {
            "event": EVENT_TEMP_BLOCK_ADDED,
            "ip": entry["ip"],
            "source": source,
            "reason": entry["reason"],
            "threshold": entry["threshold"],
            "blocked_at": entry["blocked_at"],
            "expires_at": entry["expires_at"],
            "duration_seconds": duration,
            "alert_id": entry.get("alert_id"),
            "count": entry.get("count"),
            "timestamp": timestamp,
        },
        path=audit_path,
    )
    return True, dict(entry)


def remove_temporary_block(
    ip: str,
    *,
    actor: str = "user",
    path: Path | None = None,
    audit_path: Path | None = None,
    now: datetime | None = None,
) -> tuple[bool, dict]:
    """Remove a temporary block. Returns ``(True, entry)`` on removal."""
    raw = (ip or "").strip()
    if not raw:
        return False, {"reason": "ip_required"}
    state = load_state(path)
    blocks = state.get("temp_blocks") or []
    survivor: list[dict] = []
    removed: dict | None = None
    for entry in blocks:
        if removed is None and entry.get("ip") == raw:
            removed = entry
            continue
        survivor.append(entry)
    if removed is None:
        return False, {"reason": "not_found"}
    state["temp_blocks"] = survivor
    save_state(state, path)
    timestamp = _utc_now_iso(now)
    record_audit(
        {
            "event": EVENT_TEMP_BLOCK_REMOVED,
            "ip": raw,
            "actor": actor,
            "originally_blocked_at": removed.get("blocked_at"),
            "expires_at": removed.get("expires_at"),
            "reason": removed.get("reason"),
            "timestamp": timestamp,
        },
        path=audit_path,
    )
    return True, dict(removed)


def augment_rules_with_temp_blocks(
    rules: dict | None,
    *,
    path: Path | None = None,
    now: datetime | None = None,
) -> dict:
    """Return a copy of ``rules`` with temp-blocks merged into ``blocked_ips``.

    Used by :mod:`silentguard.monitor` so the existing classification
    path naturally treats current temporary blocks as ``Blocked``
    without rewriting the rules file.
    """
    base = dict(rules or {})
    existing = {str(value) for value in base.get("blocked_ips") or []}
    try:
        temp = current_temp_blocked_ips(path=path, now=now)
    except Exception:
        LOGGER.debug("Skipping temp-block augmentation due to read error",
                     exc_info=True)
        temp = set()
    if not temp:
        # Preserve the original list ordering so callers comparing
        # rules round-trips don't see surprising changes.
        return base
    base["blocked_ips"] = sorted(existing | temp)
    return base


# ---------------------------------------------------------------------------
# Auto-block evaluation
# ---------------------------------------------------------------------------


def auto_block_candidates(
    alerts: Iterable,
) -> list[dict[str, Any]]:
    """Pick the alerts that are eligible for an automatic temporary block.

    Only ``possible_flood`` alerts at ``high`` or ``critical`` severity
    that name a single ``source_ip`` qualify. Returns dicts with the
    fields the audit log wants so the caller can pass them through.
    """
    candidates: list[dict[str, Any]] = []
    for alert in alerts:
        # Accept either an ``Alert`` dataclass or a plain dict for
        # consumer flexibility (e.g. tests, future Nova relays).
        if hasattr(alert, "to_dict"):
            payload = alert.to_dict()
        elif isinstance(alert, dict):
            payload = alert
        else:
            continue
        if payload.get("type") not in AUTO_BLOCK_ELIGIBLE_TYPES:
            continue
        if payload.get("severity") not in AUTO_BLOCK_ELIGIBLE_SEVERITIES:
            continue
        ip = (payload.get("source_ip") or "").strip()
        if not ip:
            continue
        candidates.append(
            {
                "ip": ip,
                "alert_id": payload.get("id"),
                "severity": payload.get("severity"),
                "count": payload.get("count"),
                "threshold": "REMOTE_IP_FLOOD_HIGH",
            }
        )
    return candidates


def apply_auto_blocks(
    alerts: Iterable,
    *,
    rules: dict | None = None,
    duration_seconds: int | None = None,
    path: Path | None = None,
    audit_path: Path | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Apply auto-blocks for eligible alerts when the mode allows it.

    Returns the entries that were successfully added. Refusals are
    audited but not raised; callers continue with the next candidate.
    The function is a no-op (returns ``[]``) unless the current mode is
    :data:`MODE_TEMPORARY_AUTO_BLOCK`. This is the single hook that
    enforces "default = detection_only".
    """
    if get_mode(path=path) != MODE_TEMPORARY_AUTO_BLOCK:
        return []
    added: list[dict[str, Any]] = []
    for candidate in auto_block_candidates(alerts):
        ok, payload = add_temporary_block(
            candidate["ip"],
            reason=(
                "Auto-block: high-severity possible_flood alert "
                f"({candidate.get('severity')})"
            ),
            duration_seconds=duration_seconds,
            source="auto",
            threshold=candidate["threshold"],
            alert_id=candidate.get("alert_id"),
            count=candidate.get("count"),
            rules=rules,
            path=path,
            audit_path=audit_path,
            now=now,
        )
        if ok:
            added.append(payload)
    return added


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def _load_audit(path: Path | None = None) -> list[dict]:
    file_path = path if path is not None else AUDIT_FILE
    if not file_path.exists():
        return []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        LOGGER.warning("Audit log %s invalid, ignoring: %s", file_path, exc)
        return []
    except OSError as exc:
        LOGGER.warning("Audit log %s unreadable: %s", file_path, exc)
        return []
    if not isinstance(data, list):
        return []
    cleaned: list[dict] = []
    for entry in data:
        if isinstance(entry, dict):
            cleaned.append(entry)
    return cleaned


def record_audit(entry: dict, *, path: Path | None = None) -> None:
    """Append ``entry`` to the audit log, bounding the file size."""
    file_path = path if path is not None else AUDIT_FILE
    payload = dict(entry)
    payload.setdefault("timestamp", _utc_now_iso())
    history = _load_audit(file_path)
    history.append(payload)
    if len(history) > MAX_AUDIT_ENTRIES:
        history = history[-MAX_AUDIT_ENTRIES:]
    try:
        _atomic_write_json(file_path, history)
    except OSError as exc:
        LOGGER.warning("Unable to write audit log %s: %s", file_path, exc)


def read_audit(
    *,
    path: Path | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Return audit entries newest-first.

    ``limit`` clamps the response size so callers — especially the API
    surface — never accidentally serialize the entire log.
    """
    history = list(_load_audit(path))
    history.reverse()
    if limit is None:
        return history
    if limit <= 0:
        return []
    return history[:limit]


# ---------------------------------------------------------------------------
# Status / view helpers
# ---------------------------------------------------------------------------


def status_payload(
    *,
    path: Path | None = None,
    audit_path: Path | None = None,
    audit_limit: int = 10,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Compact, JSON-friendly view of the mitigation surface.

    Used by :mod:`silentguard.api.handlers` so Nova and the TUI can
    render a single status block: current mode, the explanation copy,
    the active temp blocks, and the most recent audit events.
    """
    expire_temp_blocks(path=path, audit_path=audit_path, now=now)
    state = load_state(path)
    active = active_temp_blocks(state=state, now=now)
    return {
        "mode": state.get("mode", DEFAULT_MODE),
        "mode_changed_at": state.get("mode_changed_at"),
        "default_mode": DEFAULT_MODE,
        "available_modes": list(MITIGATION_MODES),
        "prompt": MITIGATION_PROMPT,
        "disclaimer": MITIGATION_DISCLAIMER,
        "auto_block_threshold": "REMOTE_IP_FLOOD_HIGH",
        "auto_block_severities": sorted(AUTO_BLOCK_ELIGIBLE_SEVERITIES),
        "auto_block_rate_limit": {
            "max_blocks": AUTO_BLOCK_RATE_LIMIT,
            "window_seconds": AUTO_BLOCK_RATE_WINDOW_SECONDS,
        },
        "temp_block_duration_seconds": {
            "default": DEFAULT_TEMP_BLOCK_DURATION,
            "min": MIN_TEMP_BLOCK_DURATION,
            "max": MAX_TEMP_BLOCK_DURATION,
        },
        "protected_ips": list(state.get("protected_ips") or []),
        "active_temp_blocks": active,
        "recent_audit": read_audit(path=audit_path, limit=audit_limit),
    }
