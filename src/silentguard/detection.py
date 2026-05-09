"""Local flood / anomaly detection for SilentGuard.

This module turns a snapshot of outgoing connections (plus the small
local unknown-destinations cache) into read-only alert objects. It is
deliberately small and deterministic so the behaviour is easy to audit:

* Pure-Python, no external dependencies.
* Stateless thresholds. The same input always produces the same alerts.
* No firewall changes, no automatic blocking, no privileged commands,
  no autonomous defensive actions.
* No network calls. No DNS resolution. No packet capture.

Honest limitations
==================

SilentGuard runs on the local machine. It can describe what the local
network stack already exposes via ``psutil``. It **cannot**:

* absorb or stop an upstream DDoS that saturates the internet uplink
  before traffic reaches the local NIC,
* replace ISP- or edge-level DDoS protection,
* guarantee detection of every flood pattern.

This module is for **detection and visibility only**. Future mitigation
(if any) must require explicit human confirmation or upstream
protection — never automatic actions taken by this module.

Alert object shape
==================

Each alert is a frozen dataclass that serializes via ``to_dict()`` into
a JSON-friendly mapping. ``None`` fields are omitted so the payload
stays small and predictable. See :class:`Alert` for the schema.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from silentguard.connection_state import (
    LOCAL,
    UNKNOWN,
    classification_from_label,
    load_unknown_destinations,
)

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITIES: tuple[str, ...] = (
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)

_SEVERITY_RANK: dict[str, int] = {value: index for index, value in enumerate(SEVERITIES)}


# ---------------------------------------------------------------------------
# Alert types
# ---------------------------------------------------------------------------

ALERT_TYPE_POSSIBLE_FLOOD = "possible_flood"
ALERT_TYPE_CONNECTION_SPIKE = "connection_spike"
ALERT_TYPE_UNKNOWN_BURST = "unknown_burst"
ALERT_TYPE_CONNECTION_CHURN = "connection_churn"

ALERT_TYPES: tuple[str, ...] = (
    ALERT_TYPE_POSSIBLE_FLOOD,
    ALERT_TYPE_CONNECTION_SPIKE,
    ALERT_TYPE_UNKNOWN_BURST,
    ALERT_TYPE_CONNECTION_CHURN,
)


# ---------------------------------------------------------------------------
# Default thresholds (conservative)
#
# These are intentionally on the cautious side so a normally-busy desktop
# does not generate alerts. They are constants for now; a future PR may
# expose them via a settings file. Keeping them here keeps detection
# logic deterministic and easy to audit.
# ---------------------------------------------------------------------------

# One remote IP appearing in many concurrent outgoing connections.
REMOTE_IP_FLOOD_MEDIUM = 60
REMOTE_IP_FLOOD_HIGH = 200
REMOTE_IP_FLOOD_CRITICAL = 500

# Total active outgoing connections.
TOTAL_CONNECTION_MEDIUM = 500
TOTAL_CONNECTION_HIGH = 1000
TOTAL_CONNECTION_CRITICAL = 2000

# Distinct unknown remote IPs in the current snapshot.
UNKNOWN_BURST_MEDIUM = 30
UNKNOWN_BURST_HIGH = 60
UNKNOWN_BURST_CRITICAL = 100

# Connection churn (cache-based): distinct unknown destinations whose
# most recent observation falls inside CHURN_WINDOW_SECONDS.
CHURN_WINDOW_SECONDS = 300
CHURN_MEDIUM = 50
CHURN_HIGH = 100
CHURN_CRITICAL = 200


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Alert:
    """Read-only alert produced by the detection module.

    Frozen on purpose: alerts are immutable values that downstream code
    can trust. To produce a JSON-safe view, call :meth:`to_dict`, which
    omits fields whose value is ``None`` so payloads remain compact.

    Field semantics
    ---------------

    * ``id`` — stable identifier for the anomaly (same input → same id).
    * ``severity`` — one of :data:`SEVERITIES`.
    * ``type`` — one of :data:`ALERT_TYPES`.
    * ``title`` / ``message`` — short human-readable summaries. Honest
      about what SilentGuard does and does not do.
    * ``created_at`` — UTC ISO-8601 timestamp of alert creation.
    * ``status`` — always ``"active"`` in this read-only PoC. Reserved
      for future lifecycle states (e.g. ``"resolved"``) once a
      human-approved mitigation flow lands.
    * ``source_ip`` — populated when the anomaly is keyed by a single
      remote IP. Omitted otherwise.
    * ``count`` — anomaly magnitude (e.g. number of connections).
    * ``window_seconds`` — observation window in seconds. ``None`` for
      instantaneous (current-snapshot) detectors.
    """

    id: str
    severity: str
    type: str
    title: str
    message: str
    created_at: str
    status: str = "active"
    source_ip: str | None = None
    count: int | None = None
    window_seconds: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _classification_of(conn: Any) -> str:
    canonical = (getattr(conn, "classification", "") or "").strip().lower()
    if canonical:
        return canonical
    return classification_from_label(getattr(conn, "trust", None))


def _severity_for(value: int, medium: int, high: int, critical: int) -> str | None:
    """Return the deterministic severity for ``value`` or ``None``.

    Ordering is strict (``critical > high > medium``) and the same value
    always maps to the same severity, so two callers with the same data
    will agree on the outcome.
    """
    if value >= critical:
        return SEVERITY_CRITICAL
    if value >= high:
        return SEVERITY_HIGH
    if value >= medium:
        return SEVERITY_MEDIUM
    return None


def _parse_iso_z(value: str) -> float | None:
    """Best-effort parse of ``YYYY-MM-DDTHH:MM:SSZ`` to a UTC timestamp."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc).timestamp()


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def detect_remote_ip_floods(
    connections: Iterable, *, now: str | None = None
) -> list[Alert]:
    """Flag remote IPs that appear in many concurrent outgoing connections."""
    timestamp = now or _utc_now_iso()
    counts: dict[str, int] = {}
    for conn in connections:
        if _classification_of(conn) == LOCAL:
            continue
        ip = (getattr(conn, "remote_ip", "") or "").strip()
        if not ip:
            continue
        counts[ip] = counts.get(ip, 0) + 1

    alerts: list[Alert] = []
    for ip, count in counts.items():
        severity = _severity_for(
            count,
            REMOTE_IP_FLOOD_MEDIUM,
            REMOTE_IP_FLOOD_HIGH,
            REMOTE_IP_FLOOD_CRITICAL,
        )
        if severity is None:
            continue
        alerts.append(
            Alert(
                id=f"flood-remote-ip-{ip}",
                severity=severity,
                type=ALERT_TYPE_POSSIBLE_FLOOD,
                title="Repeated connections from one remote IP",
                message=(
                    "One remote IP appears in many concurrent outgoing "
                    "connections, which can indicate a flood pattern. "
                    "SilentGuard detects only and does not block "
                    "automatically."
                ),
                source_ip=ip,
                count=count,
                created_at=timestamp,
            )
        )
    return alerts


def detect_connection_spike(
    connections: Iterable, *, now: str | None = None
) -> list[Alert]:
    """Flag a sudden total spike in active outgoing connections."""
    total = sum(1 for _ in connections)
    severity = _severity_for(
        total,
        TOTAL_CONNECTION_MEDIUM,
        TOTAL_CONNECTION_HIGH,
        TOTAL_CONNECTION_CRITICAL,
    )
    if severity is None:
        return []
    return [
        Alert(
            id="connection-spike-current",
            severity=severity,
            type=ALERT_TYPE_CONNECTION_SPIKE,
            title="Sudden spike in active connections",
            message=(
                "The number of active outgoing connections is unusually "
                "high. Review the connection list and process activity. "
                "SilentGuard cannot absorb upstream DDoS attacks; this "
                "alert is for local visibility only."
            ),
            count=total,
            created_at=now or _utc_now_iso(),
        )
    ]


def detect_unknown_burst(
    connections: Iterable, *, now: str | None = None
) -> list[Alert]:
    """Flag many distinct unknown remote IPs in the current snapshot."""
    unknown_ips: set[str] = set()
    for conn in connections:
        if _classification_of(conn) != UNKNOWN:
            continue
        ip = (getattr(conn, "remote_ip", "") or "").strip()
        if ip:
            unknown_ips.add(ip)
    distinct = len(unknown_ips)
    severity = _severity_for(
        distinct,
        UNKNOWN_BURST_MEDIUM,
        UNKNOWN_BURST_HIGH,
        UNKNOWN_BURST_CRITICAL,
    )
    if severity is None:
        return []
    return [
        Alert(
            id="unknown-burst-current",
            severity=severity,
            type=ALERT_TYPE_UNKNOWN_BURST,
            title="High number of unknown remote IPs",
            message=(
                "Many distinct unknown remote IPs are active in the "
                "current snapshot. Possible scanning, fan-out flood, or "
                "newly-installed software. Review unknown destinations."
            ),
            count=distinct,
            created_at=now or _utc_now_iso(),
        )
    ]


def detect_connection_churn(
    *,
    cache_path: Path | None = None,
    window_seconds: int = CHURN_WINDOW_SECONDS,
    now: str | None = None,
) -> list[Alert]:
    """Flag unusually high churn of unknown destinations in a recent window.

    Reads the local unknown-destinations cache (populated by the regular
    monitor refresh path) and counts entries whose ``last_seen`` falls
    within ``window_seconds`` of the current time. The cache is bounded
    so this never grows unbounded.
    """
    try:
        entries = load_unknown_destinations(path=cache_path)
    except Exception:
        return []

    window = max(0, int(window_seconds))
    cutoff = datetime.now(timezone.utc).timestamp() - window
    recent_ips: set[str] = set()
    for entry in entries:
        if entry.get("classification") != UNKNOWN:
            continue
        ip = str(entry.get("ip") or "").strip()
        if not ip:
            continue
        last_seen_ts = _parse_iso_z(entry.get("last_seen", ""))
        if last_seen_ts is None or last_seen_ts < cutoff:
            continue
        recent_ips.add(ip)

    distinct = len(recent_ips)
    severity = _severity_for(distinct, CHURN_MEDIUM, CHURN_HIGH, CHURN_CRITICAL)
    if severity is None:
        return []
    return [
        Alert(
            id="connection-churn-recent",
            severity=severity,
            type=ALERT_TYPE_CONNECTION_CHURN,
            title="Unusually high connection churn",
            message=(
                "A large number of distinct unknown destinations have "
                "been observed in the recent window. Possible scanning "
                "or fan-out activity. Detection only — no automatic "
                "mitigation is performed."
            ),
            count=distinct,
            window_seconds=window,
            created_at=now or _utc_now_iso(),
        )
    ]


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def evaluate(
    connections: Iterable,
    *,
    cache_path: Path | None = None,
    now: str | None = None,
) -> list[Alert]:
    """Run all detectors and return the merged alert list.

    Results are sorted by descending severity, then by id, so the order
    is deterministic and stable across calls with the same input.
    """
    timestamp = now or _utc_now_iso()
    snapshot = list(connections)

    alerts: list[Alert] = []
    alerts.extend(detect_remote_ip_floods(snapshot, now=timestamp))
    alerts.extend(detect_connection_spike(snapshot, now=timestamp))
    alerts.extend(detect_unknown_burst(snapshot, now=timestamp))
    alerts.extend(detect_connection_churn(cache_path=cache_path, now=timestamp))

    alerts.sort(key=lambda alert: (-_SEVERITY_RANK[alert.severity], alert.id))
    return alerts


def summarize(alerts: Iterable[Alert]) -> dict[str, Any]:
    """Return a compact summary of the supplied alerts.

    The shape is fixed up-front so consumers can rely on it even when
    no alerts are active. ``highest_severity`` is the most severe level
    present, or ``None`` when the list is empty.
    """
    alert_list = list(alerts)
    by_severity: dict[str, int] = {severity: 0 for severity in SEVERITIES}
    by_type: dict[str, int] = {}
    for alert in alert_list:
        if alert.severity in by_severity:
            by_severity[alert.severity] += 1
        by_type[alert.type] = by_type.get(alert.type, 0) + 1

    highest: str | None = None
    for severity in (
        SEVERITY_CRITICAL,
        SEVERITY_HIGH,
        SEVERITY_MEDIUM,
        SEVERITY_LOW,
    ):
        if by_severity.get(severity, 0) > 0:
            highest = severity
            break

    return {
        "total": len(alert_list),
        "by_severity": by_severity,
        "by_type": by_type,
        "highest_severity": highest,
    }
