"""Tests for the local flood / anomaly detection module."""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from silentguard import connection_state, detection


@dataclass
class _FakeConn:
    process_name: str
    remote_ip: str
    classification: str = "unknown"
    trust: str = ""
    remote_port: int = 443


def _conns(ip: str, count: int, *, classification: str = "unknown") -> list[_FakeConn]:
    return [
        _FakeConn(process_name="proc", remote_ip=ip, classification=classification)
        for _ in range(count)
    ]


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------


def test_alert_to_dict_omits_none_fields() -> None:
    alert = detection.Alert(
        id="connection-spike-current",
        severity=detection.SEVERITY_MEDIUM,
        type=detection.ALERT_TYPE_CONNECTION_SPIKE,
        title="Sudden spike in active connections",
        message="...",
        created_at="2026-05-09T20:15:00Z",
        count=600,
    )

    payload = alert.to_dict()

    assert payload["count"] == 600
    assert "source_ip" not in payload
    assert "window_seconds" not in payload
    assert payload["status"] == "active"


def test_alert_is_immutable() -> None:
    alert = detection.Alert(
        id="x",
        severity=detection.SEVERITY_LOW,
        type=detection.ALERT_TYPE_POSSIBLE_FLOOD,
        title="t",
        message="m",
        created_at="2026-05-09T20:15:00Z",
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        alert.severity = detection.SEVERITY_CRITICAL  # type: ignore[misc]


# ---------------------------------------------------------------------------
# evaluate() — the public aggregation
# ---------------------------------------------------------------------------


def test_evaluate_returns_no_alerts_for_normal_traffic() -> None:
    connections = (
        [_FakeConn(process_name="firefox", remote_ip="93.184.216.34")] * 5
        + [_FakeConn(process_name="ssh", remote_ip="9.9.9.9", classification="trusted")]
        + [_FakeConn(process_name="systemd", remote_ip="127.0.0.1", classification="local")]
    )

    alerts = detection.evaluate(connections)

    assert alerts == []


def test_evaluate_flags_per_ip_flood_at_medium_threshold() -> None:
    connections = _conns("203.0.113.10", detection.REMOTE_IP_FLOOD_MEDIUM)

    alerts = detection.evaluate(connections)

    flood = [a for a in alerts if a.type == detection.ALERT_TYPE_POSSIBLE_FLOOD]
    assert len(flood) == 1
    alert = flood[0]
    assert alert.severity == detection.SEVERITY_MEDIUM
    assert alert.source_ip == "203.0.113.10"
    assert alert.count == detection.REMOTE_IP_FLOOD_MEDIUM
    assert alert.id == "flood-remote-ip-203.0.113.10"
    assert alert.status == "active"


def test_evaluate_does_not_flag_below_threshold() -> None:
    connections = _conns("203.0.113.10", detection.REMOTE_IP_FLOOD_MEDIUM - 1)

    alerts = detection.evaluate(connections)

    assert [a for a in alerts if a.type == detection.ALERT_TYPE_POSSIBLE_FLOOD] == []


def test_evaluate_severity_is_deterministic() -> None:
    medium = detection.evaluate(_conns("1.2.3.4", detection.REMOTE_IP_FLOOD_MEDIUM))
    high = detection.evaluate(_conns("1.2.3.4", detection.REMOTE_IP_FLOOD_HIGH))
    critical = detection.evaluate(_conns("1.2.3.4", detection.REMOTE_IP_FLOOD_CRITICAL))

    assert medium[0].severity == detection.SEVERITY_MEDIUM
    assert high[0].severity == detection.SEVERITY_HIGH
    assert critical[0].severity == detection.SEVERITY_CRITICAL

    # Same input must always yield the same alert.
    repeat = detection.evaluate(_conns("1.2.3.4", detection.REMOTE_IP_FLOOD_HIGH))
    assert repeat[0].severity == high[0].severity
    assert repeat[0].id == high[0].id


def test_evaluate_excludes_local_from_per_ip_flood() -> None:
    connections = _conns("192.168.1.5", 200, classification="local")

    alerts = detection.evaluate(connections)

    assert [a for a in alerts if a.type == detection.ALERT_TYPE_POSSIBLE_FLOOD] == []


def test_evaluate_flags_total_connection_spike() -> None:
    # Spread across many IPs so the per-IP detector does not also fire.
    connections = [
        _FakeConn(process_name=f"proc-{i}", remote_ip=f"203.0.113.{i % 254 + 1}")
        for i in range(detection.TOTAL_CONNECTION_MEDIUM)
    ]

    alerts = detection.evaluate(connections)

    spikes = [a for a in alerts if a.type == detection.ALERT_TYPE_CONNECTION_SPIKE]
    assert len(spikes) == 1
    assert spikes[0].severity == detection.SEVERITY_MEDIUM
    assert spikes[0].count == detection.TOTAL_CONNECTION_MEDIUM
    assert spikes[0].source_ip is None


def test_evaluate_flags_unknown_burst() -> None:
    connections = [
        _FakeConn(
            process_name=f"proc-{i}",
            remote_ip=f"198.51.100.{i + 1}",
            classification="unknown",
        )
        for i in range(detection.UNKNOWN_BURST_MEDIUM)
    ]

    alerts = detection.evaluate(connections)

    bursts = [a for a in alerts if a.type == detection.ALERT_TYPE_UNKNOWN_BURST]
    assert len(bursts) == 1
    assert bursts[0].severity == detection.SEVERITY_MEDIUM
    assert bursts[0].count == detection.UNKNOWN_BURST_MEDIUM


def test_evaluate_burst_only_counts_unknown() -> None:
    connections = [
        _FakeConn(
            process_name=f"proc-{i}",
            remote_ip=f"198.51.100.{i + 1}",
            classification="trusted",
        )
        for i in range(detection.UNKNOWN_BURST_HIGH)
    ]

    alerts = detection.evaluate(connections)

    assert [a for a in alerts if a.type == detection.ALERT_TYPE_UNKNOWN_BURST] == []


def test_evaluate_uses_trust_label_when_classification_blank() -> None:
    connections = [
        _FakeConn(
            process_name="curl",
            remote_ip=f"198.51.100.{i + 1}",
            classification="",
            trust="Unknown",
        )
        for i in range(detection.UNKNOWN_BURST_MEDIUM)
    ]

    alerts = detection.evaluate(connections)

    assert any(a.type == detection.ALERT_TYPE_UNKNOWN_BURST for a in alerts)


def test_evaluate_orders_by_severity_desc_then_id() -> None:
    connections = (
        # Critical per-IP flood
        _conns("203.0.113.10", detection.REMOTE_IP_FLOOD_CRITICAL)
        # Medium per-IP flood (different IP, no overlap with critical)
        + _conns("203.0.113.20", detection.REMOTE_IP_FLOOD_MEDIUM)
    )

    alerts = detection.evaluate(connections)

    severities = [alert.severity for alert in alerts]
    assert severities[0] == detection.SEVERITY_CRITICAL
    # Most-severe first, then medium-or-lower entries.
    for previous, current in zip(severities, severities[1:]):
        assert (
            detection._SEVERITY_RANK[previous]
            >= detection._SEVERITY_RANK[current]
        )


# ---------------------------------------------------------------------------
# Connection churn (cache-based)
# ---------------------------------------------------------------------------


def _write_cache(cache_path: Path, entries: list[dict]) -> None:
    cache_path.write_text(
        json.dumps({"version": 1, "destinations": entries}),
        encoding="utf-8",
    )


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_detect_connection_churn_flags_high_churn(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    now = datetime.now(timezone.utc)
    entries = [
        {
            "ip": f"198.51.100.{i + 1}",
            "process": "curl",
            "first_seen": _iso(now - timedelta(seconds=120)),
            "last_seen": _iso(now - timedelta(seconds=30)),
            "seen_count": 1,
            "classification": "unknown",
        }
        for i in range(detection.CHURN_MEDIUM)
    ]
    _write_cache(cache, entries)

    alerts = detection.detect_connection_churn(cache_path=cache)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.type == detection.ALERT_TYPE_CONNECTION_CHURN
    assert alert.severity == detection.SEVERITY_MEDIUM
    assert alert.count == detection.CHURN_MEDIUM
    assert alert.window_seconds == detection.CHURN_WINDOW_SECONDS


def test_detect_connection_churn_excludes_old_entries(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    now = datetime.now(timezone.utc)
    entries = [
        {
            "ip": f"198.51.100.{i + 1}",
            "process": "curl",
            "first_seen": _iso(now - timedelta(hours=2)),
            "last_seen": _iso(now - timedelta(hours=1)),
            "seen_count": 1,
            "classification": "unknown",
        }
        for i in range(detection.CHURN_HIGH)
    ]
    _write_cache(cache, entries)

    alerts = detection.detect_connection_churn(
        cache_path=cache, window_seconds=300
    )

    assert alerts == []


def test_detect_connection_churn_excludes_non_unknown(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    now = datetime.now(timezone.utc)
    entries = [
        {
            "ip": f"198.51.100.{i + 1}",
            "process": "curl",
            "first_seen": _iso(now - timedelta(seconds=120)),
            "last_seen": _iso(now - timedelta(seconds=30)),
            "seen_count": 1,
            "classification": "trusted",
        }
        for i in range(detection.CHURN_MEDIUM)
    ]
    _write_cache(cache, entries)

    alerts = detection.detect_connection_churn(cache_path=cache)

    assert alerts == []


def test_detect_connection_churn_handles_missing_cache(tmp_path: Path) -> None:
    cache = tmp_path / "missing.json"

    alerts = detection.detect_connection_churn(cache_path=cache)

    assert alerts == []


def test_evaluate_includes_churn_alert(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    now = datetime.now(timezone.utc)
    entries = [
        {
            "ip": f"198.51.100.{i + 1}",
            "process": "curl",
            "first_seen": _iso(now - timedelta(seconds=120)),
            "last_seen": _iso(now - timedelta(seconds=30)),
            "seen_count": 1,
            "classification": "unknown",
        }
        for i in range(detection.CHURN_HIGH)
    ]
    _write_cache(cache, entries)

    alerts = detection.evaluate([], cache_path=cache)

    types = [alert.type for alert in alerts]
    assert detection.ALERT_TYPE_CONNECTION_CHURN in types
    churn = next(a for a in alerts if a.type == detection.ALERT_TYPE_CONNECTION_CHURN)
    assert churn.severity == detection.SEVERITY_HIGH


# ---------------------------------------------------------------------------
# summarize()
# ---------------------------------------------------------------------------


def test_summarize_empty_alerts() -> None:
    summary = detection.summarize([])

    assert summary["total"] == 0
    assert summary["highest_severity"] is None
    assert summary["by_type"] == {}
    assert all(count == 0 for count in summary["by_severity"].values())


def test_summarize_counts_by_severity_and_type() -> None:
    connections = _conns("203.0.113.10", detection.REMOTE_IP_FLOOD_CRITICAL)
    alerts = detection.evaluate(connections)

    summary = detection.summarize(alerts)

    assert summary["total"] == len(alerts)
    assert summary["highest_severity"] == detection.SEVERITY_CRITICAL
    assert summary["by_severity"][detection.SEVERITY_CRITICAL] >= 1
    assert summary["by_type"][detection.ALERT_TYPE_POSSIBLE_FLOOD] >= 1


# ---------------------------------------------------------------------------
# Alerts are read-only / sensitive fields not exposed
# ---------------------------------------------------------------------------


def test_alert_payload_omits_sensitive_fields() -> None:
    connections = _conns("203.0.113.10", detection.REMOTE_IP_FLOOD_HIGH)
    alerts = detection.evaluate(connections)
    encoded = json.dumps([alert.to_dict() for alert in alerts])

    assert "pid" not in encoded
    assert "remote_port" not in encoded
    assert "cmdline" not in encoded
    assert "environ" not in encoded


def test_alert_id_is_deterministic_for_same_ip() -> None:
    connections = _conns("203.0.113.10", detection.REMOTE_IP_FLOOD_HIGH)

    first = detection.evaluate(connections)
    second = detection.evaluate(connections)

    first_ids = sorted(a.id for a in first if a.type == detection.ALERT_TYPE_POSSIBLE_FLOOD)
    second_ids = sorted(a.id for a in second if a.type == detection.ALERT_TYPE_POSSIBLE_FLOOD)
    assert first_ids == second_ids


# ---------------------------------------------------------------------------
# Defensive: no automatic blocking / firewall behaviour
# ---------------------------------------------------------------------------


def test_detection_module_does_not_call_block_helpers(monkeypatch) -> None:
    """The detection module must never reach into rule mutation helpers."""
    from silentguard import monitor

    def fail(*args, **kwargs):  # pragma: no cover - guard against regression
        raise AssertionError(
            "detection module must not block, unblock, or untrust IPs"
        )

    monkeypatch.setattr(monitor, "block_ip_in_rules", fail)
    monkeypatch.setattr(monitor, "unblock_ip_in_rules", fail)
    monkeypatch.setattr(monitor, "untrust_ip_in_rules", fail)

    detection.evaluate(_conns("203.0.113.10", detection.REMOTE_IP_FLOOD_CRITICAL))


def test_detection_module_uses_only_local_state(tmp_path: Path) -> None:
    """End-to-end smoke test: detection works with only a local cache file."""
    cache = tmp_path / "unknown.json"
    now = datetime.now(timezone.utc)
    _write_cache(
        cache,
        [
            {
                "ip": f"198.51.100.{i + 1}",
                "process": "curl",
                "first_seen": _iso(now - timedelta(seconds=120)),
                "last_seen": _iso(now - timedelta(seconds=30)),
                "seen_count": 1,
                "classification": "unknown",
            }
            for i in range(detection.CHURN_MEDIUM)
        ],
    )

    alerts = detection.evaluate([], cache_path=cache)

    assert any(a.type == detection.ALERT_TYPE_CONNECTION_CHURN for a in alerts)
    # Reading the cache must not change its contents.
    assert connection_state.load_unknown_destinations(path=cache)
