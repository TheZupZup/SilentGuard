"""Tests for the local alert/event history module.

These cover the behaviour requirements from the feature spec:

* Event creation works.
* Duplicate unknown events are coalesced instead of spammed.
* Repeated unknown connections increment ``seen_count`` and update
  ``last_seen``; once the threshold is reached, the type is promoted
  to ``repeated_unknown_connection`` deterministically.
* Storage is bounded.
* Severity buckets are computed correctly by the summary helper.
* Mitigation enable/disable records events.
* Temporary block creation/expiry records events.
* Sensitive metadata (PIDs, ports, command lines, environment
  variables) never leaks into the on-disk store.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from silentguard import detection, events, mitigation


@dataclass
class _FakeConn:
    process_name: str = "firefox"
    remote_ip: str = "203.0.113.10"
    classification: str = "unknown"
    trust: str = ""


def _at(seconds_from_zero: int) -> datetime:
    return datetime(2026, 5, 9, 20, 0, 0, tzinfo=timezone.utc) + timedelta(
        seconds=seconds_from_zero
    )


# ---------------------------------------------------------------------------
# Recording — unknown observations
# ---------------------------------------------------------------------------


def test_record_unknown_connection_seen_creates_event() -> None:
    entry = events.record_unknown_connection_seen(
        "203.0.113.10", process="firefox", now=_at(0)
    )

    assert entry is not None
    assert entry["type"] == events.TYPE_UNKNOWN_CONNECTION_SEEN
    assert entry["severity"] == events.SEVERITY_LOW
    assert entry["remote_ip"] == "203.0.113.10"
    assert entry["process"] == "firefox"
    assert entry["seen_count"] == 1
    assert entry["status"] == events.STATUS_ACTIVE
    assert entry["first_seen"] == entry["last_seen"]
    assert entry["title"]
    assert entry["message"]


def test_record_unknown_connection_seen_coalesces_by_ip() -> None:
    events.record_unknown_connection_seen(
        "203.0.113.10", process="firefox", now=_at(0)
    )
    events.record_unknown_connection_seen(
        "203.0.113.10", process="firefox", now=_at(60)
    )
    events.record_unknown_connection_seen(
        "203.0.113.10", process="firefox", now=_at(120)
    )

    items = events.list_events()
    matching = [e for e in items if e.get("remote_ip") == "203.0.113.10"]
    assert len(matching) == 1
    assert matching[0]["seen_count"] == 3
    assert matching[0]["first_seen"] == "2026-05-09T20:00:00Z"
    assert matching[0]["last_seen"] == "2026-05-09T20:02:00Z"


def test_record_unknown_promotes_to_repeated_after_threshold() -> None:
    for i in range(events.REPEAT_THRESHOLD):
        events.record_unknown_connection_seen(
            "203.0.113.10", process="firefox", now=_at(i * 30)
        )

    items = events.list_events()
    matching = [e for e in items if e.get("remote_ip") == "203.0.113.10"]
    assert len(matching) == 1
    entry = matching[0]
    assert entry["type"] == events.TYPE_REPEATED_UNKNOWN_CONNECTION
    assert entry["severity"] == events.SEVERITY_MEDIUM
    assert entry["seen_count"] == events.REPEAT_THRESHOLD


def test_record_unknown_connection_seen_returns_none_for_empty_ip() -> None:
    assert events.record_unknown_connection_seen("") is None
    assert events.record_unknown_connection_seen("   ") is None
    assert events.list_events() == []


def test_record_trusted_and_blocked_ip_seen() -> None:
    trusted = events.record_trusted_ip_seen(
        "8.8.8.8", process="firefox", now=_at(0)
    )
    blocked = events.record_blocked_ip_seen(
        "203.0.113.99", process="curl", now=_at(0)
    )

    assert trusted["type"] == events.TYPE_TRUSTED_IP_SEEN
    assert trusted["severity"] == events.SEVERITY_INFO
    assert blocked["type"] == events.TYPE_BLOCKED_IP_SEEN
    assert blocked["severity"] == events.SEVERITY_MEDIUM


# ---------------------------------------------------------------------------
# Snapshot helper coalesces within a snapshot
# ---------------------------------------------------------------------------


def test_record_connection_observations_dedupes_within_snapshot() -> None:
    snapshot = [
        _FakeConn(remote_ip="203.0.113.10", classification="unknown"),
        _FakeConn(remote_ip="203.0.113.10", classification="unknown"),
        _FakeConn(remote_ip="203.0.113.10", classification="unknown"),
    ]

    events.record_connection_observations(snapshot, now=_at(0))

    items = events.list_events()
    matching = [e for e in items if e.get("remote_ip") == "203.0.113.10"]
    assert len(matching) == 1
    # Three concurrent sockets to one IP must count as one observation.
    assert matching[0]["seen_count"] == 1


def test_record_connection_observations_skips_local() -> None:
    snapshot = [
        _FakeConn(remote_ip="127.0.0.1", classification="local"),
        _FakeConn(remote_ip="192.168.1.5", classification="local"),
    ]

    events.record_connection_observations(snapshot, now=_at(0))

    assert events.list_events() == []


def test_record_connection_observations_records_each_classification() -> None:
    snapshot = [
        _FakeConn(remote_ip="203.0.113.10", classification="unknown"),
        _FakeConn(remote_ip="8.8.8.8", classification="trusted"),
        _FakeConn(remote_ip="203.0.113.99", classification="blocked"),
    ]

    events.record_connection_observations(snapshot, now=_at(0))

    types = {e["type"] for e in events.list_events()}
    assert events.TYPE_UNKNOWN_CONNECTION_SEEN in types
    assert events.TYPE_TRUSTED_IP_SEEN in types
    assert events.TYPE_BLOCKED_IP_SEEN in types


def test_record_connection_observations_uses_trust_label_fallback() -> None:
    snapshot = [_FakeConn(remote_ip="203.0.113.10", trust="Unknown")]

    events.record_connection_observations(snapshot, now=_at(0))

    items = events.list_events()
    assert len(items) == 1
    assert items[0]["type"] == events.TYPE_UNKNOWN_CONNECTION_SEEN


# ---------------------------------------------------------------------------
# Mitigation lifecycle events
# ---------------------------------------------------------------------------


def test_record_mitigation_mode_change_records_enabled_and_disabled() -> None:
    events.record_mitigation_mode_change(
        "temporary_auto_block",
        "detection_only",
        actor="user",
        now=_at(0),
    )
    events.record_mitigation_mode_change(
        "detection_only",
        "temporary_auto_block",
        actor="user",
        now=_at(10),
    )

    items = events.list_events()
    types = [e["type"] for e in items]
    assert events.TYPE_MITIGATION_ENABLED in types
    assert events.TYPE_MITIGATION_DISABLED in types
    enabled = next(e for e in items if e["type"] == events.TYPE_MITIGATION_ENABLED)
    assert enabled["severity"] == events.SEVERITY_INFO


def test_record_mitigation_mode_change_no_op_when_unchanged() -> None:
    out = events.record_mitigation_mode_change(
        "detection_only", "detection_only", actor="user", now=_at(0)
    )
    assert out is None
    assert events.list_events() == []


def test_record_mitigation_mode_change_skips_ask_before_blocking() -> None:
    out = events.record_mitigation_mode_change(
        "ask_before_blocking", "detection_only", actor="user", now=_at(0)
    )
    assert out is None
    assert events.list_events() == []


def test_set_mode_records_event_in_history() -> None:
    mitigation.set_mode(mitigation.MODE_TEMPORARY_AUTO_BLOCK, actor="test")

    items = events.list_events()
    types = [e["type"] for e in items]
    assert events.TYPE_MITIGATION_ENABLED in types


def test_temporary_block_creation_records_event() -> None:
    ok, _ = mitigation.add_temporary_block("185.199.108.153", reason="manual")
    assert ok is True

    items = events.list_events()
    types = [e["type"] for e in items]
    assert events.TYPE_TEMPORARY_BLOCK_CREATED in types
    block_event = next(
        e for e in items if e["type"] == events.TYPE_TEMPORARY_BLOCK_CREATED
    )
    assert block_event["remote_ip"] == "185.199.108.153"
    assert block_event["severity"] == events.SEVERITY_MEDIUM


def test_temporary_block_expiry_records_event(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    audit_file = tmp_path / "audit.json"

    past = (datetime.now(timezone.utc) - timedelta(seconds=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    state = {
        "version": 1,
        "mode": mitigation.MODE_DETECTION_ONLY,
        "mode_changed_at": "2026-05-09T20:00:00Z",
        "protected_ips": [],
        "temp_blocks": [
            {
                "ip": "203.0.113.1",
                "reason": "old",
                "source": "manual",
                "threshold": "",
                "blocked_at": "2026-05-09T19:00:00Z",
                "expires_at": past,
            }
        ],
    }
    mitigation.save_state(state, path=state_file)

    mitigation.expire_temp_blocks(path=state_file, audit_path=audit_file)

    items = events.list_events()
    types = [e["type"] for e in items]
    assert events.TYPE_TEMPORARY_BLOCK_EXPIRED in types


# ---------------------------------------------------------------------------
# Detection alert promotion
# ---------------------------------------------------------------------------


def test_record_detection_alerts_persists_only_possible_flood() -> None:
    flood = detection.Alert(
        id="flood-remote-ip-203.0.113.10",
        severity=detection.SEVERITY_HIGH,
        type=detection.ALERT_TYPE_POSSIBLE_FLOOD,
        title="t",
        message="m",
        created_at="2026-05-09T20:00:00Z",
        source_ip="203.0.113.10",
        count=200,
    )
    burst = detection.Alert(
        id="unknown-burst-current",
        severity=detection.SEVERITY_MEDIUM,
        type=detection.ALERT_TYPE_UNKNOWN_BURST,
        title="t",
        message="m",
        created_at="2026-05-09T20:00:00Z",
        count=50,
    )

    events.record_detection_alerts([flood, burst])

    items = events.list_events()
    types = [e["type"] for e in items]
    assert events.TYPE_POSSIBLE_FLOOD in types
    assert events.TYPE_UNKNOWN_BURST not in types if hasattr(events, "TYPE_UNKNOWN_BURST") else True


def test_record_detection_alerts_coalesces_by_ip() -> None:
    flood = detection.Alert(
        id="flood-remote-ip-203.0.113.10",
        severity=detection.SEVERITY_HIGH,
        type=detection.ALERT_TYPE_POSSIBLE_FLOOD,
        title="t",
        message="m",
        created_at="2026-05-09T20:00:00Z",
        source_ip="203.0.113.10",
        count=200,
    )

    events.record_detection_alerts([flood], now=_at(0))
    events.record_detection_alerts([flood], now=_at(60))
    events.record_detection_alerts([flood], now=_at(120))

    items = [e for e in events.list_events() if e.get("remote_ip") == "203.0.113.10"]
    assert len(items) == 1
    assert items[0]["seen_count"] == 3
    assert items[0]["severity"] == events.SEVERITY_HIGH


# ---------------------------------------------------------------------------
# Storage bounded + corruption recovery
# ---------------------------------------------------------------------------


def test_storage_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(events, "MAX_EVENTS", 5)

    for i in range(20):
        events.record_unknown_connection_seen(
            f"203.0.113.{i}", process="proc", now=_at(i)
        )

    items = events.list_events()
    assert len(items) == 5
    # Newest 5 IPs are kept (203.0.113.15 ... 203.0.113.19).
    ips = sorted(e["remote_ip"] for e in items)
    assert ips == [
        "203.0.113.15",
        "203.0.113.16",
        "203.0.113.17",
        "203.0.113.18",
        "203.0.113.19",
    ]


def test_load_recovers_from_corrupt_file(tmp_path: Path) -> None:
    events_file = tmp_path / "broken.json"
    events_file.write_text("{not valid json", encoding="utf-8")

    assert events.list_events(path=events_file) == []


def test_load_ignores_unexpected_shape(tmp_path: Path) -> None:
    events_file = tmp_path / "weird.json"
    events_file.write_text(
        json.dumps([{"id": "evt_x", "type": "unknown_connection_seen"}]),
        encoding="utf-8",
    )

    assert events.list_events(path=events_file) == []


def test_clear_events_removes_file(tmp_path: Path) -> None:
    events_file = tmp_path / "events.json"
    events_file.write_text(json.dumps(events._empty_store()), encoding="utf-8")

    events.clear_events(path=events_file)

    assert not events_file.exists()
    # Idempotent: clearing twice is fine.
    events.clear_events(path=events_file)


# ---------------------------------------------------------------------------
# Privacy: stored fields stay minimal
# ---------------------------------------------------------------------------


def test_persisted_event_omits_sensitive_metadata(tmp_path, monkeypatch) -> None:
    events_file = tmp_path / "events.json"
    monkeypatch.setattr(events, "EVENTS_FILE", events_file)

    events.record_unknown_connection_seen(
        "203.0.113.10", process="firefox", now=_at(0)
    )

    raw = events_file.read_text(encoding="utf-8")
    for forbidden in ("pid", "remote_port", "cmdline", "environ", "argv"):
        assert forbidden not in raw


# ---------------------------------------------------------------------------
# Summary helper
# ---------------------------------------------------------------------------


def test_summary_returns_zeroed_payload_when_empty() -> None:
    payload = events.summary()

    assert payload["total"] == 0
    assert payload["active"] == 0
    assert payload["recent"] == []
    for severity in events.SEVERITIES:
        assert payload["by_severity"][severity] == 0


def test_summary_counts_severity_buckets() -> None:
    events.record_unknown_connection_seen("203.0.113.10", now=_at(0))   # low
    events.record_trusted_ip_seen("8.8.8.8", now=_at(1))                # info
    events.record_blocked_ip_seen("203.0.113.99", now=_at(2))           # medium

    payload = events.summary()

    assert payload["total"] == 3
    assert payload["active"] == 3
    assert payload["by_severity"][events.SEVERITY_INFO] == 1
    assert payload["by_severity"][events.SEVERITY_LOW] == 1
    assert payload["by_severity"][events.SEVERITY_MEDIUM] == 1
    assert payload["by_severity"][events.SEVERITY_HIGH] == 0
    assert payload["by_severity"][events.SEVERITY_CRITICAL] == 0


def test_summary_recent_carries_minimal_fields() -> None:
    events.record_unknown_connection_seen(
        "203.0.113.10", process="firefox", now=_at(0)
    )

    payload = events.summary()

    assert len(payload["recent"]) == 1
    recap = payload["recent"][0]
    for field in ("id", "type", "severity", "title", "message", "seen_count", "last_seen"):
        assert field in recap
    # Recap must not leak sensitive fields.
    for forbidden in ("pid", "remote_port", "cmdline", "environ"):
        assert forbidden not in recap


def test_list_events_respects_limit_and_status_filter() -> None:
    for i in range(3):
        events.record_unknown_connection_seen(
            f"203.0.113.{i + 1}", now=_at(i)
        )

    assert len(events.list_events(limit=2)) == 2
    assert events.list_events(limit=0) == []
    # All entries are active by default; filtering by 'resolved' yields none.
    assert events.list_events(statuses=[events.STATUS_RESOLVED]) == []
    assert len(events.list_events(statuses=[events.STATUS_ACTIVE])) == 3
