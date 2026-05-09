"""Tests for the opt-in flood mitigation policy module.

These tests cover every safety requirement from the feature spec:

* Default mode is ``detection_only`` and never auto-blocks.
* Auto-blocking only fires after the user explicitly enables
  ``temporary_auto_block``.
* Local, private, multicast, reserved, trusted, and protected IPs are
  always refused.
* Temporary blocks expire on schedule.
* Audit entries are written for every block, unblock, expiry, and
  rejection so the operator has a single timeline.
* The unblock path works.
* Rate limiting prevents an alert storm from fanning out into a wall
  of blocks.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from silentguard import detection, mitigation, monitor


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_rules(tmp_path, monkeypatch):
    rules_file = tmp_path / "rules.json"
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)
    return rules_file


def _seconds_from_now(seconds: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


_TEST_PUBLIC_IP = "185.199.108.153"


def _alert(
    *,
    severity: str = "high",
    type_: str = detection.ALERT_TYPE_POSSIBLE_FLOOD,
    source_ip: str = _TEST_PUBLIC_IP,
    count: int = detection.REMOTE_IP_FLOOD_HIGH,
    alert_id: str | None = None,
):
    return detection.Alert(
        id=alert_id or f"flood-remote-ip-{source_ip}",
        severity=severity,
        type=type_,
        title="t",
        message="m",
        created_at="2026-05-09T20:15:00Z",
        source_ip=source_ip,
        count=count,
    )


# ---------------------------------------------------------------------------
# Default state and mode handling
# ---------------------------------------------------------------------------


def test_default_mode_is_detection_only_when_state_missing() -> None:
    assert mitigation.get_mode() == mitigation.MODE_DETECTION_ONLY


def test_state_files_default_to_detection_only_when_corrupt(tmp_path) -> None:
    bad_state = tmp_path / "bad.json"
    bad_state.write_text("not valid json", encoding="utf-8")
    state = mitigation.load_state(path=bad_state)
    assert state["mode"] == mitigation.MODE_DETECTION_ONLY
    assert state["temp_blocks"] == []


def test_invalid_mode_in_state_falls_back_to_default(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text(
        '{"version": 1, "mode": "wide_open", "temp_blocks": []}',
        encoding="utf-8",
    )
    state = mitigation.load_state(path=state_file)
    assert state["mode"] == mitigation.MODE_DETECTION_ONLY


def test_set_mode_persists_and_audits(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    audit_file = tmp_path / "audit.json"

    mitigation.set_mode(
        mitigation.MODE_TEMPORARY_AUTO_BLOCK,
        path=state_file,
        audit_path=audit_file,
        actor="test",
    )

    assert mitigation.get_mode(path=state_file) == mitigation.MODE_TEMPORARY_AUTO_BLOCK
    audit = mitigation.read_audit(path=audit_file)
    assert audit
    assert audit[0]["event"] == mitigation.EVENT_MODE_CHANGED
    assert audit[0]["mode"] == mitigation.MODE_TEMPORARY_AUTO_BLOCK
    assert audit[0]["previous_mode"] == mitigation.MODE_DETECTION_ONLY


def test_set_mode_rejects_unknown_mode(tmp_path) -> None:
    with pytest.raises(ValueError):
        mitigation.set_mode("definitely-not-a-mode", path=tmp_path / "s.json")


# ---------------------------------------------------------------------------
# evaluate_block_candidate / never-block guarantees
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "::1",
        "10.0.0.1",
        "192.168.1.5",
        "172.20.0.1",
        "169.254.1.1",   # link-local
        "224.0.0.1",     # multicast
        "0.0.0.0",       # unspecified
        "240.0.0.1",     # reserved
    ],
)
def test_evaluate_block_candidate_refuses_local_and_special_ranges(ip: str) -> None:
    ok, reason = mitigation.evaluate_block_candidate(ip)
    assert ok is False
    assert reason


@pytest.mark.parametrize("ip", ["", "   ", "not-an-ip", "999.999.999.999"])
def test_evaluate_block_candidate_refuses_invalid_ip(ip: str) -> None:
    ok, reason = mitigation.evaluate_block_candidate(ip)
    assert ok is False
    assert reason


def test_evaluate_block_candidate_refuses_trusted_ip() -> None:
    rules = {"trusted_ips": ["8.8.8.8"]}
    ok, reason = mitigation.evaluate_block_candidate("8.8.8.8", rules=rules)
    assert ok is False
    assert reason == "ip_is_trusted"


def test_evaluate_block_candidate_refuses_protected_ip() -> None:
    state = {"protected_ips": ["1.1.1.1"]}
    ok, reason = mitigation.evaluate_block_candidate("1.1.1.1", state=state)
    assert ok is False
    assert reason == "ip_is_protected"


def test_evaluate_block_candidate_allows_routable_public_ip() -> None:
    ok, reason = mitigation.evaluate_block_candidate("185.199.108.153")
    assert ok is True
    assert reason is None


# ---------------------------------------------------------------------------
# Temporary block lifecycle
# ---------------------------------------------------------------------------


def test_add_temporary_block_writes_state_and_audit() -> None:
    ok, payload = mitigation.add_temporary_block(
        "185.199.108.153",
        reason="manual test",
        duration_seconds=600,
    )

    assert ok is True
    assert payload["ip"] == "185.199.108.153"
    assert payload["reason"] == "manual test"
    assert payload["source"] == "manual"
    assert payload["blocked_at"]
    assert payload["expires_at"]

    audit = mitigation.read_audit()
    events = [entry["event"] for entry in audit]
    assert mitigation.EVENT_TEMP_BLOCK_ADDED in events
    added = next(e for e in audit if e["event"] == mitigation.EVENT_TEMP_BLOCK_ADDED)
    assert added["ip"] == "185.199.108.153"
    assert added["reason"] == "manual test"
    assert added["duration_seconds"] == 600


def test_add_temporary_block_clamps_duration() -> None:
    ok, payload = mitigation.add_temporary_block(
        "185.199.108.153", duration_seconds=10**9
    )
    assert ok is True
    blocked = datetime.strptime(payload["blocked_at"], "%Y-%m-%dT%H:%M:%SZ")
    expires = datetime.strptime(payload["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
    delta = (expires - blocked).total_seconds()
    assert delta == mitigation.MAX_TEMP_BLOCK_DURATION


def test_add_temporary_block_refuses_local_ip_and_audits_rejection() -> None:
    ok, payload = mitigation.add_temporary_block("192.168.1.10")
    assert ok is False
    assert payload["reason"]

    audit = mitigation.read_audit()
    rejected = [
        entry for entry in audit
        if entry["event"] == mitigation.EVENT_TEMP_BLOCK_REJECTED
    ]
    assert rejected
    assert rejected[0]["ip"] == "192.168.1.10"


def test_add_temporary_block_refuses_trusted_ip(isolated_rules) -> None:
    monitor.save_rules({
        "known_processes": [],
        "trusted_ips": ["93.184.216.34"],
        "blocked_ips": [],
    })
    rules = monitor.load_rules()

    ok, payload = mitigation.add_temporary_block("93.184.216.34", rules=rules)

    assert ok is False
    assert payload["reason"] == "ip_is_trusted"


def test_add_temporary_block_refuses_protected_ip(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    state = mitigation._empty_state()
    state["protected_ips"] = ["93.184.216.99"]
    mitigation.save_state(state, path=state_file)

    ok, payload = mitigation.add_temporary_block(
        "93.184.216.99", path=state_file
    )
    assert ok is False
    assert payload["reason"] == "ip_is_protected"


def test_add_temporary_block_does_not_duplicate() -> None:
    ok1, _ = mitigation.add_temporary_block("185.199.108.153")
    ok2, payload2 = mitigation.add_temporary_block("185.199.108.153")
    assert ok1 is True
    assert ok2 is False
    assert payload2["reason"] == "already_blocked"


def test_remove_temporary_block_returns_entry_and_audits() -> None:
    mitigation.add_temporary_block("185.199.108.153")

    ok, removed = mitigation.remove_temporary_block("185.199.108.153")

    assert ok is True
    assert removed["ip"] == "185.199.108.153"
    assert "185.199.108.153" not in mitigation.current_temp_blocked_ips()
    audit_events = [e["event"] for e in mitigation.read_audit()]
    assert mitigation.EVENT_TEMP_BLOCK_REMOVED in audit_events


def test_remove_temporary_block_returns_not_found_for_unknown_ip() -> None:
    ok, payload = mitigation.remove_temporary_block("185.199.108.99")
    assert ok is False
    assert payload["reason"] == "not_found"


def test_expire_temp_blocks_removes_only_expired_entries(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    audit_file = tmp_path / "audit.json"

    past = _seconds_from_now(-10)
    future = _seconds_from_now(120)
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
                "expires_at": past.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            {
                "ip": "203.0.113.2",
                "reason": "fresh",
                "source": "manual",
                "threshold": "",
                "blocked_at": "2026-05-09T19:30:00Z",
                "expires_at": future.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        ],
    }
    mitigation.save_state(state, path=state_file)

    expired = mitigation.expire_temp_blocks(
        path=state_file, audit_path=audit_file
    )

    assert [e["ip"] for e in expired] == ["203.0.113.1"]
    survivors = mitigation.load_state(path=state_file)["temp_blocks"]
    assert [e["ip"] for e in survivors] == ["203.0.113.2"]
    audit = mitigation.read_audit(path=audit_file)
    assert any(e["event"] == mitigation.EVENT_TEMP_BLOCK_EXPIRED for e in audit)


# ---------------------------------------------------------------------------
# Auto-block (only fires when the user explicitly enables the mode)
# ---------------------------------------------------------------------------


def test_apply_auto_blocks_no_op_in_detection_only_mode() -> None:
    alerts = [_alert(severity="high")]

    added = mitigation.apply_auto_blocks(alerts)

    assert added == []
    assert mitigation.current_temp_blocked_ips() == set()


def test_apply_auto_blocks_no_op_in_ask_before_blocking_mode() -> None:
    mitigation.set_mode(mitigation.MODE_ASK_BEFORE_BLOCKING, actor="test")
    alerts = [_alert(severity="high")]

    added = mitigation.apply_auto_blocks(alerts)

    assert added == []
    assert mitigation.current_temp_blocked_ips() == set()


def test_apply_auto_blocks_blocks_high_severity_after_explicit_enable() -> None:
    mitigation.set_mode(mitigation.MODE_TEMPORARY_AUTO_BLOCK, actor="test")
    alerts = [_alert(severity="high", source_ip="185.199.108.153")]

    added = mitigation.apply_auto_blocks(alerts)

    assert len(added) == 1
    assert added[0]["ip"] == "185.199.108.153"
    assert added[0]["source"] == "auto"
    assert added[0]["threshold"] == "REMOTE_IP_FLOOD_HIGH"


def test_apply_auto_blocks_skips_medium_severity_alerts() -> None:
    mitigation.set_mode(mitigation.MODE_TEMPORARY_AUTO_BLOCK, actor="test")
    alerts = [_alert(severity="medium", source_ip="93.184.216.20")]

    added = mitigation.apply_auto_blocks(alerts)

    assert added == []
    assert mitigation.current_temp_blocked_ips() == set()


def test_apply_auto_blocks_skips_low_severity_alerts() -> None:
    mitigation.set_mode(mitigation.MODE_TEMPORARY_AUTO_BLOCK, actor="test")
    alerts = [_alert(severity="low", source_ip="93.184.216.21")]

    added = mitigation.apply_auto_blocks(alerts)

    assert added == []


def test_apply_auto_blocks_skips_non_flood_types() -> None:
    mitigation.set_mode(mitigation.MODE_TEMPORARY_AUTO_BLOCK, actor="test")
    alerts = [
        _alert(
            severity="critical",
            type_=detection.ALERT_TYPE_CONNECTION_SPIKE,
            source_ip="93.184.216.22",
        )
    ]

    added = mitigation.apply_auto_blocks(alerts)

    # Connection spike alerts do not name a single attacker IP we can
    # safely block.
    assert added == []


def test_apply_auto_blocks_refuses_trusted_ip(isolated_rules) -> None:
    monitor.save_rules({
        "known_processes": [],
        "trusted_ips": ["185.199.108.99"],
        "blocked_ips": [],
    })
    mitigation.set_mode(mitigation.MODE_TEMPORARY_AUTO_BLOCK, actor="test")
    rules = monitor.load_rules()
    alerts = [_alert(severity="critical", source_ip="185.199.108.99")]

    added = mitigation.apply_auto_blocks(alerts, rules=rules)

    assert added == []
    audit_events = [e["event"] for e in mitigation.read_audit()]
    assert mitigation.EVENT_TEMP_BLOCK_REJECTED in audit_events


def test_apply_auto_blocks_respects_rate_limit() -> None:
    mitigation.set_mode(mitigation.MODE_TEMPORARY_AUTO_BLOCK, actor="test")
    alerts = [
        _alert(
            severity="critical",
            source_ip=f"185.199.108.{i}",
            alert_id=f"flood-remote-ip-185.199.108.{i}",
        )
        for i in range(1, mitigation.AUTO_BLOCK_RATE_LIMIT + 5)
    ]

    added = mitigation.apply_auto_blocks(alerts)

    assert len(added) == mitigation.AUTO_BLOCK_RATE_LIMIT
    audit = mitigation.read_audit()
    rate_limited = [
        e for e in audit
        if e.get("event") == mitigation.EVENT_TEMP_BLOCK_REJECTED
        and e.get("rejection_reason") == "rate_limited"
    ]
    assert rate_limited


# ---------------------------------------------------------------------------
# Augmentation: temp blocks are visible to the classification path
# ---------------------------------------------------------------------------


def test_augment_rules_with_temp_blocks_returns_unchanged_when_empty() -> None:
    rules = {"blocked_ips": ["1.1.1.1"], "trusted_ips": [], "known_processes": []}

    augmented = mitigation.augment_rules_with_temp_blocks(rules)

    assert augmented["blocked_ips"] == ["1.1.1.1"]


def test_augment_rules_with_temp_blocks_merges_active_blocks() -> None:
    mitigation.add_temporary_block("185.199.108.153")
    rules = {"blocked_ips": ["1.1.1.1"], "trusted_ips": [], "known_processes": []}

    augmented = mitigation.augment_rules_with_temp_blocks(rules)

    assert "185.199.108.153" in augmented["blocked_ips"]
    assert "1.1.1.1" in augmented["blocked_ips"]


def test_temp_blocked_ip_is_classified_as_blocked() -> None:
    from silentguard.connection_state import (
        BLOCKED,
        UNKNOWN,
        classify_connection,
    )

    rules = {"blocked_ips": [], "trusted_ips": [], "known_processes": []}

    assert classify_connection("185.199.108.153", "curl", rules) == UNKNOWN

    mitigation.add_temporary_block("185.199.108.153")
    augmented = mitigation.augment_rules_with_temp_blocks(rules)

    assert classify_connection("185.199.108.153", "curl", augmented) == BLOCKED


# ---------------------------------------------------------------------------
# Status payload
# ---------------------------------------------------------------------------


def test_status_payload_default_is_detection_only() -> None:
    payload = mitigation.status_payload()
    assert payload["mode"] == mitigation.MODE_DETECTION_ONLY
    assert payload["default_mode"] == mitigation.MODE_DETECTION_ONLY
    assert mitigation.MITIGATION_PROMPT in payload["prompt"]
    assert payload["active_temp_blocks"] == []
    assert payload["auto_block_threshold"] == "REMOTE_IP_FLOOD_HIGH"
    assert "high" in payload["auto_block_severities"]
    assert "critical" in payload["auto_block_severities"]


def test_status_payload_lists_active_temp_blocks_and_prunes_expired(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    audit_file = tmp_path / "audit.json"

    state = {
        "version": 1,
        "mode": mitigation.MODE_TEMPORARY_AUTO_BLOCK,
        "mode_changed_at": "2026-05-09T20:00:00Z",
        "protected_ips": ["1.0.0.1"],
        "temp_blocks": [
            {
                "ip": "203.0.113.1",
                "reason": "old",
                "source": "auto",
                "threshold": "REMOTE_IP_FLOOD_HIGH",
                "blocked_at": "2026-05-09T19:00:00Z",
                "expires_at": _seconds_from_now(-30).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            {
                "ip": "203.0.113.2",
                "reason": "fresh",
                "source": "auto",
                "threshold": "REMOTE_IP_FLOOD_HIGH",
                "blocked_at": "2026-05-09T19:30:00Z",
                "expires_at": _seconds_from_now(120).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        ],
    }
    mitigation.save_state(state, path=state_file)

    payload = mitigation.status_payload(
        path=state_file, audit_path=audit_file
    )

    ips = [entry["ip"] for entry in payload["active_temp_blocks"]]
    assert ips == ["203.0.113.2"]
    assert "1.0.0.1" in payload["protected_ips"]


# ---------------------------------------------------------------------------
# Audit log bounding
# ---------------------------------------------------------------------------


def test_audit_log_is_bounded(monkeypatch, tmp_path) -> None:
    audit_file = tmp_path / "audit.json"
    monkeypatch.setattr(mitigation, "MAX_AUDIT_ENTRIES", 5)

    for i in range(20):
        mitigation.record_audit({"event": "marker", "i": i}, path=audit_file)

    entries = mitigation.read_audit(path=audit_file)
    assert len(entries) == 5
    # Newest first.
    assert entries[0]["i"] == 19
    assert entries[-1]["i"] == 15
