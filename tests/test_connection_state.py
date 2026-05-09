"""Tests for the classification + unknown-destinations sync layer."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from silentguard import connection_state


@dataclass
class _FakeConn:
    process_name: str
    remote_ip: str
    classification: str = ""
    trust: str = ""

    def __post_init__(self) -> None:
        if not self.classification and self.trust:
            self.classification = connection_state.classification_from_label(self.trust)


def _make_rules(
    *,
    blocked: list[str] | None = None,
    trusted: list[str] | None = None,
    known_processes: list[str] | None = None,
) -> dict:
    return {
        "blocked_ips": list(blocked or []),
        "trusted_ips": list(trusted or []),
        "known_processes": list(known_processes or []),
    }


# ---------------------------------------------------------------------------
# classify_connection
# ---------------------------------------------------------------------------


def test_classify_connection_returns_blocked_first() -> None:
    rules = _make_rules(blocked=["203.0.113.10"], trusted=["203.0.113.10"])
    assert connection_state.classify_connection(
        "203.0.113.10", "firefox", rules
    ) == "blocked"


def test_classify_connection_returns_trusted_over_local_known() -> None:
    rules = _make_rules(trusted=["8.8.8.8"], known_processes=["firefox"])
    assert connection_state.classify_connection(
        "8.8.8.8", "firefox", rules
    ) == "trusted"


def test_classify_connection_returns_local_for_private_ip() -> None:
    rules = _make_rules(known_processes=["firefox"])
    assert connection_state.classify_connection(
        "192.168.1.10", "firefox", rules
    ) == "local"
    assert connection_state.classify_connection(
        "127.0.0.1", "firefox", rules
    ) == "local"


def test_classify_connection_returns_known_for_listed_process() -> None:
    rules = _make_rules(known_processes=["firefox"])
    assert connection_state.classify_connection(
        "8.8.8.8", "firefox", rules
    ) == "known"


def test_classify_connection_falls_back_to_unknown() -> None:
    rules = _make_rules()
    assert connection_state.classify_connection(
        "8.8.8.8", "ranyrandomcli", rules
    ) == "unknown"


def test_classify_connection_handles_missing_rules() -> None:
    assert connection_state.classify_connection(
        "8.8.8.8", "firefox", None
    ) == "unknown"


def test_classify_connection_handles_invalid_ip() -> None:
    rules = _make_rules()
    assert connection_state.classify_connection(
        "not-an-ip", "firefox", rules
    ) == "unknown"


# ---------------------------------------------------------------------------
# display_label / classification_from_label
# ---------------------------------------------------------------------------


def test_display_label_round_trip() -> None:
    for canonical in connection_state.CANONICAL_CLASSIFICATIONS:
        label = connection_state.display_label(canonical)
        assert connection_state.classification_from_label(label) == canonical


def test_classification_from_label_handles_unknown_inputs() -> None:
    assert connection_state.classification_from_label(None) == "unknown"
    assert connection_state.classification_from_label("") == "unknown"
    assert connection_state.classification_from_label("nonsense") == "unknown"


def test_display_label_for_unknown_canonical_falls_back() -> None:
    assert connection_state.display_label("not-a-real-classification") == "Unknown"


# ---------------------------------------------------------------------------
# record_connections / cache persistence
# ---------------------------------------------------------------------------


def test_record_connections_creates_cache_for_unknown(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    conns = [_FakeConn(process_name="firefox", remote_ip="93.184.216.34", classification="unknown")]

    connection_state.record_connections(conns, path=cache)

    entries = connection_state.load_unknown_destinations(path=cache)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["ip"] == "93.184.216.34"
    assert entry["process"] == "firefox"
    assert entry["classification"] == "unknown"
    assert entry["seen_count"] == 1
    assert entry["first_seen"]
    assert entry["last_seen"]


def test_record_connections_does_not_track_local(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    conns = [
        _FakeConn(process_name="systemd", remote_ip="127.0.0.1", classification="local"),
        _FakeConn(process_name="systemd", remote_ip="192.168.1.5", classification="local"),
    ]

    connection_state.record_connections(conns, path=cache)

    assert not cache.exists()
    assert connection_state.load_unknown_destinations(path=cache) == []


def test_record_connections_increments_seen_count_across_snapshots(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "unknown.json"
    conn = _FakeConn(process_name="firefox", remote_ip="203.0.113.10", classification="unknown")

    connection_state.record_connections([conn], path=cache)
    connection_state.record_connections([conn], path=cache)
    connection_state.record_connections([conn], path=cache)

    entries = connection_state.load_unknown_destinations(path=cache)
    assert len(entries) == 1
    assert entries[0]["seen_count"] == 3


def test_record_connections_dedupes_within_snapshot(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    conns = [
        _FakeConn(process_name="firefox", remote_ip="203.0.113.10", classification="unknown"),
        _FakeConn(process_name="firefox", remote_ip="203.0.113.10", classification="unknown"),
        _FakeConn(process_name="firefox", remote_ip="203.0.113.10", classification="unknown"),
    ]

    connection_state.record_connections(conns, path=cache)

    entries = connection_state.load_unknown_destinations(path=cache)
    assert len(entries) == 1
    # Multiple connections to the same destination in one snapshot count once.
    assert entries[0]["seen_count"] == 1


def test_record_connections_updates_classification_on_transition(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "unknown.json"
    unknown = _FakeConn(
        process_name="firefox", remote_ip="203.0.113.10", classification="unknown"
    )
    trusted = _FakeConn(
        process_name="firefox", remote_ip="203.0.113.10", classification="trusted"
    )

    connection_state.record_connections([unknown], path=cache)
    connection_state.record_connections([trusted], path=cache)

    entries = connection_state.load_unknown_destinations(path=cache)
    assert len(entries) == 1
    assert entries[0]["classification"] == "trusted"
    # Trusted IPs must not be reported as recent unknowns.
    assert connection_state.recent_unknown_destinations(path=cache) == []


def test_record_connections_does_not_track_blocked_with_no_history(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "unknown.json"
    blocked = _FakeConn(
        process_name="firefox", remote_ip="203.0.113.10", classification="blocked"
    )

    connection_state.record_connections([blocked], path=cache)

    assert connection_state.load_unknown_destinations(path=cache) == []


def test_record_connections_falls_back_to_trust_label(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    conn = _FakeConn(
        process_name="firefox", remote_ip="93.184.216.34", trust="Unknown"
    )
    # ``classification`` derived from the trust label by __post_init__.
    assert conn.classification == "unknown"

    connection_state.record_connections([conn], path=cache)

    entries = connection_state.load_unknown_destinations(path=cache)
    assert len(entries) == 1
    assert entries[0]["ip"] == "93.184.216.34"


def test_record_connections_skips_invalid_entries(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    conns = [
        _FakeConn(process_name="firefox", remote_ip="", classification="unknown"),
        _FakeConn(process_name="", remote_ip="93.184.216.34", classification="unknown"),
    ]

    connection_state.record_connections(conns, path=cache)

    entries = connection_state.load_unknown_destinations(path=cache)
    assert len(entries) == 1
    assert entries[0]["ip"] == "93.184.216.34"
    # When the process name is missing we still record the IP so consumers
    # can see what destination was reached.
    assert entries[0]["process"] == "Unknown"


def test_record_connections_no_change_does_not_rewrite_file(
    tmp_path: Path, monkeypatch
) -> None:
    cache = tmp_path / "unknown.json"
    trusted = _FakeConn(
        process_name="ssh", remote_ip="9.9.9.9", classification="trusted"
    )

    # No existing entry for this IP and the connection isn't unknown, so
    # nothing should change and the cache file should not be created.
    connection_state.record_connections([trusted], path=cache)
    assert not cache.exists()


def test_load_cache_recovers_from_corrupted_file(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    cache.write_text("{not valid json", encoding="utf-8")

    assert connection_state.load_unknown_destinations(path=cache) == []


def test_load_cache_recovers_from_unexpected_shape(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    cache.write_text(json.dumps([{"ip": "1.2.3.4"}]), encoding="utf-8")

    assert connection_state.load_unknown_destinations(path=cache) == []


def test_recent_unknown_destinations_filters_to_unknown(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    cache.write_text(
        json.dumps(
            {
                "version": 1,
                "destinations": [
                    {
                        "ip": "203.0.113.10",
                        "process": "firefox",
                        "first_seen": "2026-05-09T20:00:00Z",
                        "last_seen": "2026-05-09T20:10:00Z",
                        "seen_count": 4,
                        "classification": "unknown",
                    },
                    {
                        "ip": "1.1.1.1",
                        "process": "ssh",
                        "first_seen": "2026-05-09T20:00:00Z",
                        "last_seen": "2026-05-09T20:09:00Z",
                        "seen_count": 2,
                        "classification": "trusted",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    items = connection_state.recent_unknown_destinations(path=cache)
    ips = [item["ip"] for item in items]
    assert ips == ["203.0.113.10"]


def test_recent_unknown_destinations_respects_limit(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    conns = [
        _FakeConn(
            process_name=f"proc{i}", remote_ip=f"203.0.113.{i}", classification="unknown"
        )
        for i in range(1, 11)
    ]
    connection_state.record_connections(conns, path=cache)

    items = connection_state.recent_unknown_destinations(limit=3, path=cache)
    assert len(items) == 3
    items_zero = connection_state.recent_unknown_destinations(limit=0, path=cache)
    assert items_zero == []


def test_record_connections_caps_total_entries(
    tmp_path: Path, monkeypatch
) -> None:
    cache = tmp_path / "unknown.json"
    monkeypatch.setattr(connection_state, "MAX_UNKNOWN_ENTRIES", 5)

    conns = [
        _FakeConn(
            process_name="proc",
            remote_ip=f"203.0.113.{i}",
            classification="unknown",
        )
        for i in range(1, 11)
    ]
    connection_state.record_connections(conns, path=cache)

    entries = connection_state.load_unknown_destinations(path=cache)
    assert len(entries) == 5


def test_persisted_cache_omits_pid_and_socket_internals(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    conn = _FakeConn(
        process_name="firefox", remote_ip="93.184.216.34", classification="unknown"
    )
    # The fake conn doesn't have a pid attribute, so this is a guarantee
    # via the recorded shape: only the documented minimal metadata is
    # written to disk.
    connection_state.record_connections([conn], path=cache)

    raw = cache.read_text(encoding="utf-8")
    assert "pid" not in raw
    assert "remote_port" not in raw
    assert "cmdline" not in raw
    assert "environ" not in raw


def test_clear_unknown_destinations_removes_file(tmp_path: Path) -> None:
    cache = tmp_path / "unknown.json"
    cache.write_text(json.dumps(connection_state._empty_cache()), encoding="utf-8")

    connection_state.clear_unknown_destinations(path=cache)

    assert not cache.exists()
    # Idempotent: clearing twice is fine.
    connection_state.clear_unknown_destinations(path=cache)
