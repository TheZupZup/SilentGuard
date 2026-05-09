from pathlib import Path

import pytest

from silentguard import monitor
from silentguard.api import handlers


def test_get_status_shape() -> None:
    payload = handlers.get_status()

    assert payload["service"] == "silentguard"
    assert payload["available"] is True
    assert payload["mode"] == "read_only"
    assert isinstance(payload["message"], str)
    assert payload["message"]


def test_get_blocked_empty_when_rules_missing(
    tmp_path: Path, monkeypatch
) -> None:
    rules_file = tmp_path / "rules.json"
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)

    payload = handlers.get_blocked()

    assert payload == {"items": []}


def test_get_blocked_lists_rules_blocklist(
    tmp_path: Path, monkeypatch
) -> None:
    rules_file = tmp_path / "rules.json"
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)

    monitor.block_ip_in_rules("8.8.8.8")
    monitor.block_ip_in_rules("1.1.1.1")

    payload = handlers.get_blocked()
    ips = sorted(item["ip"] for item in payload["items"])

    assert ips == ["1.1.1.1", "8.8.8.8"]


def test_get_trusted_empty_when_rules_missing(
    tmp_path: Path, monkeypatch
) -> None:
    rules_file = tmp_path / "rules.json"
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)

    payload = handlers.get_trusted()

    assert payload == {"items": []}


def test_get_trusted_lists_trusted_ips(
    tmp_path: Path, monkeypatch
) -> None:
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        '{"known_processes": [], "trusted_ips": ["9.9.9.9"], "blocked_ips": []}',
        encoding="utf-8",
    )
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)

    payload = handlers.get_trusted()

    assert payload == {"items": [{"ip": "9.9.9.9"}]}


def test_get_connections_serializes_monitor_output(monkeypatch) -> None:
    fake = [
        monitor.ConnectionInfo(
            process_name="firefox",
            pid=1234,
            remote_ip="8.8.8.8",
            remote_port=443,
            status="ESTABLISHED",
            trust="Unknown",
        )
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections()

    assert payload == {
        "items": [
            {
                "process_name": "firefox",
                "pid": 1234,
                "remote_ip": "8.8.8.8",
                "remote_port": 443,
                "status": "ESTABLISHED",
                "trust": "Unknown",
            }
        ]
    }


def test_get_connections_marks_not_available_on_error(monkeypatch) -> None:
    def boom() -> list:
        raise RuntimeError("psutil unavailable")

    monkeypatch.setattr(handlers, "get_outgoing_connections", boom)

    payload = handlers.get_connections()

    assert payload["items"] == []
    assert payload["status"] == "not_available"


def test_get_blocked_marks_not_available_on_error(monkeypatch) -> None:
    def boom() -> dict:
        raise RuntimeError("rules unavailable")

    monkeypatch.setattr(handlers, "load_rules", boom)

    payload = handlers.get_blocked()

    assert payload == {"items": [], "status": "not_available"}


def test_get_trusted_marks_not_available_on_error(monkeypatch) -> None:
    def boom() -> dict:
        raise RuntimeError("rules unavailable")

    monkeypatch.setattr(handlers, "load_rules", boom)

    payload = handlers.get_trusted()

    assert payload == {"items": [], "status": "not_available"}


def test_get_alerts_returns_empty_not_available_placeholder() -> None:
    payload = handlers.get_alerts()

    assert payload["items"] == []
    assert payload["status"] == "not_available"


def _conn(
    process_name: str = "firefox",
    pid: int | None = 1234,
    remote_ip: str = "8.8.8.8",
    remote_port: int = 443,
    status: str = "ESTABLISHED",
    trust: str = "Unknown",
) -> monitor.ConnectionInfo:
    return monitor.ConnectionInfo(
        process_name=process_name,
        pid=pid,
        remote_ip=remote_ip,
        remote_port=remote_port,
        status=status,
        trust=trust,
    )


def test_get_connections_summary_empty_when_no_connections(monkeypatch) -> None:
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: [])

    payload = handlers.get_connections_summary()

    assert payload == {
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
    assert "status" not in payload


def test_get_connections_summary_marks_not_available_on_error(monkeypatch) -> None:
    def boom() -> list:
        raise RuntimeError("psutil unavailable")

    monkeypatch.setattr(handlers, "get_outgoing_connections", boom)

    payload = handlers.get_connections_summary()

    assert payload["status"] == "not_available"
    assert payload["total"] == 0
    assert payload["by_process"] == []
    assert payload["top_remote_hosts"] == []


def test_get_connections_summary_classification_counts(monkeypatch) -> None:
    fake = [
        _conn(process_name="firefox", remote_ip="8.8.8.8", trust="Known"),
        _conn(process_name="firefox", remote_ip="8.8.4.4", trust="Known"),
        _conn(process_name="firefox", remote_ip="93.184.216.34", trust="Unknown"),
        _conn(process_name="curl", remote_ip="203.0.113.10", trust="Blocked"),
        _conn(process_name="ssh", remote_ip="9.9.9.9", trust="Trusted"),
        _conn(process_name="systemd", remote_ip="127.0.0.1", trust="Local"),
        _conn(process_name="systemd", remote_ip="192.168.1.5", trust="Local"),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections_summary()

    assert payload["total"] == 7
    assert payload["local"] == 2
    assert payload["known"] == 2
    assert payload["unknown"] == 1
    assert payload["trusted"] == 1
    assert payload["blocked"] == 1


def test_get_connections_summary_top_processes(monkeypatch) -> None:
    fake = (
        [_conn(process_name="firefox", remote_ip="8.8.8.8", trust="Known")] * 3
        + [_conn(process_name="firefox", remote_ip="93.184.216.34", trust="Unknown")] * 2
        + [_conn(process_name="curl", remote_ip="203.0.113.10", trust="Unknown")]
        + [_conn(process_name="systemd", remote_ip="10.0.0.1", trust="Local")]
    )
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections_summary()

    by_process = payload["by_process"]
    assert by_process[0] == {
        "process": "firefox",
        "count": 5,
        "known": 3,
        "unknown": 2,
    }
    process_names = [bucket["process"] for bucket in by_process]
    assert process_names[:3] == ["firefox", "curl", "systemd"]
    systemd = next(b for b in by_process if b["process"] == "systemd")
    assert systemd == {"process": "systemd", "count": 1, "known": 0, "unknown": 0}


def test_get_connections_summary_top_remote_hosts_excludes_local(monkeypatch) -> None:
    fake = [
        _conn(process_name="firefox", remote_ip="8.8.8.8", trust="Known"),
        _conn(process_name="firefox", remote_ip="8.8.8.8", trust="Known"),
        _conn(process_name="curl", remote_ip="8.8.8.8", trust="Known"),
        _conn(process_name="curl", remote_ip="93.184.216.34", trust="Unknown"),
        _conn(process_name="systemd", remote_ip="127.0.0.1", trust="Local"),
        _conn(process_name="systemd", remote_ip="192.168.1.5", trust="Local"),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections_summary()

    hosts = payload["top_remote_hosts"]
    ips = [h["ip"] for h in hosts]
    assert "127.0.0.1" not in ips
    assert "192.168.1.5" not in ips
    assert hosts[0] == {"ip": "8.8.8.8", "count": 3, "classification": "known"}
    assert {"ip": "93.184.216.34", "count": 1, "classification": "unknown"} in hosts


def test_get_connections_summary_remote_classification_uses_most_severe(monkeypatch) -> None:
    fake = [
        _conn(process_name="firefox", remote_ip="93.184.216.34", trust="Known"),
        _conn(process_name="curl", remote_ip="93.184.216.34", trust="Unknown"),
        _conn(process_name="other", remote_ip="93.184.216.34", trust="Known"),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections_summary()

    host = payload["top_remote_hosts"][0]
    assert host["ip"] == "93.184.216.34"
    assert host["count"] == 3
    assert host["classification"] == "unknown"


def test_get_connections_summary_caps_top_lists(monkeypatch) -> None:
    fake = [
        _conn(process_name=f"proc{i:02d}", remote_ip=f"203.0.113.{i}", trust="Unknown")
        for i in range(1, 21)
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections_summary()

    assert len(payload["by_process"]) == handlers.SUMMARY_PROCESS_LIMIT
    assert len(payload["top_remote_hosts"]) == handlers.SUMMARY_REMOTE_HOST_LIMIT


def test_get_connections_summary_payload_is_json_serializable(monkeypatch) -> None:
    import json

    fake = [
        _conn(process_name="firefox", remote_ip="8.8.8.8", trust="Known"),
        _conn(process_name="curl", remote_ip="203.0.113.10", trust="Blocked"),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections_summary()
    encoded = json.dumps(payload)

    assert "firefox" in encoded
    assert "203.0.113.10" in encoded
    assert "PID" not in encoded
    assert "1234" not in encoded


def test_get_connections_summary_unknown_trust_label_falls_back(monkeypatch) -> None:
    fake = [
        _conn(process_name="weird", remote_ip="203.0.113.10", trust="Banana"),
        _conn(process_name="weird", remote_ip="203.0.113.10", trust=""),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections_summary()

    assert payload["total"] == 2
    assert payload["unknown"] == 2
    assert payload["known"] == 0
    assert payload["trusted"] == 0
    assert payload["local"] == 0
    assert payload["blocked"] == 0


def test_get_connections_summary_includes_recent_unknown(monkeypatch) -> None:
    fake = [
        _conn(process_name="firefox", remote_ip="93.184.216.34", trust="Unknown"),
        _conn(process_name="curl", remote_ip="203.0.113.10", trust="Unknown"),
        _conn(process_name="systemd", remote_ip="127.0.0.1", trust="Local"),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections_summary()

    assert payload["unknown"] == 2
    assert isinstance(payload["recent_unknown"], list)
    ips = {entry["ip"] for entry in payload["recent_unknown"]}
    assert ips == {"93.184.216.34", "203.0.113.10"}
    for entry in payload["recent_unknown"]:
        assert entry["classification"] == "unknown"
        assert entry["seen_count"] >= 1
        assert entry["first_seen"]
        assert entry["last_seen"]
        # Local connections must not appear in the recent_unknown list.
        assert entry["ip"] != "127.0.0.1"


def test_get_connections_summary_recent_unknown_increments_seen_count(
    monkeypatch,
) -> None:
    fake = [
        _conn(process_name="firefox", remote_ip="93.184.216.34", trust="Unknown"),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    handlers.get_connections_summary()
    payload = handlers.get_connections_summary()

    assert payload["unknown"] == 1
    assert len(payload["recent_unknown"]) == 1
    entry = payload["recent_unknown"][0]
    assert entry["ip"] == "93.184.216.34"
    assert entry["seen_count"] == 2


def test_get_connections_summary_trusted_ips_not_counted_as_unknown(
    monkeypatch,
) -> None:
    fake = [
        _conn(process_name="ssh", remote_ip="1.1.1.1", trust="Trusted"),
        _conn(process_name="ssh", remote_ip="1.1.1.1", trust="Trusted"),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections_summary()

    assert payload["trusted"] == 2
    assert payload["unknown"] == 0
    assert payload["recent_unknown"] == []


def test_get_recent_unknown_returns_empty_when_cache_missing(monkeypatch) -> None:
    payload = handlers.get_recent_unknown()

    assert payload == {"items": []}


def test_get_recent_unknown_lists_persisted_destinations(monkeypatch) -> None:
    fake = [
        _conn(process_name="firefox", remote_ip="93.184.216.34", trust="Unknown"),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    handlers.get_connections_summary()  # populate the cache
    payload = handlers.get_recent_unknown()

    assert len(payload["items"]) == 1
    entry = payload["items"][0]
    assert entry["ip"] == "93.184.216.34"
    assert entry["process"] == "firefox"
    assert entry["classification"] == "unknown"
    assert entry["seen_count"] >= 1


def test_get_recent_unknown_marks_not_available_on_cache_error(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("cache exploded")

    monkeypatch.setattr(handlers, "recent_unknown_destinations", boom)

    payload = handlers.get_recent_unknown()

    assert payload == {"items": [], "status": "not_available"}


def test_get_connections_summary_recent_unknown_omits_pid_and_port(
    monkeypatch,
) -> None:
    import json

    fake = [
        _conn(
            process_name="firefox",
            pid=4242,
            remote_ip="93.184.216.34",
            remote_port=8443,
            trust="Unknown",
        ),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    payload = handlers.get_connections_summary()
    encoded = json.dumps(payload["recent_unknown"])

    assert "4242" not in encoded
    assert "8443" not in encoded
    assert "pid" not in encoded
    assert "remote_port" not in encoded
