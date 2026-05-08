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
