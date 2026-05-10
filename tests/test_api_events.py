"""Tests for the read-only event-history API endpoints.

Exercises both the pure-Python handler functions and the HTTP server
to make sure the new ``/events`` and ``/events/summary`` endpoints
behave identically when called directly or through the local server.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from silentguard import detection, events, mitigation, monitor
from silentguard.api import handlers
from silentguard.api.server import create_server


@pytest.fixture
def api_server():
    server = create_server(host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[:2]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _get_json(host: str, port: int, path: str):
    req = urllib.request.Request(
        f"http://{host}:{port}{path}", method="GET"
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = resp.read().decode("utf-8")
        return resp.status, json.loads(body)


# ---------------------------------------------------------------------------
# /events
# ---------------------------------------------------------------------------


def test_get_events_handler_empty_when_no_events() -> None:
    payload = handlers.get_events()

    assert payload == {"items": []}


def test_get_events_handler_lists_recorded_events() -> None:
    events.record_unknown_connection_seen("203.0.113.10", process="firefox")

    payload = handlers.get_events()

    assert "items" in payload
    assert len(payload["items"]) == 1
    item = payload["items"][0]
    assert item["type"] == events.TYPE_UNKNOWN_CONNECTION_SEEN
    assert item["remote_ip"] == "203.0.113.10"


def test_get_events_handler_marks_not_available_on_error(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("store exploded")

    monkeypatch.setattr(events, "list_events", boom)

    payload = handlers.get_events()

    assert payload == {"items": [], "status": "not_available"}


def test_get_events_endpoint_lists_events(api_server) -> None:
    events.record_unknown_connection_seen("203.0.113.10", process="firefox")
    host, port = api_server

    status, payload = _get_json(host, port, "/events")

    assert status == 200
    assert len(payload["items"]) == 1
    assert payload["items"][0]["remote_ip"] == "203.0.113.10"


def test_get_events_endpoint_returns_empty_when_no_history(api_server) -> None:
    host, port = api_server

    status, payload = _get_json(host, port, "/events")

    assert status == 200
    assert payload == {"items": []}


# ---------------------------------------------------------------------------
# /events/summary
# ---------------------------------------------------------------------------


def test_get_events_summary_handler_zeroed_when_empty() -> None:
    payload = handlers.get_events_summary()

    assert payload["total"] == 0
    assert payload["active"] == 0
    assert payload["recent"] == []
    for severity in events.SEVERITIES:
        assert payload["by_severity"][severity] == 0


def test_get_events_summary_handler_counts_buckets() -> None:
    events.record_unknown_connection_seen("203.0.113.10")  # low
    events.record_trusted_ip_seen("8.8.8.8")               # info
    events.record_blocked_ip_seen("203.0.113.99")          # medium

    payload = handlers.get_events_summary()

    assert payload["total"] == 3
    assert payload["active"] == 3
    assert payload["by_severity"][events.SEVERITY_INFO] == 1
    assert payload["by_severity"][events.SEVERITY_LOW] == 1
    assert payload["by_severity"][events.SEVERITY_MEDIUM] == 1


def test_get_events_summary_handler_marks_not_available_on_error(
    monkeypatch,
) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("store exploded")

    monkeypatch.setattr(events, "summary", boom)

    payload = handlers.get_events_summary()

    assert payload["status"] == "not_available"
    assert payload["total"] == 0


def test_get_events_summary_endpoint_returns_summary(api_server) -> None:
    events.record_blocked_ip_seen("203.0.113.99", process="curl")
    host, port = api_server

    status, payload = _get_json(host, port, "/events/summary")

    assert status == 200
    assert payload["total"] == 1
    assert payload["active"] == 1
    assert payload["by_severity"][events.SEVERITY_MEDIUM] == 1
    assert len(payload["recent"]) == 1
    recap = payload["recent"][0]
    assert recap["remote_ip"] == "203.0.113.99"
    assert recap["type"] == events.TYPE_BLOCKED_IP_SEEN


def test_get_events_summary_payload_does_not_leak_pid_or_port(
    monkeypatch, api_server
) -> None:
    fake = [
        monitor.ConnectionInfo(
            process_name="firefox",
            pid=4242,
            remote_ip="93.184.216.34",
            remote_port=8443,
            status="ESTABLISHED",
            trust="Unknown",
        )
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)
    host, port = api_server

    # Touching /connections/summary primes the event history via the
    # documented sync path.
    _get_json(host, port, "/connections/summary")
    status, payload = _get_json(host, port, "/events/summary")

    assert status == 200
    encoded = json.dumps(payload)
    assert "4242" not in encoded
    assert "8443" not in encoded
    assert "pid" not in encoded
    assert "remote_port" not in encoded


# ---------------------------------------------------------------------------
# /alerts continues to work AND populates event history for possible_flood
# ---------------------------------------------------------------------------


def test_get_alerts_promotes_possible_flood_to_event_history(monkeypatch) -> None:
    fake = [
        monitor.ConnectionInfo(
            process_name="curl",
            pid=4242,
            remote_ip="203.0.113.10",
            remote_port=443,
            status="ESTABLISHED",
            trust="Unknown",
        )
        for _ in range(detection.REMOTE_IP_FLOOD_MEDIUM)
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)

    handlers.get_alerts()

    items = events.list_events()
    flood_events = [e for e in items if e["type"] == events.TYPE_POSSIBLE_FLOOD]
    assert len(flood_events) == 1
    assert flood_events[0]["remote_ip"] == "203.0.113.10"


def test_get_alerts_summary_existing_shape_is_unchanged(monkeypatch) -> None:
    """The existing /alerts/summary contract must keep its strict shape."""
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: [])

    payload = handlers.get_alerts_summary()

    assert payload == {
        "total": 0,
        "by_severity": {severity: 0 for severity in detection.SEVERITIES},
        "by_type": {},
        "highest_severity": None,
    }


# ---------------------------------------------------------------------------
# Mitigation lifecycle wires into event history
# ---------------------------------------------------------------------------


def test_enable_temporary_mitigation_via_handler_records_event() -> None:
    status, _ = handlers.enable_temporary_mitigation({"acknowledge": True})
    assert status == 200

    types = {e["type"] for e in events.list_events()}
    assert events.TYPE_MITIGATION_ENABLED in types


def test_disable_mitigation_via_handler_records_event() -> None:
    mitigation.set_mode(mitigation.MODE_TEMPORARY_AUTO_BLOCK, actor="test")

    status, _ = handlers.disable_mitigation({})
    assert status == 200

    types = {e["type"] for e in events.list_events()}
    assert events.TYPE_MITIGATION_DISABLED in types


def test_add_temporary_block_via_handler_records_event() -> None:
    status, payload = handlers.add_temporary_block({"ip": "185.199.108.153"})
    assert status == 201

    block_events = [
        e for e in events.list_events()
        if e["type"] == events.TYPE_TEMPORARY_BLOCK_CREATED
    ]
    assert len(block_events) == 1
    assert block_events[0]["remote_ip"] == "185.199.108.153"
