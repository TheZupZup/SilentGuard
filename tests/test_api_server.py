import json
import threading
import urllib.error
import urllib.request

import pytest

from silentguard import detection, monitor
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


def _request(host: str, port: int, path: str, method: str = "GET"):
    req = urllib.request.Request(
        f"http://{host}:{port}{path}", method=method
    )
    return urllib.request.urlopen(req, timeout=5)


def _get_json(host: str, port: int, path: str):
    with _request(host, port, path) as resp:
        body = resp.read().decode("utf-8")
        return resp.status, dict(resp.headers), json.loads(body)


def test_status_endpoint_returns_expected_schema(api_server) -> None:
    host, port = api_server

    status, headers, payload = _get_json(host, port, "/status")

    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert payload["service"] == "silentguard"
    assert payload["available"] is True
    assert payload["mode"] == "read_only"


def test_root_path_serves_status(api_server) -> None:
    host, port = api_server

    status, _, payload = _get_json(host, port, "/")

    assert status == 200
    assert payload["service"] == "silentguard"


def test_connections_endpoint_returns_items_list(api_server, monkeypatch) -> None:
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: [])
    host, port = api_server

    status, _, payload = _get_json(host, port, "/connections")

    assert status == 200
    assert payload == {"items": []}


def test_connections_summary_endpoint_returns_compact_summary(
    api_server, monkeypatch
) -> None:
    fake = [
        monitor.ConnectionInfo(
            process_name="firefox",
            pid=1234,
            remote_ip="8.8.8.8",
            remote_port=443,
            status="ESTABLISHED",
            trust="Known",
        ),
        monitor.ConnectionInfo(
            process_name="curl",
            pid=5678,
            remote_ip="93.184.216.34",
            remote_port=443,
            status="ESTABLISHED",
            trust="Unknown",
        ),
        monitor.ConnectionInfo(
            process_name="ssh",
            pid=900,
            remote_ip="9.9.9.9",
            remote_port=22,
            status="ESTABLISHED",
            trust="Trusted",
        ),
        monitor.ConnectionInfo(
            process_name="systemd",
            pid=1,
            remote_ip="127.0.0.1",
            remote_port=53,
            status="ESTABLISHED",
            trust="Local",
        ),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)
    host, port = api_server

    status, _, payload = _get_json(host, port, "/connections/summary")

    assert status == 200
    assert payload["total"] == 4
    assert payload["local"] == 1
    assert payload["known"] == 1
    assert payload["unknown"] == 1
    assert payload["trusted"] == 1
    assert payload["blocked"] == 0
    assert isinstance(payload["recent_unknown"], list)
    assert {bucket["process"] for bucket in payload["by_process"]} == {
        "firefox",
        "curl",
        "ssh",
        "systemd",
    }
    remote_ips = {host_entry["ip"] for host_entry in payload["top_remote_hosts"]}
    assert remote_ips == {"8.8.8.8", "93.184.216.34", "9.9.9.9"}
    recent_ips = {entry["ip"] for entry in payload["recent_unknown"]}
    assert recent_ips == {"93.184.216.34"}


def test_connections_summary_endpoint_empty(api_server, monkeypatch) -> None:
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: [])
    host, port = api_server

    status, _, payload = _get_json(host, port, "/connections/summary")

    assert status == 200
    assert payload["total"] == 0
    assert payload["by_process"] == []
    assert payload["top_remote_hosts"] == []
    assert "status" not in payload


def test_blocked_endpoint_with_no_rules(api_server, tmp_path, monkeypatch) -> None:
    rules_file = tmp_path / "rules.json"
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)
    host, port = api_server

    status, _, payload = _get_json(host, port, "/blocked")

    assert status == 200
    assert payload == {"items": []}


def test_trusted_endpoint_with_no_rules(api_server, tmp_path, monkeypatch) -> None:
    rules_file = tmp_path / "rules.json"
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)
    host, port = api_server

    status, _, payload = _get_json(host, port, "/trusted")

    assert status == 200
    assert payload == {"items": []}


def test_alerts_endpoint_empty_when_no_connections(api_server, monkeypatch) -> None:
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: [])
    host, port = api_server

    status, _, payload = _get_json(host, port, "/alerts")

    assert status == 200
    assert payload == {"items": []}


def test_alerts_endpoint_returns_alerts_when_threshold_exceeded(
    api_server, monkeypatch
) -> None:
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
    host, port = api_server

    status, _, payload = _get_json(host, port, "/alerts")

    assert status == 200
    flood_alerts = [
        item for item in payload["items"]
        if item["type"] == detection.ALERT_TYPE_POSSIBLE_FLOOD
    ]
    assert len(flood_alerts) == 1
    assert flood_alerts[0]["severity"] == detection.SEVERITY_MEDIUM
    assert flood_alerts[0]["source_ip"] == "203.0.113.10"


def test_alerts_summary_endpoint_returns_zeroed_when_no_alerts(
    api_server, monkeypatch
) -> None:
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: [])
    host, port = api_server

    status, _, payload = _get_json(host, port, "/alerts/summary")

    assert status == 200
    assert payload["total"] == 0
    assert payload["highest_severity"] is None
    assert all(count == 0 for count in payload["by_severity"].values())


def test_recent_unknown_endpoint_returns_empty_when_cache_missing(api_server) -> None:
    host, port = api_server

    status, _, payload = _get_json(host, port, "/connections/recent-unknown")

    assert status == 200
    assert payload == {"items": []}


def test_recent_unknown_endpoint_lists_persisted_destinations(
    api_server, monkeypatch
) -> None:
    fake = [
        monitor.ConnectionInfo(
            process_name="firefox",
            pid=4242,
            remote_ip="93.184.216.34",
            remote_port=443,
            status="ESTABLISHED",
            trust="Unknown",
        ),
    ]
    monkeypatch.setattr(handlers, "get_outgoing_connections", lambda: fake)
    host, port = api_server

    # Hit /connections/summary so the cache gets populated through the
    # documented sync path, then read via the dedicated endpoint.
    _get_json(host, port, "/connections/summary")
    status, _, payload = _get_json(host, port, "/connections/recent-unknown")

    assert status == 200
    assert len(payload["items"]) == 1
    item = payload["items"][0]
    assert item["ip"] == "93.184.216.34"
    assert item["process"] == "firefox"
    assert item["classification"] == "unknown"
    # PID and ports are intentionally not surfaced.
    assert "pid" not in item
    assert "remote_port" not in item


def test_unknown_endpoint_returns_404(api_server) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(host, port, "/does-not-exist")

    assert excinfo.value.code == 404
    body = json.loads(excinfo.value.read().decode("utf-8"))
    assert body["error"] == "not_found"


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_write_methods_are_rejected(api_server, method: str) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(host, port, "/status", method=method)

    assert excinfo.value.code == 405
    assert excinfo.value.headers.get("Allow") == "GET"
    body = json.loads(excinfo.value.read().decode("utf-8"))
    assert body["error"] == "method_not_allowed"


def test_server_binds_to_loopback_by_default() -> None:
    server = create_server(port=0)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


def test_internal_error_is_returned_as_500(api_server, monkeypatch) -> None:
    def boom() -> dict:
        raise RuntimeError("kaboom")

    monkeypatch.setitem(
        __import__("silentguard.api.server", fromlist=["ROUTES"]).ROUTES,
        "/status",
        boom,
    )
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(host, port, "/status")

    assert excinfo.value.code == 500
    body = json.loads(excinfo.value.read().decode("utf-8"))
    assert body["error"] == "internal_error"


def test_api_module_can_be_imported_without_starting_server() -> None:
    """The TUI/GUI must keep working without anyone touching the API."""
    import importlib

    api = importlib.import_module("silentguard.api")

    assert hasattr(api, "create_server")
    assert hasattr(api, "run_server")
    assert api.DEFAULT_HOST == "127.0.0.1"


def test_tui_module_imports_without_api(monkeypatch) -> None:
    """Importing the TUI must not require or start the API server."""
    import importlib
    import sys

    for name in list(sys.modules):
        if name.startswith("silentguard.api"):
            sys.modules.pop(name, None)
    sys.modules.pop("silentguard.tui", None)

    try:
        importlib.import_module("silentguard.tui")
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("textual"):
            pytest.skip("textual not installed in this environment")
        raise

    assert "silentguard.api" not in sys.modules
