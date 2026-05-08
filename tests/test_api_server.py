import json
import threading
import urllib.error
import urllib.request

import pytest

from silentguard import monitor
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


def test_alerts_endpoint(api_server) -> None:
    host, port = api_server

    status, _, payload = _get_json(host, port, "/alerts")

    assert status == 200
    assert payload["items"] == []
    assert payload["status"] == "not_available"


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
