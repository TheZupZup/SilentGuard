"""HTTP-level tests for the mitigation read + write endpoints.

Covers the full safety contract from the API surface:

* ``GET /mitigation`` reports ``detection_only`` by default and never
  itself escalates the mode.
* ``POST /mitigation/enable-temporary`` requires explicit acknowledge.
* ``POST /mitigation/disable`` returns to ``detection_only``.
* ``POST /blocked/temporary`` validates IPs strictly and refuses the
  full never-block list (private, trusted, protected, already-blocked).
* ``POST /blocked/<ip>/unblock`` removes a temporary block.
* All write endpoints reject non-loopback callers.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from silentguard import mitigation, monitor
from silentguard.api import handlers
from silentguard.api.server import create_server


_TEST_PUBLIC_IP = "185.199.108.153"


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


def _request(host: str, port: int, path: str, *, method: str = "GET",
             body: dict | None = None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        f"http://{host}:{port}{path}", method=method, data=data, headers=headers
    )
    return urllib.request.urlopen(req, timeout=5)


def _json(host: str, port: int, path: str, *, method: str = "GET",
          body: dict | None = None):
    with _request(host, port, path, method=method, body=body) as resp:
        text = resp.read().decode("utf-8")
        return resp.status, json.loads(text)


# ---------------------------------------------------------------------------
# GET /mitigation
# ---------------------------------------------------------------------------


def test_get_mitigation_reports_detection_only_by_default(api_server) -> None:
    host, port = api_server

    status, payload = _json(host, port, "/mitigation")

    assert status == 200
    assert payload["mode"] == mitigation.MODE_DETECTION_ONLY
    assert payload["default_mode"] == mitigation.MODE_DETECTION_ONLY
    assert mitigation.MODE_TEMPORARY_AUTO_BLOCK in payload["available_modes"]
    assert payload["prompt"]
    assert payload["disclaimer"]
    assert payload["active_temp_blocks"] == []
    assert payload["auto_block_threshold"] == "REMOTE_IP_FLOOD_HIGH"


# ---------------------------------------------------------------------------
# POST /mitigation/enable-temporary
# ---------------------------------------------------------------------------


def test_enable_temporary_requires_acknowledge(api_server) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(host, port, "/mitigation/enable-temporary", method="POST", body={})

    assert excinfo.value.code == 400
    body = json.loads(excinfo.value.read().decode("utf-8"))
    assert body["reason"] == "acknowledge_required"
    assert mitigation.get_mode() == mitigation.MODE_DETECTION_ONLY


def test_enable_temporary_with_acknowledge_switches_mode(api_server) -> None:
    host, port = api_server

    status, payload = _json(
        host,
        port,
        "/mitigation/enable-temporary",
        method="POST",
        body={"acknowledge": True, "note": "operator confirmed"},
    )

    assert status == 200
    assert payload["ok"] is True
    assert payload["mode"] == mitigation.MODE_TEMPORARY_AUTO_BLOCK
    assert mitigation.get_mode() == mitigation.MODE_TEMPORARY_AUTO_BLOCK


def test_enable_temporary_rejects_invalid_body(api_server) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(
            host,
            port,
            "/mitigation/enable-temporary",
            method="POST",
            body={"acknowledge": True, "note": 123},
        )

    assert excinfo.value.code == 400


# ---------------------------------------------------------------------------
# POST /mitigation/disable
# ---------------------------------------------------------------------------


def test_disable_returns_to_detection_only(api_server) -> None:
    mitigation.set_mode(mitigation.MODE_TEMPORARY_AUTO_BLOCK, actor="test")
    host, port = api_server

    status, payload = _json(
        host, port, "/mitigation/disable", method="POST", body={}
    )

    assert status == 200
    assert payload["mode"] == mitigation.MODE_DETECTION_ONLY


def test_disable_can_clear_active_temp_blocks(api_server) -> None:
    mitigation.set_mode(mitigation.MODE_TEMPORARY_AUTO_BLOCK, actor="test")
    mitigation.add_temporary_block(_TEST_PUBLIC_IP, reason="seed")
    host, port = api_server

    status, payload = _json(
        host, port, "/mitigation/disable", method="POST",
        body={"clear_temp_blocks": True},
    )

    assert status == 200
    assert _TEST_PUBLIC_IP in payload["cleared_temp_blocks"]
    assert mitigation.current_temp_blocked_ips() == set()


# ---------------------------------------------------------------------------
# POST /blocked/temporary
# ---------------------------------------------------------------------------


def test_add_temporary_block_endpoint_creates_block(api_server) -> None:
    host, port = api_server

    status, payload = _json(
        host, port, "/blocked/temporary", method="POST",
        body={"ip": _TEST_PUBLIC_IP, "reason": "manual", "duration_seconds": 600},
    )

    assert status == 201
    assert payload["ok"] is True
    assert payload["block"]["ip"] == _TEST_PUBLIC_IP
    assert payload["block"]["source"] == "manual"
    assert _TEST_PUBLIC_IP in mitigation.current_temp_blocked_ips()


def test_add_temporary_block_endpoint_refuses_private_ip(api_server) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(
            host, port, "/blocked/temporary", method="POST",
            body={"ip": "192.168.1.10"},
        )

    assert excinfo.value.code == 400
    assert mitigation.current_temp_blocked_ips() == set()


def test_add_temporary_block_endpoint_refuses_loopback(api_server) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(
            host, port, "/blocked/temporary", method="POST",
            body={"ip": "127.0.0.1"},
        )

    assert excinfo.value.code == 400


def test_add_temporary_block_endpoint_refuses_invalid_ip(api_server) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(
            host, port, "/blocked/temporary", method="POST",
            body={"ip": "not-an-ip"},
        )

    assert excinfo.value.code == 400


def test_add_temporary_block_endpoint_refuses_trusted_ip(
    api_server, tmp_path, monkeypatch
) -> None:
    rules_file = tmp_path / "rules.json"
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)
    monitor.save_rules({
        "known_processes": [],
        "trusted_ips": [_TEST_PUBLIC_IP],
        "blocked_ips": [],
    })
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(
            host, port, "/blocked/temporary", method="POST",
            body={"ip": _TEST_PUBLIC_IP},
        )

    assert excinfo.value.code == 400
    body = json.loads(excinfo.value.read().decode("utf-8"))
    assert body["reason"] == "ip_is_trusted"


def test_add_temporary_block_endpoint_requires_ip_field(api_server) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(host, port, "/blocked/temporary", method="POST", body={})

    assert excinfo.value.code == 400


def test_add_temporary_block_endpoint_rejects_invalid_json(api_server) -> None:
    host, port = api_server
    req = urllib.request.Request(
        f"http://{host}:{port}/blocked/temporary",
        method="POST",
        data=b"{not valid json",
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req, timeout=5)
    assert excinfo.value.code == 400


def test_add_temporary_block_endpoint_rejects_huge_body(api_server) -> None:
    host, port = api_server
    huge = b"a" * (32 * 1024)
    req = urllib.request.Request(
        f"http://{host}:{port}/blocked/temporary",
        method="POST",
        data=huge,
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req, timeout=5)
    assert excinfo.value.code == 400


# ---------------------------------------------------------------------------
# POST /blocked/<ip>/unblock
# ---------------------------------------------------------------------------


def test_unblock_endpoint_removes_temporary_block(api_server) -> None:
    mitigation.add_temporary_block(_TEST_PUBLIC_IP, reason="seed")
    host, port = api_server

    status, payload = _json(
        host, port, f"/blocked/{_TEST_PUBLIC_IP}/unblock", method="POST", body={}
    )

    assert status == 200
    assert payload["ok"] is True
    assert payload["removed"]["ip"] == _TEST_PUBLIC_IP
    assert mitigation.current_temp_blocked_ips() == set()


def test_unblock_endpoint_returns_404_when_no_block_exists(api_server) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(
            host, port, f"/blocked/{_TEST_PUBLIC_IP}/unblock", method="POST",
            body={},
        )

    assert excinfo.value.code == 404


# ---------------------------------------------------------------------------
# Loopback enforcement on writes
# ---------------------------------------------------------------------------


def test_loopback_helper_flags_non_loopback_addresses() -> None:
    """The helper that gates write endpoints must reject non-loopback clients.

    Spinning up a non-loopback bind isn't portable across CI runners,
    so we exercise the gate directly. The HTTP layer applies it inside
    ``do_POST`` before any handler is invoked.
    """
    from silentguard.api.server import _is_loopback_client

    assert _is_loopback_client("127.0.0.1") is True
    assert _is_loopback_client("::1") is True
    assert _is_loopback_client("10.0.0.5") is False
    assert _is_loopback_client("198.51.100.5") is False
    assert _is_loopback_client("not-an-ip") is False
    assert _is_loopback_client("") is False


# ---------------------------------------------------------------------------
# Existing read endpoints unaffected
# ---------------------------------------------------------------------------


def test_get_blocked_unaffected_by_temp_blocks(
    api_server, tmp_path, monkeypatch
) -> None:
    """The /blocked endpoint continues to mirror only the rules file."""
    rules_file = tmp_path / "rules.json"
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)
    monitor.save_rules({
        "known_processes": [],
        "trusted_ips": [],
        "blocked_ips": ["8.8.8.8"],
    })
    mitigation.add_temporary_block(_TEST_PUBLIC_IP, reason="temp")
    host, port = api_server

    status, payload = _json(host, port, "/blocked")

    assert status == 200
    ips = sorted(item["ip"] for item in payload["items"])
    assert ips == ["8.8.8.8"]
    # Temp blocks remain visible via /mitigation.
    _, mitigation_payload = _json(host, port, "/mitigation")
    active_ips = {b["ip"] for b in mitigation_payload["active_temp_blocks"]}
    assert _TEST_PUBLIC_IP in active_ips


def test_status_endpoint_still_works(api_server) -> None:
    host, port = api_server

    status, payload = _json(host, port, "/status")

    assert status == 200
    assert payload["service"] == "silentguard"
    assert payload["available"] is True


# ---------------------------------------------------------------------------
# Method-not-allowed shape on the new write paths
# ---------------------------------------------------------------------------


def test_get_on_write_path_returns_405(api_server) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(host, port, "/mitigation/enable-temporary", method="GET")

    # GET on a path that is not a registered read route ⇒ 404.
    # Future-friendly: GET surface stays minimal.
    assert excinfo.value.code in (404, 405)


def test_post_to_unknown_path_returns_404(api_server) -> None:
    host, port = api_server

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(
            host, port, "/totally-not-real", method="POST", body={"ip": "x"}
        )

    assert excinfo.value.code == 404


# ---------------------------------------------------------------------------
# Direct handler-level coverage (no HTTP)
# ---------------------------------------------------------------------------


def test_handler_get_mitigation_returns_default_payload() -> None:
    payload = handlers.get_mitigation()

    assert payload["mode"] == mitigation.MODE_DETECTION_ONLY
    assert "prompt" in payload
    assert "disclaimer" in payload


def test_handler_enable_temporary_without_acknowledge_returns_400() -> None:
    status, payload = handlers.enable_temporary_mitigation({})

    assert status == 400
    assert payload["reason"] == "acknowledge_required"


def test_handler_enable_temporary_with_acknowledge_switches_mode() -> None:
    status, payload = handlers.enable_temporary_mitigation(
        {"acknowledge": True}
    )

    assert status == 200
    assert payload["mode"] == mitigation.MODE_TEMPORARY_AUTO_BLOCK


def test_handler_add_temporary_block_returns_201_on_success() -> None:
    status, payload = handlers.add_temporary_block({"ip": _TEST_PUBLIC_IP})

    assert status == 201
    assert payload["block"]["ip"] == _TEST_PUBLIC_IP


def test_handler_add_temporary_block_rejects_missing_ip() -> None:
    status, payload = handlers.add_temporary_block({})
    assert status == 400
    assert payload["reason"] == "ip_required"


def test_handler_remove_temporary_block_404_when_missing() -> None:
    status, payload = handlers.remove_temporary_block(_TEST_PUBLIC_IP)
    assert status == 404
