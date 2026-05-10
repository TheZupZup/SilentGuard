"""Local-only HTTP server for SilentGuard.

The server uses only the Python standard library so the API foundation
does not introduce new runtime dependencies. It is optional and must be
started explicitly (for example via the ``silentguard-api`` console
script); the TUI and GUI continue to work whether or not the API is
running.

Security posture:

* Binds to ``127.0.0.1`` by default. Non-loopback hosts are accepted as
  a deliberate operator override, but the default keeps the API local
  and **write endpoints refuse non-loopback callers regardless of the
  bind address.**
* Read endpoints (``GET``) expose only safe summaries.
* Write endpoints (``POST``) are narrow and only cover the human-approved
  flood mitigation surface. Each one validates inputs strictly, refuses
  private/local/trusted/protected IPs through the mitigation policy
  module, and returns clear JSON.
* No shell calls, no firewall changes, no autonomous blocking.
* No external network calls and no telemetry.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from silentguard.api import handlers

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

MAX_REQUEST_BODY_BYTES = 16 * 1024

LOGGER = logging.getLogger(__name__)

ReadRoute = Callable[[], dict[str, Any]]
WriteRoute = Callable[[dict | None], tuple[int, dict[str, Any]]]

ROUTES: dict[str, ReadRoute] = {
    "/status": handlers.get_status,
    "/connections": handlers.get_connections,
    "/connections/summary": handlers.get_connections_summary,
    "/connections/recent-unknown": handlers.get_recent_unknown,
    "/blocked": handlers.get_blocked,
    "/trusted": handlers.get_trusted,
    "/alerts": handlers.get_alerts,
    "/alerts/summary": handlers.get_alerts_summary,
    "/events": handlers.get_events,
    "/events/summary": handlers.get_events_summary,
    "/mitigation": handlers.get_mitigation,
}

WRITE_ROUTES: dict[str, WriteRoute] = {
    "/mitigation/enable-temporary": handlers.enable_temporary_mitigation,
    "/mitigation/disable": handlers.disable_mitigation,
    "/blocked/temporary": handlers.add_temporary_block,
}

# Dynamic write routes accept a parameter from the path. The server
# matches them by regex and forwards the captured group to the handler.
# Kept tiny on purpose: each entry is a hand-audited unblock surface.
_UNBLOCK_PATH_RE = re.compile(r"^/blocked/(?P<ip>[^/]+)/unblock$")


def _normalize_path(raw_path: str) -> str:
    path = raw_path.split("?", 1)[0].split("#", 1)[0]
    if path != "/":
        path = path.rstrip("/")
    return path


def _resolve_route(raw_path: str) -> ReadRoute | None:
    path = _normalize_path(raw_path)
    if path in ("", "/"):
        return ROUTES["/status"]
    return ROUTES.get(path)


def _resolve_write_route(raw_path: str) -> tuple[WriteRoute, dict[str, str]] | None:
    path = _normalize_path(raw_path)
    if path in WRITE_ROUTES:
        return WRITE_ROUTES[path], {}
    match = _UNBLOCK_PATH_RE.match(path)
    if match:
        return (
            lambda body: handlers.remove_temporary_block(match.group("ip")),
            {"ip": match.group("ip")},
        )
    return None


def _is_loopback_client(client_address: str) -> bool:
    """Return ``True`` only when ``client_address`` is on the loopback."""
    if not client_address:
        return False
    try:
        addr = ipaddress.ip_address(client_address)
    except ValueError:
        return False
    return addr.is_loopback


class ReadOnlyAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler.

    The class name is preserved for backward compatibility with the
    earlier read-only-only design. Despite the name, write endpoints
    are now also routed through this handler — they are **narrow,
    audited, loopback-only, and gated by the mitigation policy module**
    (see :mod:`silentguard.mitigation`).
    """

    server_version = "SilentGuard-API/2"

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        route = _resolve_route(self.path)
        if route is None:
            self._write_json(404, {"error": "not_found", "path": self.path})
            return

        try:
            payload = route()
        except Exception:
            LOGGER.exception("Unhandled error in API route %s", self.path)
            self._write_json(500, {"error": "internal_error"})
            return

        self._write_json(200, payload)

    def do_POST(self) -> None:  # noqa: N802
        match = _resolve_write_route(self.path)
        if match is None:
            self._method_not_allowed_for_get_only_path()
            return

        if not _is_loopback_client(self.client_address[0]):
            self._write_json(
                403,
                {
                    "error": "forbidden",
                    "reason": "loopback_only",
                    "message": (
                        "Mitigation write endpoints accept loopback "
                        "callers only. Use 127.0.0.1 / ::1."
                    ),
                },
            )
            return

        body, body_error = self._read_json_body()
        if body_error is not None:
            self._write_json(400, body_error)
            return

        route, _ = match
        try:
            status, payload = route(body)
        except Exception:
            LOGGER.exception("Unhandled error in API write route %s", self.path)
            self._write_json(500, {"error": "internal_error"})
            return

        self._write_json(status, payload)

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed_for_get_only_path()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed_for_get_only_path()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed_for_get_only_path()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_json_body(self) -> tuple[dict | None, dict[str, Any] | None]:
        """Parse a small JSON body. Returns ``(body, error_payload)``."""
        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header) if length_header is not None else 0
        except ValueError:
            return None, {"error": "bad_request", "reason": "invalid_content_length"}
        if length < 0:
            return None, {"error": "bad_request", "reason": "invalid_content_length"}
        if length > MAX_REQUEST_BODY_BYTES:
            return None, {"error": "bad_request", "reason": "body_too_large"}
        if length == 0:
            return {}, None

        raw = self.rfile.read(length)
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None, {"error": "bad_request", "reason": "invalid_utf8"}
        try:
            data = json.loads(decoded)
        except json.JSONDecodeError:
            return None, {"error": "bad_request", "reason": "invalid_json"}
        if not isinstance(data, dict):
            return None, {"error": "bad_request", "reason": "json_object_required"}
        return data, None

    def _method_not_allowed_for_get_only_path(self) -> None:
        # The path is either unknown, or known as a read-only path that
        # does not accept this method.
        path = _normalize_path(self.path)
        if path in ROUTES or path in ("", "/"):
            self._write_json(
                405,
                {"error": "method_not_allowed", "allowed": ["GET"]},
                extra_headers={"Allow": "GET"},
            )
            return
        if _resolve_write_route(path) is not None:
            self._write_json(
                405,
                {"error": "method_not_allowed", "allowed": ["POST"]},
                extra_headers={"Allow": "POST"},
            )
            return
        self._write_json(404, {"error": "not_found", "path": self.path})

    def _write_json(
        self,
        status: int,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for header, value in (extra_headers or {}).items():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        LOGGER.debug("%s - %s", self.address_string(), format % args)


def create_server(
    host: str = DEFAULT_HOST, port: int = DEFAULT_PORT
) -> ThreadingHTTPServer:
    """Create (but do not start) a SilentGuard API server.

    Pass ``port=0`` to let the OS pick an available port (useful for
    tests). The returned server can be started with ``serve_forever()``
    and stopped with ``shutdown()``/``server_close()``.
    """
    return ThreadingHTTPServer((host, port), ReadOnlyAPIHandler)


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    server = create_server(host, port)
    bound_host, bound_port = server.server_address[:2]
    LOGGER.info(
        "SilentGuard API listening on http://%s:%d "
        "(read endpoints + loopback-only mitigation write endpoints)",
        bound_host,
        bound_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("SilentGuard API received shutdown signal")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="silentguard-api",
        description=(
            "Start the SilentGuard local API. "
            "Read endpoints expose safe JSON summaries. The narrow set "
            "of POST endpoints is loopback-only and only covers the "
            "opt-in flood mitigation flow."
        ),
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=(
            "Host/IP to bind to (default: 127.0.0.1). Keep the default unless "
            "you fully understand the implications of exposing the API. "
            "Mitigation write endpoints refuse non-loopback callers even when "
            "the bind address is broader."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to bind to (default: {DEFAULT_PORT}).",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
