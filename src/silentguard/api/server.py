"""Local-only read-only HTTP server for SilentGuard.

The server intentionally uses only the Python standard library so that
the API foundation does not introduce new runtime dependencies. It is
optional and must be started explicitly (for example via the
``silentguard-api`` console script); the TUI and GUI continue to work
whether or not the API is running.

Security posture:

* Binds to ``127.0.0.1`` by default. Non-loopback hosts are accepted as
  a deliberate operator override, but the default keeps the API local.
* Only ``GET`` is supported. Any other method returns ``405``.
* No shell calls, no firewall changes, no automatic blocking.
* No external network calls and no telemetry.
"""

from __future__ import annotations

import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from silentguard.api import handlers

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

LOGGER = logging.getLogger(__name__)

Route = Callable[[], dict[str, Any]]

ROUTES: dict[str, Route] = {
    "/status": handlers.get_status,
    "/connections": handlers.get_connections,
    "/connections/summary": handlers.get_connections_summary,
    "/connections/recent-unknown": handlers.get_recent_unknown,
    "/blocked": handlers.get_blocked,
    "/trusted": handlers.get_trusted,
    "/alerts": handlers.get_alerts,
}


def _resolve_route(raw_path: str) -> Route | None:
    path = raw_path.split("?", 1)[0].split("#", 1)[0]
    if path != "/":
        path = path.rstrip("/")
    if path in ("", "/"):
        return ROUTES["/status"]
    return ROUTES.get(path)


class ReadOnlyAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler that exposes only read-only GET endpoints."""

    server_version = "SilentGuard-ReadOnly/1"

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
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self._write_json(
            405,
            {"error": "method_not_allowed", "allowed": ["GET"]},
            extra_headers={"Allow": "GET"},
        )

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
    """Create (but do not start) a read-only API server.

    Pass ``port=0`` to let the OS pick an available port (useful for
    tests). The returned server can be started with ``serve_forever()``
    and stopped with ``shutdown()``/``server_close()``.
    """
    return ThreadingHTTPServer((host, port), ReadOnlyAPIHandler)


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    server = create_server(host, port)
    bound_host, bound_port = server.server_address[:2]
    LOGGER.info(
        "SilentGuard read-only API listening on http://%s:%d (mode=read_only)",
        bound_host,
        bound_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("SilentGuard read-only API received shutdown signal")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="silentguard-api",
        description=(
            "Start the SilentGuard read-only local API. "
            "The API exposes safe JSON summaries only and never mutates state."
        ),
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=(
            "Host/IP to bind to (default: 127.0.0.1). Keep the default unless "
            "you fully understand the implications of exposing the API."
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
