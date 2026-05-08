"""SilentGuard read-only local API foundation.

This sub-package exposes a minimal local-only HTTP API that surfaces
SilentGuard state for future integrations (notably Nova) to consume.

Design constraints:

* The API is read-only. No endpoint mutates rules, memory, processes,
  the firewall, or any other system state.
* The server binds to ``127.0.0.1`` by default and is opt-in: the TUI
  and GUI continue to function whether or not the API is started.
* Handlers operate on plain Python dicts, decoupled from HTTP transport,
  so the response schemas can be reused or tested without a network.
* No external dependencies: only the Python standard library is used.
"""

from silentguard.api.server import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    ReadOnlyAPIHandler,
    create_server,
    run_server,
)

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "ReadOnlyAPIHandler",
    "create_server",
    "run_server",
]
