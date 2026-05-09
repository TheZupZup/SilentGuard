"""Test-wide fixtures.

The tests should never read or write the user's real
``~/.silentguard_unknown.json``. We redirect the connection-state cache
to a per-test temp file via an autouse fixture so any handler/monitor
code path that calls :func:`silentguard.connection_state.record_connections`
during a test stays isolated.
"""

from __future__ import annotations

import pytest

from silentguard import connection_state


@pytest.fixture(autouse=True)
def _isolate_unknown_destinations_cache(tmp_path, monkeypatch):
    cache_file = tmp_path / "silentguard_unknown.json"
    monkeypatch.setattr(
        connection_state, "UNKNOWN_DESTINATIONS_FILE", cache_file
    )
    yield cache_file
