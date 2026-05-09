"""Test-wide fixtures.

The tests should never read or write the user's real local files. We
redirect the connection-state cache and the mitigation state/audit
files to per-test temp files via autouse fixtures so any handler or
monitor code path that touches them during a test stays isolated.
"""

from __future__ import annotations

import pytest

from silentguard import connection_state, mitigation


@pytest.fixture(autouse=True)
def _isolate_unknown_destinations_cache(tmp_path, monkeypatch):
    cache_file = tmp_path / "silentguard_unknown.json"
    monkeypatch.setattr(
        connection_state, "UNKNOWN_DESTINATIONS_FILE", cache_file
    )
    yield cache_file


@pytest.fixture(autouse=True)
def _isolate_mitigation_files(tmp_path, monkeypatch):
    state_file = tmp_path / "silentguard_mitigation.json"
    audit_file = tmp_path / "silentguard_mitigation_audit.json"
    monkeypatch.setattr(mitigation, "MITIGATION_FILE", state_file)
    monkeypatch.setattr(mitigation, "AUDIT_FILE", audit_file)
    yield state_file, audit_file
