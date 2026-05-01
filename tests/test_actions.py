import psutil
import pytest

from silentguard.actions import kill_process


def test_kill_process_invalid_pid_zero():
    ok, msg = kill_process(0)
    assert ok is False
    assert "Invalid PID" in msg


def test_kill_process_invalid_pid_negative():
    ok, msg = kill_process(-5)
    assert ok is False
    assert "Invalid PID" in msg


def test_kill_process_success(monkeypatch):
    terminated = []

    class FakeProcess:
        def __init__(self, pid):
            self.pid = pid

        def terminate(self):
            terminated.append(self.pid)

    monkeypatch.setattr(psutil, "Process", FakeProcess)
    ok, msg = kill_process(1234)
    assert ok is True
    assert "1234" in msg
    assert "SIGTERM" in msg
    assert terminated == [1234]


def test_kill_process_no_such_process(monkeypatch):
    class FakeProcess:
        def __init__(self, pid):
            pass

        def terminate(self):
            raise psutil.NoSuchProcess(pid=1234)

    monkeypatch.setattr(psutil, "Process", FakeProcess)
    ok, msg = kill_process(1234)
    assert ok is False
    assert "no longer exists" in msg


def test_kill_process_access_denied(monkeypatch):
    class FakeProcess:
        def __init__(self, pid):
            pass

        def terminate(self):
            raise psutil.AccessDenied(pid=1234)

    monkeypatch.setattr(psutil, "Process", FakeProcess)
    ok, msg = kill_process(1234)
    assert ok is False
    assert "Permission denied" in msg
    assert "sudo" in msg


def test_kill_process_zombie(monkeypatch):
    class FakeProcess:
        def __init__(self, pid):
            pass

        def terminate(self):
            raise psutil.ZombieProcess(pid=1234)

    monkeypatch.setattr(psutil, "Process", FakeProcess)
    ok, msg = kill_process(1234)
    assert ok is False
    assert "zombie" in msg
