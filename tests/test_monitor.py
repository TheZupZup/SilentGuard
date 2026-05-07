from pathlib import Path

import pytest

from silentguard import monitor


def test_classify_ip_variants() -> None:
    assert monitor.classify_ip("127.0.0.1") == "Local"
    assert monitor.classify_ip("192.168.1.10") == "Local"
    assert monitor.classify_ip("8.8.8.8") == "Unknown"


def test_load_rules_fallback_on_invalid_json(tmp_path: Path, monkeypatch) -> None:
    rules_file = tmp_path / "rules.json"
    rules_file.write_text("{invalid-json", encoding="utf-8")
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)

    rules = monitor.load_rules()

    assert rules["blocked_ips"] == []
    assert "python3" in rules["known_processes"]


def test_block_and_unblock_rule_file(tmp_path: Path, monkeypatch) -> None:
    rules_file = tmp_path / "rules.json"
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)

    assert monitor.block_ip_in_rules("8.8.8.8") is True
    assert monitor.block_ip_in_rules("8.8.8.8") is False

    rules = monitor.load_rules()
    assert rules["blocked_ips"] == ["8.8.8.8"]

    assert monitor.unblock_ip_in_rules("8.8.8.8") is True
    assert monitor.unblock_ip_in_rules("8.8.8.8") is False


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2001:4860:4860::8888",
    ],
)
def test_is_blockable_ip_accepts_public_addresses(ip: str) -> None:
    ok, reason = monitor.is_blockable_ip(ip)
    assert ok is True
    assert reason is None


@pytest.mark.parametrize(
    "ip,fragment",
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("10.0.0.1", "local/private"),
        ("172.16.5.4", "local/private"),
        ("192.168.1.1", "local/private"),
        ("169.254.1.1", "link-local"),
        ("224.0.0.1", "multicast"),
        ("ff02::1", "multicast"),
        ("0.0.0.0", "unspecified"),
        ("240.0.0.1", "reserved"),
        ("not-an-ip", "valid IP"),
        ("", "valid IP"),
    ],
)
def test_is_blockable_ip_rejects_unsafe_addresses(ip: str, fragment: str) -> None:
    ok, reason = monitor.is_blockable_ip(ip)
    assert ok is False
    assert reason is not None
    assert fragment in reason


def test_block_ip_in_rules_rejects_local_addresses(
    tmp_path: Path, monkeypatch
) -> None:
    rules_file = tmp_path / "rules.json"
    monkeypatch.setattr(monitor, "RULES_FILE", rules_file)

    for ip in ("127.0.0.1", "192.168.1.10", "169.254.1.1", "224.0.0.1", "bogus"):
        with pytest.raises(ValueError):
            monitor.block_ip_in_rules(ip)

    assert not rules_file.exists()
    assert monitor.load_rules()["blocked_ips"] == []
