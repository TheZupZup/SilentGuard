from pathlib import Path

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

    assert monitor.block_ip_in_rules("203.0.113.10") is True
    assert monitor.block_ip_in_rules("203.0.113.10") is False

    rules = monitor.load_rules()
    assert rules["blocked_ips"] == ["203.0.113.10"]

    assert monitor.unblock_ip_in_rules("203.0.113.10") is True
    assert monitor.unblock_ip_in_rules("203.0.113.10") is False
