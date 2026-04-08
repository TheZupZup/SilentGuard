import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from silentguard import monitor


class TestMonitorRules(unittest.TestCase):
    def test_classify_ip_local_and_unknown(self):
        self.assertEqual(monitor.classify_ip("127.0.0.1"), "Local")
        self.assertEqual(monitor.classify_ip("8.8.8.8"), "Unknown")

    def test_determine_trust_priority(self):
        rules = {
            "known_processes": ["python3"],
            "trusted_ips": ["1.1.1.1"],
            "blocked_ips": ["203.0.113.10"],
        }

        self.assertEqual(
            monitor.determine_trust("python3", "203.0.113.10", rules),
            "Blocked",
        )
        self.assertEqual(
            monitor.determine_trust("python3", "1.1.1.1", rules),
            "Known",
        )
        self.assertEqual(
            monitor.determine_trust("python3", "8.8.8.8", rules),
            "Known",
        )

    def test_load_rules_fallback_and_file(self):
        default_rules = monitor.load_rules()
        self.assertIn("known_processes", default_rules)
        self.assertIn("trusted_ips", default_rules)
        self.assertIn("blocked_ips", default_rules)

        with tempfile.TemporaryDirectory() as tmp:
            rule_file = Path(tmp) / "rules.json"
            payload = {
                "known_processes": ["curl"],
                "trusted_ips": ["9.9.9.9"],
                "blocked_ips": ["198.51.100.10"],
            }
            rule_file.write_text(json.dumps(payload), encoding="utf-8")

            with patch.object(monitor, "RULES_FILE", rule_file):
                loaded = monitor.load_rules()

            self.assertEqual(loaded["known_processes"], payload["known_processes"])
            self.assertEqual(loaded["trusted_ips"], payload["trusted_ips"])
            self.assertEqual(loaded["blocked_ips"], payload["blocked_ips"])


if __name__ == "__main__":
    unittest.main()
