import unittest
from unittest.mock import patch

from silentguard.actions import ActionError, block_ip


class TestActions(unittest.TestCase):
    def test_block_ip_invalid_ip_raises(self):
        with self.assertRaises(ActionError):
            block_ip("not-an-ip")

    @patch("silentguard.actions.shutil.which", return_value=None)
    def test_block_ip_without_backend_raises(self, _which):
        with self.assertRaises(ActionError):
            block_ip("8.8.8.8")


if __name__ == "__main__":
    unittest.main()
