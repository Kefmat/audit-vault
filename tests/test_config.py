"""Unit tests for config.py configuration logic."""

import os
import unittest
from unittest.mock import patch
from src.config import load_config, ConfigError


class TestConfig(unittest.TestCase):

    @patch.dict(os.environ, {"PORT": "9090", "STORAGE_DRIVER": "file", "VAULT_FILE_PATH": "test.jsonl", "API_TOKEN": "token"})
    def test_valid_config(self):
        config = load_config()
        self.assertEqual(config.port, 9090)
        self.assertEqual(config.storage_driver, "file")
        self.assertEqual(config.vault_file_path, "test.jsonl")
        self.assertEqual(config.api_token, "token")

    @patch.dict(os.environ, {"PORT": "invalid"})
    def test_invalid_port(self):
        with self.assertRaises(ConfigError):
            load_config()

    @patch.dict(os.environ, {"STORAGE_DRIVER": "unsupported"})
    def test_invalid_storage_driver(self):
        with self.assertRaises(ConfigError):
            load_config()


if __name__ == "__main__":
    unittest.main()
