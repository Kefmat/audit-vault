"""Unit tests for offline CLI utility."""

import unittest
from unittest.mock import patch, MagicMock
import sys
from src.cli import main
from src.types import VerificationResult


class TestCLI(unittest.TestCase):

    @patch("src.cli.FileVaultStorage")
    @patch("sys.exit")
    @patch("argparse.ArgumentParser.parse_args")
    def test_cli_success(self, mock_parse_args, mock_sys_exit, mock_storage_cls):
        mock_args = MagicMock()
        mock_args.file = "vault_log.jsonl"
        mock_parse_args.return_value = mock_args

        mock_storage = MagicMock()
        mock_storage.verify_integrity.return_value = VerificationResult(
            valid=True,
            total_events=10,
            merkle_root="root123",
            message="All systems operational."
        )
        mock_storage_cls.return_value = mock_storage

        main()

        mock_storage.verify_integrity.assert_called_once()
        mock_sys_exit.assert_called_once_with(0)

    @patch("src.cli.FileVaultStorage")
    @patch("sys.exit")
    @patch("argparse.ArgumentParser.parse_args")
    def test_cli_failure(self, mock_parse_args, mock_sys_exit, mock_storage_cls):
        mock_args = MagicMock()
        mock_args.file = "vault_log.jsonl"
        mock_parse_args.return_value = mock_args

        mock_storage = MagicMock()
        mock_storage.verify_integrity.return_value = VerificationResult(
            valid=False,
            total_events=10,
            merkle_root="",
            message="Broken link.",
            tampered_event_id="evt_xyz"
        )
        mock_storage_cls.return_value = mock_storage

        main()

        mock_sys_exit.assert_called_once_with(1)


if __name__ == "__main__":
    unittest.main()
