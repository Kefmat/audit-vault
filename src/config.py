"""Configuration settings and validation for Audit Vault."""

import os
from typing import Optional


class ConfigError(Exception):
    """Exception raised for errors in the configuration."""
    pass


class Config:
    """Configuration storage class that holds application settings parsed from environment variables."""

    def __init__(self):
        self.host = os.environ.get("HOST", "0.0.0.0")
        self.port_str = os.environ.get("PORT", "8080")
        self.storage_driver = os.environ.get("STORAGE_DRIVER", "memory").lower()
        self.api_token = os.environ.get("API_TOKEN", "dev-api-token-12345")
        self.vault_file_path = os.environ.get("VAULT_FILE_PATH", "vault_log.jsonl")
        self.port = 8080

    def validate(self) -> None:
        """Validates loaded configuration settings, raising ConfigError on validation failures."""
        # Validate Port
        try:
            self.port = int(self.port_str)
            if not (1 <= self.port <= 65535):
                raise ValueError()
        except ValueError:
            raise ConfigError(f"PORT must be a valid integer between 1 and 65535, got '{self.port_str}'")

        # Validate Storage Driver
        if self.storage_driver not in ("memory", "file"):
            raise ConfigError(f"STORAGE_DRIVER must be either 'memory' or 'file', got '{self.storage_driver}'")

        # Validate File Path if storage is file
        if self.storage_driver == "file" and not self.vault_file_path:
            raise ConfigError("VAULT_FILE_PATH must be set when STORAGE_DRIVER is 'file'")

        # Validate Host
        if not self.host.strip():
            raise ConfigError("HOST must not be empty")

        # Validate API Token length/strength (non-empty)
        if not self.api_token.strip():
            raise ConfigError("API_TOKEN must not be empty")


def load_config() -> Config:
    """Loads, validates, and returns the configuration settings."""
    config = Config()
    config.validate()
    return config
