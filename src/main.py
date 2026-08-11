"""Main entry point for starting the Audit Vault server."""

import os
import sys
import logging
from dotenv import load_dotenv

# Ensure root workspace directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.storage.memory import MemoryVaultStorage
from src.storage.file import FileVaultStorage
from src.server import create_server
from src.config import load_config, ConfigError


def main():
    load_dotenv()

    # Configure structured logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger("audit-vault")

    try:
        config = load_config()
    except ConfigError as err:
        logger.error(f"Configuration Error: {err}")
        sys.exit(1)

    if config.storage_driver == "file":
        storage = FileVaultStorage(filepath=config.vault_file_path)
        logger.info(f"Initialized file storage driver using '{config.vault_file_path}'")
    else:
        storage = MemoryVaultStorage()
        logger.info("Initialized in-memory storage driver")

    server = create_server(config.host, config.port, storage, api_token=config.api_token)
    logger.info(f"Service running on http://{config.host}:{config.port}")
    logger.info(f"API Auth Token: {config.api_token}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server gracefully...")
        server.server_close()


if __name__ == "__main__":
    main()
