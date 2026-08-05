"""Main entry point for starting the Audit Vault server."""

import os
import sys
from dotenv import load_dotenv

# Ensure root workspace directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.storage.memory import MemoryVaultStorage
from src.storage.file import FileVaultStorage
from src.server import create_server


def main():
    load_dotenv()

    port = int(os.environ.get("PORT", 8080))
    storage_driver = os.environ.get("STORAGE_DRIVER", "memory").lower()
    api_token = os.environ.get("API_TOKEN", "dev-api-token-12345")

    if storage_driver == "file":
        filepath = os.environ.get("VAULT_FILE_PATH", "vault_log.jsonl")
        storage = FileVaultStorage(filepath=filepath)
        print(f"[Audit Vault] Initialized file storage driver using '{filepath}'")
    else:
        storage = MemoryVaultStorage()
        print("[Audit Vault] Initialized in-memory storage driver")

    server = create_server("0.0.0.0", port, storage, api_token=api_token)
    print(f"[Audit Vault] Service running on http://0.0.0.0:{port}")
    print(f"[Audit Vault] API Auth Token: {api_token}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Audit Vault] Shutting down server gracefully...")
        server.server_close()


if __name__ == "__main__":
    main()
