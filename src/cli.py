"""Command Line Interface for Audit Vault offline verification."""

import argparse
import sys
import os

# Ensure root workspace directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.storage.file import FileVaultStorage


def main():
    parser = argparse.ArgumentParser(description="Audit Vault local utility tool.")
    parser.add_argument(
        "--version",
        action="version",
        version="Audit Vault 1.0.0"
    )
    parser.add_argument(
        "--file",
        default="vault_log.jsonl",
        help="Path to the JSONL log file to verify (default: vault_log.jsonl)"
    )

    args = parser.parse_args()

    print(f"Verifying vault integrity of '{args.file}'...")
    try:
        storage = FileVaultStorage(filepath=args.file)
        result = storage.verify_integrity()

        if result.valid:
            print(f"Success: {result.message}")
            print(f"Total events verified: {result.total_events}")
            print(f"Merkle root: {result.merkle_root}")
            sys.exit(0)
        else:
            print(f"Verification Failed: {result.message}")
            if result.tampered_event_id:
                print(f"Tampered Event ID: {result.tampered_event_id}")
            sys.exit(1)
    except Exception as e:
        print(f"Error during verification: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
