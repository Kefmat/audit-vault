"""Append-only file storage driver for Audit Vault."""

import json
import os
from typing import List, Optional, Dict
from src.storage.base import VaultStorage
from src.types import AuditEvent, VerificationResult
from src.hasher import compute_event_hash
from src.merkle import MerkleTree


class FileVaultStorage(VaultStorage):

    def __init__(self, filepath: str = "vault_log.jsonl"):
        self.filepath = filepath
        self._events: List[AuditEvent] = []
        self._event_index: Dict[str, AuditEvent] = {}
        self._load_from_file()

    def _load_from_file(self) -> None:
        self._events = []
        self._event_index = {}
        if not os.path.exists(self.filepath):
            return

        with open(self.filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                event = AuditEvent.from_dict(data)
                self._events.append(event)
                self._event_index[event.event_id] = event

    def append_event(self, event: AuditEvent) -> AuditEvent:
        if self._events:
            event.previous_hash = self._events[-1].hash
        else:
            event.previous_hash = "GENESIS_BLOCK_PREVIOUS_HASH"

        event.hash = compute_event_hash(event)
        self._events.append(event)
        self._event_index[event.event_id] = event

        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict()) + "\n")

        return event

    def get_all_events(self) -> List[AuditEvent]:
        return list(self._events)

    def get_event_by_id(self, event_id: str) -> Optional[AuditEvent]:
        return self._event_index.get(event_id)

    def verify_integrity(self) -> VerificationResult:
        self._load_from_file()

        if not self._events:
            return VerificationResult(
                valid=True,
                total_events=0,
                merkle_root="",
                message="Vault is empty."
            )

        expected_prev_hash = "GENESIS_BLOCK_PREVIOUS_HASH"
        hashes = []

        for idx, event in enumerate(self._events):
            if event.previous_hash != expected_prev_hash:
                return VerificationResult(
                    valid=False,
                    total_events=len(self._events),
                    merkle_root="",
                    message=f"Broken hash chain at event index {idx}.",
                    tampered_event_id=event.event_id
                )

            computed_hash = compute_event_hash(event)
            if event.hash != computed_hash:
                return VerificationResult(
                    valid=False,
                    total_events=len(self._events),
                    merkle_root="",
                    message=f"Tampered hash detected at event index {idx}.",
                    tampered_event_id=event.event_id
                )

            hashes.append(event.hash)
            expected_prev_hash = event.hash

        tree = MerkleTree(hashes)

        return VerificationResult(
            valid=True,
            total_events=len(self._events),
            merkle_root=tree.root,
            message="Vault integrity verified. Chain and Merkle root intact."
        )
