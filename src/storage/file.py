"""Append-only file storage driver for Audit Vault."""

import json
import os
import threading
from typing import List, Optional, Dict
from src.storage.base import VaultStorage, GENESIS_HASH
from src.types import AuditEvent, VerificationResult, MerkleProof
from src.hasher import compute_event_hash
from src.merkle import MerkleTree


class FileVaultStorage(VaultStorage):

    def __init__(self, filepath: str = "vault_log.jsonl"):
        if os.path.exists(filepath) and os.path.isdir(filepath):
            raise ValueError(f"Vault storage filepath '{filepath}' must be a file, not a directory.")
        self.filepath = filepath
        self._events: List[AuditEvent] = []
        self._event_index: Dict[str, AuditEvent] = {}
        self._lock = threading.RLock()
        self._load_from_file()

    def _load_from_file(self) -> None:
        with self._lock:
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
        with self._lock:
            event.validate()
            if self._events:
                event.previous_hash = self._events[-1].hash
            else:
                event.previous_hash = GENESIS_HASH

            event.hash = compute_event_hash(event)
            self._events.append(event)
            self._event_index[event.event_id] = event

            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")

            return event

    def get_all_events(
        self,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[AuditEvent]:
        with self._lock:
            filtered = list(self._events)

        if actor is not None:
            filtered = [e for e in filtered if e.actor == actor]
        if action is not None:
            filtered = [e for e in filtered if e.action == action]
        if since is not None:
            filtered = [e for e in filtered if e.timestamp >= since]
        if until is not None:
            filtered = [e for e in filtered if e.timestamp <= until]

        start = offset if (offset is not None and offset > 0) else 0
        if limit is not None and limit >= 0:
            end = start + limit
            return list(filtered[start:end])
        return list(filtered[start:])

    def get_event_by_id(self, event_id: str) -> Optional[AuditEvent]:
        with self._lock:
            return self._event_index.get(event_id)

    def get_proof_for_event(self, event_id: str) -> Optional[MerkleProof]:
        with self._lock:
            if event_id not in self._event_index:
                return None
            idx = next((i for i, e in enumerate(self._events) if e.event_id == event_id), -1)
            if idx == -1:
                return None
            hashes = [e.hash for e in self._events]
        tree = MerkleTree(hashes)
        return tree.get_proof(idx)

    def verify_integrity(self) -> VerificationResult:
        self._load_from_file()
        with self._lock:
            events_copy = list(self._events)

        if not events_copy:
            return VerificationResult(
                valid=True,
                total_events=0,
                merkle_root="",
                message="Vault is empty."
            )

        expected_prev_hash = GENESIS_HASH
        hashes = []

        for idx, event in enumerate(events_copy):
            if event.previous_hash != expected_prev_hash:
                return VerificationResult(
                    valid=False,
                    total_events=len(events_copy),
                    merkle_root="",
                    message=f"Broken hash chain at event index {idx}.",
                    tampered_event_id=event.event_id
                )

            computed_hash = compute_event_hash(event)
            if event.hash != computed_hash:
                return VerificationResult(
                    valid=False,
                    total_events=len(events_copy),
                    merkle_root="",
                    message=f"Tampered hash detected at event index {idx}.",
                    tampered_event_id=event.event_id
                )

            hashes.append(event.hash)
            expected_prev_hash = event.hash

        tree = MerkleTree(hashes)

        return VerificationResult(
            valid=True,
            total_events=len(events_copy),
            merkle_root=tree.root,
            message="Vault integrity verified. Chain and Merkle root intact."
        )
