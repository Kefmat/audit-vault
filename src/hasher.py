"""Cryptographic hashing utilities for Audit Vault."""

import hashlib
import json
from typing import Any, Dict
from src.types import AuditEvent


def canonical_json(data: Dict[str, Any]) -> str:
    """Returns deterministic JSON string representation with sorted keys."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


def compute_event_hash(event: AuditEvent) -> str:
    """Computes SHA-256 hash of an AuditEvent payload including previous_hash."""
    payload = {
        "event_id": event.event_id,
        "actor": event.actor,
        "action": event.action,
        "target": event.target,
        "metadata": event.metadata,
        "timestamp": event.timestamp,
        "previous_hash": event.previous_hash,
    }
    encoded = canonical_json(payload).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def compute_pair_hash(left_hash: str, right_hash: str) -> str:
    """Computes SHA-256 hash of two node hashes concatenated."""
    combined = (left_hash + right_hash).encode('utf-8')
    return hashlib.sha256(combined).hexdigest()


def hash_string(value: str) -> str:
    """Computes SHA-256 hash of an arbitrary UTF-8 string."""
    return hashlib.sha256(value.encode('utf-8')).hexdigest()
