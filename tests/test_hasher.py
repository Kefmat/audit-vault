"""Unit tests for cryptographic hasher utilities."""

import unittest
import hashlib
from src.hasher import (
    canonical_json,
    compute_event_hash,
    compute_pair_hash,
    hash_string,
    compute_genesis_hash,
)
from src.types import AuditEvent


class TestHasher(unittest.TestCase):

    def test_canonical_json_key_sorting(self):
        data1 = {"b": 1, "a": 2, "c": {"z": 10, "y": 20}}
        data2 = {"a": 2, "c": {"y": 20, "z": 10}, "b": 1}
        self.assertEqual(canonical_json(data1), canonical_json(data2))
        self.assertEqual(canonical_json(data1), '{"a":2,"c":{"y":20,"z":10},"b":1}')

    def test_hash_string(self):
        val = "audit-vault-test"
        expected = hashlib.sha256(val.encode("utf-8")).hexdigest()
        self.assertEqual(hash_string(val), expected)

    def test_compute_genesis_hash(self):
        genesis = compute_genesis_hash()
        expected = hashlib.sha256("audit-vault-genesis".encode("utf-8")).hexdigest()
        self.assertEqual(genesis, expected)
        self.assertEqual(len(genesis), 64)

    def test_compute_pair_hash(self):
        h1 = "a" * 64
        h2 = "b" * 64
        pair_hash = compute_pair_hash(h1, h2)
        expected = hashlib.sha256((h1 + h2).encode("utf-8")).hexdigest()
        self.assertEqual(pair_hash, expected)

    def test_compute_event_hash_deterministic(self):
        event = AuditEvent(
            actor="user1",
            action="login",
            target="portal",
            metadata={"ip": "127.0.0.1", "attempt": 1},
            event_id="evt-123",
            timestamp=1700000000.0,
            previous_hash="prev-hash-abc",
        )
        hash1 = compute_event_hash(event)
        hash2 = compute_event_hash(event)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

    def test_compute_event_hash_field_sensitivity(self):
        base_event = AuditEvent(
            actor="user1",
            action="login",
            target="portal",
            metadata={"ip": "127.0.0.1"},
            event_id="evt-123",
            timestamp=1700000000.0,
            previous_hash="prev-hash-abc",
        )
        base_hash = compute_event_hash(base_event)

        # Alter actor
        modified = AuditEvent(
            actor="user2",
            action="login",
            target="portal",
            metadata={"ip": "127.0.0.1"},
            event_id="evt-123",
            timestamp=1700000000.0,
            previous_hash="prev-hash-abc",
        )
        self.assertNotEqual(base_hash, compute_event_hash(modified))

        # Alter metadata
        modified_meta = AuditEvent(
            actor="user1",
            action="login",
            target="portal",
            metadata={"ip": "192.168.1.1"},
            event_id="evt-123",
            timestamp=1700000000.0,
            previous_hash="prev-hash-abc",
        )
        self.assertNotEqual(base_hash, compute_event_hash(modified_meta))


if __name__ == "__main__":
    unittest.main()
