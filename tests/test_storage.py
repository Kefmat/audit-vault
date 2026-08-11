"""Unit tests for Vault storage drivers."""

import os
import unittest
import tempfile
import threading
from src.storage.memory import MemoryVaultStorage
from src.storage.file import FileVaultStorage
from src.types import AuditEvent


class TestVaultStorage(unittest.TestCase):

    def test_memory_storage_chain_and_verification(self):
        storage = MemoryVaultStorage()
        ev1 = storage.append_event(AuditEvent(actor="u1", action="user.login", target="sys"))
        ev2 = storage.append_event(AuditEvent(actor="u2", action="user.logout", target="sys"))

        self.assertEqual(ev1.previous_hash, "GENESIS_BLOCK_PREVIOUS_HASH")
        self.assertEqual(ev2.previous_hash, ev1.hash)

        verification = storage.verify_integrity()
        self.assertTrue(verification.valid)
        self.assertEqual(verification.total_events, 2)
        self.assertNotEqual(verification.merkle_root, "")

    def test_memory_storage_tamper_detection(self):
        storage = MemoryVaultStorage()
        ev1 = storage.append_event(AuditEvent(actor="u1", action="user.login", target="sys"))
        storage.append_event(AuditEvent(actor="u2", action="user.logout", target="sys"))

        # Modify event actor in place
        ev1.actor = "malicious_actor"

        verification = storage.verify_integrity()
        self.assertFalse(verification.valid)
        self.assertEqual(verification.tampered_event_id, ev1.event_id)

    def test_file_storage_persistence_and_verification(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tmp:
            tmp_path = tmp.name

        try:
            storage1 = FileVaultStorage(tmp_path)
            storage1.append_event(AuditEvent(actor="admin", action="config.update", target="auth"))
            storage1.append_event(AuditEvent(actor="system", action="backup.create", target="db"))

            # Load new storage instance from same file
            storage2 = FileVaultStorage(tmp_path)
            events = storage2.get_all_events()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].actor, "admin")

            verification = storage2.verify_integrity()
            self.assertTrue(verification.valid)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_storage_pagination_and_filtering(self):
        storage = MemoryVaultStorage()
        storage.append_event(AuditEvent(actor="alice", action="read", target="doc1", timestamp=100.0))
        storage.append_event(AuditEvent(actor="bob", action="write", target="doc2", timestamp=200.0))
        storage.append_event(AuditEvent(actor="alice", action="write", target="doc3", timestamp=300.0))
        storage.append_event(AuditEvent(actor="charlie", action="read", target="doc4", timestamp=400.0))

        # Filter by actor
        alice_events = storage.get_all_events(actor="alice")
        self.assertEqual(len(alice_events), 2)

        # Filter by timestamp range
        range_events = storage.get_all_events(since=150.0, until=350.0)
        self.assertEqual(len(range_events), 2)
        self.assertEqual(range_events[0].actor, "bob")
        self.assertEqual(range_events[1].actor, "alice")

        # Pagination
        paged_events = storage.get_all_events(limit=2, offset=1)
        self.assertEqual(len(paged_events), 2)
        self.assertEqual(paged_events[0].actor, "bob")
        self.assertEqual(paged_events[1].actor, "alice")

    def test_get_proof_for_event(self):
        storage = MemoryVaultStorage()
        ev1 = storage.append_event(AuditEvent(actor="u1", action="a1", target="t1"))
        ev2 = storage.append_event(AuditEvent(actor="u2", action="a2", target="t2"))

        proof = storage.get_proof_for_event(ev1.event_id)
        self.assertIsNotNone(proof)
        self.assertEqual(proof.leaf_hash, ev1.hash)

        # Non-existent event proof returns None
        self.assertIsNone(storage.get_proof_for_event("non-existent-id"))

    def test_concurrent_append_events(self):
        storage = MemoryVaultStorage()
        threads = []

        def worker(thread_id: int):
            for i in range(10):
                storage.append_event(AuditEvent(
                    actor=f"worker_{thread_id}",
                    action="write",
                    target=f"target_{i}"
                ))

        for t_id in range(5):
            t = threading.Thread(target=worker, args=(t_id,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(len(storage.get_all_events()), 50)
        verification = storage.verify_integrity()
        self.assertTrue(verification.valid)

    def test_event_validations(self):
        storage = MemoryVaultStorage()
        # Invalid actor
        with self.assertRaises(ValueError):
            storage.append_event(AuditEvent(actor="", action="a", target="t"))
        # Invalid metadata type
        with self.assertRaises(ValueError):
            storage.append_event(AuditEvent(actor="u", action="a", target="t", metadata="not_a_dict"))
        # Far future timestamp
        with self.assertRaises(ValueError):
            storage.append_event(AuditEvent(actor="u", action="a", target="t", timestamp=9999999999.0))
        # Excessive metadata size (over 64KB)
        large_metadata = {"data": "x" * 66000}
        with self.assertRaises(ValueError):
            storage.append_event(AuditEvent(actor="u", action="a", target="t", metadata=large_metadata))


if __name__ == "__main__":
    unittest.main()
