"""Unit tests for Merkle Tree logic."""

import unittest
from src.merkle import MerkleTree
from src.hasher import compute_pair_hash


class TestMerkleTree(unittest.TestCase):

    def test_empty_tree(self):
        tree = MerkleTree([])
        self.assertEqual(tree.root, "")

    def test_single_leaf(self):
        tree = MerkleTree(["hash1"])
        self.assertEqual(tree.root, "hash1")

    def test_two_leaves(self):
        tree = MerkleTree(["hash1", "hash2"])
        expected_root = compute_pair_hash("hash1", "hash2")
        self.assertEqual(tree.root, expected_root)

    def test_odd_leaves(self):
        # 3 leaves: hash1, hash2, hash3
        # Level 1: pair(hash1, hash2), pair(hash3, hash3)
        # Root: pair(pair(hash1, hash2), pair(hash3, hash3))
        tree = MerkleTree(["h1", "h2", "h3"])
        p1 = compute_pair_hash("h1", "h2")
        p2 = compute_pair_hash("h3", "h3")
        expected_root = compute_pair_hash(p1, p2)
        self.assertEqual(tree.root, expected_root)

    def test_merkle_proof_verification(self):
        hashes = ["h1", "h2", "h3", "h4", "h5"]
        tree = MerkleTree(hashes)

        for idx in range(len(hashes)):
            proof = tree.get_proof(idx)
            self.assertIsNotNone(proof)
            self.assertTrue(MerkleTree.verify_proof(proof))

    def test_invalid_proof_rejection(self):
        hashes = ["h1", "h2", "h3", "h4"]
        tree = MerkleTree(hashes)
        proof = tree.get_proof(0)
        # Tamper with leaf hash
        proof.leaf_hash = "tampered_hash"
        self.assertFalse(MerkleTree.verify_proof(proof))


if __name__ == "__main__":
    unittest.main()
