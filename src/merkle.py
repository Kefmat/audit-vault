"""Merkle Tree implementation for tamper-evident verification."""

from typing import List, Optional, Dict
from src.hasher import compute_pair_hash
from src.types import MerkleProof


class MerkleTree:
    """Constructs a Merkle Tree from a list of hashes and generates inclusion proofs."""

    def __init__(self, hashes: List[str]):
        self.leaves: List[str] = list(hashes)
        self.levels: List[List[str]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        if not self.leaves:
            self.levels = [[""]]
            return

        current_level = list(self.leaves)
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left  # Duplicate odd leaf node
                parent = compute_pair_hash(left, right)
                next_level.append(parent)
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        if not self.levels or not self.levels[-1]:
            return ""
        return self.levels[-1][0]

    def get_proof(self, leaf_index: int) -> Optional[MerkleProof]:
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            return None

        proof_steps: List[Dict[str, str]] = []
        idx = leaf_index

        for level in self.levels[:-1]:
            is_right = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right else idx + 1

            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
            else:
                sibling_hash = level[idx]  # Duplicated boundary leaf

            position = "left" if is_right else "right"
            proof_steps.append({"position": position, "hash": sibling_hash})

            idx //= 2

        return MerkleProof(
            leaf_hash=self.leaves[leaf_index],
            root_hash=self.root,
            proof=proof_steps
        )

    @staticmethod
    def verify_proof(proof: MerkleProof) -> bool:
        current = proof.leaf_hash
        for step in proof.proof:
            if step["position"] == "left":
                current = compute_pair_hash(step["hash"], current)
            else:
                current = compute_pair_hash(current, step["hash"])
        return current == proof.root_hash
